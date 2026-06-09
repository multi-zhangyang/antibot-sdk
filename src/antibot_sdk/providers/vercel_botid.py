from __future__ import annotations

import asyncio
import ast as py_ast
import base64
import binascii
import hashlib
import json
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from Crypto.Cipher import AES

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16
IV_BYTES = 12
AES_KEY_BYTES = 32
GCM_TAG_BYTES = 16
DEFAULT_TIMEOUT = 15
DEFAULT_WEBGL = {
    "v": "Google Inc. (Intel)",
    "r": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
}
VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "vercel_botid"
RAW_VM_SOLVER = VENDOR_DIR / "raw_vm_solver.mjs"


@dataclass(frozen=True, slots=True)
class VercelBotIdScriptContext:
    """Values extracted from a Vercel BotID challenge script.

    The public header maps these fields as:
    ``{"b": arg1, "v": rand, "e": signature, "s": encrypted_fp, "d": arg2, "vr": version}``.
    """

    key: str
    seed: float
    arg1: int | float
    arg2: int | float
    rand: int | float
    signature: str
    version: str
    key_left: str | None = None
    key_right: str | None = None
    raw_js: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def tail_payload(self) -> dict[str, Any]:
        return {
            "b": self.arg1,
            "v": self.rand,
            "e": self.signature,
            "d": self.arg2,
            "vr": self.version,
        }


@dataclass(frozen=True, slots=True)
class VercelBotIdSolution:
    context: VercelBotIdScriptContext
    fingerprint: dict[str, Any]
    encrypted_fingerprint: str
    header: str
    elapsed_ms: int

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.header)

    @property
    def x_is_human(self) -> str:
        return self.header


def parse_botid_script(data: VercelBotIdScriptContext | dict[str, Any] | str) -> VercelBotIdScriptContext:
    """Extract BotID context from local JS, ``@file`` input, JSON, or an existing context.

    This prototype intentionally targets protocol-level inputs that are already available locally:
    the raw/simplified BotID ``c.js`` tail exposes the public args, while the stable key/seed
    extraction is designed for deobfuscated/simplified scripts such as the ``output.js`` produced
    by the research toolchain. It avoids browser execution entirely.
    """

    if isinstance(data, VercelBotIdScriptContext):
        return data
    if isinstance(data, dict):
        return _context_from_mapping(data)
    if not isinstance(data, str):
        raise ValueError("BotID script must be JS text, @file, JSON object, or VercelBotIdScriptContext")

    text = _load_text_arg(data)
    stripped = text.strip()
    if not stripped:
        raise ValueError("BotID script is empty")
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and {"key", "seed"}.intersection(parsed):
            return _context_from_mapping(parsed)

    tail = _extract_tail_payload_args(stripped)
    seed = _extract_seed(stripped)
    key, key_left, key_right = _extract_key(stripped)
    return VercelBotIdScriptContext(
        key=_validate_key(key),
        seed=float(seed),
        arg1=tail["arg1"],
        arg2=tail["arg2"],
        rand=tail["rand"],
        signature=_validate_signature(tail["signature"]),
        version=_validate_version(tail["version"]),
        key_left=key_left,
        key_right=key_right,
        raw_js=stripped,
        raw={"tail": tail, "key_left": key_left, "key_right": key_right},
    )


def build_botid_fingerprint(
    context_or_seed: VercelBotIdScriptContext | int | float,
    *,
    profile: dict[str, Any] | None = None,
    webgl: dict[str, Any] | tuple[str, str] | None = None,
    dom_controller: bool = False,
    selenium: bool = False,
    headless: bool = False,
    devtools: bool = False,
    devtools2: bool = False,
) -> dict[str, Any]:
    """Build the low-risk fingerprint object encrypted into ``s``.

    The shape mirrors BotID's browser payload: ``p/S/w/s/h/b/d``. Defaults deliberately report
    non-automation signals and a common Chromium WebGL pair, so tests and SDK callers can generate
    deterministic protocol payloads without launching a browser.
    """

    profile = dict(profile or {})
    seed = context_or_seed.seed if isinstance(context_or_seed, VercelBotIdScriptContext) else context_or_seed
    if "S" in profile:
        seed = profile["S"]
    fp_webgl = webgl if webgl is not None else profile.get("w") or profile.get("webgl")
    return {
        "p": bool(profile.get("p", dom_controller)),
        "S": float(seed),
        "w": _normalize_webgl(fp_webgl),
        "s": bool(profile.get("s", selenium)),
        "h": bool(profile.get("h", headless)),
        "b": bool(profile.get("b", devtools)),
        "d": bool(profile.get("d", devtools2)),
    }


def derive_botid_aes_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        _validate_key(password).encode("utf-8"),
        _validate_bytes(salt, SALT_BYTES, "salt"),
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_BYTES,
    )


def encrypt_botid_fingerprint(
    password: str,
    payload: dict[str, Any],
    *,
    salt: bytes | str | None = None,
    iv: bytes | str | None = None,
) -> str:
    """PBKDF2-SHA256 + AES-256-GCM, encoded as base64(salt || iv || ciphertext || tag)."""

    salt_bytes = secrets.token_bytes(SALT_BYTES) if salt is None else _coerce_bytes(salt, SALT_BYTES, "salt")
    iv_bytes = secrets.token_bytes(IV_BYTES) if iv is None else _coerce_bytes(iv, IV_BYTES, "iv")
    key = derive_botid_aes_key(password, salt_bytes)
    plaintext = _json_dumps(payload).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(salt_bytes + iv_bytes + ciphertext + tag).decode("ascii")


def decrypt_botid_fingerprint(password: str, encrypted: str) -> dict[str, Any]:
    raw = _b64decode(encrypted)
    if len(raw) < SALT_BYTES + IV_BYTES + GCM_TAG_BYTES + 1:
        raise ValueError("BotID encrypted fingerprint is too short")
    salt = raw[:SALT_BYTES]
    iv = raw[SALT_BYTES : SALT_BYTES + IV_BYTES]
    body = raw[SALT_BYTES + IV_BYTES :]
    ciphertext = body[:-GCM_TAG_BYTES]
    tag = body[-GCM_TAG_BYTES:]
    key = derive_botid_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    data = json.loads(plaintext.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("BotID decrypted fingerprint must be a JSON object")
    return data


def generate_x_is_human_payload(
    script_or_context: VercelBotIdScriptContext | dict[str, Any] | str,
    *,
    fingerprint: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    salt: bytes | str | None = None,
    iv: bytes | str | None = None,
) -> dict[str, Any]:
    context = parse_botid_script(script_or_context)
    fp = dict(fingerprint) if fingerprint is not None else build_botid_fingerprint(context, profile=profile)
    encrypted = encrypt_botid_fingerprint(context.key, fp, salt=salt, iv=iv)
    return {
        "b": context.arg1,
        "v": context.rand,
        "e": context.signature,
        "s": encrypted,
        "d": context.arg2,
        "vr": context.version,
    }


def generate_x_is_human(
    script_or_context: VercelBotIdScriptContext | dict[str, Any] | str,
    *,
    fingerprint: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    salt: bytes | str | None = None,
    iv: bytes | str | None = None,
) -> str:
    return _json_dumps(
        generate_x_is_human_payload(
            script_or_context,
            fingerprint=fingerprint,
            profile=profile,
            salt=salt,
            iv=iv,
        )
    )


def solve_vercel_botid_script(
    script_or_context: VercelBotIdScriptContext | dict[str, Any] | str,
    *,
    fingerprint: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    salt: bytes | str | None = None,
    iv: bytes | str | None = None,
) -> VercelBotIdSolution:
    started = time.monotonic()
    context = parse_botid_script(script_or_context)
    fp = dict(fingerprint) if fingerprint is not None else build_botid_fingerprint(context, profile=profile)
    encrypted = encrypt_botid_fingerprint(context.key, fp, salt=salt, iv=iv)
    header = _json_dumps(
        {
            "b": context.arg1,
            "v": context.rand,
            "e": context.signature,
            "s": encrypted,
            "d": context.arg2,
            "vr": context.version,
        }
    )
    return VercelBotIdSolution(
        context=context,
        fingerprint=fp,
        encrypted_fingerprint=encrypted,
        header=header,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def solve_vercel_botid_raw_vm(
    script: str,
    *,
    script_url: str | None = None,
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Execute raw BotID ``c.js`` inside a minimal Node VM browser shim.

    This path is for raw/obfuscated BotID scripts whose key/seed are intentionally hidden behind
    a string decoder or control-flow proxy.  It still avoids a browser: the VM supplies only the
    small surface used by the BotID payload builder (``window``, ``document``, WebGL, WebCrypto,
    ``btoa`` and navigator flags), then invokes the registered ``V_C`` callback and returns the
    generated ``X-Is-Human`` payload.
    """

    source = _load_text_arg(script)
    if not source.strip():
        raise ValueError("BotID raw VM script is empty")
    node_bin = node or shutil.which("node")
    if not node_bin:
        raise RuntimeError("node executable is required for BotID raw VM mode")
    if not RAW_VM_SOLVER.is_file():
        raise RuntimeError(f"BotID raw VM helper is missing: {RAW_VM_SOLVER}")
    payload = {
        "script": source,
        "script_url": script_url,
        "profile": profile or {},
        "vm_timeout_ms": max(1000, int(timeout_sec * 1000)),
    }
    proc = subprocess.run(
        [node_bin, str(RAW_VM_SOLVER)],
        input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=max(1, int(timeout_sec)),
        check=False,
    )
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "BotID raw VM helper failed").strip()
        raise RuntimeError(message)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("BotID raw VM helper returned non-JSON output") from exc
    payload_obj = data.get("payload")
    if not isinstance(payload_obj, dict) or not isinstance(payload_obj.get("s"), str):
        raise RuntimeError("BotID raw VM helper returned invalid payload")
    return data


def generate_x_is_human_raw_vm(
    script: str,
    *,
    script_url: str | None = None,
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
) -> str:
    data = solve_vercel_botid_raw_vm(
        script,
        script_url=script_url,
        profile=profile,
        node=node,
        timeout_sec=timeout_sec,
    )
    return _json_dumps(data["payload"])


class VercelBotIdSolver:
    """Prototype protocol solver for Vercel BotID ``X-Is-Human`` headers.

    Network submission is intentionally stub-only in this provider. Script fetching is disabled by
    default and must be explicitly enabled via ``allow_network=True`` for controlled mocks.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        script_js: str | None = None,
        script_file: str | None = None,
        script_url: str | None = None,
        allow_network: bool = False,
        raw_vm: bool = False,
        submit: bool = False,
        fingerprint: dict[str, Any] | None = None,
        profile: dict[str, Any] | None = None,
        salt: bytes | str | None = None,
        iv: bytes | str | None = None,
        node: str | None = None,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "script_url": script_url,
            "allow_network": allow_network,
            "raw_vm": raw_vm,
            "submit": submit,
            "submit_mode": "stub_only",
            "timeout_sec": timeout_sec,
            "proxy": redacted_proxy(proxy_server),
        }
        errors: list[str] = []

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            raw["ok"] = ok
            raw["elapsedMs"] = elapsed_ms
            return CaptchaResult(
                provider="vercel_botid",
                ok=ok,
                captcha_type="x_is_human_aes_gcm_fingerprint",
                capability="protocol_solver",
                ticket=ticket,
                randstr=str(diagnostics.get("rand")) if diagnostics.get("rand") is not None else None,
                verify_code=verify_code,
                elapsed_ms=elapsed_ms,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            script = self._load_script(
                script_js=script_js,
                script_file=script_file,
                script_url=script_url,
                allow_network=allow_network,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            if raw_vm:
                vm_data = solve_vercel_botid_raw_vm(
                    script,
                    script_url=script_url,
                    profile=profile,
                    node=node,
                    timeout_sec=timeout_sec,
                )
                payload = vm_data["payload"]
                diagnostics.update(
                    {
                        "mode": "raw_vm",
                        "arg1": payload.get("b"),
                        "arg2": payload.get("d"),
                        "rand": payload.get("v"),
                        "version": payload.get("vr"),
                        "signature_prefix": str(payload.get("e") or "")[:16],
                        "fingerprint_keys": ["vm_generated"],
                        "vm": vm_data.get("diagnostics") or {},
                    }
                )
                raw["payload"] = payload
                raw["vm"] = vm_data.get("diagnostics") or {}
                header = _json_dumps(payload)
                if submit:
                    diagnostics["submitted"] = False
                    errors.append("Vercel BotID network submit is stub-only; use ticket as X-Is-Human header")
                    return finish(ok=False, ticket=header, verify_code="submit_stub")
                return finish(ok=True, ticket=header, verify_code="solved")
            solution = solve_vercel_botid_script(
                script,
                fingerprint=fingerprint,
                profile=profile,
                salt=salt,
                iv=iv,
            )
            diagnostics.update(
                {
                    "key_length": len(solution.context.key),
                    "seed": solution.context.seed,
                    "arg1": solution.context.arg1,
                    "arg2": solution.context.arg2,
                    "rand": solution.context.rand,
                    "version": solution.context.version,
                    "signature_prefix": solution.context.signature[:16],
                    "fingerprint_keys": list(solution.fingerprint.keys()),
                }
            )
            raw["payload"] = solution.payload
            raw["fingerprint"] = solution.fingerprint
            if submit:
                diagnostics["submitted"] = False
                errors.append("Vercel BotID network submit is stub-only; use ticket as X-Is-Human header")
                return finish(ok=False, ticket=solution.header, verify_code="submit_stub")
            return finish(ok=True, ticket=solution.header, verify_code="solved")
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_script(
        self,
        *,
        script_js: str | None,
        script_file: str | None,
        script_url: str | None,
        allow_network: bool,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> str:
        if script_js is not None:
            return _load_text_arg(script_js)
        if script_file:
            return Path(script_file).read_text(encoding="utf-8")
        if not script_url:
            raise ValueError("Vercel BotID solve requires script_js, script_file, or script_url")
        if not allow_network:
            raise ValueError("script_url fetch is disabled by default; pass allow_network=True for mocks")
        proxies = _requests_proxies(proxy_server)
        resp = requests.get(script_url, headers=headers or {}, timeout=timeout_sec, proxies=proxies)
        raw["scriptResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "bodyPrefix": resp.text[:120],
        }
        resp.raise_for_status()
        return resp.text


def _context_from_mapping(data: dict[str, Any]) -> VercelBotIdScriptContext:
    tail = data.get("tail") if isinstance(data.get("tail"), dict) else data
    signature = tail.get("signature") or tail.get("e")
    version = tail.get("version") or tail.get("vr")
    rand = tail.get("rand") if tail.get("rand") is not None else tail.get("v")
    arg1 = tail.get("arg1") if tail.get("arg1") is not None else tail.get("b")
    arg2 = tail.get("arg2") if tail.get("arg2") is not None else tail.get("d")
    key_left = data.get("key_left") or data.get("k")
    key_right = data.get("key_right") or data.get("a")
    key = data.get("key") or (f"{key_left}{key_right}" if key_left is not None and key_right is not None else None)
    seed = data.get("seed") if data.get("seed") is not None else data.get("S")
    missing = [
        name
        for name, value in {
            "key": key,
            "seed": seed,
            "arg1/b": arg1,
            "arg2/d": arg2,
            "rand/v": rand,
            "signature/e": signature,
            "version/vr": version,
        }.items()
        if value is None
    ]
    if missing:
        raise ValueError(f"BotID context missing required field(s): {', '.join(missing)}")
    return VercelBotIdScriptContext(
        key=_validate_key(str(key)),
        seed=float(seed),
        arg1=_literal_number(str(arg1)),
        arg2=_literal_number(str(arg2)),
        rand=_literal_number(str(rand)),
        signature=_validate_signature(str(signature)),
        version=_validate_version(str(version)),
        key_left=str(key_left) if key_left is not None else None,
        key_right=str(key_right) if key_right is not None else None,
        raw=data,
    )


def _extract_tail_payload_args(source: str) -> dict[str, Any]:
    for sig_match in re.finditer(r"""["']eyJ""", source):
        open_pos = source.rfind("(", 0, sig_match.start())
        while open_pos >= 0:
            close_pos = _find_matching(source, open_pos)
            if close_pos > sig_match.end():
                args = _split_top_level(source[open_pos + 1 : close_pos], ",")
                if len(args) == 5:
                    signature = _literal_string(args[3])
                    version = _literal_string(args[4])
                    if signature and signature.startswith("eyJ") and version is not None:
                        return {
                            "arg1": _literal_number(args[0]),
                            "arg2": _literal_number(args[1]),
                            "rand": _literal_number(args[2]),
                            "signature": signature,
                            "version": version,
                        }
            open_pos = source.rfind("(", 0, open_pos)
    raise ValueError("BotID script does not contain the final 5-argument V_C.S call")


def _extract_seed(source: str) -> float:
    candidates: list[tuple[int, float]] = []
    number = r"[-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
    for match in re.finditer(rf"""(?:"S"|'S'|\bS\b)\s*:\s*({number})""", source):
        try:
            value = float(_literal_number(match.group(1)))
        except ValueError:
            continue
        window = source[max(0, match.start() - 500) : min(len(source), match.end() + 500)]
        score = sum(1 for key in ("p", "w", "s", "h", "b", "d") if re.search(rf"""["']?{key}["']?\s*:""", window))
        candidates.append((score, value))
    if not candidates:
        raise ValueError("BotID script does not contain fingerprint seed S")
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _extract_key(source: str) -> tuple[str, str | None, str | None]:
    for left_name, right_name in _extract_key_variable_orders(source):
        left = _extract_assigned_js_string(source, left_name)
        right = _extract_assigned_js_string(source, right_name)
        if left and right:
            return left + right, left, right

    left = _extract_assigned_js_string(source, "k")
    right = _extract_assigned_js_string(source, "a")
    if left and right:
        return left + right, left, right

    direct = _extract_direct_key(source)
    if direct:
        return direct, None, None
    raise ValueError("BotID script does not contain an extractable fingerprint encryption key")


def _extract_key_variable_orders(source: str) -> list[tuple[str, str]]:
    orders: list[tuple[str, str]] = []
    ident = r"[A-Za-z_$][\w$]*"
    pattern = re.compile(
        rf"""\[\s*({ident})\s*,\s*({ident})\s*\]\s*(?:\[\s*["']join["']\s*\]|\.\s*join)\s*\(""",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        pair = (match.group(1), match.group(2))
        if pair not in orders:
            orders.append(pair)
    return orders


def _extract_assigned_js_string(source: str, name: str) -> str | None:
    pattern = re.compile(rf"""(?<![\w$.]){re.escape(name)}\s*=""")
    found: list[str] = []
    for match in pattern.finditer(source):
        expr = _read_assignment_expression(source, match.end())
        if not expr:
            continue
        try:
            value = _eval_js_static_expr(expr)
        except ValueError:
            continue
        if isinstance(value, str) and value:
            found.append(value)
    return found[-1] if found else None


def _extract_direct_key(source: str) -> str | None:
    for pattern in (
        r"""(?:"key"|'key'|\bkey\b)\s*:\s*(["'])(.*?)\1""",
        r"""(?:"G"|'G'|\bG\b)\s*:\s*(["'])(.*?)\1""",
    ):
        match = re.search(pattern, source, re.DOTALL)
        if match:
            return _decode_js_string_literal(match.group(1) + match.group(2) + match.group(1))
    return None


def _read_assignment_expression(source: str, start: int) -> str:
    pos = _skip_ws(source, start)
    if pos >= len(source):
        return ""
    if source[pos] in "([{":
        end = _find_matching(source, pos)
        if end > pos:
            return source[pos : end + 1]

    depth = 0
    quote = ""
    escaped = False
    for idx in range(pos, len(source)):
        ch = source[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch in "([{":
            depth += 1
            continue
        if ch in ")]}":
            if depth == 0:
                return source[pos:idx].strip()
            depth -= 1
            continue
        if depth == 0 and ch in ",;\n\r":
            return source[pos:idx].strip()
    return source[pos:].strip()


def _eval_js_static_expr(expr: str) -> Any:
    text = expr.strip()
    if not text:
        raise ValueError("empty expression")
    if _is_wrapped(text, "(", ")"):
        inner = text[1:-1].strip()
        parts = _split_top_level(inner, ",")
        if len(parts) > 1:
            return _eval_js_static_expr(parts[-1])
        return _eval_js_static_expr(inner)

    parts = _split_top_level(text, ",")
    if len(parts) > 1:
        return _eval_js_static_expr(parts[-1])

    plus_parts = _split_top_level(text, "+")
    if len(plus_parts) > 1:
        values = [_eval_js_static_expr(part) for part in plus_parts]
        if all(isinstance(value, str) for value in values):
            return "".join(values)
        if all(isinstance(value, int | float) for value in values):
            return sum(values)
        return "".join(str(value) for value in values)

    literal = _literal_string(text)
    if literal is not None:
        return literal
    if re.fullmatch(r"[-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?", text):
        return _literal_number(text)
    if text in {"true", "!1", "!![]"}:
        return True
    if text in {"false", "!0"}:
        return False

    btoa_match = re.fullmatch(r"""btoa\s*\(\s*((?:"(?:\\.|[^"])*")|(?:'(?:\\.|[^'])*'))\s*\)""", text, re.DOTALL)
    if btoa_match:
        raw = _decode_js_string_literal(btoa_match.group(1)).encode("latin1")
        return base64.b64encode(raw).decode("ascii")

    from_char = re.search(r"""fromCharCode["'\]]*\s*\((.*?)\)""", text, re.DOTALL)
    if from_char:
        chars = []
        for part in _split_top_level(from_char.group(1), ","):
            chars.append(chr(int(_literal_number(part))))
        return "".join(chars)

    raise ValueError(f"unsupported JS static expression: {text[:80]}")


def _split_top_level(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch in "([{":
            depth += 1
            continue
        if ch in ")]}":
            depth -= 1
            continue
        if depth == 0 and ch == delimiter:
            parts.append(text[start:idx].strip())
            start = idx + 1
    parts.append(text[start:].strip())
    return parts


def _find_matching(source: str, open_pos: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = source[open_pos]
    closer = pairs.get(opener)
    if not closer:
        return -1
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_pos, len(source)):
        ch = source[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _is_wrapped(text: str, opener: str, closer: str) -> bool:
    return text.startswith(opener) and text.endswith(closer) and _find_matching(text, 0) == len(text) - 1


def _literal_string(text: str) -> str | None:
    value = text.strip()
    if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
        return None
    return _decode_js_string_literal(value)


def _literal_number(text: str) -> int | float:
    value = str(text).strip()
    if re.fullmatch(r"[-+]?0x[0-9a-fA-F]+", value):
        sign = -1 if value.startswith("-") else 1
        cleaned = value[1:] if value[0] in "+-" else value
        return sign * int(cleaned, 16)
    try:
        as_float = float(value)
    except ValueError as exc:
        raise ValueError(f"invalid numeric literal: {text}") from exc
    return int(as_float) if as_float.is_integer() else as_float


def _decode_js_string_literal(literal: str) -> str:
    try:
        return py_ast.literal_eval(literal)
    except Exception:
        pass
    quote = literal[0]
    body = literal[1:-1] if len(literal) >= 2 and literal[-1] == quote else literal

    def replace(match: re.Match[str]) -> str:
        esc = match.group(1)
        if esc.startswith("x"):
            return chr(int(esc[1:], 16))
        if esc.startswith("u"):
            return chr(int(esc[1:], 16))
        return {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "\\": "\\",
            "'": "'",
            '"': '"',
            "/": "/",
        }.get(esc, esc)

    return re.sub(r"""\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)""", replace, body)


def _normalize_webgl(webgl: dict[str, Any] | tuple[str, str] | None) -> dict[str, str] | None:
    if webgl is None:
        return dict(DEFAULT_WEBGL)
    if isinstance(webgl, tuple) and len(webgl) == 2:
        return {"v": str(webgl[0]), "r": str(webgl[1])}
    if not isinstance(webgl, dict):
        raise ValueError("webgl must be a {v,r} object, upstream WebGL entry, tuple, or None")
    if isinstance(webgl.get("v"), str) and isinstance(webgl.get("r"), str):
        return {"v": webgl["v"], "r": webgl["r"]}

    renderer = webgl.get("webgl_unmasked_renderer")
    vendor = None
    nested = webgl.get("webgl")
    if isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict) and isinstance(item.get("webgl_unmasked_vendor"), str):
                vendor = item["webgl_unmasked_vendor"]
                break
    if isinstance(vendor, str) and isinstance(renderer, str):
        return {"v": vendor, "r": renderer}
    raise ValueError("webgl object must contain v/r or upstream webgl_unmasked fields")


def _validate_key(value: str) -> str:
    text = str(value)
    if not text:
        raise ValueError("BotID encryption key is empty")
    if len(text) > 512:
        raise ValueError("BotID encryption key is unexpectedly long")
    return text


def _validate_signature(value: str) -> str:
    text = str(value)
    if not text.startswith("eyJ"):
        raise ValueError("BotID signature must look like a compact JWT/JWE value")
    return text


def _validate_version(value: str) -> str:
    text = str(value)
    if not text:
        raise ValueError("BotID version is empty")
    return text


def _validate_bytes(value: bytes, expected_len: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    if len(value) != expected_len:
        raise ValueError(f"{name} must be {expected_len} bytes")
    return value


def _coerce_bytes(value: bytes | str, expected_len: int, name: str) -> bytes:
    if isinstance(value, bytes):
        return _validate_bytes(value, expected_len, name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be bytes or string")
    text = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) == expected_len * 2:
        return bytes.fromhex(text)
    raw = _b64decode(text)
    return _validate_bytes(raw, expected_len, name)


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(str(value), validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid base64 data") from exc


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _skip_ws(source: str, pos: int) -> int:
    while pos < len(source) and source[pos].isspace():
        pos += 1
    return pos


def _load_text_arg(data: str) -> str:
    text = str(data)
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8")
    return text


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    if not proxy_server:
        return None
    parsed = parse_proxy(proxy_server)
    return {"http": parsed.url, "https": parsed.url}
