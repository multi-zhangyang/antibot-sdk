from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from blake3 import blake3

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

HEX_CHARS = b"0123456789abcdef"
DEFAULT_TIMEOUT_SEC = 60
GS_SETS_RE = re.compile(
    r"(?:const|let|var)?\s*(?:window\.)?_gs_sets\s*=\s*\{(?P<body>.*?)\}",
    re.DOTALL,
)
GS_FIELD_RE = re.compile(
    r"""['"]?([_A-Za-z][_A-Za-z0-9]*)['"]?\s*:\s*(?:'((?:\\.|[^'])*)'|"((?:\\.|[^"])*)")""",
    re.DOTALL,
)


@dataclass(slots=True)
class GunsLolChallenge:
    o09: str
    n: str
    org_ts: str
    x2a: str

    def to_payload(self) -> dict[str, str]:
        return {"o09": self.o09, "_n": self.n, "_org_ts": self.org_ts, "_2xa": self.x2a}


@dataclass(slots=True)
class GunsLolParsedChallenge:
    challenge: GunsLolChallenge
    dd: int
    positions: list[int]
    positions_sorted: list[int]
    key: bytes
    template: bytes
    seal_template: bytes
    suffix: bytes
    target: bytes
    total_space: int


@dataclass(slots=True)
class GunsLolSolution:
    challenge: GunsLolChallenge
    seal: str
    oo: str
    attempts: int
    took_ms: int
    dd: int
    positions: list[int]

    @property
    def submit_body(self) -> dict[str, str]:
        return {"seal": self.seal, "_oo": self.oo}


def base64url_decode_unpadded(value: str) -> bytes:
    text = str(value).strip()
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text)


def base64url_encode_unpadded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_gunslol_challenge(value: GunsLolChallenge | dict[str, Any] | str) -> GunsLolChallenge:
    if isinstance(value, GunsLolChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        if "_gs_sets" in text and not text.startswith("{"):
            obj = extract_gunslol_gs_sets(text)
        else:
            obj = json.loads(text)
    else:
        obj = dict(value)
    if isinstance(obj.get("challenge"), dict):
        obj = obj["challenge"]
    if isinstance(obj.get("_gs_sets"), dict):
        obj = obj["_gs_sets"]
    o09 = str(obj.get("o09") or obj.get("_d") or obj.get("target") or "")
    n = str(obj.get("_n") or obj.get("n") or "")
    org_ts = str(obj.get("_org_ts") or obj.get("org_ts") or obj.get("ts") or "")
    x2a = str(obj.get("_2xa") or obj.get("x2a") or obj.get("2xa") or "")
    if len(o09) != 64 or any(c not in "0123456789abcdefABCDEF" for c in o09):
        raise ValueError("guns.lol o09 must be 64 hex chars")
    if len(n) != 32:
        raise ValueError("guns.lol _n must be 32 chars")
    if len(org_ts) != 10 or not org_ts.isdigit():
        raise ValueError("guns.lol _org_ts must be a 10-digit timestamp string")
    if not x2a:
        raise ValueError("guns.lol _2xa is required")
    return GunsLolChallenge(o09=o09.lower(), n=n, org_ts=org_ts, x2a=x2a)


def extract_gunslol_gs_sets(html: str) -> dict[str, str]:
    match = GS_SETS_RE.search(html)
    if not match:
        raise ValueError("_gs_sets not found in HTML")
    body = match.group("body")
    values: dict[str, str] = {}
    for item in GS_FIELD_RE.finditer(body):
        key = item.group(1)
        value = item.group(2) if item.group(2) is not None else item.group(3)
        values[key] = _decode_js_string(value)
    for key in ("o09", "_n", "_org_ts", "_2xa"):
        if key not in values:
            raise ValueError(f"_gs_sets missing {key}")
    return {"o09": values["o09"], "_n": values["_n"], "_org_ts": values["_org_ts"], "_2xa": values["_2xa"]}


def _decode_js_string(value: str) -> str:
    if "\\" not in value:
        return value
    try:
        return json.loads('"' + value.replace('"', '\\"') + '"')
    except Exception:
        return value.encode("utf-8").decode("unicode_escape")


def parse_gunslol_2xa(challenge: GunsLolChallenge | dict[str, Any] | str) -> GunsLolParsedChallenge:
    item = parse_gunslol_challenge(challenge)
    blob = base64url_decode_unpadded(item.x2a)
    if len(blob) < 3 or blob[:2] != b"\xa1\x40":
        raise ValueError("bad guns.lol _2xa magic")
    dd = blob[2]
    if dd <= 0 or dd > 16:
        raise ValueError(f"invalid guns.lol dd: {dd}")
    expected_min = 3 + 2 * dd + 8 + (64 - dd)
    if len(blob) < expected_min:
        raise ValueError("guns.lol _2xa blob is truncated")
    positions = list(blob[3 : 3 + dd])
    if any(pos >= 64 for pos in positions) or len(set(positions)) != dd:
        raise ValueError("guns.lol blank positions are invalid")
    positions_sorted = sorted(positions)
    key = blob[3 + 2 * dd : 3 + 2 * dd + 8]
    tmpl_off = 3 + 2 * dd + 8
    template = blob[tmpl_off : tmpl_off + (64 - dd)]
    if len(template) != 64 - dd:
        raise ValueError("guns.lol _2xa template length mismatch")

    seal = bytearray(64)
    pos_set = set(positions_sorted)
    t = 0
    for idx in range(64):
        if idx in pos_set:
            seal[idx] = 0
        else:
            seal[idx] = template[t]
            t += 1
    target = bytes.fromhex(item.o09)
    suffix = (item.n + item.org_ts).encode("ascii")
    return GunsLolParsedChallenge(
        challenge=item,
        dd=dd,
        positions=positions,
        positions_sorted=positions_sorted,
        key=key,
        template=template,
        seal_template=bytes(seal),
        suffix=suffix,
        target=target,
        total_space=1 << (4 * dd),
    )


def build_gunslol_oo(parsed: GunsLolParsedChallenge, seal: bytes | str) -> str:
    seal_bytes = seal.encode("ascii") if isinstance(seal, str) else bytes(seal)
    if len(seal_bytes) != 64:
        raise ValueError("guns.lol seal must be 64 bytes")
    solution_chars = bytes(seal_bytes[pos] for pos in parsed.positions)
    prefix = bytes([0x51, parsed.dd]) + solution_chars + b"\x01\x00\x00\x00"
    tag = blake3(prefix + parsed.key + parsed.target).digest()[:8]
    return base64url_encode_unpadded(prefix + tag)


def verify_gunslol_solution(
    challenge: GunsLolChallenge | dict[str, Any] | str,
    solution: GunsLolSolution | dict[str, Any] | str,
) -> bool:
    try:
        parsed = parse_gunslol_2xa(challenge)
        if isinstance(solution, GunsLolSolution):
            seal = solution.seal
            oo = solution.oo
        elif isinstance(solution, dict):
            seal = str(solution.get("seal") or solution.get("_seal") or solution.get("s") or "")
            oo = str(solution.get("_oo") or solution.get("oo") or "")
        else:
            seal = str(solution)
            oo = ""
        if len(seal) != 64:
            return False
        if hashlib.sha256(seal.encode("ascii") + parsed.suffix).digest() != parsed.target:
            return False
        return not oo or build_gunslol_oo(parsed, seal) == oo
    except Exception:
        return False


def solve_gunslol_challenge(
    challenge: GunsLolChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int | None = None,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> GunsLolSolution | None:
    parsed = parse_gunslol_2xa(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    total = parsed.total_space
    max_attempts = total - start if max_attempts is None else max(1, int(max_attempts))
    end = min(total, start + max_attempts)
    if start >= total:
        return None
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or end - start <= 4096:
        seal, attempts = _solve_gunslol_range(
            parsed.seal_template,
            parsed.positions_sorted,
            parsed.suffix,
            parsed.target,
            start,
            end,
            deadline,
        )
        if seal is None:
            return None
        return _solution_from_seal(parsed, seal, attempts, started)

    chunk = math.ceil((end - start) / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(end, lo + chunk)
        if lo >= hi:
            break
        futures[
            pool.submit(
                _solve_gunslol_range,
                parsed.seal_template,
                parsed.positions_sorted,
                parsed.suffix,
                parsed.target,
                lo,
                hi,
                deadline,
            )
        ] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            seal, attempts = fut.result()
            checked_total += attempts
            if seal is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return _solution_from_seal(parsed, seal, checked_total, started)
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None


def _solve_gunslol_range(
    seal_template: bytes,
    positions_sorted: list[int],
    suffix: bytes,
    target: bytes,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[bytes | None, int]:
    seal = bytearray(seal_template)
    sha256 = hashlib.sha256
    attempts = 0
    dd = len(positions_sorted)
    for value in range(int(start), int(end_exclusive)):
        if deadline is not None and attempts and attempts % 8192 == 0 and time.monotonic() >= deadline:
            return None, attempts
        attempts += 1
        v = value
        for idx in range(dd):
            seal[positions_sorted[idx]] = HEX_CHARS[v & 0xF]
            v >>= 4
        if sha256(bytes(seal) + suffix).digest() == target:
            return bytes(seal), attempts
    return None, attempts


def _solution_from_seal(
    parsed: GunsLolParsedChallenge,
    seal: bytes,
    attempts: int,
    started: float,
) -> GunsLolSolution:
    seal_text = seal.decode("ascii")
    oo = build_gunslol_oo(parsed, seal)
    return GunsLolSolution(
        challenge=parsed.challenge,
        seal=seal_text,
        oo=oo,
        attempts=attempts,
        took_ms=int((time.monotonic() - started) * 1000),
        dd=parsed.dd,
        positions=list(parsed.positions),
    )


def _load_json_arg(value: Any = None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _extract_token(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "message", "status", "_oo"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


class GunsLolSolver:
    """guns.lol _gs_sets SHA-256 seal + BLAKE3 tag protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        page_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int | None = None,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "page_url": page_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
        }
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "gunslol_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="gunslol",
                ok=ok,
                captcha_type="seal_pow_blake3",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("_n"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url or page_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_gunslol_challenge(challenge_data)
            parsed = parse_gunslol_2xa(item)
            diagnostics.update(
                {
                    "o09": item.o09,
                    "_n": item.n,
                    "_org_ts": item.org_ts,
                    "dd": parsed.dd,
                    "positions": parsed.positions,
                    "total_space": parsed.total_space,
                }
            )
            raw["challenge"] = item.to_payload()
            raw["parsed"] = {
                "dd": parsed.dd,
                "positions": parsed.positions,
                "templateLength": len(parsed.template),
                "totalSpace": parsed.total_space,
            }

            solution = solve_gunslol_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("guns.lol PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "seal": solution.seal,
                "_oo": solution.oo,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {"seal": solution.seal, "_oo": solution.oo, "attempts": solution.attempts, "solve_ms": solution.took_ms}
            )

            ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit and verify_url:
                verify_data = self._submit_solution(
                    verify_url=verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(verify_data, dict) and (
                    verify_data.get("ok")
                    or verify_data.get("success")
                    or verify_data.get("status") in ("ok", "success", True)
                    or verify_data.get("token")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(verify_data, ticket)
                    diagnostics["submitted"] = True
                else:
                    errors.append("guns.lol verify rejected solution")
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            raw["challengeSource"] = "url"
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype.lower():
                return resp.json()
            return extract_gunslol_gs_sets(resp.text)
        raise ValueError("guns.lol requires challenge_json, challenge_file, challenge_url or page_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: GunsLolSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=solution.submit_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        return data
