from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import random
import time
import uuid
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from Crypto.Cipher import AES

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://auro.network"
DEFAULT_MOUSE_POINTS = 50
DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_TIMEOUT_SEC = 60
GCM_NONCE_LEN = 12


@dataclass(slots=True)
class AuroPowChallenge:
    prefix: str
    difficulty: int
    client_guid: str = ""


@dataclass(slots=True)
class AuroEncryptedMouse:
    key_b64: str
    iv_b64: str
    encrypted_data_b64: str
    plaintext_json: str


@dataclass(slots=True)
class AuroPowSolution:
    challenge: AuroPowChallenge
    nonce: int
    hash_hex: str
    attempts: int
    took_ms: int

    @property
    def validate_body(self) -> dict[str, str]:
        return {"prefix": self.challenge.prefix, "nonce": str(self.nonce)}

    def validate_body_json(self) -> str:
        return json.dumps(self.validate_body, ensure_ascii=False, separators=(",", ":"))


def generate_auro_mouse_data(
    *,
    num_points: int = DEFAULT_MOUSE_POINTS,
    base_time_ms: int | None = None,
    seed: int | str | None = None,
    start_x: int = 200,
    start_y: int = 50,
) -> list[dict[str, int]]:
    """Generate compact mouse telemetry shaped like the Auro iframe client sends."""

    rng = random.Random(seed)
    now = int(time.time() * 1000) if base_time_ms is None else int(base_time_ms)
    x, y = int(start_x), int(start_y)
    points: list[dict[str, int]] = []
    t = now
    for _ in range(max(1, int(num_points))):
        x += rng.randint(-3, 3)
        y += rng.randint(-1, 2)
        x = max(50, min(400, x))
        y = max(10, min(300, y))
        t += rng.randint(1, 5)
        points.append({"x": x, "y": y, "t": t})
    return points


def jitter_auro_mouse_data(
    mouse_data: list[dict[str, int]],
    *,
    jitter_range: int = 2,
    time_jitter_ms: int = 3,
    seed: int | str | None = None,
) -> list[dict[str, int]]:
    rng = random.Random(seed)
    out: list[dict[str, int]] = []
    for point in mouse_data:
        out.append(
            {
                "x": max(0, int(point["x"]) + rng.randint(-jitter_range, jitter_range)),
                "y": max(0, int(point["y"]) + rng.randint(-jitter_range, jitter_range)),
                "t": int(point["t"]) + rng.randint(-time_jitter_ms, time_jitter_ms),
            }
        )
    out.sort(key=lambda p: p["t"])
    return out


def encrypt_auro_mouse_data(
    data: list[dict[str, Any]] | str,
    key_b64: str,
    *,
    iv_b64: str | None = None,
) -> AuroEncryptedMouse:
    """AES-GCM encrypt mouse JSON; output matches cryptography AESGCM ciphertext||tag."""

    plaintext_json = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    key = _b64decode(key_b64)
    if len(key) not in (16, 24, 32):
        raise ValueError("Auro AES-GCM key must decode to 16/24/32 bytes")
    iv = _b64decode(iv_b64) if iv_b64 else random.randbytes(GCM_NONCE_LEN)
    if len(iv) != GCM_NONCE_LEN:
        raise ValueError("Auro AES-GCM IV must be 12 bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_json.encode("utf-8"))
    return AuroEncryptedMouse(
        key_b64=key_b64,
        iv_b64=_b64encode(iv),
        encrypted_data_b64=_b64encode(ciphertext + tag),
        plaintext_json=plaintext_json,
    )


def decrypt_auro_mouse_data(encrypted_data_b64: str, key_b64: str, iv_b64: str) -> str:
    key = _b64decode(key_b64)
    iv = _b64decode(iv_b64)
    raw = _b64decode(encrypted_data_b64)
    if len(raw) < 16:
        raise ValueError("Auro encrypted mouse payload is too short")
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(raw[:-16], raw[-16:])
    return plaintext.decode("utf-8")


def auro_pow_hash_hex(prefix: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{prefix}{nonce}".encode("utf-8")).hexdigest()


def verify_auro_pow(prefix: str, difficulty: int, nonce: int | str, hash_hex: str | None = None) -> bool:
    try:
        digest = auro_pow_hash_hex(prefix, nonce)
        return (hash_hex is None or digest == str(hash_hex).lower()) and digest.startswith(
            "0" * max(0, int(difficulty))
        )
    except Exception:
        return False


def solve_auro_pow_challenge(
    challenge: AuroPowChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    client_guid: str | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> AuroPowSolution | None:
    item = parse_auro_pow_challenge(challenge, difficulty=difficulty, client_guid=client_guid)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, attempts = _solve_auro_pow_range(
            item.prefix,
            item.difficulty,
            start,
            start + max_attempts,
            deadline,
        )
        if nonce is None or digest is None:
            return None
        return AuroPowSolution(
            item,
            nonce,
            digest,
            attempts,
            int((time.monotonic() - started) * 1000),
        )

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_auro_pow_range, item.prefix, item.difficulty, lo, hi, deadline)] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, attempts = fut.result()
            checked_total += attempts
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return AuroPowSolution(
                    item,
                    nonce,
                    digest,
                    checked_total,
                    int((time.monotonic() - started) * 1000),
                )
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None


def parse_auro_pow_challenge(
    value: AuroPowChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    client_guid: str | None = None,
) -> AuroPowChallenge:
    if isinstance(value, AuroPowChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            obj = json.loads(Path(text[1:]).read_text(encoding="utf-8"))
        elif text.startswith("{"):
            obj = json.loads(text)
        else:
            if difficulty is None:
                raise ValueError("Auro inline prefix requires difficulty")
            return AuroPowChallenge(prefix=text, difficulty=int(difficulty), client_guid=client_guid or "")
    else:
        obj = dict(value)
    prefix = obj.get("prefix") or obj.get("p")
    if not prefix:
        raise ValueError("Auro PoW challenge requires prefix")
    diff = difficulty if difficulty is not None else obj.get("difficulty", obj.get("d"))
    if diff is None:
        raise ValueError("Auro PoW challenge requires difficulty")
    return AuroPowChallenge(
        prefix=str(prefix),
        difficulty=max(0, int(diff)),
        client_guid=str(client_guid or obj.get("client_guid") or obj.get("clientGuid") or ""),
    )


def _solve_auro_pow_range(
    prefix: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, str | None, int]:
    target = "0" * max(0, int(difficulty))
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, None, checked
        digest = auro_pow_hash_hex(prefix, nonce)
        checked += 1
        if digest.startswith(target):
            return nonce, digest, checked
    return None, None, checked


def _b64decode(value: str) -> bytes:
    text = str(value).strip()
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.b64decode(text.encode("ascii"), validate=True)


def _b64encode(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _infer_url(base_url: str | None, leaf: str) -> str | None:
    if not base_url:
        return None
    base = base_url.rstrip("/") + "/"
    return urljoin(base, leaf.lstrip("/"))


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


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


def _extract_token(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "captcha_token", "status", "message"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


class AuroSolver:
    """Auro.Network AES-GCM mouse telemetry + SHA-256 PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        enckey_url: str | None = None,
        setup_url: str | None = None,
        validate_url: str | None = None,
        key_b64: str | None = None,
        prefix: str | None = None,
        difficulty: int | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        mouse_json: Any = None,
        mouse_file: str | None = None,
        mouse_points: int = DEFAULT_MOUSE_POINTS,
        mouse_seed: int | str | None = None,
        iv_b64: str | None = None,
        client_guid: str | None = None,
        submit: bool = True,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        client_guid = client_guid or str(uuid.uuid4())
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        enckey_url = enckey_url or _infer_url(base_url, "/enckey")
        setup_url = setup_url or _infer_url(base_url, "/api/pow/setup")
        validate_url = validate_url or _infer_url(base_url, "/api/pow/validate")
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "enckey_url": enckey_url,
            "setup_url": setup_url,
            "validate_url": validate_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "client_guid": client_guid,
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
                out = output_root / "auro_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="auro",
                ok=ok,
                captcha_type="encrypted_behavior_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("prefix"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            loaded_challenge = challenge_json
            if isinstance(loaded_challenge, str):
                loaded_challenge = _load_json_arg(loaded_challenge)
            if loaded_challenge is None:
                loaded_challenge = _load_json_arg(None, challenge_file)
            if loaded_challenge is not None:
                parsed = parse_auro_pow_challenge(loaded_challenge, client_guid=client_guid)
                prefix = parsed.prefix
                difficulty = parsed.difficulty

            encrypted_mouse: AuroEncryptedMouse | None = None
            if not prefix or difficulty is None:
                if not key_b64:
                    key_b64 = self._fetch_key(
                        enckey_url=enckey_url,
                        client_guid=client_guid,
                        timeout_sec=timeout_sec,
                        proxy_server=proxy_server,
                        headers=headers,
                        raw=raw,
                    )
                mouse_data = self._load_mouse_data(
                    mouse_json=mouse_json,
                    mouse_file=mouse_file,
                    mouse_points=mouse_points,
                    mouse_seed=mouse_seed,
                )
                encrypted_mouse = encrypt_auro_mouse_data(mouse_data, key_b64, iv_b64=iv_b64)
                setup_data = self._submit_setup(
                    setup_url=setup_url,
                    encrypted=encrypted_mouse,
                    client_guid=client_guid,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                parsed = parse_auro_pow_challenge(setup_data, client_guid=client_guid)
                prefix = parsed.prefix
                difficulty = parsed.difficulty
                raw["mouse"] = {
                    "points": len(mouse_data),
                    "encryptedLength": len(encrypted_mouse.encrypted_data_b64),
                    "iv": encrypted_mouse.iv_b64,
                }

            challenge = AuroPowChallenge(prefix=str(prefix), difficulty=int(difficulty), client_guid=client_guid)
            diagnostics.update({"prefix": challenge.prefix, "difficulty": challenge.difficulty})
            raw["challenge"] = {
                "prefix": challenge.prefix,
                "difficulty": challenge.difficulty,
                "clientGuid": client_guid,
            }

            solution = solve_auro_pow_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Auro PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
            }
            raw["validateBody"] = solution.validate_body
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash_prefix": solution.hash_hex[: max(8, challenge.difficulty)],
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )

            ticket = solution.validate_body_json()
            verify_code = "solved"
            if submit and validate_url:
                validate_data = self._submit_validate(
                    validate_url=validate_url,
                    solution=solution,
                    client_guid=client_guid,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(validate_data, dict) and (
                    validate_data.get("ok")
                    or validate_data.get("success")
                    or validate_data.get("status") in ("success", "ok", True)
                    or validate_data.get("token")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(validate_data, ticket)
                    diagnostics["submitted"] = True
                else:
                    errors.append("Auro validate rejected solution")
                    return finish(ok=False, ticket=ticket, verify_code="validate_failed")
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _headers(self, *, url: str, client_guid: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        origin = _origin(url)
        return {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "origin": origin,
            "referer": urljoin(origin + "/", "iframe.html"),
            "x-client": client_guid,
            **(extra or {}),
        }

    def _fetch_key(
        self,
        *,
        enckey_url: str,
        client_guid: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> str:
        resp = requests.get(
            enckey_url,
            headers=self._headers(url=enckey_url, client_guid=client_guid, extra=headers),
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["enckeyResponse"] = {"status": resp.status_code, "url": resp.url}
        resp.raise_for_status()
        data = resp.json()
        key = data.get("key") if isinstance(data, dict) else None
        if not key:
            raise ValueError("Auro /enckey response missing key")
        raw["enckeyResponse"]["keyLength"] = len(str(key))
        return str(key)

    def _load_mouse_data(
        self,
        *,
        mouse_json: Any,
        mouse_file: str | None,
        mouse_points: int,
        mouse_seed: int | str | None,
    ) -> list[dict[str, Any]]:
        data = mouse_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, mouse_file)
        if data is None:
            base = generate_auro_mouse_data(num_points=mouse_points, seed=mouse_seed)
            return jitter_auro_mouse_data(base, seed=f"{mouse_seed}:jitter" if mouse_seed is not None else None)
        if not isinstance(data, list):
            raise ValueError("Auro mouse_json must be a list of points")
        return data

    def _submit_setup(
        self,
        *,
        setup_url: str,
        encrypted: AuroEncryptedMouse,
        client_guid: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            setup_url,
            headers=self._headers(url=setup_url, client_guid=client_guid, extra=headers),
            files={
                "mouse": (None, encrypted.encrypted_data_b64),
                "iv": (None, encrypted.iv_b64),
            },
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["setupResponse"] = {"status": resp.status_code, "url": setup_url}
        resp.raise_for_status()
        data = resp.json()
        raw["setupResponse"]["json"] = data
        return data

    def _submit_validate(
        self,
        *,
        validate_url: str,
        solution: AuroPowSolution,
        client_guid: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            validate_url,
            headers={
                "content-type": "application/json",
                **self._headers(url=validate_url, client_guid=client_guid, extra=headers),
            },
            json=solution.validate_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["validateResponse"] = {"status": resp.status_code, "url": validate_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["validateResponse"]["json"] = data
        return data
