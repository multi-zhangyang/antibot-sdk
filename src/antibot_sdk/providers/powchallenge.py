from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from argon2 import low_level as argon2_low_level

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 19_456  # KiB, upstream powchallenge-server/client-js value.
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
NONCE_DEFAULT_BYTES = 32
NONCE_MAX_BYTES = 64
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class PowChallengeChallenge:
    req_id: str
    challenge: str
    difficulty: int

    @property
    def challenge_bytes(self) -> bytes:
        raw = decode_powchallenge_base64(self.challenge)
        if len(raw) != 32:
            raise ValueError("POWChallenge challenge must decode to 32 bytes")
        return raw

    def to_payload(self) -> dict[str, Any]:
        return {"req_id": self.req_id, "challenge": self.challenge, "difficulty": self.difficulty}


@dataclass(slots=True)
class PowChallengeSolution:
    challenge: PowChallengeChallenge
    nonce_b64: str
    hash_hex: str
    leading_zero_bits: int
    attempts: int
    took_ms: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def nonce_bytes(self) -> bytes:
        return decode_powchallenge_base64(self.nonce_b64)

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "req_id": self.challenge.req_id,
            "challenge": self.challenge.challenge,
            "timestamp": self.timestamp,
            "difficulty": self.challenge.difficulty,
            "nonce": self.nonce_b64,
        }


def decode_powchallenge_base64(value: str) -> bytes:
    """Decode standard or URL-safe base64, accepting missing padding.

    The Python server decodes with ``base64.b64decode`` while the demo HTML names
    its helper ``uint8ArrayToBase64Url`` and strips padding. Accept both shapes in
    SDK helpers, but the solver emits standard padded base64 for maximum server
    compatibility.
    """

    text = str(value).strip()
    if not text:
        raise ValueError("base64 value is empty")
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        if "-" in text or "_" in text:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 value") from exc


def encode_powchallenge_base64(value: bytes, *, urlsafe: bool = False, padding: bool = True) -> str:
    raw = bytes(value)
    text = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
    return text if padding else text.rstrip("=")


def powchallenge_nonce_bytes(counter: int, *, seed: bytes | str | None = None, length: int = NONCE_DEFAULT_BYTES) -> bytes:
    """Return the nonce candidate for a deterministic counter.

    Without a seed this is ``counter.to_bytes(32, 'little')``. With a seed it
    mirrors browser miners that increment a random byte array in little-endian
    order, while staying deterministic and resumable from ``--start``.
    """

    if length < 1 or length > NONCE_MAX_BYTES:
        raise ValueError("nonce length must be between 1 and 64 bytes")
    value = int(counter)
    if value < 0:
        raise ValueError("counter must be >= 0")
    if seed is None:
        return value.to_bytes(length, "little", signed=False)
    seed_bytes = parse_powchallenge_nonce(seed)
    if len(seed_bytes) > NONCE_MAX_BYTES:
        raise ValueError("nonce seed exceeds 64 bytes")
    if len(seed_bytes) < length:
        seed_bytes = seed_bytes + b"\0" * (length - len(seed_bytes))
    elif len(seed_bytes) > length:
        seed_bytes = seed_bytes[:length]
    modulus = 1 << (8 * length)
    mixed = (int.from_bytes(seed_bytes, "little") + value) % modulus
    return mixed.to_bytes(length, "little", signed=False)


def parse_powchallenge_nonce(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value).strip()
    if not text:
        raise ValueError("nonce is empty")
    if text.startswith("0x"):
        text = text[2:]
        if len(text) % 2:
            text = "0" + text
        return bytes.fromhex(text)
    if len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    # Upstream wire-format nonce is base64/base64url. Hex is accepted for
    # fixtures/seeds; 64 hex chars is common for a 32-byte nonce seed.
    try:
        return decode_powchallenge_base64(text)
    except ValueError:
        if len(text) % 2 == 0:
            try:
                return bytes.fromhex(text)
            except ValueError:
                pass
        raise


def count_leading_zero_bits(data: bytes) -> int:
    count = 0
    for byte in data:
        if byte == 0:
            count += 8
            continue
        for bit in range(7, -1, -1):
            if ((byte >> bit) & 1) == 0:
                count += 1
            else:
                return count
        return count
    return count


def powchallenge_argon2_hash_bytes(
    challenge: PowChallengeChallenge | dict[str, Any] | str,
    nonce: bytes | bytearray | str,
) -> bytes:
    item = parse_powchallenge_challenge(challenge)
    nonce_bytes = parse_powchallenge_nonce(nonce)
    if not nonce_bytes or len(nonce_bytes) > NONCE_MAX_BYTES:
        raise ValueError("POWChallenge nonce must be 1..64 bytes")
    return argon2_low_level.hash_secret_raw(
        secret=nonce_bytes,
        salt=item.challenge_bytes,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=argon2_low_level.Type.ID,
    )


def powchallenge_hash_hex(challenge: PowChallengeChallenge | dict[str, Any] | str, nonce: bytes | bytearray | str) -> str:
    return powchallenge_argon2_hash_bytes(challenge, nonce).hex()


def parse_powchallenge_challenge(value: PowChallengeChallenge | dict[str, Any] | str) -> PowChallengeChallenge:
    if isinstance(value, PowChallengeChallenge):
        value.challenge_bytes
        _validate_difficulty(value.difficulty)
        if not value.req_id:
            raise ValueError("POWChallenge req_id is required")
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("POWChallenge challenge is empty")
        if text.startswith("@"):
            return parse_powchallenge_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            return parse_powchallenge_challenge(json.loads(text))
        raise ValueError("POWChallenge inline string must be a JSON object or @file")
    if not isinstance(value, dict):
        raise ValueError("POWChallenge challenge must be an object")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge = data.get("challenge") or data.get("challenge_b64") or data.get("challengeB64")
    req_id = data.get("req_id") or data.get("reqId") or data.get("id")
    difficulty = data.get("difficulty") or data.get("difficulty_bits") or data.get("difficultyBits")
    if not challenge:
        raise ValueError("POWChallenge challenge requires challenge")
    if not req_id:
        raise ValueError("POWChallenge challenge requires req_id")
    if difficulty is None:
        raise ValueError("POWChallenge challenge requires difficulty")
    item = PowChallengeChallenge(req_id=str(req_id), challenge=str(challenge), difficulty=int(difficulty))
    item.challenge_bytes
    _validate_difficulty(item.difficulty)
    return item


def solve_powchallenge_challenge(
    challenge: PowChallengeChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
    nonce_seed: bytes | str | None = None,
    nonce_length: int = NONCE_DEFAULT_BYTES,
) -> PowChallengeSolution | None:
    item = parse_powchallenge_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    nonce_length = max(1, min(NONCE_MAX_BYTES, int(nonce_length)))
    seed_bytes = parse_powchallenge_nonce(nonce_seed) if nonce_seed is not None else None
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 8:
        nonce_b64, digest, checked = _solve_powchallenge_range(
            item,
            start,
            start + max_attempts,
            deadline,
            seed_bytes,
            nonce_length,
        )
        if nonce_b64 is None or digest is None:
            return None
        return PowChallengeSolution(
            challenge=item,
            nonce_b64=nonce_b64,
            hash_hex=digest.hex(),
            leading_zero_bits=count_leading_zero_bits(digest),
            attempts=checked,
            took_ms=int((time.monotonic() - started) * 1000),
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
        futures[pool.submit(_solve_powchallenge_range, item, lo, hi, deadline, seed_bytes, nonce_length)] = idx

    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce_b64, digest, checked = fut.result()
            checked_total += checked
            if nonce_b64 is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return PowChallengeSolution(
                    challenge=item,
                    nonce_b64=nonce_b64,
                    hash_hex=digest.hex(),
                    leading_zero_bits=count_leading_zero_bits(digest),
                    attempts=checked_total,
                    took_ms=int((time.monotonic() - started) * 1000),
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


def verify_powchallenge_solution(
    challenge: PowChallengeChallenge | dict[str, Any] | str,
    solution: PowChallengeSolution | dict[str, Any] | bytes | bytearray | str,
) -> bool:
    try:
        item = parse_powchallenge_challenge(challenge)
        if isinstance(solution, PowChallengeSolution):
            nonce = solution.nonce_b64
            hash_hex = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = solution.get("nonce") or solution.get("nonce_b64") or solution.get("nonceB64")
            hash_hex = str(solution.get("hash") or solution.get("hash_hex") or solution.get("hashHex") or "")
            if not nonce:
                return False
        else:
            nonce = solution
            hash_hex = ""
        digest = powchallenge_argon2_hash_bytes(item, nonce)
        if hash_hex and digest.hex() != hash_hex.lower():
            return False
        return count_leading_zero_bits(digest) >= item.difficulty
    except Exception:
        return False


def _solve_powchallenge_range(
    item: PowChallengeChallenge,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
    nonce_seed: bytes | None = None,
    nonce_length: int = NONCE_DEFAULT_BYTES,
) -> tuple[str | None, bytes | None, int]:
    challenge_bytes = item.challenge_bytes
    checked = 0
    for counter in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 4 == 0 and time.monotonic() >= deadline:
            return None, None, checked
        nonce_bytes = powchallenge_nonce_bytes(counter, seed=nonce_seed, length=nonce_length)
        digest = argon2_low_level.hash_secret_raw(
            secret=nonce_bytes,
            salt=challenge_bytes,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=argon2_low_level.Type.ID,
        )
        checked += 1
        if count_leading_zero_bits(digest) >= item.difficulty:
            return encode_powchallenge_base64(nonce_bytes), digest, checked
    return None, None, checked


def _validate_difficulty(value: int) -> None:
    difficulty = int(value)
    if difficulty < 1 or difficulty > ARGON2_HASH_LEN * 8:
        raise ValueError("POWChallenge difficulty must be between 1 and 256")


def _load_json_arg(value: Any = None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return None
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _derive_endpoint(base_url: str | None, explicit: str | None, path: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


class PowChallengeSolver:
    """powchallenge-server Argon2id memory-hard proof-of-work solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        nonce_seed: bytes | str | None = None,
        nonce_length: int = NONCE_DEFAULT_BYTES,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
            "nonce_length": nonce_length,
            "argon2": {
                "type": "id",
                "time_cost": ARGON2_TIME_COST,
                "memory_cost_kib": ARGON2_MEMORY_COST,
                "parallelism": ARGON2_PARALLELISM,
                "hash_len": ARGON2_HASH_LEN,
            },
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
                out = output_root / "powchallenge_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powchallenge",
                ok=ok,
                captcha_type="argon2id_memory_pow",
                capability="protocol_solver",
                ticket=ticket,
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            request_headers = _merge_headers(headers, user_agent)
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_endpoint(base_url, challenge_url, "/challenge"),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_powchallenge_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "req_id": item.req_id,
                    "difficulty": item.difficulty,
                    "challenge_bytes": len(item.challenge_bytes),
                }
            )
            solution = solve_powchallenge_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
                nonce_seed=nonce_seed,
                nonce_length=nonce_length,
            )
            if solution is None:
                errors.append("powchallenge solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce_b64,
                "hash": solution.hash_hex,
                "leadingZeroBits": solution.leading_zero_bits,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
                "submitBody": solution.submit_body,
            }
            diagnostics.update(
                {
                    "nonce": solution.nonce_b64,
                    "hash": solution.hash_hex,
                    "leading_zero_bits": solution.leading_zero_bits,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = _json_body(solution.submit_body)
            verify_code = "solved"
            if submit or verify_url:
                effective_verify_url = _derive_endpoint(base_url, verify_url, "/verify")
                if not effective_verify_url:
                    errors.append("submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                if isinstance(verify_data, dict) and (
                    verify_data.get("success") is False or verify_data.get("ok") is False or verify_data.get("error")
                ):
                    reason = verify_data.get("error") or verify_data.get("message") or "verify_failed"
                    errors.append(str(reason))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                verify_code = "validated"
                diagnostics["submitted"] = True
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
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("powchallenge requires base_url, challenge_json, challenge_file or challenge_url")
        resp = requests.get(
            challenge_url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        raw["challengeResponse"]["json"] = payload
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return payload

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PowChallengeSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            data=_json_body(solution.submit_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        resp.raise_for_status()
        return data
