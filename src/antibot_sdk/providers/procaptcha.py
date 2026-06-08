from __future__ import annotations

import asyncio
import hashlib
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

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

GET_POW_CAPTCHA_PATH = "/v1/prosopo/provider/client/captcha/pow"
SUBMIT_POW_CAPTCHA_PATH = "/v1/prosopo/provider/client/pow/solution"
DEFAULT_VERIFIED_TIMEOUT_MS = 120_000
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class ProcaptchaPowChallenge:
    challenge: str
    difficulty: int
    timestamp: str | None = None
    signature: dict[str, Any] = field(default_factory=dict)
    user: str | None = None
    dapp: str | None = None

    @property
    def provider_challenge_signature(self) -> str | None:
        provider = self.signature.get("provider") if isinstance(self.signature, dict) else None
        if isinstance(provider, dict):
            value = provider.get("challenge")
            return str(value) if value is not None else None
        return None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {"challenge": self.challenge, "difficulty": self.difficulty}
        if self.timestamp is not None:
            out["timestamp"] = self.timestamp
        if self.signature:
            out["signature"] = self.signature
        if self.user:
            out["user"] = self.user
        if self.dapp:
            out["dapp"] = self.dapp
        return out


@dataclass(slots=True)
class ProcaptchaPowSolution:
    challenge: ProcaptchaPowChallenge
    nonce: int
    hash_hex: str
    leading_zero_nibbles: int
    attempts: int
    took_ms: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge.challenge,
            "difficulty": self.challenge.difficulty,
            "nonce": self.nonce,
            "hashHex": self.hash_hex,
            "leadingZeroNibbles": self.leading_zero_nibbles,
            "attempts": self.attempts,
            "tookMs": self.took_ms,
        }


def procaptcha_pow_hash_bytes(challenge: str, nonce: int | str) -> bytes:
    """SHA-256(number-as-decimal || challenge) as used by @prosopo/util solvePoW."""

    return hashlib.sha256(f"{int(nonce)}{challenge}".encode("utf-8")).digest()


def procaptcha_pow_hash_hex(challenge: str, nonce: int | str) -> str:
    return procaptcha_pow_hash_bytes(challenge, nonce).hex()


def count_leading_zero_nibbles(data: bytes) -> int:
    total = 0
    for byte in data:
        high = byte >> 4
        if high != 0:
            break
        total += 1
        low = byte & 0x0F
        if low != 0:
            break
        total += 1
    return total


def _digest_matches_hex_difficulty(digest: bytes, difficulty: int) -> bool:
    difficulty = max(0, int(difficulty))
    if difficulty > 64:
        return False
    full_zero_bytes = difficulty // 2
    if full_zero_bytes and digest[:full_zero_bytes] != b"\0" * full_zero_bytes:
        return False
    if difficulty % 2:
        return (digest[full_zero_bytes] >> 4) == 0
    return True


def parse_procaptcha_pow_challenge(value: ProcaptchaPowChallenge | dict[str, Any] | str) -> ProcaptchaPowChallenge:
    if isinstance(value, ProcaptchaPowChallenge):
        _validate_difficulty(value.difficulty)
        if not value.challenge:
            raise ValueError("Procaptcha PoW challenge is empty")
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Procaptcha PoW challenge is empty")
        if text.startswith("@"):
            return parse_procaptcha_pow_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            return parse_procaptcha_pow_challenge(json.loads(text))
        raise ValueError("Procaptcha PoW inline string must be a JSON object or @file")
    if not isinstance(value, dict):
        raise ValueError("Procaptcha PoW challenge must be an object")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge = data.get("challenge") or data.get("powChallenge") or data.get("id")
    difficulty = data.get("difficulty")
    if difficulty is None:
        difficulty = data.get("diff")
    if not challenge:
        raise ValueError("Procaptcha PoW challenge requires challenge")
    if difficulty is None:
        raise ValueError("Procaptcha PoW challenge requires difficulty")
    item = ProcaptchaPowChallenge(
        challenge=str(challenge),
        difficulty=int(difficulty),
        timestamp=str(data["timestamp"]) if data.get("timestamp") is not None else None,
        signature=dict(data.get("signature") or {}),
        user=str(data["user"]) if data.get("user") is not None else None,
        dapp=str(data["dapp"]) if data.get("dapp") is not None else None,
    )
    _validate_difficulty(item.difficulty)
    return item


def solve_procaptcha_pow_challenge(
    challenge: ProcaptchaPowChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> ProcaptchaPowSolution | None:
    item = parse_procaptcha_pow_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_procaptcha_range(
            item.challenge,
            item.difficulty,
            start,
            start + max_attempts,
            deadline_epoch,
        )
        if nonce is None or digest is None:
            return None
        return ProcaptchaPowSolution(
            challenge=item,
            nonce=nonce,
            hash_hex=digest.hex(),
            leading_zero_nibbles=count_leading_zero_nibbles(digest),
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
        futures[pool.submit(_solve_procaptcha_range, item.challenge, item.difficulty, lo, hi, deadline_epoch)] = idx

    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return ProcaptchaPowSolution(
                    challenge=item,
                    nonce=nonce,
                    hash_hex=digest.hex(),
                    leading_zero_nibbles=count_leading_zero_nibbles(digest),
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


def verify_procaptcha_pow_solution(
    challenge: ProcaptchaPowChallenge | dict[str, Any] | str,
    solution: ProcaptchaPowSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_procaptcha_pow_challenge(challenge)
        hash_hex = ""
        if isinstance(solution, ProcaptchaPowSolution):
            nonce = solution.nonce
            hash_hex = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = int(solution.get("nonce", solution.get("solution", solution.get("pow_solution"))))
            hash_hex = str(solution.get("hashHex") or solution.get("hash") or "")
        else:
            nonce = int(solution)
        if nonce < 0:
            return False
        digest = procaptcha_pow_hash_bytes(item.challenge, nonce)
        if hash_hex and digest.hex() != hash_hex.lower():
            return False
        return _digest_matches_hex_difficulty(digest, item.difficulty)
    except Exception:
        return False


def build_procaptcha_pow_submit_body(
    challenge: ProcaptchaPowChallenge | dict[str, Any] | str,
    solution: ProcaptchaPowSolution | dict[str, Any] | int | str,
    *,
    user: str | None = None,
    dapp: str | None = None,
    user_timestamp_signature: str,
    verified_timeout: int | None = DEFAULT_VERIFIED_TIMEOUT_MS,
    provider_challenge_signature: str | None = None,
    behavioral_data: str | None = None,
    salt: str | None = None,
    simd_readings: str | None = None,
    client_meta_data: dict[str, Any] | None = None,
    include_timestamp: bool = False,
) -> dict[str, Any]:
    item = parse_procaptcha_pow_challenge(challenge)
    nonce = _solution_nonce(solution)
    if nonce < 0:
        raise ValueError("Procaptcha PoW nonce must be >= 0")
    effective_user = user or item.user
    effective_dapp = dapp or item.dapp
    if not effective_user:
        raise ValueError("Procaptcha PoW submit body requires user")
    if not effective_dapp:
        raise ValueError("Procaptcha PoW submit body requires dapp")
    provider_sig = provider_challenge_signature or item.provider_challenge_signature
    if not provider_sig:
        raise ValueError("Procaptcha PoW submit body requires provider challenge signature")
    body: dict[str, Any] = {
        "challenge": item.challenge,
        "difficulty": item.difficulty,
        "signature": {
            "provider": {"challenge": provider_sig},
            "user": {"timestamp": str(user_timestamp_signature)},
        },
        "user": str(effective_user),
        "dapp": str(effective_dapp),
        "nonce": nonce,
    }
    if include_timestamp and item.timestamp is not None:
        body["timestamp"] = item.timestamp
    if verified_timeout is not None:
        body["verifiedTimeout"] = int(verified_timeout)
    if behavioral_data:
        body["behavioralData"] = behavioral_data
    if salt:
        body["salt"] = salt
    if simd_readings:
        body["simdReadings"] = simd_readings
    if client_meta_data:
        body["clientMetaData"] = client_meta_data
    return body


def _solution_nonce(solution: ProcaptchaPowSolution | dict[str, Any] | int | str) -> int:
    if isinstance(solution, ProcaptchaPowSolution):
        return int(solution.nonce)
    if isinstance(solution, dict):
        return int(solution.get("nonce", solution.get("solution", solution.get("pow_solution"))))
    return int(solution)


def _solve_procaptcha_range(
    challenge: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, bytes | None, int]:
    challenge_bytes = challenge.encode("utf-8")
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha256(str(nonce).encode("ascii") + challenge_bytes).digest()
        checked += 1
        if _digest_matches_hex_difficulty(digest, difficulty):
            return nonce, digest, checked
    return None, None, checked


def _validate_difficulty(difficulty: int) -> None:
    if int(difficulty) < 0 or int(difficulty) > 64:
        raise ValueError("Procaptcha PoW difficulty must be between 0 and 64 hex nibbles")


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


def _merge_headers(
    *,
    site_key: str | None = None,
    user: str | None = None,
    headers: dict[str, str] | None = None,
    user_agent: str | None = None,
) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if site_key:
        out["Prosopo-Site-Key"] = site_key
    if user:
        out["Prosopo-User"] = user
    if headers:
        out.update(headers)
    return out


def _derive_url(base_url: str | None, explicit: str | None, path: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


class ProcaptchaSolver:
    """Prosopo Procaptcha PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        provider_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        site_key: str | None = None,
        user: str | None = None,
        dapp: str | None = None,
        session_id: str | None = None,
        submit: bool = False,
        user_timestamp_signature: str | None = None,
        verified_timeout: int | None = DEFAULT_VERIFIED_TIMEOUT_MS,
        provider_challenge_signature: str | None = None,
        behavioral_data: str | None = None,
        salt: str | None = None,
        simd_readings: str | None = None,
        client_meta_json: Any = None,
        client_meta_file: str | None = None,
        include_timestamp: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
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
            "provider_url": provider_url,
            "challenge_url": challenge_url,
            "submit_url": submit_url,
            "submit": submit,
            "site_key_present": bool(site_key),
            "user_present": bool(user),
            "dapp_present": bool(dapp),
            "session_id_present": bool(session_id),
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
                out = output_root / "procaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="procaptcha",
                ok=ok,
                captcha_type="prosopo_pow",
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
            effective_site_key = site_key or dapp
            request_headers = _merge_headers(site_key=effective_site_key, user=user, headers=headers, user_agent=user_agent)
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_url(provider_url, challenge_url, GET_POW_CAPTCHA_PATH),
                user=user,
                dapp=dapp,
                session_id=session_id,
                simd_readings=simd_readings,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_procaptcha_pow_challenge(challenge_data)
            if user and item.user is None:
                item.user = user
            if dapp and item.dapp is None:
                item.dapp = dapp
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "difficulty": item.difficulty,
                    "timestamp_present": bool(item.timestamp),
                    "provider_signature_present": bool(provider_challenge_signature or item.provider_challenge_signature),
                }
            )
            solution = solve_procaptcha_pow_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Procaptcha PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw_solution = solution.to_payload()
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash_hex": solution.hash_hex,
                    "leading_zero_nibbles": solution.leading_zero_nibbles,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket_payload: dict[str, Any] = raw_solution.copy()
            submit_body: dict[str, Any] | None = None
            if user_timestamp_signature:
                submit_body = build_procaptcha_pow_submit_body(
                    item,
                    solution,
                    user=user,
                    dapp=dapp,
                    user_timestamp_signature=user_timestamp_signature,
                    verified_timeout=verified_timeout,
                    provider_challenge_signature=provider_challenge_signature,
                    behavioral_data=behavioral_data,
                    salt=salt,
                    simd_readings=simd_readings,
                    client_meta_data=_load_json_arg(client_meta_json, client_meta_file),
                    include_timestamp=include_timestamp,
                )
                raw_solution["submitBody"] = submit_body
                ticket_payload = submit_body
            raw["solution"] = raw_solution
            ticket = _json_body(ticket_payload)
            verify_code = "solved"
            if submit or submit_url:
                if submit_body is None:
                    errors.append(
                        "Procaptcha submit requires user, dapp, user_timestamp_signature and provider challenge signature"
                    )
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                effective_submit_url = _derive_url(provider_url, submit_url, SUBMIT_POW_CAPTCHA_PATH)
                if not effective_submit_url:
                    errors.append("submit requested but submit_url/provider_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    submit_url=effective_submit_url,
                    submit_body=submit_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                if isinstance(verify_data, dict) and verify_data.get("escalation"):
                    diagnostics["escalation"] = verify_data.get("escalation")
                ok = isinstance(verify_data, dict) and (verify_data.get("verified") is True or verify_data.get("success") is True)
                if not ok:
                    reason = None
                    if isinstance(verify_data, dict):
                        error_obj = verify_data.get("error")
                        reason = error_obj.get("message") if isinstance(error_obj, dict) else error_obj
                        reason = reason or verify_data.get("message") or verify_data.get("reason")
                    errors.append(str(reason or "verify_failed"))
                    code = "escalated" if isinstance(verify_data, dict) and verify_data.get("escalation") else "verify_failed"
                    return finish(ok=False, ticket=ticket, verify_code=code)
                verify_code = "validated"
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
        user: str | None,
        dapp: str | None,
        session_id: str | None,
        simd_readings: str | None,
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
            raise ValueError("Procaptcha requires challenge_json, challenge_file, challenge_url or provider_url")
        if not user or not dapp:
            raise ValueError("Procaptcha challenge_url requires user and dapp")
        body: dict[str, Any] = {"user": user, "dapp": dapp}
        if session_id:
            body["sessionId"] = session_id
        if simd_readings:
            body["simdReadings"] = simd_readings
        resp = requests.post(
            challenge_url,
            data=_json_body(body),
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
        submit_url: str,
        submit_body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            submit_url,
            data=_json_body(submit_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": submit_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        resp.raise_for_status()
        return data
