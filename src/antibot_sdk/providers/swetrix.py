from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_API_URL = "https://api.swetrixcaptcha.com/v1/captcha"
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
DUMMY_ALWAYS_PASS_PID = "AP00000000000"
DUMMY_ALWAYS_PASS_SECRET = "PASS000000000000000000"


@dataclass(slots=True)
class SwetrixChallenge:
    challenge: str
    difficulty: int
    pid: str | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {"challenge": self.challenge, "difficulty": self.difficulty}
        if self.pid:
            out["pid"] = self.pid
        return out


@dataclass(slots=True)
class SwetrixSolution:
    challenge: SwetrixChallenge
    nonce: int
    solution: str
    leading_zero_nibbles: int
    attempts: int
    took_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "challenge": self.challenge.challenge,
            "nonce": self.nonce,
            "solution": self.solution,
        }
        if self.challenge.pid:
            body["pid"] = self.challenge.pid
        return body


def swetrix_hash_bytes(challenge: str, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{challenge}:{int(nonce)}".encode("utf-8")).digest()


def swetrix_hash_hex(challenge: str, nonce: int | str) -> str:
    return swetrix_hash_bytes(challenge, nonce).hex()


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
    full_zero_bytes = difficulty // 2
    if full_zero_bytes and digest[:full_zero_bytes] != b"\0" * full_zero_bytes:
        return False
    if difficulty % 2:
        return (digest[full_zero_bytes] >> 4) == 0
    return True


def parse_swetrix_challenge(
    value: SwetrixChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    pid: str | None = None,
) -> SwetrixChallenge:
    if isinstance(value, SwetrixChallenge):
        if pid and value.pid != pid:
            return SwetrixChallenge(value.challenge, value.difficulty, pid)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Swetrix challenge is empty")
        if text.startswith("@"):
            obj = json.loads(Path(text[1:]).read_text(encoding="utf-8"))
            return parse_swetrix_challenge(obj, difficulty=difficulty, pid=pid)
        if text.startswith("{"):
            return parse_swetrix_challenge(json.loads(text), difficulty=difficulty, pid=pid)
        if difficulty is None:
            raise ValueError("Swetrix inline challenge requires difficulty")
        return SwetrixChallenge(challenge=text, difficulty=max(0, int(difficulty)), pid=pid)
    if not isinstance(value, dict):
        raise ValueError("Swetrix challenge must be an object or challenge string")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge = data.get("challenge") or data.get("powChallenge") or data.get("id")
    if not challenge:
        raise ValueError("Swetrix challenge requires challenge")
    diff = difficulty if difficulty is not None else data.get("difficulty", data.get("diff"))
    if diff is None:
        raise ValueError("Swetrix challenge requires difficulty")
    challenge_pid = pid or data.get("pid") or data.get("projectId") or data.get("project_id")
    return SwetrixChallenge(
        challenge=str(challenge),
        difficulty=max(0, int(diff)),
        pid=str(challenge_pid) if challenge_pid else None,
    )


def solve_swetrix_challenge(
    challenge: SwetrixChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    pid: str | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> SwetrixSolution | None:
    item = parse_swetrix_challenge(challenge, difficulty=difficulty, pid=pid)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_swetrix_range(
            item.challenge,
            item.difficulty,
            start,
            start + max_attempts,
            deadline_epoch,
        )
        if nonce is None or digest is None:
            return None
        return SwetrixSolution(
            challenge=item,
            nonce=nonce,
            solution=digest.hex(),
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
        futures[pool.submit(_solve_swetrix_range, item.challenge, item.difficulty, lo, hi, deadline_epoch)] = idx

    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return SwetrixSolution(
                    challenge=item,
                    nonce=nonce,
                    solution=digest.hex(),
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


def verify_swetrix_solution(
    challenge: SwetrixChallenge | dict[str, Any] | str,
    solution: SwetrixSolution | dict[str, Any] | int | str,
    *,
    difficulty: int | None = None,
    pid: str | None = None,
) -> bool:
    try:
        item = parse_swetrix_challenge(challenge, difficulty=difficulty, pid=pid)
        if isinstance(solution, SwetrixSolution):
            nonce = solution.nonce
            solution_hex = solution.solution
        elif isinstance(solution, dict):
            nonce = int(solution.get("nonce", solution.get("pow_solution", solution.get("solution_nonce"))))
            solution_hex = str(solution.get("solution") or solution.get("hash") or "")
        else:
            nonce = int(solution)
            solution_hex = swetrix_hash_hex(item.challenge, nonce)
        if nonce < 0:
            return False
        digest = swetrix_hash_bytes(item.challenge, nonce)
        return digest.hex() == solution_hex.lower() and _digest_matches_hex_difficulty(digest, item.difficulty)
    except Exception:
        return False


def _solve_swetrix_range(
    challenge: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, bytes | None, int]:
    prefix = f"{challenge}:".encode("utf-8")
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha256(prefix + str(nonce).encode("ascii")).digest()
        checked += 1
        if _digest_matches_hex_difficulty(digest, difficulty):
            return nonce, digest, checked
    return None, None, checked


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
        "Origin": "https://cdn.swetrixcaptcha.com",
        "Referer": "https://cdn.swetrixcaptcha.com/",
    }
    if headers:
        out.update(headers)
    return out


def _derive_endpoint(api_url: str | None, explicit: str | None, path: str) -> str | None:
    if explicit:
        return explicit
    if not api_url:
        return None
    return urljoin(api_url.rstrip("/") + "/", path.lstrip("/"))


class SwetrixSolver:
    """Swetrix CAPTCHA SHA-256 proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        pid: str | None = None,
        api_url: str | None = DEFAULT_API_URL,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        validate_url: str | None = None,
        submit: bool = False,
        secret: str | None = None,
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
            "api_url": api_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "validate_url": validate_url,
            "pid": pid,
            "submit": submit,
            "validate": bool(secret),
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
                out = output_root / "swetrix_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="swetrix",
                ok=ok,
                captcha_type="swetrix_pow",
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
                pid=pid,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_endpoint(api_url, challenge_url, "/generate"),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_swetrix_challenge(challenge_data, pid=pid)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_present": bool(item.challenge),
                    "difficulty": item.difficulty,
                    "pid": item.pid,
                }
            )
            solution = solve_swetrix_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("swetrix solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "solution": solution.solution,
                "leadingZeroNibbles": solution.leading_zero_nibbles,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
                "submitBody": solution.submit_body,
            }
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "solution": solution.solution,
                    "leading_zero_nibbles": solution.leading_zero_nibbles,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = _json_body(solution.submit_body)
            verify_code = "solved"
            token: str | None = None
            if submit or verify_url:
                if not solution.challenge.pid:
                    errors.append("Swetrix submit requires pid/project id")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                effective_verify_url = _derive_endpoint(api_url, verify_url, "/verify")
                if not effective_verify_url:
                    errors.append("submit requested but verify_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = isinstance(verify_data, dict) and verify_data.get("success") is True
                if not ok:
                    reason = verify_data.get("message") if isinstance(verify_data, dict) else "verify_failed"
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                token = str(verify_data.get("token") or "") if isinstance(verify_data, dict) else ""
                ticket = token or ticket
                verify_code = "verified"
                diagnostics["submitted"] = True
                diagnostics["token_present"] = bool(token)
            if secret:
                if not token:
                    errors.append("Swetrix validate requires a token from /verify")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                effective_validate_url = _derive_endpoint(api_url, validate_url, "/validate")
                if not effective_validate_url:
                    errors.append("validate requested but validate_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                validate_data = self._validate_token(
                    validate_url=effective_validate_url,
                    token=token,
                    secret=secret,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = isinstance(validate_data, dict) and validate_data.get("success") is True
                if not ok:
                    reason = validate_data.get("message") if isinstance(validate_data, dict) else "validate_failed"
                    errors.append(str(reason or "validate_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="validate_failed")
                diagnostics["validated"] = True
                verify_code = "validated"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        pid: str | None,
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
            raise ValueError("swetrix requires pid+api_url, challenge_json, challenge_file or challenge_url")
        if not pid:
            raise ValueError("swetrix /generate requires pid/project id")
        resp = requests.post(
            challenge_url,
            data=_json_body({"pid": pid}),
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
        solution: SwetrixSolution,
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

    def _validate_token(
        self,
        *,
        validate_url: str,
        token: str,
        secret: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            validate_url,
            data=_json_body({"token": token, "secret": secret}),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["validateResponse"] = {"status": resp.status_code, "url": validate_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        raw["validateResponse"]["json"] = data
        resp.raise_for_status()
        return data
