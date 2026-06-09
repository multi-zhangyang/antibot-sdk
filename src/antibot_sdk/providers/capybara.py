from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
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

DEFAULT_DIFFICULTY = 3
DEFAULT_DURATION_SEC = 30
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_INSTANCE_ID = "guest"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class CapybaraPayloadToken:
    token: str
    challenge_id: str
    nonce: str
    expires_at_sec: int
    difficulty: int
    signature: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "id": self.challenge_id,
            "nonce": self.nonce,
            "expiresAtSec": self.expires_at_sec,
            "difficulty": self.difficulty,
            "signature": self.signature,
        }


@dataclass(slots=True)
class CapybaraChallenge:
    challenge_id: str
    nonce: str
    difficulty: int
    payload_token: str | None = None
    challenge_type: str = "pow"
    status: str | None = None
    progress: int | float | None = None
    expires_in: int | None = None
    raw: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.challenge_id,
            "nonce": self.nonce,
            "type": self.challenge_type,
            "difficulty": self.difficulty,
            "payloadToken": self.payload_token,
            "status": self.status,
            "progress": self.progress,
            "expiresIn": self.expires_in,
        }


@dataclass(slots=True)
class CapybaraSolution:
    challenge: CapybaraChallenge
    solution: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return build_capybara_verify_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.challenge.challenge_id,
            "solution": self.solution,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def capybara_hash_hex(nonce: str, solution: int | str) -> str:
    return hashlib.sha256(f"{nonce}{solution}".encode("utf-8")).hexdigest()


def capybara_hash_matches(hash_hex: str, difficulty: int) -> bool:
    difficulty = int(difficulty)
    if difficulty < 0 or difficulty > 64:
        raise ValueError("Capybara difficulty must be between 0 and 64 hex zeros")
    return str(hash_hex).lower().startswith("0" * difficulty)


def parse_capybara_payload_token(token: str) -> CapybaraPayloadToken:
    parts = str(token).strip().split(".")
    if len(parts) != 5:
        raise ValueError("Capybara payload_token must have 5 dot-separated parts")
    challenge_id, nonce, exp_raw, difficulty_raw, signature = parts
    if not challenge_id or not nonce or not signature:
        raise ValueError("Capybara payload_token has empty id/nonce/signature")
    try:
        expires_at_sec = int(exp_raw)
        difficulty = int(difficulty_raw)
    except ValueError as e:
        raise ValueError("Capybara payload_token exp/difficulty must be integers") from e
    if difficulty < 0 or difficulty > 64:
        raise ValueError("Capybara payload_token difficulty must be between 0 and 64")
    if len(signature) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in signature):
        raise ValueError("Capybara payload_token signature must be SHA-256 hex")
    return CapybaraPayloadToken(
        token=str(token).strip(),
        challenge_id=challenge_id,
        nonce=nonce,
        expires_at_sec=expires_at_sec,
        difficulty=difficulty,
        signature=signature.lower(),
    )


def sign_capybara_payload_token(
    challenge_id: str,
    nonce: str,
    expires_at_sec: int,
    difficulty: int,
    secret: str,
    *,
    instance_id: str = DEFAULT_INSTANCE_ID,
) -> str:
    sig = hashlib.sha256(
        f"{challenge_id}.{nonce}.{int(expires_at_sec)}.{int(difficulty)}.{instance_id}.{secret}".encode("utf-8")
    ).hexdigest()
    return f"{challenge_id}.{nonce}.{int(expires_at_sec)}.{int(difficulty)}.{sig}"


def verify_capybara_payload_token(
    token: str,
    secret: str,
    *,
    instance_id: str = DEFAULT_INSTANCE_ID,
    challenge: CapybaraChallenge | dict[str, Any] | None = None,
    now_sec: int | None = None,
    verify_expiry: bool = True,
) -> bool:
    try:
        parsed = parse_capybara_payload_token(token)
        if challenge is not None:
            item = parse_capybara_challenge(challenge)
            if (
                parsed.challenge_id != item.challenge_id
                or parsed.nonce != item.nonce
                or parsed.difficulty != item.difficulty
            ):
                return False
        if verify_expiry:
            now = int(now_sec if now_sec is not None else time.time())
            if now > parsed.expires_at_sec:
                return False
        expected = sign_capybara_payload_token(
            parsed.challenge_id,
            parsed.nonce,
            parsed.expires_at_sec,
            parsed.difficulty,
            secret,
            instance_id=instance_id,
        )
        return hmac.compare_digest(expected, parsed.token)
    except Exception:
        return False


def parse_capybara_challenge(value: CapybaraChallenge | dict[str, Any] | str) -> CapybaraChallenge:
    if isinstance(value, CapybaraChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Capybara challenge is empty")
        if text.startswith("@"):
            return parse_capybara_challenge(json.loads(Path(text[1:]).read_text(encoding="utf-8")))
        if text.startswith("{"):
            return parse_capybara_challenge(json.loads(text))
        token = parse_capybara_payload_token(text)
        return CapybaraChallenge(
            challenge_id=token.challenge_id,
            nonce=token.nonce,
            difficulty=token.difficulty,
            payload_token=token.token,
        )
    if not isinstance(value, dict):
        raise ValueError("Capybara challenge must be payload_token, JSON object or CapybaraChallenge")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    token_value = _first_str(value, "payload_token", "payloadToken") or _first_str(data, "payload_token", "payloadToken")
    token: CapybaraPayloadToken | None = None
    if token_value:
        token = parse_capybara_payload_token(token_value)

    challenge_id = _first_str(data, "id", "challenge_id", "challengeId") or (token.challenge_id if token else None)
    nonce = _first_str(data, "nonce") or (token.nonce if token else None)
    difficulty_value = data.get("difficulty", token.difficulty if token else DEFAULT_DIFFICULTY)
    if not challenge_id or not nonce:
        raise ValueError("Capybara challenge requires id and nonce")
    difficulty = int(difficulty_value)
    if difficulty < 0 or difficulty > 64:
        raise ValueError("Capybara difficulty must be between 0 and 64")
    if token and (token.challenge_id != challenge_id or token.nonce != nonce or token.difficulty != difficulty):
        raise ValueError("Capybara payload_token does not match challenge id/nonce/difficulty")
    return CapybaraChallenge(
        challenge_id=str(challenge_id),
        nonce=str(nonce),
        difficulty=difficulty,
        payload_token=token.token if token else token_value,
        challenge_type=str(data.get("type") or "pow"),
        status=str(value.get("status")) if value.get("status") is not None else None,
        progress=value.get("progress"),
        expires_in=int(value["expires_in"]) if value.get("expires_in") is not None else None,
        raw=value,
    )


def solve_capybara_challenge(
    challenge: CapybaraChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> CapybaraSolution | None:
    item = parse_capybara_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        solution, digest, checked = _solve_capybara_range(
            item.nonce,
            item.difficulty,
            start,
            start + max_attempts,
            deadline_epoch,
        )
        if solution is None or digest is None:
            return None
        return CapybaraSolution(item, str(solution), digest, checked, int((time.monotonic() - started) * 1000))

    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(_solve_capybara_range, item.nonce, item.difficulty, lo, hi, deadline_epoch): (lo, hi)
        for lo, hi in ranges
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            solution, digest, checked = fut.result()
            checked_total += checked
            if solution is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return CapybaraSolution(
                    item,
                    str(solution),
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


def verify_capybara_solution(
    challenge: CapybaraChallenge | dict[str, Any] | str,
    solution: CapybaraSolution | dict[str, Any] | str | int,
) -> bool:
    try:
        item = parse_capybara_challenge(challenge)
        if isinstance(solution, CapybaraSolution):
            value = solution.solution
            expected = solution.hash_hex
        elif isinstance(solution, dict):
            value = str(solution.get("solution") or solution.get("answer") or "")
            expected = str(solution.get("hash") or solution.get("hashHex") or "")
        else:
            value = str(solution)
            expected = ""
        if not value or len(value) > 64 or not value.isdigit():
            return False
        digest = capybara_hash_hex(item.nonce, value)
        if expected and digest != expected.lower():
            return False
        return capybara_hash_matches(digest, item.difficulty)
    except Exception:
        return False


def build_capybara_verify_body(
    challenge: CapybaraChallenge | dict[str, Any] | str,
    solution: CapybaraSolution | dict[str, Any] | str | int,
    *,
    include_payload_token: bool = True,
) -> dict[str, Any]:
    item = parse_capybara_challenge(challenge)
    if isinstance(solution, CapybaraSolution):
        value = solution.solution
    elif isinstance(solution, dict):
        value = str(solution.get("solution") or solution.get("answer") or "")
    else:
        value = str(solution)
    body: dict[str, Any] = {"id": item.challenge_id, "solution": value}
    if include_payload_token and item.payload_token:
        body["payload_token"] = item.payload_token
    return body


class CapybaraSolver:
    """Capybara-Captcha payload-token-bound SHA-256 hex-prefix PoW protocol solver."""

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
        payload_token: str | None = None,
        submit: bool = False,
        difficulty: int = DEFAULT_DIFFICULTY,
        duration_sec: int = DEFAULT_DURATION_SEC,
        secret: str | None = None,
        instance_id: str = DEFAULT_INSTANCE_ID,
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
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
            "instance_id": instance_id,
            "secret_provided": secret is not None,
        }
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "capybara_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="capybara",
                ok=ok,
                captcha_type="payload_bound_pow",
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
            source = _load_source(
                base_url=base_url,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                payload_token=payload_token,
                difficulty=difficulty,
                duration_sec=duration_sec,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            challenge = parse_capybara_challenge(source)
            raw["challenge"] = challenge.to_payload()
            diagnostics.update(
                {
                    "challenge_id": challenge.challenge_id,
                    "difficulty": challenge.difficulty,
                    "has_payload_token": bool(challenge.payload_token),
                    "expires_in": challenge.expires_in,
                    "status": challenge.status,
                }
            )
            if secret and challenge.payload_token:
                diagnostics["payload_signature_valid"] = verify_capybara_payload_token(
                    challenge.payload_token,
                    secret,
                    instance_id=instance_id,
                    challenge=challenge,
                )
                if not diagnostics["payload_signature_valid"]:
                    errors.append("Capybara payload_token signature is invalid")
                    return finish(ok=False, verify_code="payload_invalid")
            solution = solve_capybara_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Capybara solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_capybara_solution(challenge, solution):
                errors.append("Capybara internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            verify_body = build_capybara_verify_body(challenge, solution)
            raw["solution"] = {**solution.to_payload(), "verifyBody": verify_body}
            diagnostics.update(
                {
                    "solution": solution.solution,
                    "hash_hex": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            ticket = _json_body(verify_body)
            verify_code = "solved"
            final_verify_url = verify_url or (_join_base(base_url, "/api/verify") if base_url else None)
            if submit or verify_url or base_url:
                if not final_verify_url:
                    errors.append("submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp = requests.post(
                    final_verify_url,
                    data=_json_body(verify_body),
                    headers=_merge_headers(headers, user_agent),
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                try:
                    payload: Any = resp.json()
                except ValueError:
                    payload = {"text": resp.text[:500]}
                raw["verifyResponse"] = {"status": resp.status_code, "url": final_verify_url, "json": payload}
                if resp.status_code >= 400:
                    errors.append(str(payload))
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                verified = isinstance(payload, dict) and (
                    payload.get("verified") is True or payload.get("success") is True or payload.get("status") == "solved"
                )
                if not verified:
                    errors.append(str(payload))
                    return finish(ok=False, ticket=_json_body(payload) if isinstance(payload, dict) else str(payload), verify_code="not_verified")
                ticket = _json_body(payload) if isinstance(payload, dict) else str(payload)
                verify_code = "validated"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_capybara_range(
    nonce: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    prefix = str(nonce).encode("utf-8")
    zeros = "0" * int(difficulty)
    for solution in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha256(prefix + str(solution).encode("ascii")).hexdigest()
        checked += 1
        if digest.startswith(zeros):
            return solution, digest, checked
    return None, None, checked


def _load_source(
    *,
    base_url: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_url: str | None,
    payload_token: str | None,
    difficulty: int,
    duration_sec: int,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if payload_token:
        raw["challengeSource"] = "payload_token"
        return payload_token
    final_challenge_url = challenge_url or (_join_base(base_url, "/api/challenge") if base_url else None)
    if not final_challenge_url:
        raise ValueError("Capybara requires base_url, challenge_json, challenge_file, challenge_url or payload_token")
    resp = requests.post(
        final_challenge_url,
        data=_json_body({"difficulty": int(difficulty), "duration": int(duration_sec)}),
        headers=headers,
        timeout=timeout_sec,
        proxies=_requests_proxies(proxy_server),
    )
    raw["challengeResponse"] = {"status": resp.status_code, "url": final_challenge_url}
    try:
        payload = resp.json()
    except ValueError:
        payload = {"text": resp.text[:500]}
    raw["challengeResponse"]["json"] = payload
    resp.raise_for_status()
    raw["challengeSource"] = "url_json"
    return payload


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


def _first_str(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return None


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _join_base(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
