from __future__ import annotations

import asyncio
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt
import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

TYPE_EXACT = "exact"
TYPE_PREFIX = "prefix"
DEFAULT_COST = 12
DEFAULT_MAX_ATTEMPTS = 100_000
DEFAULT_TIMEOUT_SEC = 60
BCRYPT_MAX_PASSWORD_BYTES = 72
_BCRYPT_B64_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@dataclass(slots=True)
class PaulPowChallenge:
    hash: str
    salt: str
    captcha_type: str
    size: int
    cost: int = DEFAULT_COST
    token_signature: Any = None

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "hash": self.hash,
            "salt": self.salt,
            "captchaType": self.captcha_type,
            "size": self.size,
            "cost": self.cost,
        }
        if self.token_signature is not None:
            payload["tokenSignature"] = self.token_signature
        return payload


@dataclass(slots=True)
class PaulPowSolution:
    challenge: PaulPowChallenge
    nonce: int
    checked: int
    took_ms: int
    bcrypt_hash: str | None = None

    @property
    def submit_body(self) -> dict[str, Any]:
        # JSON form of upstream CaptchaServerInfo { client_info, nonce }.
        return {"clientInfo": self.challenge.to_payload(), "nonce": self.nonce}

    @property
    def nonce_body(self) -> dict[str, Any]:
        return {"salt": self.challenge.salt, "hash": self.challenge.hash, "nonce": self.nonce}


def bcrypt_base64_encode(raw: bytes) -> str:
    """Encode bytes with bcrypt's custom radix-64 alphabet."""

    out: list[str] = []
    i = 0
    while i < len(raw):
        c1 = raw[i]
        i += 1
        out.append(_BCRYPT_B64_ALPHABET[(c1 >> 2) & 0x3F])
        c1 = (c1 & 0x03) << 4
        if i >= len(raw):
            out.append(_BCRYPT_B64_ALPHABET[c1 & 0x3F])
            break
        c2 = raw[i]
        i += 1
        c1 |= (c2 >> 4) & 0x0F
        out.append(_BCRYPT_B64_ALPHABET[c1 & 0x3F])
        c1 = (c2 & 0x0F) << 2
        if i >= len(raw):
            out.append(_BCRYPT_B64_ALPHABET[c1 & 0x3F])
            break
        c2 = raw[i]
        i += 1
        c1 |= (c2 >> 6) & 0x03
        out.append(_BCRYPT_B64_ALPHABET[c1 & 0x3F])
        out.append(_BCRYPT_B64_ALPHABET[c2 & 0x3F])
    return "".join(out)


def paul_pow_password(salt: str, nonce: int | str) -> bytes:
    password = f"{salt}{int(nonce)}".encode("utf-8")
    if len(password) > BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError("bcrypt password exceeds 72 bytes; upstream bcrypt would be ambiguous")
    return password


def paul_pow_prefix_hash(salt: str, nonce: int | str, cost: int = DEFAULT_COST) -> str:
    salt_bytes = salt.encode("utf-8")
    if len(salt_bytes) < 16:
        raise ValueError("PaulDotSH prefix captcha salt must be at least 16 bytes")
    if int(cost) < 4 or int(cost) > 31:
        raise ValueError("bcrypt cost must be in 4..31")
    raw16 = salt_bytes[:16]
    bcrypt_salt = f"$2b${int(cost):02d}${bcrypt_base64_encode(raw16)}".encode("ascii")
    return bcrypt.hashpw(paul_pow_password(salt, nonce), bcrypt_salt).decode("ascii")


def verify_paul_pow_solution(
    challenge: PaulPowChallenge | dict[str, Any] | str,
    nonce: int | str | dict[str, Any],
) -> bool:
    try:
        item = parse_paul_pow_challenge(challenge)
        nonce_value = _extract_nonce(nonce)
        if item.captcha_type == TYPE_EXACT:
            return bcrypt.checkpw(paul_pow_password(item.salt, nonce_value), item.hash.encode("ascii"))
        candidate = paul_pow_prefix_hash(item.salt, nonce_value, item.cost)
        return candidate[: item.size] == item.hash[: item.size]
    except Exception:
        return False


def parse_paul_pow_challenge(value: PaulPowChallenge | dict[str, Any] | str) -> PaulPowChallenge:
    if isinstance(value, PaulPowChallenge):
        return value
    obj = _load_jsonish(value)
    if not isinstance(obj, dict):
        raise ValueError("PaulDotSH pow-captcha challenge must be a JSON object")
    if isinstance(obj.get("challenge"), dict):
        obj = obj["challenge"]
    if isinstance(obj.get("clientInfo"), dict):
        obj = obj["clientInfo"]
    if isinstance(obj.get("client_info"), dict):
        obj = obj["client_info"]

    raw_type = obj.get("captchaType", obj.get("captcha_type", obj.get("type", obj.get("captchaTypeName"))))
    captcha_type = _normalize_captcha_type(raw_type)
    hash_value = str(obj.get("hash") or "")
    salt = str(obj.get("salt") or "")
    size_value = obj.get("size", obj.get("challenge_size", obj.get("match_size")))
    cost = int(obj.get("cost", DEFAULT_COST))
    if not hash_value.startswith(("$2a$", "$2b$", "$2y$")):
        raise ValueError("PaulDotSH pow-captcha requires bcrypt hash")
    if not salt:
        raise ValueError("PaulDotSH pow-captcha requires salt")
    if size_value is None:
        raise ValueError("PaulDotSH pow-captcha requires size")
    size = int(size_value)
    if size <= 0:
        raise ValueError("PaulDotSH pow-captcha size must be positive")
    if cost < 4 or cost > 31:
        raise ValueError("bcrypt cost must be in 4..31")
    if captcha_type == TYPE_PREFIX and len(salt.encode("utf-8")) < 16:
        raise ValueError("prefix captcha salt must be at least 16 bytes")
    return PaulPowChallenge(
        hash=hash_value,
        salt=salt,
        captcha_type=captcha_type,
        size=size,
        cost=cost,
        token_signature=obj.get("tokenSignature", obj.get("token_signature")),
    )


def solve_paul_pow_challenge(
    challenge: PaulPowChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int | None = None,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PaulPowSolution | None:
    item = parse_paul_pow_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    if max_attempts is None:
        max_attempts = item.size + 1 if item.captcha_type == TYPE_EXACT else DEFAULT_MAX_ATTEMPTS
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 16:
        nonce, candidate, checked = _solve_paul_pow_range(item, start, start + max_attempts, deadline)
        if nonce is None:
            return None
        return PaulPowSolution(item, nonce, checked, int((time.monotonic() - started) * 1000), candidate)

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_paul_pow_range, item, lo, hi, deadline)] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, candidate, checked = fut.result()
            checked_total += checked
            if nonce is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return PaulPowSolution(
                    item,
                    nonce,
                    checked_total,
                    int((time.monotonic() - started) * 1000),
                    candidate,
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


def _solve_paul_pow_range(
    challenge: PaulPowChallenge,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    for nonce in range(int(start), int(end_exclusive)):
        if deadline is not None and time.monotonic() >= deadline:
            return None, None, checked
        if challenge.captcha_type == TYPE_EXACT:
            checked += 1
            if bcrypt.checkpw(paul_pow_password(challenge.salt, nonce), challenge.hash.encode("ascii")):
                return nonce, None, checked
            continue
        candidate = paul_pow_prefix_hash(challenge.salt, nonce, challenge.cost)
        checked += 1
        if candidate[: challenge.size] == challenge.hash[: challenge.size]:
            return nonce, candidate, checked
    return None, None, checked


def _normalize_captcha_type(value: Any) -> str:
    if value is None:
        raise ValueError("PaulDotSH pow-captcha requires captchaType")
    if isinstance(value, int):
        return TYPE_EXACT if value == 0 else TYPE_PREFIX if value == 1 else str(value)
    text = str(value).strip().lower()
    if text in {"exact", "captchaexact", "0"}:
        return TYPE_EXACT
    if text in {"prefix", "captchaprefix", "1"}:
        return TYPE_PREFIX
    raise ValueError("captchaType must be exact or prefix")


def _extract_nonce(value: int | str | dict[str, Any]) -> int:
    if isinstance(value, dict):
        value = value.get("nonce", value.get("solution", value.get("answer")))
    if value is None:
        raise ValueError("missing nonce")
    text = str(value)
    if text.startswith("+"):
        text = text[1:]
    if not text.isdigit():
        raise ValueError("nonce must be a non-negative decimal integer")
    return int(text)


def _load_jsonish(value: PaulPowChallenge | dict[str, Any] | str) -> Any:
    if isinstance(value, PaulPowChallenge):
        return value
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError("expected JSON object/string")
    text = value.strip()
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8")
    return json.loads(text)


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
        for key in ("token", "ticket", "message", "status"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


class PaulPowSolver:
    """PaulDotSH/pow-captcha bcrypt exact/prefix proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
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
                out = output_root / "paulpow_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="paulpow",
                ok=ok,
                captcha_type="bcrypt_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("salt"),
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
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_paul_pow_challenge(challenge_data)
            diagnostics.update(
                {
                    "captcha_type_mode": item.captcha_type,
                    "salt": item.salt,
                    "size": item.size,
                    "cost": item.cost,
                }
            )
            raw["challenge"] = item.to_payload()

            solution = solve_paul_pow_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("PaulDotSH bcrypt PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
                "bcryptHash": solution.bcrypt_hash,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {"nonce": str(solution.nonce), "checked": solution.checked, "solve_ms": solution.took_ms}
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
                    or verify_data.get("verify")
                    or verify_data.get("status") in ("ok", "success", True)
                    or verify_data.get("token")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(verify_data, ticket)
                    diagnostics["submitted"] = True
                else:
                    errors.append("PaulDotSH verify rejected solution")
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
            return resp.json()
        raise ValueError("PaulDotSH pow-captcha requires challenge_json, challenge_file or challenge_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PaulPowSolution,
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
