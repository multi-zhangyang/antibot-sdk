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
from urllib.parse import quote, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_COMPLEXITY = 2
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class LaptiChallenge:
    token: str
    complexity: int
    data: str | None = None
    raw: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        return {"token": self.token, "complexity": self.complexity, "data": self.data}


@dataclass(slots=True)
class LaptiSolution:
    challenge: LaptiChallenge
    nonce: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def action_path(self) -> str | None:
        if self.challenge.data is None:
            return None
        return build_lapti_action_path(self.challenge.data, self.nonce)

    def to_payload(self) -> dict[str, Any]:
        return {
            "data": self.challenge.data,
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "actionPath": self.action_path,
        }


def lapti_token_for_data(data: str, secret: str) -> str:
    return hashlib.sha3_512(f"{data}{secret}".encode("utf-8")).hexdigest()


def lapti_proof_hash_hex(token: str, nonce: int | str) -> str:
    return hashlib.sha3_512(f"{token}{nonce}".encode("utf-8")).hexdigest()


def lapti_hash_matches(hash_hex: str, complexity: int) -> bool:
    complexity = int(complexity)
    if complexity < 0 or complexity > 64:
        raise ValueError("Lapti complexity must be between 0 and 64 zero bytes")
    # Upstream parseHexString(...).slice(0, complexity).reduce(sum, 0) === 0,
    # i.e. the first `complexity` bytes of SHA3-512(token+nonce) must be 0x00.
    return str(hash_hex).lower().startswith("00" * complexity)


def verify_lapti_token(token: str, data: str, secret: str) -> bool:
    try:
        return hmac.compare_digest(str(token).lower(), lapti_token_for_data(data, secret))
    except Exception:
        return False


def parse_lapti_challenge(
    value: LaptiChallenge | dict[str, Any] | str,
    *,
    data: str | None = None,
) -> LaptiChallenge:
    if isinstance(value, LaptiChallenge):
        if data is not None and value.data != data:
            return LaptiChallenge(token=value.token, complexity=value.complexity, data=data, raw=value.raw)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Lapti challenge is empty")
        if text.startswith("@"):
            return parse_lapti_challenge(json.loads(Path(text[1:]).read_text(encoding="utf-8")), data=data)
        if text.startswith("{"):
            return parse_lapti_challenge(json.loads(text), data=data)
        token = text
        complexity = DEFAULT_COMPLEXITY
        raw = None
    elif isinstance(value, dict):
        item = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
        token = _first_str(item, "token", "hash", "challenge")
        if not token:
            raise ValueError("Lapti challenge JSON requires token")
        complexity = int(item.get("complexity", item.get("difficulty", DEFAULT_COMPLEXITY)))
        if data is None:
            data = _first_str(item, "data", "payload", "clientData") or _first_str(value, "data", "payload", "clientData")
        raw = value
    else:
        raise ValueError("Lapti challenge must be token string, JSON object or LaptiChallenge")
    token = str(token).strip().lower()
    if len(token) != 128 or any(ch not in "0123456789abcdef" for ch in token):
        raise ValueError("Lapti token must be SHA3-512 hex")
    if complexity < 0 or complexity > 64:
        raise ValueError("Lapti complexity must be between 0 and 64")
    return LaptiChallenge(token=token, complexity=complexity, data=data, raw=raw)


def solve_lapti_challenge(
    challenge: LaptiChallenge | dict[str, Any] | str,
    *,
    data: str | None = None,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> LaptiSolution | None:
    item = parse_lapti_challenge(challenge, data=data)
    started = time.monotonic()
    start = max(1, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_lapti_range(item.token, item.complexity, start, start + max_attempts, deadline_epoch)
        if nonce is None or digest is None:
            return None
        return LaptiSolution(item, str(nonce), digest, checked, int((time.monotonic() - started) * 1000))

    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {pool.submit(_solve_lapti_range, item.token, item.complexity, lo, hi, deadline_epoch): (lo, hi) for lo, hi in ranges}
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return LaptiSolution(
                    item,
                    str(nonce),
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


def verify_lapti_solution(
    challenge: LaptiChallenge | dict[str, Any] | str,
    solution: LaptiSolution | dict[str, Any] | str | int,
    *,
    data: str | None = None,
    secret: str | None = None,
) -> bool:
    try:
        item = parse_lapti_challenge(challenge, data=data)
        if secret and item.data is not None and not verify_lapti_token(item.token, item.data, secret):
            return False
        if isinstance(solution, LaptiSolution):
            nonce = solution.nonce
            expected = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = str(solution.get("nonce") or solution.get("proof") or "")
            expected = str(solution.get("hash") or solution.get("hashHex") or "")
        else:
            nonce = str(solution)
            expected = ""
        if not nonce or len(nonce) > 64 or not nonce.isdigit():
            return False
        digest = lapti_proof_hash_hex(item.token, nonce)
        if expected and digest != expected.lower():
            return False
        return lapti_hash_matches(digest, item.complexity)
    except Exception:
        return False


def build_lapti_action_path(data: str, nonce: int | str) -> str:
    return f"/action/{quote(str(data), safe='')}/{quote(str(nonce), safe='')}"


class LaptiSolver:
    """Lapti SHA3 token-bound proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        data: str | None = None,
        token: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        base_url: str | None = None,
        handshake_url: str | None = None,
        action_url: str | None = None,
        submit: bool = False,
        secret: str | None = None,
        start: int = 1,
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
            "handshake_url": handshake_url,
            "action_url": action_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
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
                out = output_root / "lapti_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="lapti",
                ok=ok,
                captcha_type="sha3_token_pow",
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
                data=data,
                token=token,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                base_url=base_url,
                handshake_url=handshake_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            challenge = parse_lapti_challenge(source, data=data)
            raw["challenge"] = challenge.to_payload()
            diagnostics.update({"complexity": challenge.complexity, "data_present": challenge.data is not None})
            if secret and challenge.data is not None:
                diagnostics["token_valid"] = verify_lapti_token(challenge.token, challenge.data, secret)
                if not diagnostics["token_valid"]:
                    errors.append("Lapti token is invalid for supplied data/secret")
                    return finish(ok=False, verify_code="token_invalid")
            solution = solve_lapti_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Lapti solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_lapti_solution(challenge, solution, secret=secret):
                errors.append("Lapti internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            raw["solution"] = solution.to_payload()
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash_hex": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            ticket = _json_body(solution.to_payload())
            verify_code = "solved"
            final_action_url = action_url
            if not final_action_url and base_url and challenge.data is not None:
                final_action_url = urljoin(base_url.rstrip("/") + "/", build_lapti_action_path(challenge.data, solution.nonce).lstrip("/"))
            if submit or action_url:
                if not final_action_url:
                    errors.append("submit requested but action_url/base_url+data is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp = requests.get(final_action_url, headers=_merge_headers(headers, user_agent), timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
                try:
                    payload: Any = resp.json()
                except ValueError:
                    payload = {"text": resp.text[:500]}
                raw["actionResponse"] = {"status": resp.status_code, "url": final_action_url, "json": payload}
                if resp.status_code >= 400:
                    errors.append(str(payload))
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                ticket = _json_body(payload) if isinstance(payload, dict) else str(payload)
                verify_code = "validated"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_lapti_range(
    token: str,
    complexity: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    prefix = str(token).encode("ascii")
    zeros = "00" * int(complexity)
    for nonce in range(max(1, int(start)), max(1, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha3_512(prefix + str(nonce).encode("ascii")).hexdigest()
        checked += 1
        if digest.startswith(zeros):
            return nonce, digest, checked
    return None, None, checked


def _load_source(
    *,
    data: str | None,
    token: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    base_url: str | None,
    handshake_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    payload = _load_json_arg(challenge_json, challenge_file)
    if payload is not None:
        raw["challengeSource"] = "json"
        return payload
    if token:
        raw["challengeSource"] = "token"
        return {"token": token, "complexity": DEFAULT_COMPLEXITY, "data": data}
    if not data:
        raise ValueError("Lapti requires data when fetching handshake or solving token-bound action")
    final_handshake_url = handshake_url or (urljoin(base_url.rstrip("/") + "/", f"handshake/{quote(data, safe='')}") if base_url else None)
    if not final_handshake_url:
        raise ValueError("Lapti requires token, challenge_json, challenge_file, handshake_url or base_url")
    resp = requests.get(final_handshake_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    raw["handshakeResponse"] = {"status": resp.status_code, "url": final_handshake_url}
    try:
        body = resp.json()
    except ValueError:
        body = {"text": resp.text[:500]}
    raw["handshakeResponse"]["json"] = body
    resp.raise_for_status()
    if isinstance(body, dict):
        body.setdefault("data", data)
    raw["challengeSource"] = "handshake"
    return body


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
