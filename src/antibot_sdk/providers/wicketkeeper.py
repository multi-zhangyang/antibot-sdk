from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class WicketkeeperChallenge:
    challenge: str
    difficulty: int
    token: str


@dataclass(slots=True)
class WicketkeeperSolution:
    challenge: WicketkeeperChallenge
    nonce: str
    response: str
    took_ms: int
    checked: int

    @property
    def submit_body(self) -> dict[str, str]:
        return {
            "token": self.challenge.token,
            "nonce": self.nonce,
            "response": self.response,
        }

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def wicketkeeper_hash_hex(challenge: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{challenge}{nonce}".encode("utf-8")).hexdigest()


def verify_wicketkeeper_work(
    challenge: WicketkeeperChallenge | dict[str, Any] | str,
    nonce: int | str,
    response: str,
    *,
    difficulty: int | None = None,
) -> bool:
    try:
        item = parse_wicketkeeper_challenge(challenge, difficulty=difficulty)
        expected = wicketkeeper_hash_hex(item.challenge, nonce)
        return expected == str(response).lower() and expected.startswith("0" * item.difficulty)
    except Exception:
        return False


def solve_wicketkeeper_challenge(
    challenge: WicketkeeperChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    token: str | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> WicketkeeperSolution | None:
    item = parse_wicketkeeper_challenge(challenge, difficulty=difficulty, token=token)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, response, checked = _solve_wicketkeeper_range(
            item.challenge,
            item.difficulty,
            start,
            start + max_attempts,
            deadline,
        )
        if nonce is None or response is None:
            return None
        return WicketkeeperSolution(
            challenge=item,
            nonce=str(nonce),
            response=response,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=checked,
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
        futures[
            pool.submit(
                _solve_wicketkeeper_range,
                item.challenge,
                item.difficulty,
                lo,
                hi,
                deadline,
            )
        ] = idx

    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, response, checked = fut.result()
            checked_total += checked
            if nonce is not None and response is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return WicketkeeperSolution(
                    challenge=item,
                    nonce=str(nonce),
                    response=response,
                    took_ms=int((time.monotonic() - started) * 1000),
                    checked=checked_total,
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


def parse_wicketkeeper_challenge(
    value: WicketkeeperChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    token: str | None = None,
) -> WicketkeeperChallenge:
    if isinstance(value, WicketkeeperChallenge):
        return value
    if isinstance(value, str):
        challenge = value.strip()
        if not challenge:
            raise ValueError("Wicketkeeper challenge is empty")
        jwt_claims = _decode_jwt_payload(token or "") if token else {}
        diff = difficulty if difficulty is not None else jwt_claims.get("diff")
        if diff is None:
            raise ValueError("Wicketkeeper inline challenge requires difficulty")
        return WicketkeeperChallenge(challenge=challenge, difficulty=int(diff), token=token or "")
    if not isinstance(value, dict):
        raise ValueError("Wicketkeeper challenge must be an object or challenge string")

    data = value
    challenge = data.get("challenge") or data.get("cid") or data.get("id")
    jwt_token = token or data.get("token") or data.get("jwt")
    jwt_claims = _decode_jwt_payload(str(jwt_token or "")) if jwt_token else {}
    if not challenge:
        challenge = jwt_claims.get("cid")
    if not challenge:
        raise ValueError("Wicketkeeper challenge requires challenge/cid")
    diff = (
        difficulty
        if difficulty is not None
        else data.get("difficulty", data.get("diff", jwt_claims.get("diff")))
    )
    if diff is None:
        raise ValueError("Wicketkeeper challenge requires difficulty/diff")
    return WicketkeeperChallenge(
        challenge=str(challenge),
        difficulty=max(0, int(diff)),
        token=str(jwt_token or ""),
    )


def _solve_wicketkeeper_range(
    challenge: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, str | None, int]:
    prefix = "0" * max(0, int(difficulty))
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, None, checked
        response = wicketkeeper_hash_hex(challenge, nonce)
        checked += 1
        if response.startswith(prefix):
            return nonce, response, checked
    return None, None, checked


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = (token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _infer_url(base_url: str | None, leaf: str) -> str | None:
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", f"v0/{leaf}")


def _replace_last_path_segment(url: str | None, expected: str, replacement: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if not path.endswith("/" + expected):
        return None
    new_path = path[: -len(expected)] + replacement
    return urlunparse(parsed._replace(path=new_path))


def _redact_token(data: Any) -> Any:
    if isinstance(data, dict):
        out = dict(data)
        token = out.get("token")
        if isinstance(token, str) and len(token) > 32:
            out["token"] = token[:16] + "..." + token[-10:]
        return out
    return data


class WicketkeeperSolver:
    """Wicketkeeper EdDSA-JWT proof-of-work protocol solver.

    Wicketkeeper issues a signed challenge token (`GET /v0/challenge`) and the
    client must find a nonce where `SHA256(challenge + nonce)` has `difficulty`
    leading zero hex nibbles.  The solved `{token, nonce, response}` can be
    submitted to `/v0/siteverify` for a success JWT.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        base_url: str | None = None,
        difficulty: int | None = None,
        token: str | None = None,
        siteverify_url: str | None = None,
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
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "base_url": base_url,
            "siteverify_url": siteverify_url,
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
                out = output_root / "wicketkeeper_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="wicketkeeper",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            if base_url and base_url.rstrip("/").endswith("/challenge"):
                challenge_url = challenge_url or base_url
                base_url = None
            if base_url:
                challenge_url = challenge_url or _infer_url(base_url, "challenge")
                siteverify_url = siteverify_url or _infer_url(base_url, "siteverify")
            siteverify_url = siteverify_url or _replace_last_path_segment(challenge_url, "challenge", "siteverify")
            diagnostics.update(
                {
                    "challenge_url": challenge_url,
                    "base_url": base_url,
                    "siteverify_url": siteverify_url,
                }
            )

            item = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                difficulty=difficulty,
                token=token,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            diagnostics.update(
                {
                    "challenge": item.challenge,
                    "difficulty": item.difficulty,
                    "token_prefix": item.token[:16] if item.token else None,
                }
            )
            raw["challenge"] = {
                "challenge": item.challenge,
                "difficulty": item.difficulty,
                "token": item.token[:16] + "..." if item.token else "",
            }

            solution = solve_wicketkeeper_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Wicketkeeper PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "response": solution.response,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "response_prefix": solution.response[: max(8, item.difficulty)],
                }
            )

            ticket = solution.submit_body_json()
            verify_code = "solved"
            if submit and siteverify_url:
                verify_data = self._submit_solution(
                    siteverify_url=siteverify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if not isinstance(verify_data, dict) or not verify_data.get("success"):
                    errors.append("Wicketkeeper siteverify rejected solution")
                    return finish(ok=False, ticket=ticket, verify_code="siteverify_failed")
                ticket = str(verify_data.get("token") or ticket)
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
        challenge: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        difficulty: int | None,
        token: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> WicketkeeperChallenge:
        if challenge:
            raw["challengeSource"] = "inline"
            return parse_wicketkeeper_challenge(challenge, difficulty=difficulty, token=token)
        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return parse_wicketkeeper_challenge(data, difficulty=difficulty, token=token)
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
            return parse_wicketkeeper_challenge(resp.json(), difficulty=difficulty, token=token)
        raise ValueError("Wicketkeeper requires challenge, challenge_json, challenge_file, challenge_url or base_url")

    def _submit_solution(
        self,
        *,
        siteverify_url: str,
        solution: WicketkeeperSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            siteverify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=solution.submit_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["siteverifyResponse"] = {"status": resp.status_code, "url": siteverify_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["siteverifyResponse"]["json"] = _redact_token(data)
        return data
