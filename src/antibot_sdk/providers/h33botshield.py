from __future__ import annotations

import asyncio
import hashlib
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

DEFAULT_BASE_URL = "https://api.h33.ai"
DEFAULT_CHALLENGE_PATH = "/v1/botshield/challenge"
DEFAULT_SOLVE_PATH = "/v1/botshield/solve"
DEFAULT_MAX_ATTEMPTS = 25_000_000
MAX_DIFFICULTY = 64


@dataclass(slots=True)
class H33BotShieldChallenge:
    challenge_id: str
    nonce: str
    difficulty: int
    algorithm: str = "sha256"
    expires_at: int | None = None
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class H33BotShieldSolution:
    challenge: H33BotShieldChallenge
    solution: int
    hash_hex: str
    checked: int
    elapsed_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge.challenge_id,
            "nonce": self.challenge.nonce,
            "solution": self.solution,
        }


def h33botshield_hash_hex(nonce: str, solution: int | str) -> str:
    return hashlib.sha256(f"{nonce}{solution}".encode("utf-8")).hexdigest()


def h33botshield_hash_matches(nonce: str, solution: int | str, difficulty: int) -> bool:
    return h33botshield_digest_matches(bytes.fromhex(h33botshield_hash_hex(nonce, solution)), difficulty)


def h33botshield_digest_matches(digest: bytes, difficulty: int) -> bool:
    difficulty = _validate_difficulty(difficulty)
    full_bytes, rem_bits = divmod(difficulty, 8)
    if full_bytes and any(b != 0 for b in digest[:full_bytes]):
        return False
    if rem_bits and digest[full_bytes] >> (8 - rem_bits) != 0:
        return False
    return True


def parse_h33botshield_challenge(data: Any) -> H33BotShieldChallenge:
    if isinstance(data, str):
        data = _load_json_arg(data)
    if not isinstance(data, dict):
        raise ValueError("H33 BotShield challenge must be a JSON object")
    challenge_id = data.get("challenge_id") or data.get("challengeId") or data.get("id")
    nonce = data.get("nonce")
    difficulty = data.get("difficulty")
    algorithm = str(data.get("algorithm") or "sha256").lower()
    if not challenge_id:
        raise ValueError("H33 BotShield challenge requires challenge_id")
    if not nonce:
        raise ValueError("H33 BotShield challenge requires nonce")
    if algorithm != "sha256":
        raise ValueError(f"unsupported H33 BotShield algorithm: {algorithm}")
    return H33BotShieldChallenge(
        challenge_id=str(challenge_id),
        nonce=str(nonce),
        difficulty=_validate_difficulty(difficulty),
        algorithm=algorithm,
        expires_at=int(data["expires_at"]) if data.get("expires_at") is not None else None,
        raw=data,
    )


def solve_h33botshield_challenge(
    challenge: H33BotShieldChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = 60,
) -> H33BotShieldSolution | None:
    item = parse_h33botshield_challenge(challenge) if not isinstance(challenge, H33BotShieldChallenge) else challenge
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))

    if workers <= 1:
        solution, checked, hash_hex = _solve_h33botshield_range(
            item.nonce,
            item.difficulty,
            start,
            start + max_attempts,
            deadline,
        )
        if solution is None:
            return None
        return H33BotShieldSolution(
            challenge=item,
            solution=solution,
            hash_hex=hash_hex or h33botshield_hash_hex(item.nonce, solution),
            checked=checked,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    chunk = (max_attempts + workers - 1) // workers
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(_solve_h33botshield_range, item.nonce, item.difficulty, lo, hi, deadline): (lo, hi)
        for lo, hi in ranges
    }
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            solution, checked, hash_hex = fut.result()
            checked_total += checked
            if solution is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return H33BotShieldSolution(
                    challenge=item,
                    solution=solution,
                    hash_hex=hash_hex or h33botshield_hash_hex(item.nonce, solution),
                    checked=checked_total,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
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


def verify_h33botshield_solution(
    challenge: H33BotShieldChallenge | dict[str, Any] | str,
    solution: H33BotShieldSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_h33botshield_challenge(challenge) if not isinstance(challenge, H33BotShieldChallenge) else challenge
        if isinstance(solution, H33BotShieldSolution):
            value = solution.solution
        elif isinstance(solution, dict):
            challenge_id = solution.get("challenge_id") or solution.get("challengeId")
            if challenge_id is not None and str(challenge_id) != item.challenge_id:
                return False
            nonce = solution.get("nonce")
            if nonce is not None and str(nonce) != item.nonce:
                return False
            value = solution.get("solution")
        else:
            value = solution
        return h33botshield_hash_matches(item.nonce, value, item.difficulty)
    except Exception:
        return False


def _solve_h33botshield_range(
    nonce: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline: float | None,
) -> tuple[int | None, int, str | None]:
    difficulty = _validate_difficulty(difficulty)
    full_bytes, rem_bits = divmod(difficulty, 8)
    prefix = str(nonce).encode("utf-8")
    checked = 0
    for value in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, checked, None
        checked += 1
        digest = hashlib.sha256(prefix + str(value).encode("ascii")).digest()
        if full_bytes and any(b != 0 for b in digest[:full_bytes]):
            continue
        if rem_bits and digest[full_bytes] >> (8 - rem_bits) != 0:
            continue
        return value, checked, digest.hex()
    return None, checked, None


def _validate_difficulty(value: Any) -> int:
    try:
        difficulty = int(value)
    except Exception as e:
        raise ValueError("H33 BotShield difficulty must be integer") from e
    if difficulty < 0 or difficulty > MAX_DIFFICULTY:
        raise ValueError(f"H33 BotShield difficulty must be 0..{MAX_DIFFICULTY}")
    return difficulty


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _api_url(base: str | None, path: str) -> str | None:
    if not base:
        return None
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _h33_headers(resp: requests.Response) -> dict[str, str]:
    return {k: v for k, v in resp.headers.items() if k.lower().startswith("x-h33-")}


def _redact(data: Any) -> Any:
    if isinstance(data, dict):
        out = dict(data)
        token = out.get("session_token")
        if isinstance(token, str) and len(token) > 20:
            out["session_token"] = token[:8] + "..." + token[-6:]
        return out
    return data


class H33BotShieldSolver:
    """H33 BotShield protocol solver.

    Replays the public widget protocol without a browser: POST challenge, solve
    SHA256(nonce+counter) leading-zero-bit PoW, then optionally POST solve to
    get the `h33_bot_token` session token.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        challenge_url: str | None = None,
        solve_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_body_json: Any = None,
        challenge_body_file: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = 60,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "solve_url": solve_url,
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
                out = output_root / "h33botshield_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="h33botshield",
                ok=ok,
                captcha_type="botshield_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge_id"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            data = self._load_challenge(
                base_url=base_url,
                challenge_url=challenge_url,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_body_json=challenge_body_json,
                challenge_body_file=challenge_body_file,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            challenge = parse_h33botshield_challenge(data)
            raw["challenge"] = challenge.raw or data
            diagnostics.update(
                {
                    "challenge_id": challenge.challenge_id,
                    "difficulty": challenge.difficulty,
                    "algorithm": challenge.algorithm,
                    "expires_at": challenge.expires_at,
                }
            )
            solution = solve_h33botshield_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("H33 BotShield solve failed: timeout_or_not_found")
                return finish(ok=False)
            raw["solution"] = {
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "solution": solution.solution,
                "hash": solution.hash_hex,
                "checked": solution.checked,
                "elapsedMs": solution.elapsed_ms,
            }
            diagnostics.update(
                {
                    "checked": solution.checked,
                    "solve_ms": solution.elapsed_ms,
                    "solution": solution.solution,
                    "hash": solution.hash_hex,
                }
            )
            final_ticket = json.dumps(solution.submit_body, separators=(",", ":"))
            verify_code = "solved"
            if submit or solve_url:
                solve_url = solve_url or _api_url(base_url, DEFAULT_SOLVE_PATH)
                assert solve_url is not None
                resp = requests.post(
                    solve_url,
                    headers={"Content-Type": "application/json", **(headers or {})},
                    json=solution.submit_body,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                raw["solveRequest"] = {"url": solve_url, "body": solution.submit_body}
                raw["solveResponse"] = {"status": resp.status_code, "url": resp.url, "h33Headers": _h33_headers(resp)}
                resp.raise_for_status()
                solved_data = resp.json()
                raw["solveResponse"]["json"] = _redact(solved_data)
                if not isinstance(solved_data, dict) or solved_data.get("verified") is not True:
                    errors.append(str((solved_data or {}).get("error") or "verify_failed"))
                    return finish(ok=False, ticket=final_ticket, verify_code="verify_failed")
                final_ticket = str(solved_data.get("session_token") or final_ticket)
                verify_code = "verified"
                diagnostics["valid_until"] = solved_data.get("valid_until")
                diagnostics["difficulty_solved"] = solved_data.get("difficulty_solved")
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        base_url: str,
        challenge_url: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_body_json: Any,
        challenge_body_file: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        if challenge_json is not None:
            return _load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            return loaded
        body = (
            _load_json_arg(challenge_body_json, challenge_body_file)
            if isinstance(challenge_body_json, str) or challenge_body_file
            else challenge_body_json
        )
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise ValueError("H33 BotShield challenge body must be a JSON object")
        challenge_url = challenge_url or _api_url(base_url, DEFAULT_CHALLENGE_PATH)
        assert challenge_url is not None
        resp = requests.post(
            challenge_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeRequest"] = {"url": challenge_url, "body": body}
        raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url, "h33Headers": _h33_headers(resp)}
        resp.raise_for_status()
        return resp.json()
