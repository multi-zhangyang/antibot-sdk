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

import requests
from argon2.low_level import Type, hash_secret_raw

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

CHALLENGE_ALGORITHM = "argon2id"
STRATEGY_LEADING_ZEROES = "leading_zeroes"
STRATEGY_TARGET_NUMBER = "target_number"
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 8192
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class ImpostChallenge:
    algorithm: str
    strategy: str
    salt: str
    difficulty: int | None = None
    target: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "algorithm": self.algorithm,
            "strategy": self.strategy,
            "salt": self.salt,
        }
        if self.strategy == STRATEGY_LEADING_ZEROES:
            payload["difficulty"] = self.difficulty
        elif self.strategy == STRATEGY_TARGET_NUMBER:
            payload["target"] = self.target
        return payload


@dataclass(slots=True)
class ImpostSolution:
    challenge: ImpostChallenge
    nonce: int
    hash_hex: str
    checked: int
    took_ms: int

    @property
    def submit_body(self) -> dict[str, str]:
        # Upstream example API validates {challenge: salt, nonce}; widget form currently uses
        # {challenge: salt, solution}, so expose both in diagnostics but keep submit strict.
        return {"challenge": self.challenge.salt, "nonce": str(self.nonce)}

    @property
    def form_value(self) -> dict[str, str]:
        return {"challenge": self.challenge.salt, "solution": str(self.nonce)}


def impost_argon2_hash(
    salt: str,
    nonce: int | str,
    *,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST_KIB,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> bytes:
    _validate_argon2_params(time_cost, memory_cost, parallelism, hash_len)
    salt_bytes = str(salt).encode("utf-8")
    if len(salt_bytes) < 8:
        raise ValueError("Impost Argon2 salt must be at least 8 bytes")
    return hash_secret_raw(
        secret=str(nonce).encode("utf-8"),
        salt=salt_bytes,
        time_cost=int(time_cost),
        memory_cost=int(memory_cost),
        parallelism=int(parallelism),
        hash_len=int(hash_len),
        type=Type.ID,
        version=19,
    )


def impost_argon2_hash_hex(salt: str, nonce: int | str) -> str:
    return impost_argon2_hash(salt, nonce).hex()


def verify_impost_solution(
    challenge: ImpostChallenge | dict[str, Any] | str,
    nonce: int | str | dict[str, Any],
) -> bool:
    try:
        item = parse_impost_challenge(challenge)
        nonce_value = _extract_nonce(nonce)
        digest_hex = impost_argon2_hash_hex(item.salt, nonce_value)
        if item.strategy == STRATEGY_LEADING_ZEROES:
            return digest_hex.startswith("0" * int(item.difficulty or 0))
        if item.strategy == STRATEGY_TARGET_NUMBER:
            return digest_hex == str(item.target or "").lower()
        return False
    except Exception:
        return False


def parse_impost_challenge(value: ImpostChallenge | dict[str, Any] | str) -> ImpostChallenge:
    if isinstance(value, ImpostChallenge):
        return value
    obj = _load_jsonish(value)
    if not isinstance(obj, dict):
        raise ValueError("Impost challenge must be a JSON object")
    if isinstance(obj.get("challenge"), dict):
        obj = obj["challenge"]

    algorithm = str(obj.get("algorithm") or CHALLENGE_ALGORITHM).lower()
    strategy = str(obj.get("strategy") or "").lower()
    salt = obj.get("salt") or obj.get("challenge")
    if algorithm != CHALLENGE_ALGORITHM:
        raise ValueError(f"unsupported Impost algorithm: {algorithm}")
    if strategy not in {STRATEGY_LEADING_ZEROES, STRATEGY_TARGET_NUMBER}:
        raise ValueError("Impost strategy must be leading_zeroes or target_number")
    if not salt:
        raise ValueError("Impost challenge requires salt")

    if strategy == STRATEGY_LEADING_ZEROES:
        difficulty = int(obj.get("difficulty"))
        if difficulty < 1 or difficulty > 64:
            raise ValueError("Impost leading_zeroes difficulty must be 1..64 hex zeroes")
        return ImpostChallenge(algorithm, strategy, str(salt), difficulty=difficulty)

    target = str(obj.get("target") or "").lower()
    if len(target) != ARGON2_HASH_LEN * 2 or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("Impost target_number requires 64-char hex target")
    return ImpostChallenge(algorithm, strategy, str(salt), target=target)


def solve_impost_challenge(
    challenge: ImpostChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> ImpostSolution | None:
    item = parse_impost_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 16:
        nonce, digest_hex, checked = _solve_impost_range(item, start, start + max_attempts, deadline)
        if nonce is None or digest_hex is None:
            return None
        return ImpostSolution(item, nonce, digest_hex, checked, int((time.monotonic() - started) * 1000))

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_impost_range, item, lo, hi, deadline)] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest_hex, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest_hex is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return ImpostSolution(
                    item,
                    nonce,
                    digest_hex,
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


def _solve_impost_range(
    challenge: ImpostChallenge,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    for nonce in range(int(start), int(end_exclusive)):
        if deadline is not None and time.monotonic() >= deadline:
            return None, None, checked
        digest_hex = impost_argon2_hash_hex(challenge.salt, nonce)
        checked += 1
        if challenge.strategy == STRATEGY_LEADING_ZEROES:
            if digest_hex.startswith("0" * int(challenge.difficulty or 0)):
                return nonce, digest_hex, checked
        elif digest_hex == str(challenge.target or "").lower():
            return nonce, digest_hex, checked
    return None, None, checked


def _extract_nonce(value: int | str | dict[str, Any]) -> int | str:
    if isinstance(value, dict):
        value = value.get("nonce", value.get("solution", value.get("answer")))
    if value is None:
        raise ValueError("missing nonce")
    text = str(value)
    if text.startswith("+"):
        text = text[1:]
    if not text.isdigit():
        raise ValueError("Impost nonce must be a non-negative decimal integer")
    return int(text)


def _load_jsonish(value: ImpostChallenge | dict[str, Any] | str) -> Any:
    if isinstance(value, ImpostChallenge):
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
        for key in ("token", "captcha_token", "ticket", "message", "status"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


def _validate_argon2_params(time_cost: int, memory_cost: int, parallelism: int, hash_len: int) -> None:
    if int(time_cost) <= 0:
        raise ValueError("Argon2 time_cost must be positive")
    if int(memory_cost) < 8:
        raise ValueError("Argon2 memory_cost must be at least 8 KiB")
    if int(parallelism) <= 0:
        raise ValueError("Argon2 parallelism must be positive")
    if int(hash_len) <= 0:
        raise ValueError("Argon2 hash_len must be positive")


class ImpostSolver:
    """Impost Zig/WASM Argon2id proof-of-work protocol solver."""

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
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
            "argon2": {
                "type": "argon2id",
                "time_cost": ARGON2_TIME_COST,
                "memory_cost_kib": ARGON2_MEMORY_COST_KIB,
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
                out = output_root / "impost_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="impost",
                ok=ok,
                captcha_type="argon2id_pow",
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
            item = parse_impost_challenge(challenge_data)
            diagnostics.update(
                {
                    "strategy": item.strategy,
                    "salt": item.salt,
                    "difficulty": item.difficulty,
                    "target": item.target,
                }
            )
            raw["challenge"] = item.to_payload()

            solution = solve_impost_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Impost Argon2id PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hashHex": solution.hash_hex,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            raw["formValue"] = solution.form_value
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
                    verify_data.get("ok") is not False
                    and verify_data.get("success") is not False
                    and str(verify_data.get("status", "")).lower() not in {"error", "failed", "fail"}
                    and not verify_data.get("error")
                    and not verify_data.get("errors")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(verify_data, ticket)
                    diagnostics["submitted"] = True
                else:
                    errors.append("Impost verify rejected solution")
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
        raise ValueError("Impost requires challenge_json, challenge_file or challenge_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: ImpostSolution,
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
