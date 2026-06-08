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

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

MAX_UINT_128 = (1 << 128) - 1
DEFAULT_MAX_ATTEMPTS_PER_SALT = 50_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class KerberusChallenge:
    id: str
    salts: list[str]
    difficulty_factor: int
    serialized_input: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "salts": list(self.salts),
            "difficultyFactor": self.difficulty_factor,
        }

    @property
    def threshold(self) -> int:
        return kerberus_threshold(self.difficulty_factor)


@dataclass(slots=True)
class KerberusSolution:
    challenge: KerberusChallenge
    nonces: list[str]
    scores: list[int]
    took_ms: int
    checked: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return {"id": self.challenge.id, "nonces": list(self.nonces)}

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def kerberus_threshold(difficulty_factor: int) -> int:
    factor = int(difficulty_factor)
    if factor <= 0:
        raise ValueError("Kerberus difficultyFactor must be positive")
    return MAX_UINT_128 - (MAX_UINT_128 // factor)


def kerberus_prefix_hash(salt: str, serialized_input: str) -> bytes:
    return hashlib.sha256(f"{salt}{serialized_input}".encode("utf-8")).digest()


def kerberus_score_from_prefix_hash(prefix_hash: bytes, nonce: int | str) -> int:
    digest = hashlib.sha256(prefix_hash + str(nonce).encode("utf-8")).digest()
    return int.from_bytes(digest[:16], "big", signed=False)


def kerberus_score(salt: str, serialized_input: str, nonce: int | str) -> int:
    return kerberus_score_from_prefix_hash(kerberus_prefix_hash(salt, serialized_input), nonce)


def verify_kerberus_nonce(
    salt: str,
    serialized_input: str,
    difficulty_factor: int,
    nonce: int | str,
) -> bool:
    try:
        return kerberus_score(salt, serialized_input, nonce) >= kerberus_threshold(difficulty_factor)
    except Exception:
        return False


def verify_kerberus_solution(
    challenge: KerberusChallenge | dict[str, Any] | str,
    solution: KerberusSolution | dict[str, Any] | list[str],
    *,
    serialized_input: str | None = None,
) -> bool:
    try:
        item = parse_kerberus_challenge(challenge, serialized_input=serialized_input)
        if isinstance(solution, KerberusSolution):
            nonces = solution.nonces
        elif isinstance(solution, dict):
            nonces = solution.get("nonces") or solution.get("nonce") or []
        else:
            nonces = solution
        if len(nonces) != len(item.salts):
            return False
        return all(
            verify_kerberus_nonce(salt, item.serialized_input, item.difficulty_factor, nonce)
            for salt, nonce in zip(item.salts, nonces)
        )
    except Exception:
        return False


def parse_kerberus_challenge(
    value: KerberusChallenge | dict[str, Any] | str,
    *,
    serialized_input: str | None = None,
) -> KerberusChallenge:
    if isinstance(value, KerberusChallenge):
        if serialized_input is not None and serialized_input != value.serialized_input:
            return KerberusChallenge(value.id, list(value.salts), value.difficulty_factor, serialized_input)
        return value
    obj = _load_jsonish(value)
    if not isinstance(obj, dict):
        raise ValueError("Kerberus challenge must be a JSON object")
    if isinstance(obj.get("challenge"), dict):
        embedded_input = obj.get("serializedInput", obj.get("serialized_input", obj.get("input")))
        obj = {**obj["challenge"], "serializedInput": embedded_input or obj["challenge"].get("serializedInput")}
    challenge_id = obj.get("id") or obj.get("challengeId") or obj.get("challenge_id")
    salts = obj.get("salts")
    difficulty = obj.get("difficultyFactor", obj.get("difficulty_factor", obj.get("difficulty")))
    if not challenge_id:
        raise ValueError("Kerberus challenge requires id")
    if not isinstance(salts, list) or not salts:
        raise ValueError("Kerberus challenge requires non-empty salts list")
    if difficulty is None:
        raise ValueError("Kerberus challenge requires difficultyFactor")
    input_value = serialized_input
    if input_value is None:
        input_value = obj.get("serializedInput", obj.get("serialized_input", obj.get("input", "")))
    return KerberusChallenge(
        id=str(challenge_id),
        salts=[str(salt) for salt in salts],
        difficulty_factor=int(difficulty),
        serialized_input=str(input_value or ""),
    )


def solve_kerberus_challenge(
    challenge: KerberusChallenge | dict[str, Any] | str,
    *,
    serialized_input: str | None = None,
    start: int = 0,
    max_attempts_per_salt: int = DEFAULT_MAX_ATTEMPTS_PER_SALT,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> KerberusSolution | None:
    item = parse_kerberus_challenge(challenge, serialized_input=serialized_input)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts_per_salt))
    end = start + max_attempts
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    threshold = item.threshold

    if workers <= 1 or len(item.salts) <= 1:
        nonces: list[str] = []
        scores: list[int] = []
        checked_total = 0
        for salt in item.salts:
            nonce, score, checked = _solve_kerberus_salt_range(
                salt,
                item.serialized_input,
                threshold,
                start,
                end,
                deadline,
            )
            checked_total += checked
            if nonce is None or score is None:
                return None
            nonces.append(str(nonce))
            scores.append(score)
        return KerberusSolution(
            item,
            nonces,
            scores,
            int((time.monotonic() - started) * 1000),
            checked_total,
        )

    pool = ProcessPoolExecutor(max_workers=min(workers, len(item.salts)))
    futures = {
        pool.submit(
            _solve_kerberus_salt_range,
            salt,
            item.serialized_input,
            threshold,
            start,
            end,
            deadline,
        ): idx
        for idx, salt in enumerate(item.salts)
    }
    nonces_by_idx: dict[int, str] = {}
    scores_by_idx: dict[int, int] = {}
    checked_total = 0
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx = futures[fut]
            nonce, score, checked = fut.result()
            checked_total += checked
            if nonce is None or score is None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            nonces_by_idx[idx] = str(nonce)
            scores_by_idx[idx] = score
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if len(nonces_by_idx) != len(item.salts):
        return None
    return KerberusSolution(
        item,
        [nonces_by_idx[idx] for idx in range(len(item.salts))],
        [scores_by_idx[idx] for idx in range(len(item.salts))],
        int((time.monotonic() - started) * 1000),
        checked_total,
    )


def _solve_kerberus_salt_range(
    salt: str,
    serialized_input: str,
    threshold: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, int | None, int]:
    prefix_hash = kerberus_prefix_hash(salt, serialized_input)
    checked = 0
    # Upstream starts with nonce=0 and increments before first score, so start=0 checks nonce=1.
    first_nonce = max(1, int(start) + 1)
    for nonce in range(first_nonce, max(first_nonce, int(end_exclusive) + 1)):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, None, checked
        score = kerberus_score_from_prefix_hash(prefix_hash, nonce)
        checked += 1
        if score >= threshold:
            return nonce, score, checked
    return None, None, checked


def _load_jsonish(value: KerberusChallenge | dict[str, Any] | str) -> Any:
    if isinstance(value, KerberusChallenge):
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
        for key in ("token", "ticket", "status", "message"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


class KerberusSolver:
    """Kerberus multi-salt u128-score proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        serialized_input: str | None = None,
        input_file: str | None = None,
        validate_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts_per_salt: int = DEFAULT_MAX_ATTEMPTS_PER_SALT,
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
            "validate_url": validate_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_salt": max_attempts_per_salt,
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
                out = output_root / "kerberus_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="kerberus",
                ok=ok,
                captcha_type="u128_score_pow",
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
            if input_file:
                serialized_input = Path(input_file).read_text(encoding="utf-8")
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_kerberus_challenge(challenge_data, serialized_input=serialized_input)
            diagnostics.update(
                {
                    "challenge_id": item.id,
                    "salt_count": len(item.salts),
                    "difficulty_factor": item.difficulty_factor,
                    "threshold_hex": f"{item.threshold:032x}",
                    "serialized_input_len": len(item.serialized_input),
                }
            )
            raw["challenge"] = {
                "id": item.id,
                "saltCount": len(item.salts),
                "difficultyFactor": item.difficulty_factor,
                "serializedInputLength": len(item.serialized_input),
            }

            solution = solve_kerberus_challenge(
                item,
                start=start,
                max_attempts_per_salt=max_attempts_per_salt,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Kerberus PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "id": item.id,
                "nonces": solution.nonces,
                "scoresHex": [f"{score:032x}" for score in solution.scores],
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "nonces": solution.nonces,
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                }
            )

            ticket = solution.submit_body_json()
            verify_code = "solved"
            if submit and validate_url:
                validate_data = self._submit_solution(
                    validate_url=validate_url,
                    solution=solution,
                    serialized_input=item.serialized_input,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(validate_data, dict) and (
                    validate_data.get("ok")
                    or validate_data.get("success")
                    or validate_data.get("status") in ("ok", "success", True)
                    or validate_data.get("token")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(validate_data, ticket)
                    diagnostics["submitted"] = True
                else:
                    errors.append("Kerberus validate rejected solution")
                    return finish(ok=False, ticket=ticket, verify_code="validate_failed")
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
        raise ValueError("Kerberus requires challenge_json, challenge_file or challenge_url")

    def _submit_solution(
        self,
        *,
        validate_url: str,
        solution: KerberusSolution,
        serialized_input: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        body = {"solution": solution.submit_body, "serializedInput": serialized_input}
        resp = requests.post(
            validate_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=body,
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
