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

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

PUZZLE_BUFFER_LENGTH = 128
SOLUTION_LENGTH = 8
METADATA_LENGTH = 1 + 1 + 1 + 4
DEFAULT_MAX_ATTEMPTS_PER_SOLUTION = 50_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class PrivateCaptchaPuzzle:
    raw_data: str
    puzzle_b64: str
    signature_b64: str
    puzzle_bytes: bytes
    signature_bytes: bytes
    version: int
    property_id: bytes
    puzzle_id: int
    difficulty: int
    solutions_count: int
    expiration_timestamp: int
    user_data: bytes

    @property
    def puzzle_buffer(self) -> bytes:
        if len(self.puzzle_bytes) >= PUZZLE_BUFFER_LENGTH:
            return self.puzzle_bytes
        return self.puzzle_bytes + (b"\x00" * (PUZZLE_BUFFER_LENGTH - len(self.puzzle_bytes)))

    @property
    def property_id_hex(self) -> str:
        return self.property_id.hex()

    @property
    def is_zero(self) -> bool:
        return self.puzzle_id == 0 and self.difficulty == 0 and self.expiration_timestamp == 0


@dataclass(slots=True)
class PrivateCaptchaSolutions:
    puzzle: PrivateCaptchaPuzzle
    solutions: list[bytes]
    elapsed_ms: int
    error_code: int = 0
    wasm_flag: bool = False

    @property
    def solution_bytes(self) -> bytes:
        return b"".join(self.solutions)

    @property
    def solutions_b64(self) -> str:
        raw = bytearray()
        raw.append(1)  # metadata version
        raw.append(self.error_code & 0xFF)
        raw.append(1 if self.wasm_flag else 0)
        raw.extend(int(self.elapsed_ms).to_bytes(4, "little", signed=False))
        raw.extend(self.solution_bytes)
        return base64.b64encode(bytes(raw)).decode("ascii")

    @property
    def payload(self) -> str:
        return f"{self.solutions_b64}.{self.puzzle.raw_data}"

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "response": self.payload,
            "solutions": self.solutions_b64,
            "puzzle": self.puzzle.raw_data,
            "puzzleId": str(self.puzzle.puzzle_id),
            "worker_type": "python",
            "time": self.elapsed_ms,
        }


def privatecaptcha_threshold_from_difficulty(difficulty: int) -> int:
    """Match upstream Go thresholdFromDifficulty(difficulty uint8)."""

    d = max(0, min(255, int(difficulty)))
    if d == 0:
        return 0xFFFFFFFF
    if d == 255:
        return 1
    return max(1, min(0xFFFFFFFF, int(math.pow(2, (255.999999999 - float(d)) / 8.0))))


def parse_privatecaptcha_puzzle(raw_data: str | bytes | bytearray) -> PrivateCaptchaPuzzle:
    text = _coerce_text(raw_data).strip()
    parts = text.split(".")
    if len(parts) == 3:
        # Full widget response: solutions.puzzle.signature.  Keep only the challenge suffix.
        parts = parts[1:]
        text = ".".join(parts)
    if len(parts) != 2:
        raise ValueError(f"PrivateCaptcha puzzle must have 2 parts, got {len(parts)}")
    puzzle_b64, signature_b64 = parts
    if not puzzle_b64 or not signature_b64:
        raise ValueError("PrivateCaptcha puzzle has empty part")

    puzzle_bytes = _b64decode(puzzle_b64)
    signature_bytes = _b64decode(signature_b64)
    if len(puzzle_bytes) < 47:
        raise ValueError("PrivateCaptcha puzzle bytes are too short")
    if len(signature_bytes) < 3:
        raise ValueError("PrivateCaptcha signature bytes are too short")

    offset = 0
    version = puzzle_bytes[offset]
    offset += 1
    property_id = puzzle_bytes[offset : offset + 16]
    offset += 16
    puzzle_id = int.from_bytes(puzzle_bytes[offset : offset + 8], "little")
    offset += 8
    difficulty = puzzle_bytes[offset]
    offset += 1
    solutions_count = puzzle_bytes[offset]
    offset += 1
    expiration_timestamp = int.from_bytes(puzzle_bytes[offset : offset + 4], "little")
    offset += 4
    user_data = puzzle_bytes[offset : offset + 16]

    if version != 1:
        raise ValueError(f"PrivateCaptcha unsupported puzzle version: {version}")
    if solutions_count < 1:
        raise ValueError("PrivateCaptcha solutions_count must be positive")

    return PrivateCaptchaPuzzle(
        raw_data=text,
        puzzle_b64=puzzle_b64,
        signature_b64=signature_b64,
        puzzle_bytes=puzzle_bytes,
        signature_bytes=signature_bytes,
        version=version,
        property_id=property_id,
        puzzle_id=puzzle_id,
        difficulty=difficulty,
        solutions_count=solutions_count,
        expiration_timestamp=expiration_timestamp,
        user_data=user_data,
    )


def solve_privatecaptcha_puzzle(
    puzzle: PrivateCaptchaPuzzle | str | bytes | bytearray,
    *,
    start: int = 0,
    max_attempts_per_solution: int = DEFAULT_MAX_ATTEMPTS_PER_SOLUTION,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PrivateCaptchaSolutions | None:
    item = parse_privatecaptcha_puzzle(puzzle) if not isinstance(puzzle, PrivateCaptchaPuzzle) else puzzle
    started = time.monotonic()
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    workers = max(1, int(workers or 1))
    max_attempts = max(1, int(max_attempts_per_solution))
    start = max(0, int(start))

    if item.is_zero:
        return PrivateCaptchaSolutions(
            puzzle=item,
            solutions=[b"\x00" * SOLUTION_LENGTH for _ in range(item.solutions_count)],
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    threshold = privatecaptcha_threshold_from_difficulty(item.difficulty)
    puzzle_buffer = item.puzzle_buffer

    if workers <= 1 or item.solutions_count <= 1:
        solutions: list[bytes] = []
        for puzzle_index in range(item.solutions_count):
            solution, _attempts = _solve_privatecaptcha_one(
                puzzle_buffer,
                threshold,
                puzzle_index,
                start,
                max_attempts,
                deadline,
            )
            if solution is None:
                return None
            solutions.append(solution)
        return PrivateCaptchaSolutions(item, solutions, int((time.monotonic() - started) * 1000))

    pool = ProcessPoolExecutor(max_workers=min(workers, item.solutions_count))
    futures = {
        pool.submit(
            _solve_privatecaptcha_one,
            puzzle_buffer,
            threshold,
            puzzle_index,
            start,
            max_attempts,
            deadline,
        ): puzzle_index
        for puzzle_index in range(item.solutions_count)
    }
    results: dict[int, bytes] = {}
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            puzzle_index = futures[fut]
            solution, _attempts = fut.result()
            if solution is None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            results[puzzle_index] = solution
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if len(results) != item.solutions_count:
        return None
    ordered = [results[i] for i in range(item.solutions_count)]
    return PrivateCaptchaSolutions(item, ordered, int((time.monotonic() - started) * 1000))


def verify_privatecaptcha_payload(payload: str | bytes | bytearray) -> bool:
    try:
        text = _coerce_text(payload).strip()
        parts = text.split(".")
        if len(parts) != 3:
            return False
        solutions_b64, puzzle_b64, signature_b64 = parts
        puzzle = parse_privatecaptcha_puzzle(f"{puzzle_b64}.{signature_b64}")
        solutions, _metadata = parse_privatecaptcha_solutions(solutions_b64)
        return verify_privatecaptcha_solutions(puzzle, solutions)
    except Exception:
        return False


def parse_privatecaptcha_solutions(solutions_b64: str) -> tuple[list[bytes], dict[str, Any]]:
    raw = _b64decode(solutions_b64)
    if len(raw) < METADATA_LENGTH:
        raise ValueError("PrivateCaptcha solutions metadata is too short")
    if raw[0] != 1:
        raise ValueError(f"PrivateCaptcha unsupported solutions metadata version: {raw[0]}")
    body = raw[METADATA_LENGTH:]
    if len(body) % SOLUTION_LENGTH != 0:
        raise ValueError("PrivateCaptcha solutions length is invalid")
    metadata = {
        "version": raw[0],
        "error_code": raw[1],
        "wasm": raw[2] == 1,
        "elapsed_ms": int.from_bytes(raw[3:7], "little"),
    }
    return [body[i : i + SOLUTION_LENGTH] for i in range(0, len(body), SOLUTION_LENGTH)], metadata


def verify_privatecaptcha_solutions(puzzle: PrivateCaptchaPuzzle | str | bytes | bytearray, solutions: list[bytes]) -> bool:
    try:
        item = parse_privatecaptcha_puzzle(puzzle) if not isinstance(puzzle, PrivateCaptchaPuzzle) else puzzle
        if len(solutions) != item.solutions_count:
            return False
        if len({int.from_bytes(sol, "little") for sol in solutions}) != len(solutions):
            return False
        if item.difficulty == 0:
            return all(len(sol) == SOLUTION_LENGTH for sol in solutions)
        threshold = privatecaptcha_threshold_from_difficulty(item.difficulty)
        base = bytearray(item.puzzle_buffer)
        for solution in solutions:
            if len(solution) != SOLUTION_LENGTH:
                return False
            base[-SOLUTION_LENGTH:] = solution
            digest = hashlib.blake2b(base, digest_size=32).digest()
            prefix = int.from_bytes(digest[:4], "little")
            if prefix > threshold:
                return False
        return True
    except Exception:
        return False


def _solve_privatecaptcha_one(
    puzzle_buffer: bytes,
    threshold: int,
    puzzle_index: int,
    start: int,
    max_attempts: int,
    deadline: float | None,
) -> tuple[bytes | None, int]:
    buf = bytearray(puzzle_buffer)
    buf[-SOLUTION_LENGTH] = puzzle_index & 0xFF
    attempts = 0
    end = min(0x1_0000_0000, start + max_attempts)
    for counter in range(start, end):
        if deadline is not None and attempts and attempts % 4096 == 0 and time.monotonic() >= deadline:
            return None, attempts
        attempts += 1
        buf[-4] = (counter >> 24) & 0xFF
        buf[-3] = (counter >> 16) & 0xFF
        buf[-2] = (counter >> 8) & 0xFF
        buf[-1] = counter & 0xFF
        digest = hashlib.blake2b(buf, digest_size=32).digest()
        if int.from_bytes(digest[:4], "little") <= threshold:
            return bytes(buf[-SOLUTION_LENGTH:]), attempts
    return None, attempts


def _coerce_text(value: str | bytes | bytearray) -> str:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@") and Path(text[1:]).is_file():
            return Path(text[1:]).read_text(encoding="utf-8").strip()
        return text
    return bytes(value).decode("ascii").strip()


def _b64decode(value: str) -> bytes:
    text = value.strip()
    if text.startswith("base64:"):
        text = text.split(":", 1)[1]
    missing = (-len(text)) % 4
    if missing:
        text += "=" * missing
    return base64.b64decode(text, validate=True)


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _extract_puzzle(data: Any) -> str:
    if isinstance(data, (str, bytes, bytearray)):
        return _coerce_text(data)
    if isinstance(data, dict):
        for key in (
            "puzzle",
            "challenge",
            "captcha",
            "data",
            "privateCaptcha",
            "private_captcha",
            "rawData",
            "raw_data",
        ):
            value = data.get(key)
            if isinstance(value, (str, bytes, bytearray)):
                return _coerce_text(value)
            if isinstance(value, dict):
                return _extract_puzzle(value)
        puzzle_b64 = data.get("puzzle_b64") or data.get("puzzleBase64")
        sig_b64 = data.get("signature_b64") or data.get("signatureBase64") or data.get("signature")
        if isinstance(puzzle_b64, str) and isinstance(sig_b64, str):
            return f"{puzzle_b64}.{sig_b64}"
    raise ValueError("failed to extract PrivateCaptcha puzzle")


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


class PrivateCaptchaSolver:
    """PrivateCaptcha compute puzzle protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        puzzle: str | bytes | None = None,
        puzzle_file: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        puzzle_url: str | None = None,
        sitekey: str | None = None,
        verify_url: str | None = None,
        siteverify_url: str | None = None,
        submit: bool = False,
        api_key: str | None = None,
        secret: str | None = None,
        start: int = 0,
        max_attempts_per_solution: int = DEFAULT_MAX_ATTEMPTS_PER_SOLUTION,
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
            "challenge_url": challenge_url or puzzle_url,
            "verify_url": verify_url or siteverify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_solution": max_attempts_per_solution,
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
                out = output_root / "privatecaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="privatecaptcha",
                ok=ok,
                captcha_type="compute_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("puzzle_id"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            raw_puzzle = self._load_puzzle(
                puzzle=puzzle,
                puzzle_file=puzzle_file,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                puzzle_url=puzzle_url,
                sitekey=sitekey,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_privatecaptcha_puzzle(raw_puzzle)
            threshold = privatecaptcha_threshold_from_difficulty(item.difficulty)
            raw["puzzle"] = {
                "puzzleId": str(item.puzzle_id),
                "propertyId": item.property_id_hex,
                "difficulty": item.difficulty,
                "threshold": threshold,
                "solutionsCount": item.solutions_count,
                "expirationTimestamp": item.expiration_timestamp,
            }
            diagnostics.update(raw["puzzle"])
            diagnostics["puzzle_id"] = str(item.puzzle_id)

            solution = solve_privatecaptcha_puzzle(
                item,
                start=start,
                max_attempts_per_solution=max_attempts_per_solution,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("PrivateCaptcha solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            if not verify_privatecaptcha_solutions(item, solution.solutions):
                errors.append("PrivateCaptcha local verification failed")
                return finish(ok=False)

            raw["solution"] = {
                "solutions": solution.solutions_b64,
                "payload": solution.payload,
                "elapsedMs": solution.elapsed_ms,
                "solutionHex": [s.hex() for s in solution.solutions],
            }
            diagnostics.update(
                {
                    "solve_ms": solution.elapsed_ms,
                    "solutions": len(solution.solutions),
                    "payload_bytes": len(solution.payload),
                }
            )
            ticket = solution.payload
            verify_code = "solved"
            if submit or verify_url or siteverify_url:
                target = verify_url or siteverify_url
                if not target:
                    errors.append("PrivateCaptcha submit requested but verify_url/siteverify_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=target,
                    solution=solution,
                    sitekey=sitekey,
                    api_key=api_key,
                    secret=secret,
                    siteverify=bool(siteverify_url or secret),
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(verify_data, dict):
                    if "success" in verify_data and not verify_data["success"]:
                        errors.append("PrivateCaptcha verification endpoint rejected answer")
                        return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                    token = verify_data.get("token") or verify_data.get("ticket")
                    if token:
                        ticket = str(token)
                verify_code = "validated"
                diagnostics["submitted"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_puzzle(
        self,
        *,
        puzzle: str | bytes | None,
        puzzle_file: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        puzzle_url: str | None,
        sitekey: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> str:
        if puzzle is not None:
            raw["challengeSource"] = "inline"
            return _coerce_text(puzzle)
        if puzzle_file:
            raw["challengeSource"] = "file"
            return Path(puzzle_file).read_text(encoding="utf-8").strip()

        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return _extract_puzzle(data)

        url = challenge_url or puzzle_url
        if url:
            params = {"sitekey": sitekey} if sitekey and "sitekey=" not in url else None
            req_headers = {"x-pc-captcha-version": "1", **(headers or {})}
            resp = requests.get(
                url,
                params=params,
                headers=req_headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            ctype = (resp.headers or {}).get("content-type", "").lower()
            if "json" in ctype:
                raw["challengeSource"] = "url-json"
                return _extract_puzzle(resp.json())
            raw["challengeSource"] = "url-text"
            return resp.text.strip()
        raise ValueError("PrivateCaptcha requires puzzle, puzzle_file, challenge_json, challenge_url or puzzle_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PrivateCaptchaSolutions,
        sitekey: str | None,
        api_key: str | None,
        secret: str | None,
        siteverify: bool,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        if siteverify:
            form: dict[str, str] = {"response": solution.payload}
            if secret:
                form["secret"] = secret
            if sitekey:
                form["sitekey"] = sitekey
            resp = requests.post(
                verify_url,
                data=form,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
        else:
            req_headers = {"Content-Type": "text/plain", **(headers or {})}
            if api_key:
                req_headers["X-API-Key"] = api_key
            if sitekey:
                req_headers["X-PC-Sitekey"] = sitekey
            resp = requests.post(
                verify_url,
                data=solution.payload.encode("utf-8"),
                headers=req_headers,
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
