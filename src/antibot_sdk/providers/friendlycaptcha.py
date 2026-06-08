from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

CHALLENGE_SIZE_BYTES = 128
PUZZLE_SIGNATURE_INDEX = 0
PUZZLE_BUFFER_INDEX = 1
NUMBER_OF_PUZZLES_OFFSET = 14
PUZZLE_DIFFICULTY_OFFSET = 15
SOLVER_TYPE_UNSPECIFIED = 0
DEFAULT_MAX_ATTEMPTS_PER_SOLUTION = 10_000_000
DEFAULT_FRC_CLIENT = "js-0.9.19"
_UINT32_SPACE = 2**32


@dataclass(slots=True)
class FriendlyPuzzle:
    signature: str
    base64: str
    buffer: bytes
    n: int
    difficulty: int
    threshold: int

    @property
    def puzzle(self) -> str:
        return f"{self.signature}.{self.base64}"


@dataclass(slots=True)
class FriendlySolution:
    puzzle: FriendlyPuzzle
    solution_bytes: bytes
    diagnostics: bytes
    took_ms: int
    checked: int

    @property
    def payload(self) -> str:
        return ".".join(
            (
                self.puzzle.signature,
                self.puzzle.base64,
                _b64encode(self.solution_bytes),
                _b64encode(self.diagnostics),
            )
        )

    @property
    def solution_b64(self) -> str:
        return _b64encode(self.solution_bytes)

    @property
    def diagnostics_b64(self) -> str:
        return _b64encode(self.diagnostics)


def friendly_difficulty_to_threshold(difficulty: int) -> int:
    d = max(0, min(255, int(difficulty)))
    return int(math.pow(2, (255.999 - d) / 8.0)) & 0xFFFFFFFF


def parse_friendly_puzzle(puzzle: str) -> FriendlyPuzzle:
    text = (puzzle or "").strip()
    parts = text.split(".")
    if len(parts) < 2:
        raise ValueError("FriendlyCaptcha puzzle must be '<signature>.<base64 puzzle>'")
    signature, puzzle_b64 = parts[PUZZLE_SIGNATURE_INDEX], parts[PUZZLE_BUFFER_INDEX]
    if not signature or not puzzle_b64:
        raise ValueError("FriendlyCaptcha puzzle has empty signature or buffer")
    buf = _b64decode(puzzle_b64)
    if len(buf) < 16 or len(buf) > 64:
        raise ValueError(f"FriendlyCaptcha puzzle buffer size must be 16..64 bytes, got {len(buf)}")
    n = int(buf[NUMBER_OF_PUZZLES_OFFSET])
    difficulty = int(buf[PUZZLE_DIFFICULTY_OFFSET])
    if n <= 0:
        raise ValueError("FriendlyCaptcha puzzle requires at least one solution")
    return FriendlyPuzzle(
        signature=signature,
        base64=puzzle_b64,
        buffer=buf,
        n=n,
        difficulty=difficulty,
        threshold=friendly_difficulty_to_threshold(difficulty),
    )


def solve_friendly_puzzle(
    puzzle: FriendlyPuzzle | str,
    *,
    max_attempts_per_solution: int = DEFAULT_MAX_ATTEMPTS_PER_SOLUTION,
    workers: int = 1,
    timeout_sec: int | float | None = None,
    solver_id: int = SOLVER_TYPE_UNSPECIFIED,
) -> FriendlySolution | None:
    item = parse_friendly_puzzle(puzzle) if isinstance(puzzle, str) else puzzle
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    all_solutions: list[bytes] = []
    checked_total = 0
    for index in range(item.n):
        remaining_timeout = None
        if deadline is not None:
            remaining_timeout = max(0.0, deadline - time.monotonic())
            if remaining_timeout <= 0:
                return None
        solved, checked = _solve_one_solution(
            item.buffer,
            item.threshold,
            index,
            max_attempts=max_attempts_per_solution,
            workers=workers,
            timeout_sec=remaining_timeout,
        )
        checked_total += checked
        if solved is None:
            return None
        all_solutions.append(solved)
    took_ms = int((time.monotonic() - started) * 1000)
    diagnostics = create_friendly_diagnostics(solver_id, max(0, min(65535, round(took_ms / 1000))))
    return FriendlySolution(
        puzzle=item,
        solution_bytes=b"".join(all_solutions),
        diagnostics=diagnostics,
        took_ms=took_ms,
        checked=checked_total,
    )


def create_friendly_diagnostics(solver_id: int, seconds: int) -> bytes:
    # friendly-pow uses DataView.setUint16 without littleEndian, i.e. big endian.
    return bytes([max(0, min(255, int(solver_id)))]) + max(0, min(65535, int(seconds))).to_bytes(2, "big")


def parse_friendly_solution_payload(payload: str) -> dict[str, Any]:
    parts = (payload or "").split(".")
    if len(parts) != 4:
        raise ValueError("FriendlyCaptcha solution must have 4 dot-separated parts")
    puzzle = parse_friendly_puzzle(".".join(parts[:2]))
    solution = _b64decode(parts[2])
    diagnostics = _b64decode(parts[3])
    return {
        "signature": puzzle.signature,
        "puzzle_base64": puzzle.base64,
        "solutions_base64": parts[2],
        "diagnostics_base64": parts[3],
        "solution_count": puzzle.n,
        "difficulty": puzzle.difficulty,
        "threshold": puzzle.threshold,
        "solution_bytes": solution,
        "diagnostics": diagnostics,
    }


def _solve_one_solution(
    puzzle_buffer: bytes,
    threshold: int,
    index: int,
    *,
    max_attempts: int,
    workers: int,
    timeout_sec: int | float | None,
) -> tuple[bytes | None, int]:
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if workers <= 1 or max_attempts < 80_000:
        return _solve_range(puzzle_buffer, threshold, index, 0, max_attempts)

    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = []
        for worker in range(workers):
            lo = worker * chunk
            hi = min(max_attempts, lo + chunk)
            if lo >= hi:
                break
            futures.append(pool.submit(_solve_range, puzzle_buffer, threshold, index, lo, hi))
        pending = set(futures)
        while pending:
            wait_timeout = None
            if deadline is not None:
                wait_timeout = max(0.0, deadline - time.monotonic())
                if wait_timeout <= 0:
                    break
            done, pending = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
            if not done:
                break
            for fut in done:
                solution, checked = fut.result()
                checked_total += checked
                if solution is not None:
                    for other in pending:
                        other.cancel()
                    return solution, checked_total
    return None, checked_total


def _solve_range(
    puzzle_buffer: bytes,
    threshold: int,
    index: int,
    start_attempt: int,
    end_attempt: int,
) -> tuple[bytes | None, int]:
    inp = bytearray(CHALLENGE_SIZE_BYTES)
    inp[: len(puzzle_buffer)] = puzzle_buffer
    inp[120] = int(index) & 0xFF
    checked = 0
    for attempt in range(int(start_attempt), int(end_attempt)):
        b123 = attempt // _UINT32_SPACE
        nonce = attempt % _UINT32_SPACE
        if b123 > 255:
            break
        inp[123] = b123 & 0xFF
        inp[124:128] = int(nonce).to_bytes(4, "little")
        digest = hashlib.blake2b(inp, digest_size=32).digest()
        checked += 1
        if int.from_bytes(digest[:4], "little") < threshold:
            return bytes(inp[120:128]), checked
    return None, checked


def extract_friendly_puzzle_from_response(data: Any) -> str | None:
    if isinstance(data, str):
        text = data.strip()
        return text if "." in text else None
    if isinstance(data, dict):
        for key in ("puzzle", "challenge"):
            value = data.get(key)
            if isinstance(value, str) and "." in value:
                return value
        nested = data.get("data")
        if isinstance(nested, dict):
            return extract_friendly_puzzle_from_response(nested)
    return None


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    text = value.strip()
    # FriendlyCaptcha uses standard base64, but accepting urlsafe/paddingless
    # helps with fixtures and proxy-normalized transports.
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.b64decode(text)


class FriendlyCaptchaSolver:
    """FriendlyCaptcha classic proof-of-work protocol solver.

    It solves the `friendly-pow` puzzle locally and returns the exact hidden
    field payload used by the browser widget:
    `<signature>.<puzzle_b64>.<solutions_b64>.<diagnostics_b64>`.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        puzzle: str | None = None,
        puzzle_file: str | None = None,
        puzzle_url: str | None = None,
        sitekey: str | None = None,
        max_attempts_per_solution: int = DEFAULT_MAX_ATTEMPTS_PER_SOLUTION,
        workers: int = 1,
        timeout_sec: int = 60,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        frc_client: str = DEFAULT_FRC_CLIENT,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "puzzle_url": puzzle_url,
            "sitekey_present": bool(sitekey),
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
                out = output_root / "friendlycaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="friendlycaptcha",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("puzzle_signature"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            puzzle_value = self._load_puzzle(
                puzzle=puzzle,
                puzzle_file=puzzle_file,
                puzzle_url=puzzle_url,
                sitekey=sitekey,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                frc_client=frc_client,
                raw=raw,
            )
            if not puzzle_value:
                errors.append("puzzle, puzzle_file or puzzle_url is required")
                return finish(ok=False)
            parsed = parse_friendly_puzzle(puzzle_value)
            raw["puzzle"] = {
                "signature": parsed.signature,
                "base64": parsed.base64,
                "size": len(parsed.buffer),
                "n": parsed.n,
                "difficulty": parsed.difficulty,
                "threshold": parsed.threshold,
            }
            diagnostics.update(
                {
                    "puzzle_signature": parsed.signature,
                    "puzzle_size": len(parsed.buffer),
                    "solution_count": parsed.n,
                    "difficulty": parsed.difficulty,
                    "threshold": parsed.threshold,
                }
            )
            solution = solve_friendly_puzzle(
                parsed,
                max_attempts_per_solution=max_attempts_per_solution,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("no FriendlyCaptcha solution found before timeout/attempt limit")
                return finish(ok=False)
            raw["solution"] = {
                "tookMs": solution.took_ms,
                "checked": solution.checked,
                "solutionsBase64": solution.solution_b64,
                "diagnosticsBase64": solution.diagnostics_b64,
                "payload": solution.payload,
            }
            diagnostics.update(
                {
                    "solve_ms": solution.took_ms,
                    "checked": solution.checked,
                    "solutions_b64": solution.solution_b64,
                    "diagnostics_b64": solution.diagnostics_b64,
                }
            )
            return finish(ok=True, ticket=solution.payload, verify_code=str(parsed.n))
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_puzzle(
        self,
        *,
        puzzle: str | None,
        puzzle_file: str | None,
        puzzle_url: str | None,
        sitekey: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        frc_client: str,
        raw: dict[str, Any],
    ) -> str | None:
        if puzzle_file:
            text = Path(puzzle_file).read_text(encoding="utf-8").strip()
            try:
                data = json.loads(text)
                found = extract_friendly_puzzle_from_response(data)
                if found:
                    return found
            except Exception:
                pass
            return text
        if puzzle:
            text = puzzle.strip()
            if text.startswith("@"):
                return self._load_puzzle(
                    puzzle=None,
                    puzzle_file=text[1:],
                    puzzle_url=None,
                    sitekey=None,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    frc_client=frc_client,
                    raw=raw,
                )
            return text
        if not puzzle_url:
            return None
        req_headers = {"Accept": "application/json, text/plain, */*", "x-frc-client": frc_client}
        if headers:
            req_headers.update(headers)
        params = {"sitekey": sitekey} if sitekey else None
        resp = requests.get(
            puzzle_url,
            params=params,
            headers=req_headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["puzzleResponse"] = {"status": resp.status_code, "url": resp.url}
        resp.raise_for_status()
        ctype = (resp.headers or {}).get("content-type", "")
        if "json" in ctype.lower():
            data = resp.json()
            raw["puzzleResponse"]["json"] = data
            return extract_friendly_puzzle_from_response(data)
        text = resp.text.strip()
        raw["puzzleResponse"]["text"] = text[:200]
        return extract_friendly_puzzle_from_response(text) or text
