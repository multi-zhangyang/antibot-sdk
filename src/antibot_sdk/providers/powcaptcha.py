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

DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class PowCaptchaUncertainty:
    index: int
    minimum: int
    maximum: int
    base: int
    values: tuple[int, ...]
    position_by_value: tuple[int, ...]


@dataclass(slots=True)
class PowCaptchaQuiz:
    raw: bytes
    a1: int
    a2: int
    target_hash: bytes
    buffer: bytes
    uncertainties: list[PowCaptchaUncertainty]
    challenge_id: str | None = None

    @property
    def search_space(self) -> int:
        total = 1
        for u in self.uncertainties:
            total *= u.base
        return total


@dataclass(slots=True)
class PowCaptchaSolution:
    quiz: PowCaptchaQuiz
    answer: bytes
    attempts: int
    took_ms: int
    worker_type: str = "python"

    @property
    def answer_b64(self) -> str:
        return base64.b64encode(self.answer).decode("ascii")

    @property
    def answer_hex(self) -> str:
        return self.answer.hex()

    @property
    def submit_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "answer": self.answer_b64,
            "answerHex": self.answer_hex,
            "worker_type": self.worker_type,
            "time": self.took_ms,
        }
        if self.quiz.challenge_id:
            body["id"] = self.quiz.challenge_id
        return body

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def parse_powcaptcha_quiz(raw: bytes | bytearray | str, *, challenge_id: str | None = None) -> PowCaptchaQuiz:
    data = _coerce_bytes(raw)
    if len(data) < 4 + 32:
        raise ValueError("pow_captcha quiz is too short")
    a1 = data[0]
    a2 = data[1] + 1
    count = int.from_bytes(data[2:4], "big")
    meta_len = 4 + count * 4
    if len(data) < meta_len + 32:
        raise ValueError("pow_captcha quiz is truncated")
    if a2 <= a1:
        raise ValueError("pow_captcha invalid byte domain")
    target_hash = data[meta_len : meta_len + 32]
    buffer = data[meta_len + 32 :]
    if not buffer:
        raise ValueError("pow_captcha quiz has empty buffer")

    uncertainties: list[PowCaptchaUncertainty] = []
    for i in range(count):
        off = 4 + i * 4
        index = int.from_bytes(data[off : off + 2], "big")
        minimum = data[off + 2]
        maximum = data[off + 3]
        if index >= len(buffer):
            raise ValueError(f"pow_captcha uncertainty index out of buffer: {index}")
        base = 1 + (maximum - minimum if maximum > minimum else (a2 - minimum) + (maximum - a1))
        if base < 1 or base > (a2 - a1 + 1):
            raise ValueError(f"pow_captcha invalid uncertainty base: {base}")
        values = _uncertainty_values(a1, a2, minimum, maximum, base)
        position_by_value = _position_map(values)
        uncertainties.append(
            PowCaptchaUncertainty(
                index=index,
                minimum=minimum,
                maximum=maximum,
                base=base,
                values=values,
                position_by_value=position_by_value,
            )
        )
    return PowCaptchaQuiz(
        raw=data,
        a1=a1,
        a2=a2,
        target_hash=target_hash,
        buffer=buffer,
        uncertainties=uncertainties,
        challenge_id=challenge_id,
    )


def solve_powcaptcha_quiz(
    quiz: PowCaptchaQuiz | bytes | bytearray | str,
    *,
    challenge_id: str | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PowCaptchaSolution | None:
    item = parse_powcaptcha_quiz(quiz, challenge_id=challenge_id) if not isinstance(quiz, PowCaptchaQuiz) else quiz
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if not item.uncertainties:
        if hashlib.sha256(item.buffer).digest() == item.target_hash:
            return PowCaptchaSolution(item, item.buffer, 0, int((time.monotonic() - started) * 1000))
        return None

    if workers <= 1 or max_attempts < 100_000:
        answer, attempts = _solve_powcaptcha_range(item, start, start + max_attempts, deadline)
        if answer is None:
            return None
        return PowCaptchaSolution(item, answer, attempts, int((time.monotonic() - started) * 1000))

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    raw = item.raw
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_powcaptcha_raw_range, raw, item.challenge_id, lo, hi, deadline)] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            answer, attempts = fut.result()
            checked_total += attempts
            if answer is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return PowCaptchaSolution(item, answer, checked_total, int((time.monotonic() - started) * 1000))
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None


def verify_powcaptcha_answer(quiz: PowCaptchaQuiz | bytes | bytearray | str, answer: bytes | bytearray | str) -> bool:
    try:
        item = parse_powcaptcha_quiz(quiz) if not isinstance(quiz, PowCaptchaQuiz) else quiz
        raw_answer = _coerce_answer_bytes(answer)
        return len(raw_answer) == len(item.buffer) and hashlib.sha256(raw_answer).digest() == item.target_hash
    except Exception:
        return False


def powcaptcha_quiz_to_base64(raw: bytes | bytearray | str) -> str:
    return base64.b64encode(_coerce_bytes(raw)).decode("ascii")


def _solve_powcaptcha_raw_range(
    raw: bytes,
    challenge_id: str | None,
    start: int,
    end_exclusive: int,
    deadline: float | None,
) -> tuple[bytes | None, int]:
    return _solve_powcaptcha_range(parse_powcaptcha_quiz(raw, challenge_id=challenge_id), start, end_exclusive, deadline)


def _solve_powcaptcha_range(
    quiz: PowCaptchaQuiz,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[bytes | None, int]:
    state = _state_after_attempt(quiz, start)
    attempts = 0
    for attempt in range(start, end_exclusive):
        if deadline is not None and attempts and attempts % 4096 == 0 and time.monotonic() >= deadline:
            return None, attempts
        attempts += 1
        if hashlib.sha256(state).digest() == quiz.target_hash:
            return bytes(state), attempts
        if attempt + 1 < end_exclusive:
            _increment_state(quiz, state)
    return None, attempts


def _state_after_attempt(quiz: PowCaptchaQuiz, attempt_index: int) -> bytearray:
    state = bytearray(quiz.buffer)
    increments = int(attempt_index) + 1
    if increments < 1:
        increments = 1
    carry = increments
    for u in reversed(quiz.uncertainties):
        current_pos = u.position_by_value[state[u.index]]
        if current_pos < 0:
            raise ValueError(f"buffer value {state[u.index]} is outside uncertainty range at index {u.index}")
        total = current_pos + carry
        state[u.index] = u.values[total % u.base]
        carry = total // u.base
    return state


def _increment_state(quiz: PowCaptchaQuiz, state: bytearray) -> None:
    for u in reversed(quiz.uncertainties):
        current = state[u.index]
        pos = u.position_by_value[current]
        if pos < 0:
            raise ValueError(f"buffer value {current} is outside uncertainty range at index {u.index}")
        next_pos = (pos + 1) % u.base
        state[u.index] = u.values[next_pos]
        if state[u.index] != u.minimum:
            break


def _position_map(values: tuple[int, ...]) -> tuple[int, ...]:
    pos = [-1] * 256
    for i, value in enumerate(values):
        pos[value] = i
    return tuple(pos)


def _uncertainty_values(a1: int, a2: int, minimum: int, maximum: int, base: int) -> tuple[int, ...]:
    values = [minimum]
    cur = minimum
    for _ in range(base - 1):
        cur = _next_uncertainty_value(cur, a1, a2, minimum, base)
        values.append(cur)
    return tuple(values)


def _next_uncertainty_value(current: int, a1: int, a2: int, minimum: int, base: int) -> int:
    min_off = minimum - a1
    num = (current + 1) - a1
    domain = a2 - a1
    adjusted = num + min_off + (domain - min_off) if num < min_off else num
    addition = ((adjusted - min_off) % base) + min_off
    return (addition % domain) + a1


def _coerce_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    text = str(value).strip()
    if text.startswith("base64:"):
        text = text.split(":", 1)[1]
    elif text.startswith("b64:"):
        text = text.split(":", 1)[1]
    elif text.startswith("hex:"):
        return bytes.fromhex(text.split(":", 1)[1])
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        try:
            return bytes.fromhex(text)
        except Exception:
            return text.encode("latin1")


def _coerce_answer_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value)
    if text.startswith("base64:") or text.startswith("b64:") or text.startswith("hex:"):
        return _coerce_bytes(text)
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        try:
            return bytes.fromhex(text)
        except Exception:
            return text.encode("utf-8")


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _extract_quiz(data: Any, *, challenge_id: str | None = None) -> tuple[bytes, str | None]:
    if isinstance(data, (bytes, bytearray, str)):
        return _coerce_bytes(data), challenge_id
    if isinstance(data, dict):
        cid = challenge_id or data.get("id") or data.get("challengeId") or data.get("challenge_id")
        for key in ("quiz", "test", "challenge", "captcha", "pow"):
            value = data.get(key)
            if isinstance(value, (str, bytes, bytearray)):
                return _coerce_bytes(value), str(cid) if cid is not None else None
        for key in ("quiz_b64", "quizBase64", "challenge_b64", "challengeBase64"):
            value = data.get(key)
            if isinstance(value, str):
                return base64.b64decode(value), str(cid) if cid is not None else None
        for key in ("quiz_hex", "quizHex", "challenge_hex", "challengeHex"):
            value = data.get(key)
            if isinstance(value, str):
                return bytes.fromhex(value), str(cid) if cid is not None else None
        nested = data.get("data")
        if isinstance(nested, (dict, str, bytes, bytearray)):
            return _extract_quiz(nested, challenge_id=str(cid) if cid is not None else None)
    raise ValueError("failed to extract pow_captcha quiz")


class PowCaptchaSolver:
    """pow_captcha binary proof-of-work protocol solver.

    The quiz encodes a SHA-256 hash of the correct buffer, a corrupted buffer,
    and per-byte uncertainty ranges.  Solving is pure protocol work: enumerate
    the mixed-radix uncertainty space until the buffer hash matches.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        quiz: str | bytes | None = None,
        quiz_b64: str | None = None,
        quiz_hex: str | None = None,
        quiz_file: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        challenge_id: str | None = None,
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
                out = output_root / "powcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powcaptcha",
                ok=ok,
                captcha_type="buffer_reconstruction_pow",
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
            quiz_raw, cid = self._load_quiz(
                quiz=quiz,
                quiz_b64=quiz_b64,
                quiz_hex=quiz_hex,
                quiz_file=quiz_file,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                challenge_id=challenge_id,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_powcaptcha_quiz(quiz_raw, challenge_id=cid)
            raw["quiz"] = {
                "bytes": len(item.raw),
                "bufferBytes": len(item.buffer),
                "uncertainties": len(item.uncertainties),
                "searchSpace": item.search_space,
                "hash": item.target_hash.hex(),
            }
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "buffer_bytes": len(item.buffer),
                    "uncertainties": len(item.uncertainties),
                    "search_space": item.search_space,
                    "domain": [item.a1, item.a2],
                }
            )

            solution = solve_powcaptcha_quiz(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("pow_captcha solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "answer": solution.answer_b64,
                "answerHex": solution.answer_hex,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                    "answer_bytes": len(solution.answer),
                }
            )
            ticket = solution.answer_b64
            verify_code = "solved"
            if submit or verify_url:
                if not verify_url:
                    errors.append("pow_captcha submit requested but verify_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(verify_data, dict):
                    for key in ("success", "ok", "valid", "verified"):
                        if key in verify_data and not verify_data[key]:
                            errors.append("pow_captcha verification endpoint rejected answer")
                            return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                    ticket = str(verify_data.get("token") or verify_data.get("ticket") or ticket)
                verify_code = "validated"
                diagnostics["submitted"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_quiz(
        self,
        *,
        quiz: str | bytes | None,
        quiz_b64: str | None,
        quiz_hex: str | None,
        quiz_file: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        challenge_id: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> tuple[bytes, str | None]:
        if quiz is not None:
            raw["challengeSource"] = "inline"
            return _coerce_bytes(quiz), challenge_id
        if quiz_b64:
            raw["challengeSource"] = "base64"
            return base64.b64decode(quiz_b64), challenge_id
        if quiz_hex:
            raw["challengeSource"] = "hex"
            return bytes.fromhex(quiz_hex), challenge_id
        if quiz_file:
            raw["challengeSource"] = "file"
            return Path(quiz_file).read_bytes(), challenge_id

        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return _extract_quiz(data, challenge_id=challenge_id)
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            ctype = (resp.headers or {}).get("content-type", "").lower()
            if "json" in ctype:
                data = resp.json()
                raw["challengeSource"] = "url-json"
                return _extract_quiz(data, challenge_id=challenge_id)
            raw["challengeSource"] = "url-bytes"
            return resp.content, challenge_id
        raise ValueError("pow_captcha requires quiz, quiz_b64, quiz_hex, quiz_file, challenge_json or challenge_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PowCaptchaSolution,
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
