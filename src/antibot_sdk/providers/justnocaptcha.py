from __future__ import annotations

import asyncio
import html
import json
import re
import secrets
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_DIFFICULTY = 4
DEFAULT_PUZZLES = 50
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_PUZZLES = 10_000
DEFAULT_CHALLENGE_FIELD = "challenge"
DEFAULT_RESPONSE_FIELD = "solution"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_UINT32 = 0xFFFFFFFF
_FNV_PRIME = 16_777_619
_FNV_OFFSET = 2_166_136_261


@dataclass(slots=True)
class JustNoCaptchaChallenge:
    challenge: str
    difficulty: int
    puzzles_string: str
    puzzles: list[str]
    challenge_hash: str
    threshold: int
    length_per_solution: int
    solution_length_required: int
    challenge_salt: str | None = None

    @property
    def number_puzzles(self) -> int:
        return len(self.puzzles)

    def to_payload(self, *, include_puzzles: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "challenge": self.challenge,
            "difficulty": self.difficulty,
            "numberPuzzles": self.number_puzzles,
            "threshold": self.threshold,
            "lengthPerSolution": self.length_per_solution,
            "solutionLengthRequired": self.solution_length_required,
            "challengeHash": self.challenge_hash,
            "challengeSaltProvided": self.challenge_salt is not None,
        }
        if include_puzzles:
            out["puzzles"] = self.puzzles
        return out


@dataclass(slots=True)
class JustNoCaptchaSolution:
    challenge: JustNoCaptchaChallenge
    solution: str
    candidates: list[str]
    attempts: int
    solve_time_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return build_justnocaptcha_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "solution": self.solution,
            "candidates": self.candidates,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def justnocaptcha_hash(value: str | int | bytes | bytearray) -> str:
    data = _to_bytes(value)
    a = _FNV_OFFSET
    b = 2_341_284_503
    c = 3_386_659_096
    d = 2_073_922_445
    for byte in data:
        a = _imul32((a ^ byte) & _UINT32, _FNV_PRIME)
        b = _imul32((b ^ ((byte << 1) & 0xFF)) & _UINT32, _FNV_PRIME)
        c = _imul32((c ^ ((byte << 2) & 0xFF)) & _UINT32, _FNV_PRIME)
        d = _imul32((d ^ ((byte << 3) & 0xFF)) & _UINT32, _FNV_PRIME)
    return "".join(_fmix_hex(x) for x in (a, b, c, d))


def justnocaptcha_hash_int(value: str | int | bytes | bytearray) -> int:
    h = _FNV_OFFSET
    for byte in _to_bytes(value):
        h = _imul32((h ^ byte) & _UINT32, _FNV_PRIME)
    return _fmix_int(h)


def create_justnocaptcha_challenge(
    *,
    puzzles: int = DEFAULT_PUZZLES,
    difficulty: int = DEFAULT_DIFFICULTY,
    challenge_salt: str,
) -> str:
    if not challenge_salt:
        raise ValueError("JustNoCaptcha challenge_salt is required for challenge creation")
    difficulty = int(difficulty)
    puzzles = int(puzzles)
    if not 1 <= difficulty <= 7:
        raise ValueError("JustNoCaptcha difficulty must be between 1 and 7")
    if not 1 <= puzzles <= DEFAULT_MAX_PUZZLES:
        raise ValueError(f"JustNoCaptcha puzzles must be between 1 and {DEFAULT_MAX_PUZZLES}")
    body = str(difficulty) + "".join(secrets.token_hex(16) for _ in range(puzzles))
    return body + justnocaptcha_hash(body + challenge_salt)


def parse_justnocaptcha_challenge(
    value: JustNoCaptchaChallenge | dict[str, Any] | str,
    *,
    challenge_salt: str | None = None,
) -> JustNoCaptchaChallenge:
    if isinstance(value, JustNoCaptchaChallenge):
        if challenge_salt is not None and value.challenge_salt != challenge_salt:
            return parse_justnocaptcha_challenge(value.challenge, challenge_salt=challenge_salt)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("JustNoCaptcha challenge is empty")
        if text.startswith("@"):
            return parse_justnocaptcha_challenge(Path(text[1:]).read_text(encoding="utf-8"), challenge_salt=challenge_salt)
        if "<" in text and "challenge" in text.lower():
            return parse_justnocaptcha_challenge(extract_justnocaptcha_from_html(text), challenge_salt=challenge_salt)
        if text.startswith("{"):
            try:
                return parse_justnocaptcha_challenge(json.loads(text), challenge_salt=challenge_salt)
            except ValueError:
                pass
        challenge = text
    elif isinstance(value, dict):
        data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
        if challenge_salt is None:
            challenge_salt = _first_str(data, "challengeSalt", "challenge_salt", "salt")
        challenge = _first_str(
            data,
            "challenge",
            "challengeData",
            "challenge_data",
            "justnocaptcha_challenge",
            DEFAULT_CHALLENGE_FIELD,
        )
        if not challenge:
            raise ValueError("JustNoCaptcha challenge JSON requires challenge")
    else:
        raise ValueError("JustNoCaptcha challenge must be string or JSON object")

    challenge = str(challenge).strip()
    clen = len(challenge)
    if clen < 33 or (clen - 1) % 32 != 0:
        raise ValueError("Invalid JustNoCaptcha challenge data")
    try:
        difficulty = int(challenge[0])
    except ValueError as e:
        raise ValueError("Invalid JustNoCaptcha difficulty") from e
    if not 1 <= difficulty <= 7:
        raise ValueError("JustNoCaptcha difficulty must be between 1 and 7")
    puzzles_string = challenge[1:-32]
    if not puzzles_string or len(puzzles_string) % 32 != 0:
        raise ValueError("Invalid JustNoCaptcha puzzles string")
    if not re.fullmatch(r"[0-9a-fA-F]+", puzzles_string):
        raise ValueError("JustNoCaptcha puzzles must be hexadecimal")
    challenge_hash = challenge[-32:].lower()
    if not re.fullmatch(r"[0-9a-f]{32}", challenge_hash):
        raise ValueError("Invalid JustNoCaptcha challenge hash")
    if challenge_salt is not None:
        expected = justnocaptcha_hash(challenge[:-32] + challenge_salt)
        if expected != challenge_hash:
            raise ValueError("Invalid JustNoCaptcha challenge hash for supplied challenge_salt")
    puzzles = [puzzles_string[i : i + 32].lower() for i in range(0, len(puzzles_string), 32)]
    if len(puzzles) > DEFAULT_MAX_PUZZLES:
        raise ValueError(f"JustNoCaptcha puzzle count exceeds {DEFAULT_MAX_PUZZLES}")
    length_per_solution = difficulty + 2
    return JustNoCaptchaChallenge(
        challenge=challenge,
        difficulty=difficulty,
        puzzles_string=puzzles_string.lower(),
        puzzles=puzzles,
        challenge_hash=challenge_hash,
        threshold=10 ** (10 - difficulty),
        length_per_solution=length_per_solution,
        solution_length_required=len(puzzles) * length_per_solution,
        challenge_salt=challenge_salt,
    )


def extract_justnocaptcha_from_html(html_text: str) -> dict[str, Any]:
    text = str(html_text)
    for field in (
        DEFAULT_CHALLENGE_FIELD,
        "justnocaptcha_challenge",
        "justnocaptcha_challenge_data",
        "justnocaptcha",
    ):
        value = _extract_input_value(text, field)
        if value:
            return {"challenge": value, "challengeField": field}
    for attr in ("data-challenge", "data-justnocaptcha-challenge", "data-justnocaptcha"):
        value = _extract_attr_value(text, attr)
        if value:
            return {"challenge": value, "challengeField": attr}
    raise ValueError("JustNoCaptcha HTML does not contain challenge input/data attribute")


def solve_justnocaptcha_puzzle(
    puzzle: str,
    difficulty: int,
    *,
    start: int | None = None,
    max_attempts: int | None = None,
    deadline_epoch: float | None = None,
) -> tuple[str | None, int]:
    difficulty = int(difficulty)
    if not 1 <= difficulty <= 7:
        raise ValueError("JustNoCaptcha difficulty must be between 1 and 7")
    start_value = 10 ** (difficulty + 1) if start is None else max(0, int(start))
    hard_end = 10 ** (difficulty + 2)
    if max_attempts is None:
        end_exclusive = hard_end + 1
    else:
        end_exclusive = min(hard_end + 1, start_value + max(1, int(max_attempts)))
    checked = 0
    prefix = str(puzzle)
    threshold = 10 ** (10 - difficulty)
    for candidate in range(start_value, end_exclusive):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, checked
        checked += 1
        if justnocaptcha_hash_int(prefix + str(candidate)) <= threshold:
            return str(candidate), checked
    return None, checked


def solve_justnocaptcha_challenge(
    challenge: JustNoCaptchaChallenge | dict[str, Any] | str,
    *,
    challenge_salt: str | None = None,
    start: int | None = None,
    max_attempts_per_puzzle: int | None = None,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> JustNoCaptchaSolution | None:
    item = parse_justnocaptcha_challenge(challenge, challenge_salt=challenge_salt)
    started = time.monotonic()
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None
    workers = max(1, int(workers or 1))

    if workers <= 1 or item.number_puzzles <= 1:
        candidates: list[str] = []
        attempts_total = 0
        for puzzle in item.puzzles:
            candidate, attempts = solve_justnocaptcha_puzzle(
                puzzle,
                item.difficulty,
                start=start,
                max_attempts=max_attempts_per_puzzle,
                deadline_epoch=deadline_epoch,
            )
            attempts_total += attempts
            if candidate is None:
                return None
            candidates.append(candidate)
        return JustNoCaptchaSolution(
            challenge=item,
            solution="".join(candidates),
            candidates=candidates,
            attempts=attempts_total,
            solve_time_ms=int((time.monotonic() - started) * 1000),
        )

    candidates_by_index: dict[int, str] = {}
    attempts_total = 0
    pool = ProcessPoolExecutor(max_workers=min(workers, item.number_puzzles))
    futures = {
        pool.submit(
            _solve_puzzle_worker,
            index,
            puzzle,
            item.difficulty,
            start,
            max_attempts_per_puzzle,
            deadline_epoch,
        ): index
        for index, puzzle in enumerate(item.puzzles)
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            index, candidate, attempts = fut.result()
            attempts_total += attempts
            if candidate is None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            candidates_by_index[index] = candidate
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if len(candidates_by_index) != item.number_puzzles:
        return None
    candidates = [candidates_by_index[i] for i in range(item.number_puzzles)]
    return JustNoCaptchaSolution(
        challenge=item,
        solution="".join(candidates),
        candidates=candidates,
        attempts=attempts_total,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def verify_justnocaptcha_solution(
    challenge: JustNoCaptchaChallenge | dict[str, Any] | str,
    solution: JustNoCaptchaSolution | dict[str, Any] | str,
    *,
    challenge_salt: str | None = None,
) -> bool:
    try:
        item = parse_justnocaptcha_challenge(challenge, challenge_salt=challenge_salt)
        if isinstance(solution, JustNoCaptchaSolution):
            value = solution.solution
        elif isinstance(solution, dict):
            value = _first_str(solution, "solution", "justnocaptcha_solution", DEFAULT_RESPONSE_FIELD) or ""
        else:
            value = str(solution)
        if not value or len(value) != item.solution_length_required or not value.isdigit():
            return False
        for idx, puzzle in enumerate(item.puzzles):
            lo = idx * item.length_per_solution
            candidate = value[lo : lo + item.length_per_solution]
            if justnocaptcha_hash_int(puzzle + candidate) > item.threshold:
                return False
        return True
    except Exception:
        return False


def build_justnocaptcha_submit_body(
    challenge: JustNoCaptchaChallenge | dict[str, Any] | str,
    solution: JustNoCaptchaSolution | dict[str, Any] | str,
    *,
    challenge_field: str = DEFAULT_CHALLENGE_FIELD,
    response_field: str = DEFAULT_RESPONSE_FIELD,
) -> dict[str, Any]:
    item = parse_justnocaptcha_challenge(challenge)
    if isinstance(solution, JustNoCaptchaSolution):
        value = solution.solution
    elif isinstance(solution, dict):
        value = _first_str(solution, "solution", "justnocaptcha_solution", response_field) or ""
    else:
        value = str(solution)
    return {challenge_field: item.challenge, response_field: value}


class JustNoCaptchaSolver:
    """JustNoCaptcha multi-puzzle FNV/fmix proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        challenge_salt: str | None = None,
        start: int | None = None,
        max_attempts_per_puzzle: int | None = None,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        challenge_field: str = DEFAULT_CHALLENGE_FIELD,
        response_field: str = DEFAULT_RESPONSE_FIELD,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "submit_url": submit_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_puzzle": max_attempts_per_puzzle,
            "challenge_salt_provided": challenge_salt is not None,
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
                out = output_root / "justnocaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="justnocaptcha",
                ok=ok,
                captcha_type="multi_puzzle_fnv_pow",
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
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            parsed = parse_justnocaptcha_challenge(source, challenge_salt=challenge_salt)
            raw["challenge"] = parsed.to_payload(include_puzzles=False)
            diagnostics.update(
                {
                    "difficulty": parsed.difficulty,
                    "number_puzzles": parsed.number_puzzles,
                    "threshold": parsed.threshold,
                    "solution_length_required": parsed.solution_length_required,
                    "challenge_salt_provided": parsed.challenge_salt is not None,
                }
            )
            solution = solve_justnocaptcha_challenge(
                parsed,
                start=start,
                max_attempts_per_puzzle=max_attempts_per_puzzle,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("JustNoCaptcha solve failed: timeout or max_attempts_per_puzzle exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_justnocaptcha_solution(parsed, solution):
                errors.append("JustNoCaptcha internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            submit_body = build_justnocaptcha_submit_body(
                parsed,
                solution,
                challenge_field=challenge_field,
                response_field=response_field,
            )
            raw["solution"] = {**solution.to_payload(), "submitBody": submit_body}
            diagnostics.update(
                {
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                    "solution_length": len(solution.solution),
                }
            )
            ticket = _json_body(submit_body)
            verify_code = "solved"
            if submit or submit_url:
                if not submit_url:
                    errors.append("submit requested but submit_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp = requests.post(
                    submit_url,
                    data=_json_body(submit_body),
                    headers=_merge_headers(headers, user_agent),
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                try:
                    payload: Any = resp.json()
                except ValueError:
                    payload = {"text": resp.text[:500]}
                raw["submitResponse"] = {"status": resp.status_code, "url": submit_url, "json": payload}
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


def _solve_puzzle_worker(
    index: int,
    puzzle: str,
    difficulty: int,
    start: int | None,
    max_attempts: int | None,
    deadline_epoch: float | None,
) -> tuple[int, str | None, int]:
    candidate, attempts = solve_justnocaptcha_puzzle(
        puzzle,
        difficulty,
        start=start,
        max_attempts=max_attempts,
        deadline_epoch=deadline_epoch,
    )
    return index, candidate, attempts


def _load_source(
    *,
    challenge: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_html: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if challenge:
        raw["challengeSource"] = "challenge"
        return challenge
    if challenge_html:
        raw["challengeSource"] = "html"
        return extract_justnocaptcha_from_html(challenge_html)
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("JustNoCaptcha requires challenge, challenge_json, challenge_file, challenge_html or challenge_url")
    resp = requests.get(
        challenge_url,
        headers=headers,
        timeout=timeout_sec,
        proxies=_requests_proxies(proxy_server),
    )
    content_type = resp.headers.get("Content-Type", "")
    raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "contentType": content_type}
    resp.raise_for_status()
    if "json" in content_type:
        payload = resp.json()
        raw["challengeResponse"]["json"] = payload
        raw["challengeSource"] = "url_json"
        return payload
    text = resp.text.strip()
    if "<" in text:
        raw["challengeSource"] = "url_html"
        return extract_justnocaptcha_from_html(text)
    raw["challengeSource"] = "url_text"
    return text


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


def _to_bytes(value: str | int | bytes | bytearray) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def _imul32(a: int, b: int) -> int:
    return (int(a) * int(b)) & _UINT32


def _fmix_int(value: int) -> int:
    t = int(value) & _UINT32
    t = (t ^ (t >> 16)) & _UINT32
    lo = t & 0xFFFF
    hi = (t >> 16) & 0xFFFF
    t = (51_819 * lo + (((51_819 * hi + 34_283 * lo) << 16) & _UINT32)) & _UINT32
    t = (t ^ (t >> 13)) & _UINT32
    lo = t & 0xFFFF
    hi = (t >> 16) & 0xFFFF
    t = (44_597 * lo + (((44_597 * hi + 49_842 * lo) << 16) & _UINT32)) & _UINT32
    return (t ^ (t >> 16)) & _UINT32


def _fmix_hex(value: int) -> str:
    return f"{_fmix_int(value):08x}"


def _first_str(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return None


def _extract_input_value(text: str, field_name: str) -> str | None:
    pattern = r"<input\b(?=[^>]*\bname=[\"']" + re.escape(field_name) + r"[\"'])(?P<attrs>[^>]*)>"
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    attrs = m.group("attrs")
    vm = re.search(r"\bvalue=([\"'])(?P<value>.*?)\1", attrs, flags=re.DOTALL)
    return html.unescape(vm.group("value")) if vm else ""


def _extract_attr_value(text: str, attr_name: str) -> str | None:
    pattern = re.escape(attr_name) + r"=([\"'])(?P<value>.*?)\1"
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    return html.unescape(m.group("value")) if m else None


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/html, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
