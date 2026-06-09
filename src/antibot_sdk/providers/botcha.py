from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://botcha.ai"
DEFAULT_MAX_PRIMES = 20_000


@dataclass(slots=True)
class BotchaProblem:
    num: int
    operation: str = "sha256_first8"


@dataclass(slots=True)
class BotchaSpeedChallenge:
    challenge_id: str
    problems: list[BotchaProblem]
    time_limit_ms: int | None = None
    instructions: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class BotchaSpeedSolution:
    challenge: BotchaSpeedChallenge
    answers: list[str]
    elapsed_ms: int

    @property
    def verify_body(self) -> dict[str, Any]:
        return {"id": self.challenge.challenge_id, "answers": self.answers}


@dataclass(slots=True)
class BotchaStandardChallenge:
    challenge_id: str
    puzzle: str
    primes_count: int
    salt: str
    time_limit_ms: int | None = None
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class BotchaStandardSolution:
    challenge: BotchaStandardChallenge
    answer: str
    elapsed_ms: int

    @property
    def verify_body(self) -> dict[str, Any]:
        return {"id": self.challenge.challenge_id, "answer": self.answer}


def botcha_sha256_first8(num: int | str) -> str:
    return hashlib.sha256(str(num).encode("utf-8")).hexdigest()[:8]


def solve_botcha_speed_problems(problems: list[BotchaProblem] | list[dict[str, Any]] | list[int]) -> list[str]:
    parsed: list[BotchaProblem] = []
    for item in problems:
        if isinstance(item, BotchaProblem):
            parsed.append(item)
        elif isinstance(item, dict):
            parsed.append(_problem_from_mapping(item))
        else:
            parsed.append(BotchaProblem(num=int(item)))
    answers: list[str] = []
    for problem in parsed:
        if problem.operation and problem.operation.lower() != "sha256_first8":
            raise ValueError(f"unsupported BOTCHA operation: {problem.operation}")
        answers.append(botcha_sha256_first8(problem.num))
    return answers


def parse_botcha_speed_challenge(data: Any) -> BotchaSpeedChallenge:
    if isinstance(data, str):
        data = _load_json_arg(data)
    if not isinstance(data, dict):
        raise ValueError("BOTCHA speed challenge must be a JSON object")
    raw = data
    if isinstance(data.get("challenge"), dict):
        data = data["challenge"]
    challenge_id = data.get("id") or data.get("challenge_id") or data.get("challengeId")
    entries = data.get("problems") or data.get("challenges")
    if not challenge_id:
        raise ValueError("BOTCHA speed challenge requires id")
    if not isinstance(entries, list) or not entries:
        raise ValueError("BOTCHA speed challenge requires non-empty problems list")
    problems: list[BotchaProblem] = []
    for entry in entries:
        if isinstance(entry, dict):
            problems.append(_problem_from_mapping(entry))
        else:
            problems.append(BotchaProblem(num=int(entry)))
    return BotchaSpeedChallenge(
        challenge_id=str(challenge_id),
        problems=problems,
        time_limit_ms=_parse_time_limit_ms(data.get("timeLimit") or data.get("time_limit")),
        instructions=str(data.get("instructions")) if data.get("instructions") is not None else None,
        raw=raw,
    )


def solve_botcha_speed_challenge(challenge: BotchaSpeedChallenge | dict[str, Any] | str) -> BotchaSpeedSolution:
    started = time.monotonic()
    item = parse_botcha_speed_challenge(challenge) if not isinstance(challenge, BotchaSpeedChallenge) else challenge
    answers = solve_botcha_speed_problems(item.problems)
    return BotchaSpeedSolution(challenge=item, answers=answers, elapsed_ms=int((time.monotonic() - started) * 1000))


def verify_botcha_speed_solution(
    challenge: BotchaSpeedChallenge | dict[str, Any] | str,
    solution: BotchaSpeedSolution | dict[str, Any] | list[str],
) -> bool:
    try:
        item = parse_botcha_speed_challenge(challenge) if not isinstance(challenge, BotchaSpeedChallenge) else challenge
        if isinstance(solution, BotchaSpeedSolution):
            answers = solution.answers
        elif isinstance(solution, dict):
            sid = solution.get("id") or solution.get("challenge_id") or solution.get("challengeId")
            if sid is not None and str(sid) != item.challenge_id:
                return False
            answers = solution.get("answers")
        else:
            answers = solution
        if not isinstance(answers, list) or len(answers) != len(item.problems):
            return False
        expected = solve_botcha_speed_problems(item.problems)
        return all(str(a).lower() == expected[i] for i, a in enumerate(answers))
    except Exception:
        return False


def parse_botcha_standard_challenge(data: Any) -> BotchaStandardChallenge:
    if isinstance(data, str):
        data = _load_json_arg(data)
    if not isinstance(data, dict):
        raise ValueError("BOTCHA standard challenge must be a JSON object")
    raw = data
    if isinstance(data.get("challenge"), dict):
        data = data["challenge"]
    challenge_id = data.get("id") or data.get("challenge_id") or data.get("challengeId")
    puzzle = data.get("puzzle")
    if not challenge_id:
        raise ValueError("BOTCHA standard challenge requires id")
    if not puzzle:
        raise ValueError("BOTCHA standard challenge requires puzzle")
    primes_count, salt = _parse_standard_puzzle(str(puzzle))
    return BotchaStandardChallenge(
        challenge_id=str(challenge_id),
        puzzle=str(puzzle),
        primes_count=primes_count,
        salt=salt,
        time_limit_ms=_parse_time_limit_ms(data.get("timeLimit") or data.get("time_limit")),
        raw=raw,
    )


def solve_botcha_standard_challenge(challenge: BotchaStandardChallenge | dict[str, Any] | str) -> BotchaStandardSolution:
    started = time.monotonic()
    item = parse_botcha_standard_challenge(challenge) if not isinstance(challenge, BotchaStandardChallenge) else challenge
    material = "".join(str(p) for p in first_primes(item.primes_count)) + item.salt
    answer = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return BotchaStandardSolution(challenge=item, answer=answer, elapsed_ms=int((time.monotonic() - started) * 1000))


def verify_botcha_standard_solution(
    challenge: BotchaStandardChallenge | dict[str, Any] | str,
    solution: BotchaStandardSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_botcha_standard_challenge(challenge) if not isinstance(challenge, BotchaStandardChallenge) else challenge
        if isinstance(solution, BotchaStandardSolution):
            answer = solution.answer
        elif isinstance(solution, dict):
            sid = solution.get("id") or solution.get("challenge_id") or solution.get("challengeId")
            if sid is not None and str(sid) != item.challenge_id:
                return False
            answer = solution.get("answer")
        else:
            answer = solution
        expected = solve_botcha_standard_challenge(item).answer
        return str(answer).lower() == expected
    except Exception:
        return False


@lru_cache(maxsize=32)
def first_primes(count: int) -> tuple[int, ...]:
    count = int(count)
    if count < 1 or count > DEFAULT_MAX_PRIMES:
        raise ValueError(f"BOTCHA prime count must be 1..{DEFAULT_MAX_PRIMES}")
    primes: list[int] = []
    num = 2
    while len(primes) < count:
        if _is_prime(num):
            primes.append(num)
        num += 1
    return tuple(primes)


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False
    factor = 3
    while factor * factor <= value:
        if value % factor == 0:
            return False
        factor += 2
    return True


def _parse_standard_puzzle(puzzle: str) -> tuple[int, str]:
    match = re.search(
        r"first\s+(\d+)\s+prime numbers.*?salt\s+(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`|([A-Za-z0-9_.:-]+))",
        puzzle,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError("unsupported BOTCHA standard puzzle text")
    count = int(match.group(1))
    if count < 1 or count > DEFAULT_MAX_PRIMES:
        raise ValueError(f"BOTCHA prime count must be 1..{DEFAULT_MAX_PRIMES}")
    return count, next(value for value in match.groups()[1:] if value is not None)


def _problem_from_mapping(item: dict[str, Any]) -> BotchaProblem:
    num = item.get("num", item.get("number", item.get("value")))
    if num is None:
        raise ValueError("BOTCHA speed problem requires num")
    return BotchaProblem(num=int(num), operation=str(item.get("operation") or "sha256_first8"))


def _parse_time_limit_ms(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower()
    if not text:
        return None
    if text.endswith("ms"):
        return int(float(text[:-2]))
    if text.endswith("s"):
        return int(float(text[:-1]) * 1000)
    return int(float(text))


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


def _looks_standard(data: Any) -> bool:
    if isinstance(data, dict) and isinstance(data.get("challenge"), dict):
        data = data["challenge"]
    return isinstance(data, dict) and "puzzle" in data


def _looks_speed(data: Any) -> bool:
    if isinstance(data, dict) and isinstance(data.get("challenge"), dict):
        data = data["challenge"]
    return isinstance(data, dict) and ("problems" in data or "challenges" in data)


def _redact(data: Any) -> Any:
    if isinstance(data, dict):
        out = {key: _redact(value) for key, value in data.items()}
        for key in ("access_token", "refresh_token", "token"):
            value = out.get(key)
            if isinstance(value, str) and len(value) > 24:
                out[key] = value[:10] + "..." + value[-8:]
        return out
    if isinstance(data, list):
        return [_redact(item) for item in data]
    return data


class BotchaSolver:
    """BOTCHA protocol solver.

    Supports the public speed/standard challenge endpoints and the app-scoped
    `/v1/token` flow. The speed/token flow is direct SHA256-first8 computation,
    not browser automation.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        mode: str = "speed",
        base_url: str = DEFAULT_BASE_URL,
        app_id: str | None = None,
        audience: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        difficulty: str = "medium",
        rtt_adjust: bool = False,
        timeout_sec: int = 10,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        mode = (mode or "speed").lower()
        diagnostics: dict[str, Any] = {
            "mode": mode,
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "app_id": app_id,
            "audience": audience,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
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
                out = output_root / "botcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="botcha",
                ok=ok,
                captcha_type="ai_speed_challenge" if diagnostics.get("mode") != "standard" else "prime_hash_puzzle",
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
                mode=mode,
                base_url=base_url,
                app_id=app_id,
                audience=audience,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                difficulty=difficulty,
                rtt_adjust=rtt_adjust,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            if mode == "auto":
                mode = "standard" if _looks_standard(data) else "speed"
            if _looks_standard(data) and mode not in {"token", "speed"}:
                mode = "standard"
            diagnostics["mode"] = mode

            if mode == "standard":
                std = parse_botcha_standard_challenge(data)
                sol = solve_botcha_standard_challenge(std)
                raw["challenge"] = std.raw or data
                raw["solution"] = {"id": std.challenge_id, "answer": sol.answer, "elapsedMs": sol.elapsed_ms}
                diagnostics.update(
                    {
                        "challenge_id": std.challenge_id,
                        "primes_count": std.primes_count,
                        "time_limit_ms": std.time_limit_ms,
                        "solve_ms": sol.elapsed_ms,
                    }
                )
                final_ticket = json.dumps(sol.verify_body, separators=(",", ":"))
                verify_code = "solved"
                if submit or verify_url:
                    verify_url = verify_url or _api_url(base_url, "/api/challenge")
                    final_ticket, verify_code = self._submit(verify_url, sol.verify_body, timeout_sec, proxy_server, headers, raw, errors)
                    if verify_code != "verified":
                        return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
                return finish(ok=True, ticket=final_ticket, verify_code=verify_code)

            speed = parse_botcha_speed_challenge(data)
            sol = solve_botcha_speed_challenge(speed)
            raw["challenge"] = speed.raw or data
            raw["solution"] = {"id": speed.challenge_id, "answers": sol.answers, "elapsedMs": sol.elapsed_ms}
            diagnostics.update(
                {
                    "challenge_id": speed.challenge_id,
                    "problem_count": len(speed.problems),
                    "time_limit_ms": speed.time_limit_ms,
                    "solve_ms": sol.elapsed_ms,
                }
            )
            body = sol.verify_body
            if mode == "token":
                if app_id:
                    body["app_id"] = app_id
                if audience:
                    body["audience"] = audience
            final_ticket = json.dumps(body, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url or mode == "token":
                if verify_url is None:
                    verify_url = _api_url(base_url, "/v1/token/verify" if mode == "token" else "/api/speed-challenge")
                final_ticket, verify_code = self._submit(verify_url, body, timeout_sec, proxy_server, headers, raw, errors)
                if verify_code != "verified":
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        mode: str,
        base_url: str,
        app_id: str | None,
        audience: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        difficulty: str,
        rtt_adjust: bool,
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
        params: dict[str, str] = {}
        path = "/api/speed-challenge"
        if mode == "token":
            path = "/v1/token"
            if app_id:
                params["app_id"] = app_id
            if audience:
                params["audience"] = audience
        elif mode == "standard":
            path = "/api/challenge"
            if difficulty:
                params["difficulty"] = difficulty
        if rtt_adjust:
            params["ts"] = str(int(time.time() * 1000))
        if challenge_url is None:
            challenge_url = _api_url(base_url, path)
            if params:
                challenge_url += ("&" if "?" in challenge_url else "?") + urlencode(params)
        resp = requests.get(
            challenge_url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeRequest"] = {"url": challenge_url}
        raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
        try:
            data = resp.json()
        except ValueError:
            data = None
            raw["challengeResponse"]["text"] = resp.text[:500]
        else:
            raw["challengeResponse"]["json"] = _redact(data)
        if resp.status_code >= 400:
            message = "challenge_failed"
            if isinstance(data, dict):
                message = str(data.get("error") or data.get("message") or message)
            raise RuntimeError(f"BOTCHA challenge HTTP {resp.status_code}: {message}")
        if data is None:
            raise ValueError("BOTCHA challenge response is not JSON")
        return data

    def _submit(
        self,
        verify_url: str | None,
        body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        assert verify_url is not None
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyRequest"] = {"url": verify_url, "body": body}
        raw["verifyResponse"] = {"status": resp.status_code, "url": resp.url}
        try:
            data = resp.json()
        except ValueError:
            data = None
            raw["verifyResponse"]["text"] = resp.text[:500]
        if resp.status_code >= 400:
            message = "verify_failed"
            if isinstance(data, dict):
                message = str(data.get("error") or data.get("message") or message)
                raw["verifyResponse"]["json"] = _redact(data)
            errors.append(message)
            return json.dumps(body, separators=(",", ":")), f"http_{resp.status_code}"
        if data is None:
            errors.append("verify_response_not_json")
            return json.dumps(body, separators=(",", ":")), "verify_failed"
        raw["verifyResponse"]["json"] = _redact(data)
        if not isinstance(data, dict) or not (data.get("success") or data.get("verified") or data.get("valid")):
            errors.append(str((data or {}).get("error") or (data or {}).get("message") or "verify_failed"))
            return json.dumps(body, separators=(",", ":")), "verify_failed"
        token = data.get("access_token") or data.get("token") or data.get("badge") or json.dumps(data, separators=(",", ":"))
        return str(token), "verified"
