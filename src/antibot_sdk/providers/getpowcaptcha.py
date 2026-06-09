from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import json
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BACKEND_URL = "https://api.powcaptcha.com"
DEFAULT_MAX_ATTEMPTS_PER_PROBLEM = 10_000_000
MAX_DIFFICULTY = 64


@dataclass(slots=True)
class GetPowCaptchaProblem:
    problem: str
    difficulty: int


@dataclass(slots=True)
class GetPowCaptchaChallenge:
    challenge_id: str
    signature: str
    challenges: list[GetPowCaptchaProblem]
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class GetPowCaptchaSolution:
    challenge: GetPowCaptchaChallenge
    solutions: list[int]
    time_ms: int
    checked: int = 0

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge.challenge_id,
            "solutions": self.solutions,
            "time": self.time_ms,
        }

    @property
    def token(self) -> str:
        return encode_getpowcaptcha_solution(self.payload)

    @property
    def verify_body(self) -> dict[str, Any]:
        return {"solution": self.token}


@dataclass(slots=True)
class GetPowCaptchaFingerprint:
    fingerprint_id: str
    components: dict[str, Any]
    duration: int = 12

    def to_payload(self) -> dict[str, Any]:
        return {
            "fingerprintId": self.fingerprint_id,
            "components": self.components,
            "duration": self.duration,
        }


def getpowcaptcha_hash_hex(signature: str, problem: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{signature}{problem}{nonce}".encode("utf-8")).hexdigest()


def verify_getpowcaptcha_nonce(signature: str, problem: str, difficulty: int, nonce: int | str) -> bool:
    difficulty = _validate_difficulty(difficulty)
    return getpowcaptcha_hash_hex(signature, problem, nonce).startswith("0" * difficulty)


def parse_getpowcaptcha_challenge(data: Any) -> GetPowCaptchaChallenge:
    if isinstance(data, str):
        data = _load_json_arg(data)
    if not isinstance(data, dict):
        raise ValueError("powCAPTCHA challenge must be a JSON object")
    raw = data
    if data.get("success") is True and data.get("type") == "item" and isinstance(data.get("data"), dict):
        data = data["data"]
    elif isinstance(data.get("data"), dict) and "challenges" in data["data"]:
        data = data["data"]

    challenge_id = data.get("id") or data.get("challenge_id") or data.get("challengeId")
    signature = data.get("signature") or data.get("challengeSignature")
    entries = data.get("challenges")
    if not challenge_id:
        raise ValueError("powCAPTCHA challenge requires id")
    if not signature:
        raise ValueError("powCAPTCHA challenge requires signature")
    if not isinstance(entries, list) or not entries:
        raise ValueError("powCAPTCHA challenge requires non-empty challenges list")

    problems: list[GetPowCaptchaProblem] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("powCAPTCHA challenge entry must be object")
        problem = entry.get("problem")
        difficulty = entry.get("difficulty")
        if problem is None:
            raise ValueError("powCAPTCHA challenge entry requires problem")
        problems.append(GetPowCaptchaProblem(problem=str(problem), difficulty=_validate_difficulty(difficulty)))
    return GetPowCaptchaChallenge(
        challenge_id=str(challenge_id),
        signature=str(signature),
        challenges=problems,
        raw=raw,
    )


def solve_getpowcaptcha_problem(
    signature: str,
    problem: str,
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS_PER_PROBLEM,
    deadline: float | None = None,
) -> tuple[int | None, int]:
    difficulty = _validate_difficulty(difficulty)
    prefix = "0" * difficulty
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(start) + int(max_attempts))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, checked
        checked += 1
        if hashlib.sha256(f"{signature}{problem}{nonce}".encode("utf-8")).hexdigest().startswith(prefix):
            return nonce, checked
    return None, checked


def solve_getpowcaptcha_challenge(
    challenge: GetPowCaptchaChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts_per_problem: int = DEFAULT_MAX_ATTEMPTS_PER_PROBLEM,
    workers: int = 1,
    timeout_sec: int | float | None = 60,
) -> GetPowCaptchaSolution | None:
    item = parse_getpowcaptcha_challenge(challenge) if not isinstance(challenge, GetPowCaptchaChallenge) else challenge
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    checked_total = 0
    solutions: list[int | None] = [None] * len(item.challenges)
    workers = max(1, int(workers or 1))
    max_attempts_per_problem = max(1, int(max_attempts_per_problem))

    if workers <= 1 or len(item.challenges) <= 1:
        for idx, problem in enumerate(item.challenges):
            nonce, checked = solve_getpowcaptcha_problem(
                item.signature,
                problem.problem,
                problem.difficulty,
                start=start,
                max_attempts=max_attempts_per_problem,
                deadline=deadline,
            )
            checked_total += checked
            if nonce is None:
                return None
            solutions[idx] = nonce
    else:
        pool = ProcessPoolExecutor(max_workers=min(workers, len(item.challenges)))
        futures = {
            pool.submit(
                solve_getpowcaptcha_problem,
                item.signature,
                problem.problem,
                problem.difficulty,
                start=start,
                max_attempts=max_attempts_per_problem,
                deadline=deadline,
            ): idx
            for idx, problem in enumerate(item.challenges)
        }
        try:
            wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
            for fut in as_completed(futures, timeout=wait_timeout):
                idx = futures[fut]
                nonce, checked = fut.result()
                checked_total += checked
                if nonce is None:
                    for other in futures:
                        other.cancel()
                    pool.shutdown(wait=False, cancel_futures=True)
                    return None
                solutions[idx] = nonce
        except FuturesTimeout:
            pool.shutdown(wait=False, cancel_futures=True)
            return None
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True, cancel_futures=True)

    if any(x is None for x in solutions):
        return None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return GetPowCaptchaSolution(
        challenge=item,
        solutions=[int(x) for x in solutions if x is not None],
        time_ms=elapsed_ms,
        checked=checked_total,
    )


def encode_getpowcaptcha_solution(payload: dict[str, Any]) -> str:
    # Browser widget uses btoa(JSON.stringify(solution)).
    return base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii")


def decode_getpowcaptcha_solution(token: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(str(token), validate=True).decode("utf-8")
        data = json.loads(decoded)
    except Exception as e:
        raise ValueError("invalid powCAPTCHA solution token") from e
    if not isinstance(data, dict):
        raise ValueError("powCAPTCHA solution token must decode to object")
    return data


def verify_getpowcaptcha_solution(
    challenge: GetPowCaptchaChallenge | dict[str, Any] | str,
    solution: GetPowCaptchaSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_getpowcaptcha_challenge(challenge) if not isinstance(challenge, GetPowCaptchaChallenge) else challenge
        if isinstance(solution, GetPowCaptchaSolution):
            payload = solution.payload
        elif isinstance(solution, str):
            payload = decode_getpowcaptcha_solution(solution)
        elif isinstance(solution, dict):
            payload = solution
        else:
            return False
        if str(payload.get("challenge_id")) != item.challenge_id:
            return False
        nonces = payload.get("solutions")
        if not isinstance(nonces, list) or len(nonces) != len(item.challenges):
            return False
        return all(
            verify_getpowcaptcha_nonce(item.signature, problem.problem, problem.difficulty, nonces[idx])
            for idx, problem in enumerate(item.challenges)
        )
    except Exception:
        return False


def generate_getpowcaptcha_fingerprint(
    *,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    language: str = "en-US",
    timezone: str = "America/New_York",
) -> GetPowCaptchaFingerprint:
    timezone_offset = _timezone_offset_minutes(timezone)
    components: dict[str, Any] = {
        "browser": {
            "userAgent": user_agent,
            "platform": "Win32",
            "hardwareConcurrency": 8,
            "deviceMemory": 8,
            "cookieEnabled": True,
        },
        "language": {"languages": [language, "en"], "language": language},
        "timezone": {"timezone": timezone, "offset": timezone_offset},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24, "pixelDepth": 24},
        "webdriver": {"webdriver": False},
        "plugins": {"length": 5},
        "canvas": {"dataUrlHash": "low-risk-canvas-fixture"},
        "webgl": {"vendor": "Google Inc.", "renderer": "ANGLE"},
        "mathBehavior": {"acos": 1.4473588658278522, "cosh": 1.5430806348152437},
    }
    material = json.dumps({k: components[k] for k in sorted(components)}, ensure_ascii=False, separators=(",", ":")) + "{}"
    fingerprint_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return GetPowCaptchaFingerprint(fingerprint_id=fingerprint_id, components=components)


def encode_getpowcaptcha_fingerprint(fingerprint: GetPowCaptchaFingerprint | dict[str, Any]) -> str:
    payload = fingerprint.to_payload() if isinstance(fingerprint, GetPowCaptchaFingerprint) else fingerprint
    return encode_getpowcaptcha_solution(payload)


def generate_getpowcaptcha_signals(*, now_ms: int | None = None) -> dict[str, Any]:
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    return {
        "startedAt": now_ms - 1800,
        "endedAt": now_ms,
        "duration": 1800,
        "events": [
            {"type": "focus", "t": now_ms - 1700},
            {"type": "mousemove", "x": 151, "y": 42, "t": now_ms - 1200},
            {"type": "mousemove", "x": 178, "y": 51, "t": now_ms - 900},
            {"type": "click", "x": 184, "y": 54, "t": now_ms - 80},
        ],
        "summary": {"mouseMoves": 2, "clicks": 1, "visibilityChanges": 0, "focusEvents": 1},
    }


def build_getpowcaptcha_create_body(
    *,
    app_id: str,
    fingerprint: GetPowCaptchaFingerprint | dict[str, Any] | str | None = None,
    signals: dict[str, Any] | None = None,
    context: Any = None,
) -> dict[str, Any]:
    if fingerprint is None:
        fingerprint_value = encode_getpowcaptcha_fingerprint(generate_getpowcaptcha_fingerprint())
    elif isinstance(fingerprint, str):
        fingerprint_value = fingerprint
    else:
        fingerprint_value = encode_getpowcaptcha_fingerprint(fingerprint)
    return {
        "app_id": str(app_id),
        "fingerprint": fingerprint_value,
        "context": context,
        "signals": signals if signals is not None else generate_getpowcaptcha_signals(),
    }


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


def _load_json_or_raw_string_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
    elif value and value.strip().startswith("@"):
        text = Path(value.strip()[1:]).read_text(encoding="utf-8").strip()
    else:
        text = (value or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _api_url(base: str | None, path: str) -> str | None:
    if not base:
        return None
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _validate_difficulty(value: Any) -> int:
    try:
        difficulty = int(value)
    except Exception as e:
        raise ValueError("powCAPTCHA difficulty must be integer") from e
    if difficulty < 0 or difficulty > MAX_DIFFICULTY:
        raise ValueError(f"powCAPTCHA difficulty must be 0..{MAX_DIFFICULTY}")
    return difficulty


def _timezone_offset_minutes(timezone_name: str) -> int:
    try:
        offset = datetime.now(ZoneInfo(timezone_name)).utcoffset()
    except (ZoneInfoNotFoundError, ValueError):
        return 0
    if offset is None:
        return 0
    # JavaScript Date#getTimezoneOffset(): minutes from local time to UTC.
    return -int(offset.total_seconds() // 60)


def _redact(data: Any) -> Any:
    if isinstance(data, dict):
        out = dict(data)
        if isinstance(out.get("secret"), str):
            out["secret"] = "***redacted***"
        if isinstance(out.get("fingerprint"), str) and len(out["fingerprint"]) > 48:
            out["fingerprint"] = out["fingerprint"][:18] + "..." + out["fingerprint"][-10:]
        return out
    return data


class GetPowCaptchaSolver:
    """powCAPTCHA protocol solver.

    Replays the widget protocol without a browser: create challenge with
    fingerprint/signals, solve SHA256(signature+problem+nonce) hex-prefix PoW,
    and return the base64 JSON solution token used by `powcaptcha-response`.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        app_id: str | None = None,
        backend_url: str = DEFAULT_BACKEND_URL,
        create_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        secret: str | None = None,
        verify: bool = False,
        context_json: Any = None,
        context_file: str | None = None,
        signals_json: Any = None,
        signals_file: str | None = None,
        fingerprint_json: Any = None,
        fingerprint_file: str | None = None,
        gzip_create: bool = True,
        start: int = 0,
        max_attempts_per_problem: int = DEFAULT_MAX_ATTEMPTS_PER_PROBLEM,
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
            "backend_url": backend_url,
            "create_url": create_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "verify": verify,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_problem": max_attempts_per_problem,
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
                out = output_root / "getpowcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="getpowcaptcha",
                ok=ok,
                captcha_type="signals_bound_pow",
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
                app_id=app_id,
                backend_url=backend_url,
                create_url=create_url,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                context_json=context_json,
                context_file=context_file,
                signals_json=signals_json,
                signals_file=signals_file,
                fingerprint_json=fingerprint_json,
                fingerprint_file=fingerprint_file,
                gzip_create=gzip_create,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            challenge = parse_getpowcaptcha_challenge(data)
            raw["challenge"] = challenge.raw or data
            diagnostics.update(
                {
                    "challenge_id": challenge.challenge_id,
                    "problem_count": len(challenge.challenges),
                    "difficulties": [p.difficulty for p in challenge.challenges],
                }
            )

            solution = solve_getpowcaptcha_challenge(
                challenge,
                start=start,
                max_attempts_per_problem=max_attempts_per_problem,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("powCAPTCHA solve failed: timeout_or_not_found")
                return finish(ok=False)
            raw["solution"] = {
                "challenge_id": challenge.challenge_id,
                "solutions": solution.solutions,
                "time": solution.time_ms,
                "token": solution.token,
                "checked": solution.checked,
            }
            diagnostics.update(
                {
                    "checked": solution.checked,
                    "solve_ms": solution.time_ms,
                    "first_nonce": solution.solutions[0] if solution.solutions else None,
                }
            )

            final_ticket = solution.token
            verify_code = "solved"
            if verify or verify_url or secret:
                if not secret:
                    errors.append("powCAPTCHA verify requested but secret is missing")
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
                verify_url = verify_url or _api_url(backend_url, "challenges/verify")
                body = {"solution": solution.token, "secret": secret}
                resp = requests.post(
                    verify_url,
                    headers={"Content-Type": "application/json", **(headers or {})},
                    json=body,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                raw["verifyRequest"] = {"url": verify_url, "body": _redact(body)}
                raw["verifyResponse"] = {"status": resp.status_code, "url": resp.url}
                resp.raise_for_status()
                verify_data = resp.json()
                raw["verifyResponse"]["json"] = _redact(verify_data)
                if not isinstance(verify_data, dict) or not verify_data.get("success"):
                    errors.append(str((verify_data or {}).get("error") or "verify_failed"))
                    return finish(ok=False, ticket=final_ticket, verify_code="verify_failed")
                final_ticket = str(verify_data.get("token") or final_ticket)
                verify_code = "verified"
                diagnostics["verified"] = True
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        app_id: str | None,
        backend_url: str,
        create_url: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        context_json: Any,
        context_file: str | None,
        signals_json: Any,
        signals_file: str | None,
        fingerprint_json: Any,
        fingerprint_file: str | None,
        gzip_create: bool,
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
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            return resp.json()
        if not app_id:
            raise ValueError("powCAPTCHA requires app_id, challenge_json, challenge_file or challenge_url")

        context = _load_json_arg(context_json, context_file) if isinstance(context_json, str) or context_file else context_json
        signals = _load_json_arg(signals_json, signals_file) if isinstance(signals_json, str) or signals_file else signals_json
        fingerprint = (
            _load_json_or_raw_string_arg(fingerprint_json, fingerprint_file)
            if isinstance(fingerprint_json, str) or fingerprint_file
            else fingerprint_json
        )
        body = build_getpowcaptcha_create_body(
            app_id=app_id,
            fingerprint=fingerprint,
            signals=signals if isinstance(signals, dict) else None,
            context=context,
        )
        create_url = create_url or _api_url(backend_url, "challenges/create")
        assert create_url is not None
        req_headers = {"Content-Type": "application/json", **(headers or {})}
        raw["createRequest"] = {"url": create_url, "body": _redact(body), "gzip": bool(gzip_create)}
        if gzip_create:
            try:
                compressed = gzip.compress(json.dumps(body, separators=(",", ":")).encode("utf-8"))
                resp = requests.post(
                    create_url,
                    headers={**req_headers, "Content-Encoding": "gzip"},
                    data=compressed,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                if resp.ok:
                    raw["createResponse"] = {"status": resp.status_code, "url": resp.url, "gzip": True}
                    return resp.json()
            except Exception as e:
                raw["createGzipError"] = {"type": type(e).__name__, "message": str(e)}
        resp = requests.post(
            create_url,
            headers=req_headers,
            json=body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["createResponse"] = {"status": resp.status_code, "url": resp.url, "gzip": False}
        resp.raise_for_status()
        return resp.json()
