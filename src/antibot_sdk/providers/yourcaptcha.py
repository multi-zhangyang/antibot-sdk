from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 10_000_001


@dataclass(slots=True)
class YourCaptchaChallenge:
    algorithm: str
    challenge: str
    maxnumber: int
    salt: str
    signature: str
    risk_score: float | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "algorithm": self.algorithm,
            "challenge": self.challenge,
            "maxnumber": self.maxnumber,
            "salt": self.salt,
            "signature": self.signature,
        }
        if self.risk_score is not None:
            payload["riskScore"] = self.risk_score
        return payload


@dataclass(slots=True)
class YourCaptchaSolution:
    challenge: YourCaptchaChallenge
    number: int
    hash_hex: str
    attempts: int
    took_ms: int
    signals: dict[str, Any]

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "algorithm": self.challenge.algorithm,
            "challenge": self.challenge.challenge,
            "number": self.number,
            "salt": self.challenge.salt,
            "signature": self.challenge.signature,
            "signals": self.signals,
        }


def stddev(values: list[float] | list[int]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((float(v) - mean) ** 2 for v in values) / len(values)
    return variance**0.5


def score_yourcaptcha_signals(signals: dict[str, Any]) -> dict[str, Any]:
    """Mirror yourcaptcha/src/server/signals.ts scoring rules."""

    score = 0.0
    reasons: list[str] = []

    time_before_click = int(signals.get("captchaClickedAt") or 0) - int(signals.get("pageLoadedAt") or 0)
    if time_before_click < 1500:
        score += 0.25
        reasons.append(f"captcha clicked too fast ({time_before_click}ms)")
    elif time_before_click < 3000:
        score += 0.10
        reasons.append(f"captcha clicked quickly ({time_before_click}ms)")

    mouse_movements = int(signals.get("mouseMovements") or 0)
    mouse_direction_changes = int(signals.get("mouseDirectionChanges") or 0)
    mouse_distance = float(signals.get("mouseDistance") or 0)
    if mouse_movements == 0:
        score += 0.15
        reasons.append("zero mouse movements")
    else:
        direction_ratio = mouse_direction_changes / max(mouse_movements, 1)
        if direction_ratio < 0.05 and mouse_movements > 10:
            score += 0.15
            reasons.append(f"mouse path too linear (direction ratio: {direction_ratio:.3f})")
        if mouse_movements > 20 and mouse_distance < mouse_movements * 2:
            score += 0.10
            reasons.append("mouse distance too short for movement count")

    keystroke_count = int(signals.get("keystrokeCount") or 0)
    intervals_raw = signals.get("keystrokeIntervals") or []
    intervals = [float(v) for v in intervals_raw if isinstance(v, (int, float))]
    if keystroke_count == 0:
        score += 0.10
        reasons.append("zero keystrokes")
    elif len(intervals) > 5:
        sd = stddev(intervals)
        if sd < 5:
            score += 0.20
            reasons.append(f"keystroke timing too uniform (stddev: {sd:.1f}ms)")
        elif sd < 15:
            score += 0.08
            reasons.append(f"keystroke timing suspiciously regular (stddev: {sd:.1f}ms)")

    if int(signals.get("pasteEvents") or 0) >= 3 and keystroke_count < 5:
        score += 0.10
        reasons.append("form filled mostly by pasting")

    if int(signals.get("focusChanges") or 0) == 0:
        score += 0.08
        reasons.append("zero focus changes between fields")

    if bool(signals.get("hasWebdriver")):
        score += 0.35
        reasons.append("navigator.webdriver detected")
    if bool(signals.get("hasAutomationFlags")):
        score += 0.30
        reasons.append("automation framework flags detected")

    screen_width = int(signals.get("screenWidth") or 0)
    screen_height = int(signals.get("screenHeight") or 0)
    if screen_width == 0 and screen_height == 0:
        score += 0.15
        reasons.append("screen resolution 0x0")
    elif screen_width == 800 and screen_height == 600:
        score += 0.08
        reasons.append("screen resolution 800x600 (common headless default)")

    canvas_hash = str(signals.get("canvasHash") or "")
    if not canvas_hash or canvas_hash == "0":
        score += 0.10
        reasons.append("canvas fingerprint missing")

    renderer = str(signals.get("webglRenderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa")):
        score += 0.15
        reasons.append(f"headless GPU renderer: {signals.get('webglRenderer')}")

    if not signals.get("webglRenderer") and not signals.get("webglVendor"):
        score += 0.05
        reasons.append("no WebGL support")

    if int(signals.get("hardwareConcurrency") or 0) == 0:
        score += 0.05
        reasons.append("hardwareConcurrency is 0")

    languages = signals.get("languages") or []
    if not isinstance(languages, list) or len(languages) == 0:
        score += 0.05
        reasons.append("no browser languages")

    score = min(1.0, max(0.0, score))
    if score < 0.2:
        maxnumber = 50_000
    elif score < 0.4:
        maxnumber = 200_000
    elif score < 0.6:
        maxnumber = 500_000
    elif score < 0.8:
        maxnumber = 2_000_000
    else:
        maxnumber = 10_000_000
    return {"score": score, "reasons": reasons, "maxnumber": maxnumber}


def generate_yourcaptcha_signals(*, now_ms: int | None = None) -> dict[str, Any]:
    """Generate a low-risk browser-like telemetry payload without launching a browser."""

    now = int(now_ms if now_ms is not None else time.time() * 1000)
    page_loaded = now - 7000
    clicked = page_loaded + 3600
    solved = page_loaded + 6600
    mouse_positions = [[100 + i * 7, 200 + ((i * i) % 37)] for i in range(20)]
    return {
        "pageLoadedAt": page_loaded,
        "captchaClickedAt": clicked,
        "solvedAt": solved,
        "mouseMovements": 42,
        "mouseDistance": 420,
        "mouseDirectionChanges": 9,
        "mousePositions": mouse_positions,
        "keystrokeCount": 8,
        "keystrokeIntervals": [87, 143, 221, 96, 178, 132, 264],
        "pasteEvents": 0,
        "scrollEvents": 2,
        "focusChanges": 2,
        "hasWebdriver": False,
        "hasAutomationFlags": False,
        "screenWidth": 1440,
        "screenHeight": 900,
        "colorDepth": 24,
        "timezone": "America/New_York",
        "languages": ["en-US", "en"],
        "hardwareConcurrency": 8,
        "deviceMemory": 8,
        "touchSupport": False,
        "platform": "Win32",
        "canvasHash": "7b3c2a1f",
        "webglRenderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        "webglVendor": "Google Inc. (NVIDIA)",
    }


def finalize_yourcaptcha_signals(signals: dict[str, Any], *, solved_at: int | None = None) -> dict[str, Any]:
    out = dict(signals)
    page_loaded = int(out.get("pageLoadedAt") or int(time.time() * 1000) - 7000)
    out.setdefault("captchaClickedAt", page_loaded + 3600)
    if int(out.get("captchaClickedAt") or 0) <= 0:
        out["captchaClickedAt"] = page_loaded + 3600
    out["solvedAt"] = int(solved_at if solved_at is not None else max(int(time.time() * 1000), page_loaded + 6600))
    return out


def parse_yourcaptcha_challenge(value: YourCaptchaChallenge | dict[str, Any] | str) -> YourCaptchaChallenge:
    if isinstance(value, YourCaptchaChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        obj = json.loads(text)
    else:
        obj = dict(value)
    if isinstance(obj.get("challengeResponse"), dict):
        obj = obj["challengeResponse"]
    algorithm = str(obj.get("algorithm") or "SHA-256")
    challenge = str(obj.get("challenge") or obj.get("hash") or "").lower()
    maxnumber = int(obj.get("maxnumber") or obj.get("maxNumber") or obj.get("max_number") or 0)
    salt = str(obj.get("salt") or "")
    signature = str(obj.get("signature") or "")
    risk_raw = obj.get("riskScore", obj.get("risk_score"))
    risk_score = float(risk_raw) if risk_raw is not None else None
    if algorithm.upper() not in {"SHA-256", "SHA256"}:
        raise ValueError(f"unsupported yourcaptcha algorithm: {algorithm}")
    if len(challenge) != 64 or any(c not in "0123456789abcdef" for c in challenge):
        raise ValueError("yourcaptcha challenge must be 64 lowercase/uppercase hex chars")
    if maxnumber < 0:
        raise ValueError("yourcaptcha maxnumber must be >= 0")
    if not salt:
        raise ValueError("yourcaptcha salt is required")
    if not signature:
        raise ValueError("yourcaptcha signature is required")
    return YourCaptchaChallenge(
        algorithm="SHA-256",
        challenge=challenge,
        maxnumber=maxnumber,
        salt=salt,
        signature=signature,
        risk_score=risk_score,
    )


def yourcaptcha_hash_hex(salt: str, number: int | str) -> str:
    return hashlib.sha256((str(salt) + str(number)).encode("utf-8")).hexdigest()


def verify_yourcaptcha_solution(
    challenge: YourCaptchaChallenge | dict[str, Any] | str,
    solution: YourCaptchaSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_yourcaptcha_challenge(challenge)
        if isinstance(solution, YourCaptchaSolution):
            number = solution.number
        elif isinstance(solution, dict):
            number = int(solution.get("number", solution.get("solution")))
        else:
            number = int(solution)
        if number < 0 or number > item.maxnumber:
            return False
        return yourcaptcha_hash_hex(item.salt, number) == item.challenge
    except Exception:
        return False


def solve_yourcaptcha_challenge(
    challenge: YourCaptchaChallenge | dict[str, Any] | str,
    *,
    signals: dict[str, Any] | None = None,
    start: int = 0,
    max_attempts: int | None = None,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> YourCaptchaSolution | None:
    item = parse_yourcaptcha_challenge(challenge)
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    start = max(0, int(start))
    upper = item.maxnumber + 1
    if max_attempts is not None:
        upper = min(upper, start + max(1, int(max_attempts)))
    attempts = 0
    for number in range(start, upper):
        if deadline is not None and attempts and attempts % 8192 == 0 and time.monotonic() >= deadline:
            return None
        attempts += 1
        hash_hex = yourcaptcha_hash_hex(item.salt, number)
        if hash_hex == item.challenge:
            final_signals = finalize_yourcaptcha_signals(signals or generate_yourcaptcha_signals())
            return YourCaptchaSolution(
                challenge=item,
                number=number,
                hash_hex=hash_hex,
                attempts=attempts,
                took_ms=int((time.monotonic() - started) * 1000),
                signals=final_signals,
            )
    return None


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


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


def _extract_ticket(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "proofToken", "ticket", "message"):
            if data.get(key):
                return str(data[key])
    return fallback


class YourCaptchaSolver:
    """yourcaptcha behavioral telemetry + SHA-256 exact PoW protocol solver."""

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
        signals_json: Any = None,
        signals_file: str | None = None,
        start: int = 0,
        max_attempts: int | None = None,
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
                out = output_root / "yourcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="yourcaptcha",
                ok=ok,
                captcha_type="behavior_pow",
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
            signals = _load_json_arg(signals_json, signals_file) or generate_yourcaptcha_signals()
            if not isinstance(signals, dict):
                raise ValueError("yourcaptcha signals must be a JSON object")
            score = score_yourcaptcha_signals(signals)
            raw["signals"] = signals
            diagnostics.update(
                {
                    "synthetic_signal_score": score["score"],
                    "synthetic_signal_reasons": score["reasons"],
                    "synthetic_signal_maxnumber": score["maxnumber"],
                }
            )
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                signals=signals,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_yourcaptcha_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "algorithm": item.algorithm,
                    "challenge": item.challenge,
                    "maxnumber": item.maxnumber,
                    "salt_prefix": item.salt[:24],
                    "risk_score": item.risk_score,
                }
            )
            solution = solve_yourcaptcha_challenge(
                item,
                signals=signals,
                start=start,
                max_attempts=max_attempts,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("yourcaptcha solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "number": solution.number,
                "hash": solution.hash_hex,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            final_score = score_yourcaptcha_signals(solution.signals)
            diagnostics.update(
                {
                    "number": solution.number,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                    "final_signal_score": final_score["score"],
                    "final_signal_reasons": final_score["reasons"],
                }
            )
            ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url:
                if not verify_url:
                    errors.append("submit requested but verify_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                ok = bool(
                    isinstance(verify_data, dict)
                    and (
                        verify_data.get("verified") is True
                        or verify_data.get("success") is True
                        or verify_data.get("ok") is True
                        or verify_data.get("token")
                        or verify_data.get("proofToken")
                    )
                )
                if not ok:
                    reason = "verify_failed"
                    if isinstance(verify_data, dict):
                        reason = verify_data.get("reason") or verify_data.get("error") or verify_data.get("message") or reason
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = _extract_ticket(verify_data, ticket)
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
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        signals: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("yourcaptcha requires challenge_json, challenge_file or challenge_url")
        resp = requests.post(
            challenge_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json={"signals": signals},
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        if resp.status_code in (404, 405):
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "fallback": "GET"}
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return resp.json()

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: YourCaptchaSolution,
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
        try:
            data = resp.json()
        except ValueError:
            data = {"status": resp.status_code, "text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        if resp.status_code >= 400 and not isinstance(data, dict):
            resp.raise_for_status()
        return data
