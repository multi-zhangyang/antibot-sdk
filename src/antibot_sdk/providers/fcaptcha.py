from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 2_000_000
DEFAULT_MIN_SUBMIT_MS = 1600
DEFAULT_SITE_KEY = "default"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}

WEIGHTS = {
    "vision_ai": 0.15,
    "headless": 0.15,
    "automation": 0.08,
    "cdp": 0.12,
    "behavioral": 0.18,
    "fingerprint": 0.08,
    "rate_limit": 0.01,
    "datacenter": 0.07,
    "tor_vpn": 0.01,
    "bot": 0.15,
}


@dataclass(slots=True)
class FCaptchaChallenge:
    challenge_id: str
    prefix: str
    difficulty: int
    challenge_nonce: str | None = None
    expires_at: int | None = None
    signature: str | None = None
    site_key: str = DEFAULT_SITE_KEY

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "challengeId": self.challenge_id,
            "prefix": self.prefix,
            "difficulty": self.difficulty,
            "siteKey": self.site_key,
        }
        if self.challenge_nonce is not None:
            payload["nonce"] = self.challenge_nonce
        if self.expires_at is not None:
            payload["expiresAt"] = self.expires_at
        if self.signature is not None:
            payload["sig"] = self.signature
        return payload


@dataclass(slots=True)
class FCaptchaSolution:
    challenge: FCaptchaChallenge
    nonce: int
    hash_hex: str
    signals_hash: str
    signals_json: str
    signals: dict[str, Any]
    attempts: int
    took_ms: int
    pow_timing: dict[str, Any]

    @property
    def pow_solution(self) -> dict[str, Any]:
        return {
            "challengeId": self.challenge.challenge_id,
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "signalsHash": self.signals_hash,
        }

    @property
    def verify_body(self) -> dict[str, Any]:
        return {
            "siteKey": self.challenge.site_key,
            "signals": self.signals,
            "powSolution": self.pow_solution,
            "signalsJson": self.signals_json,
            "powTiming": self.pow_timing,
        }


def fcaptcha_hash_hex(prefix: str, nonce: int | str, signals_hash: str | None = None) -> str:
    if signals_hash:
        message = f"{prefix}:{signals_hash}:{nonce}"
    else:
        message = f"{prefix}:{nonce}"
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def _canonical_json(obj: dict[str, Any]) -> str:
    # Browser JSON.stringify emits compact JSON and preserves insertion order.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def fcaptcha_signals_hash(signals_json: str | dict[str, Any]) -> str:
    text = _canonical_json(signals_json) if isinstance(signals_json, dict) else str(signals_json)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_fcaptcha_challenge(value: FCaptchaChallenge | dict[str, Any] | str, *, site_key: str = DEFAULT_SITE_KEY) -> FCaptchaChallenge:
    if isinstance(value, FCaptchaChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        obj: dict[str, Any] = json.loads(text)
    else:
        obj = dict(value)
    if isinstance(obj.get("challenge"), dict):
        obj = obj["challenge"]
    challenge_id = str(obj.get("challengeId") or obj.get("id") or "")
    prefix = str(obj.get("prefix") or "")
    difficulty = int(obj.get("difficulty") or obj.get("powDifficulty") or 0)
    challenge_nonce = obj.get("nonce")
    expires_raw = obj.get("expiresAt", obj.get("expires"))
    signature = obj.get("sig", obj.get("signature"))
    parsed_site_key = str(obj.get("siteKey") or obj.get("site_key") or site_key or DEFAULT_SITE_KEY)
    if not challenge_id:
        raise ValueError("fcaptcha challengeId is required")
    if not prefix:
        raise ValueError("fcaptcha prefix is required")
    if difficulty < 0:
        raise ValueError("fcaptcha difficulty must be >= 0")
    return FCaptchaChallenge(
        challenge_id=challenge_id,
        prefix=prefix,
        difficulty=difficulty,
        challenge_nonce=str(challenge_nonce) if challenge_nonce is not None else None,
        expires_at=int(expires_raw) if expires_raw is not None else None,
        signature=str(signature) if signature is not None else None,
        site_key=parsed_site_key,
    )


def finalize_fcaptcha_signals(signals: dict[str, Any], challenge: FCaptchaChallenge | dict[str, Any] | str | None = None) -> dict[str, Any]:
    out = dict(signals)
    meta = dict(out.get("meta") or {})
    if challenge is not None:
        item = parse_fcaptcha_challenge(challenge)
        if item.challenge_nonce:
            meta["challengeNonce"] = item.challenge_nonce
    meta.setdefault("timestamp", int(time.time() * 1000))
    out["meta"] = meta
    return out


def generate_fcaptcha_signals(*, challenge_nonce: str | None = None, now_ms: int | None = None) -> dict[str, Any]:
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    behavioral = {
        "totalPoints": 84,
        "trajectoryLength": 526.4,
        "avgVelocity": 0.42,
        "velocityVariance": 0.18,
        "avgAcceleration": 0.012,
        "accelerationChanges": 18,
        "microTremorScore": 0.42,
        "straightLineRatio": 0.27,
        "microMovements": 11,
        "directionChanges": 19,
        "eventDeltas": [16, 22, 31, 18, 27, 35, 24, 41, 29, 33, 21, 38],
        "eventDeltaVariance": 62.5,
        "mouseEventRate": 54,
        "scrollEvents": 3,
        "keyEvents": 8,
        "touchEvents": 0,
        "focusEvents": 2,
        "interactionDuration": 5200,
        "approachPoints": 24,
        "approachDirectness": 0.63,
        "clickPrecision": 8.5,
        "explorationRatio": 0.24,
        "overshootCorrections": 2,
        "clickData": {"button": 0, "holdDuration": 121},
        "touchTotalPoints": 0,
        "touchTrajectoryLength": 0,
        "touchMicroTremorScore": 0,
        "touchDirectionChanges": 0,
        "pointerTypes": ["mouse"],
    }
    environmental = {
        "webdriver": False,
        "automationFlags": {
            "plugins": 5,
            "languages": True,
            "platform": "Win32",
            "hardwareConcurrency": 8,
            "maxTouchPoints": 0,
            "chrome": True,
        },
        "navigator": {
            "platform": "Win32",
            "maxTouchPoints": 0,
            "hardwareConcurrency": 8,
            "language": "en-US",
            "languages": ["en-US", "en"],
        },
        "headlessIndicators": {
            "hasOuterDimensions": True,
            "innerEqualsOuter": False,
            "notificationPermission": "default",
        },
        "webglInfo": {
            "vendor": "Google Inc. (NVIDIA)",
            "renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        },
        "playwright": {"detected": False, "signals": []},
        "cdp": {"detected": False, "signals": []},
        "jsExecutionTime": {"mathOps": 2.4},
        "rafConsistency": {"frameTimeVariance": 1.8},
        "canvasHash": {"hash": "7b3c2a1f", "dataLength": 512, "supported": True, "error": False},
        "webrtcInfo": {
            "supported": True,
            "mediaDevices": {"supported": True, "totalDevices": 4, "videoInputs": 1, "audioInputs": 1},
            "hasLocalIP": True,
        },
        "speechInfo": {"supported": True, "totalVoices": 8, "localVoices": 6},
        "workerConsistency": {"supported": True, "consistent": True, "mismatchCount": 0, "mismatches": []},
        "cssMediaQueries": {"supported": True, "pointer": "fine", "hover": True},
        "fontsInfo": {"supported": True, "count": 12, "hasSegoeUI": True, "hasSFPro": False, "hasDejaVuSans": False},
        "permissionsInfo": {
            "supported": True,
            "hasPermissionsAPI": True,
            "hasClipboard": True,
            "hasShare": True,
            "hasCredentials": True,
            "hasBluetooth": True,
            "hasUsb": True,
        },
        "domRectFingerprint": {"supported": True, "rectAWidth": 123.45, "rectBWidth": 78.13, "rangeWidth": 44.5},
        "sensor": {"motionEventCount": 0, "motionAccelVariance": 0, "orientationEventCount": 0, "orientationVariance": 0},
    }
    return {
        "behavioral": behavioral,
        "environmental": environmental,
        "temporal": {"pageLoadToFirstInteraction": 900},
        "meta": {"timestamp": now, "challengeNonce": challenge_nonce},
    }


def score_fcaptcha_signals(
    signals: dict[str, Any],
    *,
    user_agent: str | None = None,
    headers: dict[str, str] | None = None,
    pow_valid: bool = True,
    server_elapsed_ms: int = DEFAULT_MIN_SUBMIT_MS,
) -> dict[str, Any]:
    """Approximate FCaptcha server-node scoring for local diagnostics and tests."""

    detections: list[dict[str, Any]] = []
    ua = user_agent or DEFAULT_HEADERS["User-Agent"]
    b = signals.get("behavioral") or {}
    env = signals.get("environmental") or {}
    temporal = signals.get("temporal") or {}

    if not pow_valid:
        detections.append({"category": "bot", "score": 0.7, "confidence": 0.8, "reason": "PoW verification failed"})
    if server_elapsed_ms < 1500:
        detections.append({"category": "bot", "score": 0.8, "confidence": 0.85, "reason": "Challenge solved too fast"})

    total_points = float(b.get("totalPoints") or 0)
    trajectory = float(b.get("trajectoryLength") or 0)
    key_events = float(b.get("keyEvents") or 0)
    touch_events = float(b.get("touchEvents") or 0)
    is_touch = touch_events >= 3
    is_keyboard = key_events >= 2 and total_points == 0
    if total_points < 5 and trajectory < 10 and not is_touch and not is_keyboard:
        detections.append({"category": "vision_ai", "score": 0.9, "confidence": 0.85, "reason": "No mouse movement detected before click"})
    if float(b.get("approachPoints") or 0) == 0 and not is_touch and not is_keyboard:
        detections.append({"category": "vision_ai", "score": 0.7, "confidence": 0.8, "reason": "No approach trajectory to target"})
    if float(b.get("microTremorScore") or 0.5) < 0.15:
        detections.append({"category": "vision_ai", "score": 0.7, "confidence": 0.6, "reason": "Mouse movement lacks natural micro-tremor"})
    if float(b.get("approachDirectness") or 0) > 0.95:
        detections.append({"category": "vision_ai", "score": 0.5, "confidence": 0.5, "reason": "Mouse path too direct"})
    precision = float(b.get("clickPrecision") or 10)
    if 0 < precision < 2:
        detections.append({"category": "vision_ai", "score": 0.4, "confidence": 0.5, "reason": "Click precision too accurate"})

    automation = env.get("automationFlags") or {}
    headless = env.get("headlessIndicators") or {}
    if env.get("webdriver"):
        detections.append({"category": "headless", "score": 0.95, "confidence": 0.95, "reason": "WebDriver detected"})
    if automation.get("plugins") == 0:
        detections.append({"category": "headless", "score": 0.6, "confidence": 0.6, "reason": "No browser plugins"})
    if automation.get("languages") is False:
        detections.append({"category": "headless", "score": 0.5, "confidence": 0.5, "reason": "No navigator.languages"})
    if headless.get("hasOuterDimensions") is False:
        detections.append({"category": "headless", "score": 0.7, "confidence": 0.7, "reason": "No outer dimensions"})
    if headless.get("innerEqualsOuter") is True:
        detections.append({"category": "headless", "score": 0.4, "confidence": 0.5, "reason": "Viewport equals window"})
    renderer = str((env.get("webglInfo") or {}).get("renderer") or "").lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer:
        detections.append({"category": "headless", "score": 0.8, "confidence": 0.8, "reason": "Software WebGL renderer"})
    if (env.get("playwright") or {}).get("detected"):
        detections.append({"category": "headless", "score": 0.9, "confidence": 0.8, "reason": "Playwright artifacts"})
    if (env.get("cdp") or {}).get("detected"):
        detections.append({"category": "cdp", "score": 0.8, "confidence": 0.85, "reason": "CDP automation detected"})

    js_time = float((env.get("jsExecutionTime") or {}).get("mathOps") or 0)
    if 0 < js_time < 0.1 or js_time > 50:
        detections.append({"category": "automation", "score": 0.4, "confidence": 0.3, "reason": "JS execution anomaly"})
    if float((env.get("rafConsistency") or {}).get("frameTimeVariance") or 1) < 0.1:
        detections.append({"category": "automation", "score": 0.5, "confidence": 0.4, "reason": "RAF timing too consistent"})
    if float(b.get("eventDeltaVariance") or 10) < 2 and total_points > 10:
        detections.append({"category": "automation", "score": 0.6, "confidence": 0.6, "reason": "Mouse event timing too consistent"})

    if total_points == 0 and not is_touch and not is_keyboard:
        detections.append({"category": "behavioral", "score": 0.8, "confidence": 0.9, "reason": "Zero interaction events"})
    elif total_points < 10 and not is_touch and not is_keyboard and trajectory < 30:
        detections.append({"category": "behavioral", "score": 0.6, "confidence": 0.7, "reason": "Insufficient mouse movement"})
    if float(b.get("velocityVariance") or 1) < 0.02 and trajectory > 50:
        detections.append({"category": "behavioral", "score": 0.6, "confidence": 0.6, "reason": "Mouse velocity too consistent"})
    if float(b.get("overshootCorrections") or 0) == 0 and trajectory > 200:
        detections.append({"category": "behavioral", "score": 0.4, "confidence": 0.4, "reason": "No overshoot corrections"})
    if 0 < float(b.get("interactionDuration") or 1000) < 200:
        detections.append({"category": "behavioral", "score": 0.7, "confidence": 0.7, "reason": "Interaction too fast"})
    first = temporal.get("pageLoadToFirstInteraction")
    if first is not None and 0 < float(first) < 100:
        detections.append({"category": "behavioral", "score": 0.5, "confidence": 0.5, "reason": "First interaction too soon"})
    rate = float(b.get("mouseEventRate") or 60)
    if rate > 200 or (0 < rate < 10):
        detections.append({"category": "behavioral", "score": 0.5, "confidence": 0.5, "reason": "Mouse event rate abnormal"})
    if float(b.get("straightLineRatio") or 0) > 0.8 and trajectory > 100:
        detections.append({"category": "behavioral", "score": 0.5, "confidence": 0.5, "reason": "Mouse movements too straight"})
    if total_points > 50 and float(b.get("directionChanges") or 10) < 3:
        detections.append({"category": "behavioral", "score": 0.4, "confidence": 0.4, "reason": "Too few direction changes"})

    canvas = env.get("canvasHash") or {}
    if canvas.get("error") or canvas.get("supported") is False:
        detections.append({"category": "fingerprint", "score": 0.4, "confidence": 0.4, "reason": "Canvas blocked or failed"})

    nav = env.get("navigator") or {}
    platform = str(nav.get("platform") or automation.get("platform") or "")
    if "Windows" in ua and "Win" not in platform:
        detections.append({"category": "bot", "score": 0.6, "confidence": 0.7, "reason": "UA/platform mismatch"})
    if "Chrome" in ua and not automation.get("chrome"):
        detections.append({"category": "bot", "score": 0.7, "confidence": 0.8, "reason": "Chrome UA but window.chrome missing"})

    h = {str(k).lower(): str(v) for k, v in (headers or DEFAULT_HEADERS).items()}
    missing = sum(1 for k in ("accept", "accept-language", "accept-encoding", "user-agent") if k not in h)
    if missing > 1:
        detections.append({"category": "bot", "score": 0.4, "confidence": 0.5, "reason": "Missing browser headers"})
    if h.get("accept-language") in ("", "*"):
        detections.append({"category": "bot", "score": 0.3, "confidence": 0.4, "reason": "Invalid Accept-Language"})
    if h.get("accept-encoding") and "gzip" not in h.get("accept-encoding", "") and "deflate" not in h.get("accept-encoding", ""):
        detections.append({"category": "bot", "score": 0.2, "confidence": 0.3, "reason": "Unusual Accept-Encoding"})
    if any(x in ua.lower() for x in ("bot", "spider", "crawler", "curl", "wget", "python", "httpie", "postman")):
        detections.append({"category": "bot", "score": 0.9, "confidence": 0.95, "reason": "User-Agent indicates bot"})

    category_scores = _category_scores(detections)
    final = sum(category_scores.get(cat, 0.0) * weight for cat, weight in WEIGHTS.items())
    return {
        "success": final < 0.5,
        "score": round(min(1.0, final), 4),
        "recommendation": "allow" if final < 0.3 else "challenge" if final < 0.6 else "block",
        "categoryScores": category_scores,
        "detections": detections,
    }


def _category_scores(detections: list[dict[str, Any]]) -> dict[str, float]:
    out: dict[str, float] = {k: 0.0 for k in WEIGHTS}
    grouped: dict[str, list[tuple[float, float]]] = {}
    for d in detections:
        grouped.setdefault(str(d.get("category") or "bot"), []).append((float(d.get("score") or 0), float(d.get("confidence") or 0)))
    for cat, rows in grouped.items():
        total_conf = sum(c for _, c in rows)
        if total_conf > 0:
            out[cat] = min(1.0, sum(s * c for s, c in rows) / total_conf)
    return out


def solve_fcaptcha_challenge(
    challenge: FCaptchaChallenge | dict[str, Any] | str,
    *,
    signals: dict[str, Any] | None = None,
    start: int = 0,
    max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> FCaptchaSolution | None:
    item = parse_fcaptcha_challenge(challenge)
    final_signals = finalize_fcaptcha_signals(signals or generate_fcaptcha_signals(), item)
    signals_json = _canonical_json(final_signals)
    signals_hash = fcaptcha_signals_hash(signals_json)
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    start = max(0, int(start))
    max_attempts = DEFAULT_MAX_ATTEMPTS if max_attempts is None else max(1, int(max_attempts))
    target = "0" * item.difficulty
    attempts = 0
    for nonce in range(start, start + max_attempts):
        if deadline is not None and attempts and attempts % 8192 == 0 and time.monotonic() >= deadline:
            return None
        attempts += 1
        hash_hex = fcaptcha_hash_hex(item.prefix, nonce, signals_hash)
        if hash_hex.startswith(target):
            took_ms = int((time.monotonic() - started) * 1000)
            plausible_ms = max(took_ms, int(attempts / 180_000 * 1000), 80)
            pow_timing = {"duration": plausible_ms, "iterations": attempts, "difficulty": item.difficulty}
            return FCaptchaSolution(
                challenge=item,
                nonce=nonce,
                hash_hex=hash_hex,
                signals_hash=signals_hash,
                signals_json=signals_json,
                signals=final_signals,
                attempts=attempts,
                took_ms=took_ms,
                pow_timing=pow_timing,
            )
    return None


def verify_fcaptcha_solution(challenge: FCaptchaChallenge | dict[str, Any] | str, solution: FCaptchaSolution | dict[str, Any] | int | str, *, signals_hash: str | None = None) -> bool:
    try:
        item = parse_fcaptcha_challenge(challenge)
        if isinstance(solution, FCaptchaSolution):
            nonce = solution.nonce
            hash_hex = solution.hash_hex
            sh = solution.signals_hash
        elif isinstance(solution, dict):
            nonce = int(solution.get("nonce", solution.get("solution")))
            hash_hex = str(solution.get("hash") or "")
            sh = str(solution.get("signalsHash") or signals_hash or "") or None
        else:
            nonce = int(solution)
            sh = signals_hash
            hash_hex = fcaptcha_hash_hex(item.prefix, nonce, sh)
        if nonce < 0:
            return False
        expected = fcaptcha_hash_hex(item.prefix, nonce, sh)
        return hash_hex == expected and hash_hex.startswith("0" * item.difficulty)
    except Exception:
        return False


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


def _merge_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    out = dict(DEFAULT_HEADERS)
    if headers:
        out.update(headers)
    return out


def _derive_challenge_url(base_url: str | None, challenge_url: str | None, site_key: str) -> str | None:
    if challenge_url:
        return challenge_url
    if not base_url:
        return None
    qs = urlencode({"siteKey": site_key})
    return urljoin(base_url.rstrip("/") + "/", f"api/pow/challenge?{qs}")


def _derive_verify_url(base_url: str | None, verify_url: str | None, *, score: bool = False) -> str | None:
    if verify_url:
        return verify_url
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", "api/score" if score else "api/verify")


def _extract_ticket(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "message"):
            if data.get(key):
                return str(data[key])
    return fallback


class FCaptchaSolver:
    """FCaptcha signalsHash-bound PoW + behavior/environment protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        site_key: str = DEFAULT_SITE_KEY,
        submit: bool = False,
        score_endpoint: bool = False,
        signals_json: Any = None,
        signals_file: str | None = None,
        start: int = 0,
        max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        min_submit_ms: int = DEFAULT_MIN_SUBMIT_MS,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "site_key": site_key,
            "submit": submit,
            "score_endpoint": score_endpoint,
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
                out = output_root / "fcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="fcaptcha",
                ok=ok,
                captcha_type="signals_bound_pow",
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
            request_headers = _merge_headers(headers)
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_challenge_url(base_url, challenge_url, site_key),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            challenge_received = time.monotonic()
            item = parse_fcaptcha_challenge(challenge_data, site_key=site_key)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "prefix_prefix": item.prefix[:24],
                    "difficulty": item.difficulty,
                    "challenge_nonce_present": bool(item.challenge_nonce),
                }
            )

            signals = _load_json_arg(signals_json, signals_file)
            if signals is not None and not isinstance(signals, dict):
                raise ValueError("fcaptcha signals must be a JSON object")
            signals = signals or generate_fcaptcha_signals(challenge_nonce=item.challenge_nonce)
            signals = finalize_fcaptcha_signals(signals, item)
            local_score = score_fcaptcha_signals(signals, headers=request_headers, server_elapsed_ms=max(DEFAULT_MIN_SUBMIT_MS, int(min_submit_ms)))
            raw["signals"] = signals
            diagnostics.update(
                {
                    "synthetic_score": local_score["score"],
                    "synthetic_recommendation": local_score["recommendation"],
                    "synthetic_detections": [d["reason"] for d in local_score["detections"]],
                }
            )

            solution = solve_fcaptcha_challenge(
                item,
                signals=signals,
                start=start,
                max_attempts=max_attempts,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("fcaptcha solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "signalsHash": solution.signals_hash,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
                "powTiming": solution.pow_timing,
            }
            raw["submitBody"] = solution.verify_body
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash": solution.hash_hex,
                    "signals_hash": solution.signals_hash,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = json.dumps(solution.verify_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url or base_url:
                effective_verify_url = _derive_verify_url(base_url, verify_url, score=score_endpoint)
                if not effective_verify_url:
                    errors.append("submit requested but verify_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                wait_ms = max(0, int(min_submit_ms) - int((time.monotonic() - challenge_received) * 1000))
                if wait_ms:
                    time.sleep(wait_ms / 1000)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = bool(isinstance(verify_data, dict) and (verify_data.get("success") is True or verify_data.get("ok") is True or verify_data.get("token")))
                if not ok:
                    reason = "verify_failed"
                    if isinstance(verify_data, dict):
                        reason = verify_data.get("reason") or verify_data.get("error") or verify_data.get("recommendation") or reason
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = _extract_ticket(verify_data, ticket)
                verify_code = "validated"
                diagnostics["submitted"] = True
                if isinstance(verify_data, dict):
                    diagnostics["server_score"] = verify_data.get("score")
                    diagnostics["server_recommendation"] = verify_data.get("recommendation")
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
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("fcaptcha requires base_url, challenge_json, challenge_file or challenge_url")
        resp = requests.get(
            challenge_url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return resp.json()

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: FCaptchaSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **headers},
            json=solution.verify_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"status": resp.status_code, "text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        return data
