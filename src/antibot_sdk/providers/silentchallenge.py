from __future__ import annotations

import asyncio
import hashlib
import json
import math
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MIN_SUBMIT_MS = 60
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_DELTA = 3

DEFAULT_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
}


@dataclass(slots=True)
class SilentChallengePow:
    challenge_id: str | None
    prefix: str
    difficulty: int
    space_cost: int
    time_cost: int
    delta: int = DEFAULT_DELTA

    def to_payload(self) -> dict[str, Any]:
        return {
            "challengeId": self.challenge_id,
            "prefix": self.prefix,
            "difficulty": self.difficulty,
            "spaceCost": self.space_cost,
            "timeCost": self.time_cost,
            "delta": self.delta,
        }


@dataclass(slots=True)
class SilentChallengeSolution:
    challenge: SilentChallengePow
    nonce: int
    hash_hex: str
    leading_zero_bits: int
    attempts: int
    took_ms: int
    motion: dict[str, Any]
    signals: dict[str, Any]
    vm_response: str | None = None

    @property
    def submit_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "nonce": self.nonce,
            "motion": self.motion,
            "signals": self.signals,
        }
        if self.vm_response:
            body["vmResponse"] = self.vm_response
        return body


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _u32le(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _u32be_from_digest_prefix(digest: bytes) -> int:
    return int.from_bytes(digest[:4], "big", signed=False)


def count_leading_zero_bits_bytes(data: bytes) -> int:
    total = 0
    for b in data:
        if b == 0:
            total += 8
            continue
        return total + 8 - b.bit_length()
    return len(data) * 8


def silent_balloon_hash_bytes(input_value: str | bytes, space_cost: int, time_cost: int, delta: int = DEFAULT_DELTA) -> bytes:
    """Mirror silent-challenge/src/crypto.js balloon(input, spaceCost, timeCost, delta)."""

    if space_cost <= 0:
        raise ValueError("space_cost must be > 0")
    if time_cost < 0:
        raise ValueError("time_cost must be >= 0")
    if delta < 0:
        raise ValueError("delta must be >= 0")

    input_bytes = input_value if isinstance(input_value, bytes) else str(input_value).encode("utf-8")
    buffer = [b""] * int(space_cost)
    counter = 0

    def hash_with_counter(payload: bytes) -> bytes:
        nonlocal counter
        digest = _sha256(_u32le(counter) + payload)
        counter += 1
        return digest

    buffer[0] = hash_with_counter(input_bytes)
    for i in range(1, space_cost):
        buffer[i] = hash_with_counter(buffer[i - 1])

    for t in range(time_cost):
        for i in range(space_cost):
            previous = (i or space_cost) - 1
            buffer[i] = hash_with_counter(buffer[previous] + buffer[i])
            for j in range(delta):
                param = _u32le(counter) + _u32le(t) + _u32le(i) + _u32le(j)
                counter += 1
                other = _u32be_from_digest_prefix(_sha256(param)) % space_cost
                buffer[i] = hash_with_counter(buffer[i] + buffer[other])
    return buffer[space_cost - 1]


def silent_balloon_hash_hex(input_value: str | bytes, space_cost: int, time_cost: int, delta: int = DEFAULT_DELTA) -> str:
    return silent_balloon_hash_bytes(input_value, space_cost, time_cost, delta).hex()


def verify_silentchallenge_pow(challenge: SilentChallengePow | dict[str, Any] | str, nonce: int | str) -> bool:
    try:
        item = parse_silentchallenge_challenge(challenge)
        n = int(nonce)
        if n < 0:
            return False
        digest = silent_balloon_hash_bytes(item.prefix + str(n), item.space_cost, item.time_cost, item.delta)
        return count_leading_zero_bits_bytes(digest) >= item.difficulty
    except Exception:
        return False


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


def score_silentchallenge_motion(motion: dict[str, Any]) -> dict[str, Any]:
    """Lightweight mirror for diagnostics; upstream scoring remains authoritative."""

    reasons: list[str] = []
    penalty = 0.0
    mouse = motion.get("m") or []
    keys = motion.get("k") or []
    clicks = motion.get("c") or []
    scroll = motion.get("s") or []
    events = motion.get("ev") or []
    duration = float(motion.get("dur") or 0)

    if len(mouse) < 5:
        penalty += 0.20
        reasons.append("insufficient mouse data")
    if duration < 3000:
        penalty += 0.10
        reasons.append("short engagement duration")
    if len(keys) == 0:
        penalty += 0.08
        reasons.append("no keystroke cadence")
    elif len(keys) >= 5:
        dwell = [float(x[0]) for x in keys if isinstance(x, list) and x]
        if _stddev(dwell) < 5:
            penalty += 0.08
            reasons.append("uniform key dwell")
    if len(clicks) == 0:
        penalty += 0.06
        reasons.append("no click data")
    if len(scroll) == 0:
        penalty += 0.04
        reasons.append("no scroll data")
    if len(events) < 8:
        penalty += 0.05
        reasons.append("low event-order diversity")

    score = max(0.0, min(1.0, 1.0 - penalty))
    return {"score": round(score, 3), "penalty": round(penalty, 3), "reasons": reasons}


def _count_bits(value: Any) -> int:
    try:
        return int(value or 0).bit_count()
    except Exception:
        return 0


def _penalty(state: dict[str, Any], amount: float, reason: str) -> None:
    state["score"] = max(0.0, float(state["score"]) - amount)
    state["flags"].append(reason)


def score_silentchallenge_signals(signals: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Partial Python mirror of silent-challenge/src/navigator.js validation rules."""

    state: dict[str, Any] = {"score": 1.0, "flags": []}
    automation = signals.get("automation") or {}
    for key, weight, label in (("globals", 0.15, "globals detected"), ("enhanced", 0.12, "enhanced signals"), ("extra", 0.12, "extra globals")):
        bits = _count_bits(automation.get(key))
        if bits:
            _penalty(state, min(0.5, bits * weight), f"automation:{bits} {label}")

    browser = signals.get("browser") or {}
    nav = signals.get("navigator") or {}
    ua = str(nav.get("ua") or "")
    if "Chrome" in ua:
        if not (int(browser.get("apis") or 0) & 1):
            _penalty(state, 0.08, "browser:chrome missing")
        if not (int(browser.get("apis") or 0) & 2):
            _penalty(state, 0.05, "browser:permissions missing")
    if not (int(browser.get("apis") or 0) & 4):
        _penalty(state, 0.10, "browser:no languages")
    for key, weight, label in (("selenium", 0.08, "selenium artifacts"), ("stealth", 0.08, "stealth signals"), ("advanced", 0.08, "advanced detection")):
        value = int(browser.get(key) or 0)
        if key == "stealth":
            value &= ~128
        bits = value.bit_count()
        if bits >= 3 and key == "advanced":
            _penalty(state, 0.35, f"browser:{bits} {label}")
        elif bits:
            _penalty(state, min(0.5, bits * weight), f"browser:{bits} {label}")

    props = signals.get("properties") or {}
    integrity = int(props.get("integrity") or 0)
    for bit, amount, reason in ((1, 0.10, "defineProperty tampered"), (2, 0.10, "getOwnPropDesc tampered"), (4, 0.08, "Reflect.get tampered")):
        if not (integrity & bit):
            _penalty(state, amount, f"properties:{reason}")
    overrides = int(props.get("overrides") or 0)
    if overrides:
        _penalty(state, min(0.3, overrides * 0.1), f"properties:{overrides} overrides")

    natives = signals.get("natives")
    if natives is not None:
        bits = (~int(natives) & 0xFFF).bit_count()
        if bits:
            _penalty(state, min(0.4, bits * 0.08), f"natives:{bits} tampered functions")

    features = signals.get("features")
    if features is not None:
        bits = (~int(features) & 0x7FF).bit_count()
        if bits > 3:
            _penalty(state, 0.15, f"features:{bits} missing")

    if nav:
        hc = int(nav.get("hardwareConcurrency") or 0)
        if hc == 1:
            _penalty(state, 0.08, "navigator:1 core")
        if hc == 0:
            _penalty(state, 0.15, "navigator:0 cores")
        if int(nav.get("languageCount") or 0) == 0 and not any(x in ua.lower() for x in ("mobile", "android")):
            _penalty(state, 0.12, "navigator:no languages")
        if nav.get("deviceMemory") not in (None, 0.25, 0.5, 1, 2, 4, 8, 16, 32, 64):
            _penalty(state, 0.10, "navigator:invalid deviceMemory")
        if nav.get("rtt") == 0:
            _penalty(state, 0.05, "navigator:rtt=0")
        if "Chrome" in ua and nav.get("productSub") != "20030107":
            _penalty(state, 0.08, "navigator:wrong productSub")
        if "Chrome" in ua and nav.get("vendor") != "Google Inc.":
            _penalty(state, 0.08, "navigator:wrong vendor")

    scr = signals.get("screen") or {}
    if scr:
        if int(scr.get("width") or 0) == 0 or int(scr.get("height") or 0) == 0:
            _penalty(state, 0.15, "screen:zero dimensions")
        if [scr.get("width"), scr.get("height")] in ([800, 600], [1024, 768]):
            _penalty(state, 0.10, "screen:VM-typical resolution")
        if 0 < int(scr.get("colorDepth") or 0) < 24:
            _penalty(state, 0.10, "screen:low colorDepth")
        if scr.get("devicePixelRatio") == 0:
            _penalty(state, 0.10, "screen:zero DPR")

    eng = signals.get("engine") or {}
    if eng:
        if "Chrome" in ua and eng.get("evalLength") != 33:
            _penalty(state, 0.10, "engine:wrong eval length Chrome")
        if eng.get("mathTan") == 0:
            _penalty(state, 0.05, "engine:math fingerprint zero")

    mq = signals.get("mediaQueries") or {}
    if mq:
        if not mq.get("pointerFine") and not mq.get("touch"):
            _penalty(state, 0.10, "mediaQueries:no pointer no touch")
        if not any(x in ua.lower() for x in ("mobile", "android")) and not mq.get("hover"):
            _penalty(state, 0.05, "mediaQueries:no hover on desktop")

    env = signals.get("environment") or {}
    if env:
        offset = int(env.get("timezoneOffset") or 0)
        if offset < -720 or offset > 840:
            _penalty(state, 0.10, "environment:impossible timezone")
        if env.get("timezoneName") == "":
            _penalty(state, 0.08, "environment:empty timezone name")
        touch = int(env.get("touch") or 0)
        if (touch & 1) != ((touch >> 1) & 1):
            _penalty(state, 0.05, "environment:touch inconsistency")

    if (signals.get("timing") or {}).get("perfNowIdentical"):
        _penalty(state, 0.10, "timing:identical perf.now diffs")
    gl = signals.get("webgl") or {}
    renderer = str(gl.get("renderer") or "")
    if "SwiftShader" in renderer or "llvmpipe" in renderer or "softpipe" in renderer:
        _penalty(state, 0.20, "webgl:software renderer")
    if gl.get("maxTextureSize") == 0:
        _penalty(state, 0.10, "webgl:zero maxTextureSize")

    canvas = signals.get("canvas") or {}
    if canvas.get("hash") == "err":
        _penalty(state, 0.10, "canvas:error")
    tampering = canvas.get("tampering") or {}
    if tampering.get("random"):
        _penalty(state, 0.25, "canvas:randomization")
    if tampering.get("inconsistent"):
        _penalty(state, 0.15, "canvas:data/pixel mismatch")

    fonts = signals.get("fonts") or {}
    if fonts.get("count") == 0 and fonts.get("widths"):
        _penalty(state, 0.10, "fonts:zero detected")

    headless = signals.get("headless") or {}
    for key, amount in (("pdfOff", 0.10), ("noTaskbar", 0.03), ("viewportMatch", 0.04), ("uadBlank", 0.12), ("runtimeConstructable", 0.12), ("iframeProxy", 0.15), ("pluginsNotArray", 0.10), ("mesa", 0.20)):
        if headless.get(key):
            _penalty(state, amount, f"headless:{key}")

    vmd = signals.get("vm") or {}
    for key, amount in (("softwareGL", 0.20), ("lowHardware", 0.06), ("vmResolution", 0.08), ("vmAudio", 0.10)):
        if vmd.get(key):
            _penalty(state, amount, f"vm:{key}")

    if signals.get("cdp"):
        _penalty(state, 0.15, "cdp:console side-effect")
    if (signals.get("devtools") or {}).get("sizeAnomaly"):
        _penalty(state, 0.05, "devtools:large size difference")

    if headers:
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        if not lower_headers.get("accept"):
            _penalty(state, 0.05, "headers:no Accept")
        if not lower_headers.get("accept-language"):
            _penalty(state, 0.05, "headers:no Accept-Language")
        if not lower_headers.get("accept-encoding"):
            _penalty(state, 0.05, "headers:no Accept-Encoding")
        header_ua = lower_headers.get("user-agent", "")
        if any(x in header_ua for x in ("HeadlessChrome", "PhantomJS", "SlimerJS")):
            _penalty(state, 0.20, "headers:headless UA string")
        if header_ua and "Mozilla/" not in header_ua:
            _penalty(state, 0.08, "headers:non-standard UA")

    return {"score": round(float(state["score"]), 4), "flags": state["flags"], "verdict": _classify_signal_score(float(state["score"]))}


def _classify_signal_score(score: float) -> str:
    if score >= 0.85:
        return "trusted"
    if score >= 0.6:
        return "suspicious"
    if score >= 0.3:
        return "likely_automated"
    return "automated"


def generate_silentchallenge_motion(*, now_ms: int | None = None) -> dict[str, Any]:
    _ = now_ms  # shape is relative time; upstream collector sends offsets from page load.
    mouse: list[list[float | int]] = []
    t = 120
    for i in range(80):
        t += 18 + (i % 7) * 3 + int(math.sin(i) * 5)
        x = 80 + i * 5.7 + math.sin(i / 3) * 18 + (i % 5) * 0.13
        y = 180 + math.sin(i / 5) * 55 + math.cos(i / 2) * 8 + (i % 7) * 0.11
        mouse.append([round(x, 2), round(y, 2), t])
    clicks = [
        [-8.4, 5.2, 143, 120, 38, 1860],
        [14.1, -4.7, 91, 200, 44, 2510],
        [3.7, 11.5, 174, 160, 50, 3330],
    ]
    keys = [[91, 0], [142, 173], [77, 241], [188, 119], [113, 296], [154, 151], [96, 213]]
    scroll = [[120, 120, 900], [260, 140, 1320], [405, 145, 1800], [560, 155, 2510], [710, 150, 3370]]
    events = [[0, p[2]] for p in mouse[:20]]
    events.extend([[1, 1800], [2, 1943], [3, 1960], [4, 2100], [5, 2191], [4, 2380], [5, 2522], [6, 2600], [6, 3000]])
    return {
        "m": mouse,
        "c": clicks,
        "k": keys,
        "s": scroll,
        "tc": [],
        "ac": [],
        "gy": [],
        "or": [],
        "ev": events,
        "bc": [],
        "bl": [],
        "ttfi": 120,
        "dur": 5200,
        "meta": {"hasTouchScreen": False, "hasMotionSensors": False},
    }


def generate_silentchallenge_signals(*, now_ms: int | None = None) -> dict[str, Any]:
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    ua = DEFAULT_BROWSER_HEADERS["User-Agent"]
    return {
        "automation": {"globals": 0, "enhanced": 0, "extra": 0},
        "browser": {"apis": 0xFF, "selenium": 0, "stealth": 0, "advanced": 0},
        "properties": {"integrity": 1 | 2 | 4, "overrides": 0, "protoInconsistency": 0},
        "natives": 0xFFF,
        "features": 0x7FF,
        "navigator": {
            "ua": ua,
            "platform": "Win32",
            "pluginCount": 5,
            "languageCount": 2,
            "languages": ["en-US", "en"],
            "cookieEnabled": True,
            "doNotTrack": "",
            "hardwareConcurrency": 8,
            "deviceMemory": 8,
            "rtt": 50,
            "downlink": 10,
            "effectiveType": "4g",
            "maxTouchPoints": 0,
            "pdfViewerEnabled": True,
            "vendor": "Google Inc.",
            "productSub": "20030107",
            "appVersion": "5.0 (Windows NT 10.0; Win64; x64)",
            "uadBrands": ["Chromium/124", "Google Chrome/124"],
            "uadMobile": False,
            "uadPlatform": "Windows",
        },
        "screen": {
            "width": 1440,
            "height": 900,
            "availWidth": 1440,
            "availHeight": 860,
            "colorDepth": 24,
            "pixelDepth": 24,
            "devicePixelRatio": 1,
            "orientation": "landscape-primary",
            "isExtended": False,
        },
        "engine": {"evalLength": 33, "stackStyle": "v8", "mathTan": 1.4214488238747245, "mathAcosh": None, "bindNative": 1, "externalType": "object"},
        "mediaQueries": {"hover": True, "anyHover": True, "pointerFine": True, "pointerCoarse": False, "darkMode": False, "reducedMotion": False, "highContrast": False, "forcedColors": False, "colorGamutP3": False, "colorGamutSrgb": True, "touch": False},
        "environment": {"timezoneOffset": 300, "timezoneName": "America/New_York", "touch": 0, "document": 2 | 4, "online": True, "batteryApi": 0},
        "timing": {"perfNowIdentical": False},
        "webgl": {"vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)", "maxTextureSize": 16384, "maxVertexAttribs": 16, "extensionCount": 34},
        "canvas": {"hash": "7b3c2a1f", "tampering": {"random": 0, "error": 0, "inconsistent": 0, "dataLength": 512}},
        "fonts": {"widths": [10, 12, 13], "count": 12},
        "headless": {"pdfOff": 0, "noTaskbar": 0, "viewportMatch": 0, "noShare": 0, "activeTextRed": 0, "uadBlank": 0, "chromeKeyPosition": 0, "runtimeConstructable": 0, "iframeProxy": 0, "pluginsNotArray": 0, "mesa": 0},
        "vm": {"softwareGL": 0, "lowHardware": 0, "vmResolution": 0, "vmAudio": 0},
        "consistency": {"clientHints": {"hasUAData": True, "mobileMismatch": False, "platformMismatch": False}, "screen": {"dimensionLie": False, "alwaysLight": False}, "locale": {"languagePrefix": False, "localeLie": False}},
        "devtools": {"sizeAnomaly": False},
        "cdp": False,
        "cssVersion": 124,
        "voices": {"voiceCount": 5, "mediaDevices": True, "webrtc": True},
        "performance": {"jsHeapSizeLimit": 4_294_705_152, "totalJSHeapSize": 12_345_678},
        "prototype": {"lieCount": 0, "mimeTypeProto": False},
        "drawing": {"emojiWidth": 16, "emojiHeight": 16},
        "meta": {"collectedAt": now, "elapsed": 12},
    }


def parse_silentchallenge_challenge(value: SilentChallengePow | dict[str, Any] | str) -> SilentChallengePow:
    if isinstance(value, SilentChallengePow):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        obj: dict[str, Any] = json.loads(text)
    else:
        obj = dict(value)

    outer_id = obj.get("challengeId") or obj.get("id")
    pow_obj = obj.get("pow") if isinstance(obj.get("pow"), dict) else obj
    challenge_id = str(pow_obj.get("challengeId") or outer_id or "") or None
    prefix = str(pow_obj.get("prefix") or "")
    difficulty = int(pow_obj.get("difficulty") or 0)
    space_cost = int(pow_obj.get("spaceCost") or pow_obj.get("space_cost") or 0)
    time_cost = int(pow_obj.get("timeCost") or pow_obj.get("time_cost") or 0)
    delta = int(pow_obj.get("delta") if pow_obj.get("delta") is not None else DEFAULT_DELTA)

    if not prefix:
        raise ValueError("silentchallenge prefix is required")
    if difficulty < 0:
        raise ValueError("silentchallenge difficulty must be >= 0")
    if space_cost <= 0:
        raise ValueError("silentchallenge spaceCost must be > 0")
    if time_cost < 0:
        raise ValueError("silentchallenge timeCost must be >= 0")
    if delta < 0:
        raise ValueError("silentchallenge delta must be >= 0")
    return SilentChallengePow(
        challenge_id=challenge_id,
        prefix=prefix,
        difficulty=difficulty,
        space_cost=space_cost,
        time_cost=time_cost,
        delta=delta,
    )


def solve_silentchallenge_pow(
    challenge: SilentChallengePow | dict[str, Any] | str,
    *,
    motion: dict[str, Any] | None = None,
    signals: dict[str, Any] | None = None,
    start: int = 0,
    max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> SilentChallengeSolution | None:
    item = parse_silentchallenge_challenge(challenge)
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    start = max(0, int(start))
    max_attempts = DEFAULT_MAX_ATTEMPTS if max_attempts is None else max(1, int(max_attempts))
    attempts = 0
    for nonce in range(start, start + max_attempts):
        if deadline is not None and attempts and attempts % 16 == 0 and time.monotonic() >= deadline:
            return None
        attempts += 1
        digest = silent_balloon_hash_bytes(item.prefix + str(nonce), item.space_cost, item.time_cost, item.delta)
        leading = count_leading_zero_bits_bytes(digest)
        if leading >= item.difficulty:
            return SilentChallengeSolution(
                challenge=item,
                nonce=nonce,
                hash_hex=digest.hex(),
                leading_zero_bits=leading,
                attempts=attempts,
                took_ms=int((time.monotonic() - started) * 1000),
                motion=motion or generate_silentchallenge_motion(),
                signals=signals or generate_silentchallenge_signals(),
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


def _merge_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    out = dict(DEFAULT_BROWSER_HEADERS)
    if headers:
        out.update(headers)
    return out


def _derive_challenge_url(base_url: str | None, challenge_url: str | None) -> str | None:
    if challenge_url:
        return challenge_url
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", "challenge")


def _derive_verify_url(base_url: str | None, challenge_url: str | None, verify_url: str | None, challenge_id: str | None) -> str | None:
    if verify_url:
        return verify_url.replace("{challengeId}", challenge_id or "").replace("{id}", challenge_id or "")
    if not challenge_id:
        return None
    if base_url:
        return urljoin(base_url.rstrip("/") + "/", f"challenge/{challenge_id}/verify")
    if challenge_url and challenge_url.rstrip("/").endswith("/challenge"):
        return challenge_url.rstrip("/") + f"/{challenge_id}/verify"
    if challenge_url:
        return challenge_url.rstrip("/") + f"/{challenge_id}/verify"
    return None


def _extract_ticket(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "message"):
            if data.get(key):
                return str(data[key])
    return fallback


class SilentChallengeSolver:
    """silent-challenge motion/navigator attestation + balloon SHA-256 PoW protocol solver."""

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
        submit: bool = False,
        motion_json: Any = None,
        motion_file: str | None = None,
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
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "vm_response": "not_used",
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
                out = output_root / "silentchallenge_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="silentchallenge",
                ok=ok,
                captcha_type="passive_pow",
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
            motion = _load_json_arg(motion_json, motion_file) or generate_silentchallenge_motion()
            signals = _load_json_arg(signals_json, signals_file) or generate_silentchallenge_signals()
            if not isinstance(motion, dict):
                raise ValueError("silentchallenge motion must be a JSON object")
            if not isinstance(signals, dict):
                raise ValueError("silentchallenge signals must be a JSON object")
            motion_score = score_silentchallenge_motion(motion)
            signal_score = score_silentchallenge_signals(signals, request_headers)
            raw["motion"] = motion
            raw["signals"] = signals
            diagnostics.update(
                {
                    "synthetic_motion_score": motion_score["score"],
                    "synthetic_motion_reasons": motion_score["reasons"],
                    "synthetic_signal_score": signal_score["score"],
                    "synthetic_signal_flags": signal_score["flags"],
                }
            )

            effective_challenge_url = _derive_challenge_url(base_url, challenge_url)
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=effective_challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            challenge_received = time.monotonic()
            item = parse_silentchallenge_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "prefix_prefix": item.prefix[:24],
                    "difficulty": item.difficulty,
                    "space_cost": item.space_cost,
                    "time_cost": item.time_cost,
                    "delta": item.delta,
                }
            )
            solution = solve_silentchallenge_pow(
                item,
                motion=motion,
                signals=signals,
                start=start,
                max_attempts=max_attempts,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("silentchallenge solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "leadingZeroBits": solution.leading_zero_bits,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash": solution.hash_hex,
                    "leading_zero_bits": solution.leading_zero_bits,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url or base_url:
                effective_verify_url = _derive_verify_url(base_url, effective_challenge_url, verify_url, item.challenge_id)
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
                ok = bool(
                    isinstance(verify_data, dict)
                    and (
                        verify_data.get("cleared") is True
                        or verify_data.get("verified") is True
                        or verify_data.get("success") is True
                        or verify_data.get("ok") is True
                        or verify_data.get("token")
                    )
                )
                if not ok:
                    reason = "verify_failed"
                    if isinstance(verify_data, dict):
                        reason = verify_data.get("error") or verify_data.get("reason") or verify_data.get("message") or reason
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = _extract_ticket(verify_data, ticket)
                verify_code = "validated"
                diagnostics["submitted"] = True
                if isinstance(verify_data, dict):
                    diagnostics["server_score"] = verify_data.get("score")
                    diagnostics["server_flags"] = verify_data.get("flags")
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
            raise ValueError("silentchallenge requires base_url, challenge_json, challenge_file or challenge_url")
        resp = requests.post(
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
        solution: SilentChallengeSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **headers},
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
        return data
