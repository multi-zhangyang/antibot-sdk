from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_API_URL = "https://api.crovly.com"
DEFAULT_EDGE_URL = "https://edge.crovly.com"
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 2**32
MAX_COUNTER = 2**32
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class CrovlyChallenge:
    nonce: str
    difficulty: int
    badge: bool | None = None
    color: str | None = None
    size: str | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {"nonce": self.nonce, "difficulty": self.difficulty}
        if self.badge is not None:
            out["badge"] = self.badge
        if self.color:
            out["color"] = self.color
        if self.size:
            out["size"] = self.size
        return out


@dataclass(slots=True)
class CrovlyPowSolution:
    challenge: CrovlyChallenge
    counter: int
    hash_hex: str
    leading_zero_bits: int
    attempts: int
    took_ms: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "nonce": self.challenge.nonce,
            "difficulty": self.challenge.difficulty,
            "counter": self.counter,
            "hashHex": self.hash_hex,
            "leadingZeroBits": self.leading_zero_bits,
            "attempts": self.attempts,
            "tookMs": self.took_ms,
        }


@dataclass(frozen=True, slots=True)
class CrovlyClientProfile:
    canvas_hash: str = "8f3c1a6d9e0b4c27"
    webgl_vendor: str = "Google Inc."
    webgl_renderer: str = "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)"
    audio_fingerprint: str = "124.043476"
    screen_width: int = 1920
    screen_height: int = 1080
    color_depth: int = 24
    timezone_id: str = "America/New_York"
    language: str = "en-US"
    platform: str = "Win32"
    device_memory: int | str = 8
    hardware_concurrency: int | str = 8
    webdriver: bool = False
    chrome_absent: bool = False
    no_plugins: bool = False
    swift_shader: bool = False
    notification_denied: bool = False
    zero_screen: bool = False
    no_languages: bool = False

    @property
    def webgl_fingerprint(self) -> str:
        return f"{self.webgl_vendor}|{self.webgl_renderer}"

    @property
    def screen_fingerprint(self) -> str:
        return f"{self.screen_width}x{self.screen_height}x{self.color_depth}"

    def fingerprint_parts(self) -> list[str]:
        return [
            str(self.canvas_hash),
            self.webgl_fingerprint,
            str(self.audio_fingerprint),
            self.screen_fingerprint,
            str(self.timezone_id),
            str(self.language),
            str(self.platform),
            str(self.device_memory or "unknown"),
            str(self.hardware_concurrency or "unknown"),
        ]


def count_leading_zero_bits(data: bytes) -> int:
    total = 0
    for b in data:
        if b == 0:
            total += 8
            continue
        while (b & 0x80) == 0:
            total += 1
            b <<= 1
        break
    return total


def crovly_pow_input_bytes(nonce: str, counter: int | str) -> bytes:
    """Bytes used by Crovly's inline SHA-256 worker.

    The bundled worker copies JS string charCodeAt(i) into a Uint8Array. For ASCII
    nonces this is identical to normal UTF-8/Latin-1 bytes; UTF-16 low bytes keep
    the SDK compatible with the exact browser fallback for non-ASCII fixtures.
    """

    value = f"{nonce}{int(counter)}"
    raw = value.encode("utf-16-le", "surrogatepass")
    return raw[0::2]


def crovly_pow_hash_bytes(nonce: str, counter: int | str) -> bytes:
    return hashlib.sha256(crovly_pow_input_bytes(str(nonce), counter)).digest()


def crovly_pow_hash_hex(nonce: str, counter: int | str) -> str:
    return crovly_pow_hash_bytes(nonce, counter).hex()


def parse_crovly_challenge(
    value: CrovlyChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
) -> CrovlyChallenge:
    if isinstance(value, CrovlyChallenge):
        _validate_difficulty(value.difficulty)
        if not value.nonce:
            raise ValueError("Crovly challenge nonce is empty")
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Crovly challenge is empty")
        if text.startswith("@"):
            return parse_crovly_challenge(Path(text[1:]).read_text(encoding="utf-8"), difficulty=difficulty)
        if text.startswith("{"):
            return parse_crovly_challenge(json.loads(text), difficulty=difficulty)
        if difficulty is None:
            raise ValueError("Crovly inline nonce requires difficulty")
        return CrovlyChallenge(nonce=text, difficulty=int(difficulty))
    if not isinstance(value, dict):
        raise ValueError("Crovly challenge must be an object or nonce string")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    if isinstance(data.get("pow"), dict) and not data.get("nonce"):
        data = data["pow"]
    nonce = data.get("nonce") or data.get("powNonce") or data.get("id")
    diff_raw = difficulty if difficulty is not None else data.get("difficulty", data.get("diff"))
    if not nonce:
        raise ValueError("Crovly challenge requires nonce")
    if diff_raw is None:
        raise ValueError("Crovly challenge requires difficulty")
    item = CrovlyChallenge(
        nonce=str(nonce),
        difficulty=int(diff_raw),
        badge=data.get("badge") if isinstance(data.get("badge"), bool) else None,
        color=str(data["color"]) if data.get("color") else None,
        size=str(data["size"]) if data.get("size") else None,
    )
    _validate_difficulty(item.difficulty)
    return item


def solve_crovly_pow_challenge(
    challenge: CrovlyChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> CrovlyPowSolution | None:
    item = parse_crovly_challenge(challenge, difficulty=difficulty)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if start >= MAX_COUNTER:
        return None
    end_exclusive = min(MAX_COUNTER, start + max_attempts)
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or end_exclusive - start < 100_000:
        counter, digest, checked = _solve_crovly_range(
            item.nonce,
            item.difficulty,
            start,
            end_exclusive,
            deadline_epoch,
        )
        if counter is None or digest is None:
            return None
        return CrovlyPowSolution(
            challenge=item,
            counter=counter,
            hash_hex=digest.hex(),
            leading_zero_bits=count_leading_zero_bits(digest),
            attempts=checked,
            took_ms=int((time.monotonic() - started) * 1000),
        )

    chunk = math.ceil((end_exclusive - start) / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(end_exclusive, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_crovly_range, item.nonce, item.difficulty, lo, hi, deadline_epoch)] = idx

    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            counter, digest, checked = fut.result()
            checked_total += checked
            if counter is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return CrovlyPowSolution(
                    challenge=item,
                    counter=counter,
                    hash_hex=digest.hex(),
                    leading_zero_bits=count_leading_zero_bits(digest),
                    attempts=checked_total,
                    took_ms=int((time.monotonic() - started) * 1000),
                )
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None


def verify_crovly_pow_solution(
    challenge: CrovlyChallenge | dict[str, Any] | str,
    solution: CrovlyPowSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_crovly_challenge(challenge)
        hash_hex = ""
        if isinstance(solution, CrovlyPowSolution):
            counter = solution.counter
            hash_hex = solution.hash_hex
        elif isinstance(solution, dict):
            counter = int(solution.get("counter", solution.get("nonce", solution.get("solution"))))
            hash_hex = str(solution.get("hashHex") or solution.get("hash") or "")
        else:
            counter = int(solution)
        if counter < 0 or counter >= MAX_COUNTER:
            return False
        digest = crovly_pow_hash_bytes(item.nonce, counter)
        if hash_hex and digest.hex() != hash_hex.lower():
            return False
        return _digest_matches_bit_difficulty(digest, item.difficulty)
    except Exception:
        return False


def crovly_fingerprint_material(profile: CrovlyClientProfile | dict[str, Any] | None = None) -> str:
    return "|".join(_coerce_profile(profile).fingerprint_parts())


def generate_crovly_fingerprint_hash(profile: CrovlyClientProfile | dict[str, Any] | None = None) -> str:
    material = crovly_fingerprint_material(profile)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def generate_crovly_environment(profile: CrovlyClientProfile | dict[str, Any] | None = None) -> dict[str, bool]:
    p = _coerce_profile(profile)
    return {
        "webdriver": bool(p.webdriver),
        "chromeAbsent": bool(p.chrome_absent),
        "noPlugins": bool(p.no_plugins),
        "swiftShader": bool(p.swift_shader),
        "notificationDenied": bool(p.notification_denied),
        "zeroScreen": bool(p.zero_screen),
        "noLanguages": bool(p.no_languages),
    }


def generate_crovly_behavior(*, elapsed_ms: int = 1800) -> dict[str, int | float]:
    return {
        "mm": 42,
        "md": 620,
        "mdc": 8,
        "msv": 0.37,
        "kc": 0,
        "kdv": 0,
        "sc": 1,
        "sdc": 0,
        "tc": 0,
        "el": max(50, int(elapsed_ms)),
        "mac": 0.22,
        "mte": 0.68,
        "kte": 0,
    }


def generate_crovly_hold_signals(*, duration_ms: int = 2600) -> dict[str, int | float]:
    return {
        "hd": max(0, int(duration_ms)),
        "htd": 14.8,
        "htdc": 3,
        "hpv": 0.18,
        "hgv": 0,
        "hav": 0,
    }


def score_crovly_client_signals(
    environment: dict[str, Any] | None = None,
    behavior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    env = environment or generate_crovly_environment()
    reasons: list[str] = []
    score = 0.0
    primary_headless = [env.get("webdriver"), env.get("chromeAbsent"), env.get("swiftShader")]
    headless_hits = sum(1 for x in primary_headless if bool(x))
    if headless_hits >= 2:
        score += 0.55
        reasons.append("headless primary signals >=2")
    elif headless_hits == 1:
        score += 0.20
        reasons.append("one headless primary signal")
    for key, weight in (
        ("zeroScreen", 0.20),
        ("noLanguages", 0.12),
        ("noPlugins", 0.08),
        ("notificationDenied", 0.04),
    ):
        if env.get(key):
            score += weight
            reasons.append(f"{key}=true")
    if behavior is None:
        score += 0.08
        reasons.append("missing behavior")
    else:
        if int(behavior.get("el") or 0) < 300:
            score += 0.18
            reasons.append("behavior elapsed too short")
        if int(behavior.get("mm") or 0) < 3 and int(behavior.get("tc") or 0) == 0:
            score += 0.16
            reasons.append("almost no pointer/touch movement")
        if float(behavior.get("mte") or 0) == 0 and int(behavior.get("mm") or 0) > 10:
            score += 0.08
            reasons.append("move timing entropy is zero")
    score = round(min(1.0, score), 3)
    return {"score": score, "reasons": reasons, "recommendation": "allow" if score < 0.35 else "review"}


def build_crovly_verify_body(
    challenge: CrovlyChallenge | dict[str, Any] | str,
    solution: CrovlyPowSolution | dict[str, Any] | int | str,
    *,
    fingerprint_hash: str | None = None,
    profile: CrovlyClientProfile | dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
    behavior: dict[str, Any] | None = None,
    hold_signals: dict[str, Any] | None = None,
    solve_time_ms: int | None = None,
) -> dict[str, Any]:
    item = parse_crovly_challenge(challenge)
    counter, took_ms = _solution_counter_timing(solution)
    if counter < 0:
        raise ValueError("Crovly counter must be >= 0")
    if fingerprint_hash is None:
        fingerprint_hash = generate_crovly_fingerprint_hash(profile)
    env = dict(environment) if environment is not None else generate_crovly_environment(profile)
    behavior_payload = dict(behavior) if behavior is not None else generate_crovly_behavior()
    if hold_signals:
        behavior_payload.update(hold_signals)
    effective_solve_ms = int(solve_time_ms if solve_time_ms is not None else took_ms)
    return {
        "nonce": item.nonce,
        "counter": counter,
        "solveTimeMs": max(0, effective_solve_ms),
        "fingerprintHash": str(fingerprint_hash),
        "environment": env,
        "behavior": behavior_payload,
    }


def _solve_crovly_range(
    nonce: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, bytes | None, int]:
    prefix = crovly_pow_input_bytes(str(nonce), 0)[: len(str(nonce).encode("utf-16-le", "surrogatepass")) // 2]
    checked = 0
    for counter in range(max(0, int(start)), min(MAX_COUNTER, max(0, int(end_exclusive)))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha256(prefix + str(counter).encode("ascii")).digest()
        checked += 1
        if _digest_matches_bit_difficulty(digest, difficulty):
            return counter, digest, checked
    return None, None, checked


def _digest_matches_bit_difficulty(digest: bytes, difficulty: int) -> bool:
    difficulty = int(difficulty)
    if difficulty < 0 or difficulty > len(digest) * 8:
        return False
    full_zero_bytes = difficulty // 8
    if full_zero_bytes and digest[:full_zero_bytes] != b"\0" * full_zero_bytes:
        return False
    remaining = difficulty % 8
    if remaining:
        mask = 0xFF << (8 - remaining) & 0xFF
        return (digest[full_zero_bytes] & mask) == 0
    return True


def _validate_difficulty(difficulty: int) -> None:
    if int(difficulty) < 0 or int(difficulty) > 256:
        raise ValueError("Crovly difficulty must be between 0 and 256 bits")


def _solution_counter_timing(solution: CrovlyPowSolution | dict[str, Any] | int | str) -> tuple[int, int]:
    if isinstance(solution, CrovlyPowSolution):
        return int(solution.counter), int(solution.took_ms)
    if isinstance(solution, dict):
        counter = int(solution.get("counter", solution.get("nonce", solution.get("solution"))))
        took_ms = int(solution.get("tookMs", solution.get("timeMs", solution.get("solveTimeMs", 0))) or 0)
        return counter, took_ms
    return int(solution), 0


def _coerce_profile(profile: CrovlyClientProfile | dict[str, Any] | None = None) -> CrovlyClientProfile:
    if profile is None:
        return CrovlyClientProfile()
    if isinstance(profile, CrovlyClientProfile):
        return profile
    if not isinstance(profile, dict):
        raise ValueError("Crovly profile must be a JSON object")
    mapping = {
        "canvasHash": "canvas_hash",
        "canvas": "canvas_hash",
        "webglVendor": "webgl_vendor",
        "vendor": "webgl_vendor",
        "webglRenderer": "webgl_renderer",
        "renderer": "webgl_renderer",
        "audioFingerprint": "audio_fingerprint",
        "audio": "audio_fingerprint",
        "screenWidth": "screen_width",
        "screenHeight": "screen_height",
        "colorDepth": "color_depth",
        "timezone": "timezone_id",
        "timeZone": "timezone_id",
        "timezoneId": "timezone_id",
        "language": "language",
        "platform": "platform",
        "deviceMemory": "device_memory",
        "hardwareConcurrency": "hardware_concurrency",
        "webdriver": "webdriver",
        "chromeAbsent": "chrome_absent",
        "noPlugins": "no_plugins",
        "swiftShader": "swift_shader",
        "notificationDenied": "notification_denied",
        "zeroScreen": "zero_screen",
        "noLanguages": "no_languages",
    }
    kwargs: dict[str, Any] = {}
    for key, value in profile.items():
        target = mapping.get(key, key)
        if hasattr(CrovlyClientProfile, target):
            kwargs[target] = value
    base = CrovlyClientProfile()
    return replace(base, **kwargs)


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


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _merge_headers(
    *,
    site_key: str | None = None,
    headers: dict[str, str] | None = None,
    user_agent: str | None = None,
) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "Origin": "https://get.crovly.com",
        "Referer": "https://get.crovly.com/",
    }
    if site_key:
        out["X-Site-Key"] = site_key
    if headers:
        out.update(headers)
    return out


def _derive_url(base_url: str | None, explicit: str | None, path: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _challenge_url_candidates(
    *,
    api_url: str | None,
    edge_url: str | None,
    challenge_url: str | None,
) -> list[tuple[str, str | None]]:
    if challenge_url:
        return [(challenge_url, api_url)]
    candidates: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for base in (api_url, edge_url):
        url = _derive_url(base, None, "/challenge")
        if url and url not in seen:
            candidates.append((url, base))
            seen.add(url)
    return candidates


def _extract_ticket(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "message"):
            if data.get(key):
                return str(data[key])
    return fallback


class CrovlySolver:
    """Crovly fingerprint/behavior-bound SHA-256 PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        site_key: str | None = None,
        api_url: str | None = DEFAULT_API_URL,
        edge_url: str | None = DEFAULT_EDGE_URL,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        fingerprint_hash: str | None = None,
        fingerprint_json: Any = None,
        fingerprint_file: str | None = None,
        profile_json: Any = None,
        profile_file: str | None = None,
        environment_json: Any = None,
        environment_file: str | None = None,
        behavior_json: Any = None,
        behavior_file: str | None = None,
        hold_json: Any = None,
        hold_file: str | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        min_submit_ms: int = 0,
        min_solve_ms: int = 0,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "api_url": api_url,
            "edge_url": edge_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "site_key_present": bool(site_key),
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
                out = output_root / "crovly_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="crovly",
                ok=ok,
                captcha_type="fingerprint_behavior_pow",
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
            request_headers = _merge_headers(site_key=site_key, headers=headers, user_agent=user_agent)
            challenge_data, selected_base, challenge_received = self._load_challenge(
                site_key=site_key,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                candidates=_challenge_url_candidates(
                    api_url=api_url,
                    edge_url=edge_url,
                    challenge_url=challenge_url,
                ),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_crovly_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_present": bool(item.nonce),
                    "difficulty": item.difficulty,
                    "selected_base": selected_base,
                }
            )

            profile = self._load_profile(
                profile_json=profile_json,
                profile_file=profile_file,
                fingerprint_json=fingerprint_json,
                fingerprint_file=fingerprint_file,
                raw=raw,
            )
            effective_fingerprint_hash = fingerprint_hash or self._load_fingerprint_hash(
                fingerprint_json=fingerprint_json,
                fingerprint_file=fingerprint_file,
            )
            env = _load_json_arg(environment_json, environment_file)
            if env is not None and not isinstance(env, dict):
                raise ValueError("Crovly environment must be a JSON object")
            behavior = _load_json_arg(behavior_json, behavior_file)
            if behavior is not None and not isinstance(behavior, dict):
                raise ValueError("Crovly behavior must be a JSON object")
            hold = _load_json_arg(hold_json, hold_file)
            if hold is not None and not isinstance(hold, dict):
                raise ValueError("Crovly hold signals must be a JSON object")

            solution = solve_crovly_pow_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Crovly PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            solve_time_ms = max(int(solution.took_ms), int(min_solve_ms))
            verify_body = build_crovly_verify_body(
                item,
                solution,
                fingerprint_hash=effective_fingerprint_hash,
                profile=profile,
                environment=env,
                behavior=behavior,
                hold_signals=hold,
                solve_time_ms=solve_time_ms,
            )
            signal_score = score_crovly_client_signals(
                verify_body.get("environment"),
                verify_body.get("behavior"),
            )
            raw["solution"] = {
                **solution.to_payload(),
                "solveTimeMs": solve_time_ms,
                "verifyBody": verify_body,
            }
            diagnostics.update(
                {
                    "counter": solution.counter,
                    "hash_hex": solution.hash_hex,
                    "leading_zero_bits": solution.leading_zero_bits,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                    "reported_solve_ms": solve_time_ms,
                    "synthetic_score": signal_score["score"],
                    "synthetic_recommendation": signal_score["recommendation"],
                }
            )
            ticket = _json_body(verify_body)
            verify_code = "solved"
            if submit or verify_url:
                if not site_key:
                    errors.append("Crovly submit requires site_key for X-Site-Key")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                wait_ms = max(0, int(min_submit_ms) - int((time.monotonic() - challenge_received) * 1000))
                if wait_ms:
                    time.sleep(wait_ms / 1000)
                effective_verify_url = _derive_url(selected_base or api_url, verify_url, "/verify")
                if not effective_verify_url:
                    errors.append("submit requested but verify_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    verify_body=verify_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = bool(isinstance(verify_data, dict) and verify_data.get("passed") is True and verify_data.get("token"))
                if not ok:
                    reason = "verify_failed"
                    if isinstance(verify_data, dict):
                        reason = verify_data.get("message") or verify_data.get("reason") or verify_data.get("error") or reason
                        diagnostics["retry_hint"] = bool(verify_data.get("retry"))
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = _extract_ticket(verify_data, ticket)
                verify_code = "validated"
                diagnostics["submitted"] = True
                diagnostics["token_present"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        site_key: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        candidates: list[tuple[str, str | None]],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> tuple[Any, str | None, float]:
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data, None, time.monotonic()
        if not candidates:
            raise ValueError("Crovly requires challenge_json, challenge_file, challenge_url or api_url")
        if not site_key:
            raise ValueError("Crovly /challenge requires site_key for X-Site-Key")
        attempts: list[dict[str, Any]] = []
        raw["challengeAttempts"] = attempts
        last_error: Exception | None = None
        for url, base in candidates:
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                item: dict[str, Any] = {"status": resp.status_code, "url": url}
                attempts.append(item)
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {"text": resp.text[:500]}
                item["json"] = payload
                resp.raise_for_status()
                raw["challengeSource"] = "url"
                return payload, base, time.monotonic()
            except Exception as exc:
                last_error = exc
                attempts[-1]["error"] = str(exc) if attempts else str(exc)
        if last_error:
            raise last_error
        raise ValueError("Crovly challenge fetch failed")

    def _load_profile(
        self,
        *,
        profile_json: Any,
        profile_file: str | None,
        fingerprint_json: Any,
        fingerprint_file: str | None,
        raw: dict[str, Any],
    ) -> CrovlyClientProfile | dict[str, Any] | None:
        profile_data = _load_json_arg(profile_json, profile_file)
        if profile_data is not None:
            raw["profileSource"] = "profile"
            return _coerce_profile(profile_data)
        fingerprint_data = _load_json_arg(fingerprint_json, fingerprint_file)
        if isinstance(fingerprint_data, dict) and not (fingerprint_data.get("fingerprintHash") or fingerprint_data.get("fingerprint_hash")):
            raw["profileSource"] = "fingerprint_profile"
            return _coerce_profile(fingerprint_data)
        return None

    def _load_fingerprint_hash(
        self,
        *,
        fingerprint_json: Any,
        fingerprint_file: str | None,
    ) -> str | None:
        data = _load_json_arg(fingerprint_json, fingerprint_file)
        if data is None:
            return None
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            value = data.get("fingerprintHash") or data.get("fingerprint_hash")
            return str(value) if value else None
        raise ValueError("Crovly fingerprint data must be a hash string or JSON object")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        verify_body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            data=_json_body(verify_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = payload
        return payload
