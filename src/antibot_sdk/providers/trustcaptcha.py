from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_API_URL = "https://api.trustcomponent.com"
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS_PER_TASK = 20_000_000
DEFAULT_MIN_SOLVE_MS = 1200
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_LIBRARY_VERSION = "3.0.1"


@dataclass(slots=True)
class TrustcaptchaTask:
    number: int
    input: str

    def to_payload(self) -> dict[str, Any]:
        return {"number": self.number, "input": self.input}


@dataclass(slots=True)
class TrustcaptchaChallenge:
    verification_id: str
    difficulty: int
    tasks: list[TrustcaptchaTask]

    def to_payload(self) -> dict[str, Any]:
        return {
            "verificationId": self.verification_id,
            "difficulty": self.difficulty,
            "tasks": [task.to_payload() for task in self.tasks],
        }


@dataclass(slots=True)
class TrustcaptchaTaskSolution:
    number: int
    nonce: str
    hash_hex: str
    attempts: int

    def to_submit_task(self) -> dict[str, Any]:
        return {"number": self.number, "nonce": self.nonce}


@dataclass(slots=True)
class TrustcaptchaSolution:
    challenge: TrustcaptchaChallenge
    tasks: list[TrustcaptchaTaskSolution]
    solve_time_ms: int
    attempts: int

    @property
    def submit_tasks(self) -> list[dict[str, Any]]:
        return [task.to_submit_task() for task in self.tasks]

    def to_payload(self) -> dict[str, Any]:
        return {
            "verificationId": self.challenge.verification_id,
            "difficulty": self.challenge.difficulty,
            "solveTimeMs": self.solve_time_ms,
            "attempts": self.attempts,
            "tasks": [
                {
                    "number": task.number,
                    "nonce": task.nonce,
                    "hash": task.hash_hex,
                    "attempts": task.attempts,
                }
                for task in self.tasks
            ],
        }


def count_leading_zero_bits(data: bytes | bytearray | memoryview) -> int:
    bits = 0
    for b in bytes(data):
        if b == 0:
            bits += 8
            continue
        return bits + (8 - int(b).bit_length())
    return bits


def trustcaptcha_input_bytes(input_b64: str) -> bytes:
    text = str(input_b64).strip()
    if not text:
        return b""
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(padded)


def trustcaptcha_pow_hash_bytes(input_b64: str, nonce: str) -> bytes:
    return hashlib.sha256(trustcaptcha_input_bytes(input_b64) + str(nonce).encode("utf-8")).digest()


def trustcaptcha_pow_hash_hex(input_b64: str, nonce: str) -> str:
    return trustcaptcha_pow_hash_bytes(input_b64, nonce).hex()


def verify_trustcaptcha_task_solution(
    task: TrustcaptchaTask | dict[str, Any],
    solution: TrustcaptchaTaskSolution | dict[str, Any] | str,
    difficulty: int,
) -> bool:
    try:
        parsed_task = _parse_task(task)
        if isinstance(solution, TrustcaptchaTaskSolution):
            nonce = solution.nonce
            expected_hash = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = str(solution.get("nonce", ""))
            expected_hash = str(solution.get("hash") or solution.get("hashHex") or "")
        else:
            nonce = str(solution)
            expected_hash = ""
        if not nonce.startswith("tcn") or len(nonce) > 64:
            return False
        digest = trustcaptcha_pow_hash_bytes(parsed_task.input, nonce)
        if expected_hash and digest.hex() != expected_hash.lower():
            return False
        return count_leading_zero_bits(digest) >= int(difficulty)
    except Exception:
        return False


def parse_trustcaptcha_challenge(value: TrustcaptchaChallenge | dict[str, Any] | str) -> TrustcaptchaChallenge:
    if isinstance(value, TrustcaptchaChallenge):
        _validate_challenge(value)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Trustcaptcha challenge is empty")
        if text.startswith("@"):
            return parse_trustcaptcha_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        return parse_trustcaptcha_challenge(json.loads(text))
    if not isinstance(value, dict):
        raise ValueError("Trustcaptcha challenge must be a JSON object")
    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    verification_id = data.get("verificationId") or data.get("verification_id") or data.get("id")
    if not verification_id:
        raise ValueError("Trustcaptcha challenge requires verificationId")
    difficulty = int(data.get("difficulty", 0))
    tasks_raw = data.get("tasks")
    if not isinstance(tasks_raw, list) or not tasks_raw:
        raise ValueError("Trustcaptcha challenge requires non-empty tasks")
    item = TrustcaptchaChallenge(
        verification_id=str(verification_id),
        difficulty=difficulty,
        tasks=[_parse_task(task) for task in tasks_raw],
    )
    _validate_challenge(item)
    return item


def solve_trustcaptcha_task(
    task: TrustcaptchaTask | dict[str, Any],
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS_PER_TASK,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> TrustcaptchaTaskSolution | None:
    parsed = _parse_task(task)
    deadline = time.time() + float(timeout_sec) if timeout_sec else None
    nonce, digest, checked = _solve_trustcaptcha_task_range(
        parsed.number,
        parsed.input,
        int(difficulty),
        max(0, int(start)),
        max(0, int(start)) + max(1, int(max_attempts)),
        deadline,
    )
    if nonce is None or digest is None:
        return None
    return TrustcaptchaTaskSolution(
        number=parsed.number,
        nonce=nonce,
        hash_hex=digest,
        attempts=checked,
    )


def solve_trustcaptcha_challenge(
    challenge: TrustcaptchaChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts_per_task: int = DEFAULT_MAX_ATTEMPTS_PER_TASK,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> TrustcaptchaSolution | None:
    item = parse_trustcaptcha_challenge(challenge)
    started = time.monotonic()
    workers = max(1, int(workers or 1))
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts_per_task))
    deadline = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or len(item.tasks) <= 1:
        out: list[TrustcaptchaTaskSolution] = []
        for task in item.tasks:
            remaining = None if deadline is None else max(0.0, deadline - time.time())
            solved = solve_trustcaptcha_task(
                task,
                item.difficulty,
                start=start,
                max_attempts=max_attempts,
                timeout_sec=remaining,
            )
            if solved is None:
                return None
            out.append(solved)
        attempts = sum(x.attempts for x in out)
        return TrustcaptchaSolution(
            challenge=item,
            tasks=out,
            solve_time_ms=int((time.monotonic() - started) * 1000),
            attempts=attempts,
        )

    max_workers = min(workers, len(item.tasks))
    pool = ProcessPoolExecutor(max_workers=max_workers)
    futures = {
        pool.submit(
            _solve_trustcaptcha_task_range,
            task.number,
            task.input,
            item.difficulty,
            start,
            start + max_attempts,
            deadline,
        ): task.number
        for task in item.tasks
    }
    solved_by_number: dict[int, TrustcaptchaTaskSolution] = {}
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            number = futures[fut]
            nonce, digest, checked = fut.result()
            if nonce is None or digest is None:
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            solved_by_number[number] = TrustcaptchaTaskSolution(
                number=number,
                nonce=nonce,
                hash_hex=digest,
                attempts=checked,
            )
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    ordered = [solved_by_number[task.number] for task in item.tasks]
    return TrustcaptchaSolution(
        challenge=item,
        tasks=ordered,
        solve_time_ms=int((time.monotonic() - started) * 1000),
        attempts=sum(x.attempts for x in ordered),
    )


def verify_trustcaptcha_solution(
    challenge: TrustcaptchaChallenge | dict[str, Any] | str,
    solution: TrustcaptchaSolution | dict[str, Any],
) -> bool:
    try:
        item = parse_trustcaptcha_challenge(challenge)
        if isinstance(solution, TrustcaptchaSolution):
            by_number = {task.number: task for task in solution.tasks}
        else:
            tasks = solution.get("tasks") or solution.get("submitTasks") or []
            by_number = {int(task.get("number")): task for task in tasks if isinstance(task, dict)}
        if set(by_number) != {task.number for task in item.tasks}:
            return False
        return all(verify_trustcaptcha_task_solution(task, by_number[task.number], item.difficulty) for task in item.tasks)
    except Exception:
        return False


def build_trustcaptcha_submit_body(
    challenge: TrustcaptchaChallenge | dict[str, Any] | str,
    solution: TrustcaptchaSolution | dict[str, Any],
    *,
    start_solving_timestamp: str | None = None,
    solved_timestamp: str | None = None,
    min_solve_ms: int = DEFAULT_MIN_SOLVE_MS,
    honeypot_fields: list[dict[str, Any]] | None = None,
    user_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parse_trustcaptcha_challenge(challenge)
    if isinstance(solution, TrustcaptchaSolution):
        submit_tasks = solution.submit_tasks
        solve_ms = solution.solve_time_ms
    else:
        submit_tasks = [
            {"number": int(task["number"]), "nonce": str(task["nonce"])}
            for task in solution.get("tasks", solution.get("submitTasks", []))
        ]
        solve_ms = int(solution.get("solveTimeMs", 0) or 0)
    reported_ms = max(int(solve_ms), int(min_solve_ms))
    now = datetime.now(timezone.utc)
    start_ts = start_solving_timestamp or _iso_z(now - timedelta(milliseconds=reported_ms))
    solved_ts = solved_timestamp or _iso_z(now)
    return {
        "startSolvingTimestamp": start_ts,
        "solvedTimestamp": solved_ts,
        "tasks": submit_tasks,
        "honeypotFields": honeypot_fields if honeypot_fields is not None else generate_trustcaptcha_honeypot_fields(),
        "userEvents": user_events if user_events is not None else generate_trustcaptcha_user_events(),
    }


def generate_trustcaptcha_honeypot_fields() -> list[dict[str, Any]]:
    return [
        {
            "index": index,
            "value": "",
            "firstInteractionMsRelativeToBoxCreation": None,
            "firstInteractionEvent": None,
        }
        for index in range(3)
    ]


def generate_trustcaptcha_user_events(*, seed_ms: int = 180) -> list[dict[str, Any]]:
    return [
        {
            "isTrusted": True,
            "timeStamp": seed_ms + 0.12,
            "type": "mousemove",
            "altKey": False,
            "ctrlKey": False,
            "metaKey": False,
            "shiftKey": False,
            "button": 0,
            "buttons": 0,
            "detail": 0,
            "defaultPrevented": False,
            "movementX": 3,
            "movementY": 1,
            "offsetX": 132,
            "offsetY": 24,
            "pageX": 428,
            "pageY": 512,
            "screenX": 902,
            "screenY": 612,
            "x": 428,
            "y": 512,
        },
        {
            "isTrusted": True,
            "timeStamp": seed_ms + 96.4,
            "type": "mousedown",
            "altKey": False,
            "ctrlKey": False,
            "metaKey": False,
            "shiftKey": False,
            "button": 0,
            "buttons": 1,
            "detail": 1,
            "defaultPrevented": False,
            "movementX": 0,
            "movementY": 0,
            "offsetX": 147,
            "offsetY": 28,
            "pageX": 443,
            "pageY": 516,
            "screenX": 917,
            "screenY": 616,
            "x": 443,
            "y": 516,
        },
        {
            "isTrusted": True,
            "timeStamp": seed_ms + 176.9,
            "type": "mouseup",
            "altKey": False,
            "ctrlKey": False,
            "metaKey": False,
            "shiftKey": False,
            "button": 0,
            "buttons": 0,
            "detail": 1,
            "defaultPrevented": False,
            "movementX": 0,
            "movementY": 0,
            "offsetX": 147,
            "offsetY": 28,
            "pageX": 443,
            "pageY": 516,
            "screenX": 917,
            "screenY": 616,
            "x": 443,
            "y": 516,
        },
        {
            "isTrusted": True,
            "timeStamp": seed_ms + 178.2,
            "type": "click",
            "altKey": False,
            "ctrlKey": False,
            "metaKey": False,
            "shiftKey": False,
            "button": 0,
            "buttons": 0,
            "detail": 1,
            "defaultPrevented": False,
            "movementX": 0,
            "movementY": 0,
            "offsetX": 147,
            "offsetY": 28,
            "pageX": 443,
            "pageY": 516,
            "screenX": 917,
            "screenY": 616,
            "x": 443,
            "y": 516,
        },
    ]


def generate_trustcaptcha_browser_information(
    *,
    target_url: str = "https://example.com/",
    user_agent: str = DEFAULT_USER_AGENT,
    minimal_data_mode: bool = False,
    language: str = "en-US",
    platform: str = "Win32",
    hardware_concurrency: int = 8,
    device_memory: int = 8,
    width: int = 1440,
    height: int = 900,
) -> dict[str, Any]:
    origin = _origin_for(target_url)
    common = {
        "window-devicePixelRatio": 1,
        "window-navigator-connection-downlink": 10,
        "window-navigator-connection-rtt": 50,
        "window-location-href": target_url,
        "window-navigator-deviceMemory": device_memory,
        "window-navigator-hardwareConcurrency": hardware_concurrency,
        "window-navigator-language": language,
        "window-navigator-languages": [language, language.split("-")[0]],
        "window-navigator-userAgent": user_agent,
        "window-origin": origin,
    }
    if not minimal_data_mode:
        common.update(
            {
                "window-history-length": 2,
                "window-innerHeight": height,
                "window-innerWidth": width,
                "window-locationbar-visible": True,
                "window-menubar-visible": True,
                "window-navigator-cookieEnabled": True,
                "window-navigator-maxTouchPoints": 0,
                "window-navigator-pdfViewerEnabled": True,
                "window-navigator-platform": platform,
                "window-navigator-webdriver": False,
                "window-outerHeight": height + 85,
                "window-outerWidth": width,
                "window-personalbar-visible": True,
                "window-screen-availHeight": height - 40,
                "window-screen-availWidth": width,
                "window-screen-colorDepth": 24,
                "window-screen-height": height,
                "window-screen-orientation-angle": 0,
                "window-screen-orientation-type": "landscape-primary",
                "window-screen-pixelDepth": 24,
                "window-screen-width": width,
                "window-scrollbars-visible": True,
            }
        )
    common.update(
        {
            "dom-automationNote": False,
            "dom-webGlSupport": True,
            "dom-canvasSupport": True,
            "plugins": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            "intl-locale": language,
            "embedding-isInIframe": False,
            "embedding-ancestorOriginCount": 0,
            "document-visibilityState": "visible",
        }
    )
    if not minimal_data_mode:
        common.update(
            {
                "window-navigator-userAgentData-brands": "Chromium;124|Google Chrome;124|Not-A.Brand;99",
                "window-navigator-userAgentData-mobile": False,
                "window-navigator-userAgentData-platform": "Windows",
                "media-prefersColorScheme": "light",
                "media-prefersReducedMotion": False,
                "media-prefersContrast": "no-preference",
                "media-forcedColors": "none",
            }
        )
    return common


def generate_trustcaptcha_fingerprints(*, profile_seed: str = "windows-chrome") -> dict[str, str]:
    material = {
        "audio": "audio:triangle:10000:compressor:win-chrome",
        "canvas": "canvas:TrustCaptcha — fingerprint 0123456789:Cwm fjordbank glyphs",
        "webgl": "webgl:Google Inc.:ANGLE NVIDIA Direct3D11:MAX_TEXTURE_SIZE=16384",
        "navigator": "true|null|true|Win32|Google Inc.",
        "fonts": "Arial,Verdana,Times New Roman,Courier New,Georgia,Tahoma,Segoe UI,Consolas",
        "screen": "1440x900x24x24xlandscape-primary",
    }
    return {k: _sha256_hex(f"{profile_seed}:{v}") for k, v in material.items()}


def calculate_trustcaptcha_integrity_hash(browser_information: dict[str, Any]) -> str:
    serialized = ", ".join(
        f"{key}={_js_stringify_value(browser_information[key])}" for key in sorted(browser_information)
    )
    return _sha256_hex(serialized)


def build_trustcaptcha_create_body(
    *,
    site_key: str,
    target_url: str = "https://example.com/",
    user_agent: str = DEFAULT_USER_AGENT,
    minimal_data_mode: bool = False,
    bypass_token: str | None = None,
    framework: str | None = "other",
    language: str = "en-US",
    theme: str = "light",
    current_theme: str = "light",
    invisible: bool = False,
    full_width: bool = False,
    white_label: bool = False,
    autostart_disabled: bool = False,
    library_version: str = DEFAULT_LIBRARY_VERSION,
    box_creation_timestamp: str | None = None,
    start_solving_timestamp: str | None = None,
    honeypot_fields: list[dict[str, Any]] | None = None,
    user_events: list[dict[str, Any]] | None = None,
    browser_information: dict[str, Any] | None = None,
    fingerprints: dict[str, str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    box_ts = box_creation_timestamp or _iso_z(now - timedelta(milliseconds=500))
    start_ts = start_solving_timestamp or _iso_z(now)
    browser_info = browser_information or generate_trustcaptcha_browser_information(
        target_url=target_url,
        user_agent=user_agent,
        minimal_data_mode=minimal_data_mode,
        language=language,
    )
    fp = fingerprints or generate_trustcaptcha_fingerprints()
    return {
        "siteKey": site_key,
        "widget": {
            "boxCreationTimestamp": box_ts,
            "startSolvingTimestamp": start_ts,
            "timezone": "America/New_York",
            "minimalDataMode": minimal_data_mode,
            "bypassToken": bypass_token,
            "settings": {
                "language": language,
                "currentLanguage": language,
                "theme": theme,
                "currentTheme": current_theme,
                "autostartDisabled": autostart_disabled,
                "whiteLabel": white_label,
                "privacyUrlSet": False,
                "invisible": invisible,
                "fullWidth": full_width,
            },
        },
        "metadata": {"framework": framework, "libraryVersion": library_version},
        "browserInformation": browser_info,
        "fingerprints": fp,
        "honeypotFields": honeypot_fields if honeypot_fields is not None else generate_trustcaptcha_honeypot_fields(),
        "userEvents": user_events if user_events is not None else generate_trustcaptcha_user_events(),
        "integrityHash": calculate_trustcaptcha_integrity_hash(browser_info),
    }


class TrustcaptchaSolver:
    """TrustCaptcha v3 fingerprint + multi-task SHA-256 PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        site_key: str | None = None,
        api_url: str = DEFAULT_API_URL,
        target_url: str = "https://example.com/",
        create_url: str | None = None,
        submit_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        create_body_json: Any = None,
        create_body_file: str | None = None,
        submit: bool | None = None,
        max_rounds: int = 3,
        start: int = 0,
        max_attempts_per_task: int = DEFAULT_MAX_ATTEMPTS_PER_TASK,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        min_solve_ms: int = DEFAULT_MIN_SOLVE_MS,
        minimal_data_mode: bool = False,
        bypass_token: str | None = None,
        framework: str | None = "other",
        language: str = "en-US",
        theme: str = "light",
        user_agent: str | None = None,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(), "rounds": []}
        diagnostics: dict[str, Any] = {
            "api_url": api_url,
            "create_url": create_url,
            "submit_url": submit_url,
            "site_key": site_key,
            "target_url": target_url,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_task": max_attempts_per_task,
            "minimal_data_mode": minimal_data_mode,
            "library_version": DEFAULT_LIBRARY_VERSION,
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
                out = output_root / "trustcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="trustcaptcha",
                ok=ok,
                captcha_type="fingerprint_multi_pow",
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
            effective_submit = bool(submit) if submit is not None else challenge_json is None and challenge_file is None
            request_headers = _merge_headers(headers, user_agent)
            source = _load_json_arg(challenge_json, challenge_file)
            if source is not None:
                raw["challengeSource"] = "json"
                challenge = parse_trustcaptcha_challenge(source)
                final_token: str | None = None
            else:
                if not site_key and create_body_json is None and create_body_file is None:
                    raise ValueError("Trustcaptcha requires challenge_json/challenge_file or site_key")
                effective_create_url = create_url or urljoin(api_url.rstrip("/") + "/", "v2/verifications")
                create_body = _load_json_arg(create_body_json, create_body_file)
                if create_body is None:
                    create_body = build_trustcaptcha_create_body(
                        site_key=str(site_key),
                        target_url=target_url,
                        user_agent=user_agent or DEFAULT_USER_AGENT,
                        minimal_data_mode=minimal_data_mode,
                        bypass_token=bypass_token,
                        framework=framework,
                        language=language,
                        theme=theme,
                    )
                raw["createBody"] = create_body
                create_resp = self._post_json(
                    effective_create_url,
                    create_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                )
                raw["createResponse"] = create_resp
                diagnostics["create_status"] = create_resp["status"]
                if create_resp["status"] == 201:
                    final_token = _extract_finished_token(create_resp["json"])
                    if final_token:
                        return finish(ok=True, ticket=final_token, verify_code="finished")
                    errors.append("Trustcaptcha create returned 201 without finished.verificationToken")
                    return finish(ok=False, verify_code="create_failed")
                if create_resp["status"] != 200:
                    errors.append(_trustcaptcha_status_reason(create_resp["status"]))
                    return finish(ok=False, verify_code="create_failed")
                challenge = parse_trustcaptcha_challenge(create_resp["json"])
                final_token = None

            for round_index in range(1, max(1, int(max_rounds)) + 1):
                diagnostics.update(
                    {
                        "verification_id": challenge.verification_id,
                        "difficulty": challenge.difficulty,
                        "tasks": len(challenge.tasks),
                    }
                )
                solution = solve_trustcaptcha_challenge(
                    challenge,
                    start=start,
                    max_attempts_per_task=max_attempts_per_task,
                    workers=workers,
                    timeout_sec=timeout_sec,
                )
                if solution is None:
                    errors.append("Trustcaptcha solve failed: timeout or max_attempts_per_task exhausted")
                    return finish(ok=False, verify_code="pow_failed")
                if not verify_trustcaptcha_solution(challenge, solution):
                    errors.append("Trustcaptcha internal PoW verification failed")
                    return finish(ok=False, verify_code="pow_invalid")
                submit_body = build_trustcaptcha_submit_body(
                    challenge,
                    solution,
                    min_solve_ms=min_solve_ms,
                )
                raw["rounds"].append(
                    {
                        "round": round_index,
                        "challenge": challenge.to_payload(),
                        "solution": solution.to_payload(),
                        "submitBody": submit_body,
                    }
                )
                diagnostics.update(
                    {
                        "attempts": solution.attempts,
                        "solve_ms": solution.solve_time_ms,
                        "reported_solve_ms": max(solution.solve_time_ms, min_solve_ms),
                        "nonces": [task.nonce for task in solution.tasks],
                    }
                )
                ticket = _json_body(submit_body)
                if not effective_submit and not submit_url:
                    return finish(ok=True, ticket=ticket, verify_code="solved")

                effective_submit_url = submit_url or urljoin(
                    api_url.rstrip("/") + "/",
                    f"v2/verifications/{challenge.verification_id}/challenges",
                )
                submit_resp = self._post_json(
                    effective_submit_url,
                    submit_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                )
                raw["rounds"][-1]["submitResponse"] = submit_resp
                diagnostics["submit_status"] = submit_resp["status"]
                if submit_resp["status"] == 201:
                    final_token = _extract_finished_token(submit_resp["json"])
                    if not final_token:
                        errors.append("Trustcaptcha submit returned 201 without finished.verificationToken")
                        return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                    return finish(ok=True, ticket=final_token, verify_code="validated")
                if submit_resp["status"] == 200:
                    challenge = parse_trustcaptcha_challenge(submit_resp["json"])
                    continue
                errors.append(_trustcaptcha_status_reason(submit_resp["status"]))
                return finish(ok=False, ticket=ticket, verify_code="submit_failed")

            if final_token:
                return finish(ok=True, ticket=final_token, verify_code="validated")
            errors.append("Trustcaptcha max_rounds exhausted")
            return finish(ok=False, verify_code="max_rounds_exhausted")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _post_json(
        self,
        url: str,
        body: dict[str, Any],
        *,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        resp = requests.post(
            url,
            data=_json_body(body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        return {"status": resp.status_code, "url": url, "json": payload}


def _solve_trustcaptcha_task_range(
    number: int,
    input_b64: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[str | None, str | None, int]:
    prefix = trustcaptcha_input_bytes(input_b64)
    checked = 0
    for counter in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        nonce = f"tcn{counter}"
        digest = hashlib.sha256(prefix + nonce.encode("ascii")).digest()
        checked += 1
        if count_leading_zero_bits(digest) >= int(difficulty):
            return nonce, digest.hex(), checked
    return None, None, checked


def _parse_task(value: TrustcaptchaTask | dict[str, Any]) -> TrustcaptchaTask:
    if isinstance(value, TrustcaptchaTask):
        return value
    if not isinstance(value, dict):
        raise ValueError("Trustcaptcha task must be an object")
    number = int(value.get("number", value.get("id", 0)))
    input_b64 = str(value.get("input") or value.get("inputBase64") or "")
    if not input_b64:
        raise ValueError("Trustcaptcha task requires input")
    trustcaptcha_input_bytes(input_b64)
    return TrustcaptchaTask(number=number, input=input_b64)


def _validate_challenge(item: TrustcaptchaChallenge) -> None:
    if not item.verification_id:
        raise ValueError("Trustcaptcha verificationId is empty")
    if item.difficulty < 0 or item.difficulty > 256:
        raise ValueError("Trustcaptcha difficulty must be between 0 and 256")
    if not item.tasks:
        raise ValueError("Trustcaptcha tasks are empty")


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


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _extract_finished_token(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None
    finished = data.get("finished") if isinstance(data.get("finished"), dict) else data
    for key in ("verificationToken", "verification_token", "token"):
        if finished.get(key):
            return str(finished[key])
    return None


def _trustcaptcha_status_reason(status: int) -> str:
    return {
        402: "payment_required",
        403: "captcha_not_accessible",
        404: "captcha_not_found",
        409: "pow_failure",
        422: "minimal_data_mode_mismatch",
        423: "locked",
    }.get(int(status), f"http_{status}")


def _origin_for(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return "https://example.com"
    return f"{parsed.scheme}://{parsed.netloc}"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _js_stringify_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_js_array_value(v) for v in value) + "]"
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return str(int(value))
        return str(value)
    return str(value)


def _js_array_value(value: Any) -> str:
    if value is None:
        return ""
    return _js_stringify_value(value)


def _iso_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
