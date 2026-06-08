from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import math
import re
import struct
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
DEFAULT_VERIFY_PATH = "/.tollbooth/verify"


@dataclass(slots=True)
class TollboothChallenge:
    id: str
    difficulty: int
    challenge_type: str = "sha256-balloon"
    data: str | None = None
    space_cost: int = 1024
    time_cost: int = 1
    delta: int = 3
    verify_path: str = DEFAULT_VERIFY_PATH
    redirect: str = "/"
    csrf_token: str | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "difficulty": self.difficulty,
            "type": self.challenge_type,
            "verifyPath": self.verify_path,
            "redirect": self.redirect,
        }
        if self.data is not None:
            out["data"] = self.data
        if self.challenge_type == "sha256-balloon":
            out.update({"spaceCost": self.space_cost, "timeCost": self.time_cost, "delta": self.delta})
        if self.csrf_token:
            out["csrfToken"] = self.csrf_token
        return out


@dataclass(slots=True)
class TollboothSolution:
    challenge: TollboothChallenge
    nonce: int | str
    digest_hex: str | None
    leading_zero_bits: int | None
    attempts: int
    took_ms: int

    @property
    def submit_form(self) -> dict[str, str]:
        form = {
            "id": self.challenge.id,
            "nonce": str(self.nonce),
            "redirect": self.challenge.redirect or "/",
        }
        if self.challenge.csrf_token:
            form["csrf_token"] = self.challenge.csrf_token
        return form

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.challenge.id,
            "nonce": self.nonce,
            "attempts": self.attempts,
            "tookMs": self.took_ms,
            "submitForm": self.submit_form,
        }
        if self.digest_hex is not None:
            out["hash"] = self.digest_hex
        if self.leading_zero_bits is not None:
            out["leadingZeroBits"] = self.leading_zero_bits
        return out


def count_leading_zero_bits(data: bytes) -> int:
    for i, byte in enumerate(data):
        if byte:
            return i * 8 + (8 - byte.bit_length())
    return len(data) * 8


def tollbooth_sha256_hash_bytes(data: str, nonce: int | str) -> bytes:
    return hashlib.sha256((str(data) + str(int(nonce))).encode("utf-8")).digest()


def tollbooth_sha256_hash_hex(data: str, nonce: int | str) -> str:
    return tollbooth_sha256_hash_bytes(data, nonce).hex()


def tollbooth_balloon_hash_bytes(
    data: str,
    nonce: int | str,
    *,
    space_cost: int = 1024,
    time_cost: int = 1,
    delta: int = 3,
) -> bytes:
    prefix = str(data)
    nonce_int = int(nonce)
    space_cost = max(1, int(space_cost))
    time_cost = max(0, int(time_cost))
    delta = max(0, int(delta))
    raw = (prefix + str(nonce_int)).encode("utf-8")
    buf = bytearray(space_cost * 32)
    counter = 0

    def sha(ctr: int, *parts: bytes) -> bytes:
        return hashlib.sha256(struct.pack("<I", ctr) + b"".join(parts)).digest()

    def get(i: int) -> bytes:
        return bytes(buf[i * 32 : (i + 1) * 32])

    def put(i: int, val: bytes) -> None:
        buf[i * 32 : (i + 1) * 32] = val

    put(0, sha(counter, raw))
    counter += 1

    for i in range(1, space_cost):
        put(i, sha(counter, get(i - 1)))
        counter += 1

    for t in range(time_cost):
        for i in range(space_cost):
            prev = (i - 1) % space_cost
            put(i, sha(counter, get(prev), get(i)))
            counter += 1
            for j in range(delta):
                param = struct.pack("<IIII", counter, t, i, j)
                counter += 1
                other = int.from_bytes(hashlib.sha256(param).digest()[:4], "big") % space_cost
                put(i, sha(counter, get(i), get(other)))
                counter += 1

    return get(space_cost - 1)


def tollbooth_balloon_hash_hex(
    data: str,
    nonce: int | str,
    *,
    space_cost: int = 1024,
    time_cost: int = 1,
    delta: int = 3,
) -> str:
    return tollbooth_balloon_hash_bytes(
        data,
        nonce,
        space_cost=space_cost,
        time_cost=time_cost,
        delta=delta,
    ).hex()


def generate_tollbooth_navigator_signals(checks: list[str] | None = None, *, strategy: str = "empty") -> dict[str, Any]:
    """Return a synthetic attestation payload for Tollbooth's HTTP-poll rounds.

    Tollbooth 0.3.9.x scores only present categories; omitted categories are not
    penalized. The default intentionally sends a sparse payload because it is the
    most stable cross-platform protocol strategy and avoids headless/browser work.
    """

    if strategy == "empty":
        return {}
    selected = set(checks or [])
    out: dict[str, Any] = {}
    if "navigator" in selected:
        out["navigator"] = {
            "ua": DEFAULT_USER_AGENT,
            "platform": "Win32",
            "languageCount": 2,
            "languages": ["en-US", "en"],
            "hardwareConcurrency": 8,
            "deviceMemory": 8,
            "productSub": "20030107",
            "vendor": "Google Inc.",
            "maxTouchPoints": 0,
            "pdfViewerEnabled": True,
        }
    if "browser" in selected:
        out["browser"] = {"apis": 1 | 2 | 4, "selenium": 0, "stealth": 0, "advanced": 0}
    if "automation" in selected:
        out["automation"] = {"globals": 0, "enhanced": 0, "extra": 0}
    if "features" in selected:
        out["features"] = 0x7FF
    if "natives" in selected:
        out["natives"] = 0xFFF
    if "screen" in selected:
        out["screen"] = {"width": 1920, "height": 1080, "colorDepth": 24, "devicePixelRatio": 1}
    if "engine" in selected:
        out["engine"] = {"evalLength": 33, "stackStyle": "v8", "mathTan": -1.4214488238747245, "bindNative": 1}
    if "mediaQueries" in selected:
        out["mediaQueries"] = {"pointerFine": True, "touch": False, "hover": True}
    if "environment" in selected:
        out["environment"] = {"timezoneOffset": 300, "timezoneName": "America/New_York", "touch": 0, "document": 6}
    if "timing" in selected:
        out["timing"] = {"perfNowIdentical": False}
    out["meta"] = {"collectedAt": int(time.time() * 1000), "elapsed": 1}
    return out


def parse_tollbooth_challenge(value: TollboothChallenge | dict[str, Any] | str) -> TollboothChallenge:
    if isinstance(value, TollboothChallenge):
        _validate_challenge(value)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Tollbooth challenge is empty")
        if text.startswith("@"):
            return parse_tollbooth_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            return parse_tollbooth_challenge(json.loads(text))
        if "JSON.parse(" in text or "CHALLENGE_DATA" in text:
            return parse_tollbooth_challenge(_extract_challenge_from_html(text))
        raise ValueError("Tollbooth inline challenge must be JSON, HTML or @file")
    if not isinstance(value, dict):
        raise ValueError("Tollbooth challenge must be an object")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge_id = data.get("id") or data.get("challengeId") or data.get("cid")
    if not challenge_id:
        raise ValueError("Tollbooth challenge requires id")
    challenge_type = str(data.get("type") or data.get("challengeType") or "")
    random_data = data.get("data") or data.get("randomData")
    has_balloon = any(k in data for k in ("spaceCost", "space_cost", "timeCost", "time_cost", "delta"))
    if not challenge_type:
        if random_data is None:
            challenge_type = "navigator-attestation"
        else:
            challenge_type = "sha256-balloon" if has_balloon else "sha256"
    challenge_type = challenge_type.replace("_", "-")
    difficulty = int(data.get("difficulty", 0))
    item = TollboothChallenge(
        id=str(challenge_id),
        difficulty=difficulty,
        challenge_type=challenge_type,
        data=str(random_data) if random_data is not None else None,
        space_cost=int(data.get("spaceCost", data.get("space_cost", 1024))),
        time_cost=int(data.get("timeCost", data.get("time_cost", 1))),
        delta=int(data.get("delta", 3)),
        verify_path=str(data.get("verifyPath", data.get("verify_path", DEFAULT_VERIFY_PATH))),
        redirect=str(data.get("redirect", "/")),
        csrf_token=str(data["csrfToken"]) if data.get("csrfToken") is not None else None,
    )
    _validate_challenge(item)
    return item


def solve_tollbooth_challenge(
    challenge: TollboothChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> TollboothSolution | None:
    item = parse_tollbooth_challenge(challenge)
    if item.challenge_type == "navigator-attestation":
        raise ValueError("navigator-attestation requires HTTP poll flow, not local PoW search")
    if item.data is None:
        raise ValueError("Tollbooth PoW challenge requires data")
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_tollbooth_range(item, start, start + max_attempts, deadline_epoch)
        if nonce is None or digest is None:
            return None
        return TollboothSolution(
            challenge=item,
            nonce=nonce,
            digest_hex=digest.hex(),
            leading_zero_bits=count_leading_zero_bits(digest),
            attempts=checked,
            took_ms=int((time.monotonic() - started) * 1000),
        )

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_tollbooth_range, item, lo, hi, deadline_epoch)] = idx

    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return TollboothSolution(
                    challenge=item,
                    nonce=nonce,
                    digest_hex=digest.hex(),
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


def verify_tollbooth_solution(
    challenge: TollboothChallenge | dict[str, Any] | str,
    solution: TollboothSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_tollbooth_challenge(challenge)
        if item.challenge_type == "navigator-attestation":
            return bool(_solution_nonce(solution))
        if item.data is None:
            return False
        nonce = int(_solution_nonce(solution))
        digest = _tollbooth_digest(item, nonce)
        return count_leading_zero_bits(digest) >= item.difficulty
    except Exception:
        return False


def _solution_nonce(solution: TollboothSolution | dict[str, Any] | int | str) -> int | str:
    if isinstance(solution, TollboothSolution):
        return solution.nonce
    if isinstance(solution, dict):
        return solution.get("nonce", solution.get("token", solution.get("solution", "")))
    return solution


def _solve_tollbooth_range(
    item: TollboothChallenge,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, bytes | None, int]:
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 256 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = _tollbooth_digest(item, nonce)
        checked += 1
        if count_leading_zero_bits(digest) >= item.difficulty:
            return nonce, digest, checked
    return None, None, checked


def _tollbooth_digest(item: TollboothChallenge, nonce: int) -> bytes:
    if item.data is None:
        raise ValueError("Tollbooth PoW challenge requires data")
    if item.challenge_type == "sha256":
        return tollbooth_sha256_hash_bytes(item.data, nonce)
    if item.challenge_type == "sha256-balloon":
        return tollbooth_balloon_hash_bytes(
            item.data,
            nonce,
            space_cost=item.space_cost,
            time_cost=item.time_cost,
            delta=item.delta,
        )
    raise ValueError(f"unsupported Tollbooth challenge type: {item.challenge_type}")


def _extract_challenge_from_html(html: str) -> dict[str, Any]:
    patterns = [
        r"JSON\.parse\('(?P<data>(?:\\.|[^'])*)'\)",
        r'JSON\.parse\("(?P<data>(?:\\.|[^\"])*)"\)',
    ]
    for pat in patterns:
        m = re.search(pat, html, flags=re.S)
        if not m:
            continue
        raw = m.group("data")
        quote = '"' if pat.startswith('JSON\\.parse\\(\\"') else "'"
        decoded = ast.literal_eval(quote + raw + quote)
        return json.loads(decoded)
    raise ValueError("could not extract Tollbooth CHALLENGE_DATA from HTML")


def _validate_challenge(item: TollboothChallenge) -> None:
    if not item.id:
        raise ValueError("Tollbooth challenge requires id")
    if item.difficulty < 0 or item.difficulty > 256:
        raise ValueError("Tollbooth difficulty must be between 0 and 256")
    if item.challenge_type in {"sha256", "sha256-balloon"} and item.data is None:
        raise ValueError("Tollbooth PoW challenge requires data")
    if item.space_cost < 1 or item.space_cost > 1_000_000:
        raise ValueError("Tollbooth spaceCost is out of range")
    if item.time_cost < 0 or item.time_cost > 10_000:
        raise ValueError("Tollbooth timeCost is out of range")
    if item.delta < 0 or item.delta > 10_000:
        raise ValueError("Tollbooth delta is out of range")


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
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        out.update(headers)
    return out


def _derive_url(base_url: str | None, explicit: str | None, path: str | None) -> str | None:
    if explicit:
        return explicit
    if not base_url or not path:
        return None
    if path.startswith("/"):
        parsed = urlparse(base_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


class TollboothSolver:
    """Tollbooth SHA-256/Balloon PoW and navigator-attestation protocol solver."""

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
        navigator_strategy: str = "empty",
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
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
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "navigator_strategy": navigator_strategy,
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
                out = output_root / "tollbooth_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="tollbooth",
                ok=ok,
                captcha_type="tollbooth_protocol",
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
            request_headers = _merge_headers(headers, user_agent)
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url or base_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_tollbooth_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.id,
                    "challenge_type": item.challenge_type,
                    "difficulty": item.difficulty,
                    "space_cost": item.space_cost if item.challenge_type == "sha256-balloon" else None,
                    "time_cost": item.time_cost if item.challenge_type == "sha256-balloon" else None,
                    "delta": item.delta if item.challenge_type == "sha256-balloon" else None,
                    "csrf_present": bool(item.csrf_token),
                }
            )
            effective_verify_url = verify_url or _derive_url(challenge_url or base_url, None, item.verify_path)
            solution: TollboothSolution
            if item.challenge_type == "navigator-attestation":
                if not effective_verify_url:
                    errors.append("Tollbooth navigator-attestation requires verify_url or challenge_url/base_url")
                    return finish(ok=False)
                solution = self._solve_navigator_attestation(
                    item,
                    verify_url=effective_verify_url,
                    strategy=navigator_strategy,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
            else:
                solved = solve_tollbooth_challenge(
                    item,
                    start=start,
                    max_attempts=max_attempts,
                    workers=workers,
                    timeout_sec=timeout_sec,
                )
                if solved is None:
                    errors.append("Tollbooth solve failed: timeout or max_attempts exhausted")
                    return finish(ok=False)
                solution = solved
            raw["solution"] = solution.to_payload()
            diagnostics.update(
                {
                    "nonce_present": bool(solution.nonce or solution.nonce == 0),
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                    "leading_zero_bits": solution.leading_zero_bits,
                }
            )
            ticket = _json_body(solution.to_payload())
            verify_code = "solved"
            if submit or verify_url:
                if not effective_verify_url:
                    errors.append("submit requested but verify_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                token = ""
                if isinstance(verify_data, dict):
                    token = str(verify_data.get("token") or verify_data.get("cookie") or "")
                ok = bool(token) or (isinstance(verify_data, dict) and verify_data.get("status") in (200, 302))
                if not ok:
                    errors.append("verify_failed")
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = token or ticket
                verify_code = "validated"
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
            raise ValueError("Tollbooth requires challenge_json, challenge_file, challenge_url or base_url")
        resp = requests.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            payload: Any = resp.json()
        else:
            payload = resp.text
        raw["challengeResponse"]["json" if isinstance(payload, dict) else "text"] = payload if isinstance(payload, dict) else payload[:500]
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return payload

    def _solve_navigator_attestation(
        self,
        item: TollboothChallenge,
        *,
        verify_url: str,
        strategy: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> TollboothSolution:
        started = time.monotonic()
        poll_headers = dict(headers)
        poll_headers["Content-Type"] = "application/json"
        body: dict[str, Any] = {"id": item.id, "init": True}
        rounds: list[dict[str, Any]] = []
        attempts = 0
        while True:
            resp = requests.post(
                verify_url,
                data=_json_body(body),
                headers=poll_headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            try:
                msg = resp.json()
            except ValueError:
                msg = {"type": "error", "reason": resp.text[:200]}
            rounds.append({"status": resp.status_code, "message": msg})
            resp.raise_for_status()
            attempts += 1
            if msg.get("type") == "result":
                token = str(msg.get("token") or "")
                if not token:
                    raise ValueError("Tollbooth navigator result did not include token")
                raw["navigatorPoll"] = rounds
                return TollboothSolution(
                    challenge=item,
                    nonce=token,
                    digest_hex=None,
                    leading_zero_bits=None,
                    attempts=attempts,
                    took_ms=int((time.monotonic() - started) * 1000),
                )
            if msg.get("type") != "challenge":
                raise ValueError(f"Tollbooth navigator poll failed: {msg.get('reason') or msg.get('type')}")
            body = {
                "id": item.id,
                "nonce": msg.get("nonce"),
                "round": msg.get("round"),
                "signals": generate_tollbooth_navigator_signals(msg.get("checks") or [], strategy=strategy),
            }
            if attempts > 10:
                raise ValueError("Tollbooth navigator poll exceeded round limit")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: TollboothSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        form_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        resp = requests.post(
            verify_url,
            data=solution.submit_form,
            headers=form_headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
            allow_redirects=False,
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        cookie = resp.headers.get("Set-Cookie", "")
        try:
            data: Any = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        if cookie:
            data["cookie"] = cookie
        data["status"] = resp.status_code
        raw["verifyResponse"]["json"] = data
        if resp.status_code not in (200, 302):
            resp.raise_for_status()
        return data
