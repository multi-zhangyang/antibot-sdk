from __future__ import annotations

import asyncio
import hashlib
import html
import json
import multiprocessing as mp
import os
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import requests
from blake3 import blake3

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_COOKIE_NAME = "_2__bProxy_v"
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_CHUNK_SIZE = 50_000
DEFAULT_TIMEOUT = 10


@dataclass(frozen=True, slots=True)
class BalooProxyChallenge:
    public_salt: str
    challenge: str
    difficulty: int
    cookie_name: str = DEFAULT_COOKIE_NAME
    numeric: bool = False
    page_url: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def suffix_width(self) -> int:
        return int(self.difficulty)


@dataclass(frozen=True, slots=True)
class BalooProxySolution:
    challenge: BalooProxyChallenge
    suffix: str
    cookie_value: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None

    @property
    def cookie_header(self) -> str:
        return f"{self.challenge.cookie_name}={self.cookie_value}"

    @property
    def access_hex(self) -> str:
        return balooproxy_access_hash(self.challenge.public_salt, self.suffix)


@dataclass(frozen=True, slots=True)
class BalooProxyStage2Challenge:
    ip: str
    tls_fingerprint: str
    user_agent: str
    hour: str
    js_secret: str
    day: str
    difficulty: int
    js_otp: str
    encrypted_ip: str
    public_salt: str
    suffix: str
    challenge: str
    cookie_name: str = DEFAULT_COOKIE_NAME
    numeric: bool = False

    def as_challenge(self) -> BalooProxyChallenge:
        return BalooProxyChallenge(
            public_salt=self.public_salt,
            challenge=self.challenge,
            difficulty=self.difficulty,
            cookie_name=self.cookie_name,
            numeric=self.numeric,
            raw={
                "ip": self.ip,
                "tlsFingerprint": self.tls_fingerprint,
                "userAgent": self.user_agent,
                "hour": self.hour,
                "day": self.day,
                "jsOtp": self.js_otp,
                "encryptedIp": self.encrypted_ip,
            },
        )


def balooproxy_js_otp(js_secret: str, day: date | str | None = None) -> str:
    day_text = _day_text(day)
    return hashlib.sha256(f"{js_secret}{day_text}".encode("utf-8")).hexdigest()


def balooproxy_cookie_otp(cookie_secret: str, day: date | str | None = None) -> str:
    day_text = _day_text(day)
    return hashlib.sha256(f"{cookie_secret}{day_text}".encode("utf-8")).hexdigest()


def balooproxy_access_key(ip: str, tls_fingerprint: str, user_agent: str, hour: int | str) -> str:
    return f"{ip}{tls_fingerprint}{user_agent}{hour}"


def balooproxy_access_hash(public_salt: str, suffix: str) -> str:
    public_salt = _validate_hex_text(public_salt, "public_salt")
    suffix = _validate_suffix(suffix)
    return hashlib.sha256(f"{suffix}{public_salt}".encode("utf-8")).hexdigest()


def derive_balooproxy_stage2_challenge(
    *,
    ip: str,
    tls_fingerprint: str,
    user_agent: str,
    hour: int | str,
    js_secret: str,
    difficulty: int,
    day: date | str | None = None,
    cookie_name: str = DEFAULT_COOKIE_NAME,
    numeric: bool = False,
) -> BalooProxyStage2Challenge:
    difficulty = _validate_difficulty(difficulty)
    day_text = _day_text(day)
    js_otp = balooproxy_js_otp(js_secret, day_text)
    access_key = balooproxy_access_key(ip, tls_fingerprint, user_agent, hour)
    encrypted_ip = blake3(f"{access_key}{js_otp}".encode("utf-8")).hexdigest()
    public_salt = encrypted_ip[:-difficulty] if difficulty else encrypted_ip
    suffix = encrypted_ip[-difficulty:] if difficulty else ""
    challenge_hash = hashlib.sha256(encrypted_ip.encode("utf-8")).hexdigest()
    return BalooProxyStage2Challenge(
        ip=ip,
        tls_fingerprint=tls_fingerprint,
        user_agent=user_agent,
        hour=str(hour),
        js_secret=js_secret,
        day=day_text,
        difficulty=difficulty,
        js_otp=js_otp,
        encrypted_ip=encrypted_ip,
        public_salt=public_salt,
        suffix=suffix,
        challenge=challenge_hash,
        cookie_name=_validate_cookie_name(cookie_name),
        numeric=bool(numeric),
    )


def derive_balooproxy_pow(
    *,
    ip: str,
    tls_fingerprint: str,
    user_agent: str,
    hour: int | str,
    js_secret: str,
    difficulty: int,
    day: date | str | None = None,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> tuple[BalooProxyChallenge, BalooProxySolution]:
    derived = derive_balooproxy_stage2_challenge(
        ip=ip,
        tls_fingerprint=tls_fingerprint,
        user_agent=user_agent,
        hour=hour,
        js_secret=js_secret,
        difficulty=difficulty,
        day=day,
        cookie_name=cookie_name,
    )
    challenge = derived.as_challenge()
    solution = BalooProxySolution(
        challenge=challenge,
        suffix=derived.suffix,
        cookie_value=derived.encrypted_ip,
        digest_hex=derived.challenge,
        elapsed_ms=0,
        attempts_hint=1,
    )
    return challenge, solution


def balooproxy_digest(public_salt: str, suffix: str) -> str:
    material = f"{_validate_hex_text(public_salt, 'public_salt')}{_validate_suffix(suffix)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def hex_suffix_by_index(index: int, difficulty: int) -> str:
    idx = int(index)
    width = _validate_difficulty(difficulty)
    if idx < 0:
        raise ValueError("suffix index must be non-negative")
    if width and idx >= 16**width:
        raise ValueError("suffix index exceeds hex search space")
    if not width and idx != 0:
        raise ValueError("suffix index exceeds zero-width search space")
    return f"{idx:0{width}x}" if width else ""


def validate_balooproxy_suffix(suffix: str, difficulty: int, *, numeric: bool = False) -> bool:
    try:
        text = str(suffix).strip().lower()
        width = _validate_difficulty(difficulty)
        if len(text) != width:
            return False
        pattern = r"[0-9]*" if numeric else r"[0-9a-f]*"
        return bool(re.fullmatch(pattern, text))
    except Exception:
        return False


def verify_balooproxy_suffix(public_salt: str, suffix: str, challenge: str) -> bool:
    try:
        return balooproxy_digest(public_salt, suffix) == _validate_digest(challenge)
    except Exception:
        return False


def verify_balooproxy_solution(
    challenge: BalooProxyChallenge | dict[str, Any] | str,
    solution: BalooProxySolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_balooproxy_challenge(challenge)
        if isinstance(solution, BalooProxySolution):
            suffix = solution.suffix
            cookie = solution.cookie_value
        elif isinstance(solution, dict):
            cookie = _extract_cookie_value(
                str(
                    solution.get("cookie_value")
                    or solution.get("cookieValue")
                    or solution.get(item.cookie_name)
                    or solution.get("cookie")
                    or solution.get("ticket")
                    or ""
                ),
                item.cookie_name,
            )
            suffix = str(
                solution.get("suffix")
                or (cookie[len(item.public_salt) :] if cookie.startswith(item.public_salt) else "")
            )
        else:
            cookie = _extract_cookie_value(str(solution), item.cookie_name)
            suffix = cookie[len(item.public_salt) :] if cookie.startswith(item.public_salt) else cookie
        if item.public_salt + suffix != cookie and cookie:
            return False
        return bool(cookie) and verify_balooproxy_suffix(item.public_salt, suffix, item.challenge)
    except Exception:
        return False


def solve_balooproxy_suffix(
    public_salt: str,
    challenge: str,
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[str, str, str, int]:
    public_salt = _validate_hex_text(public_salt, "public_salt")
    target = _validate_digest(challenge)
    width = _validate_difficulty(difficulty)
    start, max_attempts = _validate_search(start, max_attempts)
    max_space = 16**width if width else 1
    if start >= max_space:
        raise ValueError("start exceeds suffix search space")
    max_attempts = min(max_attempts, max_space - start)
    if workers <= 1:
        suffix, digest, attempts = _search_balooproxy_range(
            public_salt,
            target,
            width,
            start,
            start + max_attempts,
        )
        if suffix is None or digest is None:
            raise TimeoutError(f"no balooProxy suffix found within {max_attempts} attempts")
        return suffix, public_salt + suffix, digest, attempts

    workers = _bounded_workers(workers)
    chunk_size = max(1, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    pool_kwargs = _process_pool_kwargs(workers)
    with ProcessPoolExecutor(**pool_kwargs) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_balooproxy_range, public_salt, target, width, next_start, end)] = (
                next_start,
                end,
            )
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, _end = futures.pop(fut)
                suffix, digest, attempts = fut.result()
                if suffix is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return suffix, public_salt + suffix, digest, max(0, begin - start + attempts)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(
                        _search_balooproxy_range,
                        public_salt,
                        target,
                        width,
                        next_start,
                        nend,
                    )] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no balooProxy suffix found within {max_attempts} attempts")


def parse_balooproxy_challenge(data: BalooProxyChallenge | dict[str, Any] | str) -> BalooProxyChallenge:
    if isinstance(data, BalooProxyChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_balooproxy_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            data = json.loads(text)
        elif "publicSalt" in text or "public_salt" in text or "baloo" in text or DEFAULT_COOKIE_NAME in text:
            return parse_balooproxy_challenge_html(text)
        else:
            raise ValueError("balooProxy challenge string must be JSON, HTML, or @file")
    if not isinstance(data, dict):
        raise ValueError("balooProxy challenge must be JSON object or HTML")
    if "html" in data:
        return parse_balooproxy_challenge_html(
            str(data["html"]),
            page_url=data.get("page_url") or data.get("pageUrl"),
        )
    public_salt = str(data.get("publicSalt") or data.get("public_salt") or data.get("salt") or "")
    challenge = str(data.get("challenge") or data.get("hash") or data.get("target") or "")
    difficulty = int(
        data.get("difficulty")
        if data.get("difficulty") is not None
        else data.get("suffix_width") or data.get("suffixWidth") or 0
    )
    return BalooProxyChallenge(
        public_salt=_validate_hex_text(public_salt, "public_salt"),
        challenge=_validate_digest(challenge),
        difficulty=_validate_difficulty(difficulty),
        cookie_name=_validate_cookie_name(data.get("cookie_name") or data.get("cookieName")),
        numeric=_to_bool(data.get("numeric"), default=False),
        page_url=str(data.get("page_url") or data.get("pageUrl") or "") or None,
        raw=data,
    )


def parse_balooproxy_challenge_html(
    html_text: str,
    *,
    page_url: str | None = None,
) -> BalooProxyChallenge:
    text = str(html_text)
    baloopow = _parse_baloopow_constructor(text)
    public_salt = _first_match(
        text,
        [
            r"publicSalt\s*[:=]\s*['\"]([0-9a-fA-F]+)['\"]",
            r"public_salt\s*[:=]\s*['\"]([0-9a-fA-F]+)['\"]",
            r"data-public-salt\s*=\s*['\"]([0-9a-fA-F]+)['\"]",
            r"id\s*=\s*['\"]?publicSalt['\"]?[^>]*>.*?<span[^>]*>\s*([0-9a-fA-F]+)\s*</span>",
        ],
    ) or (baloopow["public_salt"] if baloopow else None)
    challenge = _first_match(
        text,
        [
            r"challenge\s*[:=]\s*['\"]([0-9a-fA-F]{64})['\"]",
            r"data-challenge\s*=\s*['\"]([0-9a-fA-F]{64})['\"]",
            r"id\s*=\s*['\"]?challenge['\"]?[^>]*>.*?<span[^>]*>\s*([0-9a-fA-F]{64})\s*</span>",
        ],
    ) or (baloopow["challenge"] if baloopow else None)
    diff_text = _first_match(
        text,
        [
            r"difficulty\s*[:=]\s*(\d+)",
            r"data-difficulty\s*=\s*['\"]?(\d+)",
        ],
    ) or (baloopow["difficulty"] if baloopow else None)
    cookie_name = _first_match(
        text,
        [
            r"cookieName\s*[:=]\s*['\"]([^'\"]+)['\"]",
            r"data-cookie-name\s*=\s*['\"]([^'\"]+)['\"]",
            r"document\.cookie\s*=\s*['\"]([^=;'\"]+)=",
        ],
    ) or DEFAULT_COOKIE_NAME
    if not public_salt or not challenge or diff_text is None:
        raise ValueError("balooProxy HTML missing publicSalt/challenge/difficulty")
    return BalooProxyChallenge(
        public_salt=_validate_hex_text(public_salt, "public_salt"),
        challenge=_validate_digest(challenge),
        difficulty=_validate_difficulty(int(diff_text)),
        cookie_name=_validate_cookie_name(cookie_name),
        numeric=_to_bool(baloopow.get("numeric") if baloopow else None, default=False),
        page_url=page_url,
        raw_html=text,
    )


def solve_balooproxy_challenge(
    challenge: BalooProxyChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> BalooProxySolution:
    started = time.monotonic()
    item = parse_balooproxy_challenge(challenge)
    suffix, cookie_value, digest, attempts = solve_balooproxy_suffix(
        item.public_salt,
        item.challenge,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return BalooProxySolution(
        challenge=item,
        suffix=suffix,
        cookie_value=cookie_value,
        digest_hex=digest,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts,
    )


class BalooProxySolver:
    """Core solver for balooProxy/balooPow JS suffix challenge."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        base_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "start": start,
            "max_attempts": max_attempts,
            "workers": workers,
            "chunk_size": chunk_size,
            "timeout_sec": timeout_sec,
            "base_url": base_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
        }
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(
            *,
            ok: bool,
            ticket: str | None = None,
            verify_code: str | None = None,
        ) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "balooproxy_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="balooproxy",
                ok=ok,
                captcha_type="balooproxy_js_suffix_sha256_cookie",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("public_salt"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            proxies = _requests_proxies(proxy_server)
            session = requests.Session()
            session.headers.update(_request_headers(headers))
            challenge = self._load_challenge(
                challenge_json,
                challenge_file,
                challenge_html,
                base_url=base_url,
                timeout_sec=timeout_sec,
                session=session,
                proxies=proxies,
                raw=raw,
            )
            solution = solve_balooproxy_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            diagnostics.update(
                {
                    "public_salt": challenge.public_salt,
                    "challenge": challenge.challenge,
                    "difficulty": challenge.difficulty,
                    "suffix": solution.suffix,
                    "cookie_name": challenge.cookie_name,
                    "cookie_value": solution.cookie_value,
                    "digest_hex": solution.digest_hex,
                    "access_hex": solution.access_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "page_url": challenge.page_url,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {
                "suffix": solution.suffix,
                "cookie": solution.cookie_header,
                "digestHex": solution.digest_hex,
                "accessHex": solution.access_hex,
            }
            ticket = json.dumps({challenge.cookie_name: solution.cookie_value}, separators=(",", ":"))
            verify_code = "solved"
            if submit:
                submit_url = base_url or challenge.page_url
                if not submit_url:
                    errors.append("balooProxy submit requested but base_url/page_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                submit_data = self._submit_cookie(
                    submit_url=submit_url,
                    solution=solution,
                    session=session,
                    proxies=proxies,
                    timeout_sec=timeout_sec,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                diagnostics["submit_status"] = submit_data["status"]
                if submit_data["status"] >= 400:
                    errors.append(f"balooProxy cookie submit failed: HTTP {submit_data['status']}")
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                verify_code = "verified"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(
        self,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_html: str | None,
        *,
        base_url: str | None,
        timeout_sec: int,
        session: requests.Session,
        proxies: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> BalooProxyChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_balooproxy_challenge(loaded)
        if challenge_html:
            if challenge_html.startswith("@"):
                text = Path(challenge_html[1:]).read_text(encoding="utf-8")
            else:
                text = challenge_html
            return parse_balooproxy_challenge_html(text, page_url=base_url)
        if base_url:
            resp = session.get(base_url, timeout=timeout_sec, proxies=proxies)
            raw["pageResponse"] = {
                "status": resp.status_code,
                "url": resp.url,
                "contentType": resp.headers.get("content-type"),
            }
            resp.raise_for_status()
            return parse_balooproxy_challenge_html(resp.text, page_url=resp.url or base_url)
        raise ValueError("balooProxy solve requires challenge_json/challenge_file/challenge_html/base_url")

    def _submit_cookie(
        self,
        *,
        submit_url: str,
        solution: BalooProxySolution,
        session: requests.Session,
        proxies: dict[str, str] | None,
        timeout_sec: int,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        resp = session.get(
            submit_url,
            headers={"Cookie": solution.cookie_header},
            timeout=timeout_sec,
            proxies=proxies,
        )
        data = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "bodyPrefix": resp.text[:120],
        }
        raw["submitResponse"] = data
        return data


def _search_balooproxy_range(
    public_salt: str,
    target: str,
    width: int,
    begin: int,
    end: int,
) -> tuple[str | None, str | None, int]:
    base = hashlib.sha256(public_salt.encode("utf-8"))
    attempts = 0
    for value in range(int(begin), int(end)):
        suffix = hex_suffix_by_index(value, width)
        h = base.copy()
        h.update(suffix.encode("ascii"))
        digest = h.hexdigest()
        attempts += 1
        if digest == target:
            return suffix, digest, attempts
    return None, None, attempts


def _validate_hex_text(value: str, name: str) -> str:
    text = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]*", text):
        raise ValueError(f"balooProxy {name} must be hex")
    return text


def _validate_suffix(value: str) -> str:
    return _validate_hex_text(value, "suffix")


def _validate_digest(value: str) -> str:
    text = _validate_hex_text(value, "challenge")
    if len(text) != 64:
        raise ValueError("balooProxy challenge must be 64 hex chars")
    return text


def _validate_difficulty(value: Any) -> int:
    diff = int(value)
    if diff < 0 or diff > 16:
        raise ValueError("balooProxy difficulty/suffix width must be 0..16 hex chars")
    return diff


def _validate_search(start: Any, max_attempts: Any) -> tuple[int, int]:
    s = int(start)
    m = int(max_attempts)
    if s < 0:
        raise ValueError("start must be non-negative")
    if m <= 0:
        raise ValueError("max_attempts must be positive")
    return s, m


def _validate_cookie_name(value: Any) -> str:
    name = str(value or DEFAULT_COOKIE_NAME).strip()
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}", name):
        raise ValueError("balooProxy cookie name must be a valid HTTP cookie token")
    return name


def _to_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n", "!1"}:
        return False
    return default


def _day_text(day: date | str | None) -> str:
    if day is None:
        return date.today().isoformat()
    if isinstance(day, date):
        return day.isoformat()
    return str(day)


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if match := re.search(pattern, text, re.I | re.S):
            return html.unescape(match.group(1))
    return None


def _parse_baloopow_constructor(text: str) -> dict[str, str] | None:
    pattern = (
        r"new\s+BalooPow\s*\(\s*['\"]([0-9a-fA-F]+)['\"]\s*,\s*(\d+)\s*,"
        r"\s*['\"]([0-9a-fA-F]{64})['\"]\s*(?:,\s*([^)]+?))?\)"
    )
    match = re.search(pattern, text, re.I | re.S)
    if not match:
        return None
    numeric_raw = (match.group(4) or "").strip().rstrip(";")
    return {
        "public_salt": html.unescape(match.group(1)),
        "difficulty": match.group(2),
        "challenge": html.unescape(match.group(3)),
        "numeric": numeric_raw,
    }


def _extract_cookie_value(text: str, cookie_name: str = DEFAULT_COOKIE_NAME) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key in (cookie_name, "cookie_value", "cookieValue", "ticket", "cookie"):
                value = data.get(key)
                if value:
                    return _extract_cookie_value(str(value), cookie_name)
    for part in raw.split(";"):
        item = part.strip()
        if item.startswith(f"{cookie_name}="):
            return item.split("=", 1)[1].strip()
    if "=" in raw and not re.fullmatch(r"[0-9a-fA-F]+", raw):
        key, value = raw.split("=", 1)
        if key.strip() == cookie_name:
            return value.split(";", 1)[0].strip()
    return raw


def _load_json_arg(value: Any, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        return json.loads(text) if text and text[0] in "[{" else text or None
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith("@"):
            return _load_json_arg(None, text[1:])
        return json.loads(text) if text[0] in "[{" else text
    return value


def _request_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    merged = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "antibot-sdk/balooproxy-protocol-solver",
    }
    for key, value in (headers or {}).items():
        merged[str(key)] = str(value)
    if not any(key.lower() == "accept-encoding" for key in merged):
        merged["Accept-Encoding"] = "gzip, deflate"
    return merged


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _bounded_workers(requested: int) -> int:
    cpu_cap = max(1, os.cpu_count() or 1)
    try:
        env_cap = int(os.environ.get("ANTIBOT_MAX_WORKERS", cpu_cap))
    except (TypeError, ValueError):
        env_cap = cpu_cap
    return max(1, min(max(1, int(requested or 1)), cpu_cap, max(1, env_cap)))


def _process_pool_kwargs(workers: int) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"max_workers": workers}
    method = os.environ.get("ANTIBOT_MP_CONTEXT", "forkserver")
    try:
        kwargs["mp_context"] = mp.get_context(method)
    except ValueError:
        pass
    return kwargs


def _challenge_raw(challenge: BalooProxyChallenge) -> dict[str, Any]:
    return {
        "publicSalt": challenge.public_salt,
        "challenge": challenge.challenge,
        "difficulty": challenge.difficulty,
        "cookieName": challenge.cookie_name,
        "numeric": challenge.numeric,
        "pageUrl": challenge.page_url,
        "hasHtml": bool(challenge.raw_html),
    }
