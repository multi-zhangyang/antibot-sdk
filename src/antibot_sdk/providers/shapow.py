from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import os
import re
import struct
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://example.com"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_ATTEMPTS = 20_000_000
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_SETTINGS_PATH = "/shapow_internal/challenge-settings.js"
DEFAULT_RESPONSE_ARG = "shapow-response"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}
SETTINGS_HEADERS = {
    "Accept": "application/javascript,text/javascript,*/*;q=0.8",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass(frozen=True, slots=True)
class ShapowChallenge:
    server_data: bytes
    difficulty: int = 12
    nonce_length: int = 16
    settings_path: str = DEFAULT_SETTINGS_PATH
    page_url: str | None = None
    raw: dict[str, Any] | None = None
    raw_html: str | None = None
    raw_settings_js: str | None = None

    @property
    def server_data_hex(self) -> str:
        return self.server_data.hex()


@dataclass(frozen=True, slots=True)
class ShapowSolution:
    challenge: ShapowChallenge
    nonce: int
    nonce_bytes: bytes
    response_hex: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None

    @property
    def query(self) -> dict[str, str]:
        return {DEFAULT_RESPONSE_ARG: self.response_hex}


def shapow_ip_bytes(remote_ip: str) -> bytes:
    addr = ipaddress.ip_address(remote_ip)
    if addr.version == 4:
        return addr.packed + (b"\x00" * 12)
    return addr.packed


def shapow_server_data(remote_ip: str, unix_time: int, random_challenge: int) -> bytes:
    random_challenge = int(random_challenge)
    if random_challenge < 0 or random_challenge > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("random_challenge must fit uint64")
    return shapow_ip_bytes(remote_ip) + struct.pack(">q", int(unix_time)) + struct.pack(">Q", random_challenge)


def shapow_digest(data: bytes | str) -> bytes:
    raw = bytes.fromhex(data) if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).digest()


def shapow_hash_matches(data_or_digest: bytes | str, difficulty: int, *, prehashed: bool = False) -> bool:
    digest = bytes.fromhex(data_or_digest) if isinstance(data_or_digest, str) else bytes(data_or_digest)
    if not prehashed:
        digest = hashlib.sha256(digest).digest()
    return _hash_has_leading_zero_bits(digest, int(difficulty))


def solve_shapow_nonce(
    server_data: bytes | str,
    difficulty: int,
    *,
    nonce_length: int = 16,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[int, bytes, str, str, int]:
    sd = bytes.fromhex(server_data) if isinstance(server_data, str) else bytes(server_data)
    _validate_server_data(sd)
    difficulty = int(difficulty)
    _validate_difficulty(difficulty)
    nonce_length = _validate_nonce_length(nonce_length)
    start = int(start)
    max_attempts = int(max_attempts)
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    max_nonce = 1 << (8 * nonce_length)
    if start >= max_nonce:
        raise ValueError("start exceeds nonce space")
    max_attempts = min(max_attempts, max_nonce - start)
    workers = max(1, int(workers or 1))
    if workers == 1:
        nonce, digest = _search_shapow_range(sd, difficulty, nonce_length, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no SHAPOW nonce found within {max_attempts} attempts")
        nb = nonce.to_bytes(nonce_length, "little")
        return nonce, nb, (sd + nb).hex(), digest.hex(), nonce - start + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_shapow_range, sd, difficulty, nonce_length, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                _begin, end = futures.pop(fut)
                nonce, digest = fut.result()
                if nonce is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    nb = nonce.to_bytes(nonce_length, "little")
                    return nonce, nb, (sd + nb).hex(), digest.hex(), max(0, end - start)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_shapow_range, sd, difficulty, nonce_length, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no SHAPOW nonce found within {max_attempts} attempts")


def parse_shapow_settings_js(js_text: str, *, page_url: str | None = None, settings_path: str | None = None) -> ShapowChallenge:
    nonce_text = _first_match(js_text, [r"\bnonceLength\s*=\s*(\d+)"])
    diff_text = _first_match(js_text, [r"\bdifficulty\s*=\s*(\d+)"])
    server_hex = _first_match(js_text, [r"\bserverData\s*=\s*['\"]([0-9a-fA-F]+)['\"]"])
    if not server_hex:
        raise ValueError("SHAPOW settings JS does not contain serverData")
    server_data = bytes.fromhex(server_hex)
    _validate_server_data(server_data)
    nonce_length = _validate_nonce_length(int(nonce_text or 16))
    difficulty = int(diff_text or 12)
    _validate_difficulty(difficulty)
    return ShapowChallenge(
        server_data=server_data,
        difficulty=difficulty,
        nonce_length=nonce_length,
        settings_path=settings_path or DEFAULT_SETTINGS_PATH,
        page_url=page_url,
        raw_settings_js=js_text,
    )


def parse_shapow_challenge_html(html_text: str, *, page_url: str | None = None) -> ShapowChallenge:
    settings_path = _first_match(
        html_text,
        [
            r"<script[^>]+src\s*=\s*['\"]([^'\"]*challenge-settings\.js[^'\"]*)['\"]",
            r"href\s*=\s*['\"]([^'\"]*challenge-settings\.js[^'\"]*)['\"]",
        ],
    )
    if not settings_path and ("shapow_internal" in html_text or "shapow-response" in html_text or "SHAPOW" in html_text):
        settings_path = DEFAULT_SETTINGS_PATH
    if not settings_path:
        raise ValueError("SHAPOW challenge HTML does not expose challenge-settings.js")
    return ShapowChallenge(
        server_data=b"",
        difficulty=12,
        nonce_length=16,
        settings_path=html.unescape(settings_path),
        page_url=page_url,
        raw_html=html_text,
    )


def parse_shapow_challenge(data: Any) -> ShapowChallenge:
    if isinstance(data, ShapowChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            data = json.loads(text)
        elif "serverData" in text and "difficulty" in text:
            return parse_shapow_settings_js(text)
        elif "challenge-settings.js" in text or "shapow_internal" in text or "shapow-response" in text:
            return parse_shapow_challenge_html(text)
        elif re.fullmatch(r"[0-9a-fA-F]{64}", text):
            return ShapowChallenge(server_data=bytes.fromhex(text))
        else:
            raise ValueError("SHAPOW challenge string must be JSON, settings JS, HTML, or 32-byte serverData hex")
    if not isinstance(data, dict):
        raise ValueError("SHAPOW challenge must be a JSON object, settings JS, or HTML")
    if "html" in data:
        return parse_shapow_challenge_html(str(data["html"]), page_url=data.get("page_url") or data.get("url"))
    if "settings_js" in data or "settingsJs" in data:
        return parse_shapow_settings_js(
            str(data.get("settings_js") or data.get("settingsJs")),
            page_url=data.get("page_url") or data.get("url"),
            settings_path=data.get("settings_path") or data.get("settingsPath"),
        )
    server_hex = (
        data.get("serverData")
        or data.get("server_data")
        or data.get("serverDataHex")
        or data.get("server_data_hex")
        or data.get("challenge")
    )
    if not server_hex:
        raise ValueError("SHAPOW challenge JSON requires serverData")
    server_data = bytes.fromhex(str(server_hex))
    _validate_server_data(server_data)
    nonce_length = _validate_nonce_length(data.get("nonceLength") or data.get("nonce_length") or 16)
    difficulty = int(data.get("difficulty") or data.get("bits") or 12)
    _validate_difficulty(difficulty)
    return ShapowChallenge(
        server_data=server_data,
        difficulty=difficulty,
        nonce_length=nonce_length,
        settings_path=str(data.get("settings_path") or data.get("settingsPath") or DEFAULT_SETTINGS_PATH),
        page_url=str(data.get("page_url") or data.get("url") or "") or None,
        raw=data,
    )


def solve_shapow_challenge(
    challenge: ShapowChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ShapowSolution:
    started = time.monotonic()
    item = parse_shapow_challenge(challenge)
    if not item.server_data:
        raise ValueError("SHAPOW challenge requires serverData; fetch challenge-settings.js first")
    nonce, nonce_bytes, response_hex, digest_hex, attempts_hint = solve_shapow_nonce(
        item.server_data,
        item.difficulty,
        nonce_length=item.nonce_length,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return ShapowSolution(
        challenge=item,
        nonce=nonce,
        nonce_bytes=nonce_bytes,
        response_hex=response_hex,
        digest_hex=digest_hex,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
    )


def verify_shapow_solution(challenge: ShapowChallenge | dict[str, Any] | str, solution: ShapowSolution | dict[str, Any] | str) -> bool:
    try:
        item = parse_shapow_challenge(challenge)
        if isinstance(solution, ShapowSolution):
            response_hex = solution.response_hex
        elif isinstance(solution, dict):
            response_hex = (
                solution.get("response_hex")
                or solution.get("responseHex")
                or solution.get(DEFAULT_RESPONSE_ARG)
                or solution.get("token")
                or solution.get("ticket")
            )
        else:
            response_hex = str(solution)
        if not response_hex:
            return False
        return verify_shapow_response(item.server_data, str(response_hex), item.difficulty, item.nonce_length)
    except Exception:
        return False


def verify_shapow_response(server_data: bytes | str, response_hex: str, difficulty: int, nonce_length: int = 16) -> bool:
    try:
        sd = bytes.fromhex(server_data) if isinstance(server_data, str) else bytes(server_data)
        _validate_server_data(sd)
        nonce_length = _validate_nonce_length(nonce_length)
        raw = bytes.fromhex(_normalise_hex(response_hex))
        if len(raw) != len(sd) + nonce_length or raw[: len(sd)] != sd:
            return False
        return shapow_hash_matches(raw, int(difficulty))
    except Exception:
        return False


class ShapowSolver:
    """Protocol solver for SHAPOW Nginx IP/time/random-bound SHA-256 PoW.

    It fetches challenge-settings.js, preserves the same requests session/proxy
    for IP-bound settings and submission, solves SHA256(serverData||nonce) with
    leading-zero bits, and optionally returns via ?shapow-response=... . No
    browser is started.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        page_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        settings_url: str | None = None,
        settings_path: str | None = None,
        submit_url: str | None = None,
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
            "base_url": base_url,
            "page_url": page_url,
            "settings_url": settings_url,
            "settings_path": settings_path,
            "submit_url": submit_url,
            "submit": submit,
            "start": start,
            "max_attempts": max_attempts,
            "workers": workers,
            "chunk_size": chunk_size,
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
                out = output_root / "shapow_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="shapow",
                ok=ok,
                captcha_type="nginx_ip_time_bound_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("server_data"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            session = requests.Session()
            merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
            proxies = _requests_proxies(proxy_server)
            challenge = self._load_challenge(
                session=session,
                base_url=base_url,
                page_url=page_url,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                settings_url=settings_url,
                settings_path=settings_path,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_shapow_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            diagnostics.update(
                {
                    "server_data": challenge.server_data_hex,
                    "server_data_len": len(challenge.server_data),
                    "difficulty": challenge.difficulty,
                    "nonce_length": challenge.nonce_length,
                    "settings_path": challenge.settings_path,
                    "nonce": solution.nonce,
                    "response_hex": solution.response_hex,
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "environment_binding": ["client_ip", "server_time", "random_challenge"],
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {
                "query": solution.query,
                "nonce": solution.nonce,
                "digestHex": solution.digest_hex,
                "elapsedMs": solution.elapsed_ms,
            }
            final_ticket = solution.response_hex
            verify_code = "solved"
            if submit or submit_url:
                final_ticket, verify_code = self._submit(
                    session=session,
                    url=submit_url or challenge.page_url or page_url or base_url,
                    response_hex=solution.response_hex,
                    timeout_sec=timeout_sec,
                    proxies=proxies,
                    headers=merged_headers,
                    raw=raw,
                    errors=errors,
                )
                if verify_code != "verified":
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        session: requests.Session,
        base_url: str,
        page_url: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        settings_url: str | None,
        settings_path: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> ShapowChallenge:
        if challenge_json is not None:
            item = parse_shapow_challenge(_load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json)
            if item.server_data:
                return _merge_shapow_meta(item, settings_path=settings_path, page_url=page_url)
            settings_url = settings_url or _resolve_settings_url(base_url, page_url or item.page_url, item.settings_path)
        else:
            loaded = _load_json_arg(None, challenge_file)
            if loaded is not None:
                item = parse_shapow_challenge(loaded)
                if item.server_data:
                    return _merge_shapow_meta(item, settings_path=settings_path, page_url=page_url)
                settings_url = settings_url or _resolve_settings_url(base_url, page_url or item.page_url, item.settings_path)

        inferred_page_url = page_url or base_url
        if not settings_url:
            resp = session.get(inferred_page_url, headers=headers, timeout=timeout_sec, proxies=proxies)
            raw["pageRequest"] = {"url": inferred_page_url, "headers": _kept_headers(headers)}
            raw["pageResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
            if resp.status_code >= 500:
                raw["pageResponse"]["text"] = resp.text[:500]
                raise RuntimeError(f"SHAPOW page HTTP {resp.status_code}")
            if "serverData" in resp.text and "difficulty" in resp.text:
                return _merge_shapow_meta(parse_shapow_settings_js(resp.text, page_url=resp.url), settings_path=settings_path, page_url=resp.url)
            page = parse_shapow_challenge_html(resp.text, page_url=resp.url)
            settings_url = _resolve_settings_url(base_url, resp.url, settings_path or page.settings_path)
        else:
            settings_url = _resolve_settings_url(base_url, inferred_page_url, settings_url)

        settings_headers = {**headers, **SETTINGS_HEADERS}
        resp = session.get(settings_url, headers=settings_headers, timeout=timeout_sec, proxies=proxies)
        raw["settingsRequest"] = {"url": settings_url, "headers": _kept_headers(settings_headers)}
        raw["settingsResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
        if resp.status_code >= 400:
            raw["settingsResponse"]["text"] = resp.text[:500]
            raise RuntimeError(f"SHAPOW challenge-settings HTTP {resp.status_code}")
        item = parse_shapow_settings_js(resp.text, page_url=inferred_page_url, settings_path=settings_path or DEFAULT_SETTINGS_PATH)
        return _merge_shapow_meta(item, settings_path=settings_path, page_url=page_url or inferred_page_url)

    def _submit(
        self,
        *,
        session: requests.Session,
        url: str,
        response_hex: str,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        submit_url = _url_with_query_arg(url, DEFAULT_RESPONSE_ARG, response_hex)
        resp = session.get(submit_url, headers=headers, timeout=timeout_sec, proxies=proxies, allow_redirects=False)
        raw["verifyRequest"] = {"url": submit_url, "headers": _kept_headers(headers)}
        raw["verifyResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "location": resp.headers.get("Location"),
            "contentType": resp.headers.get("Content-Type"),
            "xShapowPassed": resp.headers.get("X-Shapow-Passed"),
        }
        if resp.status_code >= 400:
            raw["verifyResponse"]["text"] = resp.text[:500]
            errors.append(resp.text[:120] or f"http_{resp.status_code}")
            return response_hex, f"http_{resp.status_code}"
        if resp.headers.get("X-Shapow-Passed") or resp.status_code in {301, 302, 303, 307, 308}:
            ticket = json.dumps({"location": resp.headers.get("Location"), "x_shapow_passed": bool(resp.headers.get("X-Shapow-Passed"))}, separators=(",", ":"))
            return ticket, "verified"
        if _looks_like_shapow_challenge(resp.text):
            raw["verifyResponse"]["text"] = resp.text[:500]
            errors.append("verify_failed_challenge_returned")
            return response_hex, "verify_failed"
        ticket = json.dumps({"status": resp.status_code, "url": resp.url}, separators=(",", ":"))
        return ticket, "verified"


def _search_shapow_range(server_data: bytes, difficulty: int, nonce_length: int, begin: int, end: int) -> tuple[int | None, bytes | None]:
    prefix_len = len(server_data)
    buf = bytearray(prefix_len + nonce_length)
    buf[:prefix_len] = server_data
    buf[prefix_len:] = int(begin).to_bytes(nonce_length, "little")
    nonce = int(begin)
    end = int(end)
    while nonce < end:
        digest = hashlib.sha256(buf).digest()
        if _hash_has_leading_zero_bits(digest, difficulty):
            return nonce, digest
        nonce += 1
        _increment_le_inplace(buf, prefix_len, nonce_length)
    return None, None


def _increment_le_inplace(buf: bytearray, offset: int, size: int) -> None:
    for i in range(offset, offset + size):
        value = buf[i] + 1
        buf[i] = value & 0xFF
        if value <= 0xFF:
            break


def _hash_has_leading_zero_bits(digest: bytes, difficulty: int) -> bool:
    _validate_difficulty(difficulty)
    whole, rem = divmod(difficulty, 8)
    if whole and any(digest[i] != 0 for i in range(whole)):
        return False
    if rem:
        return (digest[whole] & (0xFF << (8 - rem))) == 0
    return True


def _validate_difficulty(difficulty: int) -> None:
    if difficulty < 0 or difficulty > 256:
        raise ValueError("difficulty out of range")


def _validate_nonce_length(nonce_length: Any) -> int:
    value = int(nonce_length)
    if value <= 0 or value > 64:
        raise ValueError("nonceLength must be 1..64 bytes")
    return value


def _validate_server_data(server_data: bytes) -> None:
    if len(server_data) != 32:
        raise ValueError(f"SHAPOW serverData must be 32 bytes, got {len(server_data)}")


def _normalise_hex(value: str) -> str:
    text = value.strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", text) or len(text) % 2 != 0:
        raise ValueError("expected even-length hex")
    return text.lower()


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return html.unescape(match.group(1))
    return None


def _looks_like_shapow_challenge(text: str) -> bool:
    return any(marker in text for marker in ("shapow_internal", "shapow-response", "Checking if you're a bot", "Verification performed by"))


def _resolve_settings_url(base_url: str, page_url: str | None, settings_path: str | None) -> str:
    path = settings_path or DEFAULT_SETTINGS_PATH
    if re.match(r"^https?://", path, re.I):
        return path
    if path.startswith("/"):
        return urljoin(base_url, path)
    if page_url:
        # SHAPOW's challenge page injects a <base href=location.pathname + '/'>
        # for extensionless paths, so relative resources are resolved under the
        # challenged path instead of the site root.
        base = page_url if urlsplit(page_url).path.endswith("/") else page_url + "/"
        return urljoin(base, path)
    return urljoin(base_url, path)


def _url_with_query_arg(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _merge_shapow_meta(item: ShapowChallenge, *, settings_path: str | None, page_url: str | None) -> ShapowChallenge:
    return ShapowChallenge(
        server_data=item.server_data,
        difficulty=item.difficulty,
        nonce_length=item.nonce_length,
        settings_path=settings_path or item.settings_path,
        page_url=page_url or item.page_url,
        raw=item.raw,
        raw_html=item.raw_html,
        raw_settings_js=item.raw_settings_js,
    )


def _challenge_raw(challenge: ShapowChallenge) -> dict[str, Any]:
    return {
        "serverData": challenge.server_data_hex,
        "serverDataLen": len(challenge.server_data),
        "difficulty": challenge.difficulty,
        "nonceLength": challenge.nonce_length,
        "settingsPath": challenge.settings_path,
        "pageUrl": challenge.page_url,
        "hasHtml": bool(challenge.raw_html),
        "hasSettingsJs": bool(challenge.raw_settings_js),
    }


def _kept_headers(headers: dict[str, str]) -> dict[str, str]:
    names = ("User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Pragma")
    return {k: headers[k] for k in names if k in headers}


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        if not text:
            return None
        return json.loads(text) if text[0] in "[{" else text
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return _load_json_arg(None, text[1:])
    return json.loads(text) if text[0] in "[{" else text
