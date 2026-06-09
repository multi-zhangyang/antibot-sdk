from __future__ import annotations

import asyncio
import base64
import hashlib
import html
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
from urllib.parse import urlencode, urljoin, urlparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://example.com"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_ATTEMPTS = 5_000_000
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    "Sec-Ch-Ua-Platform": '"Linux"',
}
MAKE_HEADERS = {
    "Accept": "*/*",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


@dataclass(frozen=True, slots=True)
class GoAwayPowChallenge:
    challenge: str
    target: str
    difficulty: int = 20
    challenge_path: str | None = None
    challenge_name: str = "js-pow-sha256"
    request_id: str | None = None
    redirect: str | None = None
    raw: dict[str, Any] | None = None
    raw_html: str | None = None

    @property
    def challenge_bytes(self) -> bytes:
        return bytes.fromhex(self.challenge)

    @property
    def target_bytes(self) -> bytes:
        return bytes.fromhex(self.target)


@dataclass(frozen=True, slots=True)
class GoAwayPowSolution:
    challenge: GoAwayPowChallenge
    nonce: int
    nonce_bytes: bytes
    result: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None


def goaway_challenge_from_key(key: bytes | str, difficulty: int) -> str:
    key_bytes = base64.b64decode(key, validate=True) if isinstance(key, str) else bytes(key)
    if len(key_bytes) != 32:
        raise ValueError("go-away challenge key must be 32 bytes")
    return hashlib.sha256(struct.pack("<Q", int(difficulty)) + key_bytes).hexdigest()


def goaway_target_for_difficulty(difficulty: int, *, size: int = 32) -> str:
    difficulty = int(difficulty)
    if difficulty < 0 or difficulty > size * 8:
        raise ValueError("difficulty out of range")
    out = bytearray(size)
    remaining = difficulty
    for i in range(size):
        value = 0
        for _ in range(8):
            value <<= 1
            if remaining == 0:
                value |= 1
            else:
                remaining -= 1
        out[i] = value
    return bytes(out).hex()


def goaway_digest(challenge: bytes | str, nonce: int | bytes) -> bytes:
    c = bytes.fromhex(challenge) if isinstance(challenge, str) else bytes(challenge)
    n = nonce if isinstance(nonce, bytes) else struct.pack("<Q", int(nonce))
    return hashlib.sha256(c + n).digest()


def goaway_result_hex(challenge: bytes | str, nonce: int) -> str:
    c = bytes.fromhex(challenge) if isinstance(challenge, str) else bytes(challenge)
    return (c + struct.pack("<Q", int(nonce))).hex()


def verify_goaway_pow(challenge: bytes | str, result: str, difficulty: int, target: bytes | str | None = None) -> bool:
    try:
        c = bytes.fromhex(challenge) if isinstance(challenge, str) else bytes(challenge)
        raw = bytes.fromhex(str(result))
        if len(raw) != len(c) + 8 or raw[: len(c)] != c:
            return False
        digest = hashlib.sha256(raw).digest()
        if target is not None:
            target_bytes = bytes.fromhex(target) if isinstance(target, str) else bytes(target)
            if digest >= target_bytes:
                return False
        return _leading_zero_bits(digest) >= int(difficulty)
    except Exception:
        return False


def solve_goaway_pow_nonce(
    challenge: bytes | str,
    target: bytes | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> tuple[int, bytes, str, str, int]:
    c = bytes.fromhex(challenge) if isinstance(challenge, str) else bytes(challenge)
    t = bytes.fromhex(target) if isinstance(target, str) else bytes(target)
    if len(c) != 32 or len(t) != 32:
        raise ValueError("go-away js-pow-sha256 challenge and target must be 32 bytes")
    start = int(start)
    max_attempts = int(max_attempts)
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        nonce, digest = _search_goaway_range(c, t, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no go-away PoW nonce found within {max_attempts} attempts")
        nb = struct.pack("<Q", nonce)
        return nonce, nb, (c + nb).hex(), digest.hex(), nonce - start + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_goaway_range, c, t, next_start, end)] = (next_start, end)
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
                    nb = struct.pack("<Q", nonce)
                    return nonce, nb, (c + nb).hex(), digest.hex(), max(0, end - start)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_goaway_range, c, t, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no go-away PoW nonce found within {max_attempts} attempts")


def parse_goaway_challenge(data: Any) -> GoAwayPowChallenge:
    if isinstance(data, GoAwayPowChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            data = json.loads(text)
        elif "go-away" in text or "script.mjs" in text or "__goaway" in text:
            return parse_goaway_challenge_html(text)
        else:
            raise ValueError("go-away challenge string must be JSON or HTML")
    if not isinstance(data, dict):
        raise ValueError("go-away challenge must be a JSON object or HTML")
    if "html" in data:
        return parse_goaway_challenge_html(str(data["html"]), page_url=data.get("page_url") or data.get("url"))
    if data.get("Data") and "challenge" not in data:
        # Official wasm interface test fixture wraps response body bytes as base64.
        inner = json.loads(base64.b64decode(data["Data"]).decode("utf-8"))
        merged = {**inner, "raw_wrapper": data}
        data = merged
    challenge = data.get("challenge")
    target = data.get("target")
    difficulty = _challenge_difficulty(data)
    if not challenge or not target:
        key = data.get("key") or data.get("Key")
        if key:
            challenge = goaway_challenge_from_key(str(key), difficulty)
            target = goaway_target_for_difficulty(difficulty)
        else:
            raise ValueError("go-away challenge JSON requires challenge+target or key+difficulty")
    headers = data.get("headers") or data.get("Headers") or {}
    request_id = data.get("request_id") or data.get("id") or _header_first(headers, "X-Away-Id")
    return GoAwayPowChallenge(
        challenge=str(challenge),
        target=str(target),
        difficulty=difficulty,
        challenge_path=str(data.get("challenge_path") or data.get("path") or "") or None,
        challenge_name=str(data.get("challenge_name") or data.get("name") or "js-pow-sha256"),
        request_id=str(request_id or "") or None,
        redirect=str(data.get("redirect") or "") or None,
        raw=data,
    )


def parse_goaway_challenge_html(html_text: str, *, page_url: str | None = None) -> GoAwayPowChallenge:
    request_id = _first_match(html_text, [r"Request Id\s*<em>([0-9a-fA-F]{32})</em>", r"request id[^<]*</[^>]+>\s*:?\s*<em>([0-9a-fA-F]{32})</em>"])
    challenge_name = _first_match(html_text, [r"status_loading_challenge[^<]*<em>([^<]+)</em>", r"id=[\"']status[\"'][^>]*>.*?<em>([^<]+)</em>", r"challenge/([^/'\"?]+)/script\.mjs"])
    script_src = _first_match(html_text, [r"<script[^>]+src=[\"']([^\"']*?/challenge/[^\"']*?/script\.mjs[^\"']*)[\"']"])
    challenge_path = None
    if script_src:
        parsed = urlparse(html.unescape(script_src))
        path = parsed.path
        if path.endswith("/script.mjs"):
            challenge_path = path[: -len("/script.mjs")]
    if not challenge_name and challenge_path:
        challenge_name = challenge_path.rstrip("/").split("/")[-1]
    return GoAwayPowChallenge(
        challenge="",
        target="",
        difficulty=20,
        challenge_path=challenge_path,
        challenge_name=html.unescape(challenge_name or "js-pow-sha256"),
        request_id=request_id,
        redirect=page_url,
        raw_html=html_text,
    )


def solve_goaway_challenge(
    challenge: GoAwayPowChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> GoAwayPowSolution:
    started = time.monotonic()
    item = parse_goaway_challenge(challenge)
    if not item.challenge or not item.target:
        raise ValueError("go-away challenge requires challenge+target; fetch make-challenge first for HTML pages")
    nonce, nonce_bytes, result, digest_hex, attempts_hint = solve_goaway_pow_nonce(
        item.challenge,
        item.target,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return GoAwayPowSolution(
        challenge=item,
        nonce=nonce,
        nonce_bytes=nonce_bytes,
        result=result,
        digest_hex=digest_hex,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
    )


def verify_goaway_solution(challenge: GoAwayPowChallenge | dict[str, Any] | str, solution: GoAwayPowSolution | dict[str, Any] | str) -> bool:
    try:
        item = parse_goaway_challenge(challenge)
        if isinstance(solution, GoAwayPowSolution):
            result = solution.result
        elif isinstance(solution, dict):
            result = (
                solution.get("result")
                or solution.get("Result")
                or solution.get("token")
                or solution.get("__goaway_token")
            )
        else:
            result = str(solution)
        if not result:
            return False
        return verify_goaway_pow(item.challenge, _normalise_result_hex(str(result)), item.difficulty, item.target)
    except Exception:
        return False


class GoAwaySolver:
    """Protocol solver for go-away js-pow-sha256 challenge.

    It keeps key-bound headers stable, POSTs make-challenge, solves the browser
    worker's SHA256(challenge||uint64_le(nonce)) < target puzzle, and optionally
    calls verify-challenge with __goaway_token. No browser is started.
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
        challenge_url: str | None = None,
        verify_url: str | None = None,
        challenge_path: str | None = None,
        challenge_name: str = "js-pow-sha256",
        request_id: str | None = None,
        redirect: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = 100_000,
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
            "challenge_url": challenge_url,
            "verify_url": verify_url,
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
                out = output_root / "goaway_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="goaway",
                ok=ok,
                captcha_type="goaway_js_pow_sha256",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge"),
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
                challenge_url=challenge_url,
                challenge_path=challenge_path,
                challenge_name=challenge_name,
                request_id=request_id,
                redirect=redirect,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_goaway_challenge(challenge, start=start, max_attempts=max_attempts, workers=workers, chunk_size=chunk_size)
            diagnostics.update(
                {
                    "challenge": challenge.challenge,
                    "target": challenge.target,
                    "difficulty": challenge.difficulty,
                    "challenge_name": challenge.challenge_name,
                    "challenge_path": challenge.challenge_path,
                    "request_id": challenge.request_id,
                    "nonce": solution.nonce,
                    "result": solution.result,
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "environment_headers": ["User-Agent", "Accept-Encoding", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Platform"],
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"result": solution.result, "nonce": solution.nonce, "digestHex": solution.digest_hex, "elapsedMs": solution.elapsed_ms}
            final_ticket = solution.result
            verify_code = "solved"
            if submit or verify_url:
                final_ticket, verify_code = self._submit(
                    session=session,
                    challenge=challenge,
                    result=solution.result,
                    elapsed_ms=solution.elapsed_ms,
                    verify_url=verify_url,
                    base_url=base_url,
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
        challenge_url: str | None,
        challenge_path: str | None,
        challenge_name: str,
        request_id: str | None,
        redirect: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> GoAwayPowChallenge:
        if challenge_json is not None:
            item = parse_goaway_challenge(_load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json)
            return _merge_goaway_meta(item, challenge_path=challenge_path, challenge_name=challenge_name, request_id=request_id, redirect=redirect)
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            item = parse_goaway_challenge(loaded)
            return _merge_goaway_meta(item, challenge_path=challenge_path, challenge_name=challenge_name, request_id=request_id, redirect=redirect)

        inferred = GoAwayPowChallenge("", "", challenge_path=challenge_path, challenge_name=challenge_name, request_id=request_id, redirect=redirect)
        if not challenge_url:
            url = page_url or base_url
            resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
            raw["pageRequest"] = {"url": url}
            raw["pageResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
            if resp.status_code >= 500:
                raw["pageResponse"]["text"] = resp.text[:500]
                raise RuntimeError(f"go-away challenge page HTTP {resp.status_code}")
            inferred = parse_goaway_challenge_html(resp.text, page_url=url)
            inferred = _merge_goaway_meta(inferred, challenge_path=challenge_path, challenge_name=challenge_name, request_id=request_id, redirect=redirect or url)
            if not inferred.challenge_path:
                raise ValueError("go-away page did not expose challenge script path; pass --challenge-url")
            challenge_url = urljoin(base_url, inferred.challenge_path + "/make-challenge")
        else:
            challenge_url = urljoin(base_url, challenge_url)

        make_headers = {**headers, **MAKE_HEADERS}
        resp = session.post(challenge_url, headers=make_headers, timeout=timeout_sec, proxies=proxies)
        raw["makeChallengeRequest"] = {"url": challenge_url, "headers": _kept_headers(make_headers)}
        raw["makeChallengeResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
        if resp.status_code >= 400:
            raw["makeChallengeResponse"]["text"] = resp.text[:500]
            raise RuntimeError(f"go-away make-challenge HTTP {resp.status_code}")
        data = resp.json()
        raw["makeChallengeResponse"]["json"] = data
        item = parse_goaway_challenge(data)
        return _merge_goaway_meta(
            item,
            challenge_path=inferred.challenge_path or challenge_path,
            challenge_name=inferred.challenge_name or challenge_name,
            request_id=inferred.request_id or request_id,
            redirect=inferred.redirect or redirect,
        )

    def _submit(
        self,
        *,
        session: requests.Session,
        challenge: GoAwayPowChallenge,
        result: str,
        elapsed_ms: int,
        verify_url: str | None,
        base_url: str,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        if not verify_url:
            if not challenge.challenge_path:
                raise ValueError("verify requires challenge_path or verify_url")
            verify_url = urljoin(base_url, challenge.challenge_path + "/verify-challenge")
        params = {
            "__goaway_token": result,
            "__goaway_challenge": challenge.challenge_name,
            "__goaway_bust": str(int(time.time() * 1000)),
            "__goaway_elapsedTime": str(max(0, int(elapsed_ms))),
        }
        if challenge.request_id:
            params["__goaway_id"] = challenge.request_id
        if challenge.redirect:
            params["__goaway_redirect"] = challenge.redirect
        sep = "&" if "?" in verify_url else "?"
        url = verify_url + sep + urlencode(params)
        resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies, allow_redirects=False)
        raw["verifyRequest"] = {"url": url, "headers": _kept_headers(headers)}
        raw["verifyResponse"] = {"status": resp.status_code, "url": resp.url, "location": resp.headers.get("Location"), "setCookieNames": _set_cookie_names(resp.headers.get("Set-Cookie", ""))}
        success = resp.status_code in {302, 303, 307, 308} or any(name.endswith("-state") for name in raw["verifyResponse"]["setCookieNames"])
        if success:
            return json.dumps({"location": resp.headers.get("Location"), "state_cookie": bool(raw["verifyResponse"]["setCookieNames"])}, separators=(",", ":")), "verified"
        raw["verifyResponse"]["text"] = resp.text[:500]
        if resp.status_code >= 400:
            errors.append(resp.text[:120] or f"http_{resp.status_code}")
            return result, f"http_{resp.status_code}"
        errors.append("verify_failed")
        return result, "verify_failed"


def _search_goaway_range(challenge: bytes, target: bytes, begin: int, end: int) -> tuple[int | None, bytes | None]:
    prefix_len = len(challenge)
    buf = bytearray(prefix_len + 8)
    buf[:prefix_len] = challenge
    for nonce in range(int(begin), int(end)):
        struct.pack_into("<Q", buf, prefix_len, nonce)
        digest = hashlib.sha256(buf).digest()
        if digest < target:
            return nonce, digest
    return None, None


def _leading_zero_bits(data: bytes) -> int:
    count = 0
    for b in data:
        if b == 0:
            count += 8
            continue
        return count + (8 - b.bit_length())
    return count


def _challenge_difficulty(data: dict[str, Any]) -> int:
    params = data.get("parameters") or data.get("Parameters") or {}
    return int(data.get("difficulty") or data.get("Difficulty") or params.get("difficulty") or 20)


def _normalise_result_hex(value: str) -> str:
    text = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
        return text.lower()
    decoded = base64.b64decode(text, validate=True).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", decoded) or len(decoded) % 2 != 0:
        raise ValueError("go-away result is neither hex nor base64-encoded hex")
    return decoded.lower()


def _merge_goaway_meta(
    item: GoAwayPowChallenge,
    *,
    challenge_path: str | None,
    challenge_name: str | None,
    request_id: str | None,
    redirect: str | None,
) -> GoAwayPowChallenge:
    return GoAwayPowChallenge(
        challenge=item.challenge,
        target=item.target,
        difficulty=item.difficulty,
        challenge_path=challenge_path or item.challenge_path,
        challenge_name=challenge_name or item.challenge_name,
        request_id=request_id or item.request_id,
        redirect=redirect or item.redirect,
        raw=item.raw,
        raw_html=item.raw_html,
    )


def _challenge_raw(challenge: GoAwayPowChallenge) -> dict[str, Any]:
    return {
        "challenge": challenge.challenge,
        "target": challenge.target,
        "difficulty": challenge.difficulty,
        "challenge_path": challenge.challenge_path,
        "challenge_name": challenge.challenge_name,
        "request_id": challenge.request_id,
        "redirect": challenge.redirect,
    }


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        m = re.search(pattern, text, re.I | re.S)
        if m:
            return html.unescape(m.group(1))
    return None


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
        return json.loads(text) if text[0] in "{[" else text
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return _load_json_arg(None, text[1:])
    return json.loads(text) if text and text[0] in "{[" else text


def _kept_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: headers[k] for k in ("User-Agent", "Accept-Encoding", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Platform") if k in headers}


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)


def _header_first(headers: Any, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != name.lower():
            continue
        if isinstance(value, list | tuple):
            return str(value[0]) if value else None
        return str(value)
    return None
