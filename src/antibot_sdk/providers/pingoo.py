from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import multiprocessing as mp
import os
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

CHALLENGE_COOKIE = "__pingoo_captcha"
VERIFIED_COOKIE = "__pingoo_captcha_verified"
INIT_PATH = "/__pingoo/captcha/api/init"
VERIFY_PATH = "/__pingoo/captcha/api/verify"
DEFAULT_MAX_ATTEMPTS = 1_000_000
DEFAULT_CHUNK_SIZE = 50_000
DEFAULT_TIMEOUT = 10


@dataclass(frozen=True, slots=True)
class PingooChallenge:
    challenge: str
    difficulty: int
    captcha_cookie: str | None = None
    page_url: str | None = None
    init_url: str | None = None
    verify_url: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class PingooSolution:
    challenge: PingooChallenge
    nonce: str
    hash_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None
    verified_cookie: str | None = None

    @property
    def verify_body(self) -> dict[str, str]:
        return {"nonce": self.nonce, "hash": self.hash_hex}

    @property
    def cookie_header(self) -> str | None:
        if not self.verified_cookie:
            return None
        return f"{VERIFIED_COOKIE}={self.verified_cookie}"

    @property
    def ticket_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"nonce": self.nonce, "hash": self.hash_hex, "verify_body": self.verify_body}
        if self.verified_cookie:
            payload[VERIFIED_COOKIE] = self.verified_cookie
        return payload


def pingoo_hash_hex(challenge: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{_validate_challenge(challenge)}{_nonce_text(nonce)}".encode("utf-8")).hexdigest()


def pingoo_hash_matches(hash_hex: str, difficulty: int) -> bool:
    digest = _validate_hash(hash_hex)
    diff = _validate_difficulty(difficulty)
    return digest.startswith("0" * diff)


def solve_pingoo_nonce(
    challenge: str,
    difficulty: int,
    *,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[str, str, int]:
    ch = _validate_challenge(challenge)
    diff = _validate_difficulty(difficulty)
    start, max_attempts = _validate_search(start, max_attempts)
    if workers <= 1:
        nonce, digest, attempts = _search_pingoo_range(ch, diff, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no Pingoo nonce found within {max_attempts} attempts")
        return nonce, digest, attempts

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
            futures[pool.submit(_search_pingoo_range, ch, diff, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, _end = futures.pop(fut)
                nonce, digest, attempts = fut.result()
                if nonce is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return nonce, digest, max(0, begin - start + attempts)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_pingoo_range, ch, diff, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no Pingoo nonce found within {max_attempts} attempts")


def solve_pingoo_challenge(
    challenge: PingooChallenge | dict[str, Any] | str,
    *,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> PingooSolution:
    started = time.monotonic()
    item = parse_pingoo_challenge(challenge)
    nonce, digest, attempts = solve_pingoo_nonce(
        item.challenge,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return PingooSolution(
        challenge=item,
        nonce=nonce,
        hash_hex=digest,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts,
    )


def verify_pingoo_solution(
    challenge: PingooChallenge | dict[str, Any] | str,
    solution: PingooSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_pingoo_challenge(challenge)
        nonce, supplied_hash = _solution_nonce_hash(solution)
        computed = pingoo_hash_hex(item.challenge, nonce)
        if supplied_hash and supplied_hash != computed:
            return False
        return pingoo_hash_matches(computed, item.difficulty)
    except Exception:
        return False


def parse_pingoo_challenge(
    data: PingooChallenge | dict[str, Any] | str,
    *,
    page_url: str | None = None,
    init_url: str | None = None,
    verify_url: str | None = None,
) -> PingooChallenge:
    if isinstance(data, PingooChallenge):
        return _merge_urls(data, page_url=page_url, init_url=init_url, verify_url=verify_url)
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_pingoo_challenge(
                Path(text[1:]).read_text(encoding="utf-8"),
                page_url=page_url,
                init_url=init_url,
                verify_url=verify_url,
            )
        if text.startswith("{"):
            return parse_pingoo_challenge(json.loads(text), page_url=page_url, init_url=init_url, verify_url=verify_url)
        if _looks_like_pingoo_html(text):
            return parse_pingoo_challenge_html(text, page_url=page_url, init_url=init_url, verify_url=verify_url)
        raise ValueError("Pingoo challenge string must be JSON, HTML, or @file")
    if not isinstance(data, dict):
        raise ValueError("Pingoo challenge must be JSON object, HTML, or dataclass")
    if "html" in data:
        return parse_pingoo_challenge_html(
            str(data["html"]),
            page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
            init_url=init_url,
            verify_url=verify_url,
        )

    challenge = str(data.get("challenge") or data.get("c") or "")
    difficulty = data.get("difficulty") if data.get("difficulty") is not None else data.get("diff")
    if difficulty is None:
        difficulty = 1
    cookie = str(
        data.get("captcha_cookie")
        or data.get("captchaCookie")
        or data.get(CHALLENGE_COOKIE)
        or data.get("cookie")
        or ""
    ) or None
    return PingooChallenge(
        challenge=_validate_challenge(challenge),
        difficulty=_validate_difficulty(difficulty),
        captcha_cookie=_extract_cookie_value(cookie, CHALLENGE_COOKIE) if cookie else None,
        page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
        init_url=str(data.get("init_url") or data.get("initUrl") or init_url or "") or None,
        verify_url=str(data.get("verify_url") or data.get("verifyUrl") or verify_url or "") or None,
        raw=data,
    )


def parse_pingoo_challenge_html(
    html_text: str,
    *,
    page_url: str | None = None,
    init_url: str | None = None,
    verify_url: str | None = None,
) -> PingooChallenge:
    text = str(html_text)
    challenge = _first_match(text, [r"challenge\s*[:=]\s*['\"]([^'\"]+)['\"]", r"data-challenge\s*=\s*['\"]([^'\"]+)['\"]"])
    difficulty = _first_match(text, [r"difficulty\s*[:=]\s*(\d+)", r"data-difficulty\s*=\s*['\"]?(\d+)"])
    if not challenge:
        raise ValueError("Pingoo HTML does not contain inline challenge; fetch /__pingoo/captcha/api/init instead")
    return PingooChallenge(
        challenge=_validate_challenge(challenge),
        difficulty=_validate_difficulty(difficulty or 1),
        page_url=page_url,
        init_url=init_url,
        verify_url=verify_url,
        raw_html=text,
    )


def decode_pingoo_jwt_claims(token: str) -> dict[str, Any]:
    """Decode a Pingoo JWT payload without signature verification for diagnostics only."""

    value = _extract_cookie_value(token, CHALLENGE_COOKIE) or _extract_cookie_value(token, VERIFIED_COOKIE) or token
    parts = str(value).split(".")
    if len(parts) < 2:
        raise ValueError("Pingoo JWT must contain header.payload.signature")
    return json.loads(_b64url_decode(parts[1]).decode("utf-8"))


class PingooSolver:
    """Protocol solver for Pingoo captcha JWT + SHA-256 PoW."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        base_url: str | None = None,
        challenge_url: str | None = None,
        init_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        start: int = 1,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
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
            "init_url": init_url or challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "user_agent": user_agent,
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
                out = output_root / "pingoo_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="pingoo",
                ok=ok,
                captcha_type="jwt_cookie_sha256_pow",
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
            proxies = _requests_proxies(proxy_server)
            session = requests.Session()
            request_headers = dict(headers or {})
            if user_agent:
                request_headers["User-Agent"] = user_agent
            session.headers.update(_request_headers(request_headers))
            challenge = self._load_challenge(
                challenge_json,
                challenge_file,
                challenge_html,
                base_url=base_url,
                init_url=init_url or challenge_url,
                verify_url=verify_url,
                timeout_sec=timeout_sec,
                session=session,
                proxies=proxies,
                raw=raw,
            )
            solution = solve_pingoo_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            diagnostics.update(
                {
                    "challenge": challenge.challenge,
                    "difficulty": challenge.difficulty,
                    "nonce": solution.nonce,
                    "hash_hex": solution.hash_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "has_challenge_cookie": bool(challenge.captcha_cookie),
                    "init_url": challenge.init_url,
                    "verify_url": challenge.verify_url,
                    "page_url": challenge.page_url,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"nonce": solution.nonce, "hash": solution.hash_hex, "verifyBody": solution.verify_body}
            ticket_payload = solution.ticket_payload
            verify_code = "solved"
            if submit:
                post_url = verify_url or challenge.verify_url or _join_url(base_url or challenge.page_url, VERIFY_PATH)
                if not post_url:
                    errors.append("Pingoo submit requested but verify_url/base_url/page_url is missing")
                    return finish(ok=False, ticket=json.dumps(ticket_payload, separators=(",", ":")), verify_code=verify_code)
                submit_data = self._submit_solution(
                    verify_url=post_url,
                    solution=solution,
                    session=session,
                    proxies=proxies,
                    timeout_sec=timeout_sec,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                diagnostics["submit_status"] = submit_data["status"]
                verified_cookie = submit_data.get("verified_cookie")
                if verified_cookie:
                    diagnostics["verified_cookie"] = verified_cookie
                    ticket_payload[VERIFIED_COOKIE] = verified_cookie
                if submit_data["status"] >= 400 or not verified_cookie:
                    errors.append(f"Pingoo verify failed: HTTP {submit_data['status']}")
                    return finish(ok=False, ticket=json.dumps(ticket_payload, separators=(",", ":")), verify_code="submit_failed")
                verify_code = "verified"
            return finish(ok=True, ticket=json.dumps(ticket_payload, separators=(",", ":")), verify_code=verify_code)
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
        init_url: str | None,
        verify_url: str | None,
        timeout_sec: int,
        session: requests.Session,
        proxies: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> PingooChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_pingoo_challenge(loaded, page_url=base_url, init_url=init_url, verify_url=verify_url)
        if challenge_html:
            text = Path(challenge_html[1:]).read_text(encoding="utf-8") if challenge_html.startswith("@") else challenge_html
            return parse_pingoo_challenge_html(text, page_url=base_url, init_url=init_url, verify_url=verify_url)
        target = init_url or _join_url(base_url, INIT_PATH)
        if target:
            resp = session.get(target, timeout=timeout_sec, proxies=proxies)
            raw["initResponse"] = {
                "status": resp.status_code,
                "url": resp.url,
                "contentType": resp.headers.get("content-type"),
                "setCookieNames": _set_cookie_names(resp.headers.get("set-cookie", "")),
                "bodyPrefix": resp.text[:160],
            }
            resp.raise_for_status()
            data = resp.json()
            cookie_value = _extract_set_cookie_value(resp.headers.get("set-cookie", ""), CHALLENGE_COOKIE)
            if cookie_value:
                data["captcha_cookie"] = cookie_value
            data.setdefault("init_url", resp.url or target)
            if verify_url:
                data.setdefault("verify_url", verify_url)
            elif resp.url:
                data.setdefault("verify_url", _join_url(resp.url, VERIFY_PATH))
            return parse_pingoo_challenge(data, page_url=base_url, init_url=target, verify_url=verify_url)
        raise ValueError("Pingoo solve requires challenge_json/challenge_file/challenge_html/init_url/base_url")

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PingooSolution,
        session: requests.Session,
        proxies: dict[str, str] | None,
        timeout_sec: int,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        resp = session.post(
            verify_url,
            json=solution.verify_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout_sec,
            proxies=proxies,
        )
        header = resp.headers.get("set-cookie", "")
        verified_cookie = _extract_set_cookie_value(header, VERIFIED_COOKIE) or session.cookies.get(VERIFIED_COOKIE)
        data = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "setCookieNames": _set_cookie_names(header),
            "verified_cookie": verified_cookie,
            "bodyPrefix": resp.text[:120],
        }
        raw["verifyResponse"] = data
        return data


def _search_pingoo_range(challenge: str, difficulty: int, begin: int, end: int) -> tuple[str | None, str | None, int]:
    base = hashlib.sha256(_validate_challenge(challenge).encode("utf-8"))
    attempts = 0
    target = "0" * _validate_difficulty(difficulty)
    for value in range(int(begin), int(end)):
        nonce = str(value)
        h = base.copy()
        h.update(nonce.encode("ascii"))
        digest = h.hexdigest()
        attempts += 1
        if digest.startswith(target):
            return nonce, digest, attempts
    return None, None, attempts


def _solution_nonce_hash(solution: PingooSolution | dict[str, Any] | str) -> tuple[str, str | None]:
    if isinstance(solution, PingooSolution):
        return solution.nonce, solution.hash_hex
    if isinstance(solution, dict):
        body = solution.get("verify_body") or solution.get("verifyBody")
        if isinstance(body, dict):
            return _solution_nonce_hash(body)
        nonce = solution.get("nonce")
        digest = solution.get("hash") or solution.get("hash_hex") or solution.get("hashHex")
        if nonce is not None:
            return _nonce_text(nonce), _validate_hash(digest) if digest else None
        if solution.get("ticket") is not None:
            return _solution_nonce_hash(str(solution["ticket"]))
    text = str(solution).strip()
    if text.startswith("{"):
        return _solution_nonce_hash(json.loads(text))
    if ":" in text:
        nonce, digest = text.split(":", 1)
        return _nonce_text(nonce), _validate_hash(digest)
    return _nonce_text(text), None


def _challenge_raw(challenge: PingooChallenge) -> dict[str, Any]:
    return {
        "challenge": challenge.challenge,
        "difficulty": challenge.difficulty,
        "hasCaptchaCookie": bool(challenge.captcha_cookie),
        "pageUrl": challenge.page_url,
        "initUrl": challenge.init_url,
        "verifyUrl": challenge.verify_url,
        "hasHtml": bool(challenge.raw_html),
    }


def _merge_urls(
    item: PingooChallenge,
    *,
    page_url: str | None = None,
    init_url: str | None = None,
    verify_url: str | None = None,
) -> PingooChallenge:
    if page_url is None and init_url is None and verify_url is None:
        return item
    return PingooChallenge(
        challenge=item.challenge,
        difficulty=item.difficulty,
        captcha_cookie=item.captcha_cookie,
        page_url=page_url or item.page_url,
        init_url=init_url or item.init_url,
        verify_url=verify_url or item.verify_url,
        raw_html=item.raw_html,
        raw=item.raw,
    )


def _looks_like_pingoo_html(text: str) -> bool:
    return any(marker in text for marker in ("pingoo-captcha", "/__pingoo/captcha/", "__pingoo_captcha"))


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return html.unescape(match.group(1))
    return None


def _join_url(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    parsed = urlparse(str(base_url))
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.path.rstrip("/") == path.rstrip("/"):
        return str(base_url)
    return urljoin(f"{parsed.scheme}://{parsed.netloc}/", path.lstrip("/"))


def _request_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    out = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        out.update({str(k): str(v) for k, v in headers.items()})
    return out


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


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


def _extract_set_cookie_value(header: str, name: str) -> str | None:
    if not header:
        return None
    match = re.search(rf"(?:^|[,;]\s*){re.escape(name)}=([^;]*)", header)
    return match.group(1) if match else None


def _extract_cookie_value(text: str, name: str) -> str | None:
    if not text:
        return None
    match = re.search(rf"(?:^|[,;\s]){re.escape(name)}=([^;\s]+)", text)
    return match.group(1) if match else text.strip()


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)


def _validate_challenge(value: Any) -> str:
    text = str(value).strip()
    if not text or any(ord(ch) < 32 for ch in text):
        raise ValueError("Pingoo challenge must be a non-empty printable string")
    return text


def _validate_difficulty(value: Any) -> int:
    diff = int(value)
    if diff < 0 or diff > 64:
        raise ValueError("Pingoo difficulty must be 0..64 hex nibbles")
    return diff


def _validate_hash(value: Any) -> str:
    text = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError("Pingoo hash must be 64 hex chars")
    return text


def _validate_search(start: Any, max_attempts: Any) -> tuple[int, int]:
    s = int(start)
    m = int(max_attempts)
    if s < 0:
        raise ValueError("start must be non-negative")
    if m <= 0:
        raise ValueError("max_attempts must be positive")
    return s, m


def _nonce_text(value: int | str) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Pingoo nonce must be non-negative")
        return str(value)
    text = str(value).strip()
    if not text or not re.fullmatch(r"\d+", text):
        raise ValueError("Pingoo nonce must be decimal digits")
    return text


def _b64url_decode(value: str) -> bytes:
    text = str(value).strip()
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


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


__all__ = [
    "CHALLENGE_COOKIE",
    "VERIFIED_COOKIE",
    "PingooChallenge",
    "PingooSolution",
    "PingooSolver",
    "decode_pingoo_jwt_claims",
    "parse_pingoo_challenge",
    "parse_pingoo_challenge_html",
    "pingoo_hash_hex",
    "pingoo_hash_matches",
    "solve_pingoo_challenge",
    "solve_pingoo_nonce",
    "verify_pingoo_solution",
]
