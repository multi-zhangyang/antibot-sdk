from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import os
import re
import secrets
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

DEFAULT_BASE_URL = "https://example.com"
DEFAULT_TIMEOUT = 10
DEFAULT_DIFFICULTY = 20
DEFAULT_MAX_ATTEMPTS = 5_000_000
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_VERIFY_PATH = "/__guardianwaf/challenge/verify"
DEFAULT_COOKIE_NAME = "__gwaf_challenge"
DEFAULT_COOKIE_TTL = 3600
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/plain,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass(frozen=True, slots=True)
class GuardianWafChallenge:
    challenge: str
    difficulty: int = DEFAULT_DIFFICULTY
    redirect: str = "/"
    page_url: str | None = None
    verify_path: str = DEFAULT_VERIFY_PATH
    cookie_name: str = DEFAULT_COOKIE_NAME
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def verify_url(self) -> str | None:
        if not self.page_url:
            return self.verify_path if _is_absolute_url(self.verify_path) else None
        return _resolve_url(self.page_url, self.page_url, self.verify_path)


@dataclass(frozen=True, slots=True)
class GuardianWafSolution:
    challenge: GuardianWafChallenge
    nonce: int
    nonce_text: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None
    cookie_value: str | None = None

    @property
    def submit_body(self) -> dict[str, str]:
        return {"challenge": self.challenge.challenge, "nonce": self.nonce_text, "redirect": self.challenge.redirect or "/"}


def make_guardianwaf_challenge(*, seed: bytes | str | None = None, bytes_len: int = 16) -> str:
    """Create a client-selected GuardianWAF challenge string for the stateless verify path."""

    if seed is None:
        return secrets.token_hex(int(bytes_len))
    raw = seed if isinstance(seed, bytes) else str(seed).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[: max(2, int(bytes_len) * 2)]


def guardianwaf_digest(challenge: str, nonce: int | str) -> bytes:
    return hashlib.sha256((_validate_challenge(challenge) + _nonce_text(nonce)).encode("utf-8")).digest()


def guardianwaf_hash_hex(challenge: str, nonce: int | str) -> str:
    return guardianwaf_digest(challenge, nonce).hex()


def guardianwaf_has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    whole, mask = _guardianwaf_zero_check(bits)
    if len(digest) < whole + (1 if mask else 0):
        return False
    if whole and digest[:whole] != b"\x00" * whole:
        return False
    if mask:
        return (digest[whole] & mask) == 0
    return True


def verify_guardianwaf_pow(challenge: str, nonce: int | str, difficulty: int = DEFAULT_DIFFICULTY) -> bool:
    try:
        return guardianwaf_has_leading_zero_bits(guardianwaf_digest(challenge, nonce), int(difficulty))
    except Exception:
        return False


def solve_guardianwaf_nonce(
    challenge: str,
    difficulty: int = DEFAULT_DIFFICULTY,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[int, str, str, int]:
    prefix = _validate_challenge(challenge).encode("utf-8")
    difficulty = _validate_difficulty(difficulty)
    start = int(start)
    max_attempts = int(max_attempts)
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        nonce, digest, attempts = _search_guardianwaf_range(prefix, difficulty, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no GuardianWAF nonce found within {max_attempts} attempts")
        return nonce, format(nonce, "x"), digest.hex(), attempts

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_guardianwaf_range, prefix, difficulty, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, _end = futures.pop(fut)
                nonce, digest, _attempts = fut.result()
                if nonce is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return nonce, format(nonce, "x"), digest.hex(), max(0, begin - start + _attempts)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_guardianwaf_range, prefix, difficulty, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no GuardianWAF nonce found within {max_attempts} attempts")


def parse_guardianwaf_challenge_html(html_text: str, *, page_url: str | None = None) -> GuardianWafChallenge:
    text = str(html_text)
    challenge = _js_string_var(text, "C") or _hidden_value(text, "challenge")
    difficulty_text = _js_number_var(text, "D") or _hidden_value(text, "difficulty")
    redirect = _js_string_var(text, "R") or _hidden_value(text, "redirect") or _request_uri_from_html(text) or "/"
    if not challenge:
        raise ValueError("GuardianWAF challenge HTML does not contain JS variable C/challenge")
    difficulty = _validate_difficulty(int(difficulty_text or DEFAULT_DIFFICULTY))
    verify_path = _form_action(text) or DEFAULT_VERIFY_PATH
    return GuardianWafChallenge(
        challenge=_validate_challenge(challenge),
        difficulty=difficulty,
        redirect=_safe_redirect(redirect),
        page_url=page_url,
        verify_path=verify_path,
        cookie_name=DEFAULT_COOKIE_NAME,
        raw_html=text,
    )


def parse_guardianwaf_challenge(data: Any, *, page_url: str | None = None) -> GuardianWafChallenge:
    if isinstance(data, GuardianWafChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_guardianwaf_challenge(Path(text[1:]).read_text(encoding="utf-8"), page_url=page_url)
        if text.startswith("{"):
            data = json.loads(text)
        elif _looks_like_guardianwaf_challenge(text) or _has_guardianwaf_js_vars(text):
            return parse_guardianwaf_challenge_html(text, page_url=page_url)
        else:
            return GuardianWafChallenge(challenge=_validate_challenge(text), page_url=page_url)
    if not isinstance(data, dict):
        raise ValueError("GuardianWAF challenge must be JSON object, HTML, or challenge string")
    if "html" in data:
        return parse_guardianwaf_challenge_html(str(data["html"]), page_url=data.get("page_url") or data.get("url") or page_url)
    challenge = data.get("challenge") or data.get("C") or data.get("pow_challenge")
    if not challenge:
        raise ValueError("GuardianWAF challenge JSON requires challenge/C")
    difficulty_value = _first_present(data, "difficulty", "D", "bits", default=DEFAULT_DIFFICULTY)
    return GuardianWafChallenge(
        challenge=_validate_challenge(str(challenge)),
        difficulty=_validate_difficulty(int(difficulty_value)),
        redirect=_safe_redirect(str(data.get("redirect") or data.get("R") or "/")),
        page_url=str(data.get("page_url") or data.get("url") or page_url or "") or None,
        verify_path=str(data.get("verify_path") or data.get("verifyPath") or data.get("verify_url") or data.get("verifyUrl") or DEFAULT_VERIFY_PATH),
        cookie_name=_validate_cookie_name(data.get("cookie_name") or data.get("cookieName") or DEFAULT_COOKIE_NAME),
        raw=data,
    )


def solve_guardianwaf_challenge(
    challenge: GuardianWafChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    secret: str | bytes | None = None,
    client_ip: str = "127.0.0.1",
    cookie_ttl: int = DEFAULT_COOKIE_TTL,
    now: int | None = None,
) -> GuardianWafSolution:
    started = time.monotonic()
    item = parse_guardianwaf_challenge(challenge)
    nonce, nonce_text, digest_hex, attempts_hint = solve_guardianwaf_nonce(
        item.challenge,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    cookie_value = None
    if secret:
        cookie_value = make_guardianwaf_cookie(secret=secret, client_ip=client_ip, ttl=cookie_ttl, now=now)
    return GuardianWafSolution(
        challenge=item,
        nonce=nonce,
        nonce_text=nonce_text,
        digest_hex=digest_hex,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
        cookie_value=cookie_value,
    )


def verify_guardianwaf_solution(
    challenge: GuardianWafChallenge | dict[str, Any] | str,
    solution: GuardianWafSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_guardianwaf_challenge(challenge)
        if isinstance(solution, GuardianWafSolution):
            nonce = solution.nonce_text
        elif isinstance(solution, dict):
            nonce = solution.get("nonce") or solution.get("nonce_text") or solution.get("nonceText") or solution.get("ticket")
        else:
            nonce = str(solution)
        if nonce is None:
            return False
        return verify_guardianwaf_pow(item.challenge, str(nonce), item.difficulty)
    except Exception:
        return False


def make_guardianwaf_cookie(
    *,
    secret: str | bytes,
    client_ip: str = "127.0.0.1",
    ttl: int = DEFAULT_COOKIE_TTL,
    now: int | None = None,
) -> str:
    expiry = int(now if now is not None else time.time()) + int(ttl)
    payload = f"{expiry}|{client_ip}"
    mac = hmac.new(_secret_bytes(secret), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return payload.encode("utf-8").hex() + "." + mac


def verify_guardianwaf_cookie(
    cookie: str,
    *,
    secret: str | bytes,
    client_ip: str = "127.0.0.1",
    now: int | None = None,
) -> bool:
    try:
        payload_hex, mac = str(cookie).split(".", 1)
        payload = bytes.fromhex(payload_hex).decode("utf-8")
        expected = hmac.new(_secret_bytes(secret), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return False
        expiry_text, ip = payload.split("|", 1)
        if ip != client_ip:
            return False
        return int(expiry_text) >= int(now if now is not None else time.time())
    except Exception:
        return False


class GuardianWafSolver:
    """Protocol solver for GuardianWAF's JS SHA-256 PoW challenge.

    GuardianWAF renders an inline WebCrypto challenge page with `C`, `D` and
    `R`, then accepts POST /__guardianwaf/challenge/verify and issues an
    HMAC-signed, IP-bound `__gwaf_challenge` cookie. The upstream verifier is
    stateless for the challenge string itself, so the SDK supports both normal
    page-parse mode and direct client-selected challenge mode. No browser is
    started.
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
        challenge_html: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        direct: bool = False,
        difficulty: int | None = None,
        redirect: str | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        secret: str | None = None,
        client_ip: str = "127.0.0.1",
        cookie_name: str | None = None,
        cookie_ttl: int = DEFAULT_COOKIE_TTL,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "page_url": page_url,
            "verify_url": verify_url,
            "submit": submit,
            "direct": direct,
            "difficulty_override": difficulty,
            "start": start,
            "max_attempts": max_attempts,
            "workers": workers,
            "chunk_size": chunk_size,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "cookie_name_override": cookie_name,
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
                out = output_root / "guardianwaf_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="guardianwaf",
                ok=ok,
                captcha_type="unsigned_js_pow_hmac_cookie",
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
                challenge_html=challenge_html,
                direct=direct,
                difficulty=difficulty,
                redirect=redirect,
                cookie_name=cookie_name,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            if difficulty is not None and direct:
                challenge = _merge_guardianwaf_meta(challenge, difficulty=int(difficulty), redirect=redirect)
            elif redirect is not None:
                challenge = _merge_guardianwaf_meta(challenge, redirect=redirect)
            if secret and not submit and not verify_url:
                cookie_value = make_guardianwaf_cookie(
                    secret=secret,
                    client_ip=client_ip,
                    ttl=cookie_ttl,
                )
                diagnostics.update(
                    {
                        "challenge": challenge.challenge,
                        "difficulty": challenge.difficulty,
                        "redirect": challenge.redirect,
                        "verify_path": challenge.verify_path,
                        "cookie_name": challenge.cookie_name,
                        "pow_skipped": True,
                        "protocol_gap": "challenge_cookie_can_be_minted_with_known_secret",
                        "cookie_binding": ["client_ip", "secret_hmac", "expiry"],
                    }
                )
                raw["challenge"] = _challenge_raw(challenge)
                raw["solution"] = {
                    "localCookie": {"name": challenge.cookie_name, "value": cookie_value},
                    "powSkipped": True,
                }
                final_ticket = json.dumps(
                    {"cookie_name": challenge.cookie_name, "cookie_value": cookie_value},
                    separators=(",", ":"),
                )
                return finish(ok=True, ticket=final_ticket, verify_code="local_cookie")
            solution = solve_guardianwaf_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
                secret=secret,
                client_ip=client_ip,
                cookie_ttl=cookie_ttl,
            )
            if not verify_guardianwaf_solution(challenge, solution):
                errors.append("GuardianWAF internal solution verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            diagnostics.update(
                {
                    "challenge": challenge.challenge,
                    "difficulty": challenge.difficulty,
                    "redirect": challenge.redirect,
                    "verify_path": challenge.verify_path,
                    "cookie_name": challenge.cookie_name,
                    "nonce": solution.nonce,
                    "nonce_text": solution.nonce_text,
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "protocol_gap": "challenge_string_not_signed_or_server_tracked",
                    "cookie_binding": ["client_ip", "secret_hmac", "expiry"],
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"body": solution.submit_body, "nonce": solution.nonce, "digestHex": solution.digest_hex, "elapsedMs": solution.elapsed_ms}
            if solution.cookie_value:
                raw["solution"]["localCookie"] = {"name": challenge.cookie_name, "value": solution.cookie_value}
            final_ticket = json.dumps(solution.submit_body, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url:
                final_ticket, verify_code = self._submit(
                    session=session,
                    base_url=base_url,
                    page_url=page_url or challenge.page_url,
                    verify_url=verify_url or challenge.verify_url,
                    verify_path=challenge.verify_path,
                    body=solution.submit_body,
                    cookie_name=challenge.cookie_name,
                    timeout_sec=timeout_sec,
                    proxies=proxies,
                    headers=merged_headers,
                    raw=raw,
                    errors=errors,
                )
                if verify_code not in {"cookie_issued", "verified", "redirected"}:
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
            elif solution.cookie_value:
                final_ticket = json.dumps({"cookie_name": challenge.cookie_name, "cookie_value": solution.cookie_value}, separators=(",", ":"))
                verify_code = "local_cookie"
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
        challenge_html: str | None,
        direct: bool,
        difficulty: int | None,
        redirect: str | None,
        cookie_name: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> GuardianWafChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return _merge_guardianwaf_meta(
                parse_guardianwaf_challenge(loaded, page_url=page_url),
                difficulty=difficulty,
                redirect=redirect,
                cookie_name=cookie_name,
            )
        if challenge_html:
            text = Path(challenge_html[1:]).read_text(encoding="utf-8") if challenge_html.startswith("@") else challenge_html
            return _merge_guardianwaf_meta(
                parse_guardianwaf_challenge_html(text, page_url=page_url),
                difficulty=difficulty,
                redirect=redirect,
                cookie_name=cookie_name,
            )
        if direct:
            return GuardianWafChallenge(
                challenge=make_guardianwaf_challenge(),
                difficulty=_validate_difficulty(
                    difficulty if difficulty is not None else DEFAULT_DIFFICULTY
                ),
                redirect=_safe_redirect(redirect or "/"),
                page_url=page_url or base_url,
                cookie_name=_validate_cookie_name(cookie_name or DEFAULT_COOKIE_NAME),
                raw={"direct": True},
            )
        url = page_url or base_url
        resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
        raw["pageRequest"] = {"url": url, "headers": _kept_headers(headers)}
        raw["pageResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("Content-Type"),
            "xGuardianWafChallenge": resp.headers.get("X-GuardianWAF-Challenge"),
        }
        if resp.status_code >= 500:
            raw["pageResponse"]["text"] = resp.text[:500]
            raise RuntimeError(f"GuardianWAF page HTTP {resp.status_code}")
        return _merge_guardianwaf_meta(
            parse_guardianwaf_challenge_html(resp.text, page_url=resp.url),
            difficulty=difficulty,
            redirect=redirect,
            cookie_name=cookie_name,
        )

    def _submit(
        self,
        *,
        session: requests.Session,
        base_url: str,
        page_url: str | None,
        verify_url: str | None,
        verify_path: str,
        body: dict[str, str],
        cookie_name: str,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        url = verify_url or _resolve_url(base_url, page_url, verify_path)
        submit_headers = dict(headers)
        if page_url:
            submit_headers.setdefault("Referer", page_url)
        resp = session.post(url, data=body, headers=submit_headers, timeout=timeout_sec, proxies=proxies, allow_redirects=False)
        set_cookie = resp.headers.get("Set-Cookie", "")
        raw["verifyRequest"] = {"url": url, "body": body, "headers": _kept_headers(submit_headers)}
        raw["verifyResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "location": resp.headers.get("Location"),
            "contentType": resp.headers.get("Content-Type"),
            "setCookieNames": _set_cookie_names(set_cookie),
        }
        if resp.status_code >= 400:
            raw["verifyResponse"]["text"] = resp.text[:500]
            errors.append(resp.text[:120] or f"http_{resp.status_code}")
            return json.dumps(body, separators=(",", ":")), f"http_{resp.status_code}"
        cookie_val = session.cookies.get(cookie_name) or _extract_set_cookie_value(set_cookie, cookie_name)
        ticket = json.dumps({"cookie_name": cookie_name, "cookie_value": cookie_val, "location": resp.headers.get("Location")}, separators=(",", ":"))
        if cookie_val:
            return ticket, "cookie_issued"
        if resp.status_code in {301, 302, 303, 307, 308}:
            return ticket, "redirected"
        if _looks_like_guardianwaf_challenge(resp.text):
            raw["verifyResponse"]["text"] = resp.text[:500]
            errors.append("verify_failed_challenge_returned")
            return ticket, "verify_failed"
        return ticket, "verified"


def _search_guardianwaf_range(prefix: bytes, difficulty: int, begin: int, end: int) -> tuple[int | None, bytes | None, int]:
    whole, mask = _guardianwaf_zero_check(difficulty)
    zero_prefix = b"\x00" * whole
    base_hash = hashlib.sha256(prefix)
    copy_hash = base_hash.copy
    attempts = 0
    for nonce in range(int(begin), int(end)):
        h = copy_hash()
        h.update(f"{nonce:x}".encode("ascii"))
        digest = h.digest()
        attempts += 1
        if zero_prefix and not digest.startswith(zero_prefix):
            continue
        if mask and digest[whole] & mask:
            continue
        if len(digest) >= whole + (1 if mask else 0):
            return nonce, digest, attempts
    return None, None, attempts


def _validate_challenge(value: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError("GuardianWAF challenge must be non-empty")
    if len(text) > 512:
        raise ValueError("GuardianWAF challenge is too long")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError("GuardianWAF challenge contains control characters")
    return text


def _validate_difficulty(value: Any) -> int:
    try:
        bits = int(value)
    except Exception as exc:
        raise ValueError("GuardianWAF difficulty must be an integer") from exc
    if bits < 0 or bits > 256:
        raise ValueError("GuardianWAF difficulty must be 0..256")
    return bits


def _validate_cookie_name(value: Any) -> str:
    name = str(value or DEFAULT_COOKIE_NAME).strip()
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}", name):
        raise ValueError("GuardianWAF cookie name must be a valid HTTP cookie token")
    return name


def _guardianwaf_zero_check(bits: int) -> tuple[int, int]:
    bits = _validate_difficulty(bits)
    whole, rem = divmod(bits, 8)
    mask = ((0xFF << (8 - rem)) & 0xFF) if rem else 0
    return whole, mask


def _nonce_text(value: int | str) -> str:
    if isinstance(value, int):
        ivalue = int(value)
        if ivalue < 0:
            raise ValueError("nonce must be non-negative")
        return format(ivalue, "x")
    text = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", text):
        raise ValueError("GuardianWAF nonce must be a hex counter string")
    return text


def _js_string_var(text: str, name: str) -> str | None:
    patterns = [
        rf"\b(?:var|let|const)\s+{re.escape(name)}\s*=\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))",
        rf"[,;]\s*{re.escape(name)}\s*=\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))",
    ]
    raw = _first_match(text, patterns)
    if raw is None:
        return None
    return _decode_js_string(raw)


def _js_number_var(text: str, name: str) -> str | None:
    return _first_match(
        text,
        [
            rf"\b(?:var|let|const)\s+{re.escape(name)}\s*=\s*(\d+)",
            rf"[,;]\s*{re.escape(name)}\s*=\s*(\d+)",
        ],
    )


def _decode_js_string(raw: str) -> str:
    try:
        return str(json.loads(raw))
    except Exception:
        quote = raw[0]
        body = raw[1:-1] if raw.endswith(quote) else raw.strip("'\"")
        body = body.replace(r"\/", "/").replace(r"\'", "'")
        try:
            return bytes(body, "utf-8").decode("unicode_escape")
        except Exception:
            return body


def _hidden_value(text: str, name: str) -> str | None:
    patterns = [
        rf"<input\b(?=[^>]*\bname=[\"']{re.escape(name)}[\"'])(?=[^>]*\bvalue=[\"']([^\"']*)[\"'])[^>]*>",
        rf"<input\b(?=[^>]*\bvalue=[\"']([^\"']*)[\"'])(?=[^>]*\bname=[\"']{re.escape(name)}[\"'])[^>]*>",
    ]
    value = _first_match(text, patterns)
    return html.unescape(value) if value is not None else None


def _form_action(text: str) -> str | None:
    value = _first_match(text, [r"<form\b(?=[^>]*\baction=[\"']([^\"']*)[\"'])[^>]*>"])
    return html.unescape(value) if value else None


def _request_uri_from_html(text: str) -> str | None:
    return _first_match(text, [r"redirect\s*[:=]\s*[\"']([^\"']+)[\"']"])


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return html.unescape(match.group(1))
    return None


def _first_present(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _safe_redirect(value: str | None) -> str:
    redirect = str(value or "/")
    if not redirect.startswith("/") or redirect.startswith("//") or any(ch in redirect for ch in "\\@"):
        return "/"
    return redirect


def _merge_guardianwaf_meta(
    item: GuardianWafChallenge,
    *,
    difficulty: int | None = None,
    redirect: str | None = None,
    cookie_name: str | None = None,
) -> GuardianWafChallenge:
    return GuardianWafChallenge(
        challenge=item.challenge,
        difficulty=_validate_difficulty(difficulty if difficulty is not None else item.difficulty),
        redirect=_safe_redirect(redirect if redirect is not None else item.redirect),
        page_url=item.page_url,
        verify_path=item.verify_path,
        cookie_name=_validate_cookie_name(cookie_name or item.cookie_name),
        raw_html=item.raw_html,
        raw=item.raw,
    )


def _challenge_raw(challenge: GuardianWafChallenge) -> dict[str, Any]:
    return {
        "challenge": challenge.challenge,
        "difficulty": challenge.difficulty,
        "redirect": challenge.redirect,
        "pageUrl": challenge.page_url,
        "verifyPath": challenge.verify_path,
        "cookieName": challenge.cookie_name,
        "hasHtml": bool(challenge.raw_html),
        "direct": bool((challenge.raw or {}).get("direct")) if isinstance(challenge.raw, dict) else False,
    }


def _looks_like_guardianwaf_challenge(text: str) -> bool:
    return any(marker in text for marker in ("X-GuardianWAF-Challenge", "__guardianwaf/challenge/verify", "Verifying your browser", "GuardianWAF"))


def _has_guardianwaf_js_vars(text: str) -> bool:
    return bool(
        re.search(r"\b(?:var|let|const)\s+C\s*=", text)
        and re.search(r"(?:\b(?:var|let|const)\s+D\s*=|[,;]\s*D\s*=)", text)
    )


def _is_absolute_url(url: str) -> bool:
    return bool(re.match(r"^https?://", str(url), re.I))


def _resolve_url(base_url: str, page_url: str | None, path_or_url: str) -> str:
    if _is_absolute_url(path_or_url):
        return path_or_url
    if str(path_or_url).startswith("/"):
        return urljoin(base_url, path_or_url)
    return urljoin(page_url or base_url, path_or_url)


def _kept_headers(headers: dict[str, str]) -> dict[str, str]:
    names = ("User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Pragma", "Referer")
    return {k: headers[k] for k in names if k in headers}


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
    match = re.search(rf"(?:^|[,;]\s*){re.escape(name)}=([^;]+)", header)
    return match.group(1) if match else None


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)


def _secret_bytes(secret: str | bytes) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def _url_host(url: str | None) -> str | None:
    if not url:
        return None
    return urlparse(url).netloc or None
