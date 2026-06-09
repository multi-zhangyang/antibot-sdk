from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
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

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://example.com"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_ATTEMPTS = 5_000_000
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True, slots=True)
class PowxyChallenge:
    identifier_b64: str
    difficulty: int = 20
    page_url: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def identifier(self) -> bytes:
        return decode_powxy_identifier(self.identifier_b64)


@dataclass(frozen=True, slots=True)
class PowxySolution:
    challenge: PowxyChallenge
    nonce: int
    nonce_bytes: bytes
    powxy_field: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None

    @property
    def verify_body(self) -> dict[str, str]:
        return {"powxy": self.powxy_field}


def decode_powxy_identifier(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        text = html.unescape(str(value).strip())
        raw = base64.b64decode(text, validate=True)
    if len(raw) != 32:
        raise ValueError(f"Powxy identifier must decode to 32 bytes, got {len(raw)}")
    return raw


def powxy_nonce_bytes(nonce: int) -> bytes:
    nonce = int(nonce)
    if nonce < 0 or nonce > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Powxy nonce must fit uint64")
    return struct.pack("<Q", nonce)


def powxy_nonce_b64(nonce: int) -> str:
    return base64.b64encode(powxy_nonce_bytes(nonce)).decode("ascii")


def powxy_digest(identifier: bytes | str, nonce: int | bytes) -> bytes:
    ident = decode_powxy_identifier(identifier) if isinstance(identifier, str) else identifier
    nonce_bytes = nonce if isinstance(nonce, bytes) else powxy_nonce_bytes(int(nonce))
    return hashlib.sha256(ident + nonce_bytes).digest()


def validate_powxy_bits(digest: bytes, difficulty: int) -> bool:
    difficulty = int(difficulty)
    if difficulty < 0 or difficulty > len(digest) * 8:
        raise ValueError("difficulty out of range")
    whole, rem = divmod(difficulty, 8)
    if any(digest[i] != 0 for i in range(whole)):
        return False
    if rem:
        return (digest[whole] & (0xFF << (8 - rem))) == 0
    return True


def verify_powxy_nonce(identifier: bytes | str, nonce: int | bytes | str, difficulty: int) -> bool:
    try:
        if isinstance(nonce, str):
            nonce_bytes = base64.b64decode(nonce, validate=True)
        elif isinstance(nonce, bytes):
            nonce_bytes = nonce
        else:
            nonce_bytes = powxy_nonce_bytes(int(nonce))
        if len(nonce_bytes) != 8:
            return False
        return validate_powxy_bits(powxy_digest(identifier, nonce_bytes), int(difficulty))
    except Exception:
        return False


def solve_powxy_nonce(
    identifier: bytes | str,
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> tuple[int, bytes, str, int]:
    ident = decode_powxy_identifier(identifier) if isinstance(identifier, str) else identifier
    if len(ident) != 32:
        raise ValueError("Powxy identifier must be 32 bytes")
    difficulty = int(difficulty)
    if difficulty < 1 or difficulty > 64:
        raise ValueError("Powxy difficulty must be 1..64 for SDK search")
    start = int(start)
    max_attempts = int(max_attempts)
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        nonce, digest = _search_powxy_range(ident, difficulty, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no Powxy nonce found within {max_attempts} attempts")
        return nonce, powxy_nonce_bytes(nonce), digest.hex(), nonce - start + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_powxy_range, ident, difficulty, next_start, end)] = (next_start, end)
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
                    return nonce, powxy_nonce_bytes(nonce), digest.hex(), max(0, end - start)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_powxy_range, ident, difficulty, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no Powxy nonce found within {max_attempts} attempts")


def parse_powxy_challenge_html(html_text: str, *, page_url: str | None = None) -> PowxyChallenge:
    ident = _html_attr(html_text, "data-identifier") or _tag_text(html_text, "identifier")
    diff_text = _html_attr(html_text, "data-difficulty")
    if not diff_text:
        match = re.search(r"at least\s+(\d+)\s+zero bits", html_text, re.I)
        diff_text = match.group(1) if match else None
    if not ident:
        raise ValueError("Powxy challenge HTML does not contain identifier")
    difficulty = int(diff_text or 20)
    decode_powxy_identifier(ident)
    return PowxyChallenge(identifier_b64=html.unescape(ident).strip(), difficulty=difficulty, page_url=page_url, raw_html=html_text)


def parse_powxy_challenge(data: Any) -> PowxyChallenge:
    if isinstance(data, PowxyChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            data = json.loads(text)
        elif "data-identifier" in text or "id=\"identifier\"" in text or "id='identifier'" in text:
            return parse_powxy_challenge_html(text)
        else:
            decode_powxy_identifier(text)
            return PowxyChallenge(identifier_b64=text)
    if not isinstance(data, dict):
        raise ValueError("Powxy challenge must be JSON object, HTML, or identifier base64")
    if "html" in data:
        return parse_powxy_challenge_html(str(data["html"]), page_url=data.get("page_url") or data.get("url"))
    ident = data.get("identifier") or data.get("identifier_b64") or data.get("challenge")
    if not ident:
        raise ValueError("Powxy challenge JSON requires identifier")
    decode_powxy_identifier(str(ident))
    return PowxyChallenge(
        identifier_b64=str(ident),
        difficulty=int(data.get("difficulty") or data.get("need_bits") or data.get("bits") or 20),
        page_url=str(data.get("page_url") or data.get("url") or "") or None,
        raw=data,
    )


def solve_powxy_challenge(
    challenge: PowxyChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> PowxySolution:
    started = time.monotonic()
    item = parse_powxy_challenge(challenge)
    nonce, nonce_bytes, digest_hex, attempts_hint = solve_powxy_nonce(
        item.identifier,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return PowxySolution(
        challenge=item,
        nonce=nonce,
        nonce_bytes=nonce_bytes,
        powxy_field=base64.b64encode(nonce_bytes).decode("ascii"),
        digest_hex=digest_hex,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
    )


def verify_powxy_solution(challenge: PowxyChallenge | dict[str, Any] | str, solution: PowxySolution | dict[str, Any] | str) -> bool:
    try:
        item = parse_powxy_challenge(challenge)
        if isinstance(solution, PowxySolution):
            field = solution.powxy_field
        elif isinstance(solution, dict):
            field = solution.get("powxy") or solution.get("nonce_b64") or solution.get("nonce")
        else:
            field = str(solution)
        if field is None:
            return False
        return verify_powxy_nonce(item.identifier, str(field), item.difficulty)
    except Exception:
        return False


def make_powxy_identifier(
    *,
    remote_ip: str,
    user_agent: str,
    accept_encoding: str,
    accept_language: str,
    privkey_hash: bytes,
    unix_time: int | None = None,
) -> bytes:
    """Reproduce powxy's identifier derivation for local mocks/fixtures.

    The live server keeps privkey private, so SDK usually parses the base64
    identifier from the challenge page. This helper mirrors source behavior for
    deterministic tests: SHA256(go-varint(week) padded to 10 bytes || IP || UA
    || Accept-Encoding || Accept-Language || SHA256(privkey)).
    """
    if len(privkey_hash) != 32:
        raise ValueError("privkey_hash must be 32 bytes")
    week = int((unix_time if unix_time is not None else time.time()) // 604800)
    return hashlib.sha256(
        _go_put_varint_10(week)
        + remote_ip.encode()
        + user_agent.encode()
        + accept_encoding.encode()
        + accept_language.encode()
        + privkey_hash
    ).digest()


def powxy_cookie_hmac(identifier: bytes, privkey: bytes) -> str:
    return base64.b64encode(hmac.new(privkey, identifier, hashlib.sha256).digest()).decode("ascii")


class PowxySolver:
    """Protocol solver for powxy reverse-proxy PoW WAF.

    It parses the challenge page's base64 identifier, solves
    SHA256(identifier||uint64_le(nonce)) leading-zero-bit PoW, and POSTs the
    base64 nonce field to receive the powxy HMAC cookie. No browser is started.
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
        submit_url: str | None = None,
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
                out = output_root / "powxy_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powxy",
                ok=ok,
                captcha_type="reverse_proxy_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("identifier_b64"),
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
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_powxy_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            diagnostics.update(
                {
                    "identifier_b64": challenge.identifier_b64,
                    "identifier_len": len(challenge.identifier),
                    "difficulty": challenge.difficulty,
                    "nonce": solution.nonce,
                    "nonce_b64": solution.powxy_field,
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "environment_headers": ["User-Agent", "Accept-Encoding", "Accept-Language"],
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"body": solution.verify_body, "nonce": solution.nonce, "digestHex": solution.digest_hex, "elapsedMs": solution.elapsed_ms}
            final_ticket = json.dumps(solution.verify_body, separators=(",", ":"))
            verify_code = "solved"
            if submit or submit_url:
                final_ticket, verify_code = self._submit(
                    session=session,
                    submit_url=submit_url or challenge.page_url or page_url or base_url,
                    body=solution.verify_body,
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
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> PowxyChallenge:
        if challenge_json is not None:
            return parse_powxy_challenge(_load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json)
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            return parse_powxy_challenge(loaded)
        url = page_url or base_url
        resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
        raw["pageRequest"] = {"url": url, "headers": {k: headers[k] for k in ("User-Agent", "Accept-Encoding", "Accept-Language") if k in headers}}
        raw["pageResponse"] = {"status": resp.status_code, "url": resp.url, "setCookieNames": _set_cookie_names(resp.headers.get("Set-Cookie", ""))}
        if resp.status_code >= 500:
            raw["pageResponse"]["text"] = resp.text[:500]
            raise RuntimeError(f"Powxy page HTTP {resp.status_code}")
        return parse_powxy_challenge_html(resp.text, page_url=url)

    def _submit(
        self,
        *,
        session: requests.Session,
        submit_url: str,
        body: dict[str, str],
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        resp = session.post(submit_url, data=body, headers=headers, timeout=timeout_sec, proxies=proxies, allow_redirects=False)
        raw["verifyRequest"] = {"url": submit_url, "body": body, "headers": {k: headers[k] for k in ("User-Agent", "Accept-Encoding", "Accept-Language") if k in headers}}
        raw["verifyResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "setCookieNames": _set_cookie_names(resp.headers.get("Set-Cookie", "")),
            "location": resp.headers.get("Location"),
        }
        if resp.status_code >= 400:
            raw["verifyResponse"]["text"] = resp.text[:500]
            errors.append(resp.text[:120] or "verify_failed")
            return json.dumps(body, separators=(",", ":")), f"http_{resp.status_code}"
        powxy_cookie = session.cookies.get("powxy") or _extract_set_cookie_value(resp.headers.get("Set-Cookie", ""), "powxy")
        success = bool(powxy_cookie) or resp.status_code in {302, 303, 307, 308}
        if success:
            ticket = json.dumps({"powxy_cookie": bool(powxy_cookie), "location": resp.headers.get("Location")}, separators=(",", ":"))
            return ticket, "verified"
        if "Proof-of-work challenge" in resp.text:
            errors.append("verify_failed_challenge_returned")
        else:
            errors.append("verify_failed")
        raw["verifyResponse"]["text"] = resp.text[:500]
        return json.dumps(body, separators=(",", ":")), "verify_failed"


def _search_powxy_range(identifier: bytes, difficulty: int, begin: int, end: int) -> tuple[int | None, bytes | None]:
    prefix = bytes(identifier)
    for nonce in range(int(begin), int(end)):
        digest = hashlib.sha256(prefix + struct.pack("<Q", nonce)).digest()
        if validate_powxy_bits(digest, difficulty):
            return nonce, digest
    return None, None


def _html_attr(html_text: str, attr: str) -> str | None:
    match = re.search(rf"\b{re.escape(attr)}\s*=\s*\"([^\"]*)\"", html_text, re.I)
    if not match:
        match = re.search(rf"\b{re.escape(attr)}\s*=\s*'([^']*)'", html_text, re.I)
    return html.unescape(match.group(1)) if match else None


def _tag_text(html_text: str, element_id: str) -> str | None:
    match = re.search(rf"<[^>]+\bid\s*=\s*[\"']{re.escape(element_id)}[\"'][^>]*>(.*?)</[^>]+>", html_text, re.I | re.S)
    if not match:
        return None
    return html.unescape(re.sub(r"<[^>]+>", "", match.group(1)).strip())


def _challenge_raw(challenge: PowxyChallenge) -> dict[str, Any]:
    return {
        "identifier_b64": challenge.identifier_b64,
        "identifier_len": len(challenge.identifier),
        "difficulty": challenge.difficulty,
        "page_url": challenge.page_url,
        "has_html": bool(challenge.raw_html),
    }


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
    return json.loads(text) if text[0] in "{[" else text


def _extract_set_cookie_value(header: str, name: str) -> str | None:
    if not header:
        return None
    match = re.search(rf"(?:^|[,;]\s*){re.escape(name)}=([^;]+)", header)
    return match.group(1) if match else None


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)


def _go_put_varint_10(value: int) -> bytes:
    ux = (int(value) << 1) if value >= 0 else ((-int(value) << 1) - 1)
    out = bytearray(10)
    i = 0
    while ux >= 0x80:
        out[i] = (ux & 0x7F) | 0x80
        ux >>= 7
        i += 1
    out[i] = ux & 0x7F
    return bytes(out)
