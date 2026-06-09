from __future__ import annotations

import asyncio
import hashlib
import hmac
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
from urllib.parse import urlparse, urlunparse

import requests
from argon2.low_level import Type, hash_secret_raw

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_COOKIE_NAME = "_basedflare_pow"
DEFAULT_BOT_CHECK_PATH = "/.basedflare/bot-check"
DEFAULT_MAX_ATTEMPTS = 10_000_000
DEFAULT_CHUNK_SIZE = 50_000
DEFAULT_TIMEOUT = 10
DEFAULT_ARGON_CHUNK_SIZE = 128
SUPPORTED_MODES = {"sha256", "argon2"}


@dataclass(frozen=True, slots=True)
class BasedFlareChallenge:
    user_key: str
    challenge_hash: str
    expiry: int
    signature: str
    mode: str = "sha256"
    difficulty_bits: int | None = None
    difficulty_bytes: int | None = None
    argon_time: int = 1
    argon_kb: int = 6000
    captcha_required: bool = False
    page_url: str | None = None
    bot_check_url: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def combined(self) -> str:
        return f"{self.user_key}#{self.challenge_hash}#{self.expiry}#{self.signature}"

    @property
    def pow_meta(self) -> str:
        diff = self.difficulty_bytes
        if diff is None and self.difficulty_bits is not None:
            diff = (self.difficulty_bits + 7) // 8
        if diff is None:
            diff = 0
        return f"{self.mode}#{diff}#{self.argon_time}#{self.argon_kb}"

    @property
    def effective_difficulty_bits(self) -> int:
        if self.difficulty_bits is not None:
            return int(self.difficulty_bits)
        if self.difficulty_bytes is not None:
            return int(self.difficulty_bytes) * 8
        raise ValueError("BasedFlare challenge missing difficulty_bits/difficulty_bytes")


@dataclass(frozen=True, slots=True)
class BasedFlareSolution:
    challenge: BasedFlareChallenge
    answer: str
    digest_hex: str
    elapsed_ms: int
    attempts_hint: int | None = None
    cookie_value: str | None = None
    cookie_name: str = DEFAULT_COOKIE_NAME

    @property
    def pow_response(self) -> str:
        return f"{self.challenge.combined}#{self.answer}"

    @property
    def cookie_header(self) -> str | None:
        if not self.cookie_value:
            return None
        return f"{self.cookie_name}={self.cookie_value}"

    @property
    def ticket_payload(self) -> dict[str, str]:
        payload = {"pow_response": self.pow_response}
        if self.cookie_value:
            payload[self.cookie_name] = self.cookie_value
        return payload


def basedflare_sha256_digest(user_key: str, challenge_hash: str, answer: int | str) -> str:
    material = f"{_validate_user_key(user_key)}{_validate_digest(challenge_hash)}{_answer_text(answer)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def basedflare_argon2_digest(
    user_key: str,
    challenge_hash: str,
    answer: int | str,
    *,
    argon_time: int = 1,
    argon_kb: int = 6000,
) -> str:
    salt = _validate_user_key(user_key).encode("utf-8")
    secret = f"{_validate_digest(challenge_hash)}{_answer_text(answer)}".encode("utf-8")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=_validate_positive_int(argon_time, "argon_time"),
        memory_cost=_validate_positive_int(argon_kb, "argon_kb"),
        parallelism=1,
        hash_len=32,
        type=Type.ID,
        version=19,
    ).hex()


def basedflare_digest(
    challenge: BasedFlareChallenge,
    answer: int | str,
) -> str:
    if challenge.mode == "argon2":
        return basedflare_argon2_digest(
            challenge.user_key,
            challenge.challenge_hash,
            answer,
            argon_time=challenge.argon_time,
            argon_kb=challenge.argon_kb,
        )
    return basedflare_sha256_digest(challenge.user_key, challenge.challenge_hash, answer)


def basedflare_checkdiff_lua(hash_hex: str, difficulty_bits: int) -> bool:
    """Mirror haproxy-protection src/lua/libs/utils.lua checkdiff exactly.

    The upstream Lua routine indexes one hex character per eight requested bits and
    masks the low bits of the next hex nibble. That is intentionally nonstandard;
    reproducing it is required for server compatibility.
    """

    digest = _validate_hex(hash_hex, "hash_hex")
    if not digest:
        return False
    diff = _validate_difficulty_bits(difficulty_bits)
    i = 1  # Lua's 1-based index.
    j = 0
    while j <= diff - 8:
        if i > len(digest) or digest[i - 1] != "0":
            return False
        i += 1
        j += 8
    if i > len(digest):
        return False
    lnm = int(digest[i - 1], 16)
    shift = (i * 8) - diff
    if shift < 0:
        return False
    mask = 0xFF >> shift if shift < 256 else 0
    return (lnm & mask) == 0


def solve_basedflare_answer(
    challenge: BasedFlareChallenge | dict[str, Any] | str,
    *,
    difficulty_bits: int | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int | None = None,
) -> tuple[str, str, int]:
    item = _merge_difficulty(parse_basedflare_challenge(challenge), difficulty_bits=difficulty_bits)
    diff = item.effective_difficulty_bits
    start, max_attempts = _validate_search(start, max_attempts)
    if chunk_size is None:
        chunk_size = DEFAULT_ARGON_CHUNK_SIZE if item.mode == "argon2" else DEFAULT_CHUNK_SIZE
    chunk_size = max(1, int(chunk_size))
    if workers <= 1:
        answer, digest, attempts = _search_basedflare_range(item, diff, start, start + max_attempts)
        if answer is None or digest is None:
            raise TimeoutError(f"no BasedFlare answer found within {max_attempts} attempts")
        return answer, digest, attempts

    workers = _bounded_workers(workers)
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    pool_kwargs = _process_pool_kwargs(workers)
    with ProcessPoolExecutor(**pool_kwargs) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_basedflare_range, item, diff, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, _end = futures.pop(fut)
                answer, digest, attempts = fut.result()
                if answer is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return answer, digest, max(0, begin - start + attempts)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_basedflare_range, item, diff, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no BasedFlare answer found within {max_attempts} attempts")


def solve_basedflare_pow(
    challenge: BasedFlareChallenge | dict[str, Any] | str,
    *,
    difficulty_bits: int | None = None,
    hmac_secret: str | bytes | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int | None = None,
) -> BasedFlareSolution:
    started = time.monotonic()
    item = _merge_difficulty(parse_basedflare_challenge(challenge), difficulty_bits=difficulty_bits)
    answer, digest, attempts = solve_basedflare_answer(
        item,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    cookie_value = make_basedflare_cookie(item, answer, hmac_secret=hmac_secret)
    return BasedFlareSolution(
        challenge=item,
        answer=answer,
        digest_hex=digest,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts,
        cookie_value=cookie_value,
    )


def verify_basedflare_solution(
    challenge: BasedFlareChallenge | dict[str, Any] | str,
    solution: BasedFlareSolution | dict[str, Any] | str,
    *,
    difficulty_bits: int | None = None,
) -> bool:
    try:
        item = _merge_difficulty(parse_basedflare_challenge(challenge), difficulty_bits=difficulty_bits)
        answer = _solution_answer(solution, challenge=item)
        digest = basedflare_digest(item, answer)
        return basedflare_checkdiff_lua(digest, item.effective_difficulty_bits)
    except Exception:
        return False


def make_basedflare_cookie(
    challenge: BasedFlareChallenge | dict[str, Any] | str,
    answer: int | str,
    *,
    hmac_secret: str | bytes | None = None,
) -> str | None:
    if hmac_secret is None:
        return None
    item = parse_basedflare_challenge(challenge)
    ans = _answer_text(answer)
    signature = hmac.new(
        _secret_bytes(hmac_secret),
        f"{item.user_key}{item.challenge_hash}{item.expiry}{ans}".encode("utf-8"),
        hashlib.sha3_256,
    ).hexdigest()
    return f"{item.user_key}#{item.challenge_hash}#{item.expiry}#{ans}#{signature}"


def parse_basedflare_challenge(
    data: BasedFlareChallenge | dict[str, Any] | str,
    *,
    page_url: str | None = None,
    difficulty_bits: int | None = None,
) -> BasedFlareChallenge:
    if isinstance(data, BasedFlareChallenge):
        return _merge_difficulty(data, difficulty_bits=difficulty_bits, page_url=page_url)
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_basedflare_challenge(
                Path(text[1:]).read_text(encoding="utf-8"),
                page_url=page_url,
                difficulty_bits=difficulty_bits,
            )
        if text.startswith("{"):
            return parse_basedflare_challenge(json.loads(text), page_url=page_url, difficulty_bits=difficulty_bits)
        if _looks_like_basedflare_html(text):
            return parse_basedflare_challenge_html(text, page_url=page_url, difficulty_bits=difficulty_bits)
        if text.count("#") == 3:
            return _challenge_from_parts(
                text,
                mode="sha256",
                difficulty_bits=difficulty_bits,
                page_url=page_url,
                raw={"ch": text},
            )
        raise ValueError("BasedFlare challenge string must be JSON, HTML, combined ch, or @file")
    if not isinstance(data, dict):
        raise ValueError("BasedFlare challenge must be a JSON object, HTML, combined ch, or dataclass")
    if "html" in data:
        return parse_basedflare_challenge_html(
            str(data["html"]),
            page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
            difficulty_bits=difficulty_bits,
        )

    ch = str(
        data.get("ch")
        or data.get("combined_challenge")
        or data.get("combinedChallenge")
        or data.get("challenge")
        or data.get("pow_challenge")
        or ""
    )
    if ch.count("#") != 3:
        user_key = str(data.get("user_key") or data.get("userKey") or "")
        challenge_hash = str(data.get("challenge_hash") or data.get("challengeHash") or data.get("hash") or "")
        expiry = data.get("expiry") or data.get("expires") or data.get("exp") or 0
        signature = str(data.get("signature") or data.get("sig") or "")
        ch = f"{user_key}#{challenge_hash}#{expiry}#{signature}"

    pow_text = str(data.get("pow") or data.get("pow_meta") or data.get("powMeta") or "")
    mode, diff_bits, diff_bytes, argon_time, argon_kb = _parse_pow_meta(
        pow_text,
        mode=data.get("mode") or data.get("type"),
        difficulty_bits=data.get("difficulty_bits") or data.get("difficultyBits") or data.get("diff"),
        difficulty_bytes=data.get("difficulty_bytes") or data.get("difficultyBytes") or data.get("bytes"),
        argon_time=data.get("argon_time") or data.get("argonTime") or data.get("time"),
        argon_kb=data.get("argon_kb") or data.get("argonKb") or data.get("kb") or data.get("mem"),
    )
    if difficulty_bits is not None:
        diff_bits = _validate_difficulty_bits(difficulty_bits)
    return _challenge_from_parts(
        ch,
        mode=mode,
        difficulty_bits=diff_bits,
        difficulty_bytes=diff_bytes,
        argon_time=argon_time,
        argon_kb=argon_kb,
        captcha_required=_to_bool(data.get("ca") or data.get("captcha_required") or data.get("captchaRequired"), default=False),
        page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
        bot_check_url=str(data.get("bot_check_url") or data.get("botCheckUrl") or "") or None,
        raw=data,
    )


def parse_basedflare_challenge_html(
    html_text: str,
    *,
    page_url: str | None = None,
    difficulty_bits: int | None = None,
) -> BasedFlareChallenge:
    text = str(html_text)
    pow_value = _html_attr(text, "data-pow") or _first_match(
        text,
        [
            r"powFinished[^<]+submitPow\(`?\$?\{?pow\}?#[^`]+`?\)",
            r"name=[\"']pow_response[\"'][^>]*value=[\"']([^\"']+)[\"']",
        ],
    )
    if not pow_value or pow_value.count("#") != 3:
        raise ValueError("BasedFlare HTML missing body data-pow combined challenge")
    diff_text = _html_attr(text, "data-diff")
    time_text = _html_attr(text, "data-time")
    kb_text = _html_attr(text, "data-kb")
    mode_text = _html_attr(text, "data-mode") or "sha256"
    return _challenge_from_parts(
        pow_value,
        mode=mode_text,
        difficulty_bits=_validate_difficulty_bits(difficulty_bits if difficulty_bits is not None else diff_text),
        difficulty_bytes=None,
        argon_time=_validate_positive_int(time_text or 1, "argon_time"),
        argon_kb=_validate_positive_int(kb_text or 6000, "argon_kb"),
        captcha_required='id="captcha"' in text or "data-sitekey" in text,
        page_url=page_url,
        raw_html=text,
    )


class BasedFlareSolver:
    """Protocol solver for BasedFlare / haproxy-protection PoW clearance."""

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
        bot_check_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        difficulty_bits: int | None = None,
        hmac_secret: str | bytes | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int | None = None,
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
            "challenge_url": challenge_url or bot_check_url,
            "bot_check_url": bot_check_url,
            "submit_url": submit_url,
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
                out = output_root / "basedflare_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="basedflare",
                ok=ok,
                captcha_type="haproxy_pow_cookie",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("user_key"),
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
                challenge_url=challenge_url or bot_check_url,
                difficulty_bits=difficulty_bits,
                timeout_sec=timeout_sec,
                session=session,
                proxies=proxies,
                raw=raw,
            )
            solution = solve_basedflare_pow(
                challenge,
                hmac_secret=hmac_secret,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            diagnostics.update(
                {
                    "user_key": challenge.user_key,
                    "challenge_hash": challenge.challenge_hash,
                    "expiry": challenge.expiry,
                    "mode": challenge.mode,
                    "difficulty_bits": challenge.difficulty_bits,
                    "difficulty_bytes": challenge.difficulty_bytes,
                    "effective_difficulty_bits": challenge.effective_difficulty_bits,
                    "argon_time": challenge.argon_time,
                    "argon_kb": challenge.argon_kb,
                    "captcha_required": challenge.captcha_required,
                    "answer": solution.answer,
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "cookie_name": solution.cookie_name,
                    "cookie_value": solution.cookie_value,
                    "page_url": challenge.page_url,
                    "bot_check_url": challenge.bot_check_url,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {
                "answer": solution.answer,
                "powResponse": solution.pow_response,
                "cookie": solution.cookie_header,
                "digestHex": solution.digest_hex,
            }
            ticket_payload = solution.ticket_payload
            verify_code = "solved"
            if submit:
                post_url = submit_url or challenge.bot_check_url or _bot_check_url(base_url or challenge.page_url)
                if not post_url:
                    errors.append("BasedFlare submit requested but submit_url/base_url/page_url is missing")
                    return finish(ok=False, ticket=json.dumps(ticket_payload, separators=(",", ":")), verify_code=verify_code)
                submit_data = self._submit_pow(
                    submit_url=post_url,
                    solution=solution,
                    session=session,
                    proxies=proxies,
                    timeout_sec=timeout_sec,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                diagnostics["submit_status"] = submit_data["status"]
                diagnostics["submit_location"] = submit_data.get("location")
                cookie_value = submit_data.get("cookie_value")
                if cookie_value:
                    diagnostics["cookie_value"] = cookie_value
                    ticket_payload[DEFAULT_COOKIE_NAME] = cookie_value
                if submit_data["status"] >= 400:
                    errors.append(f"BasedFlare pow submit failed: HTTP {submit_data['status']}")
                    return finish(
                        ok=False,
                        ticket=json.dumps(ticket_payload, separators=(",", ":")),
                        verify_code="submit_failed",
                    )
                verify_code = "verified" if cookie_value or submit_data["status"] < 400 else "submitted"
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
        challenge_url: str | None,
        difficulty_bits: int | None,
        timeout_sec: int,
        session: requests.Session,
        proxies: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> BasedFlareChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_basedflare_challenge(loaded, page_url=base_url, difficulty_bits=difficulty_bits)
        if challenge_html:
            text = Path(challenge_html[1:]).read_text(encoding="utf-8") if challenge_html.startswith("@") else challenge_html
            return parse_basedflare_challenge_html(text, page_url=base_url, difficulty_bits=difficulty_bits)
        target = challenge_url or _bot_check_url(base_url)
        if target:
            resp = session.get(
                target,
                headers={"Accept": "application/json"},
                timeout=timeout_sec,
                proxies=proxies,
            )
            raw["challengeResponse"] = {
                "status": resp.status_code,
                "url": resp.url,
                "contentType": resp.headers.get("content-type"),
                "bodyPrefix": resp.text[:160],
            }
            try:
                data = resp.json()
                if isinstance(data, dict) and data.get("ch"):
                    data.setdefault("bot_check_url", resp.url or target)
                    return parse_basedflare_challenge(data, page_url=base_url, difficulty_bits=difficulty_bits)
            except ValueError:
                pass
            return parse_basedflare_challenge_html(resp.text, page_url=resp.url or base_url, difficulty_bits=difficulty_bits)
        raise ValueError("BasedFlare solve requires challenge_json/challenge_file/challenge_html/challenge_url/base_url")

    def _submit_pow(
        self,
        *,
        submit_url: str,
        solution: BasedFlareSolution,
        session: requests.Session,
        proxies: dict[str, str] | None,
        timeout_sec: int,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        resp = session.post(
            submit_url,
            data={"pow_response": solution.pow_response},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout_sec,
            proxies=proxies,
            allow_redirects=False,
        )
        header = resp.headers.get("set-cookie", "")
        cookie_value = _extract_set_cookie_value(header, DEFAULT_COOKIE_NAME)
        if not cookie_value:
            jar_value = session.cookies.get(DEFAULT_COOKIE_NAME)
            cookie_value = jar_value or None
        data = {
            "status": resp.status_code,
            "url": resp.url,
            "location": resp.headers.get("location"),
            "contentType": resp.headers.get("content-type"),
            "setCookieNames": _set_cookie_names(header),
            "cookie_value": cookie_value,
            "bodyPrefix": resp.text[:120],
        }
        raw["submitResponse"] = data
        return data


def _search_basedflare_range(
    challenge: BasedFlareChallenge,
    difficulty_bits: int,
    begin: int,
    end: int,
) -> tuple[str | None, str | None, int]:
    attempts = 0
    if challenge.mode == "sha256":
        base = hashlib.sha256(f"{challenge.user_key}{challenge.challenge_hash}".encode("utf-8"))
        for value in range(int(begin), int(end)):
            answer = str(value)
            h = base.copy()
            h.update(answer.encode("ascii"))
            digest = h.hexdigest()
            attempts += 1
            if basedflare_checkdiff_lua(digest, difficulty_bits):
                return answer, digest, attempts
        return None, None, attempts

    for value in range(int(begin), int(end)):
        answer = str(value)
        digest = basedflare_argon2_digest(
            challenge.user_key,
            challenge.challenge_hash,
            answer,
            argon_time=challenge.argon_time,
            argon_kb=challenge.argon_kb,
        )
        attempts += 1
        if basedflare_checkdiff_lua(digest, difficulty_bits):
            return answer, digest, attempts
    return None, None, attempts


def _challenge_from_parts(
    combined: str,
    *,
    mode: Any = "sha256",
    difficulty_bits: Any = None,
    difficulty_bytes: Any = None,
    argon_time: Any = 1,
    argon_kb: Any = 6000,
    captcha_required: bool = False,
    page_url: str | None = None,
    bot_check_url: str | None = None,
    raw_html: str | None = None,
    raw: dict[str, Any] | None = None,
) -> BasedFlareChallenge:
    parts = str(combined).strip().split("#")
    if len(parts) != 4:
        raise ValueError("BasedFlare combined challenge must be user_key#challenge_hash#expiry#signature")
    selected_mode = _validate_mode(mode)
    diff_bits = _validate_optional_difficulty_bits(difficulty_bits)
    diff_bytes = _validate_optional_difficulty_bytes(difficulty_bytes)
    if diff_bits is None and diff_bytes is None:
        diff_bytes = 1
    return BasedFlareChallenge(
        user_key=_validate_user_key(parts[0]),
        challenge_hash=_validate_digest(parts[1]),
        expiry=_validate_expiry(parts[2]),
        signature=_validate_signature(parts[3]),
        mode=selected_mode,
        difficulty_bits=diff_bits,
        difficulty_bytes=diff_bytes,
        argon_time=_validate_positive_int(argon_time, "argon_time"),
        argon_kb=_validate_positive_int(argon_kb, "argon_kb"),
        captcha_required=bool(captcha_required),
        page_url=page_url,
        bot_check_url=bot_check_url,
        raw_html=raw_html,
        raw=raw,
    )


def _parse_pow_meta(
    text: str,
    *,
    mode: Any = None,
    difficulty_bits: Any = None,
    difficulty_bytes: Any = None,
    argon_time: Any = None,
    argon_kb: Any = None,
) -> tuple[str, int | None, int | None, int, int]:
    selected_mode = mode
    diff_bytes = difficulty_bytes
    a_time = argon_time
    a_kb = argon_kb
    if text:
        parts = str(text).strip().split("#")
        if len(parts) >= 1 and parts[0]:
            selected_mode = parts[0]
        if len(parts) >= 2 and parts[1] != "":
            diff_bytes = parts[1]
        if len(parts) >= 3 and parts[2] != "":
            a_time = parts[2]
        if len(parts) >= 4 and parts[3] != "":
            a_kb = parts[3]
    return (
        _validate_mode(selected_mode or "sha256"),
        _validate_optional_difficulty_bits(difficulty_bits),
        _validate_optional_difficulty_bytes(diff_bytes),
        _validate_positive_int(a_time or 1, "argon_time"),
        _validate_positive_int(a_kb or 6000, "argon_kb"),
    )


def _merge_difficulty(
    item: BasedFlareChallenge,
    *,
    difficulty_bits: int | None = None,
    page_url: str | None = None,
) -> BasedFlareChallenge:
    if difficulty_bits is None and page_url is None:
        return item
    return BasedFlareChallenge(
        user_key=item.user_key,
        challenge_hash=item.challenge_hash,
        expiry=item.expiry,
        signature=item.signature,
        mode=item.mode,
        difficulty_bits=_validate_difficulty_bits(difficulty_bits) if difficulty_bits is not None else item.difficulty_bits,
        difficulty_bytes=item.difficulty_bytes,
        argon_time=item.argon_time,
        argon_kb=item.argon_kb,
        captcha_required=item.captcha_required,
        page_url=page_url or item.page_url,
        bot_check_url=item.bot_check_url,
        raw_html=item.raw_html,
        raw=item.raw,
    )


def _challenge_raw(challenge: BasedFlareChallenge) -> dict[str, Any]:
    return {
        "ch": challenge.combined,
        "pow": challenge.pow_meta,
        "mode": challenge.mode,
        "difficultyBits": challenge.difficulty_bits,
        "difficultyBytes": challenge.difficulty_bytes,
        "effectiveDifficultyBits": challenge.effective_difficulty_bits,
        "argonTime": challenge.argon_time,
        "argonKb": challenge.argon_kb,
        "captchaRequired": challenge.captcha_required,
        "pageUrl": challenge.page_url,
        "botCheckUrl": challenge.bot_check_url,
        "hasHtml": bool(challenge.raw_html),
    }


def _solution_answer(
    solution: BasedFlareSolution | dict[str, Any] | str,
    *,
    challenge: BasedFlareChallenge | None = None,
) -> str:
    if isinstance(solution, BasedFlareSolution):
        return solution.answer
    if isinstance(solution, dict):
        if solution.get("answer") is not None:
            return _answer_text(solution["answer"])
        if solution.get("pow_response") is not None or solution.get("powResponse") is not None:
            return _solution_answer(str(solution.get("pow_response") or solution.get("powResponse")), challenge=challenge)
        if solution.get(DEFAULT_COOKIE_NAME) is not None:
            return _solution_answer(str(solution[DEFAULT_COOKIE_NAME]), challenge=challenge)
        if solution.get("cookie_value") is not None or solution.get("cookieValue") is not None:
            return _solution_answer(str(solution.get("cookie_value") or solution.get("cookieValue")), challenge=challenge)
        if solution.get("ticket") is not None:
            return _solution_answer(str(solution["ticket"]), challenge=challenge)
    text = str(solution).strip()
    if text.startswith("{"):
        return _solution_answer(json.loads(text), challenge=challenge)
    if "=" in text and DEFAULT_COOKIE_NAME in text:
        # Cookie format user_key#challenge_hash#expiry#answer#signature.
        match = re.search(rf"{re.escape(DEFAULT_COOKIE_NAME)}=([^;]+)", text)
        if match:
            text = match.group(1)
    parts = text.split("#")
    if len(parts) == 5:
        if challenge is not None and parts[0] == challenge.user_key and parts[1] == challenge.challenge_hash:
            if parts[3] == challenge.signature:
                return _answer_text(parts[4])  # pow_response: ch#answer
            return _answer_text(parts[3])  # cookie: user#hash#expiry#answer#sig
        return _answer_text(parts[4])
    return _answer_text(text)


def _answer_text(value: int | str) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("BasedFlare answer must be non-negative")
        return str(value)
    text = str(value).strip()
    if not text or not re.fullmatch(r"\d+", text):
        raise ValueError("BasedFlare answer must be decimal digits")
    return text


def _html_attr(text: str, name: str) -> str | None:
    pattern = rf"\b{re.escape(name)}\s*=\s*(['\"])(.*?)\1"
    match = re.search(pattern, text, re.I | re.S)
    return html.unescape(match.group(2)) if match else None


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return html.unescape(match.group(1))
    return None


def _looks_like_basedflare_html(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "data-pow=",
            "_basedflare_pow",
            "/.basedflare/bot-check",
            "BasedFlare",
            "pow_response",
        )
    )


def _bot_check_url(base_url: str | None, path: str = DEFAULT_BOT_CHECK_PATH) -> str | None:
    if not base_url:
        return None
    parsed = urlparse(str(base_url))
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.path.rstrip("/") == path.rstrip("/"):
        return str(base_url)
    original = parsed.path or "/"
    if parsed.query:
        original = f"{original}?{parsed.query}"
    query = original if original and original != "/" else ""
    return urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


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
    match = re.search(rf"(?:^|[,;]\s*){re.escape(name)}=([^;]+)", header)
    return match.group(1) if match else None


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)


def _validate_mode(value: Any) -> str:
    mode = str(value or "sha256").strip().lower()
    if mode not in SUPPORTED_MODES:
        raise ValueError("BasedFlare mode must be sha256 or argon2")
    return mode


def _validate_hex(value: Any, name: str) -> str:
    text = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]*", text):
        raise ValueError(f"BasedFlare {name} must be hex")
    return text


def _validate_user_key(value: Any) -> str:
    text = _validate_hex(value, "user_key")
    if len(text) < 8:
        raise ValueError("BasedFlare user_key is too short")
    return text


def _validate_digest(value: Any) -> str:
    text = _validate_hex(value, "challenge_hash")
    if len(text) != 64:
        raise ValueError("BasedFlare challenge_hash must be 64 hex chars")
    return text


def _validate_signature(value: Any) -> str:
    text = _validate_hex(value, "signature")
    if len(text) < 32:
        raise ValueError("BasedFlare signature is too short")
    return text


def _validate_expiry(value: Any) -> int:
    expiry = int(value)
    if expiry <= 0:
        raise ValueError("BasedFlare expiry must be positive")
    return expiry


def _validate_difficulty_bits(value: Any) -> int:
    diff = int(value)
    if diff < 0 or diff > 256:
        raise ValueError("BasedFlare difficulty_bits must be 0..256")
    return diff


def _validate_optional_difficulty_bits(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return _validate_difficulty_bits(value)


def _validate_optional_difficulty_bytes(value: Any) -> int | None:
    if value is None or value == "":
        return None
    diff = int(value)
    if diff < 0 or diff > 64:
        raise ValueError("BasedFlare difficulty_bytes must be 0..64")
    return diff


def _validate_positive_int(value: Any, name: str) -> int:
    number = int(value)
    if number <= 0:
        raise ValueError(f"BasedFlare {name} must be positive")
    return number


def _validate_search(start: Any, max_attempts: Any) -> tuple[int, int]:
    s = int(start)
    m = int(max_attempts)
    if s < 0:
        raise ValueError("start must be non-negative")
    if m <= 0:
        raise ValueError("max_attempts must be positive")
    return s, m


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


def _secret_bytes(secret: str | bytes) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


__all__ = [
    "BasedFlareChallenge",
    "BasedFlareSolution",
    "BasedFlareSolver",
    "basedflare_argon2_digest",
    "basedflare_checkdiff_lua",
    "basedflare_digest",
    "basedflare_sha256_digest",
    "make_basedflare_cookie",
    "parse_basedflare_challenge",
    "parse_basedflare_challenge_html",
    "solve_basedflare_answer",
    "solve_basedflare_pow",
    "verify_basedflare_solution",
]
