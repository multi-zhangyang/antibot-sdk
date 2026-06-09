from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
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

DEFAULT_TIMEOUT = 20
DEFAULT_SUB_COUNT = 16
DEFAULT_SUB_DIFFICULTY = 16
DEFAULT_CHALLENGE_TTL = 30
DEFAULT_COOKIE_TTL = 1800
DEFAULT_MAX_ATTEMPTS_PER_SUB = 5_000_000
DEFAULT_OFFSET_STEP = 1 << 40
DEFAULT_COOKIE_NAME = "__pow_token"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/plain,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True, slots=True)
class PhpAntiDdosChallenge:
    challenge: str
    ts: int
    sub_count: int = DEFAULT_SUB_COUNT
    sub_difficulty: int = DEFAULT_SUB_DIFFICULTY
    sig: str | None = None
    fingerprint: str | None = None
    host: str | None = None
    page_url: str | None = None
    form_action: str | None = None
    cookie_name: str = DEFAULT_COOKIE_NAME
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def submit_url(self) -> str | None:
        if self.form_action and self.page_url:
            return urljoin(self.page_url, self.form_action)
        return self.form_action or self.page_url


@dataclass(frozen=True, slots=True)
class PhpAntiDdosSubSolution:
    index: int
    nonce: str
    digest_hex: str
    attempts: int


@dataclass(frozen=True, slots=True)
class PhpAntiDdosSolution:
    challenge: PhpAntiDdosChallenge
    sub_solutions: list[PhpAntiDdosSubSolution]
    elapsed_ms: int
    checked: int
    cookie_value: str | None = None

    @property
    def nonces(self) -> list[str]:
        return [item.nonce for item in sorted(self.sub_solutions, key=lambda item: item.index)]

    @property
    def nonces_csv(self) -> str:
        return ",".join(self.nonces)

    @property
    def submit_body(self) -> dict[str, str]:
        return {
            "pow_challenge": self.challenge.challenge,
            "pow_ts": str(self.challenge.ts),
            "pow_sub_count": str(self.challenge.sub_count),
            "pow_sub_difficulty": str(self.challenge.sub_difficulty),
            "pow_sig": self.challenge.sig or "",
            "pow_nonces": self.nonces_csv,
        }


def phpantiddos_fingerprint(client_ip: str, user_agent: str) -> str:
    return hashlib.sha256(f"{client_ip}|{user_agent}".encode("utf-8")).hexdigest()


def phpantiddos_sign_payload(payload: str, secret: str | bytes) -> str:
    return hmac.new(_secret_bytes(secret), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def phpantiddos_challenge_payload(
    challenge: str,
    ts: int | str,
    sub_count: int | str,
    sub_difficulty: int | str,
    fingerprint: str,
) -> str:
    return f"{challenge}|{int(ts)}|{int(sub_count)}|{int(sub_difficulty)}|{fingerprint}"


def sign_phpantiddos_challenge(
    challenge: str,
    ts: int | str,
    sub_count: int | str,
    sub_difficulty: int | str,
    *,
    secret: str | bytes,
    fingerprint: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> str:
    fp = fingerprint or phpantiddos_fingerprint(client_ip or "127.0.0.1", user_agent or DEFAULT_HEADERS["User-Agent"])
    payload = phpantiddos_challenge_payload(challenge, ts, sub_count, sub_difficulty, fp)
    return phpantiddos_sign_payload(payload, secret)


def phpantiddos_has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    bits = _validate_bits(bits)
    whole, rem = divmod(bits, 8)
    if len(digest) < whole + (1 if rem else 0):
        return False
    if any(digest[i] != 0 for i in range(whole)):
        return False
    if rem:
        return (digest[whole] & ((0xFF << (8 - rem)) & 0xFF)) == 0
    return True


def phpantiddos_hash(challenge: str, sub_index: int, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{challenge}:{int(sub_index)}:{nonce}".encode("utf-8")).digest()


def phpantiddos_hash_hex(challenge: str, sub_index: int, nonce: int | str) -> str:
    return phpantiddos_hash(challenge, sub_index, nonce).hex()


def verify_phpantiddos_nonce(challenge: str, sub_index: int, nonce: int | str, difficulty: int) -> bool:
    return phpantiddos_has_leading_zero_bits(phpantiddos_hash(challenge, sub_index, nonce), difficulty)


def parse_phpantiddos_challenge(data: Any, *, page_url: str | None = None) -> PhpAntiDdosChallenge:
    if isinstance(data, PhpAntiDdosChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_phpantiddos_challenge(Path(text[1:]).read_text(encoding="utf-8"), page_url=page_url)
        if text.startswith("{"):
            data = json.loads(text)
        elif "pow_challenge" in text or "var CHALLENGE" in text:
            return parse_phpantiddos_challenge_html(text, page_url=page_url)
        else:
            raise ValueError("php-anti-ddos challenge string must be JSON, HTML, or @file")
    if not isinstance(data, dict):
        raise ValueError("php-anti-ddos challenge must be a JSON object or challenge HTML")
    challenge = str(data.get("challenge") or data.get("pow_challenge") or "").strip().lower()
    _validate_challenge_hex(challenge)
    sub_count = _validate_sub_count(data.get("sub_count") or data.get("pow_sub_count") or data.get("N") or DEFAULT_SUB_COUNT)
    sub_difficulty = _validate_bits(data.get("sub_difficulty") or data.get("pow_sub_difficulty") or data.get("difficulty") or data.get("K") or DEFAULT_SUB_DIFFICULTY)
    ts = int(data.get("ts") or data.get("pow_ts") or time.time())
    sig = str(data.get("sig") or data.get("pow_sig") or "").strip().lower() or None
    if sig is not None and not re.fullmatch(r"[0-9a-f]{64}", sig):
        raise ValueError("php-anti-ddos pow_sig must be 64 hex chars")
    final_page_url = str(data.get("page_url") or data.get("url") or page_url or "") or None
    host = str(data.get("host") or "").strip() or (_url_host(final_page_url) if final_page_url else None)
    return PhpAntiDdosChallenge(
        challenge=challenge,
        ts=ts,
        sub_count=sub_count,
        sub_difficulty=sub_difficulty,
        sig=sig,
        fingerprint=str(data.get("fingerprint") or "").strip() or None,
        host=host,
        page_url=final_page_url,
        form_action=str(data.get("form_action") or data.get("submit_url") or "").strip() or None,
        cookie_name=str(data.get("cookie_name") or DEFAULT_COOKIE_NAME),
        raw=data,
    )


def parse_phpantiddos_challenge_html(html_text: str, *, page_url: str | None = None) -> PhpAntiDdosChallenge:
    text = str(html_text)
    challenge = _hidden_value(text, "pow_challenge") or _js_var(text, "CHALLENGE")
    ts = _hidden_value(text, "pow_ts") or _js_var(text, "TS")
    sub_count = _hidden_value(text, "pow_sub_count") or _js_var(text, "SUB_COUNT")
    sub_difficulty = _hidden_value(text, "pow_sub_difficulty") or _js_var(text, "DIFFICULTY")
    sig = _hidden_value(text, "pow_sig") or _js_var(text, "SIG")
    if not challenge or not ts or not sub_count or not sub_difficulty:
        raise ValueError("php-anti-ddos challenge HTML missing pow fields")
    action = _form_action(text)
    return PhpAntiDdosChallenge(
        challenge=str(challenge).strip().lower(),
        ts=int(ts),
        sub_count=_validate_sub_count(sub_count),
        sub_difficulty=_validate_bits(sub_difficulty),
        sig=str(sig).strip().lower() if sig else None,
        host=_url_host(page_url) if page_url else None,
        page_url=page_url,
        form_action=action,
        raw_html=text,
    )


def solve_phpantiddos_challenge(
    challenge: PhpAntiDdosChallenge | dict[str, Any] | str,
    *,
    max_attempts_per_subchallenge: int = DEFAULT_MAX_ATTEMPTS_PER_SUB,
    workers: int = 1,
    offset_step: int = DEFAULT_OFFSET_STEP,
    secret: str | bytes | None = None,
    fingerprint: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    host: str | None = None,
    cookie_ttl: int = DEFAULT_COOKIE_TTL,
    now: int | None = None,
) -> PhpAntiDdosSolution:
    started = time.monotonic()
    item = parse_phpantiddos_challenge(challenge)
    if secret and not verify_phpantiddos_challenge_signature(
        item,
        secret=secret,
        fingerprint=fingerprint,
        client_ip=client_ip,
        user_agent=user_agent,
    ):
        raise ValueError("php-anti-ddos challenge signature verification failed")
    subs = solve_phpantiddos_subchallenges(
        item.challenge,
        item.sub_count,
        item.sub_difficulty,
        max_attempts_per_subchallenge=max_attempts_per_subchallenge,
        workers=workers,
        offset_step=offset_step,
    )
    solution = PhpAntiDdosSolution(
        challenge=item,
        sub_solutions=subs,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        checked=sum(s.attempts for s in subs),
        cookie_value=None,
    )
    if not verify_phpantiddos_solution(item, solution):
        raise ValueError("php-anti-ddos internal solution verification failed")
    cookie_value = None
    if secret:
        fp = fingerprint or item.fingerprint or phpantiddos_fingerprint(client_ip or "127.0.0.1", user_agent or DEFAULT_HEADERS["User-Agent"])
        cookie_host = host or item.host or _url_host(item.page_url) or "localhost"
        cookie_value = make_phpantiddos_cookie(cookie_host, fp, secret=secret, ttl=cookie_ttl, now=now)
    return PhpAntiDdosSolution(
        challenge=item,
        sub_solutions=subs,
        elapsed_ms=solution.elapsed_ms,
        checked=solution.checked,
        cookie_value=cookie_value,
    )


def solve_phpantiddos_subchallenges(
    challenge: str,
    sub_count: int,
    difficulty: int,
    *,
    max_attempts_per_subchallenge: int = DEFAULT_MAX_ATTEMPTS_PER_SUB,
    workers: int = 1,
    offset_step: int = DEFAULT_OFFSET_STEP,
) -> list[PhpAntiDdosSubSolution]:
    _validate_challenge_hex(challenge)
    sub_count = _validate_sub_count(sub_count)
    difficulty = _validate_bits(difficulty)
    max_attempts_per_subchallenge = int(max_attempts_per_subchallenge)
    if max_attempts_per_subchallenge <= 0:
        raise ValueError("max_attempts_per_subchallenge must be positive")
    offset_step = int(offset_step)
    if offset_step <= 0:
        raise ValueError("offset_step must be positive")
    if workers <= 1 or sub_count == 1:
        out: list[PhpAntiDdosSubSolution] = []
        for idx in range(sub_count):
            nonce, digest, attempts = _search_phpantiddos_sub_range(
                challenge,
                idx,
                difficulty,
                idx * offset_step,
                idx * offset_step + max_attempts_per_subchallenge,
            )
            if nonce is None or digest is None:
                raise TimeoutError(f"no php-anti-ddos nonce found for subchallenge {idx}")
            out.append(PhpAntiDdosSubSolution(index=idx, nonce=str(nonce), digest_hex=digest.hex(), attempts=attempts))
        return out

    max_workers = min(max(1, int(workers)), sub_count, max(1, os.cpu_count() or 1))
    results: dict[int, PhpAntiDdosSubSolution] = {}
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _search_phpantiddos_sub_range,
                challenge,
                idx,
                difficulty,
                idx * offset_step,
                idx * offset_step + max_attempts_per_subchallenge,
            ): idx
            for idx in range(sub_count)
        }
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                idx = futures.pop(fut)
                nonce, digest, attempts = fut.result()
                if nonce is None or digest is None:
                    for other in futures:
                        other.cancel()
                    raise TimeoutError(f"no php-anti-ddos nonce found for subchallenge {idx}")
                results[idx] = PhpAntiDdosSubSolution(index=idx, nonce=str(nonce), digest_hex=digest.hex(), attempts=attempts)
    return [results[i] for i in range(sub_count)]


def verify_phpantiddos_challenge_signature(
    challenge: PhpAntiDdosChallenge | dict[str, Any] | str,
    *,
    secret: str | bytes,
    fingerprint: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> bool:
    try:
        item = parse_phpantiddos_challenge(challenge)
        if not item.sig:
            return False
        fp = fingerprint or item.fingerprint or phpantiddos_fingerprint(client_ip or "127.0.0.1", user_agent or DEFAULT_HEADERS["User-Agent"])
        payload = phpantiddos_challenge_payload(item.challenge, item.ts, item.sub_count, item.sub_difficulty, fp)
        expected = phpantiddos_sign_payload(payload, secret)
        return hmac.compare_digest(expected, item.sig)
    except Exception:
        return False


def verify_phpantiddos_solution(
    challenge: PhpAntiDdosChallenge | dict[str, Any] | str,
    solution: PhpAntiDdosSolution | dict[str, Any] | str,
    *,
    secret: str | bytes | None = None,
    fingerprint: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    challenge_ttl: int | None = None,
    now: int | None = None,
) -> bool:
    try:
        item = parse_phpantiddos_challenge(challenge)
        if secret and not verify_phpantiddos_challenge_signature(item, secret=secret, fingerprint=fingerprint, client_ip=client_ip, user_agent=user_agent):
            return False
        if challenge_ttl is not None:
            current = int(now if now is not None else time.time())
            if abs(current - item.ts) > int(challenge_ttl):
                return False
        if isinstance(solution, PhpAntiDdosSolution):
            nonces = solution.nonces
        elif isinstance(solution, dict):
            raw = solution.get("pow_nonces") or solution.get("nonces") or solution.get("nonce") or ""
            nonces = [str(x) for x in raw] if isinstance(raw, list) else str(raw).split(",")
        else:
            nonces = str(solution).split(",")
        if len(nonces) != item.sub_count:
            return False
        seen: set[str] = set()
        for idx, nonce in enumerate(nonces):
            n = str(nonce).strip()
            if not n.isdigit() or len(n) > 20 or n in seen:
                return False
            seen.add(n)
            if not verify_phpantiddos_nonce(item.challenge, idx, n, item.sub_difficulty):
                return False
        return True
    except Exception:
        return False


def make_phpantiddos_cookie(
    host: str,
    fingerprint: str,
    *,
    secret: str | bytes,
    ttl: int = DEFAULT_COOKIE_TTL,
    now: int | None = None,
) -> str:
    exp = int(now if now is not None else time.time()) + int(ttl)
    payload = f"{host}|{fingerprint}|{exp}"
    sig = hmac.new(_secret_bytes(secret), payload.encode("utf-8"), hashlib.sha256).digest()
    return f"{_b64url_encode(payload.encode('utf-8'))}.{_b64url_encode(sig)}"


def verify_phpantiddos_cookie(
    cookie: str,
    *,
    secret: str | bytes,
    host: str,
    fingerprint: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    now: int | None = None,
) -> bool:
    try:
        payload_b64, sig_b64 = str(cookie).split(".", 1)
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
        expected = hmac.new(_secret_bytes(secret), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return False
        fields = payload.decode("utf-8").split("|")
        if len(fields) != 3:
            return False
        got_host, got_fp, exp_text = fields
        fp = fingerprint or phpantiddos_fingerprint(client_ip or "127.0.0.1", user_agent or DEFAULT_HEADERS["User-Agent"])
        return got_host == host and hmac.compare_digest(got_fp, fp) and int(exp_text) >= int(now if now is not None else time.time())
    except Exception:
        return False


class PhpAntiDdosSolver:
    """Protocol solver for thblfr/php-anti-ddos stateless HMAC multi-PoW gates.

    The gate has no server-side session: challenge, timestamp, N/K and
    SHA256(IP|UA) fingerprint are HMAC-signed, the browser solves N independent
    SHA-256 sub-challenges, then the server issues an HttpOnly HMAC cookie bound
    to host + IP + UA. This solver reproduces the worker and form submit path
    without launching a browser.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        secret: str | None = None,
        fingerprint: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        host: str | None = None,
        cookie_ttl: int = DEFAULT_COOKIE_TTL,
        challenge_ttl: int | None = None,
        max_attempts_per_subchallenge: int = DEFAULT_MAX_ATTEMPTS_PER_SUB,
        workers: int = 1,
        offset_step: int = DEFAULT_OFFSET_STEP,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "submit_url": submit_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_subchallenge": max_attempts_per_subchallenge,
        }
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "phpantiddos_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="phpantiddos",
                ok=ok,
                captcha_type="stateless_hmac_multi_pow_cookie",
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
            if user_agent:
                merged_headers["User-Agent"] = user_agent
            proxies = _requests_proxies(proxy_server)
            challenge = self._load_challenge(
                session=session,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            effective_host = host or challenge.host or _url_host(challenge.page_url or challenge_url) or _url_host(submit_url)
            effective_fp = fingerprint or challenge.fingerprint
            solution = solve_phpantiddos_challenge(
                challenge,
                max_attempts_per_subchallenge=max_attempts_per_subchallenge,
                workers=workers,
                offset_step=offset_step,
                secret=secret,
                fingerprint=effective_fp,
                client_ip=client_ip,
                user_agent=merged_headers.get("User-Agent"),
                host=effective_host,
                cookie_ttl=cookie_ttl,
            )
            if not verify_phpantiddos_solution(
                challenge,
                solution,
                secret=secret,
                fingerprint=effective_fp,
                client_ip=client_ip,
                user_agent=merged_headers.get("User-Agent"),
                challenge_ttl=challenge_ttl,
            ):
                errors.append("php-anti-ddos internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            diagnostics.update(
                {
                    "challenge": challenge.challenge,
                    "ts": challenge.ts,
                    "sub_count": challenge.sub_count,
                    "sub_difficulty": challenge.sub_difficulty,
                    "sig_present": bool(challenge.sig),
                    "host": effective_host,
                    "nonce_count": len(solution.nonces),
                    "checked": solution.checked,
                    "solve_ms": solution.elapsed_ms,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {
                "nonces": solution.nonces,
                "pow_nonces": solution.nonces_csv,
                "submitBody": solution.submit_body,
                "subSolutions": [
                    {"index": s.index, "nonce": s.nonce, "digestHex": s.digest_hex, "attempts": s.attempts}
                    for s in solution.sub_solutions
                ],
            }
            if solution.cookie_value:
                raw["solution"]["localCookie"] = {"name": challenge.cookie_name, "value": solution.cookie_value}
            final_ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit:
                url = submit_url or challenge.submit_url
                if not url:
                    errors.append("submit requires submit_url or parsed form action/page_url")
                    return finish(ok=False, ticket=final_ticket, verify_code="missing_submit_url")
                resp = session.post(url, data=solution.submit_body, headers=merged_headers, timeout=timeout_sec, proxies=proxies, allow_redirects=True)
                raw["submitRequest"] = {"url": url, "body": solution.submit_body}
                raw["submitResponse"] = {
                    "status": resp.status_code,
                    "url": resp.url,
                    "history": [r.status_code for r in resp.history],
                    "contentType": resp.headers.get("Content-Type"),
                    "cookies": session.cookies.get_dict(),
                }
                if not (200 <= resp.status_code < 400):
                    errors.append(f"http_{resp.status_code}")
                    return finish(ok=False, ticket=final_ticket, verify_code=f"http_{resp.status_code}")
                cookie_val = session.cookies.get(challenge.cookie_name)
                if cookie_val:
                    final_ticket = json.dumps({"cookie_name": challenge.cookie_name, "cookie_value": cookie_val}, ensure_ascii=False, separators=(",", ":"))
                    verify_code = "cookie_issued"
                elif resp.history and any(300 <= r.status_code < 400 for r in resp.history):
                    verify_code = "redirected"
                else:
                    verify_code = "submitted"
            elif solution.cookie_value:
                final_ticket = json.dumps({"cookie_name": challenge.cookie_name, "cookie_value": solution.cookie_value}, ensure_ascii=False, separators=(",", ":"))
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
        challenge_json: Any,
        challenge_file: str | None,
        challenge_html: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> PhpAntiDdosChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_phpantiddos_challenge(loaded, page_url=challenge_url)
        if challenge_html:
            text = Path(challenge_html[1:]).read_text(encoding="utf-8") if challenge_html.startswith("@") else challenge_html
            return parse_phpantiddos_challenge_html(text, page_url=challenge_url)
        if not challenge_url:
            raise ValueError("php-anti-ddos solve requires challenge_json/challenge_file/challenge_html or challenge_url")
        resp = session.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=proxies)
        raw["challengeRequest"] = {"url": challenge_url}
        raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
        resp.raise_for_status()
        text = resp.text
        raw["challengeResponse"]["htmlPrefix"] = text[:500]
        return parse_phpantiddos_challenge_html(text, page_url=resp.url)


def _search_phpantiddos_sub_range(
    challenge: str,
    sub_index: int,
    difficulty: int,
    begin: int,
    end: int,
) -> tuple[int | None, bytes | None, int]:
    attempts = 0
    prefix = f"{challenge}:{int(sub_index)}:".encode("utf-8")
    for nonce in range(int(begin), int(end)):
        digest = hashlib.sha256(prefix + str(nonce).encode("ascii")).digest()
        attempts += 1
        if phpantiddos_has_leading_zero_bits(digest, difficulty):
            return nonce, digest, attempts
    return None, None, attempts


def _validate_bits(value: Any) -> int:
    try:
        bits = int(value)
    except Exception as exc:
        raise ValueError("php-anti-ddos difficulty must be an integer") from exc
    if bits < 1 or bits > 63:
        raise ValueError("php-anti-ddos difficulty must be 1..63")
    return bits


def _validate_sub_count(value: Any) -> int:
    try:
        count = int(value)
    except Exception as exc:
        raise ValueError("php-anti-ddos sub_count must be an integer") from exc
    if count < 1 or count > 128:
        raise ValueError("php-anti-ddos sub_count must be 1..128")
    return count


def _validate_challenge_hex(value: str) -> None:
    if not value or not re.fullmatch(r"[0-9a-fA-F]+", str(value)):
        raise ValueError("php-anti-ddos challenge must be hex")
    if len(str(value)) < 16 or len(str(value)) > 128:
        raise ValueError("php-anti-ddos challenge length must be 16..128 hex chars")


def _hidden_value(text: str, name: str) -> str | None:
    patterns = [
        rf"<input\b(?=[^>]*\bname=[\"']{re.escape(name)}[\"'])(?=[^>]*\bvalue=[\"']([^\"']*)[\"'])[^>]*>",
        rf"<input\b(?=[^>]*\bvalue=[\"']([^\"']*)[\"'])(?=[^>]*\bname=[\"']{re.escape(name)}[\"'])[^>]*>",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I | re.S)
        if m:
            return html.unescape(m.group(1))
    return None


def _js_var(text: str, name: str) -> str | None:
    m = re.search(rf"\bvar\s+{re.escape(name)}\s*=\s*(.+?);", text, re.S)
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        return str(json.loads(raw))
    except Exception:
        return raw.strip("'\"")


def _form_action(text: str) -> str | None:
    m = re.search(r"<form\b(?=[^>]*\bid=[\"']pow-form[\"'])(?=[^>]*\baction=[\"']([^\"']*)[\"'])[^>]*>", text, re.I | re.S)
    if not m:
        m = re.search(r"<form\b(?=[^>]*\baction=[\"']([^\"']*)[\"'])(?=[^>]*\bid=[\"']pow-form[\"'])[^>]*>", text, re.I | re.S)
    return html.unescape(m.group(1)) if m else None


def _challenge_raw(challenge: PhpAntiDdosChallenge) -> dict[str, Any]:
    return {
        "challenge": challenge.challenge,
        "ts": challenge.ts,
        "subCount": challenge.sub_count,
        "subDifficulty": challenge.sub_difficulty,
        "sig": challenge.sig,
        "host": challenge.host,
        "pageUrl": challenge.page_url,
        "formAction": challenge.form_action,
    }


def _load_json_arg(value: Any, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    raw = str(text)
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _secret_bytes(secret: str | bytes) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def _url_host(url: str | None) -> str | None:
    if not url:
        return None
    return urlparse(url).netloc or None


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}
