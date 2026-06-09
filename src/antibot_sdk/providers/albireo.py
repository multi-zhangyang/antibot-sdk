from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://example.com"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_ATTEMPTS = 20_000_000
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Site": "none",
}


@dataclass(frozen=True, slots=True)
class AlbireoChallenge:
    challenge: str
    issued_at: str | None = None
    difficulty: int = 3
    signature: str | None = None
    fp_nonce: str | None = None
    original_path: str = "/"
    variant: str = "v1"
    cookie_value: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AlbireoSolution:
    challenge: AlbireoChallenge
    nonce: int
    response: str
    elapsed_ms: int
    attempts_hint: int | None = None

    @property
    def verify_body(self) -> dict[str, Any]:
        body = {
            "nonce": str(self.nonce),
            "response": self.response,
            "verify": "true",
            "original_path": self.challenge.original_path or "/",
        }
        if self.challenge.fp_nonce is not None:
            body["fp_score"] = "0"
            body["fp_nonce"] = self.challenge.fp_nonce
        return body


def albireo_pow_hash(challenge: str, nonce: int | str) -> str:
    return hashlib.sha256((str(challenge) + str(nonce)).encode("utf-8")).hexdigest()


def verify_albireo_pow(challenge: str, nonce: int | str, response: str, difficulty: int) -> bool:
    expected = albireo_pow_hash(challenge, nonce)
    return expected == str(response).lower() and expected.startswith("0" * int(difficulty))


def solve_albireo_nonce(
    challenge: str,
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 50_000,
) -> tuple[int, str, int]:
    difficulty = int(difficulty)
    if difficulty < 1 or difficulty > 12:
        raise ValueError("Albireo difficulty must be 1..12")
    start = int(start)
    max_attempts = int(max_attempts)
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        nonce, digest = _search_range(challenge, difficulty, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no Albireo nonce found within {max_attempts} attempts")
        return nonce, digest, nonce - start + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_range, challenge, difficulty, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, end = futures.pop(fut)
                nonce, digest = fut.result()
                if nonce is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return nonce, digest, max(0, end - start)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_range, challenge, difficulty, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no Albireo nonce found within {max_attempts} attempts")


def parse_albireo_challenge_cookie(value: str, *, difficulty: int | None = None, original_path: str = "/") -> AlbireoChallenge:
    decoded = _normalize_albireo_cookie_value(value)
    parts = decoded.split(".")
    if len(parts) == 5:
        challenge, issued_at, diff_str, fp_nonce, signature = parts
        return AlbireoChallenge(
            challenge=challenge,
            issued_at=issued_at,
            difficulty=int(diff_str),
            signature=signature,
            fp_nonce=fp_nonce,
            original_path=original_path,
            variant="cf_v2",
            cookie_value=decoded,
        )
    if len(parts) == 3:
        challenge, issued_at, signature = parts
        return AlbireoChallenge(
            challenge=challenge,
            issued_at=issued_at,
            difficulty=int(difficulty or 3),
            signature=signature,
            original_path=original_path,
            variant="v1",
            cookie_value=decoded,
        )
    raise ValueError("unsupported Albireo challenge cookie format")


def parse_albireo_challenge_html(
    html: str,
    *,
    cookie_value: str | None = None,
    fallback_difficulty: int = 3,
) -> AlbireoChallenge:
    challenge = _js_const(html, "CHALLENGE")
    diff_text = _js_const(html, "DIFFICULTY")
    original_path = _js_const(html, "ORIG") or _js_const(html, "ORIGINAL_PATH") or "/"
    fp_nonce = _js_const(html, "FP_NONCE")
    difficulty = int(diff_text or fallback_difficulty)
    if cookie_value:
        item = parse_albireo_challenge_cookie(cookie_value, difficulty=difficulty, original_path=original_path)
        if challenge and item.challenge != challenge:
            raise ValueError("Albireo HTML challenge and cookie challenge differ")
        if fp_nonce and item.fp_nonce and item.fp_nonce != fp_nonce:
            raise ValueError("Albireo HTML fp_nonce and cookie fp_nonce differ")
        return AlbireoChallenge(
            challenge=item.challenge,
            issued_at=item.issued_at,
            difficulty=item.difficulty or difficulty,
            signature=item.signature,
            fp_nonce=item.fp_nonce or fp_nonce,
            original_path=original_path,
            variant=item.variant,
            cookie_value=item.cookie_value,
            raw_html=html,
        )
    if not challenge:
        raise ValueError("Albireo HTML does not contain CHALLENGE")
    return AlbireoChallenge(
        challenge=challenge,
        difficulty=difficulty,
        fp_nonce=fp_nonce,
        original_path=original_path,
        variant="cf_v2" if fp_nonce else "v1",
        raw_html=html,
    )


def parse_albireo_challenge(data: Any) -> AlbireoChallenge:
    if isinstance(data, AlbireoChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            data = json.loads(text)
        elif "<script" in text or "CHALLENGE" in text:
            return parse_albireo_challenge_html(text)
        else:
            return parse_albireo_challenge_cookie(text)
    if not isinstance(data, dict):
        raise ValueError("Albireo challenge must be JSON object, HTML, or challenge cookie")
    if "html" in data:
        return parse_albireo_challenge_html(
            str(data["html"]),
            cookie_value=data.get("cookie") or data.get("challenge_cookie") or data.get("cookie_value"),
            fallback_difficulty=int(data.get("difficulty") or 3),
        )
    cookie = data.get("cookie") or data.get("challenge_cookie") or data.get("cookie_value")
    if cookie:
        return parse_albireo_challenge_cookie(str(cookie), difficulty=data.get("difficulty"), original_path=str(data.get("original_path") or "/"))
    challenge = data.get("challenge") or data.get("ch") or data.get("id")
    if not challenge:
        raise ValueError("Albireo challenge JSON requires challenge")
    return AlbireoChallenge(
        challenge=str(challenge),
        issued_at=str(data.get("issued_at") or data.get("timestamp") or "") or None,
        difficulty=int(data.get("difficulty") or data.get("diff") or 3),
        signature=str(data.get("signature") or data.get("sig") or "") or None,
        fp_nonce=str(data.get("fp_nonce") or data.get("fpNonce") or "") or None,
        original_path=str(data.get("original_path") or data.get("originalPath") or "/"),
        variant=str(data.get("variant") or ("cf_v2" if data.get("fp_nonce") or data.get("fpNonce") else "v1")),
        cookie_value=str(data.get("cookie_value") or "") or None,
        raw=data,
    )


def solve_albireo_challenge(
    challenge: AlbireoChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 50_000,
) -> AlbireoSolution:
    started = time.monotonic()
    item = parse_albireo_challenge(challenge)
    nonce, digest, attempts_hint = solve_albireo_nonce(
        item.challenge,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return AlbireoSolution(
        challenge=item,
        nonce=nonce,
        response=digest,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
    )


def verify_albireo_solution(challenge: AlbireoChallenge | dict[str, Any] | str, solution: AlbireoSolution | dict[str, Any]) -> bool:
    try:
        item = parse_albireo_challenge(challenge)
        body = solution.verify_body if isinstance(solution, AlbireoSolution) else solution
        nonce = body.get("nonce")
        response = body.get("response")
        if nonce is None or response is None:
            return False
        if item.fp_nonce is not None and str(body.get("fp_nonce")) != item.fp_nonce:
            return False
        return verify_albireo_pow(item.challenge, nonce, str(response), item.difficulty)
    except Exception:
        return False


def albireo_hmac_b64(secret: str, message: str) -> str:
    return base64.b64encode(hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")


def make_albireo_cookie(
    *,
    secret: str,
    challenge: str,
    timestamp: str,
    difficulty: int | None = None,
    fp_nonce: str | None = None,
) -> str:
    if fp_nonce is not None:
        if difficulty is None:
            raise ValueError("difficulty is required for Albireo v2 cookie")
        payload = f"{challenge}.{timestamp}.{int(difficulty)}.{fp_nonce}"
    else:
        payload = f"{challenge}.{timestamp}"
    return payload + "." + albireo_hmac_b64(secret, payload)


class AlbireoSolver:
    """Protocol solver for Albireo serverless PoW protection.

    It fetches/parses the challenge page and signed albireo_challenge cookie,
    computes SHA256(challenge+nonce) leading-zero PoW, and posts the same form
    body as the Web Worker flow. No browser is started.
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
        challenge_cookie: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = 50_000,
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
                out = output_root / "albireo_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="albireo",
                ok=ok,
                captcha_type="serverless_signed_pow",
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
                challenge_cookie=challenge_cookie,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_albireo_challenge(
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
                    "variant": challenge.variant,
                    "fp_nonce_present": challenge.fp_nonce is not None,
                    "original_path": challenge.original_path,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "environment_headers": ["User-Agent", "Accept", "Accept-Language", "Sec-Fetch-Mode"],
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"body": solution.verify_body, "elapsedMs": solution.elapsed_ms}
            final_ticket = json.dumps(solution.verify_body, separators=(",", ":"))
            verify_code = "solved"
            if submit or submit_url:
                final_ticket, verify_code = self._submit(
                    session=session,
                    submit_url=submit_url or (page_url or base_url),
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
        challenge_cookie: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> AlbireoChallenge:
        if challenge_json is not None:
            return parse_albireo_challenge(_load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json)
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            return parse_albireo_challenge(loaded)
        if challenge_cookie:
            item = parse_albireo_challenge_cookie(challenge_cookie)
            session.cookies.set("albireo_challenge", item.cookie_value or unquote(challenge_cookie), path="/")
            return item
        url = page_url or base_url
        resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
        raw["pageRequest"] = {"url": url}
        raw["pageResponse"] = {"status": resp.status_code, "url": resp.url, "setCookieNames": _set_cookie_names(resp.headers.get("Set-Cookie", ""))}
        if resp.status_code >= 400:
            raw["pageResponse"]["text"] = resp.text[:500]
            raise RuntimeError(f"Albireo page HTTP {resp.status_code}")
        cookie_value = session.cookies.get("albireo_challenge")
        if not cookie_value:
            cookie_value = _extract_set_cookie_value(resp.headers.get("Set-Cookie", ""), "albireo_challenge")
        return parse_albireo_challenge_html(resp.text, cookie_value=cookie_value)

    def _submit(
        self,
        *,
        session: requests.Session,
        submit_url: str,
        body: dict[str, Any],
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        post_headers = dict(headers)
        post_headers["Accept"] = "application/json,text/plain,*/*"
        resp = session.post(submit_url, data=body, headers=post_headers, timeout=timeout_sec, proxies=proxies, allow_redirects=False)
        raw["verifyRequest"] = {"url": submit_url, "body": body}
        raw["verifyResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "setCookieNames": _set_cookie_names(resp.headers.get("Set-Cookie", "")),
            "location": resp.headers.get("Location"),
        }
        try:
            data = resp.json()
        except ValueError:
            data = None
            raw["verifyResponse"]["text"] = resp.text[:500]
        else:
            raw["verifyResponse"]["json"] = data
        if resp.status_code >= 400:
            message = resp.text[:120] or "verify_failed"
            errors.append(message)
            return json.dumps(body, separators=(",", ":")), f"http_{resp.status_code}"
        solved_cookie = session.cookies.get("albireo_solved") or _extract_set_cookie_value(resp.headers.get("Set-Cookie", ""), "albireo_solved")
        success = bool(isinstance(data, dict) and data.get("success")) or bool(solved_cookie) or resp.status_code in {302, 303}
        if success:
            ticket = json.dumps({"response": data, "albireo_solved": bool(solved_cookie), "location": resp.headers.get("Location")}, separators=(",", ":"))
            return ticket, "verified"
        errors.append("verify_failed")
        return json.dumps(body, separators=(",", ":")), "verify_failed"


def _search_range(challenge: str, difficulty: int, begin: int, end: int) -> tuple[int | None, str | None]:
    prefix = "0" * int(difficulty)
    for nonce in range(int(begin), int(end)):
        digest = albireo_pow_hash(challenge, nonce)
        if digest.startswith(prefix):
            return nonce, digest
    return None, None


def _js_const(html: str, name: str) -> str | None:
    patterns = [
        rf"(?:const\s+)?{re.escape(name)}\s*=\s*\"([^\"]*)\"",
        rf"(?:const\s+)?{re.escape(name)}\s*=\s*'([^']*)'",
        rf"(?:const\s+)?{re.escape(name)}\s*=\s*([0-9]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


def _challenge_raw(challenge: AlbireoChallenge) -> dict[str, Any]:
    return {
        "challenge": challenge.challenge,
        "issued_at": challenge.issued_at,
        "difficulty": challenge.difficulty,
        "variant": challenge.variant,
        "fp_nonce": challenge.fp_nonce,
        "original_path": challenge.original_path,
        "has_signature": bool(challenge.signature),
        "has_cookie": bool(challenge.cookie_value),
    }


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8")
        stripped = text.strip()
        if not stripped:
            return None
        return json.loads(stripped) if stripped[0] in "{[" else stripped
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return _load_json_arg(None, text[1:])
    return json.loads(text) if text[0] in "{[" else text


def _normalize_albireo_cookie_value(value: str) -> str:
    decoded = unquote(str(value).strip())
    lowered = decoded.lower()
    if lowered.startswith("set-cookie:"):
        decoded = decoded.split(":", 1)[1].strip()
    elif lowered.startswith("cookie:"):
        decoded = decoded.split(":", 1)[1].strip()
    match = re.search(r"(?:^|;\s*)albireo_challenge=([^;]+)", decoded)
    if match:
        decoded = match.group(1)
    elif decoded.startswith("albireo_challenge="):
        decoded = decoded.split("=", 1)[1]
    decoded = decoded.split(";", 1)[0].strip()
    return unquote(decoded)


def _extract_set_cookie_value(header: str, name: str) -> str | None:
    if not header:
        return None
    match = re.search(rf"(?:^|[,;]\s*){re.escape(name)}=([^;]+)", header)
    return unquote(match.group(1)) if match else None


def _set_cookie_names(header: str) -> list[str]:
    if not header:
        return []
    return re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]+)=", header)
