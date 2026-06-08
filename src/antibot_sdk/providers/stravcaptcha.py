from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import re
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_DIFFICULTY = 18
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_TOKEN_FIELD = "_captcha"
DEFAULT_RESPONSE_FIELD = "_captcha_answer"
DEFAULT_HONEYPOT_FIELD = "website"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class StravCaptchaTokenPayload:
    token_type: str
    salt: str
    issued_at_ms: int
    exp_minutes: int
    jti: str
    version: int = 1
    difficulty: int | None = None
    answer_hash: str | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": self.version,
            "t": self.token_type,
            "s": self.salt,
            "iat": self.issued_at_ms,
            "exp": self.exp_minutes,
            "jti": self.jti,
        }
        if self.difficulty is not None:
            out["d"] = self.difficulty
        if self.answer_hash is not None:
            out["ah"] = self.answer_hash
        return out


@dataclass(slots=True)
class StravCaptchaChallenge:
    token: str
    payload: StravCaptchaTokenPayload
    challenge: str
    difficulty: int
    props: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "payload": self.payload.to_payload(),
            "props": self.props,
            "challenge": self.challenge,
            "difficulty": self.difficulty,
        }


@dataclass(slots=True)
class StravCaptchaSolution:
    challenge: StravCaptchaChallenge
    nonce: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return build_stravcaptcha_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "token": self.challenge.token,
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def count_leading_zero_bits_hex(hex_digest: str) -> int:
    bits = 0
    for ch in str(hex_digest).strip().lower():
        try:
            nibble = int(ch, 16)
        except ValueError:
            break
        if nibble == 0:
            bits += 4
            continue
        if nibble < 0b0010:
            bits += 3
        elif nibble < 0b0100:
            bits += 2
        elif nibble < 0b1000:
            bits += 1
        break
    return bits


def stravcaptcha_hash_hex(salt: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{salt}:{nonce}".encode("utf-8")).hexdigest()


def decode_stravcaptcha_token(token: str) -> StravCaptchaTokenPayload:
    body, _mac = _split_token(token)
    try:
        data = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception as e:
        raise ValueError("Strav CAPTCHA token body is not valid JSON") from e
    if not isinstance(data, dict):
        raise ValueError("Strav CAPTCHA token body must be JSON object")
    try:
        payload = StravCaptchaTokenPayload(
            version=int(data["v"]),
            token_type=str(data["t"]),
            salt=str(data["s"]),
            issued_at_ms=int(data["iat"]),
            exp_minutes=int(data["exp"]),
            jti=str(data["jti"]),
            difficulty=int(data["d"]) if data.get("d") is not None else None,
            answer_hash=str(data["ah"]) if data.get("ah") is not None else None,
        )
    except KeyError as e:
        raise ValueError(f"Strav CAPTCHA token missing field: {e.args[0]}") from e
    _validate_payload(payload)
    return payload


def verify_stravcaptcha_token_signature(token: str, secret: str | bytes) -> bool:
    try:
        body, mac = _split_token(token)
        key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        expected = _b64url_encode(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
        return hmac.compare_digest(expected, mac)
    except Exception:
        return False


def stravcaptcha_token_expired(payload: StravCaptchaTokenPayload, *, now_ms: int | None = None) -> bool:
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    return now > payload.issued_at_ms + payload.exp_minutes * 60_000


def parse_stravcaptcha_challenge(
    value: StravCaptchaChallenge | dict[str, Any] | str,
    *,
    props: dict[str, Any] | None = None,
    html_text: str | None = None,
) -> StravCaptchaChallenge:
    if isinstance(value, StravCaptchaChallenge):
        return value
    if html_text is not None:
        return parse_stravcaptcha_challenge(extract_stravcaptcha_from_html(html_text), props=props)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Strav CAPTCHA challenge is empty")
        if text.startswith("@"):
            return parse_stravcaptcha_challenge(Path(text[1:]).read_text(encoding="utf-8"), props=props)
        if "<" in text and "_captcha" in text:
            return parse_stravcaptcha_challenge(extract_stravcaptcha_from_html(text), props=props)
        try:
            obj = json.loads(text)
        except ValueError:
            obj = {"token": text}
        return parse_stravcaptcha_challenge(obj, props=props)
    if not isinstance(value, dict):
        raise ValueError("Strav CAPTCHA challenge must be token string or JSON object")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    token = str(data.get("token") or data.get(DEFAULT_TOKEN_FIELD) or "")
    if not token:
        raise ValueError("Strav CAPTCHA challenge requires token")
    token_props = data.get("props") if isinstance(data.get("props"), dict) else {}
    merged_props = {**token_props, **(props or {})}
    payload = decode_stravcaptcha_token(token)
    if payload.token_type != "pow":
        raise ValueError(f"Strav CAPTCHA token type must be 'pow', got {payload.token_type!r}")
    challenge = str(merged_props.get("challenge") or payload.salt)
    difficulty = int(merged_props.get("difficulty", payload.difficulty or DEFAULT_DIFFICULTY))
    if challenge != payload.salt:
        raise ValueError("Strav CAPTCHA props.challenge does not match token salt")
    if difficulty < 0 or difficulty > 256:
        raise ValueError("Strav CAPTCHA difficulty must be between 0 and 256")
    return StravCaptchaChallenge(
        token=token,
        payload=payload,
        challenge=challenge,
        difficulty=difficulty,
        props=merged_props,
    )


def extract_stravcaptcha_from_html(html_text: str) -> dict[str, Any]:
    text = str(html_text)
    token = _extract_input_value(text, DEFAULT_TOKEN_FIELD)
    if not token:
        raise ValueError("Strav CAPTCHA HTML does not contain _captcha token input")
    props: dict[str, Any] = {}
    m = re.search(r"data-props=(['\"])(?P<props>.*?)(?<!\\)\1", text, flags=re.DOTALL)
    if m:
        raw = html.unescape(m.group("props"))
        try:
            props = json.loads(raw)
        except ValueError:
            props = {}
    return {"token": token, "props": props}


def solve_stravcaptcha_challenge(
    challenge: StravCaptchaChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> StravCaptchaSolution | None:
    item = parse_stravcaptcha_challenge(challenge)
    started = time.monotonic()
    workers = max(1, int(workers or 1))
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_stravcaptcha_range(
            item.challenge,
            item.difficulty,
            start,
            start + max_attempts,
            deadline_epoch,
        )
        if nonce is None or digest is None:
            return None
        return StravCaptchaSolution(
            challenge=item,
            nonce=str(nonce),
            hash_hex=digest,
            attempts=checked,
            solve_time_ms=int((time.monotonic() - started) * 1000),
        )

    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(_solve_stravcaptcha_range, item.challenge, item.difficulty, lo, hi, deadline_epoch): (lo, hi)
        for lo, hi in ranges
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return StravCaptchaSolution(
                    challenge=item,
                    nonce=str(nonce),
                    hash_hex=digest,
                    attempts=checked_total,
                    solve_time_ms=int((time.monotonic() - started) * 1000),
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


def verify_stravcaptcha_solution(
    challenge: StravCaptchaChallenge | dict[str, Any] | str,
    solution: StravCaptchaSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_stravcaptcha_challenge(challenge)
        if isinstance(solution, StravCaptchaSolution):
            nonce = solution.nonce
            expected = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = str(solution.get("nonce", solution.get(DEFAULT_RESPONSE_FIELD, "")))
            expected = str(solution.get("hash") or solution.get("hashHex") or "")
        else:
            nonce = str(solution)
            expected = ""
        if not nonce or len(nonce) > 64:
            return False
        digest = stravcaptcha_hash_hex(item.challenge, nonce)
        if expected and digest != expected.lower():
            return False
        return count_leading_zero_bits_hex(digest) >= item.difficulty
    except Exception:
        return False


def build_stravcaptcha_submit_body(
    challenge: StravCaptchaChallenge | dict[str, Any] | str,
    solution: StravCaptchaSolution | dict[str, Any] | int | str,
    *,
    token_field: str = DEFAULT_TOKEN_FIELD,
    response_field: str = DEFAULT_RESPONSE_FIELD,
    honeypot_field: str = DEFAULT_HONEYPOT_FIELD,
) -> dict[str, Any]:
    item = parse_stravcaptcha_challenge(challenge)
    if isinstance(solution, StravCaptchaSolution):
        nonce = solution.nonce
    elif isinstance(solution, dict):
        nonce = str(solution.get("nonce", solution.get(response_field, "")))
    else:
        nonce = str(solution)
    return {honeypot_field: "", token_field: item.token, response_field: nonce}


class StravCaptchaSolver:
    """@strav/captcha stateless HMAC-token + hashcash PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        token: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        secret: str | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        token_field: str = DEFAULT_TOKEN_FIELD,
        response_field: str = DEFAULT_RESPONSE_FIELD,
        honeypot_field: str = DEFAULT_HONEYPOT_FIELD,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
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
            "max_attempts": max_attempts,
        }
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "stravcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="stravcaptcha",
                ok=ok,
                captcha_type="stateless_hmac_pow",
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
            source = _load_source(
                token=token,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            challenge = parse_stravcaptcha_challenge(source)
            raw["challenge"] = challenge.to_payload()
            diagnostics.update(
                {
                    "token_type": challenge.payload.token_type,
                    "difficulty": challenge.difficulty,
                    "salt": challenge.challenge,
                    "jti_present": bool(challenge.payload.jti),
                    "expired": stravcaptcha_token_expired(challenge.payload),
                }
            )
            if secret:
                diagnostics["signature_valid"] = verify_stravcaptcha_token_signature(challenge.token, secret)
                if not diagnostics["signature_valid"]:
                    errors.append("Strav CAPTCHA token signature is invalid")
                    return finish(ok=False, verify_code="token_invalid")
            if stravcaptcha_token_expired(challenge.payload):
                errors.append("Strav CAPTCHA token is expired")
                return finish(ok=False, verify_code="token_expired")
            solution = solve_stravcaptcha_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Strav CAPTCHA solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_stravcaptcha_solution(challenge, solution):
                errors.append("Strav CAPTCHA internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            submit_body = build_stravcaptcha_submit_body(
                challenge,
                solution,
                token_field=token_field,
                response_field=response_field,
                honeypot_field=honeypot_field,
            )
            raw["solution"] = {**solution.to_payload(), "submitBody": submit_body}
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash_hex": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            ticket = _json_body(submit_body)
            verify_code = "solved"
            if submit or submit_url:
                if not submit_url:
                    errors.append("submit requested but submit_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp = requests.post(
                    submit_url,
                    data=_json_body(submit_body),
                    headers=_merge_headers(headers, user_agent),
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                payload: Any
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {"text": resp.text[:500]}
                raw["submitResponse"] = {"status": resp.status_code, "url": submit_url, "json": payload}
                if resp.status_code >= 400:
                    errors.append(str(payload))
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                ticket = _json_body(payload) if isinstance(payload, dict) else str(payload)
                verify_code = "validated"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_stravcaptcha_range(
    salt: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    prefix = f"{salt}:".encode("utf-8")
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = hashlib.sha256(prefix + str(nonce).encode("ascii")).hexdigest()
        checked += 1
        if count_leading_zero_bits_hex(digest) >= int(difficulty):
            return nonce, digest, checked
    return None, None, checked


def _load_source(
    *,
    token: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_html: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if token:
        raw["challengeSource"] = "token"
        return {"token": token}
    if challenge_html:
        raw["challengeSource"] = "html"
        return extract_stravcaptcha_from_html(challenge_html)
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("Strav CAPTCHA requires token, challenge_json, challenge_file, challenge_html or challenge_url")
    resp = requests.get(
        challenge_url,
        headers=headers,
        timeout=timeout_sec,
        proxies=_requests_proxies(proxy_server),
    )
    content_type = resp.headers.get("Content-Type", "")
    raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "contentType": content_type}
    resp.raise_for_status()
    if "json" in content_type:
        payload = resp.json()
        raw["challengeResponse"]["json"] = payload
        raw["challengeSource"] = "url_json"
        return payload
    payload = extract_stravcaptcha_from_html(resp.text)
    raw["challengeSource"] = "url_html"
    return payload


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


def _split_token(token: str) -> tuple[str, str]:
    parts = str(token).split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("Strav CAPTCHA token must be base64url(json).base64url(mac)")
    return parts[0], parts[1]


def _validate_payload(payload: StravCaptchaTokenPayload) -> None:
    if payload.version != 1:
        raise ValueError("Strav CAPTCHA token version must be 1")
    if not payload.token_type:
        raise ValueError("Strav CAPTCHA token type is empty")
    if not payload.salt:
        raise ValueError("Strav CAPTCHA token salt is empty")
    if not payload.jti:
        raise ValueError("Strav CAPTCHA token jti is empty")
    if payload.exp_minutes < 0:
        raise ValueError("Strav CAPTCHA token exp must be >= 0")
    if payload.difficulty is not None and not 0 <= payload.difficulty <= 256:
        raise ValueError("Strav CAPTCHA difficulty must be between 0 and 256")


def _b64url_decode(value: str) -> bytes:
    text = value.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text)


def _b64url_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii").rstrip("=").replace("+", "-").replace("/", "_")


def _extract_input_value(text: str, field_name: str) -> str | None:
    pattern = (
        r"<input\b(?=[^>]*\bname=[\"']"
        + re.escape(field_name)
        + r"[\"'])(?P<attrs>[^>]*)>"
    )
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    attrs = m.group("attrs")
    vm = re.search(r"\bvalue=(['\"])(?P<value>.*?)\1", attrs, flags=re.DOTALL)
    return html.unescape(vm.group("value")) if vm else ""


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
