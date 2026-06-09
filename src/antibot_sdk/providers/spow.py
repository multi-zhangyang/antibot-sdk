from __future__ import annotations

import asyncio
import base64
import hashlib
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

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_RESPONSE_FIELD = "pow"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
SPOW_SALT_LEN_B64 = 16
SPOW_CHALLENGE_LEN_B64 = 43
SPOW_VERSION = 1


@dataclass(slots=True)
class SpowChallenge:
    """Parsed spow / leptos-captcha challenge prefix."""

    version: int
    difficulty: int
    expires: int
    salt: str
    challenge: str
    response_field: str = DEFAULT_RESPONSE_FIELD
    raw: dict[str, Any] | None = None
    signature_valid: bool | None = None

    @property
    def challenge_string(self) -> str:
        return f"{self.version}:{self.difficulty}:{self.expires}:{self.salt}:{self.challenge}:"

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "difficulty": self.difficulty,
            "expires": self.expires,
            "salt": self.salt,
            "challenge": self.challenge,
            "challengeString": self.challenge_string,
            "responseField": self.response_field,
            "signatureValid": self.signature_valid,
        }


@dataclass(slots=True)
class SpowSolution:
    challenge: SpowChallenge
    counter: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def solution(self) -> str:
        return f"{self.challenge.challenge_string}{self.counter}"

    @property
    def submit_body(self) -> dict[str, str]:
        return build_spow_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "solution": self.solution,
            "counter": self.counter,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def sign_spow_challenge(
    version: int,
    difficulty: int,
    expires: int,
    salt: str,
    secret: str | bytes,
) -> str:
    """Return spow's STANDARD_NO_PAD base64 SHA-256 challenge signature."""

    # Rust spow::Pow::init_bytes stores STANDARD_NO_PAD.encode(secret_bytes),
    # while Pow::init stores the provided string as-is.
    secret_text = base64.b64encode(secret).decode("ascii").rstrip("=") if isinstance(secret, bytes) else str(secret)
    plain = f"{int(version)}{int(difficulty)}{int(expires)}{salt}{secret_text}"
    digest = hashlib.sha256(plain.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def create_spow_challenge(
    *,
    difficulty: int,
    expires: int,
    salt: str,
    secret: str | bytes,
    response_field: str = DEFAULT_RESPONSE_FIELD,
) -> SpowChallenge:
    challenge = sign_spow_challenge(SPOW_VERSION, difficulty, expires, salt, secret)
    return SpowChallenge(
        version=SPOW_VERSION,
        difficulty=int(difficulty),
        expires=int(expires),
        salt=str(salt),
        challenge=challenge,
        response_field=response_field,
        signature_valid=True,
    )


def spow_hash_bytes(challenge: SpowChallenge | str, counter: int | str | None = None) -> bytes:
    if isinstance(challenge, SpowChallenge):
        prefix = challenge.challenge_string
    else:
        prefix = str(challenge)
    if counter is not None:
        prefix = f"{prefix}{counter}"
    return hashlib.sha256(prefix.encode("utf-8")).digest()


def spow_hash_hex(challenge: SpowChallenge | str, counter: int | str | None = None) -> str:
    return spow_hash_bytes(challenge, counter).hex()


def count_leading_zero_bits_bytes(data: bytes) -> int:
    total = 0
    for byte in data:
        if byte == 0:
            total += 8
            continue
        return total + (8 - byte.bit_length())
    return total


def spow_hash_matches(hash_bytes_or_hex: bytes | str, difficulty: int) -> bool:
    if isinstance(hash_bytes_or_hex, str):
        data = bytes.fromhex(hash_bytes_or_hex)
    else:
        data = bytes(hash_bytes_or_hex)
    return count_leading_zero_bits_bytes(data) >= int(difficulty)


def parse_spow_challenge(
    value: SpowChallenge | dict[str, Any] | str,
    *,
    secret: str | bytes | None = None,
    response_field: str | None = None,
) -> SpowChallenge:
    if isinstance(value, SpowChallenge):
        if response_field:
            value.response_field = response_field
        if secret is not None:
            value.signature_valid = verify_spow_challenge_signature(value, secret)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("spow challenge is empty")
        if text.startswith("@"):
            return parse_spow_challenge(
                Path(text[1:]).read_text(encoding="utf-8"),
                secret=secret,
                response_field=response_field,
            )
        if "<" in text and ("leptos-captcha" in text or "pow" in text):
            return parse_spow_challenge(
                extract_spow_from_html(text),
                secret=secret,
                response_field=response_field,
            )
        if text.startswith("{"):
            return parse_spow_challenge(json.loads(text), secret=secret, response_field=response_field)
        parsed = _parse_spow_string(text)
        return SpowChallenge(
            version=parsed["version"],
            difficulty=parsed["difficulty"],
            expires=parsed["expires"],
            salt=parsed["salt"],
            challenge=parsed["challenge"],
            response_field=response_field or DEFAULT_RESPONSE_FIELD,
            raw={"input": text, "counter": parsed.get("counter")},
            signature_valid=(
                verify_spow_signature_parts(
                    parsed["version"], parsed["difficulty"], parsed["expires"], parsed["salt"], parsed["challenge"], secret
                )
                if secret is not None
                else None
            ),
        )
    if not isinstance(value, dict):
        raise ValueError("spow challenge must be string, JSON object, HTML, or SpowChallenge")
    item = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge_text = _first_str(item, "pow", "challenge", "puzzle", "captcha", "work")
    if challenge_text:
        parsed = parse_spow_challenge(str(challenge_text), secret=secret, response_field=response_field)
        parsed.raw = value
        parsed.response_field = response_field or _first_str(item, "responseField", "response_field", "field") or parsed.response_field
        return parsed
    required = {"version", "difficulty", "expires", "salt"}
    if not required <= set(item):
        raise ValueError("spow JSON requires pow/challenge string or version,difficulty,expires,salt,challenge")
    version = int(item.get("version", SPOW_VERSION))
    difficulty = int(item["difficulty"])
    expires = int(item["expires"])
    salt = str(item["salt"])
    challenge = _first_str(item, "signature", "challengeHash", "challenge_hash", "challenge")
    if not challenge:
        if secret is None:
            raise ValueError("spow JSON without challenge signature requires secret")
        challenge = sign_spow_challenge(version, difficulty, expires, salt, secret)
    out = SpowChallenge(
        version=version,
        difficulty=difficulty,
        expires=expires,
        salt=salt,
        challenge=str(challenge),
        response_field=response_field or _first_str(item, "responseField", "response_field", "field") or DEFAULT_RESPONSE_FIELD,
        raw=value,
    )
    _validate_spow_challenge_shape(out)
    out.signature_valid = verify_spow_challenge_signature(out, secret) if secret is not None else None
    return out


def extract_spow_from_html(html_text: str) -> dict[str, Any]:
    text = str(html_text)
    for pattern in (
        r"data-(?:pow|challenge|pow-challenge)\s*=\s*(['\"])(?P<value>1:\d{2}:\d{10}:[^'\"]+)\1",
        r"value\s*=\s*(['\"])(?P<value>1:\d{2}:\d{10}:[^'\"]+)\1",
    ):
        m = re.search(pattern, text, flags=re.I | re.S)
        if m:
            return {"pow": html.unescape(m.group("value")), "responseField": _extract_pow_field(text)}
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", text, flags=re.I | re.S)
    for script in scripts:
        m = re.search(r"1:\d{2}:\d{10}:[A-Za-z0-9+/]{16}:[A-Za-z0-9+/]{43}:", script)
        if m:
            return {"pow": html.unescape(m.group(0)), "responseField": _extract_pow_field(text)}
    raise ValueError("spow HTML does not contain a challenge string")


def solve_spow_challenge(
    challenge: SpowChallenge | dict[str, Any] | str,
    *,
    secret: str | bytes | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> SpowSolution | None:
    item = parse_spow_challenge(challenge, secret=secret)
    started = time.monotonic()
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None
    counter, digest, attempts = solve_spow_counter(
        item,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        deadline_epoch=deadline_epoch,
    )
    if counter is None or digest is None:
        return None
    return SpowSolution(
        challenge=item,
        counter=str(counter),
        hash_hex=digest,
        attempts=attempts,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def solve_spow_counter(
    challenge: SpowChallenge | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    item = parse_spow_challenge(challenge) if not isinstance(challenge, SpowChallenge) else challenge
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if workers <= 1 or max_attempts < 100_000:
        return _solve_spow_range(item.challenge_string, item.difficulty, start, start + max_attempts, deadline_epoch)

    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    completed: dict[int, tuple[int | None, str | None, int]] = {}
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(_solve_spow_range, item.challenge_string, item.difficulty, lo, hi, deadline_epoch): idx
        for idx, (lo, hi) in enumerate(ranges)
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx = futures[fut]
            counter, digest, checked = fut.result()
            completed[idx] = (counter, digest, checked)
            checked_total += checked
            best_ready: tuple[int, str] | None = None
            for prior_idx in range(len(ranges)):
                if prior_idx not in completed:
                    break
                p_counter, p_digest, _p_checked = completed[prior_idx]
                if p_counter is not None and p_digest is not None:
                    best_ready = (p_counter, p_digest)
                    break
            if best_ready is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return best_ready[0], best_ready[1], checked_total
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None, None, checked_total
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None, None, checked_total


def verify_spow_challenge_signature(challenge: SpowChallenge | dict[str, Any] | str, secret: str | bytes) -> bool:
    try:
        item = parse_spow_challenge(challenge) if not isinstance(challenge, SpowChallenge) else challenge
        return verify_spow_signature_parts(
            item.version,
            item.difficulty,
            item.expires,
            item.salt,
            item.challenge,
            secret,
        )
    except Exception:
        return False


def verify_spow_signature_parts(
    version: int,
    difficulty: int,
    expires: int,
    salt: str,
    challenge: str,
    secret: str | bytes | None,
) -> bool:
    if secret is None:
        return False
    return sign_spow_challenge(version, difficulty, expires, salt, secret) == challenge


def verify_spow_solution(
    challenge: SpowChallenge | dict[str, Any] | str,
    solution: SpowSolution | dict[str, Any] | str,
    *,
    secret: str | bytes | None = None,
    now: int | None = None,
    check_expiry: bool = True,
) -> bool:
    try:
        item = parse_spow_challenge(challenge, secret=secret)
        if isinstance(solution, SpowSolution):
            solved_text = solution.solution
        elif isinstance(solution, dict):
            solved_text = str(solution.get("solution") or solution.get(item.response_field) or solution.get("pow") or "")
        else:
            solved_text = str(solution)
        parsed = _parse_spow_string(solved_text)
        if parsed.get("counter") in (None, ""):
            return False
        if (
            parsed["version"] != item.version
            or parsed["difficulty"] != item.difficulty
            or parsed["expires"] != item.expires
            or parsed["salt"] != item.salt
            or parsed["challenge"] != item.challenge
        ):
            return False
        if secret is not None and not verify_spow_challenge_signature(item, secret):
            return False
        if check_expiry and int(now if now is not None else time.time()) > item.expires:
            return False
        return spow_hash_matches(spow_hash_bytes(solved_text), item.difficulty)
    except Exception:
        return False


def build_spow_submit_body(
    challenge: SpowChallenge | dict[str, Any] | str,
    solution: SpowSolution | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> dict[str, str]:
    item = parse_spow_challenge(challenge, response_field=response_field)
    if isinstance(solution, SpowSolution):
        value = solution.solution
    elif isinstance(solution, dict):
        value = str(solution.get("solution") or solution.get(item.response_field) or solution.get("pow") or "")
    else:
        value = str(solution)
    return {response_field or item.response_field: value}


class SpowSolver:
    """spow / leptos-captcha signed SHA-256 leading-zero PoW solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        submit_format: str = "json",
        secret: str | bytes | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        response_field: str | None = None,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "verify_url": verify_url,
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
                out = output_root / "spow_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="spow",
                ok=ok,
                captcha_type="signed_hashcash_pow",
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
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            item = parse_spow_challenge(source, secret=secret, response_field=response_field)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "difficulty": item.difficulty,
                    "expires": item.expires,
                    "expired": int(time.time()) > item.expires,
                    "signature_valid": item.signature_valid,
                    "response_field": item.response_field,
                }
            )
            solution = solve_spow_challenge(
                item,
                secret=secret,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("spow solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_spow_solution(item, solution, secret=secret, check_expiry=False):
                errors.append("spow internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            submit_body = build_spow_submit_body(item, solution, response_field=response_field)
            raw["solution"] = {**solution.to_payload(), "submitBody": submit_body}
            diagnostics.update(
                {
                    "counter": solution.counter,
                    "solution_length": len(solution.solution),
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            if submit:
                if not verify_url:
                    errors.append("--submit requires verify_url")
                    return finish(ok=False, verify_code="missing_verify_url")
                resp = _post_verify(
                    verify_url,
                    submit_body,
                    submit_format=submit_format,
                    headers=_merge_headers(headers, user_agent),
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                )
                raw["verifyResponse"] = resp
                if not resp.get("ok"):
                    errors.append(f"spow verify submit failed: HTTP {resp.get('status')}")
                    return finish(ok=False, ticket=_json_body(submit_body), verify_code="verify_failed")
                return finish(ok=True, ticket=_json_body(submit_body), verify_code="validated")
            return finish(ok=True, ticket=_json_body(submit_body), verify_code="solved")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_spow_range(
    challenge_string: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    checked = 0
    prefix_bytes = str(challenge_string).encode("utf-8")
    base_hasher = hashlib.sha256(prefix_bytes)
    target_bits = int(difficulty)
    for counter in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        hasher = base_hasher.copy()
        hasher.update(str(counter).encode("ascii"))
        digest = hasher.digest()
        checked += 1
        if count_leading_zero_bits_bytes(digest) >= target_bits:
            return counter, digest.hex(), checked
    return None, None, checked


def _parse_spow_string(text: str) -> dict[str, Any]:
    parts = str(text).strip().split(":")
    if len(parts) < 6:
        raise ValueError("spow string requires version:difficulty:expires:salt:challenge:")
    version_s, difficulty_s, expires_s, salt, challenge = parts[:5]
    counter = ":".join(parts[5:]) if len(parts) > 6 else parts[5]
    if version_s != "1":
        raise ValueError("spow version must be 1")
    if not re.fullmatch(r"\d{2}", difficulty_s):
        raise ValueError("spow difficulty must be two digits")
    if not re.fullmatch(r"\d{10}", expires_s):
        raise ValueError("spow expires must be a 10-digit Unix timestamp")
    out = {
        "version": int(version_s),
        "difficulty": int(difficulty_s),
        "expires": int(expires_s),
        "salt": salt,
        "challenge": challenge,
        "counter": counter,
    }
    _validate_spow_challenge_shape(
        SpowChallenge(
            version=out["version"],
            difficulty=out["difficulty"],
            expires=out["expires"],
            salt=out["salt"],
            challenge=out["challenge"],
        )
    )
    return out


def _validate_spow_challenge_shape(item: SpowChallenge) -> None:
    if item.version != SPOW_VERSION:
        raise ValueError("spow version must be 1")
    if not 10 <= item.difficulty < 99:
        raise ValueError("spow difficulty must be between 10 and 98")
    if len(str(item.expires)) != 10:
        raise ValueError("spow expires must be a 10-digit Unix timestamp")
    if len(item.salt) != SPOW_SALT_LEN_B64:
        raise ValueError("spow salt must be 16 base64 chars")
    if len(item.challenge) != SPOW_CHALLENGE_LEN_B64:
        raise ValueError("spow challenge signature must be 43 base64 chars")


def _load_source(
    *,
    challenge: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_html: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if challenge:
        raw["challengeSource"] = "string"
        return challenge
    if challenge_html:
        raw["challengeSource"] = "html"
        return extract_spow_from_html(challenge_html)
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("spow requires challenge, challenge_json, challenge_file, challenge_html or challenge_url")
    resp = requests.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    content_type = resp.headers.get("Content-Type", "")
    raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "contentType": content_type}
    resp.raise_for_status()
    if "json" in content_type:
        payload = resp.json()
        raw["challengeResponse"]["json"] = payload
        raw["challengeSource"] = "url_json"
        return payload
    text = resp.text.strip()
    raw["challengeSource"] = "url_html" if "<" in text else "url_text"
    if "<" in text:
        return extract_spow_from_html(text)
    return text.strip('"')


def _post_verify(
    verify_url: str,
    submit_body: dict[str, str],
    *,
    submit_format: str,
    headers: dict[str, str],
    timeout_sec: int,
    proxy_server: str | None,
) -> dict[str, Any]:
    if submit_format not in {"json", "form"}:
        raise ValueError("submit_format must be json or form")
    if submit_format == "form":
        resp = requests.post(
            verify_url,
            data=submit_body,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
    else:
        resp = requests.post(
            verify_url,
            json=submit_body,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
    payload: Any
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text[:500]
    ok = 200 <= resp.status_code < 400 and not (
        isinstance(payload, dict) and payload.get("ok") is False
    )
    return {"ok": ok, "status": resp.status_code, "body": payload}


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


def _first_str(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return None


def _extract_pow_field(text: str) -> str:
    m = re.search(r"<input\b(?=[^>]*(?:id|name)=['\"]pow['\"])(?P<attrs>[^>]*)>", text, flags=re.I | re.S)
    if not m:
        return DEFAULT_RESPONSE_FIELD
    attrs = _parse_attrs(m.group("attrs"))
    return attrs.get("name") or attrs.get("id") or DEFAULT_RESPONSE_FIELD


def _parse_attrs(attrs: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(['\"])(.*?)\2", attrs, flags=re.DOTALL):
        out[m.group(1).lower()] = html.unescape(m.group(3))
    return out


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
    }
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
