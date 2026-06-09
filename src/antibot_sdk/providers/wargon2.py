from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
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
from urllib.parse import urljoin

import requests
from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT = 20
DEFAULT_MAX_ATTEMPTS = 10_000_000
DEFAULT_CHUNK_SIZE = 128
DEFAULT_CHALLENGE_PATH = "/api/v1/challenge"
DEFAULT_VERIFY_PATH = "/api/v1/verify"
DEFAULT_AES_KEY_B64 = "Njfhk4k2rMQ5903sPRPuPxzoVyGfg9xScz2XMMMkvjM="
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "application/json,text/plain,*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}
DEFAULT_FINGERPRINT: dict[str, Any] = {
    "userAgent": DEFAULT_HEADERS["User-Agent"],
    "language": "en-US",
    "platform": "Linux x86_64",
    "hardwareConcurrency": 8,
    "maxTouchPoints": 0,
    "colorDepth": 24,
    "pixelRatio": 1,
    "timezone": "0",
    "cookieEnabled": True,
    "doNotTrack": "unspecified",
    "screenResolution": "1920x1080",
    "availableScreenResolution": "1920x1040",
}


@dataclass(frozen=True, slots=True)
class Wargon2Challenge:
    """femshift/wargon2-captcha challenge payload.

    Upstream computes Argon2id over ``salt_b64 + nonce_decimal`` while using the decoded
    salt bytes as Argon2 salt. ``difficulty`` is Argon2 time cost, not leading-zero bits.
    """

    id: str
    salt: str
    difficulty: int
    memory: int
    threads: int
    key_len: int
    target: str
    created_at: str | None = None
    expires_at: str | None = None
    solved: bool | None = None
    raw: dict[str, Any] | None = None

    @property
    def salt_bytes(self) -> bytes:
        return base64.b64decode(self.salt, validate=True)

    @property
    def target_nibbles(self) -> int:
        return len(self.target)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "salt": self.salt,
            "difficulty": self.difficulty,
            "memory": self.memory,
            "threads": self.threads,
            "keyLen": self.key_len,
            "target": self.target,
        }
        if self.created_at is not None:
            payload["createdAt"] = self.created_at
        if self.expires_at is not None:
            payload["expiresAt"] = self.expires_at
        if self.solved is not None:
            payload["solved"] = self.solved
        return payload


@dataclass(frozen=True, slots=True)
class Wargon2Solution:
    challenge: Wargon2Challenge
    nonce: str
    hash_hex: str
    attempts: int
    elapsed_ms: int
    fingerprint: str | None = None
    fingerprint_data: dict[str, Any] | None = None

    @property
    def verify_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "challengeId": self.challenge.id,
            "nonce": self.nonce,
            "hash": self.hash_hex,
        }
        if self.fingerprint is not None:
            body["fingerprint"] = self.fingerprint
        return body


class Wargon2FingerprintError(ValueError):
    """Raised when a Wargon2 WASM fingerprint cannot be decoded or validated."""


def parse_wargon2_challenge(data: Wargon2Challenge | dict[str, Any] | str) -> Wargon2Challenge:
    if isinstance(data, Wargon2Challenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if not text:
            raise ValueError("Wargon2 challenge string is empty")
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Wargon2 challenge must be a JSON object")

    obj = dict(data)
    if "challenge" in obj and isinstance(obj["challenge"], dict):
        obj = dict(obj["challenge"])

    challenge_id = str(
        obj.get("id") or obj.get("challengeId") or obj.get("challenge_id") or ""
    ).strip()
    if not challenge_id:
        raise ValueError("Wargon2 challenge id is missing")

    salt = str(obj.get("salt") or obj.get("saltB64") or obj.get("salt_b64") or "").strip()
    if not salt:
        raise ValueError("Wargon2 challenge salt is missing")

    difficulty = _get_int(obj, "difficulty", "time", "timeCost", "time_cost", default=1)
    memory = _get_int(obj, "memory", "mem", "memoryCost", "memory_cost", default=65_536)
    threads = _get_int(obj, "threads", "parallelism", "p", default=1)
    key_len = _get_int(obj, "keyLen", "key_len", "hashLen", "keyLength", default=32)
    target = str(obj.get("target") or obj.get("targetPrefix") or obj.get("prefix") or "").lower()
    target = target.strip()

    item = Wargon2Challenge(
        id=challenge_id,
        salt=salt,
        difficulty=difficulty,
        memory=memory,
        threads=threads,
        key_len=key_len,
        target=target,
        created_at=_optional_str(obj.get("createdAt") or obj.get("created_at")),
        expires_at=_optional_str(obj.get("expiresAt") or obj.get("expires_at")),
        solved=_optional_bool(obj.get("solved")),
        raw=dict(data),
    )
    _validate_wargon2_challenge(item)
    return item


def wargon2_hash(challenge: Wargon2Challenge | dict[str, Any] | str, nonce: int | str) -> bytes:
    item = parse_wargon2_challenge(challenge)
    nonce_text = _normalize_nonce(nonce)
    return hash_secret_raw(
        secret=(item.salt + nonce_text).encode("utf-8"),
        salt=item.salt_bytes,
        time_cost=item.difficulty,
        memory_cost=item.memory,
        parallelism=item.threads,
        hash_len=item.key_len,
        type=Type.ID,
        version=19,
    )


def wargon2_hash_hex(challenge: Wargon2Challenge | dict[str, Any] | str, nonce: int | str) -> str:
    return wargon2_hash(challenge, nonce).hex()


def verify_wargon2_solution(
    challenge: Wargon2Challenge | dict[str, Any] | str,
    nonce: int | str,
    hash_hex: str | None = None,
    *,
    fingerprint: str | None = None,
    aes_key: str | bytes | None = None,
    validate_fingerprint: bool = False,
) -> bool:
    try:
        item = parse_wargon2_challenge(challenge)
        computed = wargon2_hash_hex(item, nonce)
        if not computed.startswith(item.target):
            return False
        if hash_hex is not None:
            actual = str(hash_hex).strip().lower()
            if not hmac.compare_digest(computed, actual):
                return False
        if validate_fingerprint or fingerprint is not None:
            if not fingerprint:
                return False
            fp = decrypt_wargon2_fingerprint(fingerprint, aes_key=aes_key)
            validate_wargon2_fingerprint(fp)
        return True
    except Exception:
        return False


def solve_wargon2_nonce(
    challenge: Wargon2Challenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT,
) -> tuple[str, str, int]:
    item = parse_wargon2_challenge(challenge)
    start = int(start)
    max_attempts = int(max_attempts)
    workers = max(1, int(workers or 1))
    chunk_size = max(1, int(chunk_size or DEFAULT_CHUNK_SIZE))
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers == 1:
        nonce, digest, attempts = _search_wargon2_range(item, start, start + max_attempts, deadline)
        if nonce is None or digest is None:
            raise TimeoutError(f"no Wargon2 nonce found within {max_attempts} attempts")
        return str(nonce), digest, attempts

    workers = _bounded_workers(workers, memory_kib_per_worker=max(16_384, item.memory * 2))
    submitted = 0
    checked_hint = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    pool_kwargs = _process_pool_kwargs(workers)
    with ProcessPoolExecutor(**pool_kwargs) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_wargon2_range, item, next_start, end, deadline)] = (
                next_start,
                end,
            )
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                begin, end = futures.pop(fut)
                nonce, digest, attempts = fut.result()
                checked_hint += attempts or max(0, end - begin)
                if nonce is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return str(nonce), digest, checked_hint
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_wargon2_range, item, next_start, nend, deadline)] = (
                        next_start,
                        nend,
                    )
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no Wargon2 nonce found within {max_attempts} attempts")


def solve_wargon2_challenge(
    challenge: Wargon2Challenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT,
    fingerprint: dict[str, Any] | None = None,
    aes_key: str | bytes | None = None,
    include_fingerprint: bool = False,
    aes_nonce: bytes | str | None = None,
) -> Wargon2Solution:
    item = parse_wargon2_challenge(challenge)
    started = time.monotonic()
    nonce, digest, attempts = solve_wargon2_nonce(
        item,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
        timeout_sec=timeout_sec,
    )
    token = None
    fp_data = None
    if include_fingerprint or fingerprint is not None or aes_key is not None:
        fp_data = default_wargon2_fingerprint(**(fingerprint or {}))
        token = synthesize_wargon2_fingerprint(fp_data, aes_key=aes_key, nonce=aes_nonce)
    solution = Wargon2Solution(
        challenge=item,
        nonce=nonce,
        hash_hex=digest,
        attempts=attempts,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        fingerprint=token,
        fingerprint_data=fp_data,
    )
    if not verify_wargon2_solution(
        item,
        solution.nonce,
        solution.hash_hex,
        fingerprint=solution.fingerprint,
        aes_key=aes_key,
        validate_fingerprint=solution.fingerprint is not None,
    ):
        raise ValueError("Wargon2 internal solution verification failed")
    return solution


def default_wargon2_fingerprint(**overrides: Any) -> dict[str, Any]:
    data = dict(DEFAULT_FINGERPRINT)
    data.update({key: value for key, value in overrides.items() if value is not None})
    return data


def synthesize_wargon2_fingerprint(
    fingerprint: dict[str, Any] | None = None,
    *,
    aes_key: str | bytes | None = None,
    nonce: bytes | str | None = None,
) -> str:
    data = default_wargon2_fingerprint(**(fingerprint or {}))
    validate_wargon2_fingerprint(data)
    key = parse_wargon2_aes_key(aes_key)
    iv = _normalize_aes_nonce(nonce) if nonce is not None else os.urandom(12)
    plaintext = _fingerprint_plaintext(data)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(iv + ciphertext + tag).decode("ascii")


def decrypt_wargon2_fingerprint(
    encrypted_fingerprint: str,
    *,
    aes_key: str | bytes | None = None,
) -> dict[str, Any]:
    try:
        raw = base64.b64decode(str(encrypted_fingerprint), validate=True)
    except binascii.Error as exc:
        raise Wargon2FingerprintError("Wargon2 fingerprint is not valid base64") from exc
    if len(raw) < 12 + 16:
        raise Wargon2FingerprintError("Wargon2 fingerprint ciphertext is too short")
    key = parse_wargon2_aes_key(aes_key)
    iv = raw[:12]
    ciphertext = raw[12:-16]
    tag = raw[-16:]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
        reversed_b64 = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        json_raw = base64.b64decode(reversed_b64[::-1], validate=True)
        data = json.loads(json_raw.decode("utf-8"))
    except Exception as exc:
        raise Wargon2FingerprintError("failed to decrypt Wargon2 fingerprint") from exc
    if not isinstance(data, dict):
        raise Wargon2FingerprintError("Wargon2 fingerprint JSON must be an object")
    return data


def validate_wargon2_fingerprint(data: dict[str, Any]) -> None:
    errors = wargon2_fingerprint_errors(data)
    if errors:
        raise Wargon2FingerprintError("; ".join(errors))


def wargon2_fingerprint_errors(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    ua = str(data.get("userAgent") or "")
    if len(ua) < 10 or len(ua) > 1000:
        errors.append("userAgent length out of range")
    elif not any(re.search(pattern, ua) for pattern in _UA_PATTERNS):
        errors.append("userAgent format not recognized")

    lang = str(data.get("language") or "")
    if len(lang) < 2 or len(lang) > 10 or not re.fullmatch(r"[a-z]{2}(-[A-Z]{2})?", lang):
        errors.append("language format invalid")

    platform = str(data.get("platform") or "")
    if not any(valid in platform for valid in _VALID_PLATFORMS):
        errors.append("platform not recognized")

    hardware = _as_int(data.get("hardwareConcurrency"), default=-1)
    if hardware < 1 or hardware > 128:
        errors.append("hardwareConcurrency out of range")

    touch = _as_int(data.get("maxTouchPoints"), default=-1)
    if touch < 0 or touch > 10:
        errors.append("maxTouchPoints out of range")

    color_depth = _as_int(data.get("colorDepth"), default=-1)
    if color_depth not in {8, 16, 24, 30, 32, 48}:
        errors.append("colorDepth not valid")

    try:
        pixel_ratio = float(data.get("pixelRatio"))
    except (TypeError, ValueError):
        pixel_ratio = -1.0
    if pixel_ratio < 0.5 or pixel_ratio > 5.0:
        errors.append("pixelRatio out of range")

    timezone = str(data.get("timezone") or "")
    if len(timezone) == 0 or len(timezone) > 10 or not re.fullmatch(r"-?\d+", timezone):
        errors.append("timezone format invalid")
    else:
        offset = int(timezone)
        if offset < -840 or offset > 720:
            errors.append("timezone offset out of range")

    if str(data.get("doNotTrack") if data.get("doNotTrack") is not None else "") not in {
        "1",
        "0",
        "unspecified",
        "null",
        "",
    }:
        errors.append("doNotTrack value invalid")

    if "cookieEnabled" not in data or not isinstance(data.get("cookieEnabled"), bool):
        errors.append("cookieEnabled must be boolean")

    for key in ("screenResolution", "availableScreenResolution"):
        if not _valid_resolution(str(data.get(key) or "")):
            errors.append(f"{key} format invalid")
    return errors


def parse_wargon2_aes_key(value: str | bytes | None = None) -> bytes:
    if value is None:
        value = DEFAULT_AES_KEY_B64
    if isinstance(value, bytes):
        key = bytes(value)
    else:
        text = str(value).strip()
        if text.startswith("@"):
            text = _read_aes_key_config(Path(text[1:]))
        elif "AES_KEY=" in text:
            match = re.search(r"(?m)^\s*AES_KEY\s*=\s*([^\s#]+)", text)
            if not match:
                raise ValueError("AES_KEY entry not found")
            text = match.group(1).strip()
        elif Path(text).is_file() if text and len(text) < 240 else False:
            text = _read_aes_key_config(Path(text))
        try:
            key = base64.b64decode(text, validate=True)
        except binascii.Error:
            if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) in {32, 48, 64}:
                key = bytes.fromhex(text)
            else:
                raise ValueError("Wargon2 AES key must be base64, hex, bytes, or @config.env")
    if len(key) not in {16, 24, 32}:
        raise ValueError("Wargon2 AES key must be 16, 24, or 32 bytes")
    return key


class Wargon2Solver:
    """Protocol-level Wargon2 captcha solver; no browser or WASM runtime is required."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: Wargon2Challenge | dict[str, Any] | str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        base_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout_sec: int | float | None = DEFAULT_TIMEOUT,
        fingerprint: dict[str, Any] | None = None,
        aes_key: str | bytes | None = None,
        proxy_server: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "base_url": base_url,
            "verify_url": verify_url,
            "submit": submit,
            "browser": "not_used",
            "proxy": redacted_proxy(proxy_server),
            "workers": workers,
            "max_attempts": max_attempts,
        }

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            raw["ok"] = ok
            raw["elapsedMs"] = elapsed_ms
            return CaptchaResult(
                provider="wargon2",
                ok=ok,
                captcha_type="argon2id_prefix_pow_fingerprint",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge_id"),
                verify_code=verify_code,
                elapsed_ms=elapsed_ms,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            loaded = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                base_url=base_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_wargon2_challenge(loaded)
            diagnostics.update(
                {
                    "challenge_id": item.id,
                    "difficulty": item.difficulty,
                    "memory": item.memory,
                    "threads": item.threads,
                    "key_len": item.key_len,
                    "target": item.target,
                }
            )
            raw["challenge"] = item.to_payload()

            solution = solve_wargon2_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
                timeout_sec=timeout_sec,
                fingerprint=fingerprint,
                aes_key=aes_key,
                include_fingerprint=True,
            )
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "attempts": solution.attempts,
                "elapsedMs": solution.elapsed_ms,
                "hasFingerprint": solution.fingerprint is not None,
            }
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.elapsed_ms,
                }
            )
            ticket = json.dumps(solution.verify_body, separators=(",", ":"), ensure_ascii=False)
            verify_code = "solved"

            if submit or verify_url:
                target = verify_url or _join_url(base_url, DEFAULT_VERIFY_PATH)
                if not target:
                    errors.append("Wargon2 submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_verify(
                    verify_url=target,
                    body=solution.verify_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                valid = bool(verify_data.get("valid") or verify_data.get("success"))
                if not valid:
                    errors.append(str(verify_data.get("message") or "Wargon2 verify rejected solution"))
                    return finish(ok=False, ticket=ticket, verify_code="rejected")
                verify_code = "verified"
                raw["verify"] = verify_data
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge: Wargon2Challenge | dict[str, Any] | str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        base_url: str | None,
        timeout_sec: int | float | None,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        if challenge_json is not None:
            return challenge_json
        if challenge is not None:
            return challenge
        if challenge_file:
            return json.loads(Path(challenge_file).read_text(encoding="utf-8"))
        target = challenge_url or _join_url(base_url, DEFAULT_CHALLENGE_PATH)
        if not target:
            raise ValueError("Wargon2 challenge/challenge_url/base_url is required")
        session = requests.Session()
        response = session.get(
            target,
            headers=_headers(headers),
            proxies=_requests_proxies(proxy_server),
            timeout=timeout_sec or DEFAULT_TIMEOUT,
        )
        raw["challengeStatus"] = response.status_code
        response.raise_for_status()
        payload = response.json()
        raw["challengeResponse"] = payload
        return payload

    def _submit_verify(
        self,
        *,
        verify_url: str,
        body: dict[str, Any],
        timeout_sec: int | float | None,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        response = requests.post(
            verify_url,
            json=body,
            headers=_headers(headers, content_type=True),
            proxies=_requests_proxies(proxy_server),
            timeout=timeout_sec or DEFAULT_TIMEOUT,
        )
        raw["verifyStatus"] = response.status_code
        try:
            payload = response.json()
        except ValueError:
            payload = {"valid": False, "message": response.text[:500]}
        if response.status_code >= 400 and "valid" not in payload and "success" not in payload:
            response.raise_for_status()
        return payload


def _search_wargon2_range(
    challenge: Wargon2Challenge,
    start: int,
    end_exclusive: int,
    deadline: float | None,
) -> tuple[int | None, str | None, int]:
    attempts = 0
    for nonce in range(int(start), int(end_exclusive)):
        if deadline is not None and attempts and attempts % 4 == 0 and time.monotonic() >= deadline:
            return None, None, attempts
        attempts += 1
        digest = wargon2_hash_hex(challenge, nonce)
        if digest.startswith(challenge.target):
            return nonce, digest, attempts
    return None, None, attempts


def _validate_wargon2_challenge(item: Wargon2Challenge) -> None:
    try:
        salt = base64.b64decode(item.salt, validate=True)
    except binascii.Error as exc:
        raise ValueError("Wargon2 salt must be standard base64") from exc
    if len(salt) < 8 or len(salt) > 128:
        raise ValueError("Wargon2 salt must be 8..128 bytes")
    if not 1 <= item.difficulty <= 20:
        raise ValueError("Wargon2 difficulty/time cost must be 1..20")
    if not 8 <= item.memory <= 1_048_576:
        raise ValueError("Wargon2 memory cost must be 8..1048576 KiB")
    if not 1 <= item.threads <= 16:
        raise ValueError("Wargon2 threads must be 1..16")
    if item.memory < 8 * item.threads:
        raise ValueError("Wargon2 memory cost must be at least 8 * threads")
    if not 4 <= item.key_len <= 128:
        raise ValueError("Wargon2 keyLen must be 4..128")
    if not re.fullmatch(r"[0-9a-f]*", item.target):
        raise ValueError("Wargon2 target must be a lowercase/uppercase hex prefix")
    if len(item.target) > item.key_len * 2:
        raise ValueError("Wargon2 target prefix is longer than hash output")


def _fingerprint_plaintext(data: dict[str, Any]) -> bytes:
    json_raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(json_raw)[::-1]


def _normalize_aes_nonce(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        text = str(value).strip()
        if re.fullmatch(r"[0-9a-fA-F]{24}", text):
            raw = bytes.fromhex(text)
        else:
            raw = base64.b64decode(text, validate=True)
    if len(raw) != 12:
        raise ValueError("Wargon2 AES-GCM nonce must be 12 bytes")
    return raw


def _read_aes_key_config(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"(?m)^\s*AES_KEY\s*=\s*([^\s#]+)", text)
    if not match:
        raise ValueError(f"AES_KEY not found in {path}")
    return match.group(1).strip()


def _get_int(obj: dict[str, Any], *keys: str, default: int) -> int:
    for key in keys:
        if key in obj and obj[key] is not None:
            return int(obj[key])
    return default


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _normalize_nonce(value: int | str) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("nonce must be non-negative")
        return str(value)
    text = str(value).strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError("nonce must be a decimal string")
    return str(int(text))


def _as_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _valid_resolution(value: str) -> bool:
    match = re.fullmatch(r"(\d+)x(\d+)", value)
    if not match:
        return False
    width, height = int(match.group(1)), int(match.group(2))
    return 100 <= width <= 10000 and 100 <= height <= 10000


def _join_url(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _headers(headers: dict[str, str] | None = None, *, content_type: bool = False) -> dict[str, str]:
    merged = dict(DEFAULT_HEADERS)
    if content_type:
        merged["Content-Type"] = "application/json"
    if headers:
        merged.update(headers)
    return merged


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _bounded_workers(requested: int, *, memory_kib_per_worker: int = 0) -> int:
    cpu_cap = max(1, os.cpu_count() or 1)
    env_cap = _env_int("ANTIBOT_MAX_WORKERS", cpu_cap)
    workers = min(max(1, int(requested or 1)), cpu_cap, max(1, env_cap))
    if memory_kib_per_worker > 0 and (available := _available_memory_kib()):
        reserve_kib = max(0, _env_int("ANTIBOT_MEMORY_RESERVE_MIB", 256)) * 1024
        budget = max(0, available - reserve_kib)
        workers = min(workers, max(1, budget // max(1, int(memory_kib_per_worker))))
    return max(1, workers)


def _available_memory_kib() -> int | None:
    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _process_pool_kwargs(workers: int) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"max_workers": workers}
    method = os.environ.get("ANTIBOT_MP_CONTEXT", "forkserver")
    try:
        kwargs["mp_context"] = mp.get_context(method)
    except ValueError:
        pass
    return kwargs


_UA_PATTERNS = [
    r"Mozilla/\d+\.\d+",
    r"Chrome/\d+\.\d+",
    r"Safari/\d+\.\d+",
    r"Firefox/\d+\.\d+",
    r"Edge/\d+\.\d+",
]
_VALID_PLATFORMS = (
    "Win32",
    "MacIntel",
    "Linux x86_64",
    "Linux i686",
    "iPhone",
    "iPad",
    "Android",
    "X11",
)
