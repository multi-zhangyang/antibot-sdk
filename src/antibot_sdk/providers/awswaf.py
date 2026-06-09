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
import zlib
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from Crypto.Cipher import AES

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_ATTEMPTS = 5_000_000
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_BASE_URL = "https://example.com"
AWSWAF_TOKEN_COOKIE = "aws-waf-token"
TYPE_SCRYPT_PREFIX = "h72f957df"
TYPE_SHA2_PREFIX = "h7b0c470f"
TYPE_MP_VERIFY_PREFIX = "ha9faaffd"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True, slots=True)
class AwsWafCryptoConfig:
    key: bytes
    identifier: str
    signal_version: str = "2.4.0"
    type_names: dict[str, str] | None = None

    @property
    def key_hex(self) -> str:
        return self.key.hex()


@dataclass(frozen=True, slots=True)
class AwsWafChallenge:
    input: str
    hmac: str = ""
    region: str = ""
    challenge_type: str = ""
    difficulty: int = 0
    memory: int = 0
    raw_js: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def inner_challenge_type(self) -> str | None:
        return awswaf_inner_challenge_type(self.input)


@dataclass(frozen=True, slots=True)
class AwsWafSolution:
    challenge: AwsWafChallenge
    checksum: str
    solution: str
    mode: str
    digest_hex: str | None
    elapsed_ms: int
    attempts_hint: int | None = None

    @property
    def challenge_body(self) -> dict[str, Any]:
        return {"input": self.challenge.input, "hmac": self.challenge.hmac, "region": self.challenge.region}

    @property
    def verify_payload(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge_body,
            "solution": self.solution,
            "checksum": self.checksum,
            "client": "Browser",
        }


def awswaf_has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    whole, mask = _zero_check(bits)
    if len(digest) < whole + (1 if mask else 0):
        return False
    if whole and digest[:whole] != b"\x00" * whole:
        return False
    if mask:
        return (digest[whole] & mask) == 0
    return True


def awswaf_sha2_digest(input_value: str, checksum: str, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{input_value}{checksum}{int(nonce)}".encode("utf-8")).digest()


def awswaf_scrypt_digest(input_value: str, checksum: str, nonce: int | str, memory: int) -> bytes:
    n = _validate_scrypt_n(memory)
    password = f"{input_value}{checksum}{int(nonce)}".encode("utf-8")
    salt = str(checksum).encode("utf-8")
    # OpenSSL's default maxmem is too low for larger N; set an explicit cap.
    maxmem = max(32 * 1024 * 1024, 256 * n * 8)
    return hashlib.scrypt(password, salt=salt, n=n, r=8, p=1, dklen=16, maxmem=maxmem)


def solve_awswaf_sha2_hashcash(
    input_value: str,
    checksum: str,
    difficulty: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[str, str, int]:
    difficulty = _validate_bits(difficulty)
    start, max_attempts = _validate_search(start, max_attempts)
    prefix = f"{input_value}{checksum}".encode("utf-8")
    if workers <= 1:
        nonce, digest, attempts = _search_sha2_range(prefix, difficulty, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no AWS WAF SHA2 nonce found within {max_attempts} attempts")
        return str(nonce), digest.hex(), attempts
    return _parallel_search(_search_sha2_range, (prefix, difficulty), start, max_attempts, workers, chunk_size, "SHA2")


def solve_awswaf_scrypt_hashcash(
    input_value: str,
    checksum: str,
    difficulty: int,
    memory: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 1_000,
) -> tuple[str, str, int]:
    difficulty = _validate_bits(difficulty)
    n = _validate_scrypt_n(memory)
    start, max_attempts = _validate_search(start, max_attempts)
    base = f"{input_value}{checksum}".encode("utf-8")
    salt = str(checksum).encode("utf-8")
    if workers <= 1:
        nonce, digest, attempts = _search_scrypt_range(base, salt, n, difficulty, start, start + max_attempts)
        if nonce is None or digest is None:
            raise TimeoutError(f"no AWS WAF scrypt nonce found within {max_attempts} attempts")
        return str(nonce), digest.hex(), attempts
    return _parallel_search(
        _search_scrypt_range,
        (base, salt, n, difficulty),
        start,
        max_attempts,
        workers,
        chunk_size,
        "scrypt",
        memory_kib_per_worker=max(16_384, n * 4),
    )


def solve_awswaf_network_bandwidth(difficulty: int) -> str:
    sizes = {1: 1 * 0x400, 2: 10 * 0x400, 3: 100 * 0x400, 4: 1 * 0x100000, 5: 10 * 0x100000}
    try:
        size = sizes[int(difficulty)]
    except KeyError as exc:
        raise ValueError(f"unsupported AWS WAF NetworkBandwidth difficulty: {difficulty}") from exc
    return base64.b64encode(b"\x00" * size).decode("ascii")


def awswaf_inner_challenge_type(input_value: str) -> str | None:
    try:
        raw = base64.b64decode(str(input_value), validate=True)
        data = json.loads(raw.decode("utf-8"))
        value = data.get("challenge_type") if isinstance(data, dict) else None
        return str(value) if value else None
    except Exception:
        return None


def awswaf_challenge_mode(challenge: AwsWafChallenge | dict[str, Any] | str) -> str:
    item = parse_awswaf_challenge(challenge)
    inner = item.inner_challenge_type
    ctype = item.challenge_type or ""
    if inner == "NetworkBandwidth" or (not ctype and 1 <= item.difficulty <= 5):
        return "network_bandwidth"
    if ctype.startswith(TYPE_SHA2_PREFIX):
        return "sha2"
    return "scrypt"


def solve_awswaf_challenge(
    challenge: AwsWafChallenge | dict[str, Any] | str,
    *,
    checksum: str,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> AwsWafSolution:
    started = time.monotonic()
    item = parse_awswaf_challenge(challenge)
    checksum = _validate_checksum(checksum)
    mode = awswaf_challenge_mode(item)
    digest_hex = None
    attempts_hint = None
    if mode == "network_bandwidth":
        solution = solve_awswaf_network_bandwidth(item.difficulty)
    elif mode == "sha2":
        solution, digest_hex, attempts_hint = solve_awswaf_sha2_hashcash(
            item.input,
            checksum,
            item.difficulty,
            start=start,
            max_attempts=max_attempts,
            workers=workers,
            chunk_size=chunk_size,
        )
    else:
        solution, digest_hex, attempts_hint = solve_awswaf_scrypt_hashcash(
            item.input,
            checksum,
            item.difficulty,
            item.memory,
            start=start,
            max_attempts=max_attempts,
            workers=workers,
            chunk_size=min(chunk_size, 10_000),
        )
    return AwsWafSolution(
        challenge=item,
        checksum=checksum,
        solution=solution,
        mode=mode,
        digest_hex=digest_hex,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        attempts_hint=attempts_hint,
    )


def verify_awswaf_solution(challenge: AwsWafChallenge | dict[str, Any] | str, solution: AwsWafSolution | dict[str, Any] | str, *, checksum: str | None = None) -> bool:
    try:
        item = parse_awswaf_challenge(challenge)
        if isinstance(solution, AwsWafSolution):
            value = solution.solution
            checksum = solution.checksum
        elif isinstance(solution, dict):
            value = str(solution.get("solution") or solution.get("nonce") or solution.get("ticket") or "")
            checksum = checksum or str(solution.get("checksum") or "")
        else:
            value = str(solution)
        checksum = _validate_checksum(checksum or "")
        mode = awswaf_challenge_mode(item)
        if mode == "network_bandwidth":
            return value == solve_awswaf_network_bandwidth(item.difficulty)
        if not value.isdigit():
            return False
        if mode == "sha2":
            return awswaf_has_leading_zero_bits(awswaf_sha2_digest(item.input, checksum, int(value)), item.difficulty)
        return awswaf_has_leading_zero_bits(awswaf_scrypt_digest(item.input, checksum, int(value), item.memory), item.difficulty)
    except Exception:
        return False


def awswaf_canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def awswaf_signals_checksum(signals: dict[str, Any]) -> str:
    raw = awswaf_canonical_json(signals).encode("utf-8")
    return f"{zlib.crc32(raw) & 0xFFFFFFFF:x}"


def build_awswaf_signals(*, user_agent: str = DEFAULT_HEADERS["User-Agent"], signal_version: str = "2.4.0", screen_w: int = 1920, screen_h: int = 1080) -> dict[str, Any]:
    return {
        "version": signal_version,
        "navigator": {
            "userAgent": user_agent,
            "appCodeName": "Mozilla",
            "appName": "Netscape",
            "language": "en-US",
            "languages": ["en-US", "en"],
            "platform": "Win32",
            "product": "Gecko",
            "vendor": "Google Inc.",
            "hardwareConcurrency": 8,
            "maxTouchPoints": 0,
            "cookieEnabled": True,
            "onLine": True,
            "deviceMemory": 8,
            "pdfViewerEnabled": True,
            "webdriver": False,
        },
        "screen": {"width": screen_w, "height": screen_h, "availWidth": screen_w, "availHeight": screen_h - 40, "colorDepth": 24, "pixelDepth": 24},
        "window": {"innerWidth": screen_w, "innerHeight": screen_h - 117, "outerWidth": screen_w, "outerHeight": screen_h, "devicePixelRatio": 1.0},
        "tz": {"offset": -300, "timezone": "America/New_York"},
        "time": {"start": 1_700_000_000_000, "elapsed": 150},
        "canvas": {"hash": hashlib.sha256(f"canvas:{screen_w}x{screen_h}".encode()).hexdigest()},
        "gpu": {"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)", "extensions": 42},
        "stealth": {"webdriver": False, "phantom": False, "selenium": False, "domAutomation": False},
        "amazonUseragent": user_agent,
        "client": "Browser",
        "tVersion": signal_version,
        "errors": [],
    }


def encode_awswaf_signals(signals: dict[str, Any], crypto: AwsWafCryptoConfig | dict[str, Any], *, nonce: bytes | None = None) -> tuple[list[dict[str, Any]], str, str]:
    cfg = parse_awswaf_crypto_config(crypto)
    payload_json = awswaf_canonical_json(signals)
    checksum = awswaf_signals_checksum(signals)
    nonce = nonce if nonce is not None else os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("AWS WAF AES-GCM nonce must be 12 bytes")
    cipher = AES.new(cfg.key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(f"{checksum}#{payload_json}".encode("utf-8"))
    encrypted = f"{base64.b64encode(nonce).decode('ascii')}::{tag.hex()}::{ciphertext.hex()}"
    entry = {"name": cfg.identifier, "value": {"Present": encrypted}}
    return [entry], checksum, encrypted


def decode_awswaf_signal(encrypted_value: str, key: bytes | str) -> tuple[str, dict[str, Any]]:
    key_bytes = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
    nonce_b64, tag_hex, ciphertext_hex = str(encrypted_value).split("::", 2)
    nonce = base64.b64decode(nonce_b64, validate=True)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(bytes.fromhex(ciphertext_hex), bytes.fromhex(tag_hex)).decode("utf-8")
    checksum, json_text = plaintext.split("#", 1)
    data = json.loads(json_text)
    if awswaf_signals_checksum(data) != checksum:
        raise ValueError("AWS WAF signal checksum mismatch")
    return checksum, data


def parse_awswaf_crypto_config(data: AwsWafCryptoConfig | dict[str, Any] | str) -> AwsWafCryptoConfig:
    if isinstance(data, AwsWafCryptoConfig):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_awswaf_crypto_config(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            data = json.loads(text)
        else:
            data = {"key": text, "identifier": "AwsWafEncryptedSignals"}
    if not isinstance(data, dict):
        raise ValueError("AWS WAF crypto config must be JSON object or key hex")
    key_text = str(data.get("key") or data.get("key_hex") or data.get("keyHex") or "").strip()
    key = bytes.fromhex(key_text)
    if len(key) != 32:
        raise ValueError("AWS WAF AES key must be 32 bytes")
    identifier = str(data.get("identifier") or data.get("name") or "").strip()
    if not identifier:
        raise ValueError("AWS WAF crypto identifier is required")
    return AwsWafCryptoConfig(
        key=key,
        identifier=identifier,
        signal_version=str(data.get("signalVersion") or data.get("signal_version") or "2.4.0"),
        type_names=dict(data.get("typeNames") or data.get("type_names") or {}) or None,
    )


def parse_awswaf_challenge(data: AwsWafChallenge | dict[str, Any] | str) -> AwsWafChallenge:
    if isinstance(data, AwsWafChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_awswaf_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            data = json.loads(text)
        elif "challenge_type" in text or "parseInt" in text or "sdk.awswaf" in text:
            return parse_awswaf_challenge_js(text)
        else:
            raise ValueError("AWS WAF challenge string must be JSON, challenge.js, or @file")
    if not isinstance(data, dict):
        raise ValueError("AWS WAF challenge must be JSON object or challenge.js")
    if "challenge_js" in data or "challengeJs" in data or "js" in data:
        return parse_awswaf_challenge_js(str(data.get("challenge_js") or data.get("challengeJs") or data.get("js")))
    source = data.get("challenge") if isinstance(data.get("challenge"), dict) else data
    input_value = str(source.get("input") or source.get("Input") or data.get("input") or "")
    if not input_value:
        raise ValueError("AWS WAF challenge requires challenge.input")
    return AwsWafChallenge(
        input=input_value,
        hmac=str(source.get("hmac") or source.get("Hmac") or data.get("hmac") or ""),
        region=str(source.get("region") or source.get("Region") or data.get("region") or ""),
        challenge_type=str(data.get("challenge_type") or data.get("challengeType") or data.get("type") or ""),
        difficulty=int(data.get("difficulty") or data.get("Difficulty") or 0),
        memory=int(data.get("memory") or data.get("Memory") or 0),
        raw=data,
    )


def parse_awswaf_challenge_js(script: str) -> AwsWafChallenge:
    text = str(script)
    difficulty, memory = 0, 0
    if m := re.search(r"parseInt\(['\"](\d+)['\"]\).*?parseInt\(['\"](\d+)['\"]\)", text, re.S):
        difficulty, memory = int(m.group(1)), int(m.group(2))
    challenge_type = _first_match(text, [r"['\"](ha[0-9a-f]{60,})['\"]", r"['\"](h72f957df[0-9a-f]+)['\"]", r"['\"](h7b0c470f[0-9a-f]+)['\"]"])
    input_value = _first_match(text, [r"['\"](eyJ[A-Za-z0-9+/=]{20,})['\"]"])
    hmac_value = _first_match(text, [r"['\"]hmac['\"]\]?\s*[=:]\s*['\"]([A-Za-z0-9+/=]+)['\"]"])
    region = ""
    if input_value:
        try:
            inner = json.loads(base64.b64decode(input_value).decode("utf-8"))
            region = str(inner.get("region") or "") if isinstance(inner, dict) else ""
        except Exception:
            pass
    region = region or (_first_match(text, [r"['\"]region['\"]\]?\s*[=:]\s*['\"]([a-z0-9-]+)['\"]"]) or "")
    if not input_value and not challenge_type:
        raise ValueError("AWS WAF challenge.js did not expose challenge input/type")
    return AwsWafChallenge(input=input_value or "", hmac=hmac_value or "", region=region, challenge_type=challenge_type or "", difficulty=difficulty, memory=memory, raw_js=text)


def extract_awswaf_script_url(html_text: str, *, page_url: str | None = None) -> str | None:
    text = html.unescape(str(html_text))
    patterns = [
        r"(?:src\s*=\s*['\"]|script\.src\s*=\s*['\"])(https://[^'\"]*\.sdk\.awswaf\.com/[^'\"]*challenge\.js[^'\"]*)['\"]",
        r"['\"]?(https://[^'\"]*awswaf\.com[^'\"]*challenge[^'\"]*\.js)['\"]?",
        r"(?:src\s*=\s*['\"])(/[^'\"]*challenge\.js[^'\"]*)['\"]",
    ]
    for pattern in patterns:
        if m := re.search(pattern, text, re.I):
            url = m.group(1)
            return urljoin(page_url, url) if page_url and url.startswith("/") else url
    return None


def awswaf_challenge_base(script_url: str) -> str:
    if m := re.match(r"^(.+)/challenge.*\.js", str(script_url)):
        return m.group(1)
    return str(script_url).rsplit("/", 1)[0]


def awswaf_endpoint_type(challenge_type: str, type_names: dict[str, str] | None = None) -> str:
    if type_names and challenge_type in type_names:
        return type_names[challenge_type]
    if challenge_type.startswith(TYPE_SHA2_PREFIX) or challenge_type.startswith("h7b0c470f"):
        return "verify"
    if challenge_type.startswith(TYPE_SCRYPT_PREFIX):
        return "verify"
    return "mp_verify"


class AwsWafSolver:
    """Core protocol solver for AWS WAF challenge.js PoW.

    This provider implements the browser-independent cryptographic core:
    encrypted AES-GCM signals, CRC32 checksum, NetworkBandwidth payloads, SHA2
    hashcash and scrypt hashcash. Live `challenge.js` deobfuscation can be
    passed in via parsed JSON/JS fixtures; no browser is started.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_js: str | None = None,
        crypto_json: Any = None,
        crypto_file: str | None = None,
        checksum: str | None = None,
        signals_json: Any = None,
        aes_key_hex: str | None = None,
        identifier: str | None = None,
        signal_version: str = "2.4.0",
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
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
            "submit": False,
            "browser": "not_used",
            "start": start,
            "max_attempts": max_attempts,
            "workers": workers,
            "chunk_size": chunk_size,
            "timeout_sec": timeout_sec,
            "proxy": redacted_proxy(proxy_server),
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
                out = output_root / "awswaf_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="awswaf",
                ok=ok,
                captcha_type="encrypted_telemetry_scrypt_sha2_network_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge_input"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            _ = parse_proxy(proxy_server) if proxy_server else None
            challenge = self._load_challenge(challenge_json, challenge_file, challenge_js)
            crypto = self._load_crypto(crypto_json, crypto_file, aes_key_hex, identifier, signal_version)
            merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
            signals = _load_json_arg(signals_json) if signals_json is not None else build_awswaf_signals(user_agent=merged_headers["User-Agent"], signal_version=crypto.signal_version if crypto else signal_version)
            encrypted_signals = None
            if checksum is None:
                if crypto is not None:
                    signal_array, checksum, encrypted_signals = encode_awswaf_signals(signals, crypto)
                    raw["signals"] = {"array": signal_array, "encrypted": encrypted_signals, "checksum": checksum}
                else:
                    checksum = awswaf_signals_checksum(signals)
            solution = solve_awswaf_challenge(
                challenge,
                checksum=checksum,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            if not verify_awswaf_solution(challenge, solution):
                errors.append("AWS WAF internal solution verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            endpoint_type = awswaf_endpoint_type(challenge.challenge_type, crypto.type_names if crypto else None)
            diagnostics.update(
                {
                    "challenge_input": challenge.input,
                    "challenge_type": challenge.challenge_type,
                    "inner_challenge_type": challenge.inner_challenge_type,
                    "mode": solution.mode,
                    "difficulty": challenge.difficulty,
                    "memory": challenge.memory,
                    "checksum": solution.checksum,
                    "solution": solution.solution[:120],
                    "digest_hex": solution.digest_hex,
                    "solve_ms": solution.elapsed_ms,
                    "attempts_hint": solution.attempts_hint,
                    "endpoint_type": endpoint_type,
                    "crypto_identifier": crypto.identifier if crypto else None,
                    "signals_encrypted": bool(encrypted_signals),
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {"payload": solution.verify_payload, "mode": solution.mode, "digestHex": solution.digest_hex, "elapsedMs": solution.elapsed_ms}
            ticket = json.dumps(solution.verify_payload, ensure_ascii=False, separators=(",", ":"))
            return finish(ok=True, ticket=ticket, verify_code="solved")
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(self, challenge_json: Any, challenge_file: str | None, challenge_js: str | None) -> AwsWafChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_awswaf_challenge(loaded)
        if challenge_js:
            text = Path(challenge_js[1:]).read_text(encoding="utf-8") if str(challenge_js).startswith("@") else str(challenge_js)
            return parse_awswaf_challenge_js(text)
        raise ValueError("AWS WAF solve requires challenge_json/challenge_file/challenge_js")

    def _load_crypto(self, crypto_json: Any, crypto_file: str | None, aes_key_hex: str | None, identifier: str | None, signal_version: str) -> AwsWafCryptoConfig | None:
        loaded = _load_json_arg(crypto_json, crypto_file)
        if loaded is not None:
            return parse_awswaf_crypto_config(loaded)
        if aes_key_hex or identifier:
            return parse_awswaf_crypto_config({"key": aes_key_hex or "", "identifier": identifier or "", "signalVersion": signal_version})
        return None


def _search_sha2_range(prefix: bytes, difficulty: int, begin: int, end: int) -> tuple[int | None, bytes | None, int]:
    whole, mask = _zero_check(difficulty)
    zero_prefix = b"\x00" * whole
    base = hashlib.sha256(prefix)
    attempts = 0
    for nonce in range(int(begin), int(end)):
        h = base.copy()
        h.update(str(nonce).encode("ascii"))
        digest = h.digest()
        attempts += 1
        if zero_prefix and not digest.startswith(zero_prefix):
            continue
        if mask and digest[whole] & mask:
            continue
        return nonce, digest, attempts
    return None, None, attempts


def _search_scrypt_range(base: bytes, salt: bytes, n: int, difficulty: int, begin: int, end: int) -> tuple[int | None, bytes | None, int]:
    whole, mask = _zero_check(difficulty)
    zero_prefix = b"\x00" * whole
    maxmem = max(32 * 1024 * 1024, 256 * n * 8)
    attempts = 0
    for nonce in range(int(begin), int(end)):
        digest = hashlib.scrypt(base + str(nonce).encode("ascii"), salt=salt, n=n, r=8, p=1, dklen=16, maxmem=maxmem)
        attempts += 1
        if zero_prefix and not digest.startswith(zero_prefix):
            continue
        if mask and digest[whole] & mask:
            continue
        return nonce, digest, attempts
    return None, None, attempts


def _parallel_search(
    fn: Any,
    fixed_args: tuple[Any, ...],
    start: int,
    max_attempts: int,
    workers: int,
    chunk_size: int,
    label: str,
    *,
    memory_kib_per_worker: int = 0,
) -> tuple[str, str, int]:
    workers = _bounded_workers(workers, memory_kib_per_worker=memory_kib_per_worker)
    chunk_size = max(1, int(chunk_size))
    submitted = 0
    next_start = int(start)
    futures: dict[Any, tuple[int, int]] = {}
    pool_kwargs = _process_pool_kwargs(workers)
    with ProcessPoolExecutor(**pool_kwargs) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(fn, *fixed_args, next_start, end)] = (next_start, end)
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
                    return str(nonce), digest.hex(), max(0, begin - start + attempts)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(fn, *fixed_args, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no AWS WAF {label} nonce found within {max_attempts} attempts")


def _validate_bits(value: Any) -> int:
    bits = int(value)
    if bits < 0 or bits > 256:
        raise ValueError("AWS WAF difficulty must be 0..256")
    return bits


def _validate_scrypt_n(value: Any) -> int:
    n = int(value or 0)
    if n <= 1 or n & (n - 1):
        raise ValueError("AWS WAF scrypt memory/N must be a power of two > 1")
    return n


def _validate_search(start: Any, max_attempts: Any) -> tuple[int, int]:
    s = int(start)
    m = int(max_attempts)
    if s < 0:
        raise ValueError("start must be non-negative")
    if m <= 0:
        raise ValueError("max_attempts must be positive")
    return s, m


def _validate_checksum(value: str) -> str:
    text = str(value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{1,8}", text):
        raise ValueError("AWS WAF checksum must be 1..8 hex chars")
    return text


def _zero_check(bits: int) -> tuple[int, int]:
    bits = _validate_bits(bits)
    whole, rem = divmod(bits, 8)
    mask = ((0xFF << (8 - rem)) & 0xFF) if rem else 0
    return whole, mask


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if m := re.search(pattern, text, re.I | re.S):
            return html.unescape(m.group(1))
    return None


def _load_json_arg(value: Any, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        if not text:
            return None
        return json.loads(text) if text[0] in "[{" else text
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


def _challenge_raw(challenge: AwsWafChallenge) -> dict[str, Any]:
    return {
        "input": challenge.input,
        "hmac": challenge.hmac,
        "region": challenge.region,
        "challengeType": challenge.challenge_type,
        "innerChallengeType": challenge.inner_challenge_type,
        "difficulty": challenge.difficulty,
        "memory": challenge.memory,
        "hasJs": bool(challenge.raw_js),
    }


def _url_host(url: str | None) -> str | None:
    if not url:
        return None
    return urlparse(url).netloc or None
