from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from argon2 import low_level as argon2_low_level

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_MAX_NUMBER = 1_000_000
DEFAULT_ALGORITHM = "SHA-256"
DEFAULT_V2_MAX_COUNTER = 1_000_000
DEFAULT_V2_STRATEGY = "auto"

_ALGO_MAP = {
    "sha": "sha1",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
    "sha-512": "sha512",
    "sha512": "sha512",
}


@dataclass(slots=True)
class AltchaChallenge:
    algorithm: str
    challenge: str
    salt: str
    signature: str
    maxnumber: int = DEFAULT_MAX_NUMBER


@dataclass(slots=True)
class AltchaSolution:
    number: int
    took_ms: int
    checked: int
    algorithm: str
    challenge: str
    salt: str
    signature: str
    maxnumber: int

    def payload(self, *, include_took: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "algorithm": self.algorithm,
            "challenge": self.challenge,
            "number": self.number,
            "salt": self.salt,
            "signature": self.signature,
        }
        if include_took:
            data["took"] = self.took_ms
        return data

    def payload_json(self, *, include_took: bool = False) -> str:
        return json.dumps(self.payload(include_took=include_took), ensure_ascii=False, separators=(",", ":"))

    def payload_b64(self, *, include_took: bool = False) -> str:
        return base64.b64encode(self.payload_json(include_took=include_took).encode("utf-8")).decode(
            "ascii"
        )

    def authorization_header(self, *, style: str = "json") -> str:
        if style == "json":
            return "Altcha challenge=" + self.payload_json()
        payload = self.payload()
        parts = [f"{key}={_quote_header_value(value)}" for key, value in payload.items()]
        return "Altcha " + ", ".join(parts)


@dataclass(slots=True)
class AltchaV2Challenge:
    parameters: dict[str, Any]
    signature: str | None = None

    @property
    def algorithm(self) -> str:
        return str(self.parameters.get("algorithm") or "")

    @property
    def key_prefix(self) -> str:
        return str(self.parameters.get("keyPrefix") or "")

    @property
    def key_signature(self) -> str | None:
        value = self.parameters.get("keySignature")
        return str(value) if value not in (None, "") else None

    @property
    def cost(self) -> int:
        return int(self.parameters.get("cost") or 1)

    @property
    def key_length(self) -> int:
        return int(self.parameters.get("keyLength") or _default_v2_key_length(self.algorithm))

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {"parameters": dict(self.parameters)}
        if self.signature:
            out["signature"] = self.signature
        return out


@dataclass(slots=True)
class AltchaV2Solution:
    challenge: AltchaV2Challenge
    counter: int
    derived_key: str
    took_ms: int
    checked: int
    strategy: str
    prefix_matched: bool

    def solution_payload(self) -> dict[str, Any]:
        return {"counter": self.counter, "derivedKey": self.derived_key, "time": self.took_ms}

    def payload(self) -> dict[str, Any]:
        return {"challenge": self.challenge.to_payload(), "solution": self.solution_payload()}

    def payload_json(self) -> str:
        return json.dumps(self.payload(), ensure_ascii=False, separators=(",", ":"))

    def payload_b64(self) -> str:
        return base64.b64encode(self.payload_json().encode("utf-8")).decode("ascii")


def normalize_altcha_algorithm(algorithm: str | None) -> str:
    raw = (algorithm or DEFAULT_ALGORITHM).strip()
    key = raw.lower().replace("_", "-")
    if key not in _ALGO_MAP:
        raise ValueError(f"unsupported ALTCHA v1 algorithm: {algorithm!r}")
    return _ALGO_MAP[key]


def _canonical_algorithm(algorithm: str | None) -> str:
    name = normalize_altcha_algorithm(algorithm)
    if name == "sha1":
        return "SHA-1"
    if name == "sha512":
        return "SHA-512"
    return "SHA-256"


def altcha_hash_hex(salt: str, number: int, algorithm: str | None = None) -> str:
    h = hashlib.new(normalize_altcha_algorithm(algorithm))
    h.update(f"{salt}{int(number)}".encode("utf-8"))
    return h.hexdigest()


def is_altcha_v2_challenge(value: Any) -> bool:
    data = value.get("challenge") if isinstance(value, dict) and isinstance(value.get("challenge"), dict) else value
    return isinstance(data, dict) and isinstance(data.get("parameters"), dict)


def parse_altcha_v2_challenge(value: AltchaV2Challenge | dict[str, Any] | str) -> AltchaV2Challenge:
    if isinstance(value, AltchaV2Challenge):
        _validate_altcha_v2_parameters(value.parameters)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("ALTCHA v2 challenge is empty")
        if text.startswith("@"):
            return parse_altcha_v2_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        return parse_altcha_v2_challenge(json.loads(text))
    if not isinstance(value, dict):
        raise ValueError("ALTCHA v2 challenge must be an object")
    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    if not isinstance(data.get("parameters"), dict):
        raise ValueError("ALTCHA v2 challenge requires parameters")
    parameters = _normalize_altcha_v2_parameters(dict(data["parameters"]))
    signature = data.get("signature")
    return AltchaV2Challenge(parameters=parameters, signature=str(signature) if signature else None)


def altcha_v2_password_bytes(nonce_hex: str, counter: int, *, counter_mode: str = "uint32") -> bytes:
    nonce = bytes.fromhex(str(nonce_hex))
    value = int(counter)
    if value < 0:
        raise ValueError("ALTCHA v2 counter must be >= 0")
    if counter_mode == "string":
        return nonce + str(value).encode("utf-8")
    if counter_mode != "uint32":
        raise ValueError("ALTCHA v2 counter_mode must be uint32 or string")
    if value > 0xFFFFFFFF:
        raise ValueError("ALTCHA v2 uint32 counter exceeds 2^32-1")
    return nonce + value.to_bytes(4, "big", signed=False)


def altcha_v2_derive_key_bytes(
    challenge: AltchaV2Challenge | dict[str, Any] | str,
    counter: int,
    *,
    counter_mode: str = "uint32",
) -> bytes:
    item = parse_altcha_v2_challenge(challenge)
    params = item.parameters
    salt = bytes.fromhex(str(params["salt"]))
    password = altcha_v2_password_bytes(str(params["nonce"]), counter, counter_mode=counter_mode)
    return _altcha_v2_derive_key_from_password(params, salt, password)


def altcha_v2_derive_key_hex(
    challenge: AltchaV2Challenge | dict[str, Any] | str,
    counter: int,
    *,
    counter_mode: str = "uint32",
) -> str:
    return altcha_v2_derive_key_bytes(challenge, counter, counter_mode=counter_mode).hex()


def altcha_v2_key_matches_prefix(derived_key_hex: str, key_prefix: str) -> bool:
    prefix = str(key_prefix or "").lower()
    if not prefix:
        return True
    return str(derived_key_hex).lower().startswith(prefix)


def solve_altcha_v2_challenge(
    challenge: AltchaV2Challenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_counter: int | None = DEFAULT_V2_MAX_COUNTER,
    workers: int = 1,
    timeout_sec: int | float | None = 90,
    counter_mode: str = "uint32",
    strategy: str = DEFAULT_V2_STRATEGY,
    hmac_algorithm: str = "SHA-256",
    hmac_key_signature_secret: str | None = None,
) -> AltchaV2Solution | None:
    item = parse_altcha_v2_challenge(challenge)
    strategy = _normalize_v2_strategy(strategy)
    started = time.monotonic()
    start = max(0, int(start))
    upper = start + DEFAULT_V2_MAX_COUNTER if max_counter is None else int(max_counter)
    if upper < start:
        raise ValueError("ALTCHA v2 max_counter must be >= start")
    workers = max(1, int(workers or 1))

    # ALTCHA v2's upstream verifySolution() re-derives and compares the exact
    # supplied derivedKey when no keySignature is present; it does not re-check
    # keyPrefix in that branch. This verify-compatible path therefore avoids a
    # pointless prefix brute force for the common signed probabilistic challenge.
    if strategy in {"auto", "verify-compatible"} and not item.key_signature:
        derived_hex = altcha_v2_derive_key_hex(item, start, counter_mode=counter_mode)
        return AltchaV2Solution(
            challenge=item,
            counter=start,
            derived_key=derived_hex,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=1,
            strategy="verify-compatible",
            prefix_matched=altcha_v2_key_matches_prefix(derived_hex, item.key_prefix),
        )

    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    if workers <= 1 or upper - start < 64:
        counter, derived_hex, checked, prefix_matched = _solve_altcha_v2_range(
            item,
            start,
            upper,
            deadline,
            counter_mode,
            hmac_algorithm,
            hmac_key_signature_secret,
        )
        if counter is None or derived_hex is None:
            return None
        return AltchaV2Solution(
            challenge=item,
            counter=counter,
            derived_key=derived_hex,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=checked,
            strategy="prefix",
            prefix_matched=bool(prefix_matched),
        )

    span = upper - start + 1
    chunk = math.ceil(span / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(upper, lo + chunk - 1)
        if lo > upper:
            break
        futures[
            pool.submit(
                _solve_altcha_v2_range,
                item,
                lo,
                hi,
                deadline,
                counter_mode,
                hmac_algorithm,
                hmac_key_signature_secret,
            )
        ] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            counter, derived_hex, checked, prefix_matched = fut.result()
            checked_total += checked
            if counter is not None and derived_hex is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return AltchaV2Solution(
                    challenge=item,
                    counter=counter,
                    derived_key=derived_hex,
                    took_ms=int((time.monotonic() - started) * 1000),
                    checked=checked_total,
                    strategy="prefix",
                    prefix_matched=bool(prefix_matched),
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


def verify_altcha_v2_solution(
    challenge: AltchaV2Challenge | dict[str, Any] | str,
    solution: AltchaV2Solution | dict[str, Any],
    *,
    counter_mode: str = "uint32",
    hmac_algorithm: str = "SHA-256",
    hmac_signature_secret: str | None = None,
    hmac_key_signature_secret: str | None = None,
    enforce_key_prefix: bool = False,
    now: int | None = None,
) -> bool:
    try:
        item = parse_altcha_v2_challenge(challenge)
        if isinstance(solution, AltchaV2Solution):
            counter = solution.counter
            derived_hex = solution.derived_key.lower()
        else:
            data = solution.get("solution") if isinstance(solution.get("solution"), dict) else solution
            counter = int(data.get("counter"))
            derived_hex = str(data.get("derivedKey") or data.get("derived_key") or "").lower()
        exp = item.parameters.get("expiresAt")
        if exp is not None and int(exp) < int(now or time.time()):
            return False
        if item.signature and hmac_signature_secret is not None:
            expected = altcha_v2_hmac_hex(
                _canonical_json(item.parameters).encode("utf-8"),
                hmac_signature_secret,
                hmac_algorithm,
            )
            if not hmac.compare_digest(expected, item.signature.lower()):
                return False
        if item.key_signature and hmac_key_signature_secret is not None:
            expected_key_sig = altcha_v2_hmac_hex(bytes.fromhex(derived_hex), hmac_key_signature_secret, hmac_algorithm)
            if not hmac.compare_digest(expected_key_sig, item.key_signature.lower()):
                return False
            return not enforce_key_prefix or altcha_v2_key_matches_prefix(derived_hex, item.key_prefix)
        expected_derived = altcha_v2_derive_key_hex(item, counter, counter_mode=counter_mode)
        if not hmac.compare_digest(expected_derived, derived_hex):
            return False
        return not enforce_key_prefix or altcha_v2_key_matches_prefix(derived_hex, item.key_prefix)
    except Exception:
        return False


def altcha_v2_hmac_hex(data: bytes | str, secret: str, algorithm: str = "SHA-256") -> str:
    digest = _hmac_digest_name(algorithm)
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hmac.new(secret.encode("utf-8"), raw, digest).hexdigest()


def _solve_altcha_v2_range(
    item: AltchaV2Challenge,
    start: int,
    end_inclusive: int,
    deadline: float | None,
    counter_mode: str,
    hmac_algorithm: str,
    hmac_key_signature_secret: str | None,
) -> tuple[int | None, str | None, int, bool]:
    salt = bytes.fromhex(str(item.parameters["salt"]))
    checked = 0
    for counter in range(max(0, int(start)), max(0, int(end_inclusive)) + 1):
        if deadline is not None and checked and checked % 10 == 0 and time.monotonic() >= deadline:
            return None, None, checked, False
        password = altcha_v2_password_bytes(str(item.parameters["nonce"]), counter, counter_mode=counter_mode)
        derived = _altcha_v2_derive_key_from_password(item.parameters, salt, password)
        derived_hex = derived.hex()
        checked += 1
        prefix_matched = altcha_v2_key_matches_prefix(derived_hex, item.key_prefix)
        if item.key_signature and hmac_key_signature_secret:
            key_sig = altcha_v2_hmac_hex(derived, hmac_key_signature_secret, hmac_algorithm)
            if hmac.compare_digest(key_sig, item.key_signature.lower()):
                return counter, derived_hex, checked, prefix_matched
        elif prefix_matched:
            return counter, derived_hex, checked, True
    return None, None, checked, False


def _altcha_v2_derive_key_from_password(params: dict[str, Any], salt: bytes, password: bytes) -> bytes:
    algorithm = str(params.get("algorithm") or "").upper()
    cost = max(1, int(params.get("cost") or 1))
    key_length = max(1, int(params.get("keyLength") or _default_v2_key_length(algorithm)))
    if algorithm.startswith("PBKDF2/"):
        digest = _pbkdf2_digest_name(algorithm)
        return hashlib.pbkdf2_hmac(digest, password, salt, cost, dklen=key_length)
    if algorithm in {"SHA-256", "SHA-384", "SHA-512"}:
        data = salt + password
        derived = b""
        for i in range(cost):
            derived = hashlib.new(_sha_digest_name(algorithm), data if i == 0 else derived).digest()[:key_length]
        return derived
    if algorithm == "SCRYPT":
        n = cost
        r = int(params.get("memoryCost") or 8)
        p = int(params.get("parallelism") or 1)
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=key_length, maxmem=2_147_483_647)
    if algorithm == "ARGON2ID":
        return argon2_low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=cost,
            memory_cost=int(params.get("memoryCost") or 16_384),
            parallelism=int(params.get("parallelism") or 1),
            hash_len=key_length,
            type=argon2_low_level.Type.ID,
        )
    raise ValueError(f"unsupported ALTCHA v2 algorithm: {algorithm!r}")


def _normalize_altcha_v2_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    params = dict(parameters)
    algorithm = str(params.get("algorithm") or "").upper()
    if algorithm.startswith("PBKDF2/"):
        algorithm = "PBKDF2/" + algorithm.split("/", 1)[1].replace("_", "-")
    params["algorithm"] = algorithm
    if "keyLength" not in params or params.get("keyLength") in (None, ""):
        params["keyLength"] = _default_v2_key_length(algorithm)
    if "cost" not in params or params.get("cost") in (None, ""):
        params["cost"] = 1
    _validate_altcha_v2_parameters(params)
    return params


def _validate_altcha_v2_parameters(params: dict[str, Any]) -> None:
    required = ("algorithm", "nonce", "salt", "cost", "keyLength", "keyPrefix")
    missing = [k for k in required if k not in params or params.get(k) is None]
    if missing:
        raise ValueError(f"ALTCHA v2 parameters missing fields: {', '.join(missing)}")
    bytes.fromhex(str(params["nonce"]))
    bytes.fromhex(str(params["salt"]))
    prefix = str(params.get("keyPrefix") or "")
    if prefix and not re.fullmatch(r"[0-9a-fA-F]+", prefix):
        raise ValueError("ALTCHA v2 keyPrefix must be hex")
    key_sig = params.get("keySignature")
    if key_sig and not re.fullmatch(r"[0-9a-fA-F]+", str(key_sig)):
        raise ValueError("ALTCHA v2 keySignature must be hex")
    _altcha_v2_supported_algorithm(str(params["algorithm"]))
    if int(params["cost"]) < 1 or int(params["keyLength"]) < 1:
        raise ValueError("ALTCHA v2 cost/keyLength must be positive")


def _altcha_v2_supported_algorithm(algorithm: str) -> str:
    alg = str(algorithm).upper()
    if alg in {"SHA-256", "SHA-384", "SHA-512", "SCRYPT", "ARGON2ID"}:
        return alg
    if alg in {"PBKDF2/SHA-256", "PBKDF2/SHA-384", "PBKDF2/SHA-512"}:
        return alg
    raise ValueError(f"unsupported ALTCHA v2 algorithm: {algorithm!r}")


def _default_v2_key_length(algorithm: str) -> int:
    alg = str(algorithm).upper()
    if alg.endswith("SHA-512"):
        return 64
    if alg.endswith("SHA-384"):
        return 48
    return 32


def _pbkdf2_digest_name(algorithm: str) -> str:
    tail = str(algorithm).upper().split("/", 1)[-1]
    return _sha_digest_name(tail)


def _sha_digest_name(algorithm: str) -> str:
    alg = str(algorithm).upper().replace("_", "-")
    if alg == "SHA-256":
        return "sha256"
    if alg == "SHA-384":
        return "sha384"
    if alg == "SHA-512":
        return "sha512"
    raise ValueError(f"unsupported SHA algorithm: {algorithm!r}")


def _hmac_digest_name(algorithm: str) -> str:
    return _sha_digest_name(algorithm)


def _normalize_v2_strategy(strategy: str | None) -> str:
    value = (strategy or DEFAULT_V2_STRATEGY).strip().lower().replace("_", "-")
    if value not in {"auto", "verify-compatible", "prefix"}:
        raise ValueError("ALTCHA v2 strategy must be auto, verify-compatible or prefix")
    return value


def _canonical_json(obj: Any) -> str:
    return json.dumps(_sort_json_keys(obj), ensure_ascii=False, separators=(",", ":"))


def _sort_json_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_json_keys(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sort_json_keys(x) for x in obj]
    return obj


def _solve_range(
    challenge: str,
    salt: str,
    algorithm: str,
    start: int,
    end: int,
) -> tuple[int | None, int]:
    target = challenge.lower()
    name = normalize_altcha_algorithm(algorithm)
    checked = 0
    for n in range(max(0, start), max(0, end) + 1):
        h = hashlib.new(name)
        h.update(f"{salt}{n}".encode("utf-8"))
        checked += 1
        if h.hexdigest().lower() == target:
            return n, checked
    return None, checked


def solve_altcha_challenge(
    challenge: AltchaChallenge | dict[str, Any],
    *,
    start: int = 0,
    max_number: int | None = None,
    workers: int = 1,
    timeout_sec: int | float | None = None,
) -> AltchaSolution | None:
    item = parse_altcha_challenge(challenge)
    upper = int(max_number if max_number is not None else item.maxnumber or DEFAULT_MAX_NUMBER)
    if upper < start:
        raise ValueError("max_number must be >= start")
    started = time.monotonic()
    workers = max(1, int(workers or 1))

    if workers <= 1 or upper - start < 50_000:
        number, checked = _solve_range(item.challenge, item.salt, item.algorithm, int(start), upper)
        if number is None:
            return None
        return AltchaSolution(
            number=number,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=checked,
            algorithm=item.algorithm,
            challenge=item.challenge,
            salt=item.salt,
            signature=item.signature,
            maxnumber=upper,
        )

    span = upper - int(start) + 1
    chunk = math.ceil(span / workers)
    checked_total = 0
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = []
        for idx in range(workers):
            lo = int(start) + idx * chunk
            hi = min(upper, lo + chunk - 1)
            if lo > upper:
                break
            futures.append(pool.submit(_solve_range, item.challenge, item.salt, item.algorithm, lo, hi))
        pending = set(futures)
        while pending:
            wait_timeout = None
            if deadline is not None:
                wait_timeout = max(0.0, deadline - time.monotonic())
                if wait_timeout == 0:
                    break
            done, pending = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
            if not done:
                break
            for fut in done:
                number, checked = fut.result()
                checked_total += checked
                if number is not None:
                    for other in pending:
                        other.cancel()
                    return AltchaSolution(
                        number=number,
                        took_ms=int((time.monotonic() - started) * 1000),
                        checked=checked_total,
                        algorithm=item.algorithm,
                        challenge=item.challenge,
                        salt=item.salt,
                        signature=item.signature,
                        maxnumber=upper,
                    )
    return None


def parse_altcha_challenge(value: AltchaChallenge | dict[str, Any]) -> AltchaChallenge:
    if isinstance(value, AltchaChallenge):
        return value
    if not isinstance(value, dict):
        raise ValueError("ALTCHA challenge must be an object")
    algorithm = _canonical_algorithm(str(value.get("algorithm") or DEFAULT_ALGORITHM))
    challenge = str(value.get("challenge") or "")
    salt = str(value.get("salt") or "")
    signature = str(value.get("signature") or "")
    if not challenge or not salt or not signature:
        raise ValueError("ALTCHA challenge requires challenge/salt/signature")
    maxnumber_raw = value.get("maxnumber", value.get("max_number", DEFAULT_MAX_NUMBER))
    try:
        maxnumber = int(maxnumber_raw)
    except Exception as e:
        raise ValueError(f"invalid ALTCHA maxnumber: {maxnumber_raw!r}") from e
    return AltchaChallenge(
        algorithm=algorithm,
        challenge=challenge,
        salt=salt,
        signature=signature,
        maxnumber=maxnumber,
    )


def parse_altcha_payload_b64(value: str) -> dict[str, Any]:
    data = base64.b64decode(value).decode("utf-8")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("ALTCHA payload is not an object")
    return payload


def parse_altcha_header(header: str) -> dict[str, str]:
    text = (header or "").strip()
    if not text:
        raise ValueError("empty ALTCHA header")
    if text.lower().startswith("altcha"):
        text = text[6:].strip()
    if text.lower().startswith("challenge="):
        challenge_value = text.split("=", 1)[1].strip()
        if len(challenge_value) >= 2 and challenge_value[0] == challenge_value[-1] == '"':
            challenge_value = challenge_value[1:-1].replace('\\"', '"')
        if challenge_value.startswith("{"):
            data = json.loads(challenge_value)
            if not isinstance(data, dict):
                raise ValueError("ALTCHA header challenge JSON is not an object")
            return {k: str(v) for k, v in data.items() if v is not None}
    out: dict[str, str] = {}
    for part in _split_header_parts(text):
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].replace('\\"', '"')
        if key:
            out[key] = value
    if not out:
        raise ValueError("failed to parse ALTCHA header")
    return out


def challenge_from_altcha_header(header: str, *, default_maxnumber: int = DEFAULT_MAX_NUMBER) -> AltchaChallenge:
    data = parse_altcha_header(header)
    data.setdefault("maxnumber", str(default_maxnumber))
    return parse_altcha_challenge(data)


def _split_header_parts(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False
    for ch in text:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if ch == "," and not in_quote:
            parts.append("".join(buf).strip())
            buf.clear()
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def _quote_header_value(value: Any) -> str:
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._~:/?&=%+-]+", text):
        return text
    return '"' + text.replace('"', '\\"') + '"'


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> dict[str, Any] | None:
    if file_path:
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("challenge file must contain a JSON object")
        return data
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        data = json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("challenge JSON must be an object")
    return data


class AltchaSolver:
    """ALTCHA proof-of-work protocol solver.

    ALTCHA v1 is not a visual puzzle: the client searches for `n` such that
    `hash(salt + n) == challenge`, then sends a base64 JSON payload or an M2M
    `Authorization: Altcha ... number=...` header.  This provider keeps that
    flow fully protocol-level and does not launch a browser.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_url: str | None = None,
        challenge_json: dict[str, Any] | str | None = None,
        challenge_file: str | None = None,
        www_authenticate: str | None = None,
        default_maxnumber: int = DEFAULT_MAX_NUMBER,
        max_number: int | None = None,
        start: int = 0,
        workers: int = 1,
        timeout_sec: int = 30,
        v2_strategy: str = DEFAULT_V2_STRATEGY,
        counter_mode: str = "uint32",
        hmac_algorithm: str = "SHA-256",
        hmac_signature_secret: str | None = None,
        hmac_key_signature_secret: str | None = None,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        include_took: bool = False,
        mode: str = "form",
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(), "mode": mode}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "start": start,
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
                out = output_root / "altcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="altcha",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("salt"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            data: dict[str, Any] | None = None
            challenge_obj: AltchaChallenge | None = None
            if www_authenticate:
                challenge_obj = challenge_from_altcha_header(
                    www_authenticate,
                    default_maxnumber=default_maxnumber,
                )
                raw["challengeSource"] = "www_authenticate"
            else:
                if isinstance(challenge_json, dict):
                    data = challenge_json
                else:
                    data = _load_json_arg(challenge_json, challenge_file)
                if data is None:
                    if not challenge_url:
                        errors.append("challenge_url, challenge_json, challenge_file or www_authenticate is required")
                        return finish(ok=False)
                    resp = requests.get(
                        challenge_url,
                        headers=headers,
                        timeout=timeout_sec,
                        proxies=_requests_proxies(proxy_server),
                    )
                    raw["challengeResponse"] = {"status": resp.status_code}
                    resp.raise_for_status()
                    data = resp.json()
                    if not isinstance(data, dict):
                        raise ValueError("challenge response is not a JSON object")
                    raw["challengeSource"] = "url"

            if data is not None and is_altcha_v2_challenge(data):
                v2_challenge = parse_altcha_v2_challenge(data)
                upper = int(max_number if max_number is not None else default_maxnumber or DEFAULT_V2_MAX_COUNTER)
                raw["challenge"] = v2_challenge.to_payload()
                if hmac_signature_secret and v2_challenge.signature:
                    diagnostics["signature_valid"] = verify_altcha_v2_solution(
                        v2_challenge,
                        {"counter": start, "derivedKey": altcha_v2_derive_key_hex(v2_challenge, start)},
                        hmac_signature_secret=hmac_signature_secret,
                    )
                diagnostics.update(
                    {
                        "version": "v2",
                        "algorithm": v2_challenge.algorithm,
                        "max_counter": upper,
                        "salt": v2_challenge.parameters.get("salt"),
                        "key_prefix": v2_challenge.key_prefix,
                        "key_prefix_length": len(v2_challenge.key_prefix),
                        "signature_present": bool(v2_challenge.signature),
                        "key_signature_present": bool(v2_challenge.key_signature),
                        "v2_strategy": v2_strategy,
                        "counter_mode": counter_mode,
                    }
                )
                v2_solution = solve_altcha_v2_challenge(
                    v2_challenge,
                    start=start,
                    max_counter=upper,
                    workers=workers,
                    timeout_sec=timeout_sec,
                    counter_mode=counter_mode,
                    strategy=v2_strategy,
                    hmac_algorithm=hmac_algorithm,
                    hmac_key_signature_secret=hmac_key_signature_secret,
                )
                if v2_solution is None:
                    errors.append(f"no ALTCHA v2 solution found in range {start}..{upper}")
                    return finish(ok=False)
                payload_b64 = v2_solution.payload_b64()
                raw["solution"] = {
                    "counter": v2_solution.counter,
                    "derivedKey": v2_solution.derived_key,
                    "time": v2_solution.took_ms,
                    "checked": v2_solution.checked,
                    "strategy": v2_solution.strategy,
                    "prefixMatched": v2_solution.prefix_matched,
                }
                raw["payload"] = v2_solution.payload()
                raw["payloadBase64"] = payload_b64
                diagnostics.update(
                    {
                        "counter": v2_solution.counter,
                        "derived_key_prefix": v2_solution.derived_key[:16],
                        "checked": v2_solution.checked,
                        "solve_ms": v2_solution.took_ms,
                        "prefix_matched": v2_solution.prefix_matched,
                        "strategy_used": v2_solution.strategy,
                        "mode": "form",
                    }
                )
                return finish(ok=True, ticket=payload_b64, verify_code=str(v2_solution.counter))

            if challenge_obj is None:
                challenge_obj = parse_altcha_challenge(data)
            upper = int(max_number if max_number is not None else challenge_obj.maxnumber)
            raw["challenge"] = asdict(challenge_obj)
            diagnostics.update(
                {
                    "version": "v1",
                    "algorithm": challenge_obj.algorithm,
                    "maxnumber": upper,
                    "salt": challenge_obj.salt,
                    "challenge_prefix": challenge_obj.challenge[:12],
                }
            )
            solution = solve_altcha_challenge(
                challenge_obj,
                start=start,
                max_number=upper,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append(f"no ALTCHA solution found in range {start}..{upper}")
                return finish(ok=False)

            payload_b64 = solution.payload_b64(include_took=include_took)
            auth_header = solution.authorization_header()
            auth_header_kv = solution.authorization_header(style="kv")
            raw["solution"] = asdict(solution)
            raw["payload"] = solution.payload(include_took=include_took)
            raw["payloadBase64"] = payload_b64
            raw["authorizationHeader"] = auth_header
            raw["authorizationHeaderKeyValue"] = auth_header_kv
            diagnostics.update(
                {
                    "number": solution.number,
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "mode": "m2m" if www_authenticate or mode == "m2m" else "form",
                }
            )
            ticket = auth_header if www_authenticate or mode == "m2m" else payload_b64
            return finish(ok=True, ticket=ticket, verify_code=str(solution.number))
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)
