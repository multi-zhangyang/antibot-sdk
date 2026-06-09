from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import requests

from ..models import CaptchaResult

PROVIDER = "akamai_bm"
CAPABILITY = "akamai_bm_experimental"
CAPTCHA_TYPE = "akamai_bm_sensor_experimental"

ALPHABET = " !#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
ALPHABET_INDEX = {char: index for index, char in enumerate(ALPHABET)}

LCG_MULTIPLIER = 65_793
LCG_INCREMENT = 4_282_663
LCG_UINT32_MASK = 0xFFFFFFFF
LCG_STATE_MASK = 8_388_607
LCG_SHIFT_MASK = 65_535


@dataclass(frozen=True, slots=True)
class AkamaiBmKeys:
    """Two integer components used by Akamai Bot Manager sensor transforms.

    `bm_sz` tooling in the current research corpus exposes the last two cookie
    components as `(shuffle_key, cipher_key)`. Raw v3 sensor prefixes often store
    them as `3;<cipher_key>;<shuffle_key>;...`; the JSON helpers below normalize
    both representations into this dataclass before transforming payloads.
    """

    shuffle_key: int
    cipher_key: int

    @property
    def as_tuple(self) -> tuple[int, int]:
        return (self.shuffle_key, self.cipher_key)

    @property
    def sensor_prefix_tuple(self) -> tuple[int, int]:
        return (self.cipher_key, self.shuffle_key)


@dataclass(frozen=True, slots=True)
class AkamaiAbckMnChallenge:
    """Parsed `_abck` `mn_*` proof-of-work challenge.

    Akamai scripts derive this from the 5th `~` segment of `_abck`, where entries
    look like `1-<psn>-<seed>-<delay>-<timeout>-<type>`.  The worker computes
    SHA-256 over `abck_id + startTs + psn + (seed + round) + nonce` and accepts
    a digest whose big-endian integer is divisible by `seed + round`.
    """

    enabled: int
    abck_id: str
    psn: str
    seed: int
    delay_ms: int
    timeout_ms: int
    challenge_type: int = 1
    raw: str = ""

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.abck_id and self.psn and self.seed > 0)


@dataclass(frozen=True, slots=True)
class AkamaiAbckMnRound:
    round_index: int
    divisor: int
    nonce: str
    digest_hex: str
    attempts: int
    input_value: str
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class AkamaiAbckMnSolution:
    challenge: AkamaiAbckMnChallenge
    start_ts_ms: int
    rounds: list[AkamaiAbckMnRound]
    result: str
    elapsed_ms: int

    @property
    def nonce_csv(self) -> str:
        return ",".join(item.nonce for item in self.rounds)

    @property
    def timing_csv(self) -> str:
        return ",".join(str(item.elapsed_ms) for item in self.rounds)

    @property
    def attempts_csv(self) -> str:
        return ",".join(str(item.attempts) for item in self.rounds)


def extract_bm_sz_keys(cookie_value: str) -> AkamaiBmKeys:
    """Extract `(shuffle_key, cipher_key)` from a `bm_sz` value or Cookie header."""

    value = _extract_cookie_value(cookie_value, "bm_sz")
    parts = [part.strip() for part in value.split("~") if part.strip()]
    if len(parts) < 2:
        raise ValueError("bm_sz must contain at least two '~'-separated components")
    try:
        shuffle_key = int(parts[-2])
        cipher_key = int(parts[-1])
    except ValueError as exc:
        raise ValueError("last two bm_sz components must be integer keys") from exc
    return AkamaiBmKeys(shuffle_key=shuffle_key, cipher_key=cipher_key)


def parse_abck_mn_challenges(cookie_value: str) -> list[AkamaiAbckMnChallenge]:
    """Parse Akamai `_abck` `mn_*` challenges from a cookie value or Cookie header."""

    value = _extract_cookie_value(cookie_value, "_abck")
    parts = value.split("~")
    if len(parts) < 5:
        return []
    abck_id = parts[0]
    challenge_segment = parts[4]
    challenges: list[AkamaiAbckMnChallenge] = []
    for raw_entry in challenge_segment.split("||"):
        entry = raw_entry.strip().strip(";")
        if not entry:
            continue
        fields = entry.split("-")
        if len(fields) == 1 and fields[0] == "0":
            continue
        if len(fields) < 5:
            continue
        try:
            enabled = int(fields[0])
            seed = int(fields[2])
            delay_ms = int(fields[3])
            timeout_ms = int(fields[4])
            challenge_type = int(fields[5]) if len(fields) >= 6 and fields[5] else 1
        except ValueError:
            continue
        challenges.append(
            AkamaiAbckMnChallenge(
                enabled=enabled,
                abck_id=abck_id,
                psn=fields[1],
                seed=seed,
                delay_ms=delay_ms,
                timeout_ms=timeout_ms,
                challenge_type=challenge_type,
                raw=entry,
            )
        )
    challenges.sort(key=lambda item: 0 if item.challenge_type == 2 else 1)
    return challenges


def akamai_mn_hash_bytes(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def akamai_mn_hash_hex(value: str) -> str:
    return akamai_mn_hash_bytes(value).hex()


def akamai_mn_mod(digest: bytes | str, divisor: int) -> int:
    """Match Akamai's byte-wise `vf(digest, divisor)` modulo reducer."""

    if divisor <= 0:
        raise ValueError("Akamai mn divisor must be positive")
    raw = bytes.fromhex(digest) if isinstance(digest, str) else bytes(digest)
    acc = 0
    for byte in raw:
        acc = ((acc << 8) | byte) & 0xFFFFFFFF
        acc %= divisor
    return acc


def solve_abck_mn_challenge(
    challenge: AkamaiAbckMnChallenge | str,
    *,
    start_ts_ms: int | None = None,
    rounds: int = 10,
    start: int = 0,
    max_attempts_per_round: int = 250_000,
    nonce_prefix: str = "0.",
) -> AkamaiAbckMnSolution:
    """Solve the `_abck` `mn_*` SHA-256 modulo challenge without a browser."""

    item = _coerce_mn_challenge(challenge)
    if not item.active:
        raise ValueError("Akamai mn challenge is inactive or incomplete")
    if rounds < 1:
        raise ValueError("rounds must be positive")
    start_ts = int(time.time() * 1000) if start_ts_ms is None else int(start_ts_ms)
    started = time.monotonic()
    prefix = f"{item.abck_id}{start_ts}{item.psn}"
    solved: list[AkamaiAbckMnRound] = []
    for round_index in range(int(rounds)):
        divisor = item.seed + round_index
        if divisor <= 0:
            raise ValueError("Akamai mn round divisor must be positive")
        round_started = time.monotonic()
        found: AkamaiAbckMnRound | None = None
        for offset in range(max(0, int(start)), max(0, int(start)) + int(max_attempts_per_round)):
            nonce = f"{nonce_prefix}{offset:x}"
            input_value = f"{prefix}{divisor}{nonce}"
            digest = akamai_mn_hash_bytes(input_value)
            if akamai_mn_mod(digest, divisor) == 0:
                found = AkamaiAbckMnRound(
                    round_index=round_index,
                    divisor=divisor,
                    nonce=nonce,
                    digest_hex=digest.hex(),
                    attempts=offset - max(0, int(start)),
                    input_value=input_value,
                    elapsed_ms=int((time.monotonic() - round_started) * 1000),
                )
                break
        if found is None:
            raise RuntimeError(
                f"Akamai mn solve failed at round {round_index}; "
                f"max_attempts_per_round={max_attempts_per_round}"
            )
        solved.append(found)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    result = _build_mn_result(item, start_ts, solved, elapsed_ms)
    return AkamaiAbckMnSolution(
        challenge=item,
        start_ts_ms=start_ts,
        rounds=solved,
        result=result,
        elapsed_ms=elapsed_ms,
    )


def verify_abck_mn_solution(solution: AkamaiAbckMnSolution | dict[str, Any] | str) -> bool:
    try:
        if isinstance(solution, AkamaiAbckMnSolution):
            prefix = f"{solution.challenge.abck_id}{solution.start_ts_ms}{solution.challenge.psn}"
            return all(
                akamai_mn_mod(item.digest_hex, item.divisor) == 0
                and item.digest_hex == akamai_mn_hash_hex(f"{prefix}{item.divisor}{item.nonce}")
                for item in solution.rounds
            )
        if isinstance(solution, dict):
            chal = _coerce_mn_challenge(solution["challenge"])
            sol = solve_abck_mn_challenge(
                chal,
                start_ts_ms=int(solution["start_ts_ms"]),
                rounds=len(solution.get("nonces") or []),
                max_attempts_per_round=1,
            )
            return sol.nonce_csv == ",".join(solution.get("nonces") or [])
        return bool(solution and solution.count(";") >= 3)
    except Exception:
        return False


def akamai_lcg_next(seed: int) -> int:
    seed = (int(seed) * LCG_MULTIPLIER) & LCG_UINT32_MASK
    seed = (seed + LCG_INCREMENT) & LCG_STATE_MASK
    return (seed >> 8) & LCG_SHIFT_MASK


def akamai_shuffle_fields(text: str, seed: int, *, delimiter: str = ",") -> str:
    fields = text.split(delimiter)
    if len(fields) <= 1:
        return text
    state = int(seed)
    for _ in range(len(fields)):
        state = akamai_lcg_next(state)
        first = state % len(fields)
        state = akamai_lcg_next(state)
        second = state % len(fields)
        fields[first], fields[second] = fields[second], fields[first]
    return delimiter.join(fields)


def akamai_unshuffle_fields(text: str, seed: int, *, delimiter: str = ",") -> str:
    fields = text.split(delimiter)
    if len(fields) <= 1:
        return text
    state = int(seed)
    swaps: list[tuple[int, int]] = []
    for _ in range(len(fields)):
        state = akamai_lcg_next(state)
        first = state % len(fields)
        state = akamai_lcg_next(state)
        second = state % len(fields)
        swaps.append((first, second))
    for first, second in reversed(swaps):
        fields[first], fields[second] = fields[second], fields[first]
    return delimiter.join(fields)


def akamai_encrypt_string(text: str, key: int) -> str:
    return _akamai_shift_string(text, key=int(key), direction=1)


def akamai_decrypt_string(text: str, key: int) -> str:
    return _akamai_shift_string(text, key=int(key), direction=-1)


def akamai_encrypt_sensor(sensor: str, keys: AkamaiBmKeys | tuple[int, int]) -> str:
    normalized = _coerce_keys(keys)
    shuffled = akamai_shuffle_fields(sensor, normalized.shuffle_key, delimiter=",")
    return akamai_encrypt_string(shuffled, normalized.cipher_key)


def akamai_decrypt_sensor(sensor: str, keys: AkamaiBmKeys | tuple[int, int]) -> str:
    normalized = _coerce_keys(keys)
    half_clean = akamai_decrypt_string(sensor, normalized.cipher_key)
    return akamai_unshuffle_fields(half_clean, normalized.shuffle_key, delimiter=",")


def build_minimal_sensor_profile(
    *,
    page_url: str = "",
    user_agent: str = "",
    bm_sz: str | None = None,
    abck: str | None = None,
    now_ms: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "provider": PROVIDER,
        "mode": "experimental_minimal",
        "ts": int(time.time() * 1000) if now_ms is None else int(now_ms),
        "page_url": page_url,
        "user_agent": user_agent,
        "bm_sz_present": bool(bm_sz),
        "abck_present": bool(abck),
    }
    if extra:
        profile.update(extra)
    return profile


def encode_minimal_sensor_json(
    profile: dict[str, Any],
    keys: AkamaiBmKeys | tuple[int, int],
    *,
    version: str = "3",
    include_prefix: bool = True,
) -> str:
    if str(version) != "3":
        raise ValueError("minimal JSON sensor currently supports v3-style payloads only")
    normalized = _coerce_keys(keys)
    raw_json = json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    shuffled = akamai_shuffle_fields(raw_json, normalized.shuffle_key, delimiter=":")
    encrypted = akamai_encrypt_string(shuffled, normalized.cipher_key)
    if not include_prefix:
        return encrypted
    cipher_key, shuffle_key = normalized.sensor_prefix_tuple
    return f"3;{cipher_key};{shuffle_key};0;{encrypted}"


def decode_minimal_sensor_json(
    sensor_data: str | dict[str, Any],
    keys: AkamaiBmKeys | tuple[int, int] | None = None,
) -> dict[str, Any]:
    raw = _extract_sensor_data(sensor_data)
    normalized, encrypted = _parse_sensor_envelope(raw, keys=keys)
    half_clean = akamai_decrypt_string(encrypted, normalized.cipher_key)
    clean = akamai_unshuffle_fields(half_clean, normalized.shuffle_key, delimiter=":")
    decoded = json.loads(clean)
    if not isinstance(decoded, dict):
        raise ValueError("decoded minimal sensor JSON must be an object")
    return decoded


def submit_akamai_bm_sensor(
    sensor_data: str,
    submit_url: str,
    *,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    session: requests.Session | None = None,
) -> CaptchaResult:
    started = time.perf_counter()
    req_headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)
    body = {"sensor_data": sensor_data}
    raw_body = json.dumps(body, separators=(",", ":"))
    errors: list[str] = []
    response: requests.Response | None = None
    try:
        client = session or requests.Session()
        response = client.post(
            submit_url,
            data=raw_body.encode("utf-8"),
            headers=req_headers,
            cookies=cookies,
            timeout=timeout,
        )
        ok = 200 <= response.status_code < 400
    except requests.RequestException as exc:
        errors.append(str(exc))
        ok = False

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    diagnostics: dict[str, Any] = {
        "submit_url": submit_url,
        "request_body_keys": sorted(body),
        "mode": "mock_submit_capable",
    }
    raw: dict[str, Any] = {"request_body": body}
    ticket: str | None = None
    verify_code: str | None = None
    if response is not None:
        verify_code = str(response.status_code)
        ticket = response.headers.get("Set-Cookie")
        diagnostics.update(
            {
                "status_code": response.status_code,
                "response_content_type": response.headers.get("Content-Type", ""),
                "response_text_preview": response.text[:200],
            }
        )
        raw["response_headers"] = dict(response.headers)
        raw["response_text"] = response.text

    return CaptchaResult(
        provider=PROVIDER,
        ok=ok,
        captcha_type=CAPTCHA_TYPE,
        capability=CAPABILITY,
        ticket=ticket,
        verify_code=verify_code,
        elapsed_ms=elapsed_ms,
        diagnostics=diagnostics,
        raw=raw,
        errors=errors,
    )


class AkamaiBmSolver:
    """Experimental Akamai Bot Manager sensor primitive provider.

    This is deliberately scoped below a full Akamai bypass: it extracts `bm_sz`
    transform keys, builds/decodes a minimal v3-style sensor envelope, and can
    submit `{"sensor_data": ...}` to `/_bm/_data` style mocks or controlled
    endpoints. It does not claim dynamic `bmak` raw-script execution or `_abck`
    challenge state solving.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        sensor_data: str | None = None,
        sensor_file: str | None = None,
        bm_sz: str | None = None,
        abck: str | None = None,
        cookie_header: str | None = None,
        cookies: dict[str, str] | None = None,
        page_url: str = "",
        user_agent: str = "",
        profile: dict[str, Any] | None = None,
        profile_json: str | None = None,
        profile_file: str | None = None,
        solve_mn: bool = False,
        mn_start_ts_ms: int | None = None,
        mn_rounds: int = 10,
        mn_max_attempts_per_round: int = 250_000,
        submit: bool = False,
        submit_url: str | None = None,
        timeout_sec: int = 10,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "mode": "experimental_minimal",
            "submit": submit,
            "submit_url": submit_url,
            "solve_mn": solve_mn,
        }
        errors: list[str] = []

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            raw["ok"] = ok
            raw["elapsedMs"] = elapsed_ms
            return CaptchaResult(
                provider=PROVIDER,
                ok=ok,
                captcha_type=CAPTCHA_TYPE,
                capability=CAPABILITY,
                ticket=ticket,
                verify_code=verify_code,
                elapsed_ms=elapsed_ms,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            cookie_map = _collect_cookies(
                cookie_header=cookie_header,
                cookies=cookies,
                bm_sz=bm_sz,
                abck=abck,
            )
            keys = extract_bm_sz_keys(cookie_map["bm_sz"]) if cookie_map.get("bm_sz") else None
            if keys:
                diagnostics.update(
                    {
                        "shuffle_key": keys.shuffle_key,
                        "cipher_key": keys.cipher_key,
                        "bm_sz_present": True,
                    }
                )
            diagnostics["abck_present"] = bool(cookie_map.get("_abck"))
            mn_solution: AkamaiAbckMnSolution | None = None
            if solve_mn:
                challenges = parse_abck_mn_challenges(cookie_map.get("_abck") or abck or "")
                raw["mnChallenges"] = [
                    {
                        "enabled": item.enabled,
                        "abckId": item.abck_id,
                        "psn": item.psn,
                        "seed": item.seed,
                        "delayMs": item.delay_ms,
                        "timeoutMs": item.timeout_ms,
                        "challengeType": item.challenge_type,
                        "raw": item.raw,
                    }
                    for item in challenges
                ]
                diagnostics["mn_challenges"] = len(challenges)
                active = next((item for item in challenges if item.active), None)
                if active is None:
                    errors.append("Akamai BM solve_mn requested but _abck contains no active mn challenge")
                    return finish(ok=False, verify_code="missing_mn_challenge")
                mn_solution = solve_abck_mn_challenge(
                    active,
                    start_ts_ms=mn_start_ts_ms,
                    rounds=mn_rounds,
                    max_attempts_per_round=mn_max_attempts_per_round,
                )
                raw["mnSolution"] = {
                    "startTsMs": mn_solution.start_ts_ms,
                    "result": mn_solution.result,
                    "nonces": mn_solution.nonce_csv,
                    "attempts": mn_solution.attempts_csv,
                    "elapsedMs": mn_solution.elapsed_ms,
                    "rounds": [
                        {
                            "round": item.round_index,
                            "divisor": item.divisor,
                            "nonce": item.nonce,
                            "digestHex": item.digest_hex,
                            "attempts": item.attempts,
                            "elapsedMs": item.elapsed_ms,
                        }
                        for item in mn_solution.rounds
                    ],
                }
                diagnostics.update(
                    {
                        "mn_solved": True,
                        "mn_rounds": len(mn_solution.rounds),
                        "mn_start_ts_ms": mn_solution.start_ts_ms,
                        "mn_elapsed_ms": mn_solution.elapsed_ms,
                        "mn_result_prefix": mn_solution.result[:80],
                    }
                )

            sensor = _load_text_arg(sensor_data, sensor_file)
            decoded: dict[str, Any] | None = None
            if sensor:
                raw["sensor_data"] = sensor
                try:
                    decoded = decode_minimal_sensor_json(sensor, keys=keys)
                    raw["decoded"] = decoded
                    diagnostics["decoded"] = True
                except Exception as exc:
                    diagnostics["decoded"] = False
                    diagnostics["decode_error"] = str(exc)
            else:
                if keys is None:
                    if solve_mn and mn_solution is not None and not submit:
                        return finish(ok=True, ticket=mn_solution.result, verify_code="mn_solved")
                    errors.append("Akamai BM synthetic sensor requires bm_sz or cookie_header with bm_sz")
                    return finish(ok=False, verify_code="missing_bm_sz")
                profile_obj = _load_profile(profile=profile, profile_json=profile_json, profile_file=profile_file)
                if profile_obj is None:
                    profile_obj = build_minimal_sensor_profile(
                        page_url=page_url,
                        user_agent=user_agent,
                        bm_sz=cookie_map.get("bm_sz"),
                        abck=cookie_map.get("_abck"),
                    )
                if mn_solution is not None:
                    profile_obj = dict(profile_obj)
                    profile_obj.setdefault("mn_r", mn_solution.result)
                    profile_obj.setdefault("mn_abck", mn_solution.challenge.abck_id)
                    profile_obj.setdefault("mn_psn", mn_solution.challenge.psn)
                    profile_obj.setdefault("mn_challenge_type", mn_solution.challenge.challenge_type)
                sensor = encode_minimal_sensor_json(profile_obj, keys)
                decoded = decode_minimal_sensor_json(sensor)
                raw["decoded"] = decoded
                raw["sensor_data"] = sensor

            diagnostics["sensor_prefix"] = sensor[:32]
            diagnostics["sensor_length"] = len(sensor)
            if decoded:
                diagnostics["decoded_keys"] = sorted(decoded.keys())

            if not submit:
                return finish(ok=True, ticket=sensor, verify_code="solved")

            if not submit_url:
                errors.append("Akamai BM submit requested but submit_url is missing")
                return finish(ok=False, ticket=sensor, verify_code="missing_submit_url")
            submit_result = submit_akamai_bm_sensor(
                sensor,
                submit_url,
                cookies=cookie_map or None,
                headers=headers,
                timeout=timeout_sec,
            )
            raw["submit"] = submit_result.raw
            diagnostics.update(
                {
                    "submit_status": submit_result.diagnostics.get("status_code"),
                    "submit_mode": submit_result.diagnostics.get("mode"),
                    "submit_response_preview": submit_result.diagnostics.get("response_text_preview"),
                }
            )
            if submit_result.ok:
                return finish(ok=True, ticket=submit_result.ticket or sensor, verify_code="submitted")
            errors.extend(submit_result.errors or [f"submit failed: {submit_result.verify_code}"])
            return finish(ok=False, ticket=sensor, verify_code="submit_failed")
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)


def _akamai_shift_string(text: str, *, key: int, direction: int) -> str:
    state = int(key)
    chars: list[str] = []
    alphabet_len = len(ALPHABET)
    for char in text:
        shifted = (state >> 8) & LCG_SHIFT_MASK
        state = (state * LCG_MULTIPLIER) & LCG_UINT32_MASK
        state = (state + LCG_INCREMENT) & LCG_STATE_MASK

        index = ALPHABET_INDEX.get(char)
        if index is None:
            chars.append(char)
            continue
        chars.append(ALPHABET[(index + (direction * (shifted % alphabet_len))) % alphabet_len])
    return "".join(chars)


def _coerce_mn_challenge(challenge: AkamaiAbckMnChallenge | str | dict[str, Any]) -> AkamaiAbckMnChallenge:
    if isinstance(challenge, AkamaiAbckMnChallenge):
        return challenge
    if isinstance(challenge, dict):
        return AkamaiAbckMnChallenge(
            enabled=int(challenge.get("enabled", 1)),
            abck_id=str(challenge.get("abck_id") or challenge.get("abckId") or ""),
            psn=str(challenge.get("psn") or ""),
            seed=int(challenge.get("seed", 0)),
            delay_ms=int(challenge.get("delay_ms") or challenge.get("delayMs") or 0),
            timeout_ms=int(challenge.get("timeout_ms") or challenge.get("timeoutMs") or 0),
            challenge_type=int(challenge.get("challenge_type") or challenge.get("challengeType") or 1),
            raw=str(challenge.get("raw") or ""),
        )
    parsed = parse_abck_mn_challenges(str(challenge))
    if not parsed:
        raise ValueError("Akamai _abck contains no parseable mn challenge")
    return parsed[0]


def _build_mn_result(
    challenge: AkamaiAbckMnChallenge,
    start_ts_ms: int,
    rounds: list[AkamaiAbckMnRound],
    total_elapsed_ms: int,
) -> str:
    first = rounds[0]
    prefix = f"{challenge.abck_id}{start_ts_ms}{challenge.psn}"
    digest_bytes = ",".join(str(byte) for byte in bytes.fromhex(first.digest_hex))
    metadata = [
        challenge.abck_id,
        str(start_ts_ms),
        challenge.psn,
        prefix,
        str(challenge.seed),
        str(first.divisor),
        first.nonce,
        first.input_value,
        digest_bytes,
        "0",  # df: worker-start offset from bmak.startTs in the browser implementation.
        str(total_elapsed_ms),
        str(start_ts_ms + total_elapsed_ms),
    ]
    return (
        ",".join(item.nonce for item in rounds)
        + ";"
        + ",".join(str(item.elapsed_ms) for item in rounds)
        + ";"
        + ",".join(str(item.attempts) for item in rounds)
        + ";"
        + ",".join(metadata)
        + ";"
    )


def _load_text_arg(value: str | None, file_path: str | None = None) -> str | None:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    if value is None:
        return None
    text = value.strip()
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8").strip()
    return text


def _load_profile(
    *,
    profile: dict[str, Any] | None,
    profile_json: str | None,
    profile_file: str | None,
) -> dict[str, Any] | None:
    if profile is not None:
        return dict(profile)
    raw = _load_text_arg(profile_json, profile_file)
    if not raw:
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Akamai BM profile JSON must be an object")
    return parsed


def _collect_cookies(
    *,
    cookie_header: str | None,
    cookies: dict[str, str] | None,
    bm_sz: str | None,
    abck: str | None,
) -> dict[str, str]:
    out: dict[str, str] = {}
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        out.update({name: morsel.value for name, morsel in cookie.items()})
    if cookies:
        out.update({str(k): str(v) for k, v in cookies.items()})
    if bm_sz:
        out["bm_sz"] = _extract_cookie_value(bm_sz, "bm_sz")
    if abck:
        out["_abck"] = _extract_cookie_value(abck, "_abck")
    return out


def _coerce_keys(keys: AkamaiBmKeys | tuple[int, int]) -> AkamaiBmKeys:
    if isinstance(keys, AkamaiBmKeys):
        return keys
    if len(keys) != 2:
        raise ValueError("keys tuple must contain exactly two integers")
    return AkamaiBmKeys(shuffle_key=int(keys[0]), cipher_key=int(keys[1]))


def _extract_cookie_value(raw: str, cookie_name: str) -> str:
    value = raw.strip().strip('"')
    if not value:
        raise ValueError(f"{cookie_name} value is empty")
    if f"{cookie_name}=" not in value:
        return unquote(value.split(";", 1)[0].strip())

    cookie = SimpleCookie()
    try:
        cookie.load(value)
    except Exception:  # noqa: BLE001 - SimpleCookie is permissive but can still reject junk
        cookie = SimpleCookie()
    if cookie_name in cookie:
        return unquote(cookie[cookie_name].value.strip())

    for part in value.split(";"):
        name, sep, possible_value = part.strip().partition("=")
        if sep and name == cookie_name:
            return unquote(possible_value.strip().strip('"'))
    raise ValueError(f"{cookie_name} not found in cookie header")


def _extract_sensor_data(sensor_data: str | dict[str, Any]) -> str:
    if isinstance(sensor_data, dict):
        value = sensor_data.get("sensor_data")
        if not isinstance(value, str):
            raise ValueError("sensor_data object must contain a string 'sensor_data' field")
        return value
    raw = sensor_data.strip()
    if raw.startswith("{"):
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and isinstance(parsed.get("sensor_data"), str):
            return parsed["sensor_data"]
    return raw


def _parse_sensor_envelope(
    raw: str,
    *,
    keys: AkamaiBmKeys | tuple[int, int] | None,
) -> tuple[AkamaiBmKeys, str]:
    if raw.startswith("3;"):
        parts = raw.split(";", 4)
        if len(parts) != 5:
            raise ValueError("v3 sensor envelope must look like '3;<cipher>;<shuffle>;<meta>;<data>'")
        try:
            cipher_key = int(parts[1])
            shuffle_key = int(parts[2])
        except ValueError as exc:
            raise ValueError("v3 sensor envelope keys must be integers") from exc
        return AkamaiBmKeys(shuffle_key=shuffle_key, cipher_key=cipher_key), parts[4]
    if keys is None:
        raise ValueError("keys are required when sensor_data has no v3 key prefix")
    return _coerce_keys(keys), raw


__all__ = [
    "ALPHABET",
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "PROVIDER",
    "AkamaiAbckMnChallenge",
    "AkamaiAbckMnRound",
    "AkamaiAbckMnSolution",
    "AkamaiBmKeys",
    "AkamaiBmSolver",
    "akamai_mn_hash_bytes",
    "akamai_mn_hash_hex",
    "akamai_mn_mod",
    "akamai_decrypt_sensor",
    "akamai_decrypt_string",
    "akamai_encrypt_sensor",
    "akamai_encrypt_string",
    "akamai_lcg_next",
    "akamai_shuffle_fields",
    "akamai_unshuffle_fields",
    "build_minimal_sensor_profile",
    "decode_minimal_sensor_json",
    "encode_minimal_sensor_json",
    "extract_bm_sz_keys",
    "parse_abck_mn_challenges",
    "solve_abck_mn_challenge",
    "submit_akamai_bm_sensor",
    "verify_abck_mn_solution",
]
