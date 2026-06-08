from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

CHPIO_CHALLENGE_MAGIC = "2104f639-ba1b-48f3-9443-889128163f5a"
CHPIO_REDEEMED_MAGIC = "90a63087-993a-4376-9532-33c3dc8557c9"
DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE = 50_000_000
DEFAULT_TIMEOUT_SEC = 60
MAX_U64 = (1 << 64) - 1


@dataclass(slots=True)
class ChpioPowEntry:
    nonce: bytes
    target: bytes

    @property
    def nonce_b64(self) -> str:
        return _b64encode(self.nonce)

    @property
    def target_b64(self) -> str:
        return _b64encode(self.target)

    def to_wire(self) -> list[str]:
        return [self.nonce_b64, self.target_b64]


@dataclass(slots=True)
class ChpioPowChallenge:
    entries: list[ChpioPowEntry]
    difficulty_bits: int
    magic: str = CHPIO_CHALLENGE_MAGIC
    signed_data: dict[str, str] | None = None
    data_json: str | None = None

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_payload(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "challenges": [entry.to_wire() for entry in self.entries],
            "difficultyBits": self.difficulty_bits,
        }


@dataclass(slots=True)
class ChpioPowSolution:
    challenge: ChpioPowChallenge
    solutions: list[bytes]
    took_ms: int
    checked: int

    @property
    def solution_b64(self) -> list[str]:
        return [_b64encode(item) for item in self.solutions]

    @property
    def solution_ints(self) -> list[int]:
        return [int.from_bytes(item, "little", signed=False) for item in self.solutions]

    @property
    def submit_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {"solutions": self.solution_b64}
        if self.challenge.signed_data is not None:
            body["challengesSigned"] = dict(self.challenge.signed_data)
        else:
            body["challenge"] = self.challenge.to_payload()
        return body

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def chpiopow_utf16le_bytes(value: str) -> bytes:
    """Match upstream wire.ts Uint16Array(charCodeAt(...)).buffer hashing."""

    return value.encode("utf-16le")


def sign_chpiopow_data(data: dict[str, Any] | str, secret: str) -> dict[str, str]:
    data_json = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(chpiopow_utf16le_bytes(f"{data_json}:{secret}")).digest()
    return {"data": data_json, "hash": _b64encode(digest)}


def verify_chpiopow_signed_data(signed_data: dict[str, Any], secret: str) -> bool:
    if not isinstance(signed_data, dict):
        return False
    data = signed_data.get("data")
    hash_b64 = signed_data.get("hash")
    if not isinstance(data, str) or not isinstance(hash_b64, str):
        return False
    expected = sign_chpiopow_data(data, secret)["hash"]
    return hmac.compare_digest(expected, hash_b64)


def verify_chpiopow_redeemed(signed_data: dict[str, Any], secret: str | None = None) -> bool:
    try:
        if secret is not None and not verify_chpiopow_signed_data(signed_data, secret):
            return False
        data = json.loads(str(signed_data.get("data") or "{}"))
        return isinstance(data, dict) and data.get("magic") == CHPIO_REDEEMED_MAGIC
    except Exception:
        return False


def chpiopow_hash_bytes(nonce: bytes, solution: bytes | int) -> bytes:
    solution_bytes = (
        int(solution).to_bytes(8, "little", signed=False) if isinstance(solution, int) else bytes(solution)
    )
    if len(solution_bytes) != 8:
        raise ValueError("chpio pow-captcha solution must be exactly 8 bytes")
    return hashlib.sha256(solution_bytes + bytes(nonce)).digest()


def chpiopow_target_matches(hash_bytes: bytes, target: bytes, difficulty_bits: int) -> bool:
    difficulty_bits = max(0, int(difficulty_bits))
    required_len = math.ceil(difficulty_bits / 8)
    if len(target) < required_len:
        raise ValueError("chpio pow-captcha target is smaller than difficulty_bits")
    whole = difficulty_bits // 8
    if hash_bytes[:whole] != target[:whole]:
        return False
    rest = difficulty_bits % 8
    if rest == 0:
        return True
    mask = (0xFF << (8 - rest)) & 0xFF
    return (hash_bytes[whole] & mask) == (target[whole] & mask)


def verify_chpiopow_solution(
    nonce: bytes | str,
    target: bytes | str,
    difficulty_bits: int,
    solution: bytes | str | int,
) -> bool:
    try:
        nonce_bytes = _maybe_b64decode(nonce)
        target_bytes = _maybe_b64decode(target)
        solution_bytes = _solution_to_bytes(solution)
        digest = chpiopow_hash_bytes(nonce_bytes, solution_bytes)
        return chpiopow_target_matches(digest, target_bytes, difficulty_bits)
    except Exception:
        return False


def parse_chpiopow_challenge(
    data: ChpioPowChallenge | dict[str, Any] | str,
    *,
    secret: str | None = None,
) -> ChpioPowChallenge:
    if isinstance(data, ChpioPowChallenge):
        return data
    obj = _load_jsonish(data)
    if not isinstance(obj, dict):
        raise ValueError("chpio pow-captcha challenge must be a JSON object")

    signed: dict[str, str] | None = None
    data_json: str | None = None
    if "challengesSigned" in obj and isinstance(obj.get("challengesSigned"), dict):
        obj = dict(obj["challengesSigned"])
    if _is_signed_data(obj):
        if secret is not None and not verify_chpiopow_signed_data(obj, secret):
            raise ValueError("chpio pow-captcha signed challenge hash mismatch")
        signed = {"data": str(obj["data"]), "hash": str(obj["hash"])}
        data_json = signed["data"]
        payload = json.loads(data_json)
    else:
        payload = obj

    if not isinstance(payload, dict):
        raise ValueError("chpio pow-captcha challenge payload must be an object")
    magic = str(payload.get("magic") or CHPIO_CHALLENGE_MAGIC)
    if magic != CHPIO_CHALLENGE_MAGIC:
        raise ValueError(f"unsupported chpio pow-captcha magic: {magic}")
    difficulty_bits = int(payload.get("difficultyBits", payload.get("difficulty_bits", 0)))
    if difficulty_bits < 0 or difficulty_bits > 256:
        raise ValueError("chpio pow-captcha difficultyBits must be in [0, 256]")
    raw_entries = payload.get("challenges")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ValueError("chpio pow-captcha challenge requires non-empty challenges list")

    entries: list[ChpioPowEntry] = []
    for raw in raw_entries:
        if isinstance(raw, dict):
            nonce_value = raw.get("nonce") or raw.get("challenge") or raw.get("n")
            target_value = raw.get("target") or raw.get("t")
        elif isinstance(raw, (list, tuple)) and len(raw) == 2:
            nonce_value, target_value = raw
        else:
            raise ValueError("chpio pow-captcha challenge entries must be [nonce,target]")
        if not isinstance(nonce_value, str) or not isinstance(target_value, str):
            raise ValueError("chpio pow-captcha nonce/target must be base64 strings")
        nonce_bytes = _b64decode(nonce_value)
        target_bytes = _b64decode(target_value)
        if len(target_bytes) < math.ceil(difficulty_bits / 8):
            raise ValueError("chpio pow-captcha target is smaller than difficultyBits")
        entries.append(ChpioPowEntry(nonce=nonce_bytes, target=target_bytes))

    return ChpioPowChallenge(
        entries=entries,
        difficulty_bits=difficulty_bits,
        magic=magic,
        signed_data=signed,
        data_json=data_json,
    )


def solve_chpiopow_challenge(
    challenge: ChpioPowChallenge | dict[str, Any] | str,
    *,
    secret: str | None = None,
    start: int = 0,
    max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> ChpioPowSolution | None:
    item = parse_chpiopow_challenge(challenge, secret=secret)
    started = time.monotonic()
    start = _validate_u64_start(start)
    max_attempts = max(1, int(max_attempts_per_challenge))
    end = min(MAX_U64 + 1, start + max_attempts)
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    checked_total = 0

    if workers <= 1 or item.count <= 1:
        solutions: list[bytes] = []
        for entry in item.entries:
            solution, checked = _solve_chpiopow_range(
                entry.nonce,
                entry.target,
                item.difficulty_bits,
                start,
                end,
                deadline,
            )
            checked_total += checked
            if solution is None:
                return None
            solutions.append(solution)
        return ChpioPowSolution(
            item,
            solutions,
            int((time.monotonic() - started) * 1000),
            checked_total,
        )

    pool = ProcessPoolExecutor(max_workers=min(workers, item.count))
    futures = {
        pool.submit(
            _solve_chpiopow_range,
            entry.nonce,
            entry.target,
            item.difficulty_bits,
            start,
            end,
            deadline,
        ): idx
        for idx, entry in enumerate(item.entries)
    }
    solutions_by_idx: dict[int, bytes] = {}
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx = futures[fut]
            solution, checked = fut.result()
            checked_total += checked
            if solution is None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            solutions_by_idx[idx] = solution
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if len(solutions_by_idx) != item.count:
        return None
    solutions = [solutions_by_idx[idx] for idx in range(item.count)]
    return ChpioPowSolution(
        item,
        solutions,
        int((time.monotonic() - started) * 1000),
        checked_total,
    )


def _solve_chpiopow_range(
    nonce: bytes,
    target: bytes,
    difficulty_bits: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[bytes | None, int]:
    checked = 0
    buf = bytearray(8 + len(nonce))
    buf[8:] = nonce
    for value in range(int(start), int(end_exclusive)):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, checked
        buf[:8] = int(value).to_bytes(8, "little", signed=False)
        checked += 1
        digest = hashlib.sha256(buf).digest()
        if chpiopow_target_matches(digest, target, difficulty_bits):
            return bytes(buf[:8]), checked
    return None, checked


def _load_jsonish(value: ChpioPowChallenge | dict[str, Any] | str) -> Any:
    if isinstance(value, ChpioPowChallenge):
        return value
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError("expected JSON object/string")
    text = value.strip()
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8")
    return json.loads(text)


def _is_signed_data(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("data"), str) and isinstance(value.get("hash"), str)


def _validate_u64_start(start: int) -> int:
    value = int(start)
    if value < 0 or value > MAX_U64:
        raise ValueError("start must be in uint64 range")
    return value


def _solution_to_bytes(solution: bytes | str | int) -> bytes:
    if isinstance(solution, int):
        return int(solution).to_bytes(8, "little", signed=False)
    if isinstance(solution, bytes):
        if len(solution) != 8:
            raise ValueError("solution must be exactly 8 bytes")
        return bytes(solution)
    text = str(solution).strip()
    if text.startswith("0x"):
        raw = bytes.fromhex(text[2:])
    else:
        raw = _b64decode(text)
    if len(raw) != 8:
        raise ValueError("solution must decode to exactly 8 bytes")
    return raw


def _maybe_b64decode(value: bytes | str) -> bytes:
    return bytes(value) if isinstance(value, bytes) else _b64decode(value)


def _b64decode(value: str) -> bytes:
    text = str(value).strip()
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.b64decode(text.encode("ascii"), validate=True)


def _b64encode(value: bytes) -> str:
    return base64.b64encode(bytes(value)).decode("ascii")


def _load_json_arg(value: Any = None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _extract_token(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        for key in ("token", "ticket", "captcha_token", "redeemed"):
            value = data.get(key)
            if value:
                return str(value)
    return fallback


class ChpioPowSolver:
    """Protocol solver for chpio/pow-captcha signed multi-challenge SHA-256 PoW."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        redeem_url: str | None = None,
        submit: bool = False,
        secret: str | None = None,
        start: int = 0,
        max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "redeem_url": redeem_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "start": start,
            "max_attempts_per_challenge": max_attempts_per_challenge,
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
                out = output_root / "chpiopow_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="chpiopow",
                ok=ok,
                captcha_type="target_match_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=str(diagnostics.get("challenge_count") or ""),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            item = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                secret=secret,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            diagnostics.update(
                {
                    "challenge_count": item.count,
                    "difficulty_bits": item.difficulty_bits,
                    "signed": item.signed_data is not None,
                }
            )
            raw["challenge"] = {
                "magic": item.magic,
                "difficultyBits": item.difficulty_bits,
                "count": item.count,
                "signed": item.signed_data is not None,
            }

            solution = solve_chpiopow_challenge(
                item,
                secret=secret,
                start=start,
                max_attempts_per_challenge=max_attempts_per_challenge,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("chpio pow-captcha solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)

            raw["solution"] = {
                "solutions": solution.solution_b64,
                "solutionInts": solution.solution_ints,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "solution_ints": solution.solution_ints,
                }
            )

            ticket = solution.submit_body_json()
            verify_code = "solved"
            if submit and redeem_url:
                redeem_data = self._submit_solution(
                    redeem_url=redeem_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if _is_signed_data(redeem_data):
                    if secret is not None and not verify_chpiopow_redeemed(redeem_data, secret):
                        errors.append("chpio pow-captcha redeem signed response verification failed")
                        return finish(ok=False, ticket=ticket, verify_code="redeem_failed")
                    verify_code = "validated"
                    ticket = json.dumps(redeem_data, ensure_ascii=False, separators=(",", ":"))
                elif isinstance(redeem_data, dict) and (
                    redeem_data.get("ok") or redeem_data.get("success") or redeem_data.get("token")
                ):
                    verify_code = "validated"
                    ticket = _extract_token(redeem_data, ticket)
                else:
                    errors.append("chpio pow-captcha redeem rejected solution")
                    return finish(ok=False, ticket=ticket, verify_code="redeem_failed")
                diagnostics["submitted"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        secret: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> ChpioPowChallenge:
        if challenge:
            raw["challengeSource"] = "inline"
            return parse_chpiopow_challenge(challenge, secret=secret)
        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return parse_chpiopow_challenge(data, secret=secret)
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            raw["challengeSource"] = "url"
            return parse_chpiopow_challenge(resp.json(), secret=secret)
        raise ValueError("chpio pow-captcha requires challenge_json, challenge_file or challenge_url")

    def _submit_solution(
        self,
        *,
        redeem_url: str,
        solution: ChpioPowSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            redeem_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=solution.submit_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["redeemResponse"] = {"status": resp.status_code, "url": redeem_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["redeemResponse"]["json"] = data
        return data
