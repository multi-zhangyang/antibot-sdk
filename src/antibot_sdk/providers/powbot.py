from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 2_000_000
DEFAULT_DIFFICULTY_LEVEL = 5
DEFAULT_BATCH_INDEX = 0


@dataclass(slots=True)
class PowBotChallenge:
    challenge_b64: str
    cpu_and_memory_cost: int
    block_size: int
    parallelization: int
    key_length: int
    preimage_b64: str
    difficulty: str
    difficulty_level: int

    @property
    def preimage_bytes(self) -> bytes:
        raw = base64.b64decode(self.preimage_b64, validate=True)
        if len(raw) != 8:
            raise ValueError("PoW Bot Deterrent preimage must be 8 bytes")
        return raw

    def to_payload(self) -> dict[str, Any]:
        return {
            "N": self.cpu_and_memory_cost,
            "r": self.block_size,
            "p": self.parallelization,
            "klen": self.key_length,
            "i": self.preimage_b64,
            "d": self.difficulty,
            "dl": self.difficulty_level,
        }


@dataclass(slots=True)
class PowBotSolution:
    challenge: PowBotChallenge
    nonce_hex: str
    hash_hex: str
    end_of_hash: str
    attempts: int
    took_ms: int

    @property
    def verify_params(self) -> dict[str, str]:
        return {"challenge": self.challenge.challenge_b64, "nonce": self.nonce_hex}

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge.challenge_b64,
            "nonce": self.nonce_hex,
            "hash": self.hash_hex,
            "endOfHash": self.end_of_hash,
            "difficulty": self.challenge.difficulty,
            "attempts": self.attempts,
        }


def powbot_difficulty_hex(difficulty_level: int) -> str:
    """Reproduce upstream difficulty threshold construction.

    The server creates ceil(difficultyLevel/8) bytes where unused high-order
    search-space bits are set to 1. Verification compares the trailing hex
    bytes of scrypt(password=nonce, salt=preimage) lexicographically against
    this threshold. This gives an average search space of 2**difficultyLevel.
    """

    dl = int(difficulty_level)
    if dl < 0:
        raise ValueError("difficulty_level must be >= 0")
    out = bytearray(math.ceil(dl / 8) or 1)
    for j in range(len(out)):
        b = 0
        for k in range(8):
            current_bit_index = j * 8 + (7 - k)
            if current_bit_index + 1 > dl:
                b |= 1 << k
        out[j] = b
    return out.hex()


def powbot_scrypt_hash_hex(challenge: PowBotChallenge | dict[str, Any] | str, nonce_hex: str | int) -> str:
    item = parse_powbot_challenge(challenge)
    nonce = _nonce_bytes(nonce_hex)
    return hashlib.scrypt(
        nonce,
        salt=item.preimage_bytes,
        n=item.cpu_and_memory_cost,
        r=item.block_size,
        p=item.parallelization,
        dklen=item.key_length,
    ).hex()


def powbot_nonce_hex(nonce: int | str) -> str:
    if isinstance(nonce, str):
        text = nonce.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        if not text:
            raise ValueError("nonce hex is empty")
        if len(text) % 2:
            text = "0" + text
        int(text, 16)
        return text
    value = int(nonce)
    if value < 0:
        raise ValueError("nonce must be >= 0")
    text = format(value, "x")
    return "0" + text if len(text) % 2 else text


def parse_powbot_challenge(value: PowBotChallenge | dict[str, Any] | str, *, index: int = DEFAULT_BATCH_INDEX) -> PowBotChallenge:
    if isinstance(value, PowBotChallenge):
        return value
    challenge_b64: str | None = None
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8").strip()
        if text.startswith("["):
            arr = json.loads(text)
            if not isinstance(arr, list) or not arr:
                raise ValueError("PoW Bot Deterrent challenge array is empty")
            text = str(arr[int(index)])
        if text.startswith("{"):
            obj = json.loads(text)
        else:
            challenge_b64 = text
            obj = json.loads(base64.b64decode(challenge_b64, validate=True).decode("utf-8"))
    else:
        obj = dict(value)
        if isinstance(obj.get("challenges"), list):
            arr = obj["challenges"]
            if not arr:
                raise ValueError("PoW Bot Deterrent challenges array is empty")
            return parse_powbot_challenge(str(arr[int(index)]), index=0)
        if isinstance(obj.get("challenge"), str) and not any(k in obj for k in ("N", "r", "p", "klen", "i", "d", "dl")):
            return parse_powbot_challenge(str(obj["challenge"]), index=0)
        challenge_b64 = obj.get("challenge_b64") or obj.get("challengeBase64")

    data = _normalize_challenge_obj(obj)
    if challenge_b64 is None:
        challenge_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii")
    item = PowBotChallenge(
        challenge_b64=str(challenge_b64),
        cpu_and_memory_cost=int(data["N"]),
        block_size=int(data["r"]),
        parallelization=int(data["p"]),
        key_length=int(data["klen"]),
        preimage_b64=str(data["i"]),
        difficulty=str(data["d"]).lower(),
        difficulty_level=int(data["dl"]),
    )
    if item.cpu_and_memory_cost < 2 or item.cpu_and_memory_cost & (item.cpu_and_memory_cost - 1):
        raise ValueError("PoW Bot Deterrent N must be a power of two >= 2")
    if item.block_size < 1 or item.parallelization < 1 or item.key_length < 1:
        raise ValueError("PoW Bot Deterrent r/p/klen must be positive")
    if item.difficulty_level < 0:
        raise ValueError("PoW Bot Deterrent difficulty level must be >= 0")
    if not item.difficulty:
        raise ValueError("PoW Bot Deterrent difficulty threshold is required")
    item.preimage_bytes
    return item


def solve_powbot_challenge(
    challenge: PowBotChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PowBotSolution | None:
    item = parse_powbot_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = DEFAULT_MAX_ATTEMPTS if max_attempts is None else max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 128:
        nonce_hex, hash_hex, end_of_hash, checked = _solve_powbot_range(item, start, start + max_attempts, deadline)
        if nonce_hex is None or hash_hex is None or end_of_hash is None:
            return None
        return PowBotSolution(
            challenge=item,
            nonce_hex=nonce_hex,
            hash_hex=hash_hex,
            end_of_hash=end_of_hash,
            attempts=checked,
            took_ms=int((time.monotonic() - started) * 1000),
        )

    chunk = math.ceil(max_attempts / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_powbot_range, item, lo, hi, deadline)] = idx

    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce_hex, hash_hex, end_of_hash, checked = fut.result()
            checked_total += checked
            if nonce_hex is not None and hash_hex is not None and end_of_hash is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return PowBotSolution(
                    challenge=item,
                    nonce_hex=nonce_hex,
                    hash_hex=hash_hex,
                    end_of_hash=end_of_hash,
                    attempts=checked_total,
                    took_ms=int((time.monotonic() - started) * 1000),
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


def verify_powbot_solution(
    challenge: PowBotChallenge | dict[str, Any] | str,
    solution: PowBotSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_powbot_challenge(challenge)
        if isinstance(solution, PowBotSolution):
            nonce_hex = solution.nonce_hex
            hash_hex = solution.hash_hex
        elif isinstance(solution, dict):
            nonce_hex = str(solution.get("nonce") or solution.get("nonceHex") or solution.get("solution") or "")
            hash_hex = str(solution.get("hash") or "") or powbot_scrypt_hash_hex(item, nonce_hex)
        else:
            nonce_hex = powbot_nonce_hex(solution)
            hash_hex = powbot_scrypt_hash_hex(item, nonce_hex)
        end = hash_hex[-len(item.difficulty) :]
        return end <= item.difficulty
    except Exception:
        return False


def _solve_powbot_range(
    item: PowBotChallenge,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[str | None, str | None, str | None, int]:
    preimage = item.preimage_bytes
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 16 == 0 and time.monotonic() >= deadline:
            return None, None, None, checked
        nonce_hex = powbot_nonce_hex(nonce)
        hash_hex = hashlib.scrypt(
            bytes.fromhex(nonce_hex),
            salt=preimage,
            n=item.cpu_and_memory_cost,
            r=item.block_size,
            p=item.parallelization,
            dklen=item.key_length,
        ).hex()
        checked += 1
        end = hash_hex[-len(item.difficulty) :]
        if end <= item.difficulty:
            return nonce_hex, hash_hex, end, checked
    return None, None, None, checked


def _normalize_challenge_obj(obj: dict[str, Any]) -> dict[str, Any]:
    data = dict(obj)
    mapping = {
        "cpuAndMemoryCost": "N",
        "CPUAndMemoryCost": "N",
        "blockSize": "r",
        "parallelization": "p",
        "paralellization": "p",
        "keyLength": "klen",
        "preimage": "i",
        "difficulty": "d",
        "difficultyLevel": "dl",
    }
    for old, new in mapping.items():
        if old in data and new not in data:
            data[new] = data[old]
    required = ("N", "r", "p", "klen", "i", "d", "dl")
    missing = [k for k in required if data.get(k) in (None, "")]
    if missing:
        raise ValueError(f"PoW Bot Deterrent challenge missing fields: {', '.join(missing)}")
    return {k: data[k] for k in required}


def _nonce_bytes(nonce_hex: str | int) -> bytes:
    return bytes.fromhex(powbot_nonce_hex(nonce_hex))


def _load_json_arg(value: Any = None, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        if text.startswith("{") or text.startswith("["):
            return json.loads(text)
        return text
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8").strip()
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    return text


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, token: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        out.update(headers)
    if token:
        out["Authorization"] = f"Bearer {token}"
    return out


def _derive_challenges_url(base_url: str | None, challenges_url: str | None, difficulty_level: int) -> str | None:
    if challenges_url:
        return challenges_url
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", "GetChallenges?" + urlencode({"difficultyLevel": int(difficulty_level)}))


def _derive_verify_url(base_url: str | None, verify_url: str | None) -> str | None:
    if verify_url:
        return verify_url
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", "Verify")


class PowBotSolver:
    """PoW Bot Deterrent scrypt-WASM protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        challenge: Any = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenges_url: str | None = None,
        verify_url: str | None = None,
        api_token: str | None = None,
        difficulty_level: int = DEFAULT_DIFFICULTY_LEVEL,
        batch_index: int = DEFAULT_BATCH_INDEX,
        submit: bool = False,
        start: int = 0,
        max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenges_url": challenges_url,
            "verify_url": verify_url,
            "difficulty_level": difficulty_level,
            "batch_index": batch_index,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "api_token": "present" if api_token else None,
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
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
                out = output_root / "powbot_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powbot",
                ok=ok,
                captcha_type="scrypt_pow",
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
            request_headers = _merge_headers(headers, api_token)
            challenge_data = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenges_url=_derive_challenges_url(base_url, challenges_url, difficulty_level),
                batch_index=batch_index,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_powbot_challenge(challenge_data, index=batch_index)
            raw["challenge"] = item.to_payload()
            raw["challengeBase64"] = item.challenge_b64
            diagnostics.update(
                {
                    "N": item.cpu_and_memory_cost,
                    "r": item.block_size,
                    "p": item.parallelization,
                    "klen": item.key_length,
                    "difficulty": item.difficulty,
                    "difficulty_level": item.difficulty_level,
                    "preimage_present": bool(item.preimage_b64),
                }
            )
            solution = solve_powbot_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("powbot solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = solution.submit_body
            diagnostics.update(
                {
                    "nonce": solution.nonce_hex,
                    "hash": solution.hash_hex,
                    "end_of_hash": solution.end_of_hash,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url:
                if not api_token:
                    errors.append("submit requested but api_token is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                effective_verify_url = _derive_verify_url(base_url, verify_url)
                if not effective_verify_url:
                    errors.append("submit requested but verify_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_text = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ticket = solution.nonce_hex
                verify_code = "validated"
                diagnostics["submitted"] = True
                raw["verifyText"] = verify_text
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge: Any,
        challenge_json: Any,
        challenge_file: str | None,
        challenges_url: str | None,
        batch_index: int,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        data = challenge if challenge is not None else _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenges_url:
            raise ValueError("powbot requires base_url, challenge, challenge_json, challenge_file or challenges_url")
        resp = requests.post(
            challenges_url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenges_url}
        resp.raise_for_status()
        arr = resp.json()
        if not isinstance(arr, list) or not arr:
            raise ValueError("PoW Bot Deterrent GetChallenges response must be a non-empty array")
        raw["challengeSource"] = "url"
        raw["challengeBatchSize"] = len(arr)
        return str(arr[int(batch_index)])

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: PowBotSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> str:
        sep = "&" if "?" in verify_url else "?"
        url = verify_url + sep + urlencode(solution.verify_params)
        resp = requests.post(
            url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url, "text": resp.text[:500]}
        resp.raise_for_status()
        return resp.text
