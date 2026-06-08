from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS_PER_ROUND = 50_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class PowReactionChallenge:
    token: str
    challenge_id: str
    reaction: str
    difficulty: int
    exp: int
    client_id: str
    rounds: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.challenge_id,
            "reaction": self.reaction,
            "difficulty": self.difficulty,
            "exp": self.exp,
            "clientId": self.client_id,
            "rounds": list(self.rounds),
        }


@dataclass(slots=True)
class PowReactionSolution:
    challenge: PowReactionChallenge
    solutions: list[int]
    hashes: list[str]
    leading_zero_bits: list[int]
    attempts: int
    took_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge.token,
            "solutions": list(self.solutions),
            "reaction": self.challenge.reaction,
        }


def count_leading_zero_bits(data: bytes) -> int:
    count = 0
    for byte in data:
        if byte == 0:
            count += 8
            continue
        for bit in range(7, -1, -1):
            if ((byte >> bit) & 1) == 0:
                count += 1
            else:
                return count
        return count
    return count


def powreaction_hash_bytes(round_id: str, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{round_id}.{int(nonce)}".encode("utf-8")).digest()


def powreaction_hash_hex(round_id: str, nonce: int | str) -> str:
    return powreaction_hash_bytes(round_id, nonce).hex()


def parse_powreaction_challenge(value: PowReactionChallenge | dict[str, Any] | str) -> PowReactionChallenge:
    if isinstance(value, PowReactionChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("pow-reaction challenge is empty")
        if text.startswith("@"):
            return parse_powreaction_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if text.startswith("{"):
            return parse_powreaction_challenge(json.loads(text))
        token = text
    elif isinstance(value, dict):
        token = str(value.get("challenge") or value.get("token") or value.get("jwt") or "")
        if not token and all(k in value for k in ("id", "reaction", "difficulty", "rounds")):
            # Raw decoded payload fixture. Useful for local solving where no JWT is available.
            token = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            return _challenge_from_payload(token, value)
        if not token:
            raise ValueError("pow-reaction challenge object requires challenge/token")
    else:
        raise ValueError("pow-reaction challenge must be a JWT string or object")

    payload = _decode_jwt_payload(token)
    return _challenge_from_payload(token, payload)


def sign_powreaction_payload(payload: dict[str, Any], secret: bytes | str) -> str:
    """HS256 signer compatible with pow-reaction's @oslojs/jwt helper."""

    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_no_pad(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_no_pad(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_no_pad(sig)}"


def verify_powreaction_jwt(token: str, secret: bytes | str, *, now: int | None = None) -> bool:
    try:
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        header_b64, payload_b64, sig_b64 = token.split(".", 2)
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "HS256":
            return False
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
        got = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, got):
            return False
        payload = json.loads(_b64url_decode(payload_b64))
        exp = int(payload.get("exp") or 0)
        return not exp or exp >= int(now or time.time())
    except Exception:
        return False


def solve_powreaction_challenge(
    challenge: PowReactionChallenge | dict[str, Any] | str,
    *,
    max_attempts_per_round: int = DEFAULT_MAX_ATTEMPTS_PER_ROUND,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PowReactionSolution | None:
    item = parse_powreaction_challenge(challenge)
    started = time.monotonic()
    if not item.rounds:
        raise ValueError("pow-reaction challenge requires at least one round")
    max_attempts_per_round = max(1, int(max_attempts_per_round))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or len(item.rounds) == 1:
        solutions: list[int] = []
        hashes: list[str] = []
        lz_bits: list[int] = []
        attempts_total = 0
        for idx, round_id in enumerate(item.rounds):
            result = _solve_powreaction_round(
                idx,
                round_id,
                item.difficulty,
                max_attempts_per_round,
                deadline_epoch,
            )
            if result[1] is None or result[2] is None:
                return None
            _, nonce, digest_hex, lz, attempts = result
            solutions.append(nonce)
            hashes.append(digest_hex)
            lz_bits.append(lz)
            attempts_total += attempts
        return PowReactionSolution(
            challenge=item,
            solutions=solutions,
            hashes=hashes,
            leading_zero_bits=lz_bits,
            attempts=attempts_total,
            took_ms=int((time.monotonic() - started) * 1000),
        )

    solutions_out: list[int | None] = [None] * len(item.rounds)
    hashes_out: list[str | None] = [None] * len(item.rounds)
    lz_out: list[int | None] = [None] * len(item.rounds)
    attempts_total = 0
    max_workers = min(workers, len(item.rounds))
    pool = ProcessPoolExecutor(max_workers=max_workers)
    futures = {
        pool.submit(
            _solve_powreaction_round,
            idx,
            round_id,
            item.difficulty,
            max_attempts_per_round,
            deadline_epoch,
        ): idx
        for idx, round_id in enumerate(item.rounds)
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx, nonce, digest_hex, lz, attempts = fut.result()
            attempts_total += attempts
            if nonce is None or digest_hex is None or lz is None:
                pool.shutdown(wait=False, cancel_futures=True)
                return None
            solutions_out[idx] = nonce
            hashes_out[idx] = digest_hex
            lz_out[idx] = lz
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if any(x is None for x in solutions_out) or any(x is None for x in hashes_out):
        return None
    return PowReactionSolution(
        challenge=item,
        solutions=[int(x) for x in solutions_out if x is not None],
        hashes=[str(x) for x in hashes_out if x is not None],
        leading_zero_bits=[int(x) for x in lz_out if x is not None],
        attempts=attempts_total,
        took_ms=int((time.monotonic() - started) * 1000),
    )


def verify_powreaction_solution(
    challenge: PowReactionChallenge | dict[str, Any] | str,
    solution: PowReactionSolution | dict[str, Any] | list[int],
) -> bool:
    try:
        item = parse_powreaction_challenge(challenge)
        if isinstance(solution, PowReactionSolution):
            solutions = solution.solutions
        elif isinstance(solution, dict):
            solutions = [int(x) for x in solution.get("solutions", [])]
        else:
            solutions = [int(x) for x in solution]
        if len(solutions) != len(item.rounds):
            return False
        if any(n < 0 for n in solutions):
            return False
        for round_id, nonce in zip(item.rounds, solutions):
            digest = powreaction_hash_bytes(round_id, nonce)
            if count_leading_zero_bits(digest) < item.difficulty:
                return False
        return True
    except Exception:
        return False


def _solve_powreaction_round(
    idx: int,
    round_id: str,
    difficulty: int,
    max_attempts: int,
    deadline_epoch: float | None = None,
) -> tuple[int, int | None, str | None, int | None, int]:
    prefix = f"{round_id}.".encode("utf-8")
    attempts = 0
    for nonce in range(max(1, math.floor(max_attempts))):
        if deadline_epoch is not None and attempts and attempts % 4096 == 0 and time.time() >= deadline_epoch:
            return idx, None, None, None, attempts
        digest = hashlib.sha256(prefix + str(nonce).encode("ascii")).digest()
        attempts += 1
        lz = count_leading_zero_bits(digest)
        if lz >= difficulty:
            return idx, nonce, digest.hex(), lz, attempts
    return idx, None, None, None, attempts


def _challenge_from_payload(token: str, payload: dict[str, Any]) -> PowReactionChallenge:
    rounds = [str(x) for x in payload.get("rounds") or []]
    if not rounds:
        raise ValueError("pow-reaction payload requires rounds")
    challenge_id = str(payload.get("id") or "")
    reaction = str(payload.get("reaction") or "")
    client_id = str(payload.get("clientId") or payload.get("client_id") or "")
    if not challenge_id:
        raise ValueError("pow-reaction payload requires id")
    if not reaction:
        raise ValueError("pow-reaction payload requires reaction")
    difficulty = int(payload.get("difficulty"))
    if difficulty < 0 or difficulty > 256:
        raise ValueError("pow-reaction difficulty must be between 0 and 256")
    return PowReactionChallenge(
        token=token,
        challenge_id=challenge_id,
        reaction=reaction,
        difficulty=difficulty,
        exp=int(payload.get("exp") or 0),
        client_id=client_id,
        rounds=rounds,
    )


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        # Accept raw payload JSON as a fixture-only fallback.
        try:
            payload = json.loads(token)
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass
        raise ValueError("pow-reaction challenge must be a JWT with three parts")
    payload = json.loads(_b64url_decode(parts[1]))
    if not isinstance(payload, dict):
        raise ValueError("pow-reaction JWT payload must be an object")
    return payload


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url_no_pad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


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
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    return text


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _derive_url(base_url: str | None, explicit: str | None, suffix: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    if not suffix:
        return base_url.rstrip("/")
    return urljoin(base_url.rstrip("/") + "/", suffix.lstrip("/"))


class PowReactionSolver:
    """pow-reaction signed multi-round proof-of-work protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        reaction: str | None = None,
        submit: bool = False,
        secret: str | None = None,
        max_attempts_per_round: int = DEFAULT_MAX_ATTEMPTS_PER_ROUND,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "submit_url": submit_url,
            "reaction": reaction,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_round": max_attempts_per_round,
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
                out = output_root / "powreaction_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powreaction",
                ok=ok,
                captcha_type="signed_multi_round_pow",
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
            request_headers = _merge_headers(headers, user_agent)
            challenge_data = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_url(base_url, challenge_url, "/challenge"),
                reaction=reaction,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_powreaction_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "reaction": item.reaction,
                    "difficulty": item.difficulty,
                    "rounds": len(item.rounds),
                    "exp": item.exp,
                    "client_id_present": bool(item.client_id),
                }
            )
            if secret is not None:
                diagnostics["signature_valid"] = verify_powreaction_jwt(item.token, secret)
            solution = solve_powreaction_challenge(
                item,
                max_attempts_per_round=max_attempts_per_round,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("pow-reaction solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "solutions": solution.solutions,
                "hashes": solution.hashes,
                "leadingZeroBits": solution.leading_zero_bits,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
                "submitBody": solution.submit_body,
            }
            diagnostics.update(
                {
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                    "min_leading_zero_bits": min(solution.leading_zero_bits),
                    "max_leading_zero_bits": max(solution.leading_zero_bits),
                }
            )
            ticket = _json_body(solution.submit_body)
            verify_code = "solved"
            if submit or submit_url:
                effective_submit_url = _derive_url(base_url, submit_url, "")
                if not effective_submit_url:
                    errors.append("submit requested but submit_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    submit_url=effective_submit_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = isinstance(verify_data, dict) and verify_data.get("success") is True
                if not ok:
                    reason = verify_data.get("error") if isinstance(verify_data, dict) else "verify_failed"
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                verify_code = "validated"
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
        reaction: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        if challenge:
            raw["challengeSource"] = "inline"
            return challenge
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("pow-reaction requires challenge, challenge_json, challenge_file, challenge_url or base_url")
        if not reaction:
            raise ValueError("pow-reaction challenge_url requires reaction")
        resp = requests.post(
            challenge_url,
            data=_json_body({"reaction": reaction}),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        raw["challengeResponse"]["json"] = payload
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return payload

    def _submit_solution(
        self,
        *,
        submit_url: str,
        solution: PowReactionSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            submit_url,
            data=_json_body(solution.submit_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": submit_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        resp.raise_for_status()
        return data
