from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BASE_URL = "https://hashguard.viento.me"
DEFAULT_ROUTE_PREFIX = "v1"
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 200_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class HashGuardChallenge:
    challenge_id: str
    seed: str
    target: str
    difficulty_bits: int | None = None
    algorithm: str = "sha256"
    issued_at: str | None = None
    expires_at: str | None = None
    context: str | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "challengeId": self.challenge_id,
            "algorithm": self.algorithm,
            "seed": self.seed,
            "target": self.target,
        }
        if self.difficulty_bits is not None:
            out["difficultyBits"] = self.difficulty_bits
        if self.issued_at:
            out["issuedAt"] = self.issued_at
        if self.expires_at:
            out["expiresAt"] = self.expires_at
        if self.context:
            out["context"] = self.context
        return out


@dataclass(slots=True)
class HashGuardSolution:
    challenge: HashGuardChallenge
    nonce: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def verify_body(self) -> dict[str, Any]:
        return build_hashguard_verify_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "challengeId": self.challenge.challenge_id,
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
        }


def hashguard_target_from_difficulty_bits(difficulty_bits: int) -> str:
    bits = int(difficulty_bits)
    if bits < 0 or bits > 256:
        raise ValueError("HashGuard difficultyBits must be between 0 and 256")
    if bits == 0:
        return "f" * 64
    return f"{(1 << (256 - bits)) - 1:064x}"


def hashguard_hash_hex(challenge_id: str, seed: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{challenge_id}:{seed}:{nonce}".encode("utf-8")).hexdigest()


def hashguard_hash_matches_target(hash_hex: str, target_hex: str) -> bool:
    try:
        target = _normalize_target(target_hex)
        digest = _normalize_target(hash_hex)
        return digest <= target
    except Exception:
        return False


def parse_hashguard_challenge(value: HashGuardChallenge | dict[str, Any] | str) -> HashGuardChallenge:
    if isinstance(value, HashGuardChallenge):
        _validate_challenge(value)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("HashGuard challenge is empty")
        if text.startswith("@"):
            return parse_hashguard_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        return parse_hashguard_challenge(json.loads(text))
    if not isinstance(value, dict):
        raise ValueError("HashGuard challenge must be a JSON object")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge_id = data.get("challengeId") or data.get("challenge_id") or data.get("id")
    seed = data.get("seed")
    target = data.get("target") or data.get("targetHex") or data.get("target_hex")
    difficulty_raw = data.get("difficultyBits", data.get("difficulty_bits", data.get("difficulty")))
    if not challenge_id:
        raise ValueError("HashGuard challenge requires challengeId")
    if not seed:
        raise ValueError("HashGuard challenge requires seed")
    difficulty_bits = int(difficulty_raw) if difficulty_raw is not None else None
    if not target:
        if difficulty_bits is None:
            raise ValueError("HashGuard challenge requires target or difficultyBits")
        target = hashguard_target_from_difficulty_bits(difficulty_bits)
    item = HashGuardChallenge(
        challenge_id=str(challenge_id),
        seed=str(seed),
        target=_normalize_target(str(target)),
        difficulty_bits=difficulty_bits,
        algorithm=str(data.get("algorithm") or data.get("algo") or "sha256").lower(),
        issued_at=str(data["issuedAt"]) if data.get("issuedAt") else None,
        expires_at=str(data["expiresAt"]) if data.get("expiresAt") else None,
        context=str(data["context"]) if data.get("context") is not None else None,
    )
    _validate_challenge(item)
    return item


def solve_hashguard_challenge(
    challenge: HashGuardChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> HashGuardSolution | None:
    item = parse_hashguard_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, digest, checked = _solve_hashguard_range(
            item.challenge_id,
            item.seed,
            item.target,
            start,
            start + max_attempts,
            deadline_epoch,
        )
        if nonce is None or digest is None:
            return None
        return HashGuardSolution(
            challenge=item,
            nonce=str(nonce),
            hash_hex=digest,
            attempts=checked,
            solve_time_ms=int((time.monotonic() - started) * 1000),
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
        futures[pool.submit(_solve_hashguard_range, item.challenge_id, item.seed, item.target, lo, hi, deadline_epoch)] = idx

    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, checked = fut.result()
            checked_total += checked
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return HashGuardSolution(
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


def verify_hashguard_solution(
    challenge: HashGuardChallenge | dict[str, Any] | str,
    solution: HashGuardSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_hashguard_challenge(challenge)
        expected_hash = ""
        if isinstance(solution, HashGuardSolution):
            nonce = solution.nonce
            expected_hash = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = str(solution.get("nonce", solution.get("solution")))
            expected_hash = str(solution.get("hash") or solution.get("hashHex") or "")
        else:
            nonce = str(int(solution))
        if nonce.startswith("-"):
            return False
        digest = hashguard_hash_hex(item.challenge_id, item.seed, nonce)
        if expected_hash and digest.lower() != expected_hash.lower():
            return False
        return hashguard_hash_matches_target(digest, item.target)
    except Exception:
        return False


def build_hashguard_verify_body(
    challenge: HashGuardChallenge | dict[str, Any] | str,
    solution: HashGuardSolution | dict[str, Any] | int | str,
    *,
    solve_time_ms: int | None = None,
) -> dict[str, Any]:
    item = parse_hashguard_challenge(challenge)
    if isinstance(solution, HashGuardSolution):
        nonce = solution.nonce
        took = solution.solve_time_ms
    elif isinstance(solution, dict):
        nonce = str(solution.get("nonce", solution.get("solution")))
        took = int(solution.get("solveTimeMs", solution.get("solve_time_ms", 0)) or 0)
    else:
        nonce = str(int(solution))
        took = 0
    body: dict[str, Any] = {"challengeId": item.challenge_id, "nonce": nonce}
    effective_time = solve_time_ms if solve_time_ms is not None else took
    if effective_time is not None and int(effective_time) >= 0:
        body["clientMetrics"] = {"solveTimeMs": int(effective_time)}
    return body


def _solve_hashguard_range(
    challenge_id: str,
    seed: str,
    target_hex: str,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    target_int = int(_normalize_target(target_hex), 16)
    prefix = f"{challenge_id}:{seed}:".encode("utf-8")
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest_bytes = hashlib.sha256(prefix + str(nonce).encode("ascii")).digest()
        checked += 1
        if int.from_bytes(digest_bytes, "big") <= target_int:
            return nonce, digest_bytes.hex(), checked
    return None, None, checked


def _normalize_target(value: str) -> str:
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) > 64:
        raise ValueError("HashGuard target/hash must be <= 64 hex chars")
    text = text.rjust(64, "0")
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("HashGuard target/hash must be 64 hex chars")
    return text


def _validate_challenge(item: HashGuardChallenge) -> None:
    if item.algorithm.lower() not in {"sha256", "sha-256"}:
        raise ValueError(f"unsupported HashGuard algorithm: {item.algorithm}")
    if not item.challenge_id:
        raise ValueError("HashGuard challengeId is empty")
    if not item.seed:
        raise ValueError("HashGuard seed is empty")
    _normalize_target(item.target)
    if item.difficulty_bits is not None and not 0 <= int(item.difficulty_bits) <= 256:
        raise ValueError("HashGuard difficultyBits must be between 0 and 256")


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


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


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


def _derive_endpoint(
    base_url: str | None,
    route_prefix: str | None,
    explicit: str | None,
    path: str,
) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    prefix = (route_prefix or "").strip("/")
    suffix = f"{prefix}/{path.lstrip('/')}" if prefix else path.lstrip("/")
    return urljoin(base_url.rstrip("/") + "/", suffix)


def _extract_proof_token(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None
    for key in ("proofToken", "proof_token", "token", "jwt"):
        if data.get(key):
            return str(data[key])
    return None


class HashGuardSolver:
    """HashGuard target-threshold SHA-256 PoW + JWT proof-token protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = DEFAULT_BASE_URL,
        route_prefix: str = DEFAULT_ROUTE_PREFIX,
        context: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        introspect_url: str | None = None,
        submit: bool = False,
        introspect: bool = False,
        consume: bool = True,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        min_solve_ms: int = 0,
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
            "route_prefix": route_prefix,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "introspect_url": introspect_url,
            "context": context,
            "submit": submit,
            "introspect": introspect,
            "proxy": redacted_proxy(proxy_server),
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
                out = output_root / "hashguard_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="hashguard",
                ok=ok,
                captcha_type="jwt_proof_pow",
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
                context=context,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_endpoint(base_url, route_prefix, challenge_url, "/pow/challenges"),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_hashguard_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "difficulty_bits": item.difficulty_bits,
                    "target_prefix": item.target[:16],
                }
            )
            solution = solve_hashguard_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("HashGuard solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            reported_solve_ms = max(int(solution.solve_time_ms), int(min_solve_ms))
            verify_body = build_hashguard_verify_body(item, solution, solve_time_ms=reported_solve_ms)
            raw["solution"] = {**solution.to_payload(), "verifyBody": verify_body}
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash_hex": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                    "reported_solve_ms": reported_solve_ms,
                }
            )
            ticket = _json_body(verify_body)
            verify_code = "solved"
            proof_token: str | None = None
            if submit or verify_url:
                effective_verify_url = _derive_endpoint(base_url, route_prefix, verify_url, "/pow/verifications")
                if not effective_verify_url:
                    errors.append("submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_verification(
                    verify_url=effective_verify_url,
                    verify_body=verify_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                proof_token = _extract_proof_token(verify_data)
                if not proof_token:
                    reason = verify_data.get("message") if isinstance(verify_data, dict) else "verify_failed"
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = proof_token
                verify_code = "validated"
                diagnostics["submitted"] = True
                diagnostics["proof_token_present"] = True
            if introspect:
                if not proof_token:
                    errors.append("HashGuard introspect requires proof token from verify")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                effective_introspect_url = _derive_endpoint(
                    base_url,
                    route_prefix,
                    introspect_url,
                    "/pow/assertions/introspect",
                )
                if not effective_introspect_url:
                    errors.append("introspect requested but introspect_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                introspect_data = self._introspect_token(
                    introspect_url=effective_introspect_url,
                    proof_token=proof_token,
                    consume=consume,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = isinstance(introspect_data, dict) and introspect_data.get("valid") is True
                if not ok:
                    reason = introspect_data.get("error") if isinstance(introspect_data, dict) else "introspect_failed"
                    errors.append(str(reason or "introspect_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="introspect_failed")
                verify_code = "introspected"
                diagnostics["introspected"] = True
                if isinstance(introspect_data, dict):
                    diagnostics["token_context"] = introspect_data.get("context")
                    diagnostics["token_subject_present"] = bool(introspect_data.get("subject"))
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        context: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("HashGuard requires challenge_json, challenge_file, challenge_url or base_url")
        body: dict[str, Any] = {"context": context} if context else {}
        resp = requests.post(
            challenge_url,
            data=_json_body(body),
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

    def _submit_verification(
        self,
        *,
        verify_url: str,
        verify_body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            data=_json_body(verify_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = payload
        return payload

    def _introspect_token(
        self,
        *,
        introspect_url: str,
        proof_token: str,
        consume: bool,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            introspect_url,
            data=_json_body({"proofToken": proof_token, "consume": bool(consume)}),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["introspectResponse"] = {"status": resp.status_code, "url": introspect_url}
        try:
            payload = resp.json()
        except ValueError:
            payload = {"text": resp.text[:500]}
        raw["introspectResponse"]["json"] = payload
        return payload
