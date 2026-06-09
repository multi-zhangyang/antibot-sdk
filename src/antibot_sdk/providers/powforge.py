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

DEFAULT_BASE_URL = "https://captcha.powforge.dev"
DEFAULT_ALGO = "sha256"
DEFAULT_DIFFICULTY = 16
DEFAULT_RESPONSE_FIELD = "pf_token"
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class PowForgeChallenge:
    salt: str
    difficulty: int = DEFAULT_DIFFICULTY
    algo: str = DEFAULT_ALGO
    signature: str | None = None
    challenge: str | None = None
    challenge_id: str | None = None
    response_field: str = DEFAULT_RESPONSE_FIELD
    raw: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "salt": self.salt,
            "difficulty": self.difficulty,
            "algo": self.algo,
            "responseField": self.response_field,
        }
        if self.signature:
            out["signature"] = self.signature
        if self.challenge:
            out["challenge"] = self.challenge
        if self.challenge_id:
            out["id"] = self.challenge_id
        return out


@dataclass(slots=True)
class PowForgeSolution:
    challenge: PowForgeChallenge
    nonce: str
    hash_hex: str
    attempts: int
    solve_time_ms: int
    token: str | None = None
    verified: bool = False
    method: str | None = None

    @property
    def verify_body(self) -> dict[str, Any]:
        return build_powforge_verify_body(self.challenge, self)

    @property
    def submit_body(self) -> dict[str, str]:
        return build_powforge_submit_body(self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "verified": self.verified,
            "method": self.method,
            "token": self.token,
            "verifyBody": self.verify_body,
            "submitBody": self.submit_body,
        }


def powforge_hash_hex(salt: str, nonce: int | str) -> str:
    return hashlib.sha256(f"{salt}{nonce}".encode("utf-8")).hexdigest()


def count_leading_zero_bits_hex(hex_digest: str) -> int:
    total = 0
    for ch in str(hex_digest).lower():
        val = int(ch, 16)
        if val == 0:
            total += 4
            continue
        return total + (4 - val.bit_length())
    return total


def powforge_hash_matches(hex_digest: str, difficulty: int) -> bool:
    return count_leading_zero_bits_hex(hex_digest) >= int(difficulty)


def parse_powforge_challenge(
    value: PowForgeChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    response_field: str | None = None,
) -> PowForgeChallenge:
    if isinstance(value, PowForgeChallenge):
        if difficulty is not None:
            value.difficulty = int(difficulty)
        if response_field:
            value.response_field = response_field
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("PowForge challenge is empty")
        if text.startswith("@"):
            return parse_powforge_challenge(
                Path(text[1:]).read_text(encoding="utf-8"), difficulty=difficulty, response_field=response_field
            )
        if text.startswith("{"):
            return parse_powforge_challenge(json.loads(text), difficulty=difficulty, response_field=response_field)
        return parse_powforge_challenge({"salt": text}, difficulty=difficulty, response_field=response_field)
    if not isinstance(value, dict):
        raise ValueError("PowForge challenge must be string, JSON object, or PowForgeChallenge")

    data = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    salt = _first_str(data, "salt", "challenge", "prefix")
    if not salt:
        raise ValueError("PowForge challenge requires salt/challenge/prefix")
    diff = int(difficulty if difficulty is not None else data.get("difficulty", data.get("bits", DEFAULT_DIFFICULTY)))
    if not 1 <= diff <= 63:
        raise ValueError("PowForge difficulty must be 1..63 leading zero bits")
    algo = str(data.get("algo") or data.get("algorithm") or DEFAULT_ALGO).lower()
    if algo != DEFAULT_ALGO:
        raise ValueError("PowForge currently supports sha256 only")
    return PowForgeChallenge(
        salt=str(salt),
        difficulty=diff,
        algo=algo,
        signature=_first_str(data, "signature", "sig"),
        challenge=_first_str(data, "challenge") if _first_str(data, "challenge") != salt else None,
        challenge_id=_first_str(data, "id", "challengeId", "challenge_id"),
        response_field=response_field or _first_str(data, "responseField", "response_field", "field", "name") or DEFAULT_RESPONSE_FIELD,
        raw=value,
    )


def solve_powforge_challenge(
    challenge: PowForgeChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PowForgeSolution | None:
    item = parse_powforge_challenge(challenge, difficulty=difficulty)
    started = time.monotonic()
    start = max(1, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None

    counter, digest, checked = solve_powforge_counter(
        item.salt,
        difficulty=item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        deadline_epoch=deadline_epoch,
    )
    if counter is None or digest is None:
        return None
    return PowForgeSolution(
        challenge=item,
        nonce=str(counter),
        hash_hex=digest,
        attempts=checked,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def solve_powforge_counter(
    salt: str,
    *,
    difficulty: int,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    start = max(1, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if workers <= 1 or max_attempts < 100_000:
        return _solve_powforge_range(str(salt), int(difficulty), start, start + max_attempts, deadline_epoch)

    chunk = math.ceil(max_attempts / workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    completed: dict[int, tuple[int | None, str | None, int]] = {}
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {pool.submit(_solve_powforge_range, str(salt), int(difficulty), lo, hi, deadline_epoch): idx for idx, (lo, hi) in enumerate(ranges)}
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
                p_counter, p_digest, _ = completed[prior_idx]
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


def verify_powforge_solution(
    challenge: PowForgeChallenge | dict[str, Any] | str,
    solution: PowForgeSolution | dict[str, Any] | int | str,
    *,
    difficulty: int | None = None,
) -> bool:
    try:
        item = parse_powforge_challenge(challenge, difficulty=difficulty)
        if isinstance(solution, PowForgeSolution):
            nonce = solution.nonce
            digest = solution.hash_hex
        elif isinstance(solution, dict):
            nonce = str(solution.get("nonce", solution.get("solution", "")))
            digest = str(solution.get("hash") or powforge_hash_hex(item.salt, nonce))
        else:
            nonce = str(solution)
            digest = powforge_hash_hex(item.salt, nonce)
        if not nonce or not str(nonce).isdigit() or int(nonce) < 1:
            return False
        expected = powforge_hash_hex(item.salt, nonce)
        return expected == digest.lower() and powforge_hash_matches(expected, item.difficulty)
    except Exception:
        return False


def build_powforge_verify_body(
    challenge: PowForgeChallenge | dict[str, Any] | str,
    solution: PowForgeSolution | dict[str, Any] | int | str,
) -> dict[str, Any]:
    item = parse_powforge_challenge(challenge)
    if isinstance(solution, PowForgeSolution):
        nonce = solution.nonce
    elif isinstance(solution, dict):
        nonce = str(solution.get("nonce", solution.get("solution", "")))
    else:
        nonce = str(solution)
    body: dict[str, Any] = {
        "salt": item.salt,
        "nonce": nonce,
        "signature": item.signature,
        "algo": item.algo,
        "difficulty": item.difficulty,
        "id": item.challenge_id,
    }
    if item.challenge is not None:
        body["challenge"] = item.challenge
    else:
        body["challenge"] = None
    return body


def build_powforge_submit_body(solution: PowForgeSolution | dict[str, Any] | str, *, response_field: str | None = None) -> dict[str, str]:
    if isinstance(solution, PowForgeSolution):
        key = response_field or solution.challenge.response_field
        value = solution.token or solution.nonce
    elif isinstance(solution, dict):
        key = response_field or str(solution.get("responseField") or solution.get("response_field") or DEFAULT_RESPONSE_FIELD)
        value = str(solution.get("token") or solution.get("nonce") or "")
    else:
        key = response_field or DEFAULT_RESPONSE_FIELD
        value = str(solution)
    return {key: value}


class PowForgeSolver:
    """PowForge CAPTCHA protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        token_verify_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        salt: str | None = None,
        difficulty: int | None = None,
        response_field: str | None = None,
        submit: bool = True,
        token_verify: bool = False,
        start: int = 1,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        base = (base_url or DEFAULT_BASE_URL).rstrip("/")
        challenge_url = challenge_url or urljoin(base + "/", "api/challenge")
        verify_url = verify_url or urljoin(base + "/", "api/verify")
        token_verify_url = token_verify_url or urljoin(base + "/", "api/token/verify")
        diagnostics: dict[str, Any] = {
            "base_url": base,
            "challenge_url": challenge_url,
            "verify_url": verify_url if submit else None,
            "token_verify_url": token_verify_url if token_verify else None,
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
                out = output_root / "powforge_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="powforge",
                ok=ok,
                captcha_type="signed_sha256_pow_token",
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
                salt=salt,
                difficulty=difficulty,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            item = parse_powforge_challenge(source, difficulty=difficulty, response_field=response_field)
            raw["challenge"] = item.to_payload()
            diagnostics.update({"salt": item.salt, "difficulty": item.difficulty, "algo": item.algo, "response_field": item.response_field})
            solution = solve_powforge_challenge(item, start=start, max_attempts=max_attempts, workers=workers, timeout_sec=timeout_sec)
            if solution is None:
                errors.append("PowForge solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_powforge_solution(item, solution):
                errors.append("PowForge internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            diagnostics.update({"nonce": solution.nonce, "hash": solution.hash_hex, "attempts": solution.attempts, "solve_ms": solution.solve_time_ms})

            if submit:
                resp = _post_json(verify_url, solution.verify_body, headers=_merge_headers(headers, user_agent), timeout_sec=timeout_sec, proxy_server=proxy_server)
                raw["verifyResponse"] = resp
                if not resp.get("ok") or not isinstance(resp.get("body"), dict) or not resp["body"].get("valid") or not resp["body"].get("token"):
                    errors.append(f"PowForge verify failed: HTTP {resp.get('status')}")
                    raw["solution"] = solution.to_payload()
                    return finish(ok=False, ticket=_json_body(solution.verify_body), verify_code="submit_failed")
                body = resp["body"]
                solution.token = str(body.get("token"))
                solution.verified = True
                solution.method = str(body.get("method") or item.algo)
                diagnostics.update({"token_present": True, "method": solution.method})
                if token_verify:
                    token_resp = _post_json(token_verify_url, {"token": solution.token}, headers=_merge_headers(headers, user_agent), timeout_sec=timeout_sec, proxy_server=proxy_server)
                    raw["tokenVerifyResponse"] = token_resp
                    if not token_resp.get("ok") or not isinstance(token_resp.get("body"), dict) or not token_resp["body"].get("valid"):
                        errors.append(f"PowForge token verify failed: HTTP {token_resp.get('status')}")
                        raw["solution"] = solution.to_payload()
                        return finish(ok=False, ticket=_json_body(solution.submit_body), verify_code="token_verify_failed")
                    diagnostics["token_verified"] = True
                raw["solution"] = solution.to_payload()
                return finish(ok=True, ticket=_json_body(solution.submit_body), verify_code="validated")

            raw["solution"] = solution.to_payload()
            return finish(ok=True, ticket=_json_body(solution.verify_body), verify_code="solved")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_powforge_range(salt: str, difficulty: int, start: int, end_exclusive: int, deadline_epoch: float | None = None) -> tuple[int | None, str | None, int]:
    checked = 0
    target_bits = int(difficulty)
    for nonce in range(max(1, int(start)), max(1, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = powforge_hash_hex(salt, nonce)
        checked += 1
        if powforge_hash_matches(digest, target_bits):
            return nonce, digest, checked
    return None, None, checked


def _load_source(
    *,
    salt: str | None,
    difficulty: int | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_url: str,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if salt:
        raw["challengeSource"] = "salt"
        return {"salt": salt, "difficulty": difficulty or DEFAULT_DIFFICULTY}
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    resp = requests.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "contentType": resp.headers.get("Content-Type", "")}
    resp.raise_for_status()
    payload = resp.json()
    raw["challengeResponse"]["json"] = payload
    raw["challengeSource"] = "url_json"
    return payload


def _post_json(url: str, body: dict[str, Any], *, headers: dict[str, str], timeout_sec: int, proxy_server: str | None) -> dict[str, Any]:
    resp = requests.post(url, json=body, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    try:
        data: Any = resp.json()
    except Exception:
        data = resp.text[:500]
    return {"ok": 200 <= resp.status_code < 400 and not (isinstance(data, dict) and data.get("valid") is False), "status": resp.status_code, "body": data}


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


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {"User-Agent": user_agent or DEFAULT_USER_AGENT, "Accept": "application/json, text/html, */*", "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        out.update(headers)
    return out


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
