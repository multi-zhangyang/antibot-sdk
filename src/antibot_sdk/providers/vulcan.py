from __future__ import annotations

import asyncio
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

DEFAULT_ROUNDS = 1
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS_PER_ROUND = 1_000_000_000
DEFAULT_RESPONSE_FIELD = "captcha-response"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class VulcanChallenge:
    challenge: str
    difficulty: int
    rounds: int = DEFAULT_ROUNDS
    response_field: str = DEFAULT_RESPONSE_FIELD
    raw: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "challenge": self.challenge,
            "difficulty": self.difficulty,
            "rounds": self.rounds,
            "responseField": self.response_field,
        }


@dataclass(slots=True)
class VulcanRoundSolution:
    round_index: int
    base: str
    nonce: str
    hash_hex: str
    value: int
    attempts: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "round": self.round_index,
            "base": self.base,
            "nonce": self.nonce,
            "hash": self.hash_hex,
            "value": self.value,
            "attempts": self.attempts,
        }


@dataclass(slots=True)
class VulcanSolution:
    challenge: VulcanChallenge
    nonces: list[str]
    rounds: list[VulcanRoundSolution]
    attempts: int
    solve_time_ms: int

    @property
    def solution(self) -> str:
        return ";".join(self.nonces)

    @property
    def submit_body(self) -> dict[str, Any]:
        return build_vulcan_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "solution": self.solution,
            "nonces": self.nonces,
            "rounds": [r.to_payload() for r in self.rounds],
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def vulcan_hash_bytes(base: str, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{base}{nonce}".encode("utf-8")).digest()


def vulcan_hash_hex(base: str, nonce: int | str) -> str:
    return vulcan_hash_bytes(base, nonce).hex()


def vulcan_hash_value(hash_bytes_or_hex: bytes | str) -> int:
    if isinstance(hash_bytes_or_hex, str):
        data = bytes.fromhex(hash_bytes_or_hex[:8])
    else:
        data = bytes(hash_bytes_or_hex[:4])
    if len(data) < 4:
        raise ValueError("Vulcan hash requires at least 4 bytes")
    return int.from_bytes(data[:4], "big")


def verify_vulcan_round(base: str, nonce: int | str, difficulty: int) -> bool:
    try:
        return vulcan_hash_value(vulcan_hash_bytes(base, nonce)) < int(difficulty)
    except Exception:
        return False


def parse_vulcan_challenge(value: VulcanChallenge | dict[str, Any] | str) -> VulcanChallenge:
    if isinstance(value, VulcanChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Vulcan challenge is empty")
        if text.startswith("@"):
            return parse_vulcan_challenge(Path(text[1:]).read_text(encoding="utf-8"))
        if "<" in text and "captcha-wrapper" in text:
            return parse_vulcan_challenge(extract_vulcan_from_html(text))
        if text.startswith("{"):
            return parse_vulcan_challenge(json.loads(text))
        raise ValueError("Vulcan raw string is ambiguous; pass JSON or HTML with difficulty/rounds")
    if not isinstance(value, dict):
        raise ValueError("Vulcan challenge must be JSON object, HTML, or VulcanChallenge")
    item = value.get("challenge") if isinstance(value.get("challenge"), dict) else value
    challenge = _first_str(item, "challenge", "base", "data")
    if not challenge:
        raise ValueError("Vulcan challenge JSON requires challenge/base")
    difficulty = int(item.get("difficulty", item.get("target", 0)))
    if not 0 < difficulty <= 0xFFFFFFFF:
        raise ValueError("Vulcan difficulty/target must be uint32 in 1..4294967295")
    rounds = int(item.get("originalRounds", item.get("original_rounds", item.get("rounds", DEFAULT_ROUNDS))))
    if not 1 <= rounds <= 10_000:
        raise ValueError("Vulcan rounds must be between 1 and 10000")
    response_field = _first_str(item, "responseField", "response_field") or DEFAULT_RESPONSE_FIELD
    return VulcanChallenge(
        challenge=str(challenge),
        difficulty=difficulty,
        rounds=rounds,
        response_field=response_field,
        raw=value,
    )


def extract_vulcan_from_html(html_text: str) -> dict[str, Any]:
    text = str(html_text)
    m = re.search(r"<div\b(?=[^>]*\bcaptcha-wrapper\b)(?P<attrs>[^>]*)>", text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        raise ValueError("Vulcan HTML does not contain div.captcha-wrapper")
    attrs = m.group("attrs")
    data = _parse_attrs(attrs)
    challenge = data.get("data-challenge")
    difficulty = data.get("data-difficulty")
    rounds = data.get("data-original-rounds") or data.get("data-rounds") or DEFAULT_ROUNDS
    if not challenge or difficulty is None:
        raise ValueError("Vulcan captcha-wrapper requires data-challenge and data-difficulty")
    response_name = _extract_response_field(text) or DEFAULT_RESPONSE_FIELD
    return {"challenge": challenge, "difficulty": int(difficulty), "rounds": int(rounds), "responseField": response_name}


def solve_vulcan_challenge(
    challenge: VulcanChallenge | dict[str, Any] | str,
    *,
    start: int = 1,
    max_attempts_per_round: int = DEFAULT_MAX_ATTEMPTS_PER_ROUND,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> VulcanSolution | None:
    item = parse_vulcan_challenge(challenge)
    started = time.monotonic()
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None
    current_base = item.challenge
    rounds: list[VulcanRoundSolution] = []
    nonces: list[str] = []
    attempts_total = 0
    for idx in range(item.rounds):
        nonce, digest, value, attempts = solve_vulcan_round(
            current_base,
            item.difficulty,
            start=start,
            max_attempts=max_attempts_per_round,
            workers=workers,
            deadline_epoch=deadline_epoch,
        )
        attempts_total += attempts
        if nonce is None or digest is None or value is None:
            return None
        round_solution = VulcanRoundSolution(
            round_index=idx + 1,
            base=current_base,
            nonce=str(nonce),
            hash_hex=digest,
            value=value,
            attempts=attempts,
        )
        rounds.append(round_solution)
        nonces.append(str(nonce))
        current_base += str(nonce)
    return VulcanSolution(
        challenge=item,
        nonces=nonces,
        rounds=rounds,
        attempts=attempts_total,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def solve_vulcan_round(
    base: str,
    difficulty: int,
    *,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS_PER_ROUND,
    workers: int = 1,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int | None, int]:
    start = max(1, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if workers <= 1 or max_attempts < 100_000:
        return _solve_vulcan_range(base, int(difficulty), start, start + max_attempts, deadline_epoch)

    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    completed: dict[int, tuple[int | None, str | None, int | None, int]] = {}
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(_solve_vulcan_range, base, int(difficulty), lo, hi, deadline_epoch): idx
        for idx, (lo, hi) in enumerate(ranges)
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx = futures[fut]
            nonce, digest, value, checked = fut.result()
            completed[idx] = (nonce, digest, value, checked)
            checked_total += checked

            # Preserve the browser/WASM contract: find_single_nonce returns the
            # first decimal counter, not just any valid nonce. A later chunk may
            # finish before an earlier chunk, so only return a candidate after
            # all lower ranges are known to contain no solution.
            best_ready: tuple[int, str, int] | None = None
            for prior_idx in range(len(ranges)):
                if prior_idx not in completed:
                    break
                p_nonce, p_digest, p_value, _p_checked = completed[prior_idx]
                if p_nonce is not None and p_digest is not None and p_value is not None:
                    best_ready = (p_nonce, p_digest, p_value)
                    break
            if best_ready is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return best_ready[0], best_ready[1], best_ready[2], checked_total
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None, None, None, checked_total
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None, None, None, checked_total


def verify_vulcan_solution(
    challenge: VulcanChallenge | dict[str, Any] | str,
    solution: VulcanSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_vulcan_challenge(challenge)
        if isinstance(solution, VulcanSolution):
            nonces = solution.nonces
        elif isinstance(solution, dict):
            if isinstance(solution.get("nonces"), list):
                nonces = [str(x) for x in solution["nonces"]]
            else:
                nonces = str(solution.get("solution") or solution.get(item.response_field) or "").split(";")
        else:
            nonces = str(solution).split(";")
        if len(nonces) != item.rounds or any(not n or not n.isdigit() for n in nonces):
            return False
        current_base = item.challenge
        for nonce in nonces:
            if not verify_vulcan_round(current_base, nonce, item.difficulty):
                return False
            current_base += nonce
        return True
    except Exception:
        return False


def build_vulcan_submit_body(
    challenge: VulcanChallenge | dict[str, Any] | str,
    solution: VulcanSolution | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> dict[str, Any]:
    item = parse_vulcan_challenge(challenge)
    if isinstance(solution, VulcanSolution):
        value = solution.solution
    elif isinstance(solution, dict):
        value = str(solution.get("solution") or solution.get(item.response_field) or "")
    else:
        value = str(solution)
    return {response_field or item.response_field: value}


class VulcanSolver:
    """EduVulcan chained SHA-256 uint32-target PoW protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        start: int = 1,
        max_attempts_per_round: int = DEFAULT_MAX_ATTEMPTS_PER_ROUND,
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
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_round": max_attempts_per_round,
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
                out = output_root / "vulcan_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="vulcan",
                ok=ok,
                captcha_type="chained_sha256_uint32_pow",
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
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            challenge = parse_vulcan_challenge(source)
            if response_field:
                challenge.response_field = response_field
            raw["challenge"] = challenge.to_payload()
            diagnostics.update({"difficulty": challenge.difficulty, "rounds": challenge.rounds})
            solution = solve_vulcan_challenge(
                challenge,
                start=start,
                max_attempts_per_round=max_attempts_per_round,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Vulcan solve failed: timeout or max_attempts_per_round exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_vulcan_solution(challenge, solution):
                errors.append("Vulcan internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            submit_body = build_vulcan_submit_body(challenge, solution, response_field=response_field)
            raw["solution"] = {**solution.to_payload(), "submitBody": submit_body}
            diagnostics.update(
                {
                    "solution": solution.solution,
                    "nonces": solution.nonces,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            return finish(ok=True, ticket=_json_body(submit_body), verify_code="solved")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_vulcan_range(
    base: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int | None, int]:
    checked = 0
    base_bytes = str(base).encode("utf-8")
    base_hasher = hashlib.sha256(base_bytes)
    target = int(difficulty)
    from_bytes = int.from_bytes
    for nonce in range(max(1, int(start)), max(1, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, None, checked
        hasher = base_hasher.copy()
        hasher.update(str(nonce).encode("ascii"))
        digest = hasher.digest()
        checked += 1
        value = from_bytes(digest[:4], "big")
        if value < target:
            return nonce, digest.hex(), value, checked
    return None, None, None, checked


def _load_source(
    *,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_html: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if challenge_html:
        raw["challengeSource"] = "html"
        return extract_vulcan_from_html(challenge_html)
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("Vulcan requires challenge_json, challenge_file, challenge_html or challenge_url")
    resp = requests.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    content_type = resp.headers.get("Content-Type", "")
    raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url, "contentType": content_type}
    resp.raise_for_status()
    if "json" in content_type:
        payload = resp.json()
        raw["challengeResponse"]["json"] = payload
        raw["challengeSource"] = "url_json"
        return payload
    raw["challengeSource"] = "url_html"
    return extract_vulcan_from_html(resp.text)


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


def _parse_attrs(attrs: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(['\"])(.*?)\2", attrs, flags=re.DOTALL):
        out[m.group(1).lower()] = html.unescape(m.group(3))
    return out


def _extract_response_field(text: str) -> str | None:
    m = re.search(r"<input\b(?=[^>]*(?:id|name)=['\"]captcha-response['\"])(?P<attrs>[^>]*)>", text, flags=re.I | re.S)
    if not m:
        return None
    attrs = _parse_attrs(m.group("attrs"))
    return attrs.get("name") or attrs.get("id")


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
