from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class CaptxaSimpleChallenge:
    challenge_token: str
    pow_challenge: str
    pow_difficulty: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "challenge_token": self.challenge_token,
            "pow_challenge": self.pow_challenge,
            "pow_difficulty": self.pow_difficulty,
        }


@dataclass(slots=True)
class CaptxaSimpleSolution:
    challenge: CaptxaSimpleChallenge
    nonce: int
    hash_hex: str
    leading_zero_bits: int
    attempts: int
    took_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return {
            "challenge_token": self.challenge.challenge_token,
            "pow_solution": self.nonce,
        }


def count_leading_zero_bits(data: bytes) -> int:
    total = 0
    for b in data:
        if b == 0:
            total += 8
            continue
        while (b & 0x80) == 0:
            total += 1
            b <<= 1
        break
    return total


def captxa_pow_seed_bytes(pow_challenge: str) -> bytes:
    raw = bytes.fromhex(str(pow_challenge).strip())
    if not raw:
        raise ValueError("Captxa pow_challenge is empty")
    if len(raw) > 32:
        raise ValueError("Captxa pow_challenge must be <= 32 bytes")
    return raw.ljust(32, b"\0")


def captxa_pow_hash_bytes(pow_challenge: str, nonce: int | str) -> bytes:
    return hashlib.sha256(captxa_pow_seed_bytes(pow_challenge) + int(nonce).to_bytes(8, "little", signed=False)).digest()


def captxa_pow_hash_hex(pow_challenge: str, nonce: int | str) -> str:
    return captxa_pow_hash_bytes(pow_challenge, nonce).hex()


def parse_captxa_simple_challenge(value: CaptxaSimpleChallenge | dict[str, Any] | str) -> CaptxaSimpleChallenge:
    if isinstance(value, CaptxaSimpleChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        obj = json.loads(text)
    else:
        obj = dict(value)
    if isinstance(obj.get("challenge"), dict):
        obj = obj["challenge"]
    token = str(obj.get("challenge_token") or obj.get("challengeToken") or obj.get("token") or "")
    pow_challenge = str(obj.get("pow_challenge") or obj.get("powChallenge") or "")
    difficulty_raw = obj.get("pow_difficulty", obj.get("powDifficulty", obj.get("difficulty")))
    if not token:
        raise ValueError("Captxa challenge_token is required")
    if not pow_challenge:
        raise ValueError("Captxa pow_challenge is required")
    if difficulty_raw is None:
        raise ValueError("Captxa pow_difficulty is required")
    difficulty = int(difficulty_raw)
    if difficulty < 0:
        raise ValueError("Captxa pow_difficulty must be >= 0")
    # Validate hex early.
    captxa_pow_seed_bytes(pow_challenge)
    return CaptxaSimpleChallenge(
        challenge_token=token,
        pow_challenge=pow_challenge.lower(),
        pow_difficulty=difficulty,
    )


def generate_captxa_browser_metrics(
    *,
    timezone_id: str = "America/New_York",
    webgl_renderer: str = "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
) -> dict[str, Any]:
    """Low-risk Captxa simple-mode browser metrics.

    Upstream extracts exact lowercase keys with a zero-allocation JSON scanner,
    so the SDK intentionally emits the names it expects: webglrenderer,
    hardwareconcurrency, innerw/innerh, availw/availh, devicememory, etc.
    """

    return {
        "webglrenderer": webgl_renderer,
        "timezone": timezone_id,
        "hardwareconcurrency": 8,
        "innerw": 1365,
        "innerh": 768,
        "availw": 1365,
        "availh": 824,
        "devicememory": 8,
        "webdriver": False,
        "ischromeruntimemissing": False,
        "errorstacktripwire": False,
    }


def score_captxa_browser_metrics(metrics: dict[str, Any], *, user_agent: str = DEFAULT_USER_AGENT) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0
    renderer = str(metrics.get("webglrenderer") or "")
    if metrics.get("webdriver"):
        reasons.append("webdriver=true")
        score += 5
    if metrics.get("errorstacktripwire"):
        reasons.append("error stack tripwire")
        score += 5
    if "HeadlessChrome" in user_agent:
        reasons.append("HeadlessChrome UA")
        score += 5
    if any(x in renderer for x in ("SwiftShader", "llvmpipe", "VirtualBox", "VMware")):
        reasons.append("software/vm WebGL renderer")
        score += 5
    if "Mesa" in renderer:
        reasons.append("Mesa renderer")
        score += 2
    if metrics.get("ischromeruntimemissing"):
        reasons.append("Chrome runtime missing")
        score += 2
    if 0 < int(metrics.get("devicememory") or 0) <= 2:
        reasons.append("low deviceMemory")
        score += 1
    if 0 < int(metrics.get("hardwareconcurrency") or 0) <= 2:
        reasons.append("low hardwareConcurrency")
        score += 1
    return {"success": score < 5, "score": score, "reasons": reasons}


def solve_captxa_simple_challenge(
    challenge: CaptxaSimpleChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> CaptxaSimpleSolution | None:
    item = parse_captxa_simple_challenge(challenge)
    started = time.monotonic()
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    start = max(0, int(start))
    max_attempts = DEFAULT_MAX_ATTEMPTS if max_attempts is None else max(1, int(max_attempts))
    seed = captxa_pow_seed_bytes(item.pow_challenge)
    attempts = 0
    for nonce in range(start, start + max_attempts):
        if deadline is not None and attempts and attempts % 8192 == 0 and time.monotonic() >= deadline:
            return None
        digest = hashlib.sha256(seed + nonce.to_bytes(8, "little", signed=False)).digest()
        attempts += 1
        leading = count_leading_zero_bits(digest)
        if leading >= item.pow_difficulty:
            return CaptxaSimpleSolution(
                challenge=item,
                nonce=nonce,
                hash_hex=digest.hex(),
                leading_zero_bits=leading,
                attempts=attempts,
                took_ms=int((time.monotonic() - started) * 1000),
            )
    return None


def verify_captxa_simple_solution(
    challenge: CaptxaSimpleChallenge | dict[str, Any] | str,
    solution: CaptxaSimpleSolution | dict[str, Any] | int | str,
) -> bool:
    try:
        item = parse_captxa_simple_challenge(challenge)
        if isinstance(solution, CaptxaSimpleSolution):
            nonce = solution.nonce
        elif isinstance(solution, dict):
            nonce = int(solution.get("pow_solution", solution.get("nonce", solution.get("solution"))))
        else:
            nonce = int(solution)
        if nonce < 0:
            return False
        return count_leading_zero_bits(captxa_pow_hash_bytes(item.pow_challenge, nonce)) >= item.pow_difficulty
    except Exception:
        return False


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


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "Origin": "https://example.com",
        "Referer": "https://example.com/",
    }
    if headers:
        out.update(headers)
    return out


def _derive_url(base_url: str | None, explicit: str | None, path: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _json_body(obj: dict[str, Any]) -> str:
    # Captxa's C JSON scanner expects compact key tokens with ':' immediately
    # after the closing quote. Compact JSON also avoids unnecessary bytes.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


class CaptxaSolver:
    """Captxa simple challenge protocol solver."""

    async def solve_simple(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_simple_sync, **kwargs)

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await self.solve_simple(**kwargs)

    def _solve_simple_sync(
        self,
        *,
        base_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        solve_url: str | None = None,
        submit: bool = False,
        metrics_json: Any = None,
        metrics_file: str | None = None,
        start: int = 0,
        max_attempts: int | None = DEFAULT_MAX_ATTEMPTS,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
        timezone_id: str = "America/New_York",
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "solve_url": solve_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
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
                out = output_root / "captxa_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="captxa",
                ok=ok,
                captcha_type="ja4_bound_pow",
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
            metrics = _load_json_arg(metrics_json, metrics_file) or generate_captxa_browser_metrics(timezone_id=timezone_id)
            if not isinstance(metrics, dict):
                raise ValueError("Captxa metrics must be a JSON object")
            metric_score = score_captxa_browser_metrics(metrics, user_agent=request_headers["User-Agent"])
            raw["metrics"] = metrics
            diagnostics["metric_score"] = metric_score
            challenge_data = self._load_challenge(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_url(base_url, challenge_url, "/challenge/simp"),
                metrics=metrics,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_captxa_simple_challenge(challenge_data)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "pow_challenge": item.pow_challenge,
                    "pow_difficulty": item.pow_difficulty,
                    "challenge_token_present": bool(item.challenge_token),
                }
            )
            solution = solve_captxa_simple_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("captxa solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "leadingZeroBits": solution.leading_zero_bits,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
                "submitBody": solution.submit_body,
            }
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "hash": solution.hash_hex,
                    "leading_zero_bits": solution.leading_zero_bits,
                    "attempts": solution.attempts,
                    "solve_ms": solution.took_ms,
                }
            )
            ticket = _json_body(solution.submit_body)
            verify_code = "solved"
            if submit or solve_url:
                effective_solve_url = _derive_url(base_url, solve_url, "/solve/simp")
                if not effective_solve_url:
                    errors.append("submit requested but solve_url could not be derived")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data, pass_token = self._submit_solution(
                    solve_url=effective_solve_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = verify_data is True or (isinstance(verify_data, dict) and verify_data.get("valid") is True)
                if not ok:
                    reason = verify_data.get("error") if isinstance(verify_data, dict) else "verify_failed"
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = pass_token or ticket
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
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        metrics: dict[str, Any],
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
            raise ValueError("captxa requires base_url, challenge_json, challenge_file or challenge_url")
        resp = requests.post(
            challenge_url,
            data=_json_body(metrics),
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
        solve_url: str,
        solution: CaptxaSimpleSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> tuple[Any, str | None]:
        resp = requests.post(
            solve_url,
            data=_json_body(solution.submit_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": solve_url}
        pass_token = resp.headers.get("x-captcha-token") or resp.headers.get("X-Captcha-Token")
        try:
            data = resp.json()
        except ValueError:
            text = resp.text.strip()
            data = True if text == "true" else {"text": text[:500]}
        raw["verifyResponse"]["json"] = data
        raw["verifyResponse"]["passTokenPresent"] = bool(pass_token)
        return data, pass_token
