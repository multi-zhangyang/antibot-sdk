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
from argon2.low_level import Type, hash_secret_raw

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

ARGON2_OUT_LEN = 32
LEGACY_M_COST = 4096
LEGACY_T_COST = 1
LEGACY_P_COST = 1
DEFAULT_MAX_ITERS = 10_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class PortcullisChallenge:
    id: str
    salt: bytes
    diff: int
    exp: int
    site_key: str
    m_cost: int = LEGACY_M_COST
    t_cost: int = LEGACY_T_COST
    p_cost: int = LEGACY_P_COST
    sig: str | None = None

    @property
    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode("ascii")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "salt": self.salt_b64,
            "diff": self.diff,
            "exp": self.exp,
            "site_key": self.site_key,
            "m_cost": self.m_cost,
            "t_cost": self.t_cost,
            "p_cost": self.p_cost,
        }

    def sign_bytes(self) -> bytes:
        raw = bytearray()
        raw.extend(self.id.encode("utf-8"))
        raw.extend(self.salt)
        raw.append(self.diff & 0xFF)
        raw.extend(int(self.exp).to_bytes(8, "little", signed=False))
        raw.extend(self.site_key.encode("utf-8"))
        raw.extend(int(self.m_cost).to_bytes(4, "little", signed=False))
        raw.extend(int(self.t_cost).to_bytes(4, "little", signed=False))
        raw.extend(int(self.p_cost).to_bytes(4, "little", signed=False))
        return bytes(raw)


@dataclass(slots=True)
class PortcullisSolution:
    challenge: PortcullisChallenge
    nonce: int
    hash_hex: str
    leading_zero_bits: int
    attempts: int
    took_ms: int

    @property
    def verify_body(self) -> dict[str, Any]:
        return {"challenge": self.challenge.to_payload(), "sig": self.challenge.sig, "nonce": self.nonce}


def leading_zero_bits(data: bytes) -> int:
    count = 0
    for b in data:
        if b == 0:
            count += 8
        else:
            return count + (8 - b.bit_length())
    return count


def compute_portcullis_base_hash(challenge: PortcullisChallenge | dict[str, Any] | str) -> bytes:
    item = parse_portcullis_challenge(challenge)
    _validate_argon2_params(item)
    return hash_secret_raw(
        secret=item.id.encode("utf-8"),
        salt=item.salt,
        time_cost=item.t_cost,
        memory_cost=item.m_cost,
        parallelism=item.p_cost,
        hash_len=ARGON2_OUT_LEN,
        type=Type.ID,
        version=19,
    )


def portcullis_pow_hash(base_hash: bytes, nonce: int) -> bytes:
    return hashlib.sha256(base_hash + int(nonce).to_bytes(8, "little", signed=False)).digest()


def verify_portcullis_solution(challenge: PortcullisChallenge | dict[str, Any] | str, nonce: int) -> bool:
    try:
        item = parse_portcullis_challenge(challenge)
        base = compute_portcullis_base_hash(item)
        digest = portcullis_pow_hash(base, nonce)
        return leading_zero_bits(digest) >= item.diff
    except Exception:
        return False


def sign_portcullis_challenge(challenge: PortcullisChallenge | dict[str, Any] | str, secret: str | bytes) -> str:
    item = parse_portcullis_challenge(challenge)
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return base64.b64encode(hmac.new(key, item.sign_bytes(), hashlib.sha256).digest()).decode("ascii")


def verify_portcullis_signature(
    challenge: PortcullisChallenge | dict[str, Any] | str,
    sig: str | bytes | None = None,
    secret: str | bytes | None = None,
) -> bool:
    if secret is None:
        return False
    item = parse_portcullis_challenge(challenge)
    expected = sign_portcullis_challenge(item, secret)
    actual = sig.decode("ascii") if isinstance(sig, bytes) else sig or item.sig
    return bool(actual) and hmac.compare_digest(expected, str(actual))


def solve_portcullis_challenge(
    challenge: PortcullisChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_iters: int = DEFAULT_MAX_ITERS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> PortcullisSolution | None:
    item = parse_portcullis_challenge(challenge)
    started = time.monotonic()
    start = max(0, int(start))
    max_iters = max(1, int(max_iters))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    base = compute_portcullis_base_hash(item)

    if workers <= 1 or max_iters < 100_000:
        nonce, digest, attempts = _solve_portcullis_range(base, item.diff, start, start + max_iters, deadline)
        if nonce is None or digest is None:
            return None
        return PortcullisSolution(
            item,
            nonce,
            digest.hex(),
            leading_zero_bits(digest),
            attempts,
            int((time.monotonic() - started) * 1000),
        )

    chunk = math.ceil(max_iters / workers)
    checked_total = 0
    pool = ProcessPoolExecutor(max_workers=workers)
    futures = {}
    for idx in range(workers):
        lo = start + idx * chunk
        hi = min(start + max_iters, lo + chunk)
        if lo >= hi:
            break
        futures[pool.submit(_solve_portcullis_range, base, item.diff, lo, hi, deadline)] = idx
    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, digest, attempts = fut.result()
            checked_total += attempts
            if nonce is not None and digest is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return PortcullisSolution(
                    item,
                    nonce,
                    digest.hex(),
                    leading_zero_bits(digest),
                    checked_total,
                    int((time.monotonic() - started) * 1000),
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


def parse_portcullis_challenge(data: PortcullisChallenge | dict[str, Any] | str) -> PortcullisChallenge:
    if isinstance(data, PortcullisChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
        obj = json.loads(text)
    else:
        obj = dict(data)

    sig = obj.get("sig")
    if "challenge" in obj and isinstance(obj["challenge"], dict):
        sig = obj.get("sig") or obj["challenge"].get("sig")
        obj = dict(obj["challenge"])

    salt_raw = obj.get("salt")
    if isinstance(salt_raw, str):
        salt = base64.b64decode(salt_raw, validate=True)
    elif isinstance(salt_raw, (bytes, bytearray)):
        salt = bytes(salt_raw)
    elif isinstance(salt_raw, list):
        salt = bytes(int(x) & 0xFF for x in salt_raw)
    else:
        raise ValueError("Portcullis challenge salt is missing")
    if len(salt) != 16:
        raise ValueError("Portcullis salt must be 16 bytes")

    item = PortcullisChallenge(
        id=str(obj["id"]),
        salt=salt,
        diff=int(obj["diff"]),
        exp=int(obj["exp"]),
        site_key=str(obj["site_key"]),
        m_cost=int(obj.get("m_cost", LEGACY_M_COST)),
        t_cost=int(obj.get("t_cost", LEGACY_T_COST)),
        p_cost=int(obj.get("p_cost", LEGACY_P_COST)),
        sig=str(sig) if sig else None,
    )
    _validate_argon2_params(item)
    return item


def parse_portcullis_token(token: str) -> dict[str, Any]:
    payload_b64, sig_b64 = token.split(".", 1)
    payload = _b64url_decode(payload_b64)
    return {"payload": json.loads(payload), "signature_b64url": sig_b64}


def _solve_portcullis_range(
    base: bytes,
    diff: int,
    start: int,
    end_exclusive: int,
    deadline: float | None,
) -> tuple[int | None, bytes | None, int]:
    attempts = 0
    target = int(diff)
    for nonce in range(int(start), int(end_exclusive)):
        if deadline is not None and attempts and attempts % 4096 == 0 and time.monotonic() >= deadline:
            return None, None, attempts
        attempts += 1
        digest = portcullis_pow_hash(base, nonce)
        if leading_zero_bits(digest) >= target:
            return nonce, digest, attempts
    return None, None, attempts


def _validate_argon2_params(item: PortcullisChallenge) -> None:
    if not 0 <= item.diff <= 255:
        raise ValueError("Portcullis diff must be 0..255")
    if not 8 <= item.m_cost <= 65_536:
        raise ValueError("Portcullis m_cost must be 8..65536 KiB")
    if not 1 <= item.t_cost <= 10:
        raise ValueError("Portcullis t_cost must be 1..10")
    if item.p_cost != 1:
        raise ValueError("Portcullis p_cost must be 1")
    if item.exp < 0:
        raise ValueError("Portcullis exp must be non-negative")


def _b64url_decode(value: str) -> bytes:
    text = value.strip().replace("-", "+").replace("_", "/")
    text += "=" * ((4 - len(text) % 4) % 4)
    return base64.b64decode(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


class PortcullisSolver:
    """Portcullis Argon2id + SHA-256 protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | dict[str, Any] | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        base_url: str | None = None,
        sitekey: str | None = None,
        sig: str | None = None,
        verify_url: str | None = None,
        siteverify_url: str | None = None,
        submit: bool = False,
        secret_key: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        start: int = 0,
        max_iters: int = DEFAULT_MAX_ITERS,
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
            "base_url": base_url,
            "verify_url": verify_url,
            "siteverify_url": siteverify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_iters": max_iters,
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
                out = output_root / "portcullis_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="portcullis",
                ok=ok,
                captcha_type="argon2_pow",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge_id"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            loaded = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                base_url=base_url,
                sitekey=sitekey,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_portcullis_challenge(loaded)
            if sig:
                item.sig = sig
            raw["challenge"] = {"challenge": item.to_payload(), "sig": item.sig}
            diagnostics.update(
                {
                    "challenge_id": item.id,
                    "sitekey": item.site_key,
                    "diff": item.diff,
                    "m_cost": item.m_cost,
                    "t_cost": item.t_cost,
                    "p_cost": item.p_cost,
                    "exp": item.exp,
                }
            )

            solution = solve_portcullis_challenge(
                item,
                start=start,
                max_iters=max_iters,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("Portcullis solve failed: timeout or max_iters exhausted")
                return finish(ok=False)
            raw["solution"] = {
                "nonce": solution.nonce,
                "hash": solution.hash_hex,
                "leadingZeroBits": solution.leading_zero_bits,
                "attempts": solution.attempts,
                "tookMs": solution.took_ms,
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
            ticket = json.dumps(solution.verify_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"

            if submit or verify_url:
                target = verify_url or _infer_endpoint(base_url, "/api/v1/verify")
                if not target:
                    errors.append("Portcullis submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                if not item.sig:
                    errors.append("Portcullis verify submit requires challenge sig")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_verify(
                    verify_url=target,
                    body=solution.verify_body,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(verify_data, dict):
                    if not verify_data.get("success", False):
                        errors.append("Portcullis verification endpoint rejected answer")
                        return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                    ticket = str(verify_data.get("captcha_token") or verify_data.get("token") or ticket)
                    raw["tokenParsed"] = parse_portcullis_token(ticket) if "." in ticket else None
                verify_code = "validated"
                diagnostics["submitted"] = True

            if siteverify_url and secret_key and ticket:
                siteverify_data = self._submit_siteverify(
                    siteverify_url=siteverify_url,
                    token=ticket,
                    secret_key=secret_key,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if isinstance(siteverify_data, dict) and not siteverify_data.get("success", False):
                    errors.append("Portcullis siteverify rejected token")
                    return finish(ok=False, ticket=ticket, verify_code="siteverify_failed")
                verify_code = "siteverified"
                diagnostics["siteverified"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge: str | dict[str, Any] | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        base_url: str | None,
        sitekey: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        if challenge is not None:
            raw["challengeSource"] = "inline"
            return challenge
        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        url = challenge_url or _infer_endpoint(base_url, "/api/v1/challenge")
        if url:
            if not sitekey:
                raise ValueError("Portcullis challenge_url/base_url requires sitekey")
            resp = requests.post(
                url,
                json={"site_key": sitekey},
                headers={"content-type": "application/json", **(headers or {})},
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": url}
            resp.raise_for_status()
            raw["challengeSource"] = "url-json"
            return resp.json()
        raise ValueError("Portcullis requires challenge, challenge_json, challenge_file, challenge_url or base_url")

    def _submit_verify(
        self,
        *,
        verify_url: str,
        body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            json=body,
            headers={"content-type": "application/json", **(headers or {})},
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        resp.raise_for_status()
        data: Any = resp.json()
        raw["verifyResponse"]["json"] = data
        return data

    def _submit_siteverify(
        self,
        *,
        siteverify_url: str,
        token: str,
        secret_key: str,
        client_ip: str | None,
        user_agent: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        body: dict[str, Any] = {"token": token, "secret_key": secret_key}
        if client_ip:
            body["client_ip"] = client_ip
        if user_agent:
            body["user_agent"] = user_agent
        resp = requests.post(
            siteverify_url,
            json=body,
            headers={"content-type": "application/json", **(headers or {})},
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["siteverifyResponse"] = {"status": resp.status_code, "url": siteverify_url}
        resp.raise_for_status()
        data: Any = resp.json()
        raw["siteverifyResponse"]["json"] = data
        return data


def _infer_endpoint(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    return base_url.rstrip("/") + path
