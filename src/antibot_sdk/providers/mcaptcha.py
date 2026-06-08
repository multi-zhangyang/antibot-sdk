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
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

U128_MAX = (1 << 128) - 1
DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(slots=True)
class MCaptchaConfig:
    string: str
    difficulty_factor: int
    salt: str
    key: str | None = None
    max_recorded_nonce: int | None = None


@dataclass(slots=True)
class MCaptchaSolution:
    config: MCaptchaConfig
    nonce: int
    result: str
    took_ms: int
    checked: int
    worker_type: str = "python"

    @property
    def submit_body(self) -> dict[str, Any]:
        if not self.config.key:
            raise ValueError("mCaptcha submit body requires sitekey/key")
        return {
            "key": self.config.key,
            "string": self.config.string,
            "nonce": self.nonce,
            "result": self.result,
            "time": self.took_ms,
            "worker_type": self.worker_type,
        }

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def bincode_serialize_string(value: str) -> bytes:
    """Serialize a Rust `String` the way bincode v1 default options do.

    mCaptcha's Rust verifier calls `bincode::serialize(&String)` before hashing.
    For strings this is an unsigned 64-bit little-endian byte length followed by
    UTF-8 bytes.  The browser polyfill mirrors the same prefix.
    """

    raw = str(value).encode("utf-8")
    return len(raw).to_bytes(8, "little", signed=False) + raw


def mcaptcha_difficulty_target(difficulty_factor: int) -> int:
    difficulty = int(difficulty_factor)
    if difficulty < 1:
        raise ValueError("mCaptcha difficulty_factor must be >= 1")
    return U128_MAX - U128_MAX // difficulty


def mcaptcha_hash_bytes(salt: str, phrase: str, nonce: int | str) -> bytes:
    prefix = str(salt).encode("utf-8") + bincode_serialize_string(str(phrase))
    return hashlib.sha256(prefix + str(int(nonce)).encode("ascii")).digest()


def mcaptcha_score(salt: str, phrase: str, nonce: int | str) -> int:
    return int.from_bytes(mcaptcha_hash_bytes(salt, phrase, nonce)[:16], "big")


def verify_mcaptcha_work(
    config: MCaptchaConfig | dict[str, Any],
    nonce: int | str,
    result: str | int,
) -> bool:
    item = parse_mcaptcha_config(config)
    try:
        score = mcaptcha_score(item.salt, item.string, int(nonce))
        return str(result) == str(score) and score >= mcaptcha_difficulty_target(item.difficulty_factor)
    except Exception:
        return False


def solve_mcaptcha_config(
    config: MCaptchaConfig | dict[str, Any],
    *,
    start: int = 1,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> MCaptchaSolution | None:
    item = parse_mcaptcha_config(config)
    started = time.monotonic()
    start = max(1, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None

    if workers <= 1 or max_attempts < 100_000:
        nonce, result, checked = _solve_mcaptcha_range(
            item.salt,
            item.string,
            item.difficulty_factor,
            start,
            start + max_attempts,
            deadline,
        )
        if nonce is None or result is None:
            return None
        return MCaptchaSolution(
            config=item,
            nonce=nonce,
            result=result,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=checked,
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
        futures[
            pool.submit(
                _solve_mcaptcha_range,
                item.salt,
                item.string,
                item.difficulty_factor,
                lo,
                hi,
                deadline,
            )
        ] = idx

    try:
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=wait_timeout):
            nonce, result, checked = fut.result()
            checked_total += checked
            if nonce is not None and result is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return MCaptchaSolution(
                    config=item,
                    nonce=nonce,
                    result=result,
                    took_ms=int((time.monotonic() - started) * 1000),
                    checked=checked_total,
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


def parse_mcaptcha_config(value: MCaptchaConfig | dict[str, Any], *, key: str | None = None) -> MCaptchaConfig:
    if isinstance(value, MCaptchaConfig):
        if key and value.key != key:
            return MCaptchaConfig(
                string=value.string,
                difficulty_factor=value.difficulty_factor,
                salt=value.salt,
                key=key,
                max_recorded_nonce=value.max_recorded_nonce,
            )
        return value
    if not isinstance(value, dict):
        raise ValueError("mCaptcha config must be an object")

    data = value
    if isinstance(data.get("config"), dict):
        nested = dict(data["config"])
        for k in ("key", "sitekey"):
            if k in data and k not in nested:
                nested[k] = data[k]
        data = nested

    phrase = data.get("string", data.get("phrase"))
    salt = data.get("salt")
    difficulty = data.get("difficulty_factor", data.get("difficultyFactor", data.get("difficulty")))
    if phrase is None or salt is None or difficulty is None:
        raise ValueError("mCaptcha config requires string/difficulty_factor/salt")
    max_nonce = data.get("max_recorded_nonce", data.get("maxRecordedNonce", data.get("max_nonce")))
    return MCaptchaConfig(
        string=str(phrase),
        difficulty_factor=int(difficulty),
        salt=str(salt),
        key=key or _str_or_none(data.get("key") or data.get("sitekey")),
        max_recorded_nonce=int(max_nonce) if max_nonce is not None else None,
    )


def _solve_mcaptcha_range(
    salt: str,
    phrase: str,
    difficulty_factor: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, str | None, int]:
    target = mcaptcha_difficulty_target(difficulty_factor)
    prefix = str(salt).encode("utf-8") + bincode_serialize_string(str(phrase))
    base = hashlib.sha256(prefix)
    checked = 0
    for nonce in range(max(1, int(start)), max(1, int(end_exclusive))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, None, checked
        h = base.copy()
        h.update(str(nonce).encode("ascii"))
        score = int.from_bytes(h.digest()[:16], "big")
        checked += 1
        if score >= target:
            return nonce, str(score), checked
    return None, None, checked


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _infer_pow_url(base_url: str | None, leaf: str) -> str | None:
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", f"api/v1/pow/{leaf}")


def _replace_last_path_segment(url: str | None, expected: str, replacement: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if not path.endswith("/" + expected):
        return None
    new_path = path[: -len(expected)] + replacement
    return urlunparse(parsed._replace(path=new_path))


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _redact_token(data: Any) -> Any:
    if isinstance(data, dict):
        out = dict(data)
        token = out.get("token")
        if isinstance(token, str) and len(token) > 24:
            out["token"] = token[:12] + "..." + token[-8:]
        return out
    return data


class MCaptchaSolver:
    """mCaptcha SHA-256 proof-of-work protocol solver.

    The provider mirrors the official Rust/JS algorithm:
    `SHA256(salt || bincode(String) || decimal_nonce)`, score is the first 16
    digest bytes interpreted as a big-endian u128, and a proof is valid when
    `score >= u128::MAX - u128::MAX / difficulty_factor`.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        config_json: Any = None,
        config_file: str | None = None,
        config_url: str | None = None,
        base_url: str | None = None,
        sitekey: str | None = None,
        key: str | None = None,
        verify_url: str | None = None,
        submit: bool = True,
        siteverify_url: str | None = None,
        siteverify: bool = False,
        secret: str | None = None,
        start: int = 1,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
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
            "config_url": config_url,
            "base_url": base_url,
            "verify_url": verify_url,
            "siteverify_url": siteverify_url,
            "submit": submit,
            "siteverify": siteverify,
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
                out = output_root / "mcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="mcaptcha",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("sitekey"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            sitekey = sitekey or key
            if base_url and base_url.rstrip("/").endswith("/config"):
                config_url = config_url or base_url
                base_url = None
            if base_url:
                config_url = config_url or _infer_pow_url(base_url, "config")
                verify_url = verify_url or _infer_pow_url(base_url, "verify")
                siteverify_url = siteverify_url or _infer_pow_url(base_url, "siteverify")
            verify_url = verify_url or _replace_last_path_segment(config_url, "config", "verify")
            siteverify_url = siteverify_url or _replace_last_path_segment(verify_url, "verify", "siteverify")
            diagnostics.update(
                {
                    "config_url": config_url,
                    "base_url": base_url,
                    "verify_url": verify_url,
                    "siteverify_url": siteverify_url,
                    "sitekey": sitekey,
                }
            )

            config = self._load_config(
                config_json=config_json,
                config_file=config_file,
                config_url=config_url,
                sitekey=sitekey,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            diagnostics.update(
                {
                    "sitekey": config.key,
                    "difficulty_factor": config.difficulty_factor,
                    "max_recorded_nonce": config.max_recorded_nonce,
                }
            )
            raw["config"] = {
                "key": config.key,
                "string": config.string,
                "difficulty_factor": config.difficulty_factor,
                "salt": config.salt,
                "max_recorded_nonce": config.max_recorded_nonce,
            }

            solve_started = time.monotonic()
            solution = solve_mcaptcha_config(
                config,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("mCaptcha PoW solve failed: timeout or max_attempts exhausted")
                return finish(ok=False)
            solution.took_ms = int((time.monotonic() - solve_started) * 1000)
            diagnostics.update(
                {
                    "nonce": solution.nonce,
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "target": str(mcaptcha_difficulty_target(config.difficulty_factor)),
                }
            )
            raw["solution"] = {
                "nonce": solution.nonce,
                "result": solution.result,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            if config.key:
                raw["submitBody"] = solution.submit_body

            ticket = solution.submit_body_json() if config.key else json.dumps(raw["solution"], separators=(",", ":"))
            verify_code = "solved"
            token: str | None = None
            if submit and verify_url:
                if not config.key:
                    errors.append("mCaptcha submit requested but sitekey/key is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp_data = self._submit_work(
                    verify_url=verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                token = _str_or_none(resp_data.get("token") if isinstance(resp_data, dict) else None)
                if not token:
                    errors.append("mCaptcha verify response did not include token")
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                ticket = token
                verify_code = "token"
                raw["token"] = token
                diagnostics["submitted"] = True

            if siteverify or (secret and siteverify_url and token):
                if not token:
                    errors.append("mCaptcha siteverify requested but token is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                if not secret:
                    errors.append("mCaptcha siteverify requested but secret is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                if not siteverify_url:
                    errors.append("mCaptcha siteverify requested but siteverify_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                valid = self._siteverify(
                    siteverify_url=siteverify_url,
                    secret=secret,
                    key=config.key,
                    token=token,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                    raw=raw,
                )
                if not valid:
                    errors.append("mCaptcha siteverify rejected token")
                    return finish(ok=False, ticket=ticket, verify_code="siteverify_failed")
                verify_code = "validated"
                diagnostics["siteverified"] = True
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_config(
        self,
        *,
        config_json: Any,
        config_file: str | None,
        config_url: str | None,
        sitekey: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> MCaptchaConfig:
        data = config_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, config_file)
        if data is not None:
            raw["configSource"] = "json"
            return parse_mcaptcha_config(data, key=sitekey)

        if config_url:
            if not sitekey:
                raise ValueError("mCaptcha config_url/base_url requires --sitekey/--key")
            resp = requests.post(
                config_url,
                headers={"Content-Type": "application/json", **(headers or {})},
                json={"key": sitekey},
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["configResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            data = resp.json()
            raw["configSource"] = "url"
            return parse_mcaptcha_config(data, key=sitekey)

        raise ValueError("mCaptcha requires config_json, config_file, config_url or base_url")

    def _submit_work(
        self,
        *,
        verify_url: str,
        solution: MCaptchaSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=solution.submit_body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = _redact_token(data)
        return data

    def _siteverify(
        self,
        *,
        siteverify_url: str,
        secret: str,
        key: str | None,
        token: str,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> bool:
        resp = requests.post(
            siteverify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json={"secret": secret, "key": key, "token": token},
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["siteverifyResponse"] = {"status": resp.status_code, "url": siteverify_url}
        resp.raise_for_status()
        try:
            data: Any = resp.json()
        except Exception:
            data = {"text": resp.text[:500]}
        raw["siteverifyResponse"]["json"] = _redact_token(data)
        if isinstance(data, dict) and "valid" in data:
            return bool(data["valid"])
        return 200 <= int(resp.status_code) < 300
