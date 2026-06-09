from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_API_PATH = "/api/v1"
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "application/json,text/plain,*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True, slots=True)
class NeoIrcHashcashChallenge:
    bits: int
    resource: str
    mode: str = "session"
    date: str | None = None
    channel: str | None = None
    body: bytes | None = None
    body_hash: str | None = None
    response_field: str = "pow_token"
    raw: dict[str, Any] | None = None

    @property
    def date_value(self) -> str:
        return self.date or datetime.now(timezone.utc).strftime("%y%m%d")

    @property
    def body_hash_value(self) -> str:
        if self.mode != "channel":
            return ""
        if self.body_hash:
            return self.body_hash.lower()
        if self.body is None:
            raise ValueError("channel hashcash requires body or body_hash")
        return neoirc_body_hash(self.body)

    def prefix(self) -> str:
        if self.mode == "session":
            return f"1:{int(self.bits)}:{self.date_value}:{self.resource}::"
        if self.mode == "channel":
            return f"1:{int(self.bits)}:{self.date_value}:{self.resource}:{self.body_hash_value}:"
        raise ValueError("NeoIRC hashcash mode must be session or channel")


@dataclass(frozen=True, slots=True)
class NeoIrcHashcashSolution:
    challenge: NeoIrcHashcashChallenge
    counter: int
    counter_hex: str
    stamp: str
    hash_hex: str
    attempts: int
    elapsed_ms: int

    @property
    def submit_body(self) -> dict[str, str]:
        return {self.challenge.response_field: self.stamp}


def neoirc_body_hash(body: bytes | str | dict[str, Any] | list[Any]) -> str:
    if isinstance(body, bytes):
        raw = body
    elif isinstance(body, (dict, list)):
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        raw = str(body).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def neoirc_hashcash_hash(stamp: str) -> bytes:
    return hashlib.sha256(str(stamp).encode("utf-8")).digest()


def neoirc_hashcash_hash_hex(stamp: str) -> str:
    return neoirc_hashcash_hash(stamp).hex()


def neoirc_hashcash_matches(stamp_or_digest: str | bytes, bits: int, *, prehashed: bool = False) -> bool:
    digest = bytes.fromhex(stamp_or_digest) if isinstance(stamp_or_digest, str) and prehashed else (
        bytes(stamp_or_digest) if isinstance(stamp_or_digest, bytes) and prehashed else neoirc_hashcash_hash(str(stamp_or_digest))
    )
    return _leading_zero_bits_ok(digest, int(bits))


def solve_neoirc_hashcash_counter(
    prefix: str,
    bits: int,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> tuple[int, str, str, int]:
    bits = _validate_bits(bits)
    start = int(start)
    max_attempts = int(max_attempts)
    if start < 0:
        raise ValueError("start must be non-negative")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        counter, digest = _search_neoirc_range(prefix, bits, start, start + max_attempts)
        if counter is None or digest is None:
            raise TimeoutError(f"no NeoIRC hashcash counter found within {max_attempts} attempts")
        return counter, format(counter, "x"), digest.hex(), counter - start + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_neoirc_range, prefix, bits, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                _begin, end = futures.pop(fut)
                counter, digest = fut.result()
                if counter is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return counter, format(counter, "x"), digest.hex(), max(0, end - start)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_neoirc_range, prefix, bits, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no NeoIRC hashcash counter found within {max_attempts} attempts")


def parse_neoirc_hashcash_challenge(data: Any) -> NeoIrcHashcashChallenge:
    if isinstance(data, NeoIrcHashcashChallenge):
        return data
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            data = json.loads(text)
        elif text.startswith("1:"):
            parsed = parse_neoirc_hashcash_stamp(text)
            return NeoIrcHashcashChallenge(
                bits=parsed["bits"],
                resource=parsed["resource"],
                mode="channel" if parsed["body_hash"] else "session",
                date=parsed["date"],
                body_hash=parsed["body_hash"] or None,
                raw={"stamp": text, "counter": parsed["counter"]},
            )
        else:
            raise ValueError("NeoIRC hashcash challenge string must be JSON or stamp")
    if not isinstance(data, dict):
        raise ValueError("NeoIRC hashcash challenge must be JSON, stamp, or challenge object")
    mode = str(data.get("mode") or ("channel" if data.get("channel") or data.get("body_hash") or data.get("body") else "session")).lower()
    bits = _validate_bits(data.get("bits") or data.get("hashcash_bits") or data.get("difficulty") or 0)
    resource = str(data.get("resource") or data.get("name") or data.get("serverName") or data.get("channel") or "")
    if not resource:
        raise ValueError("NeoIRC hashcash challenge requires resource/name/channel")
    body = data.get("body")
    body_bytes: bytes | None = None
    if body is not None:
        if isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, (dict, list)):
            body_bytes = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        else:
            body_bytes = str(body).encode("utf-8")
    response_field = str(data.get("response_field") or data.get("field") or ("hashcash" if mode == "channel" else "pow_token"))
    return NeoIrcHashcashChallenge(
        bits=bits,
        resource=resource,
        mode=mode,
        date=str(data.get("date") or "") or None,
        channel=str(data.get("channel") or "") or None,
        body=body_bytes,
        body_hash=str(data.get("body_hash") or data.get("bodyHash") or "") or None,
        response_field=response_field,
        raw=data,
    )


def parse_neoirc_hashcash_stamp(stamp: str) -> dict[str, Any]:
    parts = str(stamp).split(":")
    if len(parts) != 6:
        raise ValueError("NeoIRC hashcash stamp requires 6 fields: 1:bits:date:resource:bodyhash:counter")
    version, bits_text, date_text, resource, body_hash, counter_hex = parts
    if version != "1":
        raise ValueError("NeoIRC hashcash version must be 1")
    bits = _validate_bits(bits_text)
    if not re.fullmatch(r"\d{6}(?:\d{6})?", date_text):
        raise ValueError("NeoIRC hashcash date must be YYMMDD or YYMMDDHHMMSS")
    if not resource:
        raise ValueError("NeoIRC hashcash resource is empty")
    if body_hash and not re.fullmatch(r"[0-9a-fA-F]{64}", body_hash):
        raise ValueError("NeoIRC channel body_hash must be SHA-256 hex")
    if not counter_hex or not re.fullmatch(r"[0-9a-fA-F]+", counter_hex):
        raise ValueError("NeoIRC hashcash counter must be hex")
    return {
        "version": version,
        "bits": bits,
        "date": date_text,
        "resource": resource,
        "body_hash": body_hash.lower(),
        "counter": counter_hex.lower(),
        "counter_int": int(counter_hex, 16),
    }


def solve_neoirc_hashcash_challenge(
    challenge: NeoIrcHashcashChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> NeoIrcHashcashSolution:
    started = time.monotonic()
    item = parse_neoirc_hashcash_challenge(challenge)
    prefix = item.prefix()
    counter, counter_hex, digest_hex, attempts = solve_neoirc_hashcash_counter(
        prefix,
        item.bits,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    stamp = prefix + counter_hex
    return NeoIrcHashcashSolution(
        challenge=item,
        counter=counter,
        counter_hex=counter_hex,
        stamp=stamp,
        hash_hex=digest_hex,
        attempts=attempts,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def verify_neoirc_hashcash_solution(
    challenge: NeoIrcHashcashChallenge | dict[str, Any] | str,
    solution: NeoIrcHashcashSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_neoirc_hashcash_challenge(challenge)
        if isinstance(solution, NeoIrcHashcashSolution):
            stamp_text = solution.stamp
        elif isinstance(solution, dict):
            stamp_text = str(solution.get("stamp") or solution.get("pow_token") or solution.get("hashcash") or solution.get(item.response_field) or "")
        else:
            stamp_text = str(solution)
        parsed = parse_neoirc_hashcash_stamp(stamp_text)
        if parsed["resource"] != item.resource:
            return False
        if parsed["bits"] < item.bits:
            return False
        if item.mode == "session" and parsed["body_hash"]:
            return False
        if item.mode == "channel" and parsed["body_hash"] != item.body_hash_value:
            return False
        return neoirc_hashcash_matches(stamp_text, item.bits)
    except Exception:
        return False


class NeoIrcSolver:
    """Protocol solver for NeoIRC's SHA-256 Hashcash anti-abuse gates.

    NeoIRC uses two six-field Hashcash variants: login/session stamps bound to
    the server name, and per-channel PRIVMSG stamps bound to both channel and
    the raw JSON body hash. The solver mirrors the WebCrypto client without a
    browser and can optionally submit the session flow.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        mode: str = "session",
        base_url: str | None = None,
        api_base: str | None = None,
        server_url: str | None = None,
        session_url: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        resource: str | None = None,
        bits: int | None = None,
        stamp_date: str | None = None,
        nick: str = "antibot-sdk",
        channel: str | None = None,
        body: str | bytes | None = None,
        body_json: Any = None,
        body_file: str | None = None,
        body_hash: str | None = None,
        submit: bool = False,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        chunk_size: int = 100_000,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "mode": mode,
            "base_url": base_url,
            "api_base": api_base,
            "server_url": server_url,
            "session_url": session_url,
            "submit": submit,
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
                out = output_root / "neoirc_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="neoirc",
                ok=ok,
                captcha_type="resource_body_bound_hashcash",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("resource"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            session = requests.Session()
            merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
            proxies = _requests_proxies(proxy_server)
            challenge = self._load_challenge(
                session=session,
                mode=mode,
                base_url=base_url,
                api_base=api_base,
                server_url=server_url,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                resource=resource,
                bits=bits,
                stamp_date=stamp_date,
                channel=channel,
                body=body,
                body_json=body_json,
                body_file=body_file,
                body_hash=body_hash,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_neoirc_hashcash_challenge(
                challenge,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
            )
            if not verify_neoirc_hashcash_solution(challenge, solution):
                errors.append("NeoIRC internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            diagnostics.update(
                {
                    "resource": challenge.resource,
                    "bits": challenge.bits,
                    "date": challenge.date_value,
                    "response_field": challenge.response_field,
                    "counter": solution.counter,
                    "counter_hex": solution.counter_hex,
                    "hash_hex": solution.hash_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.elapsed_ms,
                    "body_hash": challenge.body_hash_value if challenge.mode == "channel" else None,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = {
                "stamp": solution.stamp,
                "hashHex": solution.hash_hex,
                "counter": solution.counter,
                "counterHex": solution.counter_hex,
                "submitBody": solution.submit_body,
            }
            final_ticket = json.dumps(solution.submit_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit:
                if challenge.mode != "session":
                    errors.append("submit currently supports session mode only")
                    return finish(ok=False, ticket=final_ticket, verify_code="submit_unsupported")
                url = session_url or _api_url(base_url, api_base, "/session")
                if not url:
                    errors.append("session submit requires base_url/api_base or session_url")
                    return finish(ok=False, ticket=final_ticket, verify_code="missing_session_url")
                payload = {"nick": nick, "pow_token": solution.stamp}
                resp = session.post(url, json=payload, headers=merged_headers, timeout=timeout_sec, proxies=proxies)
                raw["submitRequest"] = {"url": url, "body": {"nick": nick, "pow_token": solution.stamp}}
                raw["submitResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
                try:
                    submit_data: Any = resp.json()
                except Exception:
                    submit_data = resp.text[:500]
                raw["submitResponse"]["body"] = submit_data
                if not (200 <= resp.status_code < 400):
                    errors.append(str(submit_data)[:160] or f"http_{resp.status_code}")
                    return finish(ok=False, ticket=final_ticket, verify_code=f"http_{resp.status_code}")
                if isinstance(submit_data, dict) and submit_data.get("token"):
                    final_ticket = str(submit_data["token"])
                else:
                    final_ticket = json.dumps(submit_data, ensure_ascii=False, separators=(",", ":"))
                verify_code = "validated"
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        session: requests.Session,
        mode: str,
        base_url: str | None,
        api_base: str | None,
        server_url: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        resource: str | None,
        bits: int | None,
        stamp_date: str | None,
        channel: str | None,
        body: str | bytes | None,
        body_json: Any,
        body_file: str | None,
        body_hash: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> NeoIrcHashcashChallenge:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            item = parse_neoirc_hashcash_challenge(loaded)
            if bits is not None or stamp_date is not None:
                return _merge_challenge(item, bits=bits, stamp_date=stamp_date)
            return item

        body_bytes = _load_body_bytes(body=body, body_json=body_json, body_file=body_file)
        mode = mode.lower()
        if mode == "channel":
            if not channel and not resource:
                raise ValueError("channel mode requires --channel or --resource")
            if bits is None:
                raise ValueError("channel mode requires --bits")
            return NeoIrcHashcashChallenge(
                bits=_validate_bits(bits),
                resource=str(channel or resource),
                mode="channel",
                date=stamp_date,
                channel=channel,
                body=body_bytes,
                body_hash=body_hash,
                response_field="hashcash",
            )

        server_data: dict[str, Any] = {}
        if server_url or base_url or api_base:
            url = server_url or _api_url(base_url, api_base, "/server")
            if url:
                resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
                raw["serverRequest"] = {"url": url}
                raw["serverResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
                resp.raise_for_status()
                server_data = resp.json()
                raw["serverResponse"]["json"] = server_data
        final_bits = bits if bits is not None else server_data.get("hashcash_bits") or server_data.get("bits")
        final_resource = resource or server_data.get("name") or server_data.get("resource")
        if final_bits is None or int(final_bits) <= 0:
            raise ValueError("session mode requires positive bits/hashcash_bits")
        if not final_resource:
            raise ValueError("session mode requires resource/server name")
        return NeoIrcHashcashChallenge(
            bits=_validate_bits(final_bits),
            resource=str(final_resource),
            mode="session",
            date=stamp_date,
            response_field="pow_token",
            raw=server_data or None,
        )


def _search_neoirc_range(prefix: str, bits: int, begin: int, end: int) -> tuple[int | None, bytes | None]:
    prefix = str(prefix)
    for counter in range(int(begin), int(end)):
        stamp = prefix + format(counter, "x")
        digest = hashlib.sha256(stamp.encode("utf-8")).digest()
        if _leading_zero_bits_ok(digest, bits):
            return counter, digest
    return None, None


def _leading_zero_bits_ok(digest: bytes, bits: int) -> bool:
    bits = _validate_bits(bits)
    whole, rem = divmod(bits, 8)
    if any(digest[i] != 0 for i in range(whole)):
        return False
    if rem:
        return (digest[whole] & (0xFF << (8 - rem))) == 0
    return True


def _validate_bits(value: Any) -> int:
    try:
        bits = int(value)
    except Exception as exc:
        raise ValueError("NeoIRC hashcash bits must be an integer") from exc
    if bits < 1 or bits > 63:
        raise ValueError("NeoIRC hashcash bits must be 1..63")
    return bits


def _load_json_arg(value: Any, file_path: str | None = None) -> Any:
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith("@"):
            return _load_json_arg(None, text[1:])
        return json.loads(text) if text[0] in "[{" else text
    return value


def _load_body_bytes(*, body: str | bytes | None, body_json: Any, body_file: str | None) -> bytes | None:
    if body_file:
        return Path(body_file).read_bytes()
    if body_json is not None:
        data = _load_json_arg(body_json)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if body is None:
        return None
    return body if isinstance(body, bytes) else str(body).encode("utf-8")


def _api_url(base_url: str | None, api_base: str | None, path: str) -> str | None:
    if api_base:
        base = api_base.rstrip("/") + "/"
    elif base_url:
        base = urljoin(base_url.rstrip("/") + "/", DEFAULT_API_PATH.strip("/") + "/")
    else:
        return None
    return urljoin(base, path.lstrip("/"))


def _merge_challenge(item: NeoIrcHashcashChallenge, *, bits: int | None, stamp_date: str | None) -> NeoIrcHashcashChallenge:
    return NeoIrcHashcashChallenge(
        bits=_validate_bits(bits) if bits is not None else item.bits,
        resource=item.resource,
        mode=item.mode,
        date=stamp_date or item.date,
        channel=item.channel,
        body=item.body,
        body_hash=item.body_hash,
        response_field=item.response_field,
        raw=item.raw,
    )


def _challenge_raw(challenge: NeoIrcHashcashChallenge) -> dict[str, Any]:
    return {
        "bits": challenge.bits,
        "resource": challenge.resource,
        "mode": challenge.mode,
        "date": challenge.date_value,
        "responseField": challenge.response_field,
        "bodyHash": challenge.body_hash_value if challenge.mode == "channel" else None,
    }


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}
