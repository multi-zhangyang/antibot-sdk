from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_MAX_NUMBER = 1_000_000
DEFAULT_ALGORITHM = "SHA-256"

_ALGO_MAP = {
    "sha": "sha1",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
    "sha-512": "sha512",
    "sha512": "sha512",
}


@dataclass(slots=True)
class AltchaChallenge:
    algorithm: str
    challenge: str
    salt: str
    signature: str
    maxnumber: int = DEFAULT_MAX_NUMBER


@dataclass(slots=True)
class AltchaSolution:
    number: int
    took_ms: int
    checked: int
    algorithm: str
    challenge: str
    salt: str
    signature: str
    maxnumber: int

    def payload(self, *, include_took: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "algorithm": self.algorithm,
            "challenge": self.challenge,
            "number": self.number,
            "salt": self.salt,
            "signature": self.signature,
        }
        if include_took:
            data["took"] = self.took_ms
        return data

    def payload_json(self, *, include_took: bool = False) -> str:
        return json.dumps(self.payload(include_took=include_took), ensure_ascii=False, separators=(",", ":"))

    def payload_b64(self, *, include_took: bool = False) -> str:
        return base64.b64encode(self.payload_json(include_took=include_took).encode("utf-8")).decode(
            "ascii"
        )

    def authorization_header(self, *, style: str = "json") -> str:
        if style == "json":
            return "Altcha challenge=" + self.payload_json()
        payload = self.payload()
        parts = [f"{key}={_quote_header_value(value)}" for key, value in payload.items()]
        return "Altcha " + ", ".join(parts)


def normalize_altcha_algorithm(algorithm: str | None) -> str:
    raw = (algorithm or DEFAULT_ALGORITHM).strip()
    key = raw.lower().replace("_", "-")
    if key not in _ALGO_MAP:
        raise ValueError(f"unsupported ALTCHA v1 algorithm: {algorithm!r}")
    return _ALGO_MAP[key]


def _canonical_algorithm(algorithm: str | None) -> str:
    name = normalize_altcha_algorithm(algorithm)
    if name == "sha1":
        return "SHA-1"
    if name == "sha512":
        return "SHA-512"
    return "SHA-256"


def altcha_hash_hex(salt: str, number: int, algorithm: str | None = None) -> str:
    h = hashlib.new(normalize_altcha_algorithm(algorithm))
    h.update(f"{salt}{int(number)}".encode("utf-8"))
    return h.hexdigest()


def _solve_range(
    challenge: str,
    salt: str,
    algorithm: str,
    start: int,
    end: int,
) -> tuple[int | None, int]:
    target = challenge.lower()
    name = normalize_altcha_algorithm(algorithm)
    checked = 0
    for n in range(max(0, start), max(0, end) + 1):
        h = hashlib.new(name)
        h.update(f"{salt}{n}".encode("utf-8"))
        checked += 1
        if h.hexdigest().lower() == target:
            return n, checked
    return None, checked


def solve_altcha_challenge(
    challenge: AltchaChallenge | dict[str, Any],
    *,
    start: int = 0,
    max_number: int | None = None,
    workers: int = 1,
    timeout_sec: int | float | None = None,
) -> AltchaSolution | None:
    item = parse_altcha_challenge(challenge)
    upper = int(max_number if max_number is not None else item.maxnumber or DEFAULT_MAX_NUMBER)
    if upper < start:
        raise ValueError("max_number must be >= start")
    started = time.monotonic()
    workers = max(1, int(workers or 1))

    if workers <= 1 or upper - start < 50_000:
        number, checked = _solve_range(item.challenge, item.salt, item.algorithm, int(start), upper)
        if number is None:
            return None
        return AltchaSolution(
            number=number,
            took_ms=int((time.monotonic() - started) * 1000),
            checked=checked,
            algorithm=item.algorithm,
            challenge=item.challenge,
            salt=item.salt,
            signature=item.signature,
            maxnumber=upper,
        )

    span = upper - int(start) + 1
    chunk = math.ceil(span / workers)
    checked_total = 0
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = []
        for idx in range(workers):
            lo = int(start) + idx * chunk
            hi = min(upper, lo + chunk - 1)
            if lo > upper:
                break
            futures.append(pool.submit(_solve_range, item.challenge, item.salt, item.algorithm, lo, hi))
        pending = set(futures)
        while pending:
            wait_timeout = None
            if deadline is not None:
                wait_timeout = max(0.0, deadline - time.monotonic())
                if wait_timeout == 0:
                    break
            done, pending = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
            if not done:
                break
            for fut in done:
                number, checked = fut.result()
                checked_total += checked
                if number is not None:
                    for other in pending:
                        other.cancel()
                    return AltchaSolution(
                        number=number,
                        took_ms=int((time.monotonic() - started) * 1000),
                        checked=checked_total,
                        algorithm=item.algorithm,
                        challenge=item.challenge,
                        salt=item.salt,
                        signature=item.signature,
                        maxnumber=upper,
                    )
    return None


def parse_altcha_challenge(value: AltchaChallenge | dict[str, Any]) -> AltchaChallenge:
    if isinstance(value, AltchaChallenge):
        return value
    if not isinstance(value, dict):
        raise ValueError("ALTCHA challenge must be an object")
    algorithm = _canonical_algorithm(str(value.get("algorithm") or DEFAULT_ALGORITHM))
    challenge = str(value.get("challenge") or "")
    salt = str(value.get("salt") or "")
    signature = str(value.get("signature") or "")
    if not challenge or not salt or not signature:
        raise ValueError("ALTCHA challenge requires challenge/salt/signature")
    maxnumber_raw = value.get("maxnumber", value.get("max_number", DEFAULT_MAX_NUMBER))
    try:
        maxnumber = int(maxnumber_raw)
    except Exception as e:
        raise ValueError(f"invalid ALTCHA maxnumber: {maxnumber_raw!r}") from e
    return AltchaChallenge(
        algorithm=algorithm,
        challenge=challenge,
        salt=salt,
        signature=signature,
        maxnumber=maxnumber,
    )


def parse_altcha_payload_b64(value: str) -> dict[str, Any]:
    data = base64.b64decode(value).decode("utf-8")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("ALTCHA payload is not an object")
    return payload


def parse_altcha_header(header: str) -> dict[str, str]:
    text = (header or "").strip()
    if not text:
        raise ValueError("empty ALTCHA header")
    if text.lower().startswith("altcha"):
        text = text[6:].strip()
    if text.lower().startswith("challenge="):
        challenge_value = text.split("=", 1)[1].strip()
        if len(challenge_value) >= 2 and challenge_value[0] == challenge_value[-1] == '"':
            challenge_value = challenge_value[1:-1].replace('\\"', '"')
        if challenge_value.startswith("{"):
            data = json.loads(challenge_value)
            if not isinstance(data, dict):
                raise ValueError("ALTCHA header challenge JSON is not an object")
            return {k: str(v) for k, v in data.items() if v is not None}
    out: dict[str, str] = {}
    for part in _split_header_parts(text):
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].replace('\\"', '"')
        if key:
            out[key] = value
    if not out:
        raise ValueError("failed to parse ALTCHA header")
    return out


def challenge_from_altcha_header(header: str, *, default_maxnumber: int = DEFAULT_MAX_NUMBER) -> AltchaChallenge:
    data = parse_altcha_header(header)
    data.setdefault("maxnumber", str(default_maxnumber))
    return parse_altcha_challenge(data)


def _split_header_parts(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False
    for ch in text:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if ch == "," and not in_quote:
            parts.append("".join(buf).strip())
            buf.clear()
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def _quote_header_value(value: Any) -> str:
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._~:/?&=%+-]+", text):
        return text
    return '"' + text.replace('"', '\\"') + '"'


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> dict[str, Any] | None:
    if file_path:
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("challenge file must contain a JSON object")
        return data
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        data = json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("challenge JSON must be an object")
    return data


class AltchaSolver:
    """ALTCHA proof-of-work protocol solver.

    ALTCHA v1 is not a visual puzzle: the client searches for `n` such that
    `hash(salt + n) == challenge`, then sends a base64 JSON payload or an M2M
    `Authorization: Altcha ... number=...` header.  This provider keeps that
    flow fully protocol-level and does not launch a browser.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_url: str | None = None,
        challenge_json: dict[str, Any] | str | None = None,
        challenge_file: str | None = None,
        www_authenticate: str | None = None,
        default_maxnumber: int = DEFAULT_MAX_NUMBER,
        max_number: int | None = None,
        start: int = 0,
        workers: int = 1,
        timeout_sec: int = 30,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        include_took: bool = False,
        mode: str = "form",
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(), "mode": mode}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "start": start,
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
                out = output_root / "altcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="altcha",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("salt"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            challenge_obj: AltchaChallenge
            if www_authenticate:
                challenge_obj = challenge_from_altcha_header(
                    www_authenticate,
                    default_maxnumber=default_maxnumber,
                )
                raw["challengeSource"] = "www_authenticate"
            else:
                data: dict[str, Any] | None
                if isinstance(challenge_json, dict):
                    data = challenge_json
                else:
                    data = _load_json_arg(challenge_json, challenge_file)
                if data is None:
                    if not challenge_url:
                        errors.append("challenge_url, challenge_json, challenge_file or www_authenticate is required")
                        return finish(ok=False)
                    resp = requests.get(
                        challenge_url,
                        headers=headers,
                        timeout=timeout_sec,
                        proxies=_requests_proxies(proxy_server),
                    )
                    raw["challengeResponse"] = {"status": resp.status_code}
                    resp.raise_for_status()
                    data = resp.json()
                    if not isinstance(data, dict):
                        raise ValueError("challenge response is not a JSON object")
                    raw["challengeSource"] = "url"
                challenge_obj = parse_altcha_challenge(data)

            upper = int(max_number if max_number is not None else challenge_obj.maxnumber)
            raw["challenge"] = asdict(challenge_obj)
            diagnostics.update(
                {
                    "algorithm": challenge_obj.algorithm,
                    "maxnumber": upper,
                    "salt": challenge_obj.salt,
                    "challenge_prefix": challenge_obj.challenge[:12],
                }
            )
            solution = solve_altcha_challenge(
                challenge_obj,
                start=start,
                max_number=upper,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append(f"no ALTCHA solution found in range {start}..{upper}")
                return finish(ok=False)

            payload_b64 = solution.payload_b64(include_took=include_took)
            auth_header = solution.authorization_header()
            auth_header_kv = solution.authorization_header(style="kv")
            raw["solution"] = asdict(solution)
            raw["payload"] = solution.payload(include_took=include_took)
            raw["payloadBase64"] = payload_b64
            raw["authorizationHeader"] = auth_header
            raw["authorizationHeaderKeyValue"] = auth_header_kv
            diagnostics.update(
                {
                    "number": solution.number,
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "mode": "m2m" if www_authenticate or mode == "m2m" else "form",
                }
            )
            ticket = auth_header if www_authenticate or mode == "m2m" else payload_b64
            return finish(ok=True, ticket=ticket, verify_code=str(solution.number))
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)
