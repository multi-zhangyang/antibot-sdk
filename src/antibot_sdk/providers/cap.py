from __future__ import annotations

import asyncio
import hashlib
import json
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_CHALLENGE_COUNT = 50
DEFAULT_CHALLENGE_SIZE = 32
DEFAULT_CHALLENGE_DIFFICULTY = 4
MAX_CHALLENGE_COUNT = 1000
MAX_CHALLENGE_SIZE = 256
MAX_CHALLENGE_DIFFICULTY = 16
MAX_RSW_T = 1_000_000
DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE = 10_000_000
FNV1A_OFFSET_BASIS = 2166136261
FNV1A_PRIME = 16777619


@dataclass(slots=True)
class CapChallenge:
    salt: str
    target: str
    protocol: str = "sha256-pow"


@dataclass(slots=True)
class CapRswChallenge:
    N: str
    x: str
    t: int
    protocol: str = "rsw"


@dataclass(slots=True)
class CapUnsupportedChallenge:
    protocol: str
    payload: dict[str, Any] | None = None


@dataclass(slots=True)
class CapSolution:
    token: str | None
    challenges: list[CapChallenge | CapRswChallenge]
    solutions: list[int] | list[dict[str, Any]]
    format: int = 1
    took_ms: int = 0
    checked: int = 0

    @property
    def submit_body(self) -> dict[str, Any]:
        if self.token is None:
            return {"solutions": self.solutions}
        return {"token": self.token, "solutions": self.solutions}

    def submit_body_json(self) -> str:
        return json.dumps(self.submit_body, ensure_ascii=False, separators=(",", ":"))


def fnv1a(value: str) -> int:
    """FNV-1a as used by Cap's JavaScript PRNG seed."""

    h = FNV1A_OFFSET_BASIS
    for ch in value:
        h ^= ord(ch)
        h = (h * FNV1A_PRIME) & 0xFFFFFFFF
    return h


def fnv1a_resume(state: int, value: str) -> int:
    h = int(state) & 0xFFFFFFFF
    for ch in value:
        h ^= ord(ch)
        h = (h * FNV1A_PRIME) & 0xFFFFFFFF
    return h


def prng_from_hash(initial_hash: int, length: int) -> str:
    """Cap's xorshift32 hex PRNG (`core/src/prng.js`)."""

    if length < 0:
        raise ValueError("length must be >= 0")
    state = int(initial_hash) & 0xFFFFFFFF
    out: list[str] = []
    out_len = 0
    while out_len < length:
        state ^= (state << 13) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        state ^= state >> 17
        state &= 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        out.append(f"{state:08x}")
        out_len += 8
    return "".join(out)[:length]


def cap_seeded_challenges(
    token: str,
    *,
    c: int = DEFAULT_CHALLENGE_COUNT,
    s: int = DEFAULT_CHALLENGE_SIZE,
    d: int = DEFAULT_CHALLENGE_DIFFICULTY,
) -> list[CapChallenge]:
    c, s, d = _validate_seeded_params(c, s, d)
    token_hash = fnv1a(token)
    challenges: list[CapChallenge] = []
    for i in range(c):
        idx = str(i + 1)
        salt_seed = fnv1a_resume(token_hash, idx)
        target_seed = fnv1a_resume(salt_seed, "d")
        challenges.append(
            CapChallenge(
                salt=prng_from_hash(salt_seed, s),
                target=prng_from_hash(target_seed, d),
            )
        )
    return challenges


def cap_hash_bytes(salt: str, nonce: int | str) -> bytes:
    return hashlib.sha256(f"{salt}{nonce}".encode("utf-8")).digest()


def cap_hash_hex(salt: str, nonce: int | str) -> str:
    return cap_hash_bytes(salt, nonce).hex()


def cap_pow_matches(hash_bytes: bytes, target: str) -> bool:
    target = (target or "").strip().lower()
    if not _is_hex(target):
        raise ValueError(f"Cap target must be hex, got {target!r}")
    if len(target) > len(hash_bytes) * 2:
        raise ValueError(f"Cap target is longer than SHA-256 digest: {len(target)} hex chars")
    full_bytes = len(target) // 2
    for i in range(full_bytes):
        if hash_bytes[i] != int(target[i * 2 : i * 2 + 2], 16):
            return False
    if len(target) & 1:
        return (hash_bytes[full_bytes] >> 4) == int(target[-1], 16)
    return True


def verify_cap_solution(salt: str, target: str, nonce: int | str) -> bool:
    return cap_pow_matches(cap_hash_bytes(salt, nonce), target)


def cap_rsw_solution_hex(
    N: int | str,
    x: int | str,
    t: int,
    *,
    timeout_sec: int | float | None = None,
) -> str | None:
    """Solve Cap format-2 RSW time-lock puzzle by repeated modular squaring.

    The widget fallback does exactly this:
    `for i in range(t): y = (y * y) % N`, then submits `{y: y.toString(16)}`.
    """

    challenge = CapRswChallenge(
        N=_normalize_hex(N, "N"),
        x=_normalize_hex(x, "x"),
        t=_validate_rsw_t(t),
    )
    y, _diag = solve_cap_rsw(challenge, timeout_sec=timeout_sec)
    return y


def verify_cap_rsw_solution(
    N: int | str,
    x: int | str,
    t: int,
    y: int | str,
    *,
    timeout_sec: int | float | None = None,
) -> bool:
    solved = cap_rsw_solution_hex(N, x, t, timeout_sec=timeout_sec)
    if solved is None:
        return False
    return _normalize_rsw_y(solved) == _normalize_rsw_y(y)


def solve_cap_rsw(
    challenge: CapRswChallenge | dict[str, Any],
    *,
    timeout_sec: int | float | None = None,
    deadline: float | None = None,
) -> tuple[str | None, dict[str, Any]]:
    started = time.monotonic()
    item = _coerce_rsw_challenge(challenge)
    modulus = int(item.N, 16)
    y = int(item.x, 16) % modulus
    if modulus <= 1:
        raise ValueError("Cap RSW N must be > 1")
    deadline = deadline or (started + float(timeout_sec) if timeout_sec else None)
    # Same cadence as Cap widget JS fallback: ~50 progress slices.
    check_every = max(64, item.t // 50)
    for step in range(item.t):
        if deadline is not None and step and step % check_every == 0 and time.monotonic() >= deadline:
            return None, _cap_diag(started, step, 0, "timeout")
        y = (y * y) % modulus
    return format(y, "x"), _cap_diag(started, item.t, 1, None)


def solve_cap_pow(
    salt: str,
    target: str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
    deadline: float | None = None,
) -> tuple[int | None, int]:
    return _solve_cap_pow_range(salt, target, start, int(start) + int(max_attempts), deadline)


def solve_cap_challenges(
    challenges: Iterable[CapChallenge | tuple[str, str] | list[str] | dict[str, Any]],
    *,
    start: int = 0,
    max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
    workers: int = 1,
    timeout_sec: int | float | None = None,
) -> tuple[list[int] | None, dict[str, Any]]:
    items = [_coerce_challenge(ch) for ch in challenges]
    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    checked_total = 0
    solutions: list[int | None] = [None] * len(items)
    workers = max(1, int(workers or 1))
    max_attempts_per_challenge = max(1, int(max_attempts_per_challenge))

    if workers <= 1 or len(items) <= 1:
        for idx, ch in enumerate(items):
            if deadline is not None and time.monotonic() >= deadline:
                return None, _cap_diag(started, checked_total, idx, "timeout")
            nonce, checked = solve_cap_pow(
                ch.salt,
                ch.target,
                start=start,
                max_attempts=max_attempts_per_challenge,
                deadline=deadline,
            )
            checked_total += checked
            if nonce is None:
                reason = "timeout" if deadline is not None and time.monotonic() >= deadline else "not_found"
                return None, _cap_diag(started, checked_total, idx, reason)
            solutions[idx] = nonce
        return [int(x) for x in solutions if x is not None], _cap_diag(started, checked_total, len(items), None)

    pool = ProcessPoolExecutor(max_workers=min(workers, len(items)))
    futures = {
        pool.submit(
            _solve_cap_pow_range,
            ch.salt,
            ch.target,
            int(start),
            int(start) + max_attempts_per_challenge,
            deadline,
        ): idx
        for idx, ch in enumerate(items)
    }
    try:
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        for fut in as_completed(futures, timeout=timeout):
            idx = futures[fut]
            nonce, checked = fut.result()
            checked_total += checked
            if nonce is None:
                for other in futures:
                    other.cancel()
                reason = "timeout" if deadline is not None and time.monotonic() >= deadline else "not_found"
                return None, _cap_diag(started, checked_total, idx, reason)
            solutions[idx] = nonce
    except FuturesTimeout:
        for fut in futures:
            fut.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        return None, _cap_diag(started, checked_total, sum(x is not None for x in solutions), "timeout")
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)

    if any(x is None for x in solutions):
        return None, _cap_diag(started, checked_total, sum(x is not None for x in solutions), "incomplete")
    return [int(x) for x in solutions if x is not None], _cap_diag(started, checked_total, len(items), None)


def solve_cap_seeded(
    token: str,
    *,
    c: int = DEFAULT_CHALLENGE_COUNT,
    s: int = DEFAULT_CHALLENGE_SIZE,
    d: int = DEFAULT_CHALLENGE_DIFFICULTY,
    start: int = 0,
    max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
    workers: int = 1,
    timeout_sec: int | float | None = None,
) -> CapSolution | None:
    started = time.monotonic()
    challenges = cap_seeded_challenges(token, c=c, s=s, d=d)
    nonces, diag = solve_cap_challenges(
        challenges,
        start=start,
        max_attempts_per_challenge=max_attempts_per_challenge,
        workers=workers,
        timeout_sec=timeout_sec,
    )
    if nonces is None:
        return None
    return CapSolution(
        token=token,
        challenges=challenges,
        solutions=nonces,
        format=1,
        took_ms=int((time.monotonic() - started) * 1000),
        checked=int(diag.get("checked", 0)),
    )


def solve_cap_format2_challenges(
    challenges: Iterable[CapChallenge | CapRswChallenge],
    *,
    start: int = 0,
    max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
    workers: int = 1,
    timeout_sec: int | float | None = None,
) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
    items = list(challenges)
    if all(isinstance(ch, CapChallenge) and ch.protocol == "sha256-pow" for ch in items):
        nonces, diag = solve_cap_challenges(
            items,
            start=start,
            max_attempts_per_challenge=max_attempts_per_challenge,
            workers=workers,
            timeout_sec=timeout_sec,
        )
        if nonces is None:
            return None, diag
        return [{"nonce": int(n)} for n in nonces], diag

    started = time.monotonic()
    deadline = started + float(timeout_sec) if timeout_sec else None
    checked_total = 0
    solutions: list[dict[str, Any]] = []
    for idx, ch in enumerate(items):
        if deadline is not None and time.monotonic() >= deadline:
            return None, _cap_diag(started, checked_total, idx, "timeout")
        if isinstance(ch, CapChallenge) and ch.protocol == "sha256-pow":
            nonce, checked = solve_cap_pow(
                ch.salt,
                ch.target,
                start=start,
                max_attempts=max_attempts_per_challenge,
                deadline=deadline,
            )
            checked_total += checked
            if nonce is None:
                reason = "timeout" if deadline is not None and time.monotonic() >= deadline else "not_found"
                return None, _cap_diag(started, checked_total, idx, reason)
            solutions.append({"nonce": int(nonce)})
        elif isinstance(ch, CapRswChallenge):
            y_hex, diag = solve_cap_rsw(ch, deadline=deadline)
            checked_total += int(diag.get("checked", 0))
            if y_hex is None:
                return None, _cap_diag(started, checked_total, idx, diag.get("error") or "timeout")
            solutions.append({"y": y_hex})
        else:
            protocol = getattr(ch, "protocol", "unknown")
            return None, _cap_diag(started, checked_total, len(solutions), f"unsupported:{protocol}")
    return solutions, _cap_diag(started, checked_total, len(solutions), None)


def parse_cap_challenge_response(
    data: Any,
) -> tuple[str | None, int, list[CapChallenge | CapRswChallenge | CapUnsupportedChallenge], bool]:
    """Return (token, format, challenges, has_unsupported_protocol)."""

    if isinstance(data, list):
        return None, 1, [_coerce_challenge(x) for x in data], False
    if not isinstance(data, dict):
        raise ValueError("Cap challenge must be a JSON object or challenge list")

    token = data.get("token")
    token = str(token) if token is not None else None
    fmt = int(data.get("format") or 1)

    if fmt == 2:
        entries = data.get("challenges")
        if not isinstance(entries, list):
            raise ValueError("Cap format=2 requires challenges list")
        challenges: list[CapChallenge | CapRswChallenge | CapUnsupportedChallenge] = []
        unsupported = False
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Cap format=2 challenge entry must be object")
            proto = str(entry.get("protocol") or "")
            if proto != "sha256-pow":
                if proto == "rsw":
                    challenges.append(_coerce_rsw_challenge(entry))
                else:
                    unsupported = True
                    payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
                    challenges.append(CapUnsupportedChallenge(protocol=proto or "unknown", payload=payload))
                continue
            payload = entry.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("Cap sha256-pow challenge requires payload object")
            salt = str(payload.get("salt") or "")
            target = str(payload.get("target") or "")
            if not salt or not target:
                raise ValueError("Cap sha256-pow challenge requires salt/target")
            challenges.append(CapChallenge(salt=salt, target=target, protocol=proto))
        return token, 2, challenges, unsupported

    challenge = data.get("challenge", data.get("challenges"))
    if isinstance(challenge, list):
        return token, 1, [_coerce_challenge(x) for x in challenge], False
    if isinstance(challenge, dict):
        if not token:
            raise ValueError("Cap seeded challenge requires token")
        c = int(challenge.get("c", challenge.get("challengeCount", DEFAULT_CHALLENGE_COUNT)))
        s = int(challenge.get("s", challenge.get("challengeSize", DEFAULT_CHALLENGE_SIZE)))
        d = int(challenge.get("d", challenge.get("challengeDifficulty", DEFAULT_CHALLENGE_DIFFICULTY)))
        return token, 1, cap_seeded_challenges(token, c=c, s=s, d=d), False
    if token:
        c = int(data.get("c", DEFAULT_CHALLENGE_COUNT))
        s = int(data.get("s", DEFAULT_CHALLENGE_SIZE))
        d = int(data.get("d", DEFAULT_CHALLENGE_DIFFICULTY))
        return token, 1, cap_seeded_challenges(token, c=c, s=s, d=d), False
    raise ValueError("Cap challenge response requires challenge/challenges or token+c/s/d")


def _solve_cap_pow_range(
    salt: str,
    target: str,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, int]:
    target = (target or "").strip().lower()
    if not _is_hex(target):
        raise ValueError(f"Cap target must be hex, got {target!r}")
    if len(target) > 64:
        raise ValueError(f"Cap target is longer than SHA-256 digest: {len(target)} hex chars")
    checked = 0
    for nonce in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, checked
        checked += 1
        if cap_pow_matches(cap_hash_bytes(salt, nonce), target):
            return nonce, checked
    return None, checked


def _coerce_challenge(value: CapChallenge | tuple[str, str] | list[str] | dict[str, Any]) -> CapChallenge:
    if isinstance(value, CapChallenge):
        return value
    if isinstance(value, dict):
        if "payload" in value and isinstance(value.get("payload"), dict):
            payload = value["payload"]
            return CapChallenge(
                salt=str(payload.get("salt") or ""),
                target=str(payload.get("target") or ""),
                protocol=str(value.get("protocol") or "sha256-pow"),
            )
        return CapChallenge(
            salt=str(value.get("salt") or value.get("s") or ""),
            target=str(value.get("target") or value.get("d") or ""),
            protocol=str(value.get("protocol") or "sha256-pow"),
        )
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return CapChallenge(salt=str(value[0]), target=str(value[1]))
    raise ValueError(f"invalid Cap challenge item: {value!r}")


def _coerce_rsw_challenge(value: CapRswChallenge | dict[str, Any]) -> CapRswChallenge:
    if isinstance(value, CapRswChallenge):
        return value
    if not isinstance(value, dict):
        raise ValueError(f"invalid Cap RSW challenge item: {value!r}")
    payload = value.get("payload") if isinstance(value.get("payload"), dict) else value
    return CapRswChallenge(
        N=_normalize_hex(payload.get("N"), "N"),
        x=_normalize_hex(payload.get("x"), "x"),
        t=_validate_rsw_t(payload.get("t")),
    )


def _normalize_hex(value: Any, name: str) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"Cap RSW {name} must be non-negative")
        text = format(value, "x")
    else:
        text = str(value or "").strip().lower()
        if text.startswith("0x"):
            text = text[2:]
    if not text or not _is_hex(text):
        raise ValueError(f"Cap RSW {name} must be hex")
    return text.lstrip("0") or "0"


def _normalize_rsw_y(value: Any) -> str:
    return _normalize_hex(value, "y")


def _validate_rsw_t(value: Any) -> int:
    try:
        t = int(value)
    except Exception as e:
        raise ValueError("Cap RSW t must be an integer") from e
    if t < 0 or t > MAX_RSW_T:
        raise ValueError(f"Cap RSW t must be 0..{MAX_RSW_T}")
    return t


def _cap_diag(started: float, checked: int, solved_count: int, error: str | None) -> dict[str, Any]:
    return {
        "took_ms": int((time.monotonic() - started) * 1000),
        "checked": checked,
        "solved_count": solved_count,
        **({"error": error} if error else {}),
    }


def _validate_seeded_params(c: int, s: int, d: int) -> tuple[int, int, int]:
    c = int(c)
    s = int(s)
    d = int(d)
    if c < 1 or c > MAX_CHALLENGE_COUNT:
        raise ValueError(f"Cap c must be 1..{MAX_CHALLENGE_COUNT}")
    if s < 1 or s > MAX_CHALLENGE_SIZE:
        raise ValueError(f"Cap s must be 1..{MAX_CHALLENGE_SIZE}")
    if d < 1 or d > MAX_CHALLENGE_DIFFICULTY:
        raise ValueError(f"Cap d must be 1..{MAX_CHALLENGE_DIFFICULTY}")
    return c, s, d


def _is_hex(value: str) -> bool:
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


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


def _api_url(api_endpoint: str | None, path: str) -> str | None:
    if not api_endpoint:
        return None
    base = api_endpoint.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _infer_redeem_url(challenge_url: str | None) -> str | None:
    if not challenge_url:
        return None
    if challenge_url.rstrip("/").endswith("/challenge"):
        return challenge_url.rstrip("/")[: -len("/challenge")] + "/redeem"
    return None


def _redact_cap_response(data: Any) -> Any:
    if isinstance(data, dict):
        out = dict(data)
        token = out.get("token")
        if isinstance(token, str) and len(token) > 24:
            out["token"] = token[:12] + "..." + token[-8:]
        return out
    return data


class CapSolver:
    """Cap/@cap.js proof-of-work protocol solver.

    This provider mirrors Cap v1 seeded SHA-256 PoW, format-2 `sha256-pow`,
    and format-2 `rsw` time-lock puzzles. It deliberately does not launch a
    browser and marks instrumentation-only challenges unsupported instead of
    pretending to solve browser telemetry.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        token: str | None = None,
        c: int = DEFAULT_CHALLENGE_COUNT,
        s: int = DEFAULT_CHALLENGE_SIZE,
        d: int = DEFAULT_CHALLENGE_DIFFICULTY,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        api_endpoint: str | None = None,
        redeem_url: str | None = None,
        redeem: bool = False,
        start: int = 0,
        max_attempts_per_challenge: int = DEFAULT_MAX_ATTEMPTS_PER_CHALLENGE,
        workers: int = 1,
        timeout_sec: int = 60,
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
            "api_endpoint": api_endpoint,
            "redeem_url": redeem_url,
            "redeem": redeem,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts_per_challenge": max_attempts_per_challenge,
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
                out = output_root / "cap_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="cap",
                ok=ok,
                captcha_type="proof_of_work",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("token_prefix"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            if api_endpoint:
                challenge_url = challenge_url or _api_url(api_endpoint, "challenge")
                redeem_url = redeem_url or _api_url(api_endpoint, "redeem")
                redeem = True if redeem_url else redeem

            data = self._load_challenge(
                token=token,
                c=c,
                s=s,
                d=d,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            if isinstance(data, dict) and data.get("instrumentation"):
                errors.append("Cap instrumentation challenge is not supported by protocol-only solver")
                diagnostics["unsupported"] = "instrumentation"
                raw["challenge"] = _redact_cap_response(data)
                return finish(ok=False)

            parsed_token, fmt, parsed_challenges, unsupported = parse_cap_challenge_response(data)
            if unsupported:
                unsupported_protocols = sorted(
                    {
                        ch.protocol
                        for ch in parsed_challenges
                        if isinstance(ch, CapUnsupportedChallenge)
                        or ch.protocol not in {"sha256-pow", "rsw"}
                    }
                )
                errors.append(f"unsupported Cap format-2 protocols: {', '.join(unsupported_protocols)}")
                diagnostics["unsupported_protocols"] = unsupported_protocols
                raw["challenge"] = _redact_cap_response(data)
                return finish(ok=False)

            challenges = [ch for ch in parsed_challenges if isinstance(ch, (CapChallenge, CapRswChallenge))]
            protocols = [ch.protocol for ch in challenges]
            raw["challenge"] = _redact_cap_response(data)
            diagnostics.update(
                {
                    "format": fmt,
                    "challenge_count": len(challenges),
                    "protocols": protocols,
                    "target_lengths": sorted(
                        {len(ch.target) for ch in challenges if isinstance(ch, CapChallenge)}
                    ),
                    "rsw_t": [ch.t for ch in challenges if isinstance(ch, CapRswChallenge)],
                    "token_prefix": parsed_token[:12] if parsed_token else None,
                }
            )
            solve_started = time.monotonic()
            if fmt == 2:
                fmt2_solutions, solve_diag = solve_cap_format2_challenges(
                    challenges,
                    start=start,
                    max_attempts_per_challenge=max_attempts_per_challenge,
                    workers=workers,
                    timeout_sec=timeout_sec,
                )
                nonces = [
                    int(sol["nonce"])
                    for sol in (fmt2_solutions or [])
                    if isinstance(sol, dict) and "nonce" in sol
                ]
            else:
                nonces, solve_diag = solve_cap_challenges(
                    challenges,
                    start=start,
                    max_attempts_per_challenge=max_attempts_per_challenge,
                    workers=workers,
                    timeout_sec=timeout_sec,
                )
                fmt2_solutions = None
            diagnostics.update({f"solve_{k}": v for k, v in solve_diag.items()})
            if fmt == 2 and fmt2_solutions is None:
                err = solve_diag.get("error") or "not_found"
                errors.append(f"Cap solve failed: {err}")
                return finish(ok=False)
            if fmt != 2 and nonces is None:
                err = solve_diag.get("error") or "not_found"
                errors.append(f"Cap solve failed: {err}")
                return finish(ok=False)

            if fmt == 2:
                solutions: list[int] | list[dict[str, Any]] = fmt2_solutions or []
            else:
                solutions = [int(n) for n in nonces]
            solution = CapSolution(
                token=parsed_token,
                challenges=challenges,
                solutions=solutions,
                format=fmt,
                took_ms=int((time.monotonic() - solve_started) * 1000),
                checked=int(solve_diag.get("checked", 0)),
            )
            raw["solution"] = {
                "format": fmt,
                "solutions": solution.solutions,
                "checked": solution.checked,
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics.update(
                {
                    "checked": solution.checked,
                    "solve_ms": solution.took_ms,
                    "first_nonce": nonces[0] if nonces else None,
                }
            )

            final_ticket = solution.submit_body_json()
            verify_code = "solved"
            should_redeem = bool(redeem or redeem_url)
            redeem_url = redeem_url or (_infer_redeem_url(challenge_url) if should_redeem else None)
            if should_redeem:
                if not redeem_url:
                    errors.append("redeem requested but redeem_url cannot be inferred")
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
                resp = requests.post(
                    redeem_url,
                    headers={"Content-Type": "application/json", **(headers or {})},
                    json=solution.submit_body,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                raw["redeemResponse"] = {"status": resp.status_code, "url": redeem_url}
                resp.raise_for_status()
                redeem_data = resp.json()
                raw["redeemResponse"]["json"] = _redact_cap_response(redeem_data)
                if not isinstance(redeem_data, dict):
                    raise ValueError("Cap redeem response is not a JSON object")
                if not redeem_data.get("success"):
                    errors.append(str(redeem_data.get("error") or redeem_data.get("reason") or "redeem_failed"))
                    return finish(ok=False, ticket=final_ticket, verify_code="redeem_failed")
                final_ticket = str(redeem_data.get("token") or final_ticket)
                verify_code = "redeemed"
                diagnostics["redeemed"] = True
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        token: str | None,
        c: int,
        s: int,
        d: int,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> Any:
        if challenge_json is not None:
            if isinstance(challenge_json, str):
                return _load_json_arg(challenge_json)
            return challenge_json
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            return loaded
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            data = resp.json()
            raw["challengeSource"] = "url"
            return data
        if token:
            raw["challengeSource"] = "token"
            return {"token": token, "challenge": {"c": c, "s": s, "d": d}}
        raise ValueError("Cap requires token, challenge_json, challenge_file, challenge_url or api_endpoint")
