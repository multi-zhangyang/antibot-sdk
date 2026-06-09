from __future__ import annotations

import asyncio
import hashlib
import html
import json
import random
import re
import string
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_BITS = 16
DEFAULT_VERSION = 1
DEFAULT_EXT = "sha256"
DEFAULT_RESPONSE_FIELD = "hashcash"
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ALPHANUM = string.ascii_letters + string.digits


@dataclass(slots=True)
class ActiveHashcashChallenge:
    resource: str
    bits: int = DEFAULT_BITS
    date: str | None = None
    version: int = DEFAULT_VERSION
    rand: str | None = None
    ext: str = DEFAULT_EXT
    response_field: str = DEFAULT_RESPONSE_FIELD
    raw: dict[str, Any] | None = None

    @property
    def date_value(self) -> str:
        return self.date or date.today().strftime("%y%m%d")

    @property
    def rand_value(self) -> str:
        return self.rand or random_alphanumeric(16)

    def prefix(self, *, rand: str | None = None) -> str:
        return ":".join(
            [
                str(int(self.version)),
                str(int(self.bits)),
                self.date_value,
                self.resource,
                self.ext,
                rand if rand is not None else self.rand_value,
            ]
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "bits": self.bits,
            "date": self.date_value,
            "resource": self.resource,
            "ext": self.ext,
            "rand": self.rand,
            "responseField": self.response_field,
        }


@dataclass(slots=True)
class ActiveHashcashSolution:
    challenge: ActiveHashcashChallenge
    rand: str
    counter: str
    stamp: str
    hash_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def submit_body(self) -> dict[str, str]:
        return build_activehashcash_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "stamp": self.stamp,
            "rand": self.rand,
            "counter": self.counter,
            "hash": self.hash_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "submitBody": self.submit_body,
        }


def random_alphanumeric(length: int = 16) -> str:
    rng = random.SystemRandom()
    return "".join(rng.choice(ALPHANUM) for _ in range(int(length)))


def activehashcash_hash_hex(stamp: str, *, ext: str = DEFAULT_EXT) -> str:
    data = str(stamp).encode("utf-8")
    if ext == DEFAULT_EXT:
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha1(data).hexdigest()


def count_leading_zero_bits_hex(hex_digest: str) -> int:
    total = 0
    for ch in str(hex_digest).lower():
        val = int(ch, 16)
        if val == 0:
            total += 4
            continue
        return total + (4 - val.bit_length())
    return total


def activehashcash_hash_matches(hex_digest: str, bits: int) -> bool:
    return count_leading_zero_bits_hex(hex_digest) >= int(bits)


def parse_activehashcash_challenge(
    value: ActiveHashcashChallenge | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> ActiveHashcashChallenge:
    if isinstance(value, ActiveHashcashChallenge):
        if response_field:
            value.response_field = response_field
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("ActiveHashcash challenge is empty")
        if text.startswith("@"):
            return parse_activehashcash_challenge(Path(text[1:]).read_text(encoding="utf-8"), response_field=response_field)
        if "<" in text and ("data-hashcash" in text or "hashcash" in text):
            return parse_activehashcash_challenge(extract_activehashcash_from_html(text), response_field=response_field)
        if text.startswith("{"):
            return parse_activehashcash_challenge(json.loads(text), response_field=response_field)
        stamp = parse_activehashcash_stamp(text)
        return ActiveHashcashChallenge(
            resource=stamp["resource"],
            bits=int(stamp["bits"]),
            date=stamp["date"],
            version=int(stamp["version"]),
            rand=stamp["rand"],
            ext=stamp["ext"],
            response_field=response_field or DEFAULT_RESPONSE_FIELD,
            raw={"stamp": text, "counter": stamp["counter"]},
        )
    if not isinstance(value, dict):
        raise ValueError("ActiveHashcash challenge must be string, JSON object, HTML, or ActiveHashcashChallenge")
    item = value.get("hashcash") if isinstance(value.get("hashcash"), dict) else value
    if isinstance(item.get("stamp"), str):
        parsed = parse_activehashcash_challenge(item["stamp"], response_field=response_field)
        parsed.raw = value
        parsed.response_field = response_field or _first_str(item, "responseField", "response_field", "field", "name") or parsed.response_field
        return parsed
    resource = _first_str(item, "resource", "host", "domain")
    if not resource:
        raise ValueError("ActiveHashcash JSON requires resource/host/domain")
    bits = int(item.get("bits", item.get("difficulty", DEFAULT_BITS)))
    if not 1 <= bits <= 63:
        raise ValueError("ActiveHashcash bits must be between 1 and 63")
    version = int(item.get("version", DEFAULT_VERSION))
    if version != 1:
        raise ValueError("ActiveHashcash version must be 1")
    ext = str(item.get("ext", DEFAULT_EXT))
    if ext not in (DEFAULT_EXT, ""):
        raise ValueError("ActiveHashcash ext must be sha256 or empty sha1 fallback")
    return ActiveHashcashChallenge(
        resource=str(resource),
        bits=bits,
        date=_first_str(item, "date") or date.today().strftime("%y%m%d"),
        version=version,
        rand=_first_str(item, "rand"),
        ext=ext,
        response_field=response_field or _first_str(item, "responseField", "response_field", "field", "name") or DEFAULT_RESPONSE_FIELD,
        raw=value,
    )


def parse_activehashcash_stamp(stamp: str) -> dict[str, str]:
    parts = str(stamp).split(":")
    if len(parts) < 7:
        raise ValueError("ActiveHashcash stamp requires ver:bits:date:resource:ext:rand:counter")
    version, bits, stamp_date = parts[:3]
    resource = ":".join(parts[3:-3])
    ext, rand, counter = parts[-3:]
    if version != "1":
        raise ValueError("ActiveHashcash stamp version must be 1")
    if not bits.isdigit() or not (1 <= int(bits) <= 63):
        raise ValueError("ActiveHashcash stamp bits must be 1..63")
    if not re.fullmatch(r"\d{6}", stamp_date):
        raise ValueError("ActiveHashcash date must be YYMMDD")
    if ext not in (DEFAULT_EXT, ""):
        raise ValueError("ActiveHashcash ext must be sha256 or empty sha1 fallback")
    if not resource:
        raise ValueError("ActiveHashcash resource is empty")
    if not rand:
        raise ValueError("ActiveHashcash rand is empty")
    if not counter or not str(counter).isdigit():
        raise ValueError("ActiveHashcash counter must be decimal")
    return {
        "version": version,
        "bits": bits,
        "date": stamp_date,
        "resource": resource,
        "ext": ext,
        "rand": rand,
        "counter": counter,
    }


def extract_activehashcash_from_html(html_text: str) -> dict[str, Any]:
    text = str(html_text)
    m = re.search(r"<input\b(?=[^>]*\bdata-hashcash\b)(?P<attrs>[^>]*)>", text, flags=re.I | re.S)
    if not m:
        raise ValueError("ActiveHashcash HTML does not contain input[data-hashcash]")
    attrs = _parse_attrs(m.group("attrs"))
    raw = attrs.get("data-hashcash")
    if not raw:
        raise ValueError("input[data-hashcash] is empty")
    payload = json.loads(html.unescape(raw))
    payload["responseField"] = attrs.get("name") or attrs.get("id") or DEFAULT_RESPONSE_FIELD
    return payload


def solve_activehashcash_challenge(
    challenge: ActiveHashcashChallenge | dict[str, Any] | str,
    *,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> ActiveHashcashSolution | None:
    item = parse_activehashcash_challenge(challenge)
    started = time.monotonic()
    rand_value = item.rand_value
    prefix = item.prefix(rand=rand_value)
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None
    counter, digest, attempts = solve_activehashcash_counter(
        prefix,
        bits=item.bits,
        ext=item.ext,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        deadline_epoch=deadline_epoch,
    )
    if counter is None or digest is None:
        return None
    stamp = f"{prefix}:{counter}"
    return ActiveHashcashSolution(
        challenge=item,
        rand=rand_value,
        counter=str(counter),
        stamp=stamp,
        hash_hex=digest,
        attempts=attempts,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def solve_activehashcash_counter(
    prefix: str,
    *,
    bits: int,
    ext: str = DEFAULT_EXT,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    if workers <= 1 or max_attempts < 100_000:
        return _solve_range(str(prefix), int(bits), str(ext), start, start + max_attempts, deadline_epoch)
    chunk = max(1, max_attempts // workers)
    ranges = []
    for idx in range(workers):
        lo = start + idx * chunk
        hi = start + max_attempts if idx == workers - 1 else min(start + max_attempts, lo + chunk)
        if lo < hi:
            ranges.append((lo, hi))
    checked_total = 0
    completed: dict[int, tuple[int | None, str | None, int]] = {}
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {pool.submit(_solve_range, str(prefix), int(bits), str(ext), lo, hi, deadline_epoch): idx for idx, (lo, hi) in enumerate(ranges)}
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
                p_counter, p_digest, _p_checked = completed[prior_idx]
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


def verify_activehashcash_solution(
    challenge: ActiveHashcashChallenge | dict[str, Any] | str,
    solution: ActiveHashcashSolution | dict[str, Any] | str,
    *,
    min_date: str | None = None,
    check_not_future: bool = False,
) -> bool:
    try:
        item = parse_activehashcash_challenge(challenge)
        if isinstance(solution, ActiveHashcashSolution):
            stamp_text = solution.stamp
        elif isinstance(solution, dict):
            stamp_text = str(solution.get("stamp") or solution.get("hashcash") or solution.get(item.response_field) or "")
        else:
            stamp_text = str(solution)
        stamp = parse_activehashcash_stamp(stamp_text)
        if stamp["resource"] != item.resource:
            return False
        if int(stamp["bits"]) < int(item.bits):
            return False
        if stamp["ext"] != item.ext:
            return False
        if min_date and stamp["date"] < min_date:
            return False
        if check_not_future and stamp["date"] > date.today().strftime("%y%m%d"):
            return False
        return activehashcash_hash_matches(activehashcash_hash_hex(stamp_text, ext=stamp["ext"]), int(stamp["bits"]))
    except Exception:
        return False


def build_activehashcash_submit_body(
    challenge: ActiveHashcashChallenge | dict[str, Any] | str,
    solution: ActiveHashcashSolution | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> dict[str, str]:
    item = parse_activehashcash_challenge(challenge, response_field=response_field)
    if isinstance(solution, ActiveHashcashSolution):
        value = solution.stamp
    elif isinstance(solution, dict):
        value = str(solution.get("stamp") or solution.get("hashcash") or solution.get(item.response_field) or "")
    else:
        value = str(solution)
    return {response_field or item.response_field: value}


class ActiveHashcashSolver:
    """BaseSecrete/active_hashcash Rails Hashcash protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        resource: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_html: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        submit_format: str = "form",
        bits: int | None = None,
        stamp_date: str | None = None,
        rand: str | None = None,
        response_field: str | None = None,
        start: int = 0,
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
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "submit_url": submit_url,
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
                out = output_root / "activehashcash_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="activehashcash",
                ok=ok,
                captcha_type="rails_hashcash_sha256",
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
                resource=resource,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_html=challenge_html,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=_merge_headers(headers, user_agent),
                raw=raw,
            )
            if isinstance(source, dict):
                if bits is not None:
                    source["bits"] = bits
                if stamp_date is not None:
                    source["date"] = stamp_date
                if rand is not None:
                    source["rand"] = rand
            item = parse_activehashcash_challenge(source, response_field=response_field)
            raw["challenge"] = item.to_payload()
            diagnostics.update({"resource": item.resource, "bits": item.bits, "date": item.date_value, "response_field": item.response_field})
            solution = solve_activehashcash_challenge(item, start=start, max_attempts=max_attempts, workers=workers, timeout_sec=timeout_sec)
            if solution is None:
                errors.append("ActiveHashcash solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_activehashcash_solution(item, solution):
                errors.append("ActiveHashcash internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            submit_body = build_activehashcash_submit_body(item, solution, response_field=response_field)
            raw["solution"] = {**solution.to_payload(), "submitBody": submit_body}
            diagnostics.update({"counter": solution.counter, "rand": solution.rand, "attempts": solution.attempts, "solve_ms": solution.solve_time_ms})
            if submit:
                if not submit_url:
                    errors.append("--submit requires submit_url")
                    return finish(ok=False, ticket=_json_body(submit_body), verify_code="missing_submit_url")
                resp = _post_submit(submit_url, submit_body, submit_format=submit_format, headers=_merge_headers(headers, user_agent), timeout_sec=timeout_sec, proxy_server=proxy_server)
                raw["submitResponse"] = resp
                if not resp.get("ok"):
                    errors.append(f"ActiveHashcash submit failed: HTTP {resp.get('status')}")
                    return finish(ok=False, ticket=_json_body(submit_body), verify_code="submit_failed")
                return finish(ok=True, ticket=_json_body(submit_body), verify_code="validated")
            return finish(ok=True, ticket=_json_body(submit_body), verify_code="solved")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


def _solve_range(prefix: str, bits: int, ext: str, start: int, end_exclusive: int, deadline_epoch: float | None = None) -> tuple[int | None, str | None, int]:
    checked = 0
    target_bits = int(bits)
    hash_fn = hashlib.sha256 if ext == DEFAULT_EXT else hashlib.sha1
    for counter in range(max(0, int(start)), max(0, int(end_exclusive))):
        if deadline_epoch is not None and checked and checked % 8192 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        stamp = f"{prefix}:{counter}"
        digest = hash_fn(stamp.encode("utf-8")).hexdigest()
        checked += 1
        if activehashcash_hash_matches(digest, target_bits):
            return counter, digest, checked
    return None, None, checked


def _load_source(
    *,
    resource: str | None,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_html: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    if resource:
        raw["challengeSource"] = "resource"
        return {"resource": resource}
    if challenge_html:
        raw["challengeSource"] = "html"
        return extract_activehashcash_from_html(challenge_html)
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("ActiveHashcash requires resource, challenge_json, challenge_file, challenge_html or challenge_url")
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
    return extract_activehashcash_from_html(resp.text)


def _post_submit(submit_url: str, submit_body: dict[str, str], *, submit_format: str, headers: dict[str, str], timeout_sec: int, proxy_server: str | None) -> dict[str, Any]:
    if submit_format not in {"json", "form"}:
        raise ValueError("submit_format must be json or form")
    if submit_format == "json":
        resp = requests.post(submit_url, json=submit_body, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    else:
        resp = requests.post(submit_url, data=submit_body, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
    try:
        body: Any = resp.json()
    except Exception:
        body = resp.text[:500]
    return {"ok": 200 <= resp.status_code < 400 and not (isinstance(body, dict) and body.get("ok") is False), "status": resp.status_code, "body": body}


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
