from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT = 20
DEFAULT_MAX_ATTEMPTS = 100_000_000
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Accept": "application/json,text/plain,*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}
HASHPTCHA_HASH_BITS = {"MD5": 128, "SHA256": 256}


@dataclass(frozen=True, slots=True)
class HashptchaTask:
    token: str
    hash_type: str
    target: str
    start_point: str = "00000000"
    secret_key: str | None = None
    response_field: str = "hashptcha-response"
    raw: dict[str, Any] | None = None

    @property
    def hash_bits(self) -> int:
        return HASHPTCHA_HASH_BITS[self.hash_type]

    @property
    def start_int(self) -> int:
        return int(self.start_point, 2)

    @property
    def min_value_bits(self) -> int:
        return max(8, len(self.start_point))


@dataclass(frozen=True, slots=True)
class HashptchaSolution:
    task: HashptchaTask
    value: str
    value_int: int
    hash_hex: str
    hash_binary_prefix: str
    attempts: int
    elapsed_ms: int

    @property
    def verify_body(self) -> dict[str, str]:
        body = {"token": self.task.token, "value": self.value}
        if self.task.secret_key:
            body["secret_key"] = self.task.secret_key
        return body

    @property
    def submit_body(self) -> dict[str, str]:
        return {self.task.response_field: json.dumps(self.verify_body, separators=(",", ":"))}


def normalize_hashptcha_hash_type(value: Any) -> str:
    text = str(value or "").strip().upper().replace("-", "")
    if text in {"SHA", "SHA2", "SHA256"}:
        return "SHA256"
    if text == "MD5":
        return "MD5"
    raise ValueError("Hashptcha hash_type must be MD5 or SHA256")


def normalize_hashptcha_binary(value: Any, *, min_bits: int = 8, field: str = "binary") -> str:
    text = str(value if value is not None else "").strip()
    if text.startswith("0b"):
        text = text[2:]
    if not text:
        text = "0"
    if any(ch not in "01" for ch in text):
        raise ValueError(f"Hashptcha {field} must be a binary string")
    width = max(int(min_bits), len(text), 8)
    width = 8 * math.ceil(width / 8)
    return text.zfill(width)


def hashptcha_int_to_binary(value: int, *, min_bits: int = 8) -> str:
    value = int(value)
    if value < 0:
        raise ValueError("Hashptcha value must be non-negative")
    bits = bin(value)[2:]
    width = max(int(min_bits), len(bits), 8)
    width = 8 * math.ceil(width / 8)
    return bits.zfill(width)


def hashptcha_binary_to_bytes(value: str) -> bytes:
    binary = normalize_hashptcha_binary(value, min_bits=len(str(value or "")), field="value")
    return int(binary, 2).to_bytes(len(binary) // 8, byteorder="big")


def hashptcha_hash(data: bytes, hash_type: str) -> bytes:
    alg = normalize_hashptcha_hash_type(hash_type)
    if alg == "MD5":
        return hashlib.md5(data).digest()  # noqa: S324 - MD5 is the upstream Hashptcha puzzle algorithm.
    return hashlib.sha256(data).digest()


def hashptcha_hash_hex(value_binary: str, hash_type: str) -> str:
    return hashptcha_hash(hashptcha_binary_to_bytes(value_binary), hash_type).hex()


def hashptcha_hash_binary(hash_hex_or_bytes: str | bytes, hash_type: str) -> str:
    alg = normalize_hashptcha_hash_type(hash_type)
    total_bits = HASHPTCHA_HASH_BITS[alg]
    digest = bytes.fromhex(hash_hex_or_bytes) if isinstance(hash_hex_or_bytes, str) else bytes(hash_hex_or_bytes)
    return bin(int.from_bytes(digest, "big"))[2:].zfill(total_bits)


def hashptcha_matches(value_binary: str, hash_type: str, target: str) -> bool:
    alg = normalize_hashptcha_hash_type(hash_type)
    target_text = _validate_target(target, HASHPTCHA_HASH_BITS[alg])
    digest = hashptcha_hash(hashptcha_binary_to_bytes(value_binary), alg)
    return _digest_matches_target(digest, target_text, HASHPTCHA_HASH_BITS[alg])


def parse_hashptcha_task(data: Any, *, secret_key: str | None = None) -> HashptchaTask:
    if isinstance(data, HashptchaTask):
        if secret_key is None or secret_key == data.secret_key:
            return data
        return HashptchaTask(
            token=data.token,
            hash_type=data.hash_type,
            target=data.target,
            start_point=data.start_point,
            secret_key=secret_key,
            response_field=data.response_field,
            raw=data.raw,
        )
    if isinstance(data, str):
        text = data.strip()
        if not text:
            raise ValueError("Hashptcha task string is empty")
        if text.startswith("@"):
            return parse_hashptcha_task(Path(text[1:]).read_text(encoding="utf-8"), secret_key=secret_key)
        if text.startswith("{"):
            data = json.loads(text)
        else:
            raise ValueError("Hashptcha task string must be JSON or @file")
    if not isinstance(data, dict):
        raise ValueError("Hashptcha task must be a JSON object")
    token = str(data.get("token") or data.get("task_token") or data.get("id") or "").strip()
    if not token:
        raise ValueError("Hashptcha task requires token")
    alg = normalize_hashptcha_hash_type(data.get("hash_type") or data.get("hashType") or data.get("type"))
    target = _validate_target(data.get("target") or data.get("hash_target") or data.get("prefix"), HASHPTCHA_HASH_BITS[alg])
    start_point = normalize_hashptcha_binary(
        data.get("start_point") or data.get("startPoint") or data.get("start") or "00000000",
        field="start_point",
    )
    return HashptchaTask(
        token=token,
        hash_type=alg,
        target=target,
        start_point=start_point,
        secret_key=secret_key or (str(data.get("secret_key") or data.get("secretKey") or "").strip() or None),
        response_field=str(data.get("response_field") or data.get("field") or "hashptcha-response"),
        raw=data,
    )


def solve_hashptcha_value(
    hash_type: str,
    target: str,
    *,
    start_point: str | int = "00000000",
    min_value_bits: int | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
) -> tuple[str, int, str, int]:
    alg = normalize_hashptcha_hash_type(hash_type)
    target_text = _validate_target(target, HASHPTCHA_HASH_BITS[alg])
    if isinstance(start_point, int):
        start_int = int(start_point)
        min_bits = int(min_value_bits or 8)
    else:
        normalized_start = normalize_hashptcha_binary(start_point, field="start_point")
        start_int = int(normalized_start, 2)
        min_bits = int(min_value_bits or len(normalized_start))
    if start_int < 0:
        raise ValueError("Hashptcha start_point must be non-negative")
    max_attempts = int(max_attempts)
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    workers = max(1, int(workers or 1))
    if workers == 1:
        value_int, value, digest = _search_hashptcha_range(
            alg,
            target_text,
            min_bits,
            start_int,
            start_int + max_attempts,
        )
        if value_int is None or value is None or digest is None:
            raise TimeoutError(f"no Hashptcha value found within {max_attempts} attempts")
        return value, value_int, digest.hex(), value_int - start_int + 1

    workers = min(workers, max(1, os.cpu_count() or 1))
    chunk_size = max(1_000, int(chunk_size))
    submitted = 0
    next_start = start_int
    futures: dict[Any, tuple[int, int]] = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        while submitted < max_attempts and len(futures) < workers:
            size = min(chunk_size, max_attempts - submitted)
            end = next_start + size
            futures[pool.submit(_search_hashptcha_range, alg, target_text, min_bits, next_start, end)] = (next_start, end)
            next_start = end
            submitted += size
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for fut in done:
                _begin, end = futures.pop(fut)
                value_int, value, digest = fut.result()
                if value_int is not None and value is not None and digest is not None:
                    for other in futures:
                        other.cancel()
                    return value, value_int, digest.hex(), max(0, end - start_int)
                if submitted < max_attempts:
                    size = min(chunk_size, max_attempts - submitted)
                    nend = next_start + size
                    futures[pool.submit(_search_hashptcha_range, alg, target_text, min_bits, next_start, nend)] = (next_start, nend)
                    next_start = nend
                    submitted += size
    raise TimeoutError(f"no Hashptcha value found within {max_attempts} attempts")


def solve_hashptcha_task(
    task: HashptchaTask | dict[str, Any] | str,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    chunk_size: int = 100_000,
    secret_key: str | None = None,
) -> HashptchaSolution:
    started = time.monotonic()
    item = parse_hashptcha_task(task, secret_key=secret_key)
    value, value_int, digest_hex, attempts = solve_hashptcha_value(
        item.hash_type,
        item.target,
        start_point=item.start_point,
        min_value_bits=item.min_value_bits,
        max_attempts=max_attempts,
        workers=workers,
        chunk_size=chunk_size,
    )
    return HashptchaSolution(
        task=item,
        value=value,
        value_int=value_int,
        hash_hex=digest_hex,
        hash_binary_prefix=hashptcha_hash_binary(digest_hex, item.hash_type)[: len(item.target)],
        attempts=attempts,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def verify_hashptcha_solution(
    task: HashptchaTask | dict[str, Any] | str,
    solution: HashptchaSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_hashptcha_task(task)
        if isinstance(solution, HashptchaSolution):
            value = solution.value
            token = solution.task.token
        elif isinstance(solution, dict):
            nested = solution.get("hashptcha-response") or solution.get("response")
            if isinstance(nested, str) and nested.strip().startswith("{"):
                nested_data = json.loads(nested)
                value = str(nested_data.get("value") or "")
                token = str(nested_data.get("token") or solution.get("token") or "")
            else:
                value = str(solution.get("value") or solution.get("pass_point") or "")
                token = str(solution.get("token") or "")
        else:
            value = str(solution)
            token = item.token
        value_text = _strict_value_binary(value, min_bits=item.min_value_bits)
        if token and token != item.token:
            return False
        if int(value_text, 2) < item.start_int:
            return False
        return hashptcha_matches(value_text, item.hash_type, item.target)
    except Exception:
        return False


class HashptchaSolver:
    """Protocol solver for szche/Hashptcha distributed hash-cracking tasks.

    Runtime path mirrors the iframe client and Flask verifier: fetch /get-task,
    byte-align the binary start point, hash the corresponding raw bytes with
    MD5/SHA-256, match the binary digest prefix, then optionally POST /verify
    with token/value/secret_key. No browser or OCR is involved.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        get_task_url: str | None = None,
        verify_url: str | None = None,
        public_key: str | None = None,
        secret_key: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        submit: bool = False,
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
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "get_task_url": get_task_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
        }
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "hashptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="hashptcha",
                ok=ok,
                captcha_type="prefix_hash_cracking_task",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("token"),
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
            task = self._load_task(
                session=session,
                base_url=base_url,
                get_task_url=get_task_url,
                public_key=public_key,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                secret_key=secret_key,
                timeout_sec=timeout_sec,
                proxies=proxies,
                headers=merged_headers,
                raw=raw,
            )
            solution = solve_hashptcha_task(
                task,
                max_attempts=max_attempts,
                workers=workers,
                chunk_size=chunk_size,
                secret_key=secret_key,
            )
            if not verify_hashptcha_solution(task, solution):
                errors.append("Hashptcha internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            diagnostics.update(
                {
                    "token": task.token,
                    "hash_type": task.hash_type,
                    "target": task.target,
                    "target_bits": len(task.target),
                    "start_point": task.start_point,
                    "value": solution.value,
                    "value_int": solution.value_int,
                    "hash_hex": solution.hash_hex,
                    "hash_binary_prefix": solution.hash_binary_prefix,
                    "attempts": solution.attempts,
                    "solve_ms": solution.elapsed_ms,
                }
            )
            raw["task"] = _task_raw(task)
            raw["solution"] = {
                "token": task.token,
                "value": solution.value,
                "valueInt": solution.value_int,
                "hashHex": solution.hash_hex,
                "verifyBody": solution.verify_body,
                "submitBody": solution.submit_body,
            }
            final_ticket = json.dumps(solution.verify_body, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit:
                if not solution.task.secret_key:
                    errors.append("submit requires secret_key")
                    return finish(ok=False, ticket=final_ticket, verify_code="missing_secret_key")
                url = verify_url or _base_url_join(base_url, "/verify")
                if not url:
                    errors.append("submit requires verify_url or base_url")
                    return finish(ok=False, ticket=final_ticket, verify_code="missing_verify_url")
                resp = session.post(url, json=solution.verify_body, headers=merged_headers, timeout=timeout_sec, proxies=proxies)
                raw["verifyRequest"] = {"url": url, "body": solution.verify_body}
                raw["verifyResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
                try:
                    verify_data: Any = resp.json()
                except Exception:
                    verify_data = resp.text[:500]
                raw["verifyResponse"]["body"] = verify_data
                if not (200 <= resp.status_code < 400):
                    errors.append(str(verify_data)[:160] or f"http_{resp.status_code}")
                    return finish(ok=False, ticket=final_ticket, verify_code=f"http_{resp.status_code}")
                final_ticket = json.dumps(verify_data, ensure_ascii=False, separators=(",", ":"))
                verify_code = "validated"
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_task(
        self,
        *,
        session: requests.Session,
        base_url: str | None,
        get_task_url: str | None,
        public_key: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        secret_key: str | None,
        timeout_sec: int,
        proxies: dict[str, str] | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> HashptchaTask:
        loaded = _load_json_arg(challenge_json, challenge_file)
        if loaded is not None:
            return parse_hashptcha_task(loaded, secret_key=secret_key)
        url = get_task_url or _hashptcha_get_task_url(base_url, public_key)
        if not url:
            raise ValueError("Hashptcha solve requires challenge_json/challenge_file or get_task_url/base_url")
        resp = session.get(url, headers=headers, timeout=timeout_sec, proxies=proxies)
        raw["taskRequest"] = {"url": url}
        raw["taskResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("Content-Type")}
        resp.raise_for_status()
        data = resp.json()
        raw["taskResponse"]["json"] = data
        return parse_hashptcha_task(data, secret_key=secret_key)


def _search_hashptcha_range(
    hash_type: str,
    target: str,
    min_bits: int,
    begin: int,
    end: int,
) -> tuple[int | None, str | None, bytes | None]:
    alg = normalize_hashptcha_hash_type(hash_type)
    total_bits = HASHPTCHA_HASH_BITS[alg]
    target_int = int(target, 2)
    shift = total_bits - len(target)
    use_md5 = alg == "MD5"
    for value_int in range(int(begin), int(end)):
        value = hashptcha_int_to_binary(value_int, min_bits=min_bits)
        payload = int(value, 2).to_bytes(len(value) // 8, byteorder="big")
        digest = hashlib.md5(payload).digest() if use_md5 else hashlib.sha256(payload).digest()  # noqa: S324
        if (int.from_bytes(digest, "big") >> shift) == target_int:
            return value_int, value, digest
    return None, None, None


def _digest_matches_target(digest: bytes, target: str, total_bits: int) -> bool:
    return (int.from_bytes(digest, "big") >> (int(total_bits) - len(target))) == int(target, 2)


def _strict_value_binary(value: Any, *, min_bits: int) -> str:
    text = str(value if value is not None else "").strip()
    if text.startswith("0b"):
        text = text[2:]
    if not text or any(ch not in "01" for ch in text):
        raise ValueError("Hashptcha value must be a binary string")
    if len(text) % 8 != 0:
        raise ValueError("Hashptcha value must be byte-aligned")
    if len(text) < int(min_bits):
        raise ValueError("Hashptcha value is narrower than task start_point")
    return text


def _validate_target(value: Any, hash_bits: int) -> str:
    target = str(value if value is not None else "").strip()
    if target.startswith("0b"):
        target = target[2:]
    if not target:
        raise ValueError("Hashptcha task requires target")
    if any(ch not in "01" for ch in target):
        raise ValueError("Hashptcha target must be a binary string")
    if len(target) > int(hash_bits):
        raise ValueError(f"Hashptcha target length exceeds {hash_bits} bits")
    return target


def _task_raw(task: HashptchaTask) -> dict[str, Any]:
    return {
        "token": task.token,
        "hashType": task.hash_type,
        "target": task.target,
        "startPoint": task.start_point,
        "targetBits": len(task.target),
        "hashBits": task.hash_bits,
        "responseField": task.response_field,
    }


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


def _base_url_join(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _hashptcha_get_task_url(base_url: str | None, public_key: str | None) -> str | None:
    root = _base_url_join(base_url, "/get-task")
    if not root:
        return None
    if public_key:
        return root + "?" + urlencode({"k": public_key})
    return root


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}
