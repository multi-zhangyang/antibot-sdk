from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass(slots=True)
class CryptoPuzzleArchive:
    n: int
    a: int
    t: int
    encrypted_key: int
    encrypted_message: bytes
    raw: bytes

    def to_payload(self, *, include_raw: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "n": str(self.n),
            "a": str(self.a),
            "t": str(self.t),
            "Ck": str(self.encrypted_key),
            "CmHex": self.encrypted_message.hex(),
            "bytes": len(self.raw),
        }
        if include_raw:
            out["puzzleB64"] = encode_cryptopuzzle_base64(self.raw)
        return out


@dataclass(slots=True)
class CryptoPuzzleSolution:
    puzzle: CryptoPuzzleArchive
    message: str
    key_hex: str
    b: int
    iterations: int
    took_ms: int

    @property
    def submit_body(self) -> dict[str, Any]:
        return {"solution": self.message, "message": self.message}

    def to_payload(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "keyHex": self.key_hex,
            "b": str(self.b),
            "iterations": self.iterations,
            "tookMs": self.took_ms,
            "submitBody": self.submit_body,
        }


def decode_cryptopuzzle_base64(value: str) -> bytes:
    text = str(value).strip()
    if not text:
        raise ValueError("crypto-puzzle base64 value is empty")
    if text.startswith("data:") and "," in text:
        text = text.split(",", 1)[1]
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        if "-" in text or "_" in text:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid crypto-puzzle base64") from exc


def encode_cryptopuzzle_base64(value: bytes, *, urlsafe: bool = False, padding: bool = True) -> str:
    raw = bytes(value)
    text = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode("ascii")
    return text if padding else text.rstrip("=")


def int_to_minimal_bytes(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise ValueError("negative integers are not supported")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def int_from_bytes(value: bytes | bytearray) -> int:
    return int.from_bytes(bytes(value), "big")


def parse_cryptopuzzle_archive(value: CryptoPuzzleArchive | bytes | bytearray | dict[str, Any] | str) -> CryptoPuzzleArchive:
    if isinstance(value, CryptoPuzzleArchive):
        _validate_archive(value)
        return value
    if isinstance(value, (bytes, bytearray)):
        return _parse_archive_bytes(bytes(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("crypto-puzzle value is empty")
        if text.startswith("@"):
            path = Path(text[1:])
            raw = path.read_bytes()
            try:
                decoded = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                return _parse_archive_bytes(raw)
            if decoded.startswith("{"):
                return parse_cryptopuzzle_archive(json.loads(decoded))
            return parse_cryptopuzzle_archive(decoded)
        if text.startswith("{"):
            return parse_cryptopuzzle_archive(json.loads(text))
        if text.startswith("0x") or _looks_hex(text):
            return _parse_archive_bytes(bytes.fromhex(text[2:] if text.startswith("0x") else text))
        return _parse_archive_bytes(decode_cryptopuzzle_base64(text))
    if isinstance(value, dict):
        data = value.get("puzzle") if isinstance(value.get("puzzle"), dict) else value
        raw_value = (
            data.get("puzzle")
            or data.get("archive")
            or data.get("puzzleB64")
            or data.get("puzzle_b64")
            or data.get("data")
            or data.get("challenge")
        )
        if raw_value is not None:
            return parse_cryptopuzzle_archive(raw_value)
        raw_hex = data.get("puzzleHex") or data.get("puzzle_hex") or data.get("hex")
        if raw_hex is not None:
            return parse_cryptopuzzle_archive(str(raw_hex))
        required = {"n", "a", "t", "Ck", "Cm"}
        if required <= set(data):
            cm = data["Cm"]
            if isinstance(cm, str):
                cm_bytes = bytes.fromhex(cm[2:] if cm.startswith("0x") else cm) if _looks_hex(cm[2:] if cm.startswith("0x") else cm) else decode_cryptopuzzle_base64(cm)
            else:
                cm_bytes = bytes(cm)
            item = CryptoPuzzleArchive(
                n=int(data["n"]),
                a=int(data["a"]),
                t=int(data["t"]),
                encrypted_key=int(data["Ck"]),
                encrypted_message=cm_bytes,
                raw=b"",
            )
            _validate_archive(item)
            return item
    raise ValueError("crypto-puzzle must be archive bytes/base64/hex or object")


def solve_cryptopuzzle_archive(
    puzzle: CryptoPuzzleArchive | bytes | bytearray | dict[str, Any] | str,
    *,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> CryptoPuzzleSolution:
    item = parse_cryptopuzzle_archive(puzzle)
    started = time.monotonic()
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    b = sequential_mod_exp_squares(item.a, item.t, item.n, deadline=deadline)
    key_int = item.encrypted_key - b
    if key_int < 0:
        raise ValueError("crypto-puzzle derived negative key")
    key = int_to_minimal_bytes(key_int)
    message = tiny_encryptor_decrypt_v1(item.encrypted_message, key)
    return CryptoPuzzleSolution(
        puzzle=item,
        message=message.decode("utf-8"),
        key_hex=key.hex(),
        b=b,
        iterations=item.t,
        took_ms=int((time.monotonic() - started) * 1000),
    )


def verify_cryptopuzzle_solution(
    puzzle: CryptoPuzzleArchive | bytes | bytearray | dict[str, Any] | str,
    solution: CryptoPuzzleSolution | dict[str, Any] | str,
    *,
    expected_message: str | None = None,
) -> bool:
    try:
        solved = solve_cryptopuzzle_archive(puzzle)
        if isinstance(solution, CryptoPuzzleSolution):
            message = solution.message
        elif isinstance(solution, dict):
            message = str(solution.get("message") or solution.get("solution") or solution.get("token") or "")
        else:
            message = str(solution)
        if solved.message != message:
            return False
        if expected_message is not None and message != expected_message:
            return False
        return True
    except Exception:
        return False


def sequential_mod_exp_squares(a: int, t: int, n: int, *, deadline: float | None = None) -> int:
    if n <= 0:
        raise ValueError("modulus n must be > 0")
    if t < 0:
        raise ValueError("iteration count t must be >= 0")
    x = int(a) % int(n)
    for i in range(int(t)):
        if deadline is not None and i and i % 100_000 == 0 and time.monotonic() >= deadline:
            raise TimeoutError("crypto-puzzle solve timed out")
        x = (x * x) % n
    return x % n


def tiny_encryptor_decrypt_v1(archive: bytes | bytearray, secret: bytes | bytearray) -> bytes:
    data = bytes(archive)
    if len(data) < 54:
        raise ValueError("tiny-encryptor archive is too short")
    version = data[0]
    if version != 1:
        raise ValueError("unsupported tiny-encryptor archive version")
    salt = data[1:33]
    rounds = int.from_bytes(data[33:37], "big", signed=False)
    iv = data[37:53]
    encrypted = data[53:]
    if len(encrypted) < 16:
        raise ValueError("tiny-encryptor ciphertext is too short")
    key = PBKDF2(bytes(secret), salt, dkLen=32, count=max(1, rounds), hmac_hash_module=SHA256)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    return cipher.decrypt_and_verify(ciphertext, tag)


def tiny_encryptor_encrypt_v1(
    message: bytes | str,
    secret: bytes | bytearray,
    *,
    salt: bytes,
    iv: bytes,
    rounds: int = 1,
) -> bytes:
    # Test/fixture helper matching tiny-encryptor v1. Public because it is useful
    # for local challenge construction in CI and private fixtures.
    msg = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    if len(salt) != 32:
        salt = SHA256.new(salt).digest()
    if len(iv) != 16:
        raise ValueError("tiny-encryptor iv must be 16 bytes")
    rounds = max(1, int(rounds))
    key = PBKDF2(bytes(secret), salt, dkLen=32, count=rounds, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    return b"\x01" + salt + rounds.to_bytes(4, "big") + iv + ciphertext + tag


def archive_cryptopuzzle_parts(n: int, a: int, t: int, encrypted_key: int, encrypted_message: bytes) -> bytes:
    parts = []
    for value in (n, a, t, encrypted_key):
        raw = int_to_minimal_bytes(int(value))
        parts.append(len(raw).to_bytes(4, "big", signed=True))
        parts.append(raw)
    parts.append(bytes(encrypted_message))
    return b"".join(parts)


def build_cryptopuzzle_fixture(
    *,
    n: int,
    a: int,
    t: int,
    key: bytes,
    message: str,
    salt: bytes,
    iv: bytes,
    rounds: int = 1,
) -> bytes:
    b = sequential_mod_exp_squares(a, t, n)
    cm = tiny_encryptor_encrypt_v1(message, key, salt=salt, iv=iv, rounds=rounds)
    ck = int_from_bytes(key) + b
    return archive_cryptopuzzle_parts(n, a, t, ck, cm)


def _parse_archive_bytes(raw: bytes) -> CryptoPuzzleArchive:
    offset = 0
    values: list[int] = []
    for _ in range(4):
        if offset + 4 > len(raw):
            raise ValueError("crypto-puzzle archive is truncated")
        length = int.from_bytes(raw[offset : offset + 4], "big", signed=True)
        offset += 4
        if length < 0 or offset + length > len(raw):
            raise ValueError("invalid crypto-puzzle archive length")
        values.append(int_from_bytes(raw[offset : offset + length]))
        offset += length
    cm = raw[offset:]
    item = CryptoPuzzleArchive(
        n=values[0],
        a=values[1],
        t=values[2],
        encrypted_key=values[3],
        encrypted_message=cm,
        raw=raw,
    )
    _validate_archive(item)
    return item


def _validate_archive(item: CryptoPuzzleArchive) -> None:
    if item.n <= 1:
        raise ValueError("crypto-puzzle n must be > 1")
    if item.a <= 0 or item.a >= item.n:
        raise ValueError("crypto-puzzle a must be in range 1..n-1")
    if item.t < 0:
        raise ValueError("crypto-puzzle t must be >= 0")
    if item.encrypted_key < 0:
        raise ValueError("crypto-puzzle encrypted key must be >= 0")
    if len(item.encrypted_message) < 54:
        raise ValueError("crypto-puzzle encrypted message is too short")


def _looks_hex(text: str) -> bool:
    text = text.strip()
    return bool(text) and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text)


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


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _json_body(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }
    if headers:
        out.update(headers)
    return out


def _derive_url(base_url: str | None, explicit: str | None, suffix: str) -> str | None:
    if explicit:
        return explicit
    if not base_url:
        return None
    if not suffix:
        return base_url.rstrip("/")
    return urljoin(base_url.rstrip("/") + "/", suffix.lstrip("/"))


class CryptoPuzzleSolver:
    """crypto-puzzle RSW time-lock protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        puzzle: str | bytes | None = None,
        puzzle_file: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        expected_message: str | None = None,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
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
                out = output_root / "cryptopuzzle_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="cryptopuzzle",
                ok=ok,
                captcha_type="rsw_time_lock_puzzle",
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
            challenge_data = self._load_challenge(
                puzzle=puzzle,
                puzzle_file=puzzle_file,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=_derive_url(base_url, challenge_url, "/challenge"),
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_cryptopuzzle_archive(challenge_data)
            raw["puzzle"] = item.to_payload(include_raw=False)
            diagnostics.update({"n_bits": item.n.bit_length(), "t": item.t, "archive_bytes": len(item.raw)})
            solution = solve_cryptopuzzle_archive(item, timeout_sec=timeout_sec)
            raw["solution"] = solution.to_payload()
            diagnostics.update(
                {
                    "message_present": bool(solution.message),
                    "iterations": solution.iterations,
                    "solve_ms": solution.took_ms,
                }
            )
            if expected_message is not None and solution.message != expected_message:
                errors.append("crypto-puzzle message did not match expected_message")
                return finish(ok=False, ticket=solution.message, verify_code="message_mismatch")
            ticket = solution.message
            verify_code = "solved"
            if submit or verify_url:
                effective_verify_url = _derive_url(base_url, verify_url, "/verify")
                if not effective_verify_url:
                    errors.append("submit requested but verify_url/base_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                verify_data = self._submit_solution(
                    verify_url=effective_verify_url,
                    solution=solution,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=request_headers,
                    raw=raw,
                )
                ok = isinstance(verify_data, dict) and (
                    verify_data.get("ok") is True
                    or verify_data.get("success") is True
                    or verify_data.get("verified") is True
                )
                if not ok:
                    reason = verify_data.get("error") if isinstance(verify_data, dict) else "verify_failed"
                    errors.append(str(reason or "verify_failed"))
                    return finish(ok=False, ticket=ticket, verify_code="verify_failed")
                diagnostics["submitted"] = True
                verify_code = "validated"
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        puzzle: str | bytes | None,
        puzzle_file: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        if puzzle is not None:
            raw["challengeSource"] = "puzzle"
            return puzzle
        if puzzle_file:
            raw["challengeSource"] = "puzzle_file"
            return "@" + puzzle_file
        data = _load_json_arg(challenge_json, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return data
        if not challenge_url:
            raise ValueError("crypto-puzzle requires puzzle, puzzle_file, challenge_json, challenge_file, challenge_url or base_url")
        resp = requests.get(
            challenge_url,
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["challengeResponse"] = {"status": resp.status_code, "url": challenge_url}
        try:
            payload: Any = resp.json()
            raw["challengeResponse"]["json"] = payload
        except ValueError:
            payload = resp.text.strip()
            raw["challengeResponse"]["text"] = payload[:500]
        resp.raise_for_status()
        raw["challengeSource"] = "url"
        return payload

    def _submit_solution(
        self,
        *,
        verify_url: str,
        solution: CryptoPuzzleSolution,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str],
        raw: dict[str, Any],
    ) -> Any:
        resp = requests.post(
            verify_url,
            data=_json_body(solution.submit_body),
            headers=headers,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyResponse"] = {"status": resp.status_code, "url": verify_url}
        try:
            data = resp.json()
        except ValueError:
            data = {"text": resp.text[:500]}
        raw["verifyResponse"]["json"] = data
        resp.raise_for_status()
        return data
