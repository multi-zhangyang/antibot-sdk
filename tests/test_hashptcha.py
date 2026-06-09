from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.hashptcha import (
    HashptchaSolver,
    hashptcha_binary_to_bytes,
    hashptcha_hash_binary,
    hashptcha_hash_hex,
    hashptcha_matches,
    parse_hashptcha_task,
    solve_hashptcha_task,
    solve_hashptcha_value,
    verify_hashptcha_solution,
)


MD5_TARGET_8 = "00000000"
SHA256_TARGET_8 = "00000000"


def test_hashptcha_md5_prefix_cracking_fixture() -> None:
    value, value_int, digest_hex, attempts = solve_hashptcha_value(
        "MD5",
        MD5_TARGET_8,
        start_point="00000000",
        max_attempts=1_000,
    )
    assert value == "10101111"
    assert value_int == 175
    assert attempts == 176
    assert digest_hex == "00d9712ec5eb70807a73b8d2d6ead90d"
    assert hashptcha_hash_hex(value, "MD5") == digest_hex
    assert hashptcha_hash_binary(digest_hex, "MD5").startswith(MD5_TARGET_8)
    assert hashptcha_matches(value, "MD5", MD5_TARGET_8)


def test_hashptcha_sha256_prefix_cracking_fixture() -> None:
    value, value_int, digest_hex, _attempts = solve_hashptcha_value(
        "SHA-256",
        SHA256_TARGET_8,
        start_point="00000000",
        max_attempts=2_000,
        workers=2,
        chunk_size=500,
    )
    assert value == "0000010111000110"
    assert value_int == 1478
    assert digest_hex == "0017e45fd2b557b01ae7a12fdb082fa28342981e012d13cb54a0a23890431b59"
    assert hashptcha_matches(value, "SHA256", SHA256_TARGET_8)


def test_hashptcha_preserves_byte_aligned_start_width() -> None:
    start_point = "0000000010101111"
    raw = int(start_point, 2).to_bytes(len(start_point) // 8, "big")
    target = bin(int(hashlib.md5(raw).hexdigest(), 16))[2:].zfill(128)[:16]
    task = parse_hashptcha_task({"token": "tok-width", "hash_type": "MD5", "target": target, "start_point": start_point})
    solution = solve_hashptcha_task(task, max_attempts=1)
    assert solution.value == start_point
    assert hashptcha_binary_to_bytes(solution.value) == b"\x00\xaf"
    assert verify_hashptcha_solution(task, solution)
    assert not verify_hashptcha_solution(task, {"token": "tok-width", "value": "10101111"})


class _HashptchaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    used = False
    token = "tok-local"
    secret = "secret-local"
    target = MD5_TARGET_8
    start_point = "00000000"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if self.path.startswith("/get-task"):
            payload = {
                "hash_type": "MD5",
                "target": self.target,
                "token": self.token,
                "start_point": self.start_point,
            }
            self._write(json.dumps(payload).encode(), 200, {"Content-Type": "application/json"})
            return
        self._write(b"not found", 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "payload": payload})
        ok = (
            self.path == "/verify"
            and not type(self).used
            and payload.get("token") == self.token
            and payload.get("secret_key") == self.secret
            and int(str(payload.get("value")), 2) >= int(self.start_point, 2)
            and hashptcha_matches(str(payload.get("value")), "MD5", self.target)
        )
        if ok:
            type(self).used = True
            self._write(json.dumps("Ok").encode(), 200, {"Content-Type": "application/json"})
            return
        self._write(json.dumps("Error").encode(), 403, {"Content-Type": "application/json"})


def test_hashptcha_solver_local_fetch_and_submit_flow() -> None:
    _HashptchaHandler.calls = []
    _HashptchaHandler.used = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HashptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            HashptchaSolver().solve(
                base_url=base,
                public_key="pub-local",
                secret_key=_HashptchaHandler.secret,
                submit=True,
                max_attempts=1_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "hashptcha"
    assert ret.captcha_type == "prefix_hash_cracking_task"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["hash_type"] == "MD5"
    assert ret.diagnostics["value"] == "10101111"
    assert ret.diagnostics["value_int"] == 175
    assert _HashptchaHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _HashptchaHandler.calls[1]["payload"] == {
        "token": _HashptchaHandler.token,
        "value": "10101111",
        "secret_key": _HashptchaHandler.secret,
    }
