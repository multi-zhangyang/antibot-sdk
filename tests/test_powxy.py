from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.powxy import (
    PowxySolver,
    make_powxy_identifier,
    parse_powxy_challenge,
    parse_powxy_challenge_html,
    powxy_cookie_hmac,
    powxy_digest,
    powxy_nonce_b64,
    solve_powxy_challenge,
    solve_powxy_nonce,
    validate_powxy_bits,
    verify_powxy_solution,
)

IDENTIFIER = bytes(range(32))
IDENTIFIER_B64 = base64.b64encode(IDENTIFIER).decode("ascii")
PRIVKEY = b"powxy-test-private-key-32-bytes!!"[:32]
PRIVKEY_HASH = hashlib.sha256(PRIVKEY).digest()
FIXED_TIME = 604800 * 12345


def test_powxy_source_style_fixture() -> None:
    nonce, nonce_bytes, digest_hex, attempts = solve_powxy_nonce(IDENTIFIER, 20, max_attempts=200_000)
    assert nonce == 96585
    assert nonce_bytes == b"Iy\x01\x00\x00\x00\x00\x00"
    assert powxy_nonce_b64(nonce) == "SXkBAAAAAAA="
    assert digest_hex == "000001bd132ae1c80db0c2a37980bcc55c1b1b9d6b7ec9e3bc54378c0ec166d9"
    assert attempts == 96586
    assert validate_powxy_bits(powxy_digest(IDENTIFIER, nonce), 20)


def test_powxy_html_json_and_solution_parse() -> None:
    html = f'''
    <body data-identifier="{IDENTIFIER_B64}" data-difficulty="16">
      <pre id="identifier">{IDENTIFIER_B64}</pre>
      <input id="nonce" name="powxy" type="text" />
    </body>
    '''
    parsed = parse_powxy_challenge_html(html, page_url="https://target.example/protected")
    assert parsed.identifier == IDENTIFIER
    assert parsed.difficulty == 16
    assert parsed.page_url == "https://target.example/protected"

    solution = solve_powxy_challenge(parsed, max_attempts=20_000)
    assert solution.nonce == 14417
    assert solution.powxy_field == "UTgAAAAAAAA="
    assert verify_powxy_solution(parsed, solution)
    assert verify_powxy_solution({"identifier": IDENTIFIER_B64, "difficulty": 16}, {"powxy": solution.powxy_field})
    assert parse_powxy_challenge(IDENTIFIER_B64).identifier == IDENTIFIER


def test_powxy_identifier_derivation_and_cookie_hmac() -> None:
    identifier = make_powxy_identifier(
        remote_ip="127.0.0.1",
        user_agent="ua-fixture",
        accept_encoding="gzip, deflate",
        accept_language="en-US,en;q=0.9",
        privkey_hash=PRIVKEY_HASH,
        unix_time=FIXED_TIME,
    )
    assert base64.b64encode(identifier).decode("ascii") == "n0x82slgUDYdADRuzgiWj+vzq2po5VBvJiAbQH/hzjo="
    expected_mac = base64.b64encode(hmac.new(PRIVKEY, identifier, hashlib.sha256).digest()).decode("ascii")
    assert powxy_cookie_hmac(identifier, PRIVKEY) == expected_mac


class _PowxyHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    difficulty = 16

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _identifier(self) -> bytes:
        return make_powxy_identifier(
            remote_ip=self.client_address[0],
            user_agent=self.headers.get("User-Agent", ""),
            accept_encoding=self.headers.get("Accept-Encoding", ""),
            accept_language=self.headers.get("Accept-Language", ""),
            privkey_hash=PRIVKEY_HASH,
            unix_time=FIXED_TIME,
        )

    def _challenge(self, message: str = "") -> bytes:
        identifier_b64 = base64.b64encode(self._identifier()).decode("ascii")
        msg = f"<p><strong>{message}</strong></p>" if message else ""
        return f'''
        <!doctype html><html><body data-identifier="{identifier_b64}" data-difficulty="{type(self).difficulty}">
        <h1>Proof-of-work challenge</h1>
        <pre id="identifier">{identifier_b64}</pre>
        <form method="POST"><input id="nonce" name="powxy" type="text" /></form>
        {msg}
        </body></html>
        '''.encode("utf-8")

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        self._write(self._challenge(), 200, {"Content-Type": "text/html"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = parse_qs(self.rfile.read(length).decode("utf-8"))
        body = {key: values[-1] for key, values in payload.items()}
        type(self).calls.append({"method": "POST", "path": self.path, "payload": body, "headers": dict(self.headers)})
        field = body.get("powxy", "")
        try:
            nonce_bytes = base64.b64decode(field, validate=True)
        except Exception:
            nonce_bytes = b""
        digest = hashlib.sha256(self._identifier() + nonce_bytes).digest() if len(nonce_bytes) == 8 else b"\xff" * 32
        if len(nonce_bytes) == 8 and validate_powxy_bits(digest, type(self).difficulty):
            cookie = powxy_cookie_hmac(self._identifier(), PRIVKEY)
            self._write(b"", 303, {"Set-Cookie": f"powxy={cookie}; Path=/; HttpOnly", "Location": self.path})
            return
        self._write(self._challenge("Your submission was incorrect."), 200, {"Content-Type": "text/html"})


def test_powxy_solver_local_submit() -> None:
    _PowxyHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(PowxySolver().solve(base_url=base, submit=True, timeout_sec=5, max_attempts=100_000))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powxy"
    assert ret.captcha_type == "reverse_proxy_pow"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["difficulty"] == 16
    assert ret.diagnostics["identifier_len"] == 32
    assert json.loads(ret.ticket or "{}") == {"powxy_cookie": True, "location": "/protected"}
    assert _PowxyHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _PowxyHandler.calls[1]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert "powxy" in _PowxyHandler.calls[1]["payload"]
