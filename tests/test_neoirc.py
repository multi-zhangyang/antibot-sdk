from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.neoirc import (
    NeoIrcSolver,
    neoirc_body_hash,
    neoirc_hashcash_hash_hex,
    neoirc_hashcash_matches,
    parse_neoirc_hashcash_stamp,
    solve_neoirc_hashcash_challenge,
    solve_neoirc_hashcash_counter,
    verify_neoirc_hashcash_solution,
)

DATE = "260609"
RESOURCE = "NeoIRC"
SESSION_STAMP_16 = "1:16:260609:NeoIRC::9510"
SESSION_DIGEST_16 = "000029c1ff0f2e24aefe7cb8c1d94ac2079df5390e284c5b3db18f8473e4a353"
BODY = b'{"command":"PRIVMSG","to":"#pow","body":"hello"}'
BODY_HASH = "148f78d2d833b5a2b0162813b73187afb835e200d8499756c66d03107c5692c2"
CHANNEL_STAMP_16 = f"1:16:260609:#pow:{BODY_HASH}:33ee"
CHANNEL_DIGEST_16 = "000094611f82d99dd5bace2725adadc8f9f9793e51ab3a11aabfa22f7684914e"


def test_neoirc_session_hashcash_fixture() -> None:
    counter, counter_hex, digest_hex, attempts = solve_neoirc_hashcash_counter(
        f"1:16:{DATE}:{RESOURCE}::",
        16,
        max_attempts=100_000,
    )
    assert counter == 38_160
    assert counter_hex == "9510"
    assert attempts == 38_161
    assert digest_hex == SESSION_DIGEST_16
    assert neoirc_hashcash_hash_hex(SESSION_STAMP_16) == SESSION_DIGEST_16
    assert neoirc_hashcash_matches(SESSION_STAMP_16, 16)

    parsed = parse_neoirc_hashcash_stamp(SESSION_STAMP_16)
    assert parsed["resource"] == RESOURCE
    assert parsed["body_hash"] == ""
    assert parsed["counter_int"] == 38_160


def test_neoirc_channel_body_bound_hashcash_fixture() -> None:
    assert neoirc_body_hash(BODY) == BODY_HASH
    solution = solve_neoirc_hashcash_challenge(
        {"mode": "channel", "bits": 16, "resource": "#pow", "date": DATE, "body_hash": BODY_HASH},
        max_attempts=50_000,
    )
    assert solution.counter == 13_294
    assert solution.counter_hex == "33ee"
    assert solution.stamp == CHANNEL_STAMP_16
    assert solution.hash_hex == CHANNEL_DIGEST_16
    assert verify_neoirc_hashcash_solution(
        {"mode": "channel", "bits": 16, "resource": "#pow", "date": DATE, "body": BODY.decode()},
        solution,
    )
    assert not verify_neoirc_hashcash_solution(
        {"mode": "channel", "bits": 16, "resource": "#pow", "date": DATE, "body_hash": "0" * 64},
        solution,
    )


class _NeoIrcHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

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
        if self.path == "/api/v1/server":
            self._write(json.dumps({"name": RESOURCE, "hashcash_bits": 12}).encode(), 200, {"Content-Type": "application/json"})
            return
        self._write(b"not found", 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "payload": payload})
        if self.path != "/api/v1/session":
            self._write(b"not found", 404)
            return
        stamp = str(payload.get("pow_token") or "")
        ok = (
            payload.get("nick") == "sdkbot"
            and stamp.startswith("1:12:")
            and parse_neoirc_hashcash_stamp(stamp)["resource"] == RESOURCE
            and neoirc_hashcash_matches(stamp, 12)
        )
        if ok:
            token = hashlib.sha256(stamp.encode()).hexdigest()
            self._write(json.dumps({"token": token, "nick": payload["nick"]}).encode(), 200, {"Content-Type": "application/json"})
            return
        self._write(json.dumps({"error": "invalid hashcash"}).encode(), 403, {"Content-Type": "application/json"})


def test_neoirc_solver_local_session_submit_flow() -> None:
    _NeoIrcHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NeoIrcHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            NeoIrcSolver().solve(
                base_url=base,
                submit=True,
                nick="sdkbot",
                stamp_date=DATE,
                max_attempts=20_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "neoirc"
    assert ret.captcha_type == "resource_body_bound_hashcash"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["bits"] == 12
    assert ret.diagnostics["resource"] == RESOURCE
    assert ret.diagnostics["counter"] == 4669
    assert len(ret.ticket or "") == 64
    assert _NeoIrcHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _NeoIrcHandler.calls[1]["payload"]["pow_token"] == "1:12:260609:NeoIRC::123d"
