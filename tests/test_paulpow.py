from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.paulpow import (
    PaulPowSolver,
    bcrypt_base64_encode,
    parse_paul_pow_challenge,
    paul_pow_prefix_hash,
    solve_paul_pow_challenge,
    verify_paul_pow_solution,
)

EXACT_CHALLENGE = {
    "hash": "$2b$04$WUHhXETkX0fnYkrqZU3ta.20gWPJrey8d9fW7k9o4QX9pDmRcnOi2",
    "salt": "exact-salt",
    "captchaType": "exact",
    "size": 10,
    "cost": 4,
}
PREFIX_SALT = "abcdefghijklmnopXYZ"
PREFIX_HASH_NONCE_5 = "$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC"
PREFIX_CHALLENGE = {
    "hash": PREFIX_HASH_NONCE_5,
    "salt": PREFIX_SALT,
    "captchaType": "prefix",
    "size": 30,
    "cost": 4,
}


def test_paulpow_bcrypt_base64_and_prefix_hash_match_rust_fixture() -> None:
    # Rust bcrypt::hash_with_salt("abcdefghijklmnopqrstuvwxyz012", 4, *b"abcdefghijklmnop")
    # prints this salt prefix: $2b$04$WUHhXETkX0fnYkrqZU3ta.
    assert bcrypt_base64_encode(b"abcdefghijklmnop") == "WUHhXETkX0fnYkrqZU3ta."
    assert paul_pow_prefix_hash("abcdefghijklmnop", 0, 4).startswith(
        "$2b$04$WUHhXETkX0fnYkrqZU3ta."
    )
    assert paul_pow_prefix_hash(PREFIX_SALT, 5, 4) == PREFIX_HASH_NONCE_5
    assert verify_paul_pow_solution(PREFIX_CHALLENGE, 5)


def test_paulpow_solve_exact_bcrypt_fixture() -> None:
    solution = solve_paul_pow_challenge(EXACT_CHALLENGE, max_attempts=11, timeout_sec=10)

    assert solution is not None
    assert solution.nonce == 7
    assert solution.checked == 8
    assert verify_paul_pow_solution(EXACT_CHALLENGE, solution.nonce)
    assert solution.submit_body["nonce"] == 7
    assert solution.submit_body["clientInfo"]["captchaType"] == "exact"


def test_paulpow_solve_prefix_bcrypt_fixture() -> None:
    solution = solve_paul_pow_challenge(PREFIX_CHALLENGE, max_attempts=10, timeout_sec=10)

    assert solution is not None
    assert solution.nonce == 5
    assert solution.checked == 6
    assert solution.bcrypt_hash == PREFIX_HASH_NONCE_5
    assert verify_paul_pow_solution(PREFIX_CHALLENGE, {"nonce": "5"})


class _PaulPowHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/challenge":
            self._json({"error": "not-found"}, 404)
            return
        self._json({"challenge": PREFIX_CHALLENGE})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/verify":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        item = parse_paul_pow_challenge(payload.get("clientInfo", {}))
        ok = item.salt == PREFIX_SALT and verify_paul_pow_solution(item, payload)
        self._json({"verify": ok, "token": "paulpow-token"}, 200 if ok else 400)


def test_paulpow_solver_protocol_flow_local_server() -> None:
    _PaulPowHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PaulPowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PaulPowSolver().solve(
                challenge_url=f"{base}/challenge",
                verify_url=f"{base}/verify",
                submit=True,
                max_attempts=10,
                timeout_sec=10,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "paulpow"
    assert ret.captcha_type == "bcrypt_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "paulpow-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonce"] == "5"
    assert ret.diagnostics["browser"] == "not_used"
    assert _PaulPowHandler.calls[0]["nonce"] == 5
