from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from antibot_sdk.providers.pingoo import (
    CHALLENGE_COOKIE,
    VERIFIED_COOKIE,
    PingooSolver,
    decode_pingoo_jwt_claims,
    parse_pingoo_challenge,
    pingoo_hash_hex,
    pingoo_hash_matches,
    solve_pingoo_challenge,
    solve_pingoo_nonce,
    verify_pingoo_solution,
)

CHALLENGE = "fixture-pingoo-challenge"
DIFFICULTY = 2
NONCE = "23"
HASH_HEX = "0045611ba0e187141d10d7bad3a951ea85e7a42cf9849f1a07a29a446bbbf3d1"
CHALLENGE_COOKIE_VALUE = "eyJhbGciOiJFZERTQSIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJwaW5nb28iLCJzdWIiOiJjbGllbnQiLCJhdWQiOiJwaW5nb28iLCJjaGFsbGVuZ2UiOiJmaXh0dXJlLXBpbmdvby1jaGFsbGVuZ2UiLCJkaWZmaWN1bHR5IjoyfQ.sig"
VERIFIED_COOKIE_VALUE = "verified.jwt.fixture"


def _b64url_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_pingoo_pow_fixture_and_parser() -> None:
    challenge = parse_pingoo_challenge(
        {"challenge": CHALLENGE, "difficulty": DIFFICULTY, CHALLENGE_COOKIE: CHALLENGE_COOKIE_VALUE}
    )
    assert challenge.challenge == CHALLENGE
    assert challenge.difficulty == DIFFICULTY
    assert challenge.captcha_cookie == CHALLENGE_COOKIE_VALUE

    assert pingoo_hash_hex(CHALLENGE, NONCE) == HASH_HEX
    assert pingoo_hash_matches(HASH_HEX, DIFFICULTY)
    assert not pingoo_hash_matches(HASH_HEX.replace("00", "10", 1), DIFFICULTY)

    nonce, digest, attempts = solve_pingoo_nonce(CHALLENGE, DIFFICULTY, max_attempts=100)
    assert nonce == NONCE
    assert digest == HASH_HEX
    assert attempts == 23

    solution = solve_pingoo_challenge(challenge, max_attempts=100)
    assert solution.nonce == NONCE
    assert solution.hash_hex == HASH_HEX
    assert solution.verify_body == {"nonce": NONCE, "hash": HASH_HEX}
    assert verify_pingoo_solution(challenge, solution)
    assert verify_pingoo_solution(challenge, {"nonce": NONCE, "hash": HASH_HEX})
    assert verify_pingoo_solution(challenge, f"{NONCE}:{HASH_HEX}")
    assert not verify_pingoo_solution(challenge, {"nonce": "22", "hash": HASH_HEX})


def test_pingoo_decode_jwt_claims_without_verification() -> None:
    token = f"{_b64url_json({'alg': 'EdDSA', 'kid': 'fixture'})}.{_b64url_json({'iss': 'pingoo', 'challenge': CHALLENGE, 'difficulty': DIFFICULTY})}.sig"
    claims = decode_pingoo_jwt_claims(f"{CHALLENGE_COOKIE}={token}; Path=/")
    assert claims["iss"] == "pingoo"
    assert claims["challenge"] == CHALLENGE
    assert claims["difficulty"] == DIFFICULTY


class _PingooHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        parsed = urlsplit(self.path)
        if parsed.path == "/__pingoo/captcha/api/init":
            body = json.dumps({"challenge": CHALLENGE, "difficulty": DIFFICULTY}, separators=(",", ":")).encode()
            self._write(
                body,
                200,
                {
                    "Content-Type": "application/json",
                    "Set-Cookie": f"{CHALLENGE_COOKIE}={CHALLENGE_COOKIE_VALUE}; HttpOnly; SameSite=Lax; Path=/",
                },
            )
            return
        self._write(b"not found", 404, {"Content-Type": "text/plain"})

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        body = json.loads(raw.decode("utf-8") or "{}")
        type(self).calls.append(
            {"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body}
        )
        challenge = parse_pingoo_challenge({"challenge": CHALLENGE, "difficulty": DIFFICULTY})
        cookie = self.headers.get("Cookie", "")
        if (
            urlsplit(self.path).path != "/__pingoo/captcha/api/verify"
            or CHALLENGE_COOKIE not in cookie
            or not verify_pingoo_solution(challenge, body)
        ):
            self._write(b"{}", 500, {"Content-Type": "application/json"})
            return
        self._write(
            b"{}",
            200,
            {
                "Content-Type": "application/json",
                "Set-Cookie": (
                    f"{VERIFIED_COOKIE}={VERIFIED_COOKIE_VALUE}; HttpOnly; SameSite=Lax; Path=/, "
                    f"{CHALLENGE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/"
                ),
            },
        )


def test_pingoo_solver_local_init_verify_flow() -> None:
    _PingooHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PingooHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(
            PingooSolver().solve(base_url=base_url, submit=True, max_attempts=100, timeout_sec=5)
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "pingoo"
    assert ret.captcha_type == "jwt_cookie_sha256_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["challenge"] == CHALLENGE
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["nonce"] == NONCE
    assert ret.diagnostics["hash_hex"] == HASH_HEX

    ticket = json.loads(ret.ticket or "{}")
    assert ticket["verify_body"] == {"nonce": NONCE, "hash": HASH_HEX}
    assert ticket[VERIFIED_COOKIE] == VERIFIED_COOKIE_VALUE

    assert _PingooHandler.calls[0]["method"] == "GET"
    assert _PingooHandler.calls[0]["path"] == "/__pingoo/captcha/api/init"
    assert _PingooHandler.calls[1]["method"] == "POST"
    assert _PingooHandler.calls[1]["path"] == "/__pingoo/captcha/api/verify"
    assert _PingooHandler.calls[1]["body"] == {"nonce": NONCE, "hash": HASH_HEX}
    assert CHALLENGE_COOKIE in _PingooHandler.calls[1]["headers"]["Cookie"]
