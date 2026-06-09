from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.powforge import (
    PowForgeSolver,
    build_powforge_submit_body,
    build_powforge_verify_body,
    count_leading_zero_bits_hex,
    parse_powforge_challenge,
    powforge_hash_hex,
    powforge_hash_matches,
    solve_powforge_challenge,
    solve_powforge_counter,
    verify_powforge_solution,
)

SALT = "powforge-fixture-salt"
DIFFICULTY = 14
NONCE = "567"
HASH_HEX = "00011be080ab23422aea07408a2d3c52dbabe27b3e93f5e4d84fa1ae7e5723ea"
SIGNATURE = "fixture-signature"
CHALLENGE_ID = "powforge-fixture-salt.1780967045273"
TOKEN = "fixture-token.powforge"


class _PowForgeHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    verify_calls: list[dict[str, Any]] = []
    token_verify_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/api/challenge":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        self._json({"salt": SALT, "difficulty": DIFFICULTY, "algo": "sha256", "signature": SIGNATURE, "id": CHALLENGE_ID})

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}")
        if self.path == "/api/verify":
            type(self).verify_calls.append(payload)
            challenge = {"salt": payload.get("salt"), "difficulty": payload.get("difficulty"), "algo": payload.get("algo")}
            if not verify_powforge_solution(challenge, payload):
                self._json({"valid": False, "reason": "invalid_pow"}, 422)
                return
            if payload.get("signature") != SIGNATURE or payload.get("id") != CHALLENGE_ID:
                self._json({"valid": False, "reason": "invalid_signature_or_id"}, 422)
                return
            self._json({"valid": True, "token": TOKEN, "method": "sha256", "witnessed": False})
            return
        if self.path == "/api/token/verify":
            type(self).token_verify_calls.append(payload)
            self._json({"valid": payload.get("token") == TOKEN, "method": "sha256", "issued_at": 1780967045273})
            return
        self._json({"error": "not-found"}, 404)


def test_powforge_solve_fixture() -> None:
    challenge = parse_powforge_challenge({"salt": SALT, "difficulty": DIFFICULTY, "algo": "sha256", "signature": SIGNATURE, "id": CHALLENGE_ID})
    solution = solve_powforge_challenge(challenge, timeout_sec=5, max_attempts=10_000)

    assert solution is not None
    assert solution.nonce == NONCE
    assert solution.hash_hex == HASH_HEX
    assert solution.attempts == 567
    assert powforge_hash_hex(SALT, NONCE) == HASH_HEX
    assert count_leading_zero_bits_hex(HASH_HEX) >= DIFFICULTY
    assert powforge_hash_matches(HASH_HEX, DIFFICULTY)
    assert verify_powforge_solution(challenge, solution)
    assert not verify_powforge_solution(challenge, "566")
    assert build_powforge_verify_body(challenge, solution) == {
        "salt": SALT,
        "nonce": NONCE,
        "signature": SIGNATURE,
        "algo": "sha256",
        "difficulty": DIFFICULTY,
        "id": CHALLENGE_ID,
        "challenge": None,
    }

    solution.token = TOKEN
    assert build_powforge_submit_body(solution) == {"pf_token": TOKEN}

    counter, digest, attempts = solve_powforge_counter(SALT, difficulty=DIFFICULTY, max_attempts=10_000, deadline_epoch=None)
    assert (counter, digest, attempts) == (567, HASH_HEX, 567)


def test_powforge_solver_protocol_flow_local_server() -> None:
    _PowForgeHandler.challenge_calls = 0
    _PowForgeHandler.verify_calls = []
    _PowForgeHandler.token_verify_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowForgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PowForgeSolver().solve(
                base_url=base,
                token_verify=True,
                timeout_sec=5,
                max_attempts=10_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powforge"
    assert ret.captcha_type == "signed_sha256_pow_token"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.ticket == '{"pf_token":"fixture-token.powforge"}'
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == NONCE
    assert ret.diagnostics["token_verified"] is True
    assert _PowForgeHandler.challenge_calls == 1
    assert _PowForgeHandler.verify_calls[0]["nonce"] == NONCE
    assert _PowForgeHandler.token_verify_calls[0]["token"] == TOKEN
