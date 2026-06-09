from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.capybara import (
    CapybaraSolver,
    build_capybara_verify_body,
    capybara_hash_hex,
    capybara_hash_matches,
    parse_capybara_challenge,
    parse_capybara_payload_token,
    sign_capybara_payload_token,
    solve_capybara_challenge,
    verify_capybara_payload_token,
    verify_capybara_solution,
)

SECRET = "capybara-secret-fixture"
INSTANCE_ID = "CAPY25"
CHALLENGE_ID = "capybara-fixture-id"
NONCE = "capybara-nonce-fixture"
EXP = 4_102_444_800
DIFFICULTY = 4
PAYLOAD_TOKEN = sign_capybara_payload_token(
    CHALLENGE_ID,
    NONCE,
    EXP,
    DIFFICULTY,
    SECRET,
    instance_id=INSTANCE_ID,
)
FIXTURE = {
    "challenge": {"id": CHALLENGE_ID, "nonce": NONCE, "type": "pow", "difficulty": DIFFICULTY},
    "status": "in-progress",
    "progress": 0,
    "expires_in": 30,
    "payload_token": PAYLOAD_TOKEN,
}


class _CapybaraHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    verify_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/api/challenge":
            type(self).challenge_calls += 1
            self._json(FIXTURE)
            return
        if self.path == "/api/verify":
            type(self).verify_calls.append(payload)
            if not verify_capybara_payload_token(
                payload.get("payload_token", ""),
                SECRET,
                instance_id=INSTANCE_ID,
                challenge=FIXTURE,
            ):
                self._json({"error": "invalid_payload"}, 400)
                return
            if not verify_capybara_solution(FIXTURE, payload.get("solution", "")):
                self._json({"status": "in-progress", "verified": False, "progress": 12}, 200)
                return
            self._json({"status": "solved", "verified": True, "progress": 100})
            return
        self._json({"error": "not-found"}, 404)


def test_capybara_payload_token_and_pow_fixture() -> None:
    token = parse_capybara_payload_token(PAYLOAD_TOKEN)
    challenge = parse_capybara_challenge(FIXTURE)
    solution = solve_capybara_challenge(challenge, timeout_sec=5)

    assert token.challenge_id == CHALLENGE_ID
    assert token.nonce == NONCE
    assert token.expires_at_sec == EXP
    assert token.difficulty == DIFFICULTY
    assert PAYLOAD_TOKEN == (
        "capybara-fixture-id.capybara-nonce-fixture.4102444800.4."
        "a0d6bad836b008a2b4b095c1084949e3440f615dacda515786aed9ec9e015ace"
    )
    assert verify_capybara_payload_token(PAYLOAD_TOKEN, SECRET, instance_id=INSTANCE_ID, challenge=challenge)
    assert not verify_capybara_payload_token(PAYLOAD_TOKEN, "wrong", instance_id=INSTANCE_ID, challenge=challenge)
    assert solution is not None
    assert solution.solution == "96094"
    assert solution.hash_hex == "0000d15140f6b11d2b956f646f3166375a71310e1b99b9a05bc335aca8b70433"
    assert solution.attempts == 96095
    assert capybara_hash_hex(NONCE, "96094") == solution.hash_hex
    assert capybara_hash_matches(solution.hash_hex, DIFFICULTY)
    assert verify_capybara_solution(challenge, solution)
    assert not verify_capybara_solution(challenge, "96093")

    body = build_capybara_verify_body(challenge, solution)
    assert body == {"id": CHALLENGE_ID, "solution": "96094", "payload_token": PAYLOAD_TOKEN}


def test_capybara_solver_protocol_flow_local_server() -> None:
    _CapybaraHandler.challenge_calls = 0
    _CapybaraHandler.verify_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapybaraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            CapybaraSolver().solve(
                base_url=base,
                submit=True,
                secret=SECRET,
                instance_id=INSTANCE_ID,
                difficulty=DIFFICULTY,
                duration_sec=30,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "capybara"
    assert ret.captcha_type == "payload_bound_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["solution"] == "96094"
    assert ret.diagnostics["payload_signature_valid"] is True
    assert _CapybaraHandler.challenge_calls == 1
    assert _CapybaraHandler.verify_calls[0]["solution"] == "96094"
