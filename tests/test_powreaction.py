from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.powreaction import (
    PowReactionSolver,
    count_leading_zero_bits,
    parse_powreaction_challenge,
    powreaction_hash_hex,
    sign_powreaction_payload,
    solve_powreaction_challenge,
    verify_powreaction_jwt,
    verify_powreaction_solution,
)

SECRET = "test-secret-32-bytes-long-powreact"
PAYLOAD = {
    "id": "11111111-2222-4333-8444-555555555555",
    "reaction": "👍",
    "difficulty": 8,
    "exp": 4102444800,
    "clientId": "a" * 64,
    "rounds": [
        "00000000000000000000000000000000",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
    ],
}
TOKEN = sign_powreaction_payload(PAYLOAD, SECRET)
FIXTURE = {"challenge": TOKEN}


class _PowReactionHandler(BaseHTTPRequestHandler):
    challenge_calls: list[dict[str, Any]] = []
    submit_calls: list[dict[str, Any]] = []

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
        if self.path == "/demo/reactions/challenge":
            type(self).challenge_calls.append(payload)
            if payload.get("reaction") != PAYLOAD["reaction"]:
                self._json({"success": False, "error": "invalid_reaction"}, 400)
                return
            self._json({"challenge": TOKEN})
            return
        if self.path == "/demo/reactions":
            type(self).submit_calls.append(payload)
            if payload.get("reaction") != PAYLOAD["reaction"]:
                self._json({"success": False, "error": "invalid_reaction"}, 400)
                return
            if not verify_powreaction_jwt(payload.get("challenge", ""), SECRET):
                self._json({"success": False, "error": "bad_signature"}, 403)
                return
            if not verify_powreaction_solution(FIXTURE, payload):
                self._json({"success": False, "error": "pow_failed"}, 403)
                return
            self._json({"success": True})
            return
        self._json({"error": "not-found"}, 404)


def test_powreaction_signed_fixture() -> None:
    challenge = parse_powreaction_challenge(FIXTURE)
    solution = solve_powreaction_challenge(challenge, timeout_sec=5)

    assert verify_powreaction_jwt(TOKEN, SECRET)
    assert not verify_powreaction_jwt(TOKEN, "wrong-secret")
    assert challenge.challenge_id == PAYLOAD["id"]
    assert challenge.reaction == "👍"
    assert solution is not None
    assert solution.solutions == [199, 98, 85]
    assert solution.hashes == [
        "00d196ef6acdc983e5acebe801018f2e907058fdbd0c3db9c47ec8cfba9f9e75",
        "005b90ff430a78727a511fe0ef3321e0dbf123d2650e38251febb444b5903d0a",
        "00c133708ec1880737735be104b4b68bba05a5c34f224096c275a2987c2cec94",
    ]
    assert solution.leading_zero_bits == [8, 9, 8]
    assert solution.attempts == 385
    assert powreaction_hash_hex(PAYLOAD["rounds"][0], 199) == solution.hashes[0]
    assert count_leading_zero_bits(bytes.fromhex(solution.hashes[1])) == 9
    assert verify_powreaction_solution(FIXTURE, solution)
    assert not verify_powreaction_solution(FIXTURE, {"solutions": [198, 98, 85]})


def test_powreaction_solver_protocol_flow_local_server() -> None:
    _PowReactionHandler.challenge_calls = []
    _PowReactionHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowReactionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/demo/reactions"
    try:
        ret = asyncio.run(
            PowReactionSolver().solve(
                base_url=base,
                reaction="👍",
                submit=True,
                secret=SECRET,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powreaction"
    assert ret.captcha_type == "signed_multi_round_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["signature_valid"] is True
    assert ret.diagnostics["rounds"] == 3
    assert ret.diagnostics["difficulty"] == 8
    assert _PowReactionHandler.challenge_calls[0]["reaction"] == "👍"
    assert _PowReactionHandler.submit_calls[0]["solutions"] == [199, 98, 85]
