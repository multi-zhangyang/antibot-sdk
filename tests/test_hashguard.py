from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.hashguard import (
    HashGuardSolver,
    build_hashguard_verify_body,
    hashguard_hash_hex,
    hashguard_hash_matches_target,
    hashguard_target_from_difficulty_bits,
    parse_hashguard_challenge,
    solve_hashguard_challenge,
    verify_hashguard_solution,
)

CONTEXT = "login"
PROOF_TOKEN = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjcuMC4wLjEiLCJjb250ZXh0IjoibG9naW4iLCJpYXQiOjE3ODA5NjAwMDAsImV4cCI6MTc4MDk2MDMwMH0.signature"
FIXTURE = {
    "challengeId": "hg-fixture-1",
    "algorithm": "sha256",
    "seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "difficultyBits": 12,
    "target": hashguard_target_from_difficulty_bits(12),
    "issuedAt": "2026-06-08T23:00:00.000Z",
    "expiresAt": "2026-06-08T23:10:00.000Z",
    "context": CONTEXT,
}


class _HashGuardHandler(BaseHTTPRequestHandler):
    challenge_calls: list[dict[str, Any]] = []
    verify_calls: list[dict[str, Any]] = []
    introspect_calls: list[dict[str, Any]] = []

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
        if self.path == "/v1/pow/challenges":
            type(self).challenge_calls.append(payload)
            if payload.get("context") != CONTEXT:
                self._json({"code": "BAD_CONTEXT", "message": "bad context"}, 400)
                return
            self._json(FIXTURE)
            return
        if self.path == "/v1/pow/verifications":
            type(self).verify_calls.append(payload)
            if payload.get("challengeId") != FIXTURE["challengeId"]:
                self._json({"code": "BAD_CHALLENGE", "message": "bad challenge"}, 400)
                return
            if (payload.get("clientMetrics") or {}).get("solveTimeMs") != 900:
                self._json({"code": "BAD_METRICS", "message": "bad metrics"}, 400)
                return
            if not verify_hashguard_solution(FIXTURE, payload):
                self._json({"code": "BAD_POW", "message": "bad pow"}, 400)
                return
            self._json({"proofToken": PROOF_TOKEN, "expiresAt": "2026-06-08T23:05:00.000Z"})
            return
        if self.path == "/v1/pow/assertions/introspect":
            type(self).introspect_calls.append(payload)
            if payload.get("proofToken") != PROOF_TOKEN:
                self._json({"valid": False, "error": "bad token"}, 400)
                return
            self._json(
                {
                    "valid": True,
                    "subject": "127.0.0.1",
                    "context": CONTEXT,
                    "issuedAt": "2026-06-08T23:00:00.000Z",
                    "expiresAt": "2026-06-08T23:05:00.000Z",
                }
            )
            return
        self._json({"error": "not-found"}, 404)


def test_hashguard_target_and_pow_fixture() -> None:
    challenge = parse_hashguard_challenge(FIXTURE)
    solution = solve_hashguard_challenge(challenge, timeout_sec=5)

    assert challenge.target == "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    assert solution is not None
    assert solution.nonce == "7155"
    assert solution.hash_hex == "000323e968ececaed5de7e3622674edc2d00543a97fee78521ca7a7e07795bac"
    assert solution.attempts == 7156
    assert hashguard_hash_hex(FIXTURE["challengeId"], FIXTURE["seed"], 7155) == solution.hash_hex
    assert hashguard_hash_matches_target(solution.hash_hex, challenge.target)
    assert verify_hashguard_solution(FIXTURE, solution)
    assert not verify_hashguard_solution(FIXTURE, 7154)

    body = build_hashguard_verify_body(challenge, solution, solve_time_ms=123)
    assert body == {"challengeId": FIXTURE["challengeId"], "nonce": "7155", "clientMetrics": {"solveTimeMs": 123}}


def test_hashguard_solver_protocol_flow_local_server() -> None:
    _HashGuardHandler.challenge_calls = []
    _HashGuardHandler.verify_calls = []
    _HashGuardHandler.introspect_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HashGuardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            HashGuardSolver().solve(
                base_url=base_url,
                context=CONTEXT,
                submit=True,
                introspect=True,
                min_solve_ms=900,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "hashguard"
    assert ret.captcha_type == "jwt_proof_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == PROOF_TOKEN
    assert ret.verify_code == "introspected"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == "7155"
    assert ret.diagnostics["reported_solve_ms"] == 900
    assert ret.diagnostics["token_context"] == CONTEXT
    assert _HashGuardHandler.challenge_calls[0] == {"context": CONTEXT}
    assert _HashGuardHandler.verify_calls[0] == {
        "challengeId": FIXTURE["challengeId"],
        "nonce": "7155",
        "clientMetrics": {"solveTimeMs": 900},
    }
    assert _HashGuardHandler.introspect_calls[0] == {"proofToken": PROOF_TOKEN, "consume": True}
