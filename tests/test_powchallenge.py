from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.powchallenge import (
    PowChallengeSolver,
    count_leading_zero_bits,
    decode_powchallenge_base64,
    encode_powchallenge_base64,
    parse_powchallenge_challenge,
    powchallenge_hash_hex,
    solve_powchallenge_challenge,
    verify_powchallenge_solution,
)

FIXTURE = {
    "req_id": "019aa0e6-b33f-7000-8000-000000000001",
    "challenge": base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
    "difficulty": 2,
}


class _PowChallengeHandler(BaseHTTPRequestHandler):
    challenge_calls: int = 0
    verify_calls: list[dict[str, Any]] = []
    redeemed: bool = False

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
        if self.path == "/challenge":
            type(self).challenge_calls += 1
            self._json(FIXTURE)
            return
        self._json({"error": "not-found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/verify":
            type(self).verify_calls.append(payload)
            if type(self).redeemed:
                self._json({"error": "Challenge not found or expired"}, 400)
                return
            if payload.get("req_id") != FIXTURE["req_id"]:
                self._json({"error": "Challenge not found or expired"}, 400)
                return
            if payload.get("challenge") != FIXTURE["challenge"] or payload.get("difficulty") != FIXTURE["difficulty"]:
                self._json({"error": "Difficulty mismatch"}, 400)
                return
            if not verify_powchallenge_solution(FIXTURE, payload):
                self._json({"error": "Invalid Proof of Work"}, 400)
                return
            type(self).redeemed = True
            self._json({"message": "Proof of Work validated successfully."})
            return
        self._json({"error": "not-found"}, 404)


def test_powchallenge_argon2_fixture() -> None:
    solution = solve_powchallenge_challenge(FIXTURE, max_attempts=20, timeout_sec=10)

    assert solution is not None
    assert solution.nonce_b64 == "BQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    assert solution.hash_hex == "08c334528036ae3e34b9de25ab25d2c0dbd22964c90e676032db879f498ca94d"
    assert solution.leading_zero_bits == 4
    assert solution.attempts == 6
    assert powchallenge_hash_hex(FIXTURE, solution.nonce_b64) == solution.hash_hex
    assert count_leading_zero_bits(bytes.fromhex(solution.hash_hex)) == 4
    assert verify_powchallenge_solution(FIXTURE, solution)
    assert not verify_powchallenge_solution(FIXTURE, {"nonce": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})


def test_powchallenge_base64_compatibility_and_parser() -> None:
    challenge = parse_powchallenge_challenge(FIXTURE)
    raw_nonce = bytes(range(32))
    urlsafe = encode_powchallenge_base64(raw_nonce, urlsafe=True, padding=False)

    assert challenge.req_id == FIXTURE["req_id"]
    assert challenge.challenge_bytes == b"0123456789abcdef0123456789abcdef"
    assert decode_powchallenge_base64(urlsafe) == raw_nonce
    assert decode_powchallenge_base64(encode_powchallenge_base64(raw_nonce)) == raw_nonce


def test_powchallenge_solver_protocol_flow_local_server() -> None:
    _PowChallengeHandler.challenge_calls = 0
    _PowChallengeHandler.verify_calls = []
    _PowChallengeHandler.redeemed = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowChallengeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PowChallengeSolver().solve(
                base_url=base_url,
                submit=True,
                max_attempts=20,
                timeout_sec=10,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powchallenge"
    assert ret.captcha_type == "argon2id_memory_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == 2
    assert ret.diagnostics["nonce"] == "BQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    assert _PowChallengeHandler.challenge_calls == 1
    assert _PowChallengeHandler.verify_calls[0]["req_id"] == FIXTURE["req_id"]
    assert _PowChallengeHandler.verify_calls[0]["nonce"] == "BQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
