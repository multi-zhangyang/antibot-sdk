from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.h33botshield import (
    H33BotShieldSolver,
    h33botshield_hash_hex,
    h33botshield_hash_matches,
    parse_h33botshield_challenge,
    solve_h33botshield_challenge,
    verify_h33botshield_solution,
)

CHALLENGE = {
    "challenge_id": "h33-fixture-1",
    "nonce": "h33-fixture-nonce",
    "difficulty": 12,
    "algorithm": "sha256",
    "expires_at": 4_102_444_800,
}


def test_h33botshield_hash_and_solution_fixture() -> None:
    challenge = parse_h33botshield_challenge(CHALLENGE)
    solution = solve_h33botshield_challenge(challenge, max_attempts=20_000, timeout_sec=5)

    assert solution is not None
    assert solution.solution == 9893
    assert solution.hash_hex == h33botshield_hash_hex("h33-fixture-nonce", 9893)
    assert solution.hash_hex.startswith("000")
    assert h33botshield_hash_matches("h33-fixture-nonce", 9893, 12)
    assert verify_h33botshield_solution(challenge, solution)
    assert verify_h33botshield_solution(CHALLENGE, solution.submit_body)
    assert verify_h33botshield_solution(CHALLENGE, {"solution": 9893})


class _H33Handler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-h33-substrate", "fixture-substrate")
        self.send_header("x-h33-receipt", "fixture-receipt")
        self.send_header("x-h33-algorithms", "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f")
        self.send_header("x-h33-substrate-ts", "1780970251587")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append({"path": self.path, "payload": payload})
        if self.path == "/v1/botshield/challenge":
            self._json({**CHALLENGE, "expires_at": int(time.time()) + 30})
            return
        if self.path == "/v1/botshield/solve":
            ok = verify_h33botshield_solution(CHALLENGE, payload)
            self._json(
                {
                    "verified": bool(ok),
                    "session_token": "h33-session-fixture-token",
                    "valid_until": int(time.time()) + 3600,
                    "difficulty_solved": CHALLENGE["difficulty"],
                },
                200 if ok else 400,
            )
            return
        self._json({"error": "not_found"}, 404)


def test_h33botshield_solver_protocol_flow_local_server() -> None:
    _H33Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H33Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            H33BotShieldSolver().solve(
                base_url=base,
                submit=True,
                max_attempts=20_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "h33botshield"
    assert ret.captcha_type == "botshield_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "h33-session-fixture-token"
    assert ret.verify_code == "verified"
    assert ret.randstr == "h33-fixture-1"
    assert ret.diagnostics["difficulty"] == 12
    assert ret.raw["solution"]["solution"] == 9893
    assert ret.raw["challengeResponse"]["h33Headers"]["x-h33-substrate"] == "fixture-substrate"
    assert _H33Handler.calls[0]["path"] == "/v1/botshield/challenge"
    assert _H33Handler.calls[1]["path"] == "/v1/botshield/solve"
