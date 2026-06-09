from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote

from antibot_sdk.providers.lapti import (
    LaptiSolver,
    build_lapti_action_path,
    lapti_hash_matches,
    lapti_proof_hash_hex,
    lapti_token_for_data,
    parse_lapti_challenge,
    solve_lapti_challenge,
    verify_lapti_solution,
    verify_lapti_token,
)

DATA = "lapti-data-fixture"
SECRET = "lapti-secret-fixture"
TOKEN = lapti_token_for_data(DATA, SECRET)
COMPLEXITY = 2


class _LaptiHandler(BaseHTTPRequestHandler):
    handshake_calls = 0
    action_calls: list[tuple[str, str]] = []

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
        parts = [unquote(x) for x in self.path.strip("/").split("/")]
        if len(parts) == 2 and parts[0] == "handshake":
            type(self).handshake_calls += 1
            if not parts[1]:
                self._json({"error": "no.token.provided"}, 400)
                return
            self._json({"token": lapti_token_for_data(parts[1], SECRET), "complexity": COMPLEXITY})
            return
        if len(parts) == 3 and parts[0] == "action":
            data, nonce = parts[1], parts[2]
            type(self).action_calls.append((data, nonce))
            token = lapti_token_for_data(data, SECRET)
            if not lapti_hash_matches(lapti_proof_hash_hex(token, nonce), COMPLEXITY):
                self._json({"error": "proof.is.invalid"}, 400)
                return
            self._json({"message": "Action is completed!"})
            return
        self._json({"error": "nothing.here"}, 404)


def test_lapti_sha3_token_and_proof_fixture() -> None:
    challenge = parse_lapti_challenge({"token": TOKEN, "complexity": COMPLEXITY, "data": DATA})
    solution = solve_lapti_challenge(challenge, timeout_sec=5)

    assert TOKEN == hashlib.sha3_512(f"{DATA}{SECRET}".encode()).hexdigest()
    assert verify_lapti_token(TOKEN, DATA, SECRET)
    assert not verify_lapti_token(TOKEN, DATA, "wrong")
    assert solution is not None
    assert solution.nonce == "45510"
    assert solution.hash_hex == "00003b4360139014ad26b871a9e7226043eb58f5fc5d3e6c38d9dae449915dc91d60d268daf85aa5d1217fdb3765581153b4a5acbe88dab7a9c2db1b466cd74f"
    assert solution.attempts == 45510
    assert lapti_hash_matches(solution.hash_hex, COMPLEXITY)
    assert lapti_proof_hash_hex(TOKEN, "45510") == solution.hash_hex
    assert verify_lapti_solution(challenge, solution, secret=SECRET)
    assert not verify_lapti_solution(challenge, "45509", secret=SECRET)
    assert build_lapti_action_path(DATA, solution.nonce) == "/action/lapti-data-fixture/45510"


def test_lapti_solver_protocol_flow_local_server() -> None:
    _LaptiHandler.handshake_calls = 0
    _LaptiHandler.action_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LaptiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            LaptiSolver().solve(
                base_url=base,
                data=DATA,
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
    assert ret.provider == "lapti"
    assert ret.captcha_type == "sha3_token_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["complexity"] == COMPLEXITY
    assert ret.diagnostics["nonce"] == "45510"
    assert ret.diagnostics["token_valid"] is True
    assert _LaptiHandler.handshake_calls == 1
    assert _LaptiHandler.action_calls == [(DATA, "45510")]
