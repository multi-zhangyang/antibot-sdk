from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.friendlycaptcha import (
    FriendlyCaptchaSolver,
    create_friendly_diagnostics,
    friendly_difficulty_to_threshold,
    parse_friendly_solution_payload,
    parse_friendly_puzzle,
    solve_friendly_puzzle,
)


def _fixture_puzzle() -> str:
    # Same easy fixture shape used by friendly-pow: difficulty=50, n=1.
    puzzle = bytes(
        [
            97,
            131,
            208,
            51,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            10,
            1,
            50,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            2,
            3,
            4,
            5,
        ]
    )
    return "sigtest." + base64.b64encode(puzzle).decode("ascii")


def test_friendlycaptcha_fixture_solution_matches_friendly_pow() -> None:
    puzzle = parse_friendly_puzzle(_fixture_puzzle())

    solution = solve_friendly_puzzle(puzzle, max_attempts_per_solution=1_000)

    assert puzzle.n == 1
    assert puzzle.difficulty == 50
    assert puzzle.threshold == friendly_difficulty_to_threshold(50)
    assert solution is not None
    assert solution.solution_bytes == bytes([0, 0, 0, 0, 154, 0, 0, 0])
    assert solution.payload.startswith("sigtest.")
    decoded = parse_friendly_solution_payload(solution.payload)
    assert decoded["solution_bytes"] == solution.solution_bytes


def test_friendlycaptcha_diagnostics_big_endian() -> None:
    assert create_friendly_diagnostics(0, 258) == bytes([0, 1, 2])


class _FriendlyHandler(BaseHTTPRequestHandler):
    puzzle = _fixture_puzzle()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path.split("?", 1)[0] != "/api/v1/puzzle":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"data": {"puzzle": self.puzzle}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_friendlycaptcha_solver_protocol_flow_local_server() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FriendlyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/api/v1/puzzle"
    try:
        ret = asyncio.run(
            FriendlyCaptchaSolver().solve(
                puzzle_url=url,
                sitekey="FC_TEST",
                timeout_sec=5,
                max_attempts_per_solution=1_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    payload = parse_friendly_solution_payload(str(ret.ticket))
    assert ret.ok is True
    assert ret.provider == "friendlycaptcha"
    assert ret.captcha_type == "proof_of_work"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "1"
    assert payload["solution_bytes"] == bytes([0, 0, 0, 0, 154, 0, 0, 0])
