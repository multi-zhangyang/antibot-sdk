from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.vulcan import (
    VulcanSolver,
    build_vulcan_submit_body,
    extract_vulcan_from_html,
    parse_vulcan_challenge,
    solve_vulcan_challenge,
    solve_vulcan_round,
    verify_vulcan_round,
    verify_vulcan_solution,
    vulcan_hash_hex,
    vulcan_hash_value,
)

CHALLENGE = "vulcan-fixture"
DIFFICULTY = 1_048_576
ROUNDS = 3
SOLUTION = "1136;5242;945"
ROUND_HASHES = [
    "0004011df37dafbe978e8a265b29372179b0e33982ebb463e8a1e1ec25a613ca",
    "00042775d32f79dbc2971bb19fac7c4ee0740213c2ff522543a5105e03f22a5a",
    "000a29862790f9049b10cc1a20bf5e5c98a4e86f033b99289128dedd1255797e",
]
ROUND_VALUES = [262_429, 272_245, 665_990]


class _VulcanHandler(BaseHTTPRequestHandler):
    challenge_calls = 0

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/captcha":
            self.send_response(404)
            self.end_headers()
            return
        type(self).challenge_calls += 1
        body = f"""
        <html><body>
          <form method="post" action="/protected">
            <div class="captcha-wrapper vulcan"
                 data-challenge="{CHALLENGE}"
                 data-difficulty="{DIFFICULTY}"
                 data-rounds="0"
                 data-original-rounds="{ROUNDS}"></div>
            <input type="hidden" id="captcha-response" name="vulcan_response" value="">
          </form>
        </body></html>
        """.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_vulcan_hash_round_vectors() -> None:
    assert vulcan_hash_hex(CHALLENGE, "1136") == ROUND_HASHES[0]
    assert vulcan_hash_value(ROUND_HASHES[0]) == ROUND_VALUES[0]
    assert verify_vulcan_round(CHALLENGE, "1136", DIFFICULTY)
    assert not verify_vulcan_round(CHALLENGE, "1135", DIFFICULTY)

    nonce, digest, value, attempts = solve_vulcan_round(
        CHALLENGE,
        DIFFICULTY,
        max_attempts=2_000,
        deadline_epoch=None,
    )
    assert (nonce, digest, value, attempts) == (1136, ROUND_HASHES[0], ROUND_VALUES[0], 1136)


def test_vulcan_chained_solution_fixture() -> None:
    challenge = parse_vulcan_challenge({"challenge": CHALLENGE, "difficulty": DIFFICULTY, "rounds": ROUNDS})
    solution = solve_vulcan_challenge(challenge, timeout_sec=5, max_attempts_per_round=10_000, workers=2)

    assert solution is not None
    assert solution.solution == SOLUTION
    assert solution.nonces == ["1136", "5242", "945"]
    assert [r.hash_hex for r in solution.rounds] == ROUND_HASHES
    assert [r.value for r in solution.rounds] == ROUND_VALUES
    assert verify_vulcan_solution(challenge, solution)
    assert verify_vulcan_solution(challenge, SOLUTION)
    assert not verify_vulcan_solution(challenge, "1136;5242;944")
    assert build_vulcan_submit_body(challenge, solution) == {"captcha-response": SOLUTION}


def test_vulcan_extracts_html_wrapper_and_response_field() -> None:
    html = f"""
    <div class="captcha-wrapper"
         data-challenge="{CHALLENGE}"
         data-difficulty="{DIFFICULTY}"
         data-rounds="1"
         data-original-rounds="{ROUNDS}"></div>
    <input id="captcha-response" name="custom_vulcan_response" value="">
    """
    extracted = extract_vulcan_from_html(html)
    challenge = parse_vulcan_challenge(extracted)

    assert extracted == {
        "challenge": CHALLENGE,
        "difficulty": DIFFICULTY,
        "rounds": ROUNDS,
        "responseField": "custom_vulcan_response",
    }
    assert challenge.response_field == "custom_vulcan_response"


def test_vulcan_solver_protocol_flow_local_html_server() -> None:
    _VulcanHandler.challenge_calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulcanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            VulcanSolver().solve(
                challenge_url=f"{base}/captcha",
                timeout_sec=5,
                max_attempts_per_round=10_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "vulcan"
    assert ret.captcha_type == "chained_sha256_uint32_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "solved"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["rounds"] == ROUNDS
    assert ret.diagnostics["solution"] == SOLUTION
    assert json.loads(ret.ticket or "{}") == {"vulcan_response": SOLUTION}
    assert _VulcanHandler.challenge_calls == 1
