from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.justnocaptcha import (
    JustNoCaptchaSolver,
    build_justnocaptcha_submit_body,
    create_justnocaptcha_challenge,
    extract_justnocaptcha_from_html,
    justnocaptcha_hash,
    justnocaptcha_hash_int,
    parse_justnocaptcha_challenge,
    solve_justnocaptcha_challenge,
    solve_justnocaptcha_puzzle,
    verify_justnocaptcha_solution,
)

SALT = "randomtestsalt"
CHALLENGE = (
    "30123456789abcdef0123456789abcdef"
    "fedcba9876543210fedcba9876543210"
    "00112233445566778899aabbccddeeff"
    "75d657ca1816d8d2fdffaaf0c8ef691d"
)
SOLUTION = "102601057110821"


class _JustNoCaptchaHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
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

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/justnocaptcha/challenge":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        self._json({"challenge": CHALLENGE})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/protected":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        type(self).submit_calls.append(payload)
        if not verify_justnocaptcha_solution(payload.get("challenge", ""), payload.get("solution", ""), challenge_salt=SALT):
            self._json({"ok": False, "reason": "pow_invalid"}, 422)
            return
        self._json({"ok": True, "accepted": True})


def test_justnocaptcha_hash_compatibility_vectors() -> None:
    assert justnocaptcha_hash("") == "ab3e7c0b3c04c6ccc8cb2ad33d4ca517"
    assert justnocaptcha_hash("abc") == "1cc93dbcdca8e0ac5d9d1d8c0ce42a46"
    assert justnocaptcha_hash_int("abc") == 482950588
    assert justnocaptcha_hash("hello") == "888d766ec5111e178e870fc58b84ba61"
    assert justnocaptcha_hash_int("hello") == 2290972270


def test_justnocaptcha_parse_solve_verify_fixture() -> None:
    challenge = parse_justnocaptcha_challenge(CHALLENGE, challenge_salt=SALT)
    solution = solve_justnocaptcha_challenge(challenge, timeout_sec=5)

    assert challenge.difficulty == 3
    assert challenge.number_puzzles == 3
    assert challenge.threshold == 10_000_000
    assert challenge.solution_length_required == 15
    assert solution is not None
    assert solution.solution == SOLUTION
    assert solution.candidates == ["10260", "10571", "10821"]
    assert solution.attempts == 1655
    assert solve_justnocaptcha_puzzle(challenge.puzzles[0], 3, deadline_epoch=None) == ("10260", 261)
    assert verify_justnocaptcha_solution(challenge, solution)
    assert verify_justnocaptcha_solution(CHALLENGE, SOLUTION, challenge_salt=SALT)
    assert not verify_justnocaptcha_solution(CHALLENGE, "102601057110820", challenge_salt=SALT)

    body = build_justnocaptcha_submit_body(challenge, solution)
    assert body == {"challenge": CHALLENGE, "solution": SOLUTION}


def test_justnocaptcha_create_and_extract_html() -> None:
    challenge = create_justnocaptcha_challenge(puzzles=1, difficulty=2, challenge_salt=SALT)
    parsed = parse_justnocaptcha_challenge(challenge, challenge_salt=SALT)
    html = f'<input type="hidden" name="challenge" value="{challenge}"><input name="solution" value="">'
    extracted = extract_justnocaptcha_from_html(html)

    assert parsed.difficulty == 2
    assert parsed.number_puzzles == 1
    assert extracted["challenge"] == challenge


def test_justnocaptcha_solver_protocol_flow_local_server() -> None:
    _JustNoCaptchaHandler.challenge_calls = 0
    _JustNoCaptchaHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JustNoCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            JustNoCaptchaSolver().solve(
                challenge_url=f"{base}/justnocaptcha/challenge",
                submit_url=f"{base}/protected",
                submit=True,
                challenge_salt=SALT,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "justnocaptcha"
    assert ret.captcha_type == "multi_puzzle_fnv_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == 3
    assert ret.diagnostics["number_puzzles"] == 3
    assert ret.diagnostics["solution_length"] == 15
    assert _JustNoCaptchaHandler.challenge_calls == 1
    assert _JustNoCaptchaHandler.submit_calls[0]["solution"] == SOLUTION
