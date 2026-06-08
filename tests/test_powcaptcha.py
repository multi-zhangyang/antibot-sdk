from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.powcaptcha import (
    PowCaptchaSolver,
    parse_powcaptcha_quiz,
    powcaptcha_quiz_to_base64,
    solve_powcaptcha_quiz,
    verify_powcaptcha_answer,
)

# Generated with Y0ursTruly/pow_captcha pow.js takeTest fixture:
# quiz = SERIAL(Buffer([0]), sha256(Buffer([2])), [[0,[0,3]]], 0, 256)
FIXTURE_QUIZ_B64 = "AP8AAQAAAAPbwbTJAP/kjVdbXaXGOAQBJfZdsP4+JElLduqYZFfZhgA="
FIXTURE_ANSWER = b"\x02"

# Generated with makeTest(16, "abcd", 32, 127) from upstream pow.js.
SAMPLE_QUIZ_B64 = "IH4AAgADXmUAAWJjiNQmb9TmM40TuEX88olXnSCciXgjuSF9o+Fhk28DFYlhYmNh"
SAMPLE_ANSWER = b"abcd"


def test_powcaptcha_parse_and_solve_wasm_fixture() -> None:
    quiz = parse_powcaptcha_quiz(FIXTURE_QUIZ_B64)

    assert quiz.a1 == 0
    assert quiz.a2 == 256
    assert quiz.search_space == 4
    assert quiz.buffer == b"\x00"
    assert quiz.uncertainties[0].index == 0
    assert quiz.uncertainties[0].values == (0, 1, 2, 3)
    assert powcaptcha_quiz_to_base64(quiz.raw) == FIXTURE_QUIZ_B64

    solution = solve_powcaptcha_quiz(quiz, max_attempts=10, timeout_sec=5)

    assert solution is not None
    assert solution.answer == FIXTURE_ANSWER
    assert solution.answer_hex == "02"
    assert solution.attempts == 2
    assert verify_powcaptcha_answer(quiz, solution.answer)
    assert verify_powcaptcha_answer(FIXTURE_QUIZ_B64, solution.answer_b64)


def test_powcaptcha_solve_mixed_radix_sample() -> None:
    quiz = parse_powcaptcha_quiz(SAMPLE_QUIZ_B64)

    assert quiz.a1 == 32
    assert quiz.a2 == 127
    assert quiz.search_space == 16
    assert [(u.index, u.minimum, u.maximum, u.base) for u in quiz.uncertainties] == [
        (3, 94, 101, 8),
        (1, 98, 99, 2),
    ]

    solution = solve_powcaptcha_quiz(quiz, max_attempts=100, timeout_sec=5)

    assert solution is not None
    assert solution.answer == SAMPLE_ANSWER
    assert solution.answer_b64 == base64.b64encode(SAMPLE_ANSWER).decode("ascii")
    assert verify_powcaptcha_answer(quiz, SAMPLE_ANSWER)


class _PowCaptchaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"id": "pow-1", "quiz": FIXTURE_QUIZ_B64}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/verify":
            self.send_response(404)
            self.end_headers()
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        ok = payload.get("id") == "pow-1" and verify_powcaptcha_answer(FIXTURE_QUIZ_B64, payload.get("answer", ""))
        body = json.dumps({"ok": ok, "token": "pow-token"}).encode("utf-8")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_powcaptcha_solver_protocol_flow_local_server() -> None:
    _PowCaptchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PowCaptchaSolver().solve(
                challenge_url=f"{base}/challenge",
                verify_url=f"{base}/verify",
                submit=True,
                max_attempts=10,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powcaptcha"
    assert ret.captcha_type == "buffer_reconstruction_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "pow-token"
    assert ret.randstr == "pow-1"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["search_space"] == 4
    assert _PowCaptchaHandler.calls[0]["answerHex"] == "02"
