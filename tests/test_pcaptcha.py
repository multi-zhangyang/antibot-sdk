from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.pcaptcha import (
    PCaptchaSolver,
    base64_to_bigint,
    bigint_to_base64,
    generate_pcaptcha_challenge_from_roots,
    parse_pcaptcha_challenge,
    solve_pcaptcha_challenge,
    verify_pcaptcha_answer,
)


def test_pcaptcha_bigint_base64_roundtrip() -> None:
    values = [1, 255, 256, 123456789012345678901234567890]
    for value in values:
        assert base64_to_bigint(bigint_to_base64(value)) == value


def test_pcaptcha_parse_and_solve_quadratic_residue_problem() -> None:
    challenge = generate_pcaptcha_challenge_from_roots([3, 12345], woodall="2xs", challenge_id="cid-1")

    parsed = parse_pcaptcha_challenge(challenge.raw, challenge_id="cid-1")
    solution = solve_pcaptcha_challenge(parsed)

    assert parsed.woodall == "751*2^751-1"
    assert parsed.rounds == 2
    assert parsed.bits == 761
    assert verify_pcaptcha_answer(parsed, solution.answer) is True
    decoded_roots = [base64_to_bigint(x) for x in solution.answer.split(",")]
    assert len(decoded_roots) == 2


class _PCaptchaHandler(BaseHTTPRequestHandler):
    challenge = generate_pcaptcha_challenge_from_roots([42, 1337], woodall="2xs", challenge_id="pcap-local")
    validated = 0

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/api/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"id": self.challenge.challenge_id, "challenge": self.challenge.raw}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/api/validate":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        ok = data.get("id") == self.challenge.challenge_id and verify_pcaptcha_answer(
            self.challenge,
            str(data.get("answer") or ""),
        )
        type(self).validated += int(ok)
        body = json.dumps({"success": bool(ok)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_pcaptcha_solver_local_protocol_flow() -> None:
    _PCaptchaHandler.validated = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PCaptchaSolver().solve(
                challenge_url=f"{base}/api/challenge",
                validate_url=f"{base}/api/validate",
                validate=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "pcaptcha"
    assert ret.captcha_type == "quadratic_residue_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert verify_pcaptcha_answer(_PCaptchaHandler.challenge, str(ret.ticket)) is True
    assert _PCaptchaHandler.validated == 1
