from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.altcha import (
    AltchaChallenge,
    AltchaSolver,
    altcha_hash_hex,
    challenge_from_altcha_header,
    parse_altcha_payload_b64,
    solve_altcha_challenge,
)


def _challenge(number: int = 4321) -> dict[str, Any]:
    salt = "salt:test"
    algorithm = "SHA-256"
    return {
        "algorithm": algorithm,
        "challenge": altcha_hash_hex(salt, number, algorithm),
        "salt": salt,
        "signature": "sig-test",
        "maxnumber": 9000,
    }


def test_altcha_hash_and_payload_solution() -> None:
    data = _challenge(4321)

    solution = solve_altcha_challenge(data, max_number=9000)

    assert solution is not None
    assert solution.number == 4321
    assert solution.payload()["challenge"] == data["challenge"]
    assert parse_altcha_payload_b64(solution.payload_b64()) == solution.payload()
    assert solution.authorization_header().startswith("Altcha challenge=")
    assert solution.authorization_header(style="kv").startswith("Altcha algorithm=SHA-256")


def test_altcha_header_challenge_parse_and_solve() -> None:
    data = _challenge(123)
    header = (
        'Altcha algorithm=SHA-256, challenge="%s", salt="%s", signature="%s", maxnumber=1000'
        % (data["challenge"], data["salt"], data["signature"])
    )

    challenge = challenge_from_altcha_header(header)
    solution = solve_altcha_challenge(challenge)

    assert isinstance(challenge, AltchaChallenge)
    assert challenge.salt == data["salt"]
    assert solution is not None
    assert solution.number == 123


def test_altcha_official_json_header_parse_and_solve() -> None:
    data = _challenge(321)
    header = "Altcha challenge=" + json.dumps(data, separators=(",", ":"))

    challenge = challenge_from_altcha_header(header)
    solution = solve_altcha_challenge(challenge)

    assert solution is not None
    assert solution.number == 321
    assert challenge.challenge == data["challenge"]


class _AltchaHandler(BaseHTTPRequestHandler):
    challenge = _challenge(789)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/altcha/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(self.challenge).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_altcha_solver_protocol_flow_local_server() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AltchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/altcha/challenge"
    try:
        ret = asyncio.run(AltchaSolver().solve(challenge_url=url, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    payload = parse_altcha_payload_b64(str(ret.ticket))
    assert ret.ok is True
    assert ret.provider == "altcha"
    assert ret.captcha_type == "proof_of_work"
    assert ret.capability == "protocol_solver"
    assert payload["number"] == 789
    assert payload["challenge"] == _AltchaHandler.challenge["challenge"]
    assert ret.verify_code == "789"
