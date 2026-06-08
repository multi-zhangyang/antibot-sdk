from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.privatecaptcha import (
    PrivateCaptchaSolver,
    parse_privatecaptcha_puzzle,
    parse_privatecaptcha_solutions,
    privatecaptcha_threshold_from_difficulty,
    solve_privatecaptcha_puzzle,
    verify_privatecaptcha_payload,
    verify_privatecaptcha_solutions,
)

# Fixture from PrivateCaptcha binary format:
# version=1, property_id=000102...0f, puzzle_id=0x1122334455667788,
# difficulty=64, solutions_count=2, expiration=2030-01-01, user_data=101112...1f.
# The solved payload was accepted by upstream Go VerifySolutions(): code=no-error.
FIXTURE_PUZZLE = (
    "AQABAgMEBQYHCAkKCwwNDg+Id2ZVRDMiEUACgNjbcBAREhMUFRYXGBkaGxwdHh8=."
    "AQB7Zml4dHVyZS1zaWduYXR1cmUteHg="
)
FIXTURE_PAYLOAD = (
    "AQAAAAAAAAAAAAAAAAAMAQAAAAAAAIk=."
    "AQABAgMEBQYHCAkKCwwNDg+Id2ZVRDMiEUACgNjbcBAREhMUFRYXGBkaGxwdHh8=."
    "AQB7Zml4dHVyZS1zaWduYXR1cmUteHg="
)


def test_privatecaptcha_threshold_matches_upstream_edges() -> None:
    assert privatecaptcha_threshold_from_difficulty(0) == 0xFFFFFFFF
    assert privatecaptcha_threshold_from_difficulty(255) == 1
    assert privatecaptcha_threshold_from_difficulty(64) == 16_777_215


def test_privatecaptcha_parse_solve_and_verify_fixture() -> None:
    puzzle = parse_privatecaptcha_puzzle(FIXTURE_PUZZLE)

    assert puzzle.version == 1
    assert puzzle.property_id_hex == "000102030405060708090a0b0c0d0e0f"
    assert puzzle.puzzle_id == 0x1122334455667788
    assert puzzle.difficulty == 64
    assert puzzle.solutions_count == 2
    assert len(puzzle.puzzle_buffer) == 128

    solution = solve_privatecaptcha_puzzle(puzzle, max_attempts_per_solution=1_000_000, timeout_sec=5)

    assert solution is not None
    assert [s.hex() for s in solution.solutions] == ["000000000000000c", "0100000000000089"]
    assert solution.payload == FIXTURE_PAYLOAD
    parsed_solutions, metadata = parse_privatecaptcha_solutions(solution.solutions_b64)
    assert metadata["version"] == 1
    assert metadata["error_code"] == 0
    assert verify_privatecaptcha_solutions(puzzle, parsed_solutions)
    assert verify_privatecaptcha_payload(solution.payload)


def test_privatecaptcha_parser_accepts_full_widget_payload() -> None:
    puzzle = parse_privatecaptcha_puzzle(FIXTURE_PAYLOAD)
    assert puzzle.raw_data == FIXTURE_PUZZLE


class _PrivateCaptchaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path.split("?", 1)[0] != "/puzzle":
            self.send_response(404)
            self.end_headers()
            return
        body = FIXTURE_PUZZLE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/verify":
            self.send_response(404)
            self.end_headers()
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = raw.decode("utf-8")
        self.calls.append({"payload": payload, "api_key": self.headers.get("X-API-Key")})
        ok = verify_privatecaptcha_payload(payload)
        body = json.dumps({"success": ok, "token": "pc-token"}).encode("utf-8")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_privatecaptcha_solver_protocol_flow_local_server() -> None:
    _PrivateCaptchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PrivateCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PrivateCaptchaSolver().solve(
                puzzle_url=f"{base}/puzzle",
                sitekey="site-key",
                verify_url=f"{base}/verify",
                api_key="api-key",
                submit=True,
                max_attempts_per_solution=1_000_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "privatecaptcha"
    assert ret.captcha_type == "compute_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "pc-token"
    assert ret.randstr == str(0x1122334455667788)
    assert ret.verify_code == "validated"
    assert ret.diagnostics["difficulty"] == 64
    assert _PrivateCaptchaHandler.calls[0]["payload"] == FIXTURE_PAYLOAD
    assert _PrivateCaptchaHandler.calls[0]["api_key"] == "api-key"
