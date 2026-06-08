from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.swetrix import (
    SwetrixSolver,
    count_leading_zero_nibbles,
    solve_swetrix_challenge,
    swetrix_hash_hex,
    verify_swetrix_solution,
)

FIXTURE = {
    "pid": "AP00000000000",
    "challenge": "swetrix-fixture-challenge",
    "difficulty": 4,
}


class _SwetrixHandler(BaseHTTPRequestHandler):
    generate_calls: list[dict[str, Any]] = []
    verify_calls: list[dict[str, Any]] = []
    validate_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/v1/captcha/generate":
            type(self).generate_calls.append(payload)
            if payload.get("pid") != FIXTURE["pid"]:
                self._json({"success": False, "message": "invalid pid"}, 403)
                return
            self._json({"challenge": FIXTURE["challenge"], "difficulty": FIXTURE["difficulty"]})
            return
        if self.path == "/v1/captcha/verify":
            type(self).verify_calls.append(payload)
            if payload.get("pid") != FIXTURE["pid"]:
                self._json({"success": False, "message": "invalid pid"}, 403)
                return
            if not verify_swetrix_solution(FIXTURE, payload):
                self._json({"success": False, "message": "PoW verification failed"}, 403)
                return
            self._json(
                {
                    "success": True,
                    "token": "swetrix-pass-token",
                    "timestamp": 1780955164000,
                    "challenge": FIXTURE["challenge"],
                    "pid": FIXTURE["pid"],
                }
            )
            return
        if self.path == "/v1/captcha/validate":
            type(self).validate_calls.append(payload)
            if payload.get("token") != "swetrix-pass-token" or payload.get("secret") != "PASS000000000000000000":
                self._json({"success": False, "message": "invalid token"}, 403)
                return
            self._json({"success": True, "data": {"challenge": FIXTURE["challenge"], "pid": FIXTURE["pid"]}})
            return
        self._json({"error": "not-found"}, 404)


def test_swetrix_pow_fixture() -> None:
    solution = solve_swetrix_challenge(FIXTURE, timeout_sec=5)

    assert solution is not None
    assert solution.nonce == 7944
    assert solution.solution == "0000fc991df7f982c1c15d19106a06daf81daeb2ab775aa35e87fa9fb3b1f496"
    assert solution.leading_zero_nibbles == 4
    assert solution.attempts == 7945
    assert swetrix_hash_hex(FIXTURE["challenge"], 7944) == solution.solution
    assert count_leading_zero_nibbles(bytes.fromhex(solution.solution)) == 4
    assert verify_swetrix_solution(FIXTURE, solution)
    assert not verify_swetrix_solution(FIXTURE, 7943)


def test_swetrix_solver_protocol_flow_local_server() -> None:
    _SwetrixHandler.generate_calls = []
    _SwetrixHandler.verify_calls = []
    _SwetrixHandler.validate_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SwetrixHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    api_url = f"http://127.0.0.1:{server.server_port}/v1/captcha"
    try:
        ret = asyncio.run(
            SwetrixSolver().solve(
                pid=FIXTURE["pid"],
                api_url=api_url,
                submit=True,
                secret="PASS000000000000000000",
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "swetrix"
    assert ret.captcha_type == "swetrix_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "swetrix-pass-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == 7944
    assert _SwetrixHandler.generate_calls[0]["pid"] == FIXTURE["pid"]
    assert _SwetrixHandler.verify_calls[0]["solution"] == "0000fc991df7f982c1c15d19106a06daf81daeb2ab775aa35e87fa9fb3b1f496"
    assert _SwetrixHandler.validate_calls[0]["token"] == "swetrix-pass-token"
