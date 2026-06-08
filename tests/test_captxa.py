from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.captxa import (
    CaptxaSolver,
    captxa_pow_hash_hex,
    count_leading_zero_bits,
    generate_captxa_browser_metrics,
    score_captxa_browser_metrics,
    solve_captxa_simple_challenge,
    verify_captxa_simple_solution,
)

FIXTURE = {
    "challenge_token": "opaque-token",
    "pow_challenge": "0102030405060708090a0b0c0d0e0f10",
    "pow_difficulty": 12,
}


def test_captxa_pow_fixture() -> None:
    solution = solve_captxa_simple_challenge(FIXTURE, timeout_sec=5)

    assert solution is not None
    assert solution.nonce == 1063
    assert solution.hash_hex == "000eebbbc131e32bbe27789e77ca2d2555e54d31952e83e1050990fc7f182744"
    assert solution.leading_zero_bits == 12
    assert solution.attempts == 1064
    assert captxa_pow_hash_hex(FIXTURE["pow_challenge"], 1063) == solution.hash_hex
    assert count_leading_zero_bits(bytes.fromhex(solution.hash_hex)) == 12
    assert verify_captxa_simple_solution(FIXTURE, solution)
    assert not verify_captxa_simple_solution(FIXTURE, 1062)


def test_captxa_synthetic_metrics_low_risk_and_botty() -> None:
    low = generate_captxa_browser_metrics()
    assert score_captxa_browser_metrics(low) == {"success": True, "score": 0, "reasons": []}

    botty = dict(low)
    botty.update({"webdriver": True, "webglrenderer": "SwiftShader"})
    scored = score_captxa_browser_metrics(botty)
    assert scored["success"] is False
    assert scored["score"] >= 5


class _CaptxaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    metrics: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200, *, token: str | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if token:
            self.send_header("X-Captcha-Token", token)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/challenge/simp":
            type(self).metrics.append(payload)
            if score_captxa_browser_metrics(payload)["success"] is not True:
                self._json({"valid": False, "error": "Do_complex_captcha"}, 403)
                return
            self._json(FIXTURE)
            return
        if self.path == "/solve/simp":
            type(self).calls.append(payload)
            if payload.get("challenge_token") != FIXTURE["challenge_token"]:
                self._json({"valid": False, "error": "invalid_token"}, 403)
                return
            if not verify_captxa_simple_solution(FIXTURE, payload.get("pow_solution")):
                self._json({"valid": False, "error": "pow_failed"}, 403)
                return
            self._json(True, token="captxa-pass-token")
            return
        self._json({"error": "not-found"}, 404)


def test_captxa_solver_protocol_flow_local_server() -> None:
    _CaptxaHandler.calls = []
    _CaptxaHandler.metrics = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CaptxaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            CaptxaSolver().solve(
                base_url=base,
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "captxa"
    assert ret.captcha_type == "ja4_bound_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "captxa-pass-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == 1063
    assert _CaptxaHandler.metrics[0]["webdriver"] is False
    assert _CaptxaHandler.calls[0]["pow_solution"] == 1063
