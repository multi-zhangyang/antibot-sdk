from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.shapow import (
    ShapowSolver,
    parse_shapow_challenge,
    parse_shapow_challenge_html,
    parse_shapow_settings_js,
    shapow_digest,
    shapow_hash_matches,
    shapow_server_data,
    solve_shapow_challenge,
    solve_shapow_nonce,
    verify_shapow_response,
    verify_shapow_solution,
)

SERVER_DATA = shapow_server_data("127.0.0.1", 1_700_000_000, 0x1122334455667788)
SERVER_DATA_HEX = "7f000001000000000000000000000000000000006553f1001122334455667788"
VALID_RESPONSE_16 = SERVER_DATA_HEX + "07000200000000000000000000000000"


def _settings_js(server_data: bytes = SERVER_DATA, difficulty: int = 16) -> str:
    return f"""
    const nonceLength = 16;
    const difficulty = {difficulty};
    const serverData = '{server_data.hex()}';
    """


def test_shapow_fixture_and_nonce_search() -> None:
    assert SERVER_DATA.hex() == SERVER_DATA_HEX

    nonce, nonce_bytes, response_hex, digest_hex, attempts = solve_shapow_nonce(SERVER_DATA, 16, max_attempts=200_000)
    assert nonce == 131_079
    assert nonce_bytes.hex() == "07000200000000000000000000000000"
    assert response_hex == VALID_RESPONSE_16
    assert digest_hex == "00002c1df0b58af60c8cafacf44baa7cc633259921e65e5418ca87ec04ae2e2c"
    assert attempts == 131_080
    assert shapow_digest(response_hex).hex() == digest_hex
    assert shapow_hash_matches(bytes.fromhex(response_hex), 16)
    assert verify_shapow_response(SERVER_DATA, response_hex, 16, 16)
    assert not verify_shapow_response(SERVER_DATA, response_hex[:-1] + "1", 16, 16)


def test_shapow_settings_html_json_and_solution_parse() -> None:
    challenge = parse_shapow_settings_js(_settings_js())
    assert challenge.server_data == SERVER_DATA
    assert challenge.difficulty == 16
    assert challenge.nonce_length == 16

    html = """
    <!doctype html><html><body>
      <h1>Checking if you're a bot</h1>
      <a href="shapow_internal/challenge-settings.js">settings</a>
      <script src="shapow_internal/challenge-settings.js"></script>
      <script src="shapow_internal/challenge.js"></script>
    </body></html>
    """
    page = parse_shapow_challenge_html(html, page_url="http://target.test/protected")
    assert page.settings_path == "shapow_internal/challenge-settings.js"
    assert page.page_url == "http://target.test/protected"

    parsed = parse_shapow_challenge({"serverData": SERVER_DATA_HEX, "difficulty": 16, "nonceLength": 16})
    solution = solve_shapow_challenge(parsed, max_attempts=200_000)
    assert solution.response_hex == VALID_RESPONSE_16
    assert verify_shapow_solution(parsed, solution)
    assert verify_shapow_solution(parsed, {"shapow-response": VALID_RESPONSE_16})
    assert parse_shapow_challenge(SERVER_DATA_HEX).server_data == SERVER_DATA


class _ShapowHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    difficulty = 16
    random_challenge = 0x1122334455667788
    unix_time = 1_700_000_000

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _server_data(self) -> bytes:
        return shapow_server_data(self.client_address[0], type(self).unix_time, type(self).random_challenge)

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _challenge_page(self) -> bytes:
        return b"""
        <!doctype html><html><body>
          <h1>Checking if you're a bot</h1>
          <p>Verification performed by SHAPOW</p>
          <script src="shapow_internal/challenge-settings.js"></script>
          <script src="shapow_internal/challenge.js"></script>
        </body></html>
        """

    def _valid_response(self, value: str) -> bool:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return False
        return (
            len(raw) == 48
            and raw[:32] == self._server_data()
            and hashlib.sha256(raw).digest()[0] == 0
            and verify_shapow_response(self._server_data(), value, type(self).difficulty, 16)
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if parsed.path.endswith("/shapow_internal/challenge-settings.js"):
            self._write(_settings_js(self._server_data(), type(self).difficulty).encode("utf-8"), 200, {"Content-Type": "application/javascript"})
            return
        q = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        if "shapow-response" in q:
            if self._valid_response(q["shapow-response"]):
                self._write(b"ok", 200, {"Content-Type": "text/plain", "X-Shapow-Passed": "1"})
                return
            self._write(self._challenge_page(), 200, {"Content-Type": "text/html"})
            return
        self._write(self._challenge_page(), 200, {"Content-Type": "text/html"})


def test_shapow_solver_local_settings_and_submit_flow() -> None:
    _ShapowHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ShapowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(ShapowSolver().solve(base_url=base, submit=True, timeout_sec=5, max_attempts=200_000))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "shapow"
    assert ret.captcha_type == "nginx_ip_time_bound_pow"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["difficulty"] == 16
    assert ret.diagnostics["server_data_len"] == 32
    assert ret.diagnostics["nonce_length"] == 16
    assert json.loads(ret.ticket or "{}") == {"location": None, "x_shapow_passed": True}
    assert _ShapowHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _ShapowHandler.calls[1]["headers"]["Accept"].startswith("application/javascript")
    assert "shapow-response=" in _ShapowHandler.calls[2]["path"]
