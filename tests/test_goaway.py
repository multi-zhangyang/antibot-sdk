from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.goaway import (
    GoAwaySolver,
    goaway_challenge_from_key,
    goaway_digest,
    goaway_result_hex,
    goaway_target_for_difficulty,
    parse_goaway_challenge,
    parse_goaway_challenge_html,
    solve_goaway_challenge,
    verify_goaway_pow,
    verify_goaway_solution,
)

KEY_B64 = "Pl02g55pPapXdVc3SVfMZQGymmyE0dTCpq0qm8ax9ss="
DIFFICULTY = 20
CHALLENGE_HEX = "37964cdb86c8b4fe24ae9654cd40b0d6d68296ce846f4575ba414e41b07f2893"
TARGET_HEX = "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
VALID_RESULT_HEX = CHALLENGE_HEX + "68cd110000000000"
FAIL_RESULT_HEX = CHALLENGE_HEX + "68cd110000000001"
VALID_RESULT_B64 = base64.b64encode(VALID_RESULT_HEX.encode("ascii")).decode("ascii")
FAIL_RESULT_B64 = base64.b64encode(FAIL_RESULT_HEX.encode("ascii")).decode("ascii")


def test_goaway_source_style_fixture() -> None:
    assert goaway_challenge_from_key(KEY_B64, DIFFICULTY) == CHALLENGE_HEX
    assert goaway_target_for_difficulty(DIFFICULTY) == TARGET_HEX

    challenge = parse_goaway_challenge({"Key": KEY_B64, "Parameters": {"difficulty": "20"}})
    solution = solve_goaway_challenge(challenge, max_attempts=1_500_000)

    assert solution.nonce == 1_166_696
    assert solution.result == VALID_RESULT_HEX
    assert goaway_result_hex(CHALLENGE_HEX, solution.nonce) == VALID_RESULT_HEX
    assert solution.digest_hex == "000005b687a4e6ca8f8d0658f9d4b3dbd489019a521f58e63c8338c8c4f2967d"
    assert goaway_digest(CHALLENGE_HEX, solution.nonce).hex() == solution.digest_hex
    assert verify_goaway_solution(challenge, solution)
    assert verify_goaway_solution(challenge, {"Result": VALID_RESULT_B64})
    assert not verify_goaway_solution(challenge, {"Result": FAIL_RESULT_B64})
    assert verify_goaway_pow(CHALLENGE_HEX, VALID_RESULT_HEX, DIFFICULTY, TARGET_HEX)


def test_goaway_make_challenge_wrapper_and_html_parse() -> None:
    wrapper = {
        "Code": 200,
        "Data": base64.b64encode(
            json.dumps(
                {"challenge": CHALLENGE_HEX, "target": TARGET_HEX, "difficulty": DIFFICULTY}
            ).encode("utf-8")
        ).decode("ascii"),
        "Headers": {"Content-Type": ["application/json; charset=utf-8"]},
    }
    parsed = parse_goaway_challenge(wrapper)
    assert parsed.challenge == CHALLENGE_HEX
    assert parsed.target == TARGET_HEX
    assert parsed.difficulty == DIFFICULTY

    html = """
    <!doctype html><html><body>
      <p id="status">Loading challenge <em>js-pow-sha256</em>...</p>
      <p><small>If you have any issues contact the site administrator and provide the following Request Id: <em>cf33e115f699c50822c4e56ed3c610dc</em></small></p>
      <script async type="module" src="/go-away/challenge/js-pow-sha256/script.mjs?cacheBust=1"></script>
      <footer>Protected by go-away :: Request Id <em>cf33e115f699c50822c4e56ed3c610dc</em></footer>
    </body></html>
    """
    page = parse_goaway_challenge_html(html, page_url="https://target.example/protected")
    assert page.challenge_path == "/go-away/challenge/js-pow-sha256"
    assert page.challenge_name == "js-pow-sha256"
    assert page.request_id == "cf33e115f699c50822c4e56ed3c610dc"
    assert page.redirect == "https://target.example/protected"


class _GoAwayHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    difficulty = 16
    key_b64 = KEY_B64
    request_id = "cf33e115f699c50822c4e56ed3c610dc"
    challenge_path = "/go-away/challenge/js-pow-sha256"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    @classmethod
    def challenge_hex(cls) -> str:
        return goaway_challenge_from_key(cls.key_b64, cls.difficulty)

    @classmethod
    def target_hex(cls) -> str:
        return goaway_target_for_difficulty(cls.difficulty)

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if parsed.path.endswith("/verify-challenge"):
            q = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
            ok = (
                q.get("__goaway_challenge") == "js-pow-sha256"
                and q.get("__goaway_id") == type(self).request_id
                and verify_goaway_pow(
                    type(self).challenge_hex(),
                    q.get("__goaway_token", ""),
                    type(self).difficulty,
                    type(self).target_hex(),
                )
            )
            if ok:
                self._write(
                    b"",
                    307,
                    {
                        "Location": q.get("__goaway_redirect") or "/protected",
                        "Set-Cookie": "goaway-test-state=ok; Path=/; HttpOnly",
                    },
                )
                return
            self._write(b"access denied", 403, {"Content-Type": "text/plain"})
            return

        html = f"""
        <!doctype html><html><body>
          <p id="status">Loading challenge <em>js-pow-sha256</em>...</p>
          <script async type="module" src="{type(self).challenge_path}/script.mjs?cacheBust=fixture"></script>
          <footer>Protected by go-away :: Request Id <em>{type(self).request_id}</em></footer>
        </body></html>
        """.encode("utf-8")
        self._write(html, 418, {"Content-Type": "text/html; charset=utf-8"})

    def do_POST(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers)})
        if self.path != type(self).challenge_path + "/make-challenge":
            self._write(b"not found", 404)
            return
        body = json.dumps(
            {
                "challenge": type(self).challenge_hex(),
                "target": type(self).target_hex(),
                "difficulty": type(self).difficulty,
            }
        ).encode("utf-8")
        self._write(body, 200, {"Content-Type": "application/json; charset=utf-8"})


def test_goaway_solver_local_make_and_verify_flow() -> None:
    _GoAwayHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GoAwayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(
            GoAwaySolver().solve(base_url=base, submit=True, timeout_sec=5, max_attempts=200_000)
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "goaway"
    assert ret.captcha_type == "goaway_js_pow_sha256"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["difficulty"] == 16
    assert ret.diagnostics["challenge_path"] == _GoAwayHandler.challenge_path
    assert json.loads(ret.ticket or "{}")["state_cookie"] is True
    assert _GoAwayHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _GoAwayHandler.calls[1]["headers"]["Sec-Fetch-Mode"] == "cors"
    assert _GoAwayHandler.calls[2]["headers"]["Accept-Language"] == "en-US,en;q=0.9"
    assert "__goaway_elapsedTime=" in _GoAwayHandler.calls[2]["path"]
