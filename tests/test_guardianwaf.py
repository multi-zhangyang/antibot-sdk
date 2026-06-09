from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.guardianwaf import (
    GuardianWafSolver,
    guardianwaf_hash_hex,
    make_guardianwaf_cookie,
    parse_guardianwaf_challenge,
    parse_guardianwaf_challenge_html,
    solve_guardianwaf_challenge,
    solve_guardianwaf_nonce,
    verify_guardianwaf_cookie,
    verify_guardianwaf_pow,
    verify_guardianwaf_solution,
)

CHALLENGE = "0123456789abcdef0123456789abcdef"
DIFFICULTY = 16
VALID_NONCE = 63_947
VALID_NONCE_HEX = "f9cb"
VALID_DIGEST = "0000aa98479fc133481ba43e472e5d19f16b17ed48d3634ddb3f5b7cf2ed2c5c"
SECRET = "guardian-secret"


def _challenge_page(challenge: str = CHALLENGE, difficulty: int = DIFFICULTY, redirect: str = "/protected") -> str:
    return f"""
    <!doctype html><html><body>
      <h1>Verifying your browser</h1>
      <form method="POST" action="/__guardianwaf/challenge/verify"></form>
      <script>
      (function(){{
        "use strict";
        var C="{challenge}",D={difficulty},R="{redirect}";
        function submit(nonce){{}}
      }})();
      </script>
    </body></html>
    """


def test_guardianwaf_source_style_fixture_and_cookie() -> None:
    nonce, nonce_text, digest_hex, attempts = solve_guardianwaf_nonce(CHALLENGE, DIFFICULTY, max_attempts=100_000)
    assert nonce == VALID_NONCE
    assert nonce_text == VALID_NONCE_HEX
    assert digest_hex == VALID_DIGEST
    assert attempts == VALID_NONCE + 1
    assert guardianwaf_hash_hex(CHALLENGE, nonce_text) == VALID_DIGEST
    assert verify_guardianwaf_pow(CHALLENGE, nonce_text, DIFFICULTY)
    assert not verify_guardianwaf_pow(CHALLENGE, "f9cc", DIFFICULTY)

    cookie = make_guardianwaf_cookie(secret=SECRET, client_ip="127.0.0.1", ttl=3600, now=1_700_000_000)
    assert cookie == "313730303030333630307c3132372e302e302e31.66b1097c660d5a18cf04710c6bf3b4853afbe4ec945eaf716f862764912dc198"
    assert verify_guardianwaf_cookie(cookie, secret=SECRET, client_ip="127.0.0.1", now=1_700_000_100)
    assert not verify_guardianwaf_cookie(cookie, secret=SECRET, client_ip="127.0.0.2", now=1_700_000_100)


def test_guardianwaf_parse_html_json_and_solution() -> None:
    html = _challenge_page(redirect="/protected?x=1")
    parsed = parse_guardianwaf_challenge_html(html, page_url="https://gate.example/protected?x=1")
    assert parsed.challenge == CHALLENGE
    assert parsed.difficulty == DIFFICULTY
    assert parsed.redirect == "/protected?x=1"
    assert parsed.verify_path == "/__guardianwaf/challenge/verify"
    assert parsed.verify_url == "https://gate.example/__guardianwaf/challenge/verify"

    parsed_json = parse_guardianwaf_challenge({"challenge": CHALLENGE, "difficulty": DIFFICULTY, "redirect": "/r"})
    solution = solve_guardianwaf_challenge(parsed_json, max_attempts=100_000)
    assert solution.nonce == VALID_NONCE
    assert solution.nonce_text == VALID_NONCE_HEX
    assert solution.submit_body == {"challenge": CHALLENGE, "nonce": VALID_NONCE_HEX, "redirect": "/r"}
    assert verify_guardianwaf_solution(parsed_json, solution)
    assert verify_guardianwaf_solution(parsed_json, {"nonce": VALID_NONCE_HEX})


def test_guardianwaf_parse_spaced_inline_vars_from_generic_html() -> None:
    html = (
        "<script>let C = \"0123456789abcdef0123456789abcdef\", "
        "D = 16, R = \"/spaced\";</script>"
    )
    parsed = parse_guardianwaf_challenge(html, page_url="https://gate.example/start")
    assert parsed.challenge == CHALLENGE
    assert parsed.difficulty == DIFFICULTY
    assert parsed.redirect == "/spaced"


def test_guardianwaf_parallel_attempts_hint_is_precise() -> None:
    nonce, nonce_text, digest_hex, attempts = solve_guardianwaf_nonce(
        CHALLENGE,
        DIFFICULTY,
        max_attempts=100_000,
        workers=2,
        chunk_size=50_000,
    )
    assert nonce == VALID_NONCE
    assert nonce_text == VALID_NONCE_HEX
    assert digest_hex == VALID_DIGEST
    assert attempts == VALID_NONCE + 1


class _GuardianWafHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    difficulty = DIFFICULTY
    challenge = CHALLENGE
    secret = SECRET
    cookie_name = "__gwaf_challenge"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        body = _challenge_page(type(self).challenge, type(self).difficulty, redirect=self.path).encode("utf-8")
        self._write(body, 403, {"Content-Type": "text/html; charset=utf-8", "X-GuardianWAF-Challenge": "1"})

    def do_POST(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers)})
        if urlparse(self.path).path != "/__guardianwaf/challenge/verify":
            self._write(b"not found", 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        form = {key: values[-1] for key, values in parse_qs(body).items()}
        if not verify_guardianwaf_pow(form.get("challenge", ""), form.get("nonce", ""), type(self).difficulty):
            self._write(b"Invalid solution", 403, {"Content-Type": "text/plain"})
            return
        cookie = make_guardianwaf_cookie(secret=type(self).secret, client_ip=self.client_address[0], ttl=3600, now=1_700_000_000)
        self._write(
            b"",
            303,
            {
                "Location": form.get("redirect") or "/",
                "Set-Cookie": (
                    f"{type(self).cookie_name}={cookie}; "
                    "Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax"
                ),
            },
        )


def _run_server_and_solve(**kwargs: Any):
    _GuardianWafHandler.calls = []
    _GuardianWafHandler.cookie_name = kwargs.pop("handler_cookie_name", "__gwaf_challenge")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GuardianWafHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(GuardianWafSolver().solve(base_url=base, timeout_sec=5, max_attempts=100_000, **kwargs))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()
    return ret, list(_GuardianWafHandler.calls)


def test_guardianwaf_solver_local_page_and_submit_flow() -> None:
    ret, calls = _run_server_and_solve(submit=True)
    assert ret.ok is True
    assert ret.provider == "guardianwaf"
    assert ret.captcha_type == "unsigned_js_pow_hmac_cookie"
    assert ret.verify_code == "cookie_issued"
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["nonce_text"] == VALID_NONCE_HEX
    ticket = json.loads(ret.ticket or "{}")
    assert ticket["cookie_name"] == "__gwaf_challenge"
    assert verify_guardianwaf_cookie(ticket["cookie_value"], secret=SECRET, client_ip="127.0.0.1", now=1_700_000_100)
    assert [call["method"] for call in calls] == ["GET", "POST"]
    assert calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert calls[1]["path"] == "/__guardianwaf/challenge/verify"


def test_guardianwaf_solver_direct_stateless_submit_flow() -> None:
    ret, calls = _run_server_and_solve(
        submit=True,
        direct=True,
        difficulty=DIFFICULTY,
        redirect="/direct",
        challenge_json=json.dumps({"challenge": CHALLENGE, "difficulty": DIFFICULTY, "redirect": "/direct"}),
    )
    assert ret.ok is True
    assert ret.verify_code == "cookie_issued"
    assert ret.diagnostics["protocol_gap"] == "challenge_string_not_signed_or_server_tracked"
    assert [call["method"] for call in calls] == ["POST"]
    ticket = json.loads(ret.ticket or "{}")
    assert ticket["location"] == "/direct"


def test_guardianwaf_solver_submit_custom_cookie_name() -> None:
    ret, calls = _run_server_and_solve(
        submit=True,
        cookie_name="__gwaf_custom",
        handler_cookie_name="__gwaf_custom",
    )
    assert ret.ok is True
    assert ret.verify_code == "cookie_issued"
    assert [call["method"] for call in calls] == ["GET", "POST"]
    assert ret.diagnostics["cookie_name"] == "__gwaf_custom"
    ticket = json.loads(ret.ticket or "{}")
    assert ticket["cookie_name"] == "__gwaf_custom"
    assert verify_guardianwaf_cookie(ticket["cookie_value"], secret=SECRET, client_ip="127.0.0.1", now=1_700_000_100)


def test_guardianwaf_solver_secret_local_cookie_skips_pow() -> None:
    ret = asyncio.run(
        GuardianWafSolver().solve(
            direct=True,
            difficulty=32,
            secret=SECRET,
            client_ip="127.0.0.1",
            cookie_name="__gwaf_local",
            max_attempts=1,
        )
    )
    assert ret.ok is True
    assert ret.verify_code == "local_cookie"
    assert ret.diagnostics["pow_skipped"] is True
    ticket = json.loads(ret.ticket or "{}")
    assert ticket["cookie_name"] == "__gwaf_local"
    assert verify_guardianwaf_cookie(ticket["cookie_value"], secret=SECRET, client_ip="127.0.0.1")
