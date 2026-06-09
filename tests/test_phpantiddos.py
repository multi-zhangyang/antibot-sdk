from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.phpantiddos import (
    DEFAULT_HEADERS,
    PhpAntiDdosSolver,
    parse_phpantiddos_challenge_html,
    phpantiddos_fingerprint,
    phpantiddos_hash_hex,
    sign_phpantiddos_challenge,
    solve_phpantiddos_challenge,
    verify_phpantiddos_challenge_signature,
    verify_phpantiddos_cookie,
    verify_phpantiddos_solution,
)

CHALLENGE = "0123456789abcdef0123456789abcdef"
TS = 1_700_000_000
SUB_COUNT = 3
SUB_DIFFICULTY = 8
SECRET = "secret"
CLIENT_IP = "203.0.113.9"
USER_AGENT = "Mozilla/5.0 fixture"
FINGERPRINT = "cb3e514f671db7277045db73f1e884eafc97c440b802ef005094fafcf344e547"
SIGNATURE = "362870dcaf5c05430c8fa27de2226ff35adf1a30878e28d27cd8305b9af8f52c"
NONCES = ["2", "1099511628213", "2199023255668"]
DIGESTS = [
    "0008ac4ae45ece456188d12a7b8367001f3817842b90baf17505d7a85be715d5",
    "006ec060e1c130b9f7e426bfcb5da87e6fef80cb8e1fcbd0469e9f8e748c0b1d",
    "00a420f9e89d9c1d1ee58392ecb300115083d448c4837f3db3076c9088059cc9",
]


def _challenge_dict() -> dict[str, Any]:
    return {
        "challenge": CHALLENGE,
        "ts": TS,
        "sub_count": SUB_COUNT,
        "sub_difficulty": SUB_DIFFICULTY,
        "sig": SIGNATURE,
        "fingerprint": FINGERPRINT,
        "host": "example.test",
    }


def _html(action: str = "/protected", sig: str = SIGNATURE) -> str:
    return f'''
    <html><body>
      <form id="pow-form" method="POST" action="{action}" style="display:none">
        <input type="hidden" name="pow_challenge" value="{CHALLENGE}">
        <input type="hidden" name="pow_ts" value="{TS}">
        <input type="hidden" name="pow_sub_count" value="{SUB_COUNT}">
        <input type="hidden" name="pow_sub_difficulty" value="{SUB_DIFFICULTY}">
        <input type="hidden" name="pow_sig" value="{sig}">
        <input type="hidden" name="pow_nonces" id="pow-nonces" value="">
      </form>
      <script>
        var CHALLENGE = "{CHALLENGE}";
        var TS = "{TS}";
        var SIG = "{sig}";
        var SUB_COUNT = {SUB_COUNT};
        var DIFFICULTY = {SUB_DIFFICULTY};
      </script>
    </body></html>
    '''


def test_phpantiddos_signed_multi_subchallenge_fixture() -> None:
    assert phpantiddos_fingerprint(CLIENT_IP, USER_AGENT) == FINGERPRINT
    assert sign_phpantiddos_challenge(
        CHALLENGE,
        TS,
        SUB_COUNT,
        SUB_DIFFICULTY,
        secret=SECRET,
        fingerprint=FINGERPRINT,
    ) == SIGNATURE

    solution = solve_phpantiddos_challenge(
        _challenge_dict(),
        secret=SECRET,
        fingerprint=FINGERPRINT,
        client_ip=CLIENT_IP,
        user_agent=USER_AGENT,
        workers=2,
        max_attempts_per_subchallenge=100_000,
        now=TS,
    )
    assert solution.nonces == NONCES
    assert [s.digest_hex for s in solution.sub_solutions] == DIGESTS
    assert verify_phpantiddos_solution(_challenge_dict(), solution, secret=SECRET, fingerprint=FINGERPRINT)
    assert verify_phpantiddos_challenge_signature(_challenge_dict(), secret=SECRET, fingerprint=FINGERPRINT)
    assert verify_phpantiddos_cookie(
        solution.cookie_value or "",
        secret=SECRET,
        host="example.test",
        fingerprint=FINGERPRINT,
        now=TS,
    )
    assert phpantiddos_hash_hex(CHALLENGE, 0, NONCES[0]) == DIGESTS[0]


def test_phpantiddos_parse_html_and_reject_nonce_reuse() -> None:
    parsed = parse_phpantiddos_challenge_html(_html(), page_url="http://example.test/protected")
    assert parsed.challenge == CHALLENGE
    assert parsed.ts == TS
    assert parsed.sub_count == SUB_COUNT
    assert parsed.sub_difficulty == SUB_DIFFICULTY
    assert parsed.sig == SIGNATURE
    assert parsed.submit_url == "http://example.test/protected"
    assert verify_phpantiddos_solution(parsed, ",".join(NONCES))
    assert not verify_phpantiddos_solution(parsed, "2,2,2")


class _PhpAntiDdosHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    token = "issued-cookie"
    sig = sign_phpantiddos_challenge(
        CHALLENGE,
        TS,
        SUB_COUNT,
        SUB_DIFFICULTY,
        secret=SECRET,
        client_ip="127.0.0.1",
        user_agent=DEFAULT_HEADERS["User-Agent"],
    )

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
        if self.headers.get("Cookie", "").find("__pow_token=") >= 0:
            self._write(b"OK", 200, {"Content-Type": "text/plain"})
            return
        self._write(_html(sig=self.sig).encode(), 200, {"Content-Type": "text/html"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length).decode("utf-8")
        payload = {k: v[0] for k, v in parse_qs(raw_body).items()}
        type(self).calls.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "payload": payload})
        challenge = {
            "challenge": payload.get("pow_challenge"),
            "ts": payload.get("pow_ts"),
            "sub_count": payload.get("pow_sub_count"),
            "sub_difficulty": payload.get("pow_sub_difficulty"),
            "sig": payload.get("pow_sig"),
        }
        ok = verify_phpantiddos_solution(
            challenge,
            payload.get("pow_nonces", ""),
            secret=SECRET,
            client_ip="127.0.0.1",
            user_agent=DEFAULT_HEADERS["User-Agent"],
        )
        if ok:
            self.send_response(303)
            self.send_header("Location", "/protected")
            self.send_header("Set-Cookie", f"__pow_token={self.token}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._write(json.dumps({"error": "bad pow"}).encode(), 403, {"Content-Type": "application/json"})


def test_phpantiddos_solver_local_fetch_submit_cookie_flow() -> None:
    _PhpAntiDdosHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PhpAntiDdosHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(
            PhpAntiDdosSolver().solve(
                challenge_url=url,
                submit=True,
                secret=SECRET,
                client_ip="127.0.0.1",
                max_attempts_per_subchallenge=100_000,
                workers=2,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "phpantiddos"
    assert ret.captcha_type == "stateless_hmac_multi_pow_cookie"
    assert ret.verify_code == "cookie_issued"
    assert ret.diagnostics["sub_count"] == SUB_COUNT
    assert ret.diagnostics["sub_difficulty"] == SUB_DIFFICULTY
    assert _PhpAntiDdosHandler.calls[1]["payload"]["pow_nonces"].count(",") == 2
    assert _PhpAntiDdosHandler.token in (ret.ticket or "")
