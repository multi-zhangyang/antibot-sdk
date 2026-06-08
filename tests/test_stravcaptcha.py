from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.stravcaptcha import (
    StravCaptchaSolver,
    build_stravcaptcha_submit_body,
    count_leading_zero_bits_hex,
    decode_stravcaptcha_token,
    extract_stravcaptcha_from_html,
    parse_stravcaptcha_challenge,
    solve_stravcaptcha_challenge,
    stravcaptcha_hash_hex,
    verify_stravcaptcha_solution,
    verify_stravcaptcha_token_signature,
)

SECRET = "strav-secret-material-32-bytes-fixture"
SALT = "0123456789abcdef0123456789abcdef"
JTI = "00112233445566778899aabbccddeeff"


class _StravCaptchaHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    submit_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/__captcha/pow":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        token = _issue_token()
        self._json({"token": token, "props": {"challenge": SALT, "difficulty": 12}})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/protected":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        type(self).submit_calls.append(payload)
        token = payload.get("_captcha")
        nonce = payload.get("_captcha_answer")
        if payload.get("website") != "":
            self._json({"ok": False, "reason": "honeypot_tripped"}, 422)
            return
        if not isinstance(token, str) or not verify_stravcaptcha_token_signature(token, SECRET):
            self._json({"ok": False, "reason": "token_invalid"}, 422)
            return
        challenge = parse_stravcaptcha_challenge({"token": token})
        if not verify_stravcaptcha_solution(challenge, nonce):
            self._json({"ok": False, "reason": "pow_insufficient"}, 422)
            return
        self._json({"ok": True, "accepted": True, "jti": challenge.payload.jti})


def test_stravcaptcha_token_parse_and_pow_fixture() -> None:
    token = _issue_token()
    payload = decode_stravcaptcha_token(token)
    challenge = parse_stravcaptcha_challenge({"token": token, "props": {"challenge": SALT, "difficulty": 12}})
    solution = solve_stravcaptcha_challenge(challenge, timeout_sec=5)

    assert payload.token_type == "pow"
    assert payload.salt == SALT
    assert payload.difficulty == 12
    assert verify_stravcaptcha_token_signature(token, SECRET)
    assert solution is not None
    assert solution.nonce == "6092"
    assert solution.hash_hex == "0001ff048d37307ddeed431d52e95b4e9a6289b74b52f522bc603996f344f689"
    assert solution.attempts == 6093
    assert stravcaptcha_hash_hex(SALT, "6092") == solution.hash_hex
    assert count_leading_zero_bits_hex(solution.hash_hex) >= 12
    assert verify_stravcaptcha_solution(challenge, solution)
    assert not verify_stravcaptcha_solution(challenge, "6091")

    body = build_stravcaptcha_submit_body(challenge, solution)
    assert body == {"website": "", "_captcha": token, "_captcha_answer": "6092"}


def test_stravcaptcha_extracts_view_helper_html() -> None:
    token = _issue_token()
    html = (
        '<input type="hidden" name="_captcha" value="'
        + token
        + '"><input type="hidden" name="_captcha_answer" value="">'
        + "<div data-captcha=\"pow\" data-props='{\"challenge\":\""
        + SALT
        + "\",\"difficulty\":12,\"tokenField\":\"_captcha\",\"responseField\":\"_captcha_answer\"}'></div>"
    )
    extracted = extract_stravcaptcha_from_html(html)
    challenge = parse_stravcaptcha_challenge(extracted)

    assert extracted["token"] == token
    assert extracted["props"]["challenge"] == SALT
    assert challenge.difficulty == 12


def test_stravcaptcha_solver_protocol_flow_local_server() -> None:
    _StravCaptchaHandler.challenge_calls = 0
    _StravCaptchaHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StravCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            StravCaptchaSolver().solve(
                challenge_url=f"{base}/__captcha/pow",
                submit_url=f"{base}/protected",
                submit=True,
                secret=SECRET,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "stravcaptcha"
    assert ret.captcha_type == "stateless_hmac_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == 12
    assert ret.diagnostics["nonce"] == "6092"
    assert ret.diagnostics["signature_valid"] is True
    assert _StravCaptchaHandler.challenge_calls == 1
    assert _StravCaptchaHandler.submit_calls[0]["_captcha_answer"] == "6092"


def _issue_token() -> str:
    payload = {
        "v": 1,
        "t": "pow",
        "s": SALT,
        "d": 12,
        "iat": int(time.time() * 1000),
        "exp": 10,
        "jti": JTI,
    }
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    mac = _b64url(hmac.new(SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{mac}"


def _b64url(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=").replace("+", "-").replace("/", "_")
