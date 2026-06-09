from __future__ import annotations

import asyncio
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.getpowcaptcha import (
    GetPowCaptchaSolver,
    build_getpowcaptcha_create_body,
    decode_getpowcaptcha_solution,
    encode_getpowcaptcha_fingerprint,
    encode_getpowcaptcha_solution,
    generate_getpowcaptcha_fingerprint,
    generate_getpowcaptcha_signals,
    getpowcaptcha_hash_hex,
    parse_getpowcaptcha_challenge,
    solve_getpowcaptcha_challenge,
    verify_getpowcaptcha_solution,
)

CHALLENGE = {
    "id": "gpc-fixture-1",
    "signature": "sig-fixture",
    "challenges": [
        {"problem": "p0", "difficulty": 2},
        {"problem": "p1", "difficulty": 3},
    ],
}
SECRET = "private-key-fixture"


def test_getpowcaptcha_hash_and_solution_token_fixture() -> None:
    challenge = parse_getpowcaptcha_challenge(CHALLENGE)
    solution = solve_getpowcaptcha_challenge(challenge, max_attempts_per_problem=1000, timeout_sec=5)

    assert solution is not None
    assert solution.solutions == [2, 209]
    assert getpowcaptcha_hash_hex("sig-fixture", "p0", 2).startswith("00")
    assert getpowcaptcha_hash_hex("sig-fixture", "p1", 209).startswith("000")
    assert verify_getpowcaptcha_solution(challenge, solution)

    payload = decode_getpowcaptcha_solution(solution.token)
    assert payload == {"challenge_id": "gpc-fixture-1", "solutions": [2, 209], "time": solution.time_ms}
    assert encode_getpowcaptcha_solution(payload) == solution.token
    assert verify_getpowcaptcha_solution(CHALLENGE, solution.token)


def test_getpowcaptcha_fingerprint_and_create_body_shape() -> None:
    fingerprint = generate_getpowcaptcha_fingerprint(timezone="Asia/Shanghai")
    signals = generate_getpowcaptcha_signals(now_ms=1_700_000_000_000)
    body = build_getpowcaptcha_create_body(app_id="app_fixture", fingerprint=fingerprint, signals=signals, context={"page": "/x"})

    decoded_fp = decode_getpowcaptcha_solution(body["fingerprint"])
    assert body["app_id"] == "app_fixture"
    assert body["context"] == {"page": "/x"}
    assert body["signals"]["summary"]["clicks"] == 1
    assert decoded_fp["fingerprintId"] == fingerprint.fingerprint_id
    assert decoded_fp["components"]["webdriver"]["webdriver"] is False
    assert decoded_fp["components"]["timezone"]["offset"] == -480
    assert build_getpowcaptcha_create_body(app_id="app_fixture", fingerprint=body["fingerprint"])["fingerprint"] == body["fingerprint"]


class _GetPowCaptchaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length)
        if self.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        payload = json.loads(raw.decode("utf-8"))
        type(self).calls.append({"path": self.path, "payload": payload, "encoding": self.headers.get("Content-Encoding")})
        if self.path == "/challenges/create":
            ok = payload.get("app_id") == "app_fixture" and isinstance(payload.get("fingerprint"), str)
            self._json({"success": ok, "type": "item", "data": CHALLENGE} if ok else {"success": False}, 200 if ok else 400)
            return
        if self.path == "/challenges/verify":
            ok = payload.get("secret") == SECRET and verify_getpowcaptcha_solution(CHALLENGE, payload.get("solution", ""))
            self._json({"success": bool(ok), "data": {"signals": {"score": 0.99}}}, 200 if ok else 400)
            return
        self._json({"success": False, "error": "not_found"}, 404)


def test_getpowcaptcha_solver_create_solve_verify_flow() -> None:
    _GetPowCaptchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GetPowCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        raw_fingerprint = encode_getpowcaptcha_fingerprint(generate_getpowcaptcha_fingerprint())
        ret = asyncio.run(
            GetPowCaptchaSolver().solve(
                app_id="app_fixture",
                backend_url=base,
                fingerprint_json=raw_fingerprint,
                secret=SECRET,
                verify=True,
                max_attempts_per_problem=1000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "getpowcaptcha"
    assert ret.captcha_type == "signals_bound_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "verified"
    assert ret.randstr == "gpc-fixture-1"
    assert ret.diagnostics["difficulties"] == [2, 3]
    assert ret.raw["solution"]["solutions"] == [2, 209]
    assert _GetPowCaptchaHandler.calls[0]["path"] == "/challenges/create"
    assert _GetPowCaptchaHandler.calls[0]["encoding"] == "gzip"
    assert _GetPowCaptchaHandler.calls[0]["payload"]["fingerprint"] == raw_fingerprint
    assert _GetPowCaptchaHandler.calls[1]["path"] == "/challenges/verify"
