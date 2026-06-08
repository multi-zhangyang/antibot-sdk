from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.yourcaptcha import (
    YourCaptchaSolver,
    generate_yourcaptcha_signals,
    score_yourcaptcha_signals,
    solve_yourcaptcha_challenge,
    verify_yourcaptcha_solution,
    yourcaptcha_hash_hex,
)

SECRET = "yourcaptcha-test-secret-32-bytes"


def _sign(challenge: str) -> str:
    return hmac.new(SECRET.encode(), challenge.encode(), hashlib.sha256).hexdigest()


def _make_challenge(number: int = 17, signals: dict[str, Any] | None = None) -> dict[str, Any]:
    score = score_yourcaptcha_signals(signals or generate_yourcaptcha_signals())
    now_ms = int(time.time() * 1000)
    salt = f"abcdef0123456789abcdef0123456789:{now_ms + 300_000}:{now_ms}:{score['score']:.2f}"
    challenge = yourcaptcha_hash_hex(salt, number)
    return {
        "algorithm": "SHA-256",
        "challenge": challenge,
        "maxnumber": score["maxnumber"],
        "salt": salt,
        "signature": _sign(challenge),
        "riskScore": score["score"],
    }


def _verify_payload(payload: dict[str, Any]) -> tuple[bool, str, float]:
    challenge = str(payload.get("challenge") or "")
    signature = str(payload.get("signature") or "")
    expected_sig = _sign(challenge)
    if not hmac.compare_digest(signature, expected_sig):
        return False, "invalid signature", 0.0
    try:
        number = int(payload.get("number"))
    except Exception:
        return False, "missing number", 0.0
    if yourcaptcha_hash_hex(str(payload.get("salt") or ""), number) != challenge:
        return False, "incorrect solution", 0.0
    salt_parts = str(payload.get("salt") or "").split(":")
    if len(salt_parts) < 4:
        return False, "invalid salt format", 0.0
    if int(salt_parts[1]) < int(time.time() * 1000):
        return False, "challenge expired", 0.0
    embedded_score = float(salt_parts[3])
    signals = payload.get("signals") or {}
    re_score = float(score_yourcaptcha_signals(signals)["score"])
    submit_time = int(signals.get("solvedAt") or int(time.time() * 1000)) - int(signals.get("pageLoadedAt") or 0)
    if submit_time < 3000:
        return False, "submitted too quickly", re_score
    if re_score > 0.85:
        return False, "behavioral score too high", re_score
    if abs(re_score - embedded_score) > 0.4:
        return False, "signal tampering detected", re_score
    return True, "", re_score


def test_yourcaptcha_signal_scoring_low_risk_and_botty() -> None:
    low = generate_yourcaptcha_signals(now_ms=1_800_000_000_000)
    assert score_yourcaptcha_signals(low) == {"score": 0.0, "reasons": [], "maxnumber": 50_000}

    botty = dict(low)
    botty.update(
        {
            "captchaClickedAt": botty["pageLoadedAt"] + 500,
            "mouseMovements": 0,
            "keystrokeCount": 0,
            "focusChanges": 0,
            "hasWebdriver": True,
            "screenWidth": 800,
            "screenHeight": 600,
            "canvasHash": "0",
            "webglRenderer": "SwiftShader",
        }
    )
    scored = score_yourcaptcha_signals(botty)
    assert scored["score"] > 0.8
    assert scored["maxnumber"] == 10_000_000


def test_yourcaptcha_exact_pow_fixture() -> None:
    signals = generate_yourcaptcha_signals(now_ms=1_800_000_000_000)
    challenge = _make_challenge(17, signals)
    solution = solve_yourcaptcha_challenge(challenge, signals=signals, timeout_sec=5)

    assert solution is not None
    assert solution.number == 17
    assert solution.attempts == 18
    assert solution.hash_hex == challenge["challenge"]
    assert verify_yourcaptcha_solution(challenge, solution)
    assert solution.submit_body["number"] == 17
    assert solution.submit_body["signals"]["solvedAt"] - solution.submit_body["signals"]["pageLoadedAt"] >= 3000


class _YourCaptchaHandler(BaseHTTPRequestHandler):
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
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}")
        if self.path == "/challenge":
            signals = payload.get("signals") or {}
            challenge = _make_challenge(23, signals)
            self._json({k: challenge[k] for k in ("algorithm", "challenge", "maxnumber", "salt", "signature")})
            return
        if self.path == "/verify":
            self.calls.append(payload)
            ok, reason, re_score = _verify_payload(payload)
            self._json(
                {"verified": ok, "reason": reason or None, "riskScore": re_score, "token": "yourcaptcha-token" if ok else None},
                200 if ok else 400,
            )
            return
        self._json({"error": "not-found"}, 404)


def test_yourcaptcha_solver_protocol_flow_local_server() -> None:
    _YourCaptchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _YourCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            YourCaptchaSolver().solve(
                challenge_url=f"{base}/challenge",
                verify_url=f"{base}/verify",
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "yourcaptcha"
    assert ret.captcha_type == "behavior_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "yourcaptcha-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["synthetic_signal_score"] == 0.0
    assert ret.diagnostics["number"] == 23
    assert _YourCaptchaHandler.calls[0]["number"] == 23
    assert _YourCaptchaHandler.calls[0]["signals"]["hasWebdriver"] is False
