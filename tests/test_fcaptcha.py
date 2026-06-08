from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.fcaptcha import (
    FCaptchaSolver,
    fcaptcha_hash_hex,
    fcaptcha_signals_hash,
    finalize_fcaptcha_signals,
    generate_fcaptcha_signals,
    score_fcaptcha_signals,
    solve_fcaptcha_challenge,
    verify_fcaptcha_solution,
)


FIXTURE_CHALLENGE = {
    "challengeId": "fc-1",
    "prefix": "fc-1:1700000000000:2",
    "difficulty": 2,
    "nonce": "server-nonce",
    "siteKey": "site-key",
}


def _compact_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def test_fcaptcha_signals_hash_and_pow_input_binding() -> None:
    signals = finalize_fcaptcha_signals(
        generate_fcaptcha_signals(now_ms=1_800_000_000_000),
        FIXTURE_CHALLENGE,
    )
    signals_json = _compact_json(signals)
    signals_hash = hashlib.sha256(signals_json.encode()).hexdigest()

    assert fcaptcha_signals_hash(signals_json) == signals_hash
    assert fcaptcha_signals_hash(signals) == signals_hash
    assert signals["meta"]["challengeNonce"] == "server-nonce"

    nonce = 54
    expected = hashlib.sha256(
        f"{FIXTURE_CHALLENGE['prefix']}:{signals_hash}:{nonce}".encode()
    ).hexdigest()
    assert fcaptcha_hash_hex(FIXTURE_CHALLENGE["prefix"], nonce, signals_hash) == expected


def test_fcaptcha_synthetic_signals_score_low_risk() -> None:
    signals = finalize_fcaptcha_signals(generate_fcaptcha_signals(now_ms=1_800_000_000_000), FIXTURE_CHALLENGE)
    scored = score_fcaptcha_signals(signals, server_elapsed_ms=1600)

    assert scored["success"] is True
    assert scored["score"] < 0.3
    assert scored["recommendation"] == "allow"
    assert scored["detections"] == []


def test_fcaptcha_solver_fixture() -> None:
    signals = finalize_fcaptcha_signals(generate_fcaptcha_signals(now_ms=1_800_000_000_000), FIXTURE_CHALLENGE)
    solution = solve_fcaptcha_challenge(FIXTURE_CHALLENGE, signals=signals, timeout_sec=5)

    assert solution is not None
    assert solution.nonce == 247
    assert solution.hash_hex == "006898164bca7c9261bb04768e43ee692979737b772765730025a47de6caadef"
    assert solution.signals_hash == fcaptcha_signals_hash(solution.signals_json)
    assert solution.pow_solution["signalsHash"] == solution.signals_hash
    assert solution.verify_body["signals"]["meta"]["challengeNonce"] == "server-nonce"
    assert verify_fcaptcha_solution(FIXTURE_CHALLENGE, solution)


class _FCaptchaHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    issued_at = 0.0
    challenge: dict[str, Any] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/pow/challenge":
            site_key = parse_qs(parsed.query).get("siteKey", ["default"])[0]
            type(self).issued_at = time.monotonic()
            type(self).challenge = {
                "challengeId": "fc-local-1",
                "prefix": "fc-local-1:1800000000000:2",
                "difficulty": 2,
                "expiresAt": int(time.time() * 1000) + 300_000,
                "nonce": "server-nonce-local",
                "siteKey": site_key,
                "sig": "fixture-signature",
            }
            self._json(type(self).challenge)
            return
        self._json({"error": "not-found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path != "/api/verify":
            self._json({"error": "not-found"}, 404)
            return
        type(self).calls.append(payload)
        challenge = type(self).challenge
        pow_solution = payload.get("powSolution") or {}
        signals = payload.get("signals") or {}
        signals_json = str(payload.get("signalsJson") or "")
        signals_hash = hashlib.sha256(signals_json.encode()).hexdigest()
        expected_hash = hashlib.sha256(
            f"{challenge['prefix']}:{signals_hash}:{pow_solution.get('nonce')}".encode()
        ).hexdigest()
        elapsed_ms = int((time.monotonic() - type(self).issued_at) * 1000)
        errors: list[str] = []
        if payload.get("siteKey") != "site-key":
            errors.append("site_key_mismatch")
        if signals_hash != pow_solution.get("signalsHash"):
            errors.append("signals_hash_mismatch")
        if expected_hash != pow_solution.get("hash"):
            errors.append("invalid_hash")
        if not str(pow_solution.get("hash") or "").startswith("0" * int(challenge["difficulty"])):
            errors.append("insufficient_difficulty")
        if (signals.get("meta") or {}).get("challengeNonce") != challenge["nonce"]:
            errors.append("challenge_nonce_mismatch")
        if elapsed_ms < 1500:
            errors.append("too_fast")
        try:
            if json.loads(signals_json) != signals:
                errors.append("signals_json_not_canonical_source")
        except Exception:
            errors.append("invalid_signals_json")
        if errors:
            self._json({"success": False, "error": ",".join(errors), "score": 0.9}, 400)
            return
        self._json({"success": True, "score": 0.0, "recommendation": "allow", "token": "fcaptcha-token"})


def test_fcaptcha_solver_protocol_flow_local_server() -> None:
    _FCaptchaHandler.calls = []
    _FCaptchaHandler.challenge = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FCaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            FCaptchaSolver().solve(
                base_url=base,
                site_key="site-key",
                submit=True,
                timeout_sec=5,
                min_submit_ms=1510,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "fcaptcha"
    assert ret.captcha_type == "signals_bound_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "fcaptcha-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["submitted"] is True
    assert ret.diagnostics["synthetic_recommendation"] == "allow"
    assert _FCaptchaHandler.calls[0]["signals"]["meta"]["challengeNonce"] == "server-nonce-local"
