from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.crovly import (
    CrovlyClientProfile,
    CrovlySolver,
    build_crovly_verify_body,
    count_leading_zero_bits,
    crovly_fingerprint_material,
    crovly_pow_hash_hex,
    generate_crovly_behavior,
    generate_crovly_environment,
    generate_crovly_fingerprint_hash,
    parse_crovly_challenge,
    score_crovly_client_signals,
    solve_crovly_pow_challenge,
    verify_crovly_pow_solution,
)

SITE_KEY = "crvl_site_fixture"
FIXTURE = {"nonce": "crovly-fixture", "difficulty": 12, "badge": True, "color": "#10b981"}


class _CrovlyHandler(BaseHTTPRequestHandler):
    challenge_headers: list[str] = []
    verify_headers: list[str] = []
    verify_calls: list[dict[str, Any]] = []

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
        if self.path != "/challenge":
            self._json({"error": "not-found"}, 404)
            return
        site_key = self.headers.get("X-Site-Key", "")
        type(self).challenge_headers.append(site_key)
        if site_key != SITE_KEY:
            self._json({"error": "bad site key"}, 403)
            return
        self._json(FIXTURE)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path != "/verify":
            self._json({"error": "not-found"}, 404)
            return
        type(self).verify_headers.append(self.headers.get("X-Site-Key", ""))
        type(self).verify_calls.append(payload)
        errors: list[str] = []
        if self.headers.get("X-Site-Key") != SITE_KEY:
            errors.append("site_key")
        if payload.get("nonce") != FIXTURE["nonce"]:
            errors.append("nonce")
        if not verify_crovly_pow_solution(FIXTURE, {"counter": payload.get("counter")}):
            errors.append("pow")
        if payload.get("fingerprintHash") != generate_crovly_fingerprint_hash():
            errors.append("fingerprint")
        env = payload.get("environment") or {}
        if any(env.get(k) for k in ("webdriver", "chromeAbsent", "swiftShader", "zeroScreen", "noLanguages")):
            errors.append("environment")
        behavior = payload.get("behavior") or {}
        if int(behavior.get("mm") or 0) <= 0 or int(behavior.get("el") or 0) < 50:
            errors.append("behavior")
        if errors:
            self._json({"passed": False, "error": ",".join(errors), "retry": True}, 400)
            return
        self._json({"passed": True, "token": "crovly-pass-token", "expiresAt": int(time.time() * 1000) + 300_000})


def test_crovly_pow_fixture_uses_leading_zero_bits() -> None:
    challenge = parse_crovly_challenge(FIXTURE)
    solution = solve_crovly_pow_challenge(challenge, timeout_sec=5)

    assert solution is not None
    assert solution.counter == 1549
    assert solution.hash_hex == "000665edf0ec8941c3c2c1797c7cd91b2be41a5fa59320cf3da18af6ab5ed7c3"
    assert solution.leading_zero_bits == 13
    assert solution.attempts == 1550
    assert crovly_pow_hash_hex(FIXTURE["nonce"], 1549) == solution.hash_hex
    assert count_leading_zero_bits(bytes.fromhex(solution.hash_hex)) == 13
    assert verify_crovly_pow_solution(FIXTURE, solution)
    assert not verify_crovly_pow_solution(FIXTURE, 1548)


def test_crovly_fingerprint_and_signals_are_deterministic_low_risk() -> None:
    profile = CrovlyClientProfile()
    material = crovly_fingerprint_material(profile)

    assert material == "|".join(profile.fingerprint_parts())
    assert generate_crovly_fingerprint_hash(profile) == hashlib.sha256(material.encode()).hexdigest()
    assert generate_crovly_environment(profile) == {
        "webdriver": False,
        "chromeAbsent": False,
        "noPlugins": False,
        "swiftShader": False,
        "notificationDenied": False,
        "zeroScreen": False,
        "noLanguages": False,
    }
    behavior = generate_crovly_behavior(elapsed_ms=1900)
    scored = score_crovly_client_signals(generate_crovly_environment(profile), behavior)
    assert behavior["el"] == 1900
    assert scored["recommendation"] == "allow"
    assert scored["score"] < 0.35


def test_crovly_verify_body_matches_widget_schema() -> None:
    solution = solve_crovly_pow_challenge(FIXTURE, timeout_sec=5)
    assert solution is not None

    body = build_crovly_verify_body(FIXTURE, solution, solve_time_ms=1234)

    assert body["nonce"] == FIXTURE["nonce"]
    assert body["counter"] == 1549
    assert body["solveTimeMs"] == 1234
    assert set(body) == {"nonce", "counter", "solveTimeMs", "fingerprintHash", "environment", "behavior"}
    assert body["fingerprintHash"] == generate_crovly_fingerprint_hash()
    assert body["environment"]["webdriver"] is False
    assert body["behavior"]["mm"] > 0


def test_crovly_solver_protocol_flow_local_server() -> None:
    _CrovlyHandler.challenge_headers = []
    _CrovlyHandler.verify_headers = []
    _CrovlyHandler.verify_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CrovlyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    api_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            CrovlySolver().solve(
                api_url=api_url,
                edge_url=None,
                site_key=SITE_KEY,
                submit=True,
                timeout_sec=5,
                min_solve_ms=900,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "crovly"
    assert ret.captcha_type == "fingerprint_behavior_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "crovly-pass-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["counter"] == 1549
    assert ret.diagnostics["reported_solve_ms"] == 900
    assert _CrovlyHandler.challenge_headers == [SITE_KEY]
    assert _CrovlyHandler.verify_headers == [SITE_KEY]
    assert _CrovlyHandler.verify_calls[0]["counter"] == 1549
    assert _CrovlyHandler.verify_calls[0]["solveTimeMs"] == 900
