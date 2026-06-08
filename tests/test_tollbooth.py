from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.tollbooth import (
    TollboothSolver,
    count_leading_zero_bits,
    generate_tollbooth_navigator_signals,
    parse_tollbooth_challenge,
    solve_tollbooth_challenge,
    tollbooth_balloon_hash_hex,
    tollbooth_sha256_hash_hex,
    verify_tollbooth_solution,
)

BALLOON = {
    "id": "tb-fixture",
    "data": "tollbooth-fixture",
    "difficulty": 8,
    "spaceCost": 8,
    "timeCost": 1,
    "delta": 1,
    "verifyPath": "/.tollbooth/verify",
    "redirect": "/protected",
    "csrfToken": "csrf-balloon",
}
NAV = {
    "id": "tb-nav",
    "type": "navigator-attestation",
    "difficulty": 8,
    "verifyPath": "/.tollbooth/verify",
    "redirect": "/nav",
    "csrfToken": "csrf-nav",
}


class _TollboothHandler(BaseHTTPRequestHandler):
    verify_calls: list[dict[str, Any]] = []
    poll_calls: list[dict[str, Any]] = []

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
        if self.path == "/protected":
            self._json({"challenge": BALLOON})
            return
        if self.path == "/nav":
            self._json({"challenge": NAV})
            return
        self._json({"error": "not-found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        if self.path != "/.tollbooth/verify":
            self._json({"error": "not-found"}, 404)
            return
        if "application/json" in self.headers.get("Content-Type", ""):
            payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            type(self).poll_calls.append(payload)
            if payload.get("init"):
                self._json({"type": "challenge", "round": 1, "totalRounds": 2, "nonce": "n1", "checks": ["automation"]})
                return
            if payload.get("nonce") == "n1" and payload.get("round") == 1:
                self._json({"type": "challenge", "round": 2, "totalRounds": 2, "nonce": "n2", "checks": ["navigator"]})
                return
            if payload.get("nonce") == "n2" and payload.get("round") == 2:
                self._json({"type": "result", "token": "nav-attestation-token"})
                return
            self._json({"type": "error", "reason": "bad poll"}, 400)
            return
        form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}
        type(self).verify_calls.append(form)
        if form.get("id") == BALLOON["id"]:
            if form.get("csrf_token") != BALLOON["csrfToken"] or not verify_tollbooth_solution(BALLOON, form):
                self._json({"error": "invalid"}, 403)
                return
            self._json({"token": "tollbooth-clearance"})
            return
        if form.get("id") == NAV["id"]:
            if form.get("csrf_token") != NAV["csrfToken"] or form.get("nonce") != "nav-attestation-token":
                self._json({"error": "invalid"}, 403)
                return
            self._json({"token": "tollbooth-nav-clearance"})
            return
        self._json({"error": "invalid"}, 403)


def test_tollbooth_balloon_fixture() -> None:
    challenge = parse_tollbooth_challenge({"challenge": BALLOON})
    solution = solve_tollbooth_challenge(challenge, timeout_sec=5)

    assert solution is not None
    assert challenge.challenge_type == "sha256-balloon"
    assert solution.nonce == 433
    assert solution.digest_hex == "007484b639553467e9ffdb5d3925b1cd3d292fb8003d9b2d95a6fdd4cae38739"
    assert solution.leading_zero_bits == 9
    assert solution.attempts == 434
    assert tollbooth_balloon_hash_hex("tollbooth-fixture", 433, space_cost=8, time_cost=1, delta=1) == solution.digest_hex
    assert count_leading_zero_bits(bytes.fromhex(solution.digest_hex)) == 9
    assert solution.submit_form == {"id": "tb-fixture", "nonce": "433", "redirect": "/protected", "csrf_token": "csrf-balloon"}
    assert verify_tollbooth_solution(BALLOON, solution)
    assert not verify_tollbooth_solution(BALLOON, 432)


def test_tollbooth_sha256_fixture_and_html_extract() -> None:
    payload = {
        "id": "tb-sha",
        "type": "sha256",
        "data": "tollbooth-fixture",
        "difficulty": 8,
        "verifyPath": "/.tollbooth/verify",
        "redirect": "/sha",
    }
    html = "<script>var C = JSON.parse('" + json.dumps(payload).replace("'", "\\u0027") + "');</script>"
    challenge = parse_tollbooth_challenge(html)
    solution = solve_tollbooth_challenge(challenge, timeout_sec=5)

    assert solution is not None
    assert challenge.challenge_type == "sha256"
    assert solution.nonce == 108
    assert solution.digest_hex == "008bf691f0db06ee587aab6b15169b4d357f474ed48e455219e2725718f38c31"
    assert tollbooth_sha256_hash_hex("tollbooth-fixture", 108) == solution.digest_hex


def test_tollbooth_solver_balloon_local_server() -> None:
    _TollboothHandler.verify_calls = []
    _TollboothHandler.poll_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TollboothHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(TollboothSolver().solve(challenge_url=url, submit=True, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "tollbooth"
    assert ret.captcha_type == "tollbooth_protocol"
    assert ret.verify_code == "validated"
    assert ret.ticket == "tollbooth-clearance"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["challenge_type"] == "sha256-balloon"
    assert _TollboothHandler.verify_calls[0]["nonce"] == "433"


def test_tollbooth_solver_navigator_poll_local_server() -> None:
    _TollboothHandler.verify_calls = []
    _TollboothHandler.poll_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TollboothHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/nav"
    try:
        ret = asyncio.run(TollboothSolver().solve(challenge_url=url, submit=True, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.ticket == "tollbooth-nav-clearance"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["challenge_type"] == "navigator-attestation"
    assert _TollboothHandler.poll_calls[0] == {"id": "tb-nav", "init": True}
    assert _TollboothHandler.poll_calls[1]["signals"] == generate_tollbooth_navigator_signals(["automation"])
    assert _TollboothHandler.verify_calls[0]["nonce"] == "nav-attestation-token"
