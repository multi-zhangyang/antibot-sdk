from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.botcha import (
    BotchaSolver,
    botcha_sha256_first8,
    parse_botcha_speed_challenge,
    parse_botcha_standard_challenge,
    solve_botcha_speed_challenge,
    solve_botcha_speed_problems,
    solve_botcha_standard_challenge,
    verify_botcha_speed_solution,
    verify_botcha_standard_solution,
)

SPEED_CHALLENGE = {
    "success": True,
    "challenge": {
        "id": "botcha-speed-fixture",
        "problems": [
            {"num": 123456, "operation": "sha256_first8"},
            {"num": 789012, "operation": "sha256_first8"},
            {"num": 42, "operation": "sha256_first8"},
        ],
        "timeLimit": "500ms",
        "instructions": "Compute SHA256 first8",
    },
}

STANDARD_CHALLENGE = {
    "success": True,
    "challenge": {
        "id": "botcha-standard-fixture",
        "puzzle": 'Compute SHA256 of the first 5 prime numbers concatenated (no separators) followed by the salt "fixture-salt". Return the first 16 hex characters.',
        "timeLimit": 10000,
    },
}


def test_botcha_speed_answers_fixture() -> None:
    challenge = parse_botcha_speed_challenge(SPEED_CHALLENGE)
    solution = solve_botcha_speed_challenge(challenge)

    assert challenge.challenge_id == "botcha-speed-fixture"
    assert challenge.time_limit_ms == 500
    assert botcha_sha256_first8(123456) == hashlib.sha256(b"123456").hexdigest()[:8]
    assert solution.answers == solve_botcha_speed_problems([123456, 789012, 42])
    assert solve_botcha_speed_problems([{"number": 123456, "operation": "SHA256_FIRST8"}]) == ["8d969eef"]
    assert verify_botcha_speed_solution(challenge, solution)
    assert verify_botcha_speed_solution(SPEED_CHALLENGE, solution.verify_body)


def test_botcha_standard_prime_puzzle_fixture() -> None:
    challenge = parse_botcha_standard_challenge(STANDARD_CHALLENGE)
    solution = solve_botcha_standard_challenge(challenge)
    expected = hashlib.sha256(b"235711fixture-salt").hexdigest()[:16]

    assert challenge.primes_count == 5
    assert challenge.salt == "fixture-salt"
    assert solution.answer == expected
    single_quote = {
        "id": "single-quote-standard",
        "puzzle": "Compute SHA256 of the first 5 prime numbers concatenated followed by the salt 'fixture-salt'.",
    }
    assert solve_botcha_standard_challenge(single_quote).answer == expected
    assert verify_botcha_standard_solution(challenge, solution)
    assert verify_botcha_standard_solution(STANDARD_CHALLENGE, solution.verify_body)


class _BotchaHandler(BaseHTTPRequestHandler):
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

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path})
        if self.path.startswith("/v1/token"):
            self._json(SPEED_CHALLENGE)
            return
        if self.path.startswith("/api/challenge"):
            self._json(STANDARD_CHALLENGE)
            return
        self._json({"success": False, "error": "not_found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append({"method": "POST", "path": self.path, "payload": payload})
        if self.path == "/v1/token/verify":
            ok = payload.get("app_id") == "app_fixture" and verify_botcha_speed_solution(SPEED_CHALLENGE, payload)
            self._json({"success": bool(ok), "verified": bool(ok), "access_token": "botcha-access-token"}, 200 if ok else 400)
            return
        if self.path == "/api/challenge":
            ok = verify_botcha_standard_solution(STANDARD_CHALLENGE, payload)
            self._json({"success": bool(ok), "message": "ok"}, 200 if ok else 400)
            return
        self._json({"success": False, "error": "not_found"}, 404)


def test_botcha_token_flow_local_server() -> None:
    _BotchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BotchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            BotchaSolver().solve(
                mode="token",
                base_url=base,
                app_id="app_fixture",
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "botcha"
    assert ret.captcha_type == "ai_speed_challenge"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "botcha-access-token"
    assert ret.verify_code == "verified"
    assert ret.randstr == "botcha-speed-fixture"
    assert ret.raw["solution"]["answers"] == solve_botcha_speed_problems([123456, 789012, 42])
    assert _BotchaHandler.calls[0]["path"].startswith("/v1/token?app_id=app_fixture")
    assert _BotchaHandler.calls[1]["path"] == "/v1/token/verify"


def test_botcha_standard_flow_local_server() -> None:
    _BotchaHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BotchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            BotchaSolver().solve(
                mode="standard",
                base_url=base,
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "botcha"
    assert ret.captcha_type == "prime_hash_puzzle"
    assert ret.verify_code == "verified"
    assert ret.randstr == "botcha-standard-fixture"
    assert ret.raw["solution"]["answer"] == hashlib.sha256(b"235711fixture-salt").hexdigest()[:16]
