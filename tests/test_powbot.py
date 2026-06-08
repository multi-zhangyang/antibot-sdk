from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.powbot import (
    PowBotSolver,
    parse_powbot_challenge,
    powbot_difficulty_hex,
    powbot_scrypt_hash_hex,
    solve_powbot_challenge,
    verify_powbot_solution,
)

API_TOKEN = "0123456789abcdef0123456789abcdef"


def _challenge_obj(difficulty_level: int = 3) -> dict[str, Any]:
    return {
        "N": 16,
        "r": 8,
        "p": 1,
        "klen": 16,
        "i": base64.b64encode(bytes.fromhex("0102030405060708")).decode(),
        "d": powbot_difficulty_hex(difficulty_level),
        "dl": difficulty_level,
    }


def _challenge_b64(difficulty_level: int = 3) -> str:
    return base64.b64encode(json.dumps(_challenge_obj(difficulty_level), separators=(",", ":")).encode()).decode()


def test_powbot_difficulty_thresholds() -> None:
    assert powbot_difficulty_hex(3) == "1f"
    assert powbot_difficulty_hex(5) == "07"
    assert powbot_difficulty_hex(8) == "00"
    assert powbot_difficulty_hex(9) == "007f"


def test_powbot_scrypt_fixture() -> None:
    challenge = _challenge_b64(3)
    item = parse_powbot_challenge(challenge)
    solution = solve_powbot_challenge(item, timeout_sec=5)

    assert solution is not None
    assert solution.nonce_hex == "10"
    assert solution.hash_hex == "c78d96a6d881218646dcb67a1f7d8b13"
    assert solution.end_of_hash == "13"
    assert solution.attempts == 17
    assert powbot_scrypt_hash_hex(item, "10") == solution.hash_hex
    assert verify_powbot_solution(item, solution)
    assert not verify_powbot_solution(item, "0f")


class _PowBotHandler(BaseHTTPRequestHandler):
    issued: set[str] = set()
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _text(self, payload: str, status: int = 200) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {API_TOKEN}":
            self._text("Unauthorized", 401)
            return False
        return True

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/GetChallenges":
            difficulty_level = int(qs.get("difficultyLevel", ["3"])[0])
            challenge = _challenge_b64(difficulty_level)
            type(self).issued.add(challenge)
            self._json([challenge])
            return
        if parsed.path == "/Verify":
            challenge = qs.get("challenge", [""])[0]
            nonce = qs.get("nonce", [""])[0]
            type(self).calls.append({"challenge": challenge, "nonce": nonce})
            if challenge not in type(self).issued:
                self._text("challenge not found", 404)
                return
            type(self).issued.remove(challenge)
            if not verify_powbot_solution(challenge, nonce):
                self._text("bad nonce", 400)
                return
            self._text("OK")
            return
        self._text("not found", 404)


def test_powbot_solver_protocol_flow_local_server() -> None:
    _PowBotHandler.issued = set()
    _PowBotHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PowBotHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PowBotSolver().solve(
                base_url=base,
                api_token=API_TOKEN,
                difficulty_level=3,
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "powbot"
    assert ret.captcha_type == "scrypt_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "10"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["N"] == 16
    assert _PowBotHandler.calls == [{"challenge": _challenge_b64(3), "nonce": "10"}]
