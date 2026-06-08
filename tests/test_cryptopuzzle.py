from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.cryptopuzzle import (
    CryptoPuzzleSolver,
    build_cryptopuzzle_fixture,
    decode_cryptopuzzle_base64,
    encode_cryptopuzzle_base64,
    parse_cryptopuzzle_archive,
    sequential_mod_exp_squares,
    solve_cryptopuzzle_archive,
    verify_cryptopuzzle_solution,
)

KEY = bytes.fromhex("11" * 32)
SALT = bytes.fromhex("22" * 32)
IV = bytes.fromhex("33" * 16)
MESSAGE = "crypto-puzzle-pass-token"
PUZZLE = build_cryptopuzzle_fixture(n=3233, a=5, t=25, key=KEY, message=MESSAGE, salt=SALT, iv=IV)
PUZZLE_B64 = encode_cryptopuzzle_base64(PUZZLE)


class _CryptoPuzzleHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
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
        if self.path == "/challenge":
            type(self).challenge_calls += 1
            self._json({"puzzleB64": PUZZLE_B64})
            return
        self._json({"error": "not-found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/verify":
            type(self).verify_calls.append(payload)
            ok = payload.get("solution") == MESSAGE
            self._json({"ok": ok, "token": payload.get("solution") if ok else ""}, 200 if ok else 403)
            return
        self._json({"error": "not-found"}, 404)


def test_cryptopuzzle_fixture_solve() -> None:
    puzzle = parse_cryptopuzzle_archive(PUZZLE_B64)
    solution = solve_cryptopuzzle_archive(puzzle)

    assert puzzle.n == 3233
    assert puzzle.a == 5
    assert puzzle.t == 25
    assert sequential_mod_exp_squares(5, 25, 3233) == 452
    assert decode_cryptopuzzle_base64(PUZZLE_B64) == PUZZLE
    assert solution.message == MESSAGE
    assert solution.key_hex == KEY.hex()
    assert solution.b == 452
    assert solution.iterations == 25
    assert solution.submit_body == {"solution": MESSAGE, "message": MESSAGE}
    assert verify_cryptopuzzle_solution(PUZZLE_B64, solution, expected_message=MESSAGE)
    assert not verify_cryptopuzzle_solution(PUZZLE_B64, "wrong-token")


def test_cryptopuzzle_parse_parts_object() -> None:
    parsed = parse_cryptopuzzle_archive(PUZZLE)
    obj = {
        "n": str(parsed.n),
        "a": str(parsed.a),
        "t": str(parsed.t),
        "Ck": str(parsed.encrypted_key),
        "Cm": parsed.encrypted_message.hex(),
    }
    solution = solve_cryptopuzzle_archive(obj)

    assert solution.message == MESSAGE
    assert solution.key_hex == KEY.hex()


def test_cryptopuzzle_solver_protocol_flow_local_server() -> None:
    _CryptoPuzzleHandler.challenge_calls = 0
    _CryptoPuzzleHandler.verify_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CryptoPuzzleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(CryptoPuzzleSolver().solve(base_url=base, submit=True, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "cryptopuzzle"
    assert ret.captcha_type == "rsw_time_lock_puzzle"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == MESSAGE
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["t"] == 25
    assert _CryptoPuzzleHandler.challenge_calls == 1
    assert _CryptoPuzzleHandler.verify_calls[0] == {"solution": MESSAGE, "message": MESSAGE}
