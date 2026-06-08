from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.impost import (
    ImpostSolver,
    impost_argon2_hash_hex,
    parse_impost_challenge,
    solve_impost_challenge,
    verify_impost_solution,
)

SALT = "impost-salt"
TARGET_HASH_NONCE_2 = "001f1f03c8591bd692761601e1402ae569e0151ef8d5ba3d083e803ac4f2cd5e"
TARGET_CHALLENGE = {
    "algorithm": "argon2id",
    "strategy": "target_number",
    "salt": SALT,
    "target": TARGET_HASH_NONCE_2,
}
LEADING_CHALLENGE = {
    "algorithm": "argon2id",
    "strategy": "leading_zeroes",
    "salt": SALT,
    "difficulty": 2,
}


def test_impost_argon2_hash_matches_reversed_wasm_fixture() -> None:
    # Reproduces packages/solver/src/argon2.zig: Argon2id(t=3, m=8192KiB, p=1),
    # secret = decimal nonce UTF-8, salt = challenge salt UTF-8, 32-byte hex output.
    assert impost_argon2_hash_hex(SALT, 2) == TARGET_HASH_NONCE_2
    assert verify_impost_solution(TARGET_CHALLENGE, 2)
    assert verify_impost_solution(LEADING_CHALLENGE, {"solution": "2"})


def test_impost_solve_target_number_fixture() -> None:
    solution = solve_impost_challenge(TARGET_CHALLENGE, max_attempts=5, timeout_sec=10)

    assert solution is not None
    assert solution.nonce == 2
    assert solution.hash_hex == TARGET_HASH_NONCE_2
    assert solution.checked == 3
    assert solution.submit_body == {"challenge": SALT, "nonce": "2"}
    assert solution.form_value == {"challenge": SALT, "solution": "2"}


def test_impost_solve_leading_zeroes_fixture() -> None:
    solution = solve_impost_challenge(LEADING_CHALLENGE, max_attempts=5, timeout_sec=10)

    assert solution is not None
    assert solution.nonce == 2
    assert solution.hash_hex == TARGET_HASH_NONCE_2
    assert solution.hash_hex.startswith("00")


class _ImpostHandler(BaseHTTPRequestHandler):
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

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/challenge":
            self._json({"error": "not-found"}, 404)
            return
        self._json({"challenge": TARGET_CHALLENGE})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/verify":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        challenge = parse_impost_challenge(TARGET_CHALLENGE)
        ok = payload.get("challenge") == SALT and verify_impost_solution(challenge, payload)
        self._json({"ok": ok, "message": "Challenge solved"}, 200 if ok else 400)


def test_impost_solver_protocol_flow_local_server() -> None:
    _ImpostHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ImpostHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            ImpostSolver().solve(
                challenge_url=f"{base}/challenge",
                verify_url=f"{base}/verify",
                submit=True,
                max_attempts=5,
                timeout_sec=10,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "impost"
    assert ret.captcha_type == "argon2id_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "Challenge solved"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonce"] == "2"
    assert ret.diagnostics["browser"] == "not_used"
    assert _ImpostHandler.calls[0] == {"challenge": SALT, "nonce": "2"}
