from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.chpiopow import (
    CHPIO_CHALLENGE_MAGIC,
    CHPIO_REDEEMED_MAGIC,
    ChpioPowSolver,
    chpiopow_hash_bytes,
    parse_chpiopow_challenge,
    sign_chpiopow_data,
    solve_chpiopow_challenge,
    verify_chpiopow_redeemed,
    verify_chpiopow_signed_data,
    verify_chpiopow_solution,
)

SECRET = "test-secret"
FIXTURE_PAYLOAD = {
    "magic": CHPIO_CHALLENGE_MAGIC,
    "challenges": [["AQI=", "AwQF"]],
    "difficultyBits": 18,
}
FIXTURE_SIGNED = {
    "data": '{"magic":"2104f639-ba1b-48f3-9443-889128163f5a","challenges":[["AQI=","AwQF"]],"difficultyBits":18}',
    "hash": "uMXVPYj+GgchQWH0IG1qwPAvf9UtEVt+bgciYMzHuCg=",
}
FIXTURE_SOLUTION_BYTES = bytes([45, 176, 0, 0, 0, 0, 0, 0])
FIXTURE_SOLUTION_B64 = "LbAAAAAAAAA="
FIXTURE_SOLUTION_INT = 45101


def test_chpiopow_upstream_solver_fixture() -> None:
    # Matches chpio/pow-captcha pkgs/pow-captcha/src/solver/solver.spec.ts:
    # solveJs([1,2], [3,4,5], 18) -> [45,176,0,0,0,0,0,0].
    challenge = parse_chpiopow_challenge(FIXTURE_PAYLOAD)
    solution = solve_chpiopow_challenge(challenge, max_attempts_per_challenge=100_000, timeout_sec=5)

    assert solution is not None
    assert solution.solutions == [FIXTURE_SOLUTION_BYTES]
    assert solution.solution_b64 == [FIXTURE_SOLUTION_B64]
    assert solution.solution_ints == [FIXTURE_SOLUTION_INT]
    assert chpiopow_hash_bytes(b"\x01\x02", FIXTURE_SOLUTION_BYTES).hex().startswith("030")
    assert verify_chpiopow_solution(b"\x01\x02", b"\x03\x04\x05", 18, FIXTURE_SOLUTION_BYTES)
    assert verify_chpiopow_solution("AQI=", "AwQF", 18, FIXTURE_SOLUTION_B64)


def test_chpiopow_signed_data_matches_upstream_utf16_hash() -> None:
    assert sign_chpiopow_data(FIXTURE_PAYLOAD, SECRET) == FIXTURE_SIGNED
    assert verify_chpiopow_signed_data(FIXTURE_SIGNED, SECRET)
    assert not verify_chpiopow_signed_data(FIXTURE_SIGNED, "wrong-secret")

    challenge = parse_chpiopow_challenge(FIXTURE_SIGNED, secret=SECRET)
    assert challenge.signed_data == FIXTURE_SIGNED
    assert challenge.difficulty_bits == 18
    assert challenge.entries[0].nonce == b"\x01\x02"


def test_chpiopow_redeemed_signed_magic() -> None:
    redeemed = sign_chpiopow_data({"magic": CHPIO_REDEEMED_MAGIC}, SECRET)
    assert verify_chpiopow_redeemed(redeemed, SECRET)
    assert not verify_chpiopow_redeemed(redeemed, "wrong-secret")


class _ChpioPowHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(FIXTURE_SIGNED).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/redeem":
            self.send_response(404)
            self.end_headers()
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        assert payload["challengesSigned"] == FIXTURE_SIGNED
        ok = payload.get("solutions") == [FIXTURE_SOLUTION_B64]
        body_payload = sign_chpiopow_data({"magic": CHPIO_REDEEMED_MAGIC}, SECRET) if ok else {"ok": False}
        body = json.dumps(body_payload).encode("utf-8")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_chpiopow_solver_protocol_flow_local_server() -> None:
    _ChpioPowHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChpioPowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            ChpioPowSolver().solve(
                challenge_url=f"{base}/challenge",
                redeem_url=f"{base}/redeem",
                submit=True,
                secret=SECRET,
                max_attempts_per_challenge=100_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "chpiopow"
    assert ret.captcha_type == "target_match_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["solution_ints"] == [FIXTURE_SOLUTION_INT]
    assert ret.diagnostics["difficulty_bits"] == 18
    assert verify_chpiopow_redeemed(json.loads(ret.ticket or "{}"), SECRET)
    assert _ChpioPowHandler.calls[0]["solutions"] == [FIXTURE_SOLUTION_B64]
