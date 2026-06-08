from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.cap import (
    CapSolver,
    cap_hash_hex,
    cap_pow_matches,
    cap_seeded_challenges,
    fnv1a,
    prng_from_hash,
    solve_cap_challenges,
    solve_cap_seeded,
    verify_cap_solution,
)


def test_cap_prng_known_values() -> None:
    # Cross-checked against Cap core/src/prng.js at tiagorangel1/cap@2d9871c.
    assert fnv1a("challenge token") == 1864351151
    assert prng_from_hash(fnv1a("challenge token1"), 8) == "0301c97a"
    assert prng_from_hash(fnv1a("challenge token1d"), 3) == "d4f"


def test_cap_seeded_solver_returns_valid_nonces() -> None:
    token = "challenge token"
    solution = solve_cap_seeded(
        token,
        c=3,
        s=8,
        d=1,
        max_attempts_per_challenge=50_000,
        timeout_sec=5,
    )

    assert solution is not None
    assert solution.token == token
    assert len(solution.solutions) == 3
    for challenge, nonce in zip(solution.challenges, solution.solutions, strict=True):
        assert verify_cap_solution(challenge.salt, challenge.target, nonce)


def test_cap_challenge_list_exact_digest_solution() -> None:
    salt = "salt-list"
    target = cap_hash_hex(salt, 123)

    nonces, diag = solve_cap_challenges([(salt, target)], max_attempts_per_challenge=200)

    assert nonces == [123]
    assert diag["checked"] == 124
    assert cap_pow_matches(bytes.fromhex(target), target)


class _CapV1Handler(BaseHTTPRequestHandler):
    token = "local-cap-token"
    c = 4
    s = 8
    d = 1
    redeemed = 0

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "challenge": {"c": self.c, "s": self.s, "d": self.d},
                "token": self.token,
                "expires": int(time.time() * 1000) + 600_000,
            }
        ).encode("utf-8")
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
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        ok = data.get("token") == self.token and isinstance(data.get("solutions"), list)
        challenges = cap_seeded_challenges(self.token, c=self.c, s=self.s, d=self.d)
        if ok:
            ok = len(data["solutions"]) == len(challenges) and all(
                verify_cap_solution(ch.salt, ch.target, nonce)
                for ch, nonce in zip(challenges, data["solutions"], strict=True)
            )
        type(self).redeemed += int(ok)
        body = json.dumps(
            {
                "success": bool(ok),
                "token": "cap-verification-token" if ok else None,
                "expires": int(time.time() * 1000) + 1_200_000,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_cap_solver_v1_api_endpoint_redeem_flow() -> None:
    _CapV1Handler.redeemed = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapV1Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}/"
    try:
        ret = asyncio.run(
            CapSolver().solve(
                api_endpoint=endpoint,
                timeout_sec=5,
                max_attempts_per_challenge=50_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "cap"
    assert ret.captcha_type == "proof_of_work"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "cap-verification-token"
    assert ret.verify_code == "redeemed"
    assert _CapV1Handler.redeemed == 1


class _CapV2Handler(BaseHTTPRequestHandler):
    token = "format-two-token"
    challenges = [
        {"protocol": "sha256-pow", "payload": {"salt": "v2-a", "target": cap_hash_hex("v2-a", 0)}},
        {"protocol": "sha256-pow", "payload": {"salt": "v2-b", "target": cap_hash_hex("v2-b", 7)}},
    ]

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "token": self.token,
                "format": 2,
                "challenges": self.challenges,
                "expires": int(time.time() * 1000) + 600_000,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        solutions = data.get("solutions")
        ok = data.get("token") == self.token and isinstance(solutions, list)
        if ok:
            expected = [("v2-a", cap_hash_hex("v2-a", 0)), ("v2-b", cap_hash_hex("v2-b", 7))]
            ok = len(solutions) == 2 and all(
                isinstance(sol, dict) and verify_cap_solution(salt, target, sol.get("nonce"))
                for (salt, target), sol in zip(expected, solutions, strict=True)
            )
        body = json.dumps({"success": bool(ok), "token": "cap-v2-token"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_cap_solver_v2_sha256_pow_flow() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapV2Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}/"
    try:
        ret = asyncio.run(CapSolver().solve(api_endpoint=endpoint, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.ticket == "cap-v2-token"
    assert ret.verify_code == "redeemed"
    assert ret.raw["solution"]["solutions"] == [{"nonce": 0}, {"nonce": 7}]


def test_cap_solver_reports_unsupported_protocols() -> None:
    ret = asyncio.run(
        CapSolver().solve(
            challenge_json={
                "token": "x",
                "format": 2,
                "challenges": [{"protocol": "rsw", "payload": {"N": "1", "x": "2", "t": 1}}],
            }
        )
    )

    assert ret.ok is False
    assert "rsw" in ret.errors[0]
    assert ret.diagnostics["unsupported_protocols"] == ["rsw"]
