from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.btx import (
    HEADER_CHALLENGE,
    HEADER_CHALLENGE_ID,
    HEADER_PROOF_DIGEST,
    HEADER_PROOF_NONCE,
    NOISE_TAG_EL,
    BtxSolver,
    build_btx_proof,
    build_btx_submit_body,
    build_btx_submit_headers,
    btx_attempt_digest_hex,
    btx_canonical_matmul,
    btx_from_seed_rect,
    btx_generate_noise,
    compute_btx_header_hash,
    derive_btx_sigma,
    parse_btx_challenge,
    serialize_btx_header,
    solve_btx_challenge,
    solve_btx_nonce,
    verify_btx_solution,
)
from antibot_sdk.providers import btx as btx_mod

ZERO = "00" * 32
A = "11" * 32
B = "22" * 32
C = "33" * 32
D = "44" * 32


def make_challenge(*, target: str = "ff" * 32, nonce64_start: int = 0) -> dict[str, Any]:
    return {
        "kind": "matmul_service_challenge_v1",
        "challenge_id": "btx-fixture",
        "issued_at": 1700000000,
        "expires_at": 1700000600,
        "expires_in_s": 600,
        "binding": {
            "chain": "regtest",
            "purpose": "rate_limit",
            "resource": "fixture:/api",
            "subject": "fixture:user",
            "resource_hash": "aa",
            "subject_hash": "bb",
            "salt": "cc",
            "anchor_height": 1,
            "anchor_hash": "dd",
        },
        "proof_policy": {
            "verification_rule": "fixture",
            "sigma_gate_applied": False,
            "expiration_enforced": True,
            "challenge_id_required": True,
            "replay_protection": "redeemmatmulserviceproof",
            "redeem_rpc": "redeemmatmulserviceproof",
            "solve_rpc": "solvematmulservicechallenge",
            "locally_issued_required": True,
        },
        "challenge": {
            "chain": "regtest",
            "algorithm": "matmul",
            "height": 2,
            "previousblockhash": A,
            "mintime": 1700000000,
            "bits": "1d00ffff",
            "difficulty": 0.0001,
            "target": target,
            "noncerange": "0000000000000000ffffffffffffffff",
            "header_context": {
                "version": 1,
                "previousblockhash": A,
                "merkleroot": B,
                "time": 1700000000,
                "bits": "1d00ffff",
                "nonce64_start": nonce64_start,
                "matmul_dim": 4,
                "seed_a": C,
                "seed_b": D,
            },
            "matmul": {
                "n": 4,
                "b": 2,
                "r": 1,
                "q": 2147483647,
                "min_dimension": 4,
                "max_dimension": 2048,
                "seed_a": C,
                "seed_b": D,
            },
        },
    }


class _BtxHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    submit_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/gate":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        challenge = make_challenge(target="0f" * 32)
        self._json({"challenge": challenge, "retry_with": [HEADER_PROOF_NONCE]}, 402, {HEADER_CHALLENGE: json.dumps(challenge)})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/gate":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        body = json.loads(raw.decode("utf-8") or "{}") if raw else None
        challenge_raw = self.headers.get(HEADER_CHALLENGE) or "{}"
        challenge = json.loads(challenge_raw)
        solution = {
            "nonce64_hex": self.headers.get(HEADER_PROOF_NONCE),
            "digest_hex": self.headers.get(HEADER_PROOF_DIGEST),
        }
        ok = (
            self.headers.get(HEADER_CHALLENGE_ID) == "btx-fixture"
            and verify_btx_solution(challenge, solution)
        )
        type(self).submit_calls.append({"headers": dict(self.headers), "body": body, "ok": ok})
        self._json({"valid": ok, "admitted": ok}, 200 if ok else 403)


def test_btx_header_and_golden_vectors() -> None:
    challenge = parse_btx_challenge(make_challenge())
    header = serialize_btx_header(challenge.header_context, 0)
    assert len(header) == 150
    assert header[0:4] == b"\x01\x00\x00\x00"
    assert header[68:72] == bytes.fromhex("00f15365")
    assert header[72:76] == bytes.fromhex("ffff001d")
    assert len(compute_btx_header_hash(challenge.header_context, 0)) == 32
    assert len(derive_btx_sigma(challenge.header_context, 0)) == 32

    zero_seed = bytes(32)
    m = btx_from_seed_rect(zero_seed, 8, 8)
    assert m.data[:3] == [1432335981, 1134348657, 428617384]

    noise_seed = btx_mod._derive_noise_seed(NOISE_TAG_EL, zero_seed)  # noqa: SLF001
    assert noise_seed.hex() == "993a427eeb3dc053000d570842d2e7f0f093393c00e8e729155c48719118b386"

    noise = btx_generate_noise(zero_seed, 4, 2)
    assert noise["E_L"].data == [
        1931902215,
        129748845,
        505403935,
        538008036,
        1006343602,
        1697202758,
        2128262120,
        942473671,
    ]
    assert noise["E_R"].data == [
        962405871,
        1142251768,
        505582893,
        443901062,
        858057583,
        2082571321,
        70698889,
        1087797252,
    ]


def test_btx_canonical_matmul_golden_vector() -> None:
    seed_a = bytes.fromhex("376d8f3e225ed14f5614a884f822920360a7b021684bd74600aa5f88dbd32a27")
    seed_b = bytes.fromhex("3609c5eaeae940efb3035712cd65b09f0330d77fdf852128a89069b3ac02f586")
    sigma = bytes.fromhex("ffc381ccd5e78ab52348ec8ba82f51d5feb0e857d7969ab0df9a5891c68cdf15")
    matrix_a = btx_from_seed_rect(seed_a, 8, 8)
    matrix_b = btx_from_seed_rect(seed_b, 8, 8)
    _, transcript_hash = btx_canonical_matmul(matrix_a, matrix_b, 4, sigma)
    assert transcript_hash.hex() == "b134b59bfdd28f3bf566e35a4d44b0af8e9530dce8047125a59d308ed22c17b8"


def test_btx_solver_fixture_vectors() -> None:
    assert btx_attempt_digest_hex(make_challenge(target="ff" * 32, nonce64_start=0), 0) == (
        "f2b7266e9db525ea742dc70e64838a2fd1f50762911446f129aff78161696837"
    )
    assert btx_attempt_digest_hex(make_challenge(target="ff" * 32, nonce64_start=7), 7) == (
        "89ef677daf38cb6d400f0a7ff6c4eb9d709ff7db4376816d6d3d7431fae7bdb7"
    )
    assert btx_attempt_digest_hex(make_challenge(target="ff" * 32, nonce64_start=42), 42) == (
        "4beaa5eb0fea1d9148107348d4b1aaed13906bc00a530893d1f2f94027911b16"
    )

    lax = solve_btx_challenge(make_challenge(target="ff" * 32), timeout_sec=5, max_attempts=10)
    assert lax is not None
    assert lax.nonce64_hex == "0000000000000000"
    assert lax.digest_hex == "f2b7266e9db525ea742dc70e64838a2fd1f50762911446f129aff78161696837"

    mid = solve_btx_challenge(make_challenge(target="7f" * 32), timeout_sec=5, max_attempts=10)
    assert mid is not None
    assert mid.nonce64_hex == "0000000000000002"
    assert mid.digest_hex == "2ab74c27f6f05d88fe4b8ec400bdd0594455dc760bf0ceef05c1c20301bfb74a"

    hard = solve_btx_challenge(make_challenge(target="0f" * 32), timeout_sec=5, max_attempts=100)
    assert hard is not None
    assert hard.nonce64_hex == "0000000000000012"
    assert hard.digest_hex == "0b2af4e3c77579dba0f67d56399e9873549814a0f27c6ab79608eba21211e6e7"
    assert verify_btx_solution(make_challenge(target="0f" * 32), hard)
    assert not verify_btx_solution(make_challenge(target="0f" * 32), {"nonce64_hex": "0000000000000011", "digest_hex": hard.digest_hex})

    nonce, digest, attempts = solve_btx_nonce(
        make_challenge(target="0f" * 32),
        max_attempts=100,
        deadline_epoch=None,
    )
    assert (nonce, digest, attempts) == (
        18,
        "0b2af4e3c77579dba0f67d56399e9873549814a0f27c6ab79608eba21211e6e7",
        19,
    )


def test_btx_headers_and_submit_body() -> None:
    challenge = parse_btx_challenge(make_challenge(target="ff" * 32))
    solution = solve_btx_challenge(challenge, timeout_sec=5, max_attempts=10)
    assert solution is not None
    proof = build_btx_proof(challenge, solution)
    assert proof["nonce64_hex"] == "0000000000000000"
    assert proof["digest_hex"] == solution.digest_hex
    headers = build_btx_submit_headers(challenge, solution)
    assert headers[HEADER_CHALLENGE_ID] == "btx-fixture"
    assert headers[HEADER_PROOF_NONCE] == "0000000000000000"
    assert headers[HEADER_PROOF_DIGEST] == solution.digest_hex
    assert json.loads(headers[HEADER_CHALLENGE])["challenge_id"] == "btx-fixture"
    body = build_btx_submit_body(challenge, solution)
    assert json.loads(body["btx_proof"])["digest_hex"] == solution.digest_hex


def test_btx_solver_protocol_flow_local_server() -> None:
    _BtxHandler.challenge_calls = 0
    _BtxHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BtxHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/gate"
    try:
        ret = asyncio.run(
            BtxSolver().solve(
                challenge_url=base,
                submit_url=base,
                submit=True,
                submit_json={"payload": "fixture"},
                timeout_sec=5,
                max_attempts=100,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "btx"
    assert ret.captcha_type == "matmul_service_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce64_hex"] == "0000000000000012"
    assert _BtxHandler.challenge_calls == 1
    assert _BtxHandler.submit_calls[0]["ok"] is True
