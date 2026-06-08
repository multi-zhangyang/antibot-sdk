from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.portcullis import (
    PortcullisSolver,
    compute_portcullis_base_hash,
    leading_zero_bits,
    parse_portcullis_challenge,
    parse_portcullis_token,
    sign_portcullis_challenge,
    solve_portcullis_challenge,
    verify_portcullis_signature,
    verify_portcullis_solution,
)

SECRET = b"server-secret-32bytes-fixture"
FIXTURE_CHALLENGE = {
    "id": "test-id-001",
    "salt": "AQIDBAUGBwgJCgsMDQ4PEA==",
    "diff": 12,
    "exp": 9999999999999,
    "site_key": "pk_test",
    "m_cost": 8,
    "t_cost": 1,
    "p_cost": 1,
}
FIXTURE_SIG = "Fnv7B8nI4lCm7TVCUuU3Yhc/qE49vLkTkTR9+SBLxTg="
FIXTURE_BASE_HASH = "9ad549858f257bbed625072cd542f88746b3a3a2f711fb97454ac955c02e41dd"
FIXTURE_NONCE = 1756
FIXTURE_HASH = "0007dc26538be91230b0bcde0acc3a824b064dc19b1d17ec5d259255c19dc820"


def test_portcullis_argon2_pow_matches_upstream_rust_fixture() -> None:
    challenge = parse_portcullis_challenge({"success": True, "challenge": FIXTURE_CHALLENGE, "sig": FIXTURE_SIG})

    assert challenge.salt == bytes(range(1, 17))
    assert challenge.sig == FIXTURE_SIG
    assert compute_portcullis_base_hash(challenge).hex() == FIXTURE_BASE_HASH
    assert sign_portcullis_challenge(challenge, SECRET) == FIXTURE_SIG
    assert verify_portcullis_signature(challenge, secret=SECRET)

    solution = solve_portcullis_challenge(challenge, max_iters=100_000, timeout_sec=5)

    assert solution is not None
    assert solution.nonce == FIXTURE_NONCE
    assert solution.hash_hex == FIXTURE_HASH
    assert solution.leading_zero_bits == 13
    assert verify_portcullis_solution(challenge, solution.nonce)


def test_portcullis_legacy_defaults_and_leading_zero_bits() -> None:
    legacy = dict(FIXTURE_CHALLENGE)
    legacy.pop("m_cost")
    legacy.pop("t_cost")
    legacy.pop("p_cost")
    challenge = parse_portcullis_challenge(legacy)

    assert challenge.m_cost == 4096
    assert challenge.t_cost == 1
    assert challenge.p_cost == 1
    assert leading_zero_bits(bytes.fromhex("000001ff")) == 23


def _token(challenge_id: str = "test-id-001", site_key: str = "pk_test") -> str:
    payload = json.dumps(
        {"challenge_id": challenge_id, "site_key": site_key, "exp": 9999999999999},
        separators=(",", ":"),
    ).encode("utf-8")
    sig = b"\x11" * 32
    return (
        base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        + "."
        + base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    )


class _PortcullisHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if self.path == "/api/v1/challenge":
            assert body == {"site_key": "pk_test"}
            payload = {"success": True, "challenge": FIXTURE_CHALLENGE, "sig": FIXTURE_SIG}
            self._send(payload)
            return
        if self.path == "/api/v1/verify":
            self.calls.append(body)
            ok = body.get("sig") == FIXTURE_SIG and verify_portcullis_solution(body.get("challenge"), body.get("nonce"))
            self._send({"success": ok, "captcha_token": _token(), "exp": 9999999999999}, status=200 if ok else 400)
            return
        if self.path == "/api/v1/siteverify":
            ok = body.get("token") == _token() and body.get("secret_key") == "sk_test_secret"
            self._send({"success": ok, "challenge_id": "test-id-001", "site_key": "pk_test"})
            return
        self.send_response(404)
        self.end_headers()

    def _send(self, payload: dict[str, Any], *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_portcullis_solver_protocol_flow_local_server() -> None:
    _PortcullisHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PortcullisHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            PortcullisSolver().solve(
                base_url=base,
                sitekey="pk_test",
                submit=True,
                siteverify_url=f"{base}/api/v1/siteverify",
                secret_key="sk_test_secret",
                max_iters=100_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "portcullis"
    assert ret.captcha_type == "argon2_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == _token()
    assert ret.randstr == "test-id-001"
    assert ret.verify_code == "siteverified"
    assert ret.diagnostics["nonce"] == FIXTURE_NONCE
    assert ret.diagnostics["leading_zero_bits"] == 13
    assert parse_portcullis_token(str(ret.ticket))["payload"]["site_key"] == "pk_test"
    assert _PortcullisHandler.calls[0]["nonce"] == FIXTURE_NONCE
