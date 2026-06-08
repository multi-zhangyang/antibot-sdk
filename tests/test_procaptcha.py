from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.procaptcha import (
    ProcaptchaSolver,
    build_procaptcha_pow_submit_body,
    count_leading_zero_nibbles,
    parse_procaptcha_pow_challenge,
    procaptcha_pow_hash_hex,
    solve_procaptcha_pow_challenge,
    verify_procaptcha_pow_solution,
)

USER = "5FProsopoUserAccount000000000000000000000000000"
DAPP = "5FProsopoDappAccount000000000000000000000000000"
USER_TIMESTAMP_SIGNATURE = "0x" + "ab" * 64
PROVIDER_SIGNATURE = "0x" + "cd" * 64
FIXTURE = {
    "challenge": "prosopo-fixture",
    "difficulty": 3,
    "timestamp": "1780955164000",
    "signature": {"provider": {"challenge": PROVIDER_SIGNATURE}},
}


class _ProcaptchaHandler(BaseHTTPRequestHandler):
    challenge_calls: list[dict[str, Any]] = []
    submit_calls: list[dict[str, Any]] = []
    challenge_headers: list[dict[str, str]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/v1/prosopo/provider/client/captcha/pow":
            type(self).challenge_calls.append(payload)
            type(self).challenge_headers.append(
                {
                    "Prosopo-Site-Key": self.headers.get("Prosopo-Site-Key", ""),
                    "Prosopo-User": self.headers.get("Prosopo-User", ""),
                }
            )
            if payload.get("user") != USER or payload.get("dapp") != DAPP:
                self._json({"error": {"message": "bad account"}}, 403)
                return
            if payload.get("sessionId") != "session-1":
                self._json({"error": {"message": "bad session"}}, 403)
                return
            self._json(FIXTURE)
            return
        if self.path == "/v1/prosopo/provider/client/pow/solution":
            type(self).submit_calls.append(payload)
            if payload.get("user") != USER or payload.get("dapp") != DAPP:
                self._json({"verified": False, "error": {"message": "bad account"}}, 403)
                return
            if payload.get("signature", {}).get("provider", {}).get("challenge") != PROVIDER_SIGNATURE:
                self._json({"verified": False, "error": {"message": "bad provider signature"}}, 403)
                return
            if payload.get("signature", {}).get("user", {}).get("timestamp") != USER_TIMESTAMP_SIGNATURE:
                self._json({"verified": False, "error": {"message": "bad user signature"}}, 403)
                return
            if payload.get("verifiedTimeout") != 120_000:
                self._json({"verified": False, "error": {"message": "bad timeout"}}, 403)
                return
            if not verify_procaptcha_pow_solution(FIXTURE, payload):
                self._json({"verified": False, "error": {"message": "pow failed"}}, 403)
                return
            self._json({"verified": True})
            return
        self._json({"error": "not-found"}, 404)


def test_procaptcha_pow_fixture() -> None:
    challenge = parse_procaptcha_pow_challenge(FIXTURE)
    solution = solve_procaptcha_pow_challenge(challenge, timeout_sec=5)

    assert challenge.provider_challenge_signature == PROVIDER_SIGNATURE
    assert solution is not None
    assert solution.nonce == 12996
    assert solution.hash_hex == "0006955884fe61953c1ae5749318dc5e1636a86601571a8408d5dfcfdc1d5b51"
    assert solution.leading_zero_nibbles == 3
    assert solution.attempts == 12997
    assert procaptcha_pow_hash_hex(FIXTURE["challenge"], 12996) == solution.hash_hex
    assert count_leading_zero_nibbles(bytes.fromhex(solution.hash_hex)) == 3
    assert verify_procaptcha_pow_solution(FIXTURE, solution)
    assert not verify_procaptcha_pow_solution(FIXTURE, 12995)

    body = build_procaptcha_pow_submit_body(
        challenge,
        solution,
        user=USER,
        dapp=DAPP,
        user_timestamp_signature=USER_TIMESTAMP_SIGNATURE,
    )
    assert body == {
        "challenge": FIXTURE["challenge"],
        "difficulty": 3,
        "signature": {
            "provider": {"challenge": PROVIDER_SIGNATURE},
            "user": {"timestamp": USER_TIMESTAMP_SIGNATURE},
        },
        "user": USER,
        "dapp": DAPP,
        "nonce": 12996,
        "verifiedTimeout": 120_000,
    }


def test_procaptcha_solver_protocol_flow_local_server() -> None:
    _ProcaptchaHandler.challenge_calls = []
    _ProcaptchaHandler.submit_calls = []
    _ProcaptchaHandler.challenge_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProcaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    provider_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            ProcaptchaSolver().solve(
                provider_url=provider_url,
                user=USER,
                dapp=DAPP,
                session_id="session-1",
                submit=True,
                user_timestamp_signature=USER_TIMESTAMP_SIGNATURE,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "procaptcha"
    assert ret.captcha_type == "prosopo_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == 12996
    assert _ProcaptchaHandler.challenge_calls[0] == {"user": USER, "dapp": DAPP, "sessionId": "session-1"}
    assert _ProcaptchaHandler.challenge_headers[0] == {"Prosopo-Site-Key": DAPP, "Prosopo-User": USER}
    assert _ProcaptchaHandler.submit_calls[0]["nonce"] == 12996
