from __future__ import annotations

import asyncio
import base64
import json
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.trustcaptcha import (
    TrustcaptchaSolver,
    build_trustcaptcha_create_body,
    build_trustcaptcha_submit_body,
    calculate_trustcaptcha_integrity_hash,
    count_leading_zero_bits,
    parse_trustcaptcha_challenge,
    solve_trustcaptcha_challenge,
    trustcaptcha_pow_hash_bytes,
    verify_trustcaptcha_solution,
    verify_trustcaptcha_task_solution,
)

SITE_KEY = "tc_site_fixture"
VERIFICATION_TOKEN = "tc.finished.token.fixture"
FIXTURE = {
    "verificationId": "tc-fixture-1",
    "difficulty": 12,
    "tasks": [
        {"number": 1, "input": base64.b64encode(b"trustcaptcha-fixture-a").decode()},
        {"number": 2, "input": base64.b64encode(b"trustcaptcha-fixture-b").decode()},
    ],
}


class _TrustcaptchaHandler(BaseHTTPRequestHandler):
    create_calls: list[dict[str, Any]] = []
    submit_calls: list[dict[str, Any]] = []

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
        if self.path == "/v2/verifications":
            type(self).create_calls.append(payload)
            if payload.get("siteKey") != SITE_KEY:
                self._json({"error": "bad site key"}, 404)
                return
            if payload.get("integrityHash") != calculate_trustcaptcha_integrity_hash(payload["browserInformation"]):
                self._json({"error": "bad integrity"}, 409)
                return
            self._json({"challenge": FIXTURE}, 200)
            return
        if self.path == f"/v2/verifications/{FIXTURE['verificationId']}/challenges":
            type(self).submit_calls.append(payload)
            if not _valid_iso(payload.get("startSolvingTimestamp")) or not _valid_iso(payload.get("solvedTimestamp")):
                self._json({"error": "bad timestamps"}, 409)
                return
            tasks = payload.get("tasks")
            if not isinstance(tasks, list) or len(tasks) != len(FIXTURE["tasks"]):
                self._json({"error": "bad tasks"}, 409)
                return
            by_number = {task["number"]: task for task in FIXTURE["tasks"]}
            for task_solution in tasks:
                task = by_number.get(task_solution.get("number"))
                if not task or not verify_trustcaptcha_task_solution(task, task_solution, FIXTURE["difficulty"]):
                    self._json({"error": "bad pow"}, 409)
                    return
            if any(field.get("value") for field in payload.get("honeypotFields") or []):
                self._json({"error": "honeypot"}, 409)
                return
            self._json({"finished": {"verificationToken": VERIFICATION_TOKEN, "expiresInMs": 900000}}, 201)
            return
        self._json({"error": "not-found"}, 404)


def test_trustcaptcha_pow_fixture() -> None:
    challenge = parse_trustcaptcha_challenge(FIXTURE)
    solution = solve_trustcaptcha_challenge(challenge, timeout_sec=5)

    assert solution is not None
    assert solution.tasks[0].nonce == "tcn3823"
    assert solution.tasks[0].hash_hex == "00048beb79fe106120f4105819b3417c44f509a22ee426ad2ad51b712a86f348"
    assert solution.tasks[0].attempts == 3824
    assert solution.tasks[1].nonce == "tcn287"
    assert solution.tasks[1].hash_hex == "0000714b9d3e2fc2f86290867965beb52dc292fbb351a2b10ade49a4f2cf876e"
    assert solution.tasks[1].attempts == 288
    assert solution.attempts == 4112
    assert count_leading_zero_bits(trustcaptcha_pow_hash_bytes(FIXTURE["tasks"][0]["input"], "tcn3823")) >= 12
    assert verify_trustcaptcha_solution(challenge, solution)
    assert not verify_trustcaptcha_task_solution(FIXTURE["tasks"][0], {"number": 1, "nonce": "tcn3822"}, 12)

    submit = build_trustcaptcha_submit_body(challenge, solution, min_solve_ms=900)
    assert submit["tasks"] == [{"number": 1, "nonce": "tcn3823"}, {"number": 2, "nonce": "tcn287"}]
    assert [field["index"] for field in submit["honeypotFields"]] == [0, 1, 2]
    assert submit["userEvents"][0]["type"] == "mousemove"


def test_trustcaptcha_create_body_integrity() -> None:
    body = build_trustcaptcha_create_body(site_key=SITE_KEY, target_url="https://example.test/form")

    assert body["siteKey"] == SITE_KEY
    assert body["metadata"] == {"framework": "other", "libraryVersion": "3.0.1"}
    assert body["browserInformation"]["window-origin"] == "https://example.test"
    assert body["browserInformation"]["window-navigator-webdriver"] is False
    assert body["fingerprints"]["canvas"]
    assert body["integrityHash"] == calculate_trustcaptcha_integrity_hash(body["browserInformation"])


def test_trustcaptcha_solver_protocol_flow_local_server() -> None:
    _TrustcaptchaHandler.create_calls = []
    _TrustcaptchaHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TrustcaptchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            TrustcaptchaSolver().solve(
                site_key=SITE_KEY,
                api_url=base_url,
                target_url="https://example.test/form",
                submit=True,
                timeout_sec=5,
                min_solve_ms=900,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "trustcaptcha"
    assert ret.captcha_type == "fingerprint_multi_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == VERIFICATION_TOKEN
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["verification_id"] == FIXTURE["verificationId"]
    assert ret.diagnostics["difficulty"] == 12
    assert ret.diagnostics["nonces"] == ["tcn3823", "tcn287"]
    assert _TrustcaptchaHandler.create_calls[0]["siteKey"] == SITE_KEY
    assert _TrustcaptchaHandler.submit_calls[0]["tasks"] == [
        {"number": 1, "nonce": "tcn3823"},
        {"number": 2, "nonce": "tcn287"},
    ]


def _valid_iso(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True
