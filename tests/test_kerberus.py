from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.kerberus import (
    KerberusSolver,
    kerberus_score,
    kerberus_threshold,
    parse_kerberus_challenge,
    solve_kerberus_challenge,
    verify_kerberus_nonce,
    verify_kerberus_solution,
)

SMALL_CHALLENGE = {
    "id": "kerb-1",
    "salts": ["salt-a", "salt-b"],
    "difficultyFactor": 50,
}
SMALL_INPUT = "JRTFM"
SMALL_NONCES = ["1", "47"]
SMALL_SCORES_HEX = [
    "fc630919a76eac38c3bcbc348bddf36c",
    "febf422c7e51d6d13077e91576a15dbb",
]

# Copied from upstream Kerberus library/src/commonTest/kotlin/PowTest.kt, "Validate dart".
UPSTREAM_DART_CHALLENGE = {
    "id": "dart-fixture",
    "salts": [
        "9d876973-ebbe-44db-a33b-53944a7e0104",
        "9ea876a8-0300-497a-9876-69df00981f80",
        "c4284a65-89fa-40fd-bd03-1cf1d24f6bd0",
        "1a97960f-9dbe-4acc-bdf6-370bad8f3999",
        "e5a39e10-3f96-46cd-ba44-84629fbcf111",
        "bc5a1758-3164-4ed5-9da1-f9b1a8dd1d34",
        "b88a8fc0-75e9-4370-b0a2-902fb878a06c",
        "bf057ec2-5653-41eb-8b7c-5b7b42cdbc92",
        "ef973dfc-81f3-49d8-8594-edb89251d586",
        "ee61e4e8-989b-4f11-a8b0-fadd5b3d5d8a",
    ],
    "difficultyFactor": 50000,
}
UPSTREAM_DART_NONCES = [
    "59178",
    "126246",
    "17245",
    "37861",
    "113007",
    "37189",
    "17777",
    "22940",
    "147380",
    "1033",
]


def test_kerberus_threshold_and_upstream_validate_dart_fixture() -> None:
    assert kerberus_threshold(50_000) == int("fffeb074a771c970f7b9e060fe47991b", 16)
    challenge = parse_kerberus_challenge(UPSTREAM_DART_CHALLENGE, serialized_input="JRTFM")

    assert verify_kerberus_solution(challenge, {"id": challenge.id, "nonces": UPSTREAM_DART_NONCES})
    assert all(
        verify_kerberus_nonce(salt, "JRTFM", 50_000, nonce)
        for salt, nonce in zip(challenge.salts, UPSTREAM_DART_NONCES)
    )


def test_kerberus_solve_small_multi_salt_fixture() -> None:
    solution = solve_kerberus_challenge(
        SMALL_CHALLENGE,
        serialized_input=SMALL_INPUT,
        max_attempts_per_salt=1_000,
        timeout_sec=5,
    )

    assert solution is not None
    assert solution.nonces == SMALL_NONCES
    assert [f"{score:032x}" for score in solution.scores] == SMALL_SCORES_HEX
    assert solution.submit_body == {"id": "kerb-1", "nonces": SMALL_NONCES}
    assert verify_kerberus_solution(solution.challenge, solution)
    assert f"{kerberus_score('salt-a', SMALL_INPUT, 1):032x}" == SMALL_SCORES_HEX[0]


class _KerberusHandler(BaseHTTPRequestHandler):
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
        self._json({"challenge": SMALL_CHALLENGE, "serializedInput": SMALL_INPUT})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/validate":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        ok = verify_kerberus_solution(
            parse_kerberus_challenge(SMALL_CHALLENGE, serialized_input=payload.get("serializedInput", "")),
            payload.get("solution", {}),
        )
        self._json({"success": ok, "token": "kerberus-token"}, 200 if ok else 400)


def test_kerberus_solver_protocol_flow_local_server() -> None:
    _KerberusHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _KerberusHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            KerberusSolver().solve(
                challenge_url=f"{base}/challenge",
                validate_url=f"{base}/validate",
                submit=True,
                max_attempts_per_salt=1_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "kerberus"
    assert ret.captcha_type == "u128_score_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "kerberus-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonces"] == SMALL_NONCES
    assert _KerberusHandler.calls[0]["solution"] == {"id": "kerb-1", "nonces": SMALL_NONCES}
