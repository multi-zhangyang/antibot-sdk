from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.wargon2 import (
    DEFAULT_AES_KEY_B64,
    Wargon2Solver,
    decrypt_wargon2_fingerprint,
    default_wargon2_fingerprint,
    parse_wargon2_aes_key,
    parse_wargon2_challenge,
    solve_wargon2_challenge,
    solve_wargon2_nonce,
    synthesize_wargon2_fingerprint,
    validate_wargon2_fingerprint,
    verify_wargon2_solution,
    wargon2_fingerprint_errors,
    wargon2_hash_hex,
)

FIXTURE_SALT_RAW = b"1234567890abcdef"
FIXTURE_CHALLENGE = {
    "id": "fixture-wargon2-001",
    "salt": base64.b64encode(FIXTURE_SALT_RAW).decode("ascii"),
    "difficulty": 1,
    "memory": 1024,
    "threads": 1,
    "keyLen": 32,
    "target": "00",
    "createdAt": "2026-06-09T00:00:00Z",
    "expiresAt": "2026-06-09T00:05:00Z",
    "solved": False,
}
FIXTURE_NONCE = "344"
FIXTURE_HASH = "002fb511a500d6d56fd94e84cfdfc209b3ed68aac4c715d87b1eb4efb1f65af1"
FIXTURE_AES_NONCE = bytes.fromhex("000102030405060708090a0b")
FIXTURE_FINGERPRINT_TOKEN = (
    "AAECAwQFBgcICQoLvrQ8tlmU0/STeiwSIZfXW2gy4qcHEkzEGe0uguqZzskmRRivUMKeYqgPoCwp"
    "CcQq+hybWGetyWopZYc/jIN9N6uFc46drGtdT9zshG10hhDRBRQ4YIsDZy9VCOFcYx+iUns"
    "udb1iOEVQ7NeIG7R6XQqAljgz6PtuXiH+fCyr/qMr+2mfgidpji97lTOE9pOqLO6Vci0Qn"
    "M0kKA/yfErPfNqOi37gr7MHqCbmqa/Xnq3l9qBMP4HNeYPGxPVSK+CGPzVjMUJSCNMkHeu"
    "GQfFa0NRlOjNVNzCN/U2ywbqR+zKlIbWQslArZvapsICfdguU7zme22NWK18XQuzUu59"
    "WICoSah1UCfyOElnRyukG5k62+J0SFfoFG6QR7p26MDt+HmkSWwCy7bsq5jBVNW/7duq"
    "iQvUTTe/ARJ/0K8XhcDppeqS7bJLuMqMOVqeJHgbIhdvaUH+WYsCBItLE9hkk1/ZpW"
    "wy7xNB7Eli7F1LmfPucQwE1mAedRl+lMwmzpyA+czNcgSWznfN+nFFC2A6qQWuVvqc"
    "6Bfx8yDKQDAGgv/ziZLPszmTWL8vxOyjtC3PmzLx9mFqdr/BhaWSUqS41DRgGhMp5"
    "kB2xS85YUkQPNo1NKgUJgc8DKMQRE9vPTcnjv6LSflMQh4FFG4DenolfAOTEcI+MtH"
    "xx8KzNa9nSCKk="
)

def test_wargon2_argon2_prefix_fixture() -> None:
    challenge = parse_wargon2_challenge({"challenge": FIXTURE_CHALLENGE})

    assert challenge.id == "fixture-wargon2-001"
    assert challenge.salt_bytes == FIXTURE_SALT_RAW
    assert challenge.target_nibbles == 2
    assert wargon2_hash_hex(challenge, FIXTURE_NONCE) == FIXTURE_HASH
    assert verify_wargon2_solution(challenge, FIXTURE_NONCE, FIXTURE_HASH)
    assert not verify_wargon2_solution(challenge, "343", FIXTURE_HASH)

    nonce, digest, attempts = solve_wargon2_nonce(challenge, max_attempts=1_000, timeout_sec=10)

    assert nonce == FIXTURE_NONCE
    assert digest == FIXTURE_HASH
    assert attempts == 345

    solution = solve_wargon2_challenge(challenge, max_attempts=1_000, timeout_sec=10)
    assert solution.nonce == FIXTURE_NONCE
    assert solution.hash_hex == FIXTURE_HASH
    assert solution.verify_body == {
        "challengeId": "fixture-wargon2-001",
        "nonce": FIXTURE_NONCE,
        "hash": FIXTURE_HASH,
    }


def test_wargon2_fingerprint_aes_gcm_fixture_roundtrip() -> None:
    key = parse_wargon2_aes_key(DEFAULT_AES_KEY_B64)
    assert key.hex() == "3637e1938936acc439f74dec3d13ee3f1ce857219f83dc52733d9730c324be33"

    fingerprint = default_wargon2_fingerprint()
    token = synthesize_wargon2_fingerprint(
        fingerprint,
        aes_key=DEFAULT_AES_KEY_B64,
        nonce=FIXTURE_AES_NONCE,
    )

    assert token == FIXTURE_FINGERPRINT_TOKEN
    decoded = decrypt_wargon2_fingerprint(token, aes_key=DEFAULT_AES_KEY_B64)
    assert decoded == fingerprint
    validate_wargon2_fingerprint(decoded)
    assert wargon2_fingerprint_errors(decoded) == []


def test_wargon2_fingerprint_validation_rejects_bad_semantics() -> None:
    bad = default_wargon2_fingerprint(userAgent="curl/8", screenResolution="1x1")

    errors = wargon2_fingerprint_errors(bad)

    assert "userAgent length out of range" in errors
    assert "screenResolution format invalid" in errors


class _Wargon2Handler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path == "/api/v1/challenge":
            self._send({"challenge": FIXTURE_CHALLENGE})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if self.path == "/api/v1/verify":
            self.calls.append(body)
            fingerprint = decrypt_wargon2_fingerprint(body.get("fingerprint", ""))
            validate_wargon2_fingerprint(fingerprint)
            ok = body.get("challengeId") == FIXTURE_CHALLENGE["id"] and verify_wargon2_solution(
                FIXTURE_CHALLENGE,
                body.get("nonce", ""),
                body.get("hash", ""),
            )
            self._send(
                {"valid": ok, "message": "Captcha solved successfully" if ok else "Invalid solution"},
                status=200 if ok else 400,
            )
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


def test_wargon2_solver_protocol_flow_local_mock_server() -> None:
    _Wargon2Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Wargon2Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            Wargon2Solver().solve(
                base_url=base,
                submit=True,
                start=344,
                max_attempts=10,
                timeout_sec=10,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "wargon2"
    assert ret.captcha_type == "argon2id_prefix_pow_fingerprint"
    assert ret.capability == "protocol_solver"
    assert ret.randstr == "fixture-wargon2-001"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["nonce"] == FIXTURE_NONCE
    assert ret.diagnostics["hash"] == FIXTURE_HASH
    assert ret.diagnostics["attempts"] == 1

    posted = _Wargon2Handler.calls[0]
    assert posted["challengeId"] == FIXTURE_CHALLENGE["id"]
    assert posted["nonce"] == FIXTURE_NONCE
    assert posted["hash"] == FIXTURE_HASH
    assert decrypt_wargon2_fingerprint(posted["fingerprint"])["platform"] == "Linux x86_64"
