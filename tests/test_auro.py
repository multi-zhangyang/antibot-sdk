from __future__ import annotations

import asyncio
import base64
import json
import threading
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.auro import (
    AuroSolver,
    auro_pow_hash_hex,
    decrypt_auro_mouse_data,
    encrypt_auro_mouse_data,
    generate_auro_mouse_data,
    solve_auro_pow_challenge,
    verify_auro_pow,
)

KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
IV_B64 = base64.b64encode(b"123456789012").decode("ascii")
PREFIX = "prefix-"
DIFFICULTY = 3
FIXTURE_NONCE = 822
FIXTURE_HASH = "000db5e4c4065ac7540a4c5ccc65613467f0fe1601501c21308322d8a737a449"


def test_auro_aes_gcm_mouse_roundtrip() -> None:
    mouse = generate_auro_mouse_data(num_points=4, base_time_ms=1_700_000_000_000, seed=7)
    encrypted = encrypt_auro_mouse_data(mouse, KEY_B64, iv_b64=IV_B64)

    assert encrypted.iv_b64 == IV_B64
    assert encrypted.encrypted_data_b64
    assert encrypted.plaintext_json == json.dumps(mouse, ensure_ascii=False, separators=(",", ":"))
    assert decrypt_auro_mouse_data(encrypted.encrypted_data_b64, KEY_B64, IV_B64) == encrypted.plaintext_json


def test_auro_pow_fixture() -> None:
    assert auro_pow_hash_hex(PREFIX, FIXTURE_NONCE) == FIXTURE_HASH
    assert verify_auro_pow(PREFIX, DIFFICULTY, FIXTURE_NONCE, FIXTURE_HASH)

    solution = solve_auro_pow_challenge(
        {"prefix": PREFIX, "difficulty": DIFFICULTY},
        max_attempts=10_000,
        timeout_sec=5,
    )

    assert solution is not None
    assert solution.nonce == FIXTURE_NONCE
    assert solution.hash_hex == FIXTURE_HASH
    assert solution.validate_body == {"prefix": PREFIX, "nonce": str(FIXTURE_NONCE)}


class _AuroHandler(BaseHTTPRequestHandler):
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
        if self.path != "/enckey":
            self._json({"error": "not-found"}, 404)
            return
        assert self.headers.get("x-client")
        self._json({"key": KEY_B64})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path == "/api/pow/setup":
            form = _read_multipart_form(self)
            encrypted_mouse = form["mouse"]
            iv = form["iv"]
            plaintext = decrypt_auro_mouse_data(str(encrypted_mouse), KEY_B64, str(iv))
            points = json.loads(plaintext)
            assert isinstance(points, list)
            assert len(points) == 8
            self.calls.append({"setup_points": len(points), "iv": iv})
            self._json({"prefix": PREFIX, "difficulty": DIFFICULTY})
            return

        if self.path == "/api/pow/validate":
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            payload = json.loads(raw.decode("utf-8"))
            ok = verify_auro_pow(PREFIX, DIFFICULTY, payload.get("nonce"))
            self.calls.append({"validate": payload, "ok": ok})
            self._json({"success": ok, "token": "auro-token"}, 200 if ok else 400)
            return

        self._json({"error": "not-found"}, 404)


def _read_multipart_form(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    raw = handler.rfile.read(int(handler.headers.get("Content-Length", "0") or "0"))
    msg = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {handler.headers.get('Content-Type', '')}\n\n".encode("utf-8") + raw
    )
    out: dict[str, str] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name:
            payload = part.get_payload(decode=True) or b""
            out[str(name)] = payload.decode(part.get_content_charset() or "utf-8")
    return out


def test_auro_solver_encrypted_setup_and_validate_local_server() -> None:
    _AuroHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuroHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            AuroSolver().solve(
                base_url=base,
                mouse_points=8,
                mouse_seed=123,
                max_attempts=10_000,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "auro"
    assert ret.captcha_type == "encrypted_behavior_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "auro-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonce"] == FIXTURE_NONCE
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert _AuroHandler.calls[0]["setup_points"] == 8
    assert _AuroHandler.calls[1]["validate"] == {"prefix": PREFIX, "nonce": str(FIXTURE_NONCE)}
