from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.akamai_bm import (
    AkamaiBmKeys,
    AkamaiBmSolver,
    akamai_decrypt_sensor,
    akamai_decrypt_string,
    akamai_encrypt_sensor,
    akamai_encrypt_string,
    build_minimal_sensor_profile,
    decode_minimal_sensor_json,
    encode_minimal_sensor_json,
    extract_bm_sz_keys,
    submit_akamai_bm_sensor,
)

BM_SZ = "A0F0D145~YAAQfixture~3~4~1700000000~3499107~3759692"
KEYS = AkamaiBmKeys(shuffle_key=3_499_107, cipher_key=3_759_692)
GO_ABCK_TOOLS_VECTOR = "m+Dh#OJ_`@iy$8*6.HFK7Y:^JqtIpvcrCn~Pk2LdTU$D+f1vc b5}u_s>/9"


class _AkamaiBmHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        body = json.loads(raw.decode("utf-8"))
        decoded = decode_minimal_sensor_json(body["sensor_data"])
        call = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "decoded": decoded,
        }
        type(self).calls.append(call)

        if (
            self.path != "/_bm/_data"
            or self.headers.get("Content-Type") != "application/json"
            or decoded.get("provider") != "akamai_bm"
            or decoded.get("page_url") != "https://target.example/protected?x=1"
            or decoded.get("events") != [{"type": "load", "t": 7}]
        ):
            self._write(b'{"ok":false}', 403, {"Content-Type": "application/json"})
            return

        self._write(
            b'{"ok":true}',
            200,
            {
                "Content-Type": "application/json",
                "Set-Cookie": "_abck=updated-fixture; Path=/; HttpOnly",
            },
        )


def test_extract_bm_sz_keys_from_value_and_cookie_header() -> None:
    assert extract_bm_sz_keys(BM_SZ) == KEYS
    assert extract_bm_sz_keys(f"sid=1; bm_sz={BM_SZ}; _abck=fixture") == KEYS
    assert extract_bm_sz_keys(f"bm_sz={BM_SZ}") == KEYS
    assert KEYS.as_tuple == (3_499_107, 3_759_692)
    assert KEYS.sensor_prefix_tuple == (3_759_692, 3_499_107)


def test_akamai_lcg_string_and_sensor_roundtrip() -> None:
    plaintext = "-100,ua=Mozilla/5.0,-105,1,2,-115,_abck=fixture,-80,fp-hash"

    encrypted_string = akamai_encrypt_string(plaintext, KEYS.cipher_key)
    assert encrypted_string != plaintext
    assert akamai_decrypt_string(encrypted_string, KEYS.cipher_key) == plaintext

    encrypted_sensor = akamai_encrypt_sensor(plaintext, KEYS)
    assert encrypted_sensor == GO_ABCK_TOOLS_VECTOR
    assert akamai_decrypt_sensor(encrypted_sensor, KEYS) == plaintext


def test_minimal_sensor_json_encode_decode_with_v3_prefix_and_wrapped_body() -> None:
    profile = build_minimal_sensor_profile(
        page_url="https://target.example/protected?x=1",
        user_agent="Mozilla/5.0 fixture",
        bm_sz=BM_SZ,
        abck="abck-fixture",
        now_ms=1_700_000_000_000,
        extra={"events": [{"type": "load", "t": 7}], "risk": 0},
    )

    sensor = encode_minimal_sensor_json(profile, KEYS)

    assert sensor.startswith("3;3759692;3499107;0;")
    assert decode_minimal_sensor_json(sensor) == profile
    assert decode_minimal_sensor_json({"sensor_data": sensor}) == profile
    assert decode_minimal_sensor_json(json.dumps({"sensor_data": sensor})) == profile

    unprefixed = encode_minimal_sensor_json(profile, KEYS, include_prefix=False)
    assert decode_minimal_sensor_json(unprefixed, keys=KEYS) == profile


def test_mock_submit_to_bm_data_receives_decodable_sensor() -> None:
    _AkamaiBmHandler.calls = []
    profile = build_minimal_sensor_profile(
        page_url="https://target.example/protected?x=1",
        user_agent="Mozilla/5.0 fixture",
        bm_sz=BM_SZ,
        abck="abck-fixture",
        now_ms=1_700_000_000_000,
        extra={"events": [{"type": "load", "t": 7}]},
    )
    sensor = encode_minimal_sensor_json(profile, KEYS)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = submit_akamai_bm_sensor(
            sensor,
            f"http://127.0.0.1:{server.server_port}/_bm/_data",
            cookies={"bm_sz": BM_SZ, "_abck": "abck-fixture"},
            headers={"User-Agent": "Mozilla/5.0 fixture"},
            timeout=5,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok
    assert result.provider == "akamai_bm"
    assert result.capability == "akamai_bm_experimental"
    assert result.verify_code == "200"
    assert result.ticket == "_abck=updated-fixture; Path=/; HttpOnly"
    assert result.raw["request_body"] == {"sensor_data": sensor}

    assert len(_AkamaiBmHandler.calls) == 1
    call = _AkamaiBmHandler.calls[0]
    assert call["body"] == {"sensor_data": sensor}
    assert call["decoded"] == profile
    assert "bm_sz=" in call["headers"]["Cookie"]


def test_akamai_bm_solver_builds_minimal_sensor_without_browser() -> None:
    result = asyncio.run(
        AkamaiBmSolver().solve(
            bm_sz=BM_SZ,
            abck="abck-fixture",
            page_url="https://target.example/protected?x=1",
            user_agent="Mozilla/5.0 fixture",
            profile={
                "provider": "akamai_bm",
                "mode": "experimental_minimal",
                "ts": 1_700_000_000_000,
                "page_url": "https://target.example/protected?x=1",
                "user_agent": "Mozilla/5.0 fixture",
                "bm_sz_present": True,
                "abck_present": True,
            },
        )
    )

    assert result.ok is True
    assert result.provider == "akamai_bm"
    assert result.captcha_type == "akamai_bm_sensor_experimental"
    assert result.capability == "akamai_bm_experimental"
    assert result.verify_code == "solved"
    assert result.diagnostics["browser"] == "not_used"
    assert result.diagnostics["shuffle_key"] == KEYS.shuffle_key
    assert result.diagnostics["cipher_key"] == KEYS.cipher_key
    assert result.ticket
    assert result.ticket.startswith("3;3759692;3499107;0;")
    assert decode_minimal_sensor_json(result.ticket) == result.raw["decoded"]
