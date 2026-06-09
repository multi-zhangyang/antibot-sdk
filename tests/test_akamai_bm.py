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
    akamai_mn_hash_hex,
    akamai_mn_mod,
    build_minimal_sensor_profile,
    decode_minimal_sensor_json,
    encode_minimal_sensor_json,
    extract_bm_sz_keys,
    fetch_akamai_bm_get_params,
    parse_abck_mn_challenges,
    parse_akamai_bm_get_params,
    solve_abck_mn_challenge,
    submit_akamai_bm_sensor,
    verify_abck_mn_solution,
)

BM_SZ = "A0F0D145~YAAQfixture~3~4~1700000000~3499107~3759692"
ABCK = "89E9305CB44AD0606B67BE2A31F9367C~-1~YAAQfixture~-1~||1-jaHBmBrjqk-2-10-1000-2||~-1"
KEYS = AkamaiBmKeys(shuffle_key=3_499_107, cipher_key=3_759_692)
GO_ABCK_TOOLS_VECTOR = "m+Dh#OJ_`@iy$8*6.HFK7Y:^JqtIpvcrCn~Pk2LdTU$D+f1vc b5}u_s>/9"


class _AkamaiBmHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int, headers: dict[str, str | list[str]] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            if isinstance(value, list):
                for item in value:
                    self.send_header(key, item)
            else:
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
            or not str(decoded.get("page_url") or "").startswith(("http://127.0.0.1:", "https://target.example/"))
            or not (
                decoded.get("events") == [{"type": "load", "t": 7}]
                or decoded.get("get_params", {}).get("e") == "encrypted-state-fixture"
            )
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

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"path": self.path, "headers": dict(self.headers)})
        if self.path != "/_bm/get_params?type=sensor":
            self._write(b"not found", 404, {"Content-Type": "text/plain"})
            return
        body = json.dumps(
            {
                "k": f"{KEYS.shuffle_key}~{KEYS.cipher_key}",
                "t": "1700000000000~42",
                "e": "encrypted-state-fixture",
                "a": "JB~lB",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._write(
            body,
            200,
            {
                "Content-Type": "application/json",
                "Set-Cookie": [
                    "gp_cookie=1; Path=/; HttpOnly",
                    "bm_sz=refreshed-bm-sz; Path=/; HttpOnly",
                ],
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


def test_abck_mn_challenge_parse_solve_and_verify_fixture() -> None:
    challenges = parse_abck_mn_challenges(f"_abck={ABCK}; bm_sz={BM_SZ}")
    assert len(challenges) == 1
    challenge = challenges[0]
    assert challenge.active is True
    assert challenge.abck_id == "89E9305CB44AD0606B67BE2A31F9367C"
    assert challenge.psn == "jaHBmBrjqk"
    assert challenge.seed == 2
    assert challenge.delay_ms == 10
    assert challenge.timeout_ms == 1000
    assert challenge.challenge_type == 2

    solution = solve_abck_mn_challenge(
        challenge,
        start_ts_ms=1_700_000_000_000,
        rounds=4,
        max_attempts_per_round=1000,
    )

    assert solution.challenge == challenge
    assert len(solution.rounds) == 4
    assert solution.result.count(";") == 4
    assert solution.nonce_csv == ",".join(item.nonce for item in solution.rounds)
    assert verify_abck_mn_solution(solution)
    for item in solution.rounds:
        assert item.input_value.endswith(item.nonce)
        assert item.digest_hex == akamai_mn_hash_hex(item.input_value)
        assert akamai_mn_mod(item.digest_hex, item.divisor) == 0


def test_get_params_parse_fetch_and_profile_injection() -> None:
    params = parse_akamai_bm_get_params(
        {"k": f"{KEYS.shuffle_key}~{KEYS.cipher_key}", "t": "1700000000000~42", "e": "e-state", "a": "JB~lB"}
    )
    assert params.key_parts == [str(KEYS.shuffle_key), str(KEYS.cipher_key)]
    assert params.time_parts == ["1700000000000", "42"]
    assert params.action_parts == ["JB", "lB"]
    assert params.transform_keys == KEYS

    _AkamaiBmHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/_bm/get_params?type=sensor"
        fetched, raw = fetch_akamai_bm_get_params(url, headers={"User-Agent": "Mozilla/5.0 fixture"}, timeout=5)
        result = asyncio.run(
            AkamaiBmSolver().solve(
                page_url=f"http://127.0.0.1:{server.server_port}/protected",
                get_params_url="/_bm/get_params?type=sensor",
                user_agent="Mozilla/5.0 fixture",
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert fetched.transform_keys == KEYS
    assert raw["status"] == 200
    assert result.ok is True
    assert result.diagnostics["get_params"] is True
    assert result.diagnostics["keys_source"] == "get_params"
    assert result.ticket
    decoded = decode_minimal_sensor_json(result.ticket)
    assert decoded["get_params"]["k"] == f"{KEYS.shuffle_key}~{KEYS.cipher_key}"
    assert decoded["get_params"]["e"] == "encrypted-state-fixture"


def test_solver_full_get_params_to_bm_data_flow_derives_submit_url_and_reuses_session() -> None:
    _AkamaiBmHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    page_url = f"{base}/protected?x=1"
    try:
        result = asyncio.run(
            AkamaiBmSolver().solve(
                page_url=page_url,
                get_params_url="/_bm/get_params?type=sensor",
                submit=True,
                user_agent="Mozilla/5.0 fixture",
                profile={
                    "provider": "akamai_bm",
                    "mode": "experimental_minimal",
                    "ts": 1_700_000_000_000,
                    "page_url": page_url,
                    "events": [{"type": "load", "t": 7}],
                },
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok is True
    assert result.verify_code == "submitted"
    assert result.ticket == "_abck=updated-fixture; Path=/; HttpOnly"
    assert result.diagnostics["submit_url"] == f"{base}/_bm/_data"
    assert result.diagnostics["get_params"] is True
    assert result.diagnostics["keys_source"] == "get_params"

    assert [call["path"] for call in _AkamaiBmHandler.calls] == [
        "/_bm/get_params?type=sensor",
        "/_bm/_data",
    ]
    assert _AkamaiBmHandler.calls[0]["headers"].get("User-Agent") == "Mozilla/5.0 fixture"
    post_call = _AkamaiBmHandler.calls[1]
    assert post_call["headers"].get("User-Agent") == "Mozilla/5.0 fixture"
    assert "gp_cookie=1" in post_call["headers"].get("Cookie", "")
    assert "bm_sz=refreshed-bm-sz" in post_call["headers"].get("Cookie", "")
    assert post_call["decoded"]["get_params"]["e"] == "encrypted-state-fixture"
    assert post_call["decoded"]["page_url"] == page_url


def test_solver_get_params_set_cookie_overrides_initial_cookie_on_submit() -> None:
    _AkamaiBmHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    page_url = f"{base}/protected"
    try:
        result = asyncio.run(
            AkamaiBmSolver().solve(
                bm_sz=BM_SZ,
                page_url=page_url,
                get_params_url="/_bm/get_params?type=sensor",
                submit=True,
                profile={
                    "provider": "akamai_bm",
                    "mode": "experimental_minimal",
                    "ts": 1_700_000_000_000,
                    "page_url": page_url,
                    "events": [{"type": "load", "t": 7}],
                },
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok is True
    post_cookie = _AkamaiBmHandler.calls[1]["headers"].get("Cookie", "")
    assert "bm_sz=refreshed-bm-sz" in post_cookie
    assert BM_SZ not in post_cookie


def test_solver_derives_submit_url_from_absolute_get_params_url() -> None:
    _AkamaiBmHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    page_url = f"{base}/protected"
    try:
        result = asyncio.run(
            AkamaiBmSolver().solve(
                get_params_url=f"{base}/_bm/get_params?type=sensor",
                submit=True,
                profile={
                    "provider": "akamai_bm",
                    "mode": "experimental_minimal",
                    "ts": 1_700_000_000_000,
                    "page_url": page_url,
                    "events": [{"type": "load", "t": 7}],
                },
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok is True
    assert result.diagnostics["submit_url"] == f"{base}/_bm/_data"
    assert [call["path"] for call in _AkamaiBmHandler.calls] == [
        "/_bm/get_params?type=sensor",
        "/_bm/_data",
    ]


def test_solver_preserves_get_params_failure_response_preview() -> None:
    _AkamaiBmHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AkamaiBmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        result = asyncio.run(
            AkamaiBmSolver().solve(
                page_url=f"{base}/protected",
                get_params_url="/_bm/get_params?type=missing",
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok is False
    assert result.raw["getParamsResponse"]["status"] == 404
    assert result.raw["getParamsResponse"]["bodyPrefix"] == "not found"
    assert "HTTP 404" in result.errors[0]


def test_solver_submit_without_submit_url_requires_absolute_page_url() -> None:
    result = asyncio.run(
        AkamaiBmSolver().solve(
            bm_sz=BM_SZ,
            submit=True,
            profile={
                "provider": "akamai_bm",
                "mode": "experimental_minimal",
                "ts": 1_700_000_000_000,
            },
        )
    )

    assert result.ok is False
    assert result.verify_code == "missing_submit_url"
    assert result.ticket
    assert result.ticket.startswith("3;3759692;3499107;0;")
    assert "submit_url" in result.errors[0]


def test_solver_uses_user_agent_header_in_default_profile() -> None:
    result = asyncio.run(
        AkamaiBmSolver().solve(
            bm_sz=BM_SZ,
            page_url="https://target.example/protected?x=1",
            headers={"User-Agent": "Mozilla/5.0 header-fixture"},
        )
    )

    assert result.ok is True
    assert result.ticket
    decoded = decode_minimal_sensor_json(result.ticket)
    assert decoded["user_agent"] == "Mozilla/5.0 header-fixture"
    assert result.diagnostics["user_agent_present"] is True


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


def test_akamai_bm_solver_embeds_mn_result_into_minimal_sensor() -> None:
    result = asyncio.run(
        AkamaiBmSolver().solve(
            bm_sz=BM_SZ,
            abck=ABCK,
            page_url="https://target.example/protected?x=1",
            user_agent="Mozilla/5.0 fixture",
            solve_mn=True,
            mn_start_ts_ms=1_700_000_000_000,
            mn_rounds=4,
            mn_max_attempts_per_round=1000,
        )
    )

    assert result.ok is True
    assert result.verify_code == "solved"
    assert result.diagnostics["mn_solved"] is True
    assert result.diagnostics["mn_rounds"] == 4
    assert result.raw["mnSolution"]["result"]
    assert result.ticket
    decoded = decode_minimal_sensor_json(result.ticket)
    assert decoded["mn_r"] == result.raw["mnSolution"]["result"]
    assert decoded["mn_abck"] == "89E9305CB44AD0606B67BE2A31F9367C"
    assert decoded["mn_psn"] == "jaHBmBrjqk"
