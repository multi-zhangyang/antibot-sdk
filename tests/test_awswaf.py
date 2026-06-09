from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from typing import Any, Iterator

from antibot_sdk.cli import amain
from antibot_sdk.providers.awswaf import (
    AWSWAF_TOKEN_COOKIE,
    AwsWafSolver,
    awswaf_challenge_base,
    awswaf_challenge_mode,
    awswaf_endpoint_type,
    awswaf_has_leading_zero_bits,
    awswaf_inner_challenge_type,
    awswaf_sha2_digest,
    awswaf_signals_checksum,
    awswaf_scrypt_digest,
    build_awswaf_mp_verify_payload,
    build_awswaf_signals,
    build_awswaf_verify_payload,
    decode_awswaf_signal,
    encode_awswaf_signals,
    extract_awswaf_script_url,
    parse_awswaf_challenge,
    parse_awswaf_challenge_js,
    parse_awswaf_crypto_config,
    solve_awswaf_challenge,
    solve_awswaf_network_bandwidth,
    solve_awswaf_scrypt_hashcash,
    solve_awswaf_sha2_hashcash,
    verify_awswaf_solution,
)

SHA_INPUT = "eyJjaGFsbGVuZ2VfdHlwZSI6Ikhhc2hjYXNoIiwicmVnaW9uIjoidXMtZWFzdC0xIn0="
NB_INPUT = "eyJjaGFsbGVuZ2VfdHlwZSI6Ik5ldHdvcmtCYW5kd2lkdGgiLCJyZWdpb24iOiJ1cy1lYXN0LTEifQ=="
CHECKSUM = "1a2b3c4d"
SHA_TYPE = "h7b0c470f" + "a" * 60
SCRYPT_TYPE = "h72f957df" + "b" * 60
MP_TYPE = "ha9faaffd" + "c" * 60


@contextmanager
def awswaf_mock_server(
    *,
    token: str | None = "mock-token",
    json_token_field: str | None = None,
    json_token: str | None = None,
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    captured: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length)
            captured.append(
                {
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body.decode("utf-8"),
                    "json": json.loads(body.decode("utf-8")),
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if token:
                self.send_header("Set-Cookie", f"{AWSWAF_TOKEN_COOKIE}={token}; Path=/; HttpOnly")
            self.end_headers()
            response = {"ok": True}
            if json_token_field:
                response[json_token_field] = json_token or "json-token"
            self.wfile.write(json.dumps(response).encode("utf-8"))

        def log_message(self, *_args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", captured
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_awswaf_sha2_and_scrypt_fixtures() -> None:
    nonce, digest_hex, attempts = solve_awswaf_sha2_hashcash(
        SHA_INPUT,
        CHECKSUM,
        12,
        max_attempts=10_000,
    )
    assert nonce == "2605"
    assert attempts == 2606
    assert digest_hex == "000fca3bdc7479ca10c629d87367e38314dd0d1a64b5be2e660352c45039c9b1"
    assert awswaf_sha2_digest(SHA_INPUT, CHECKSUM, nonce).hex() == digest_hex
    assert awswaf_has_leading_zero_bits(bytes.fromhex(digest_hex), 12)

    s_nonce, s_digest_hex, s_attempts = solve_awswaf_scrypt_hashcash(
        "fixture-input",
        "deadbeef",
        8,
        16,
        max_attempts=1_000,
    )
    assert s_nonce == "446"
    assert s_attempts == 447
    assert s_digest_hex == "00881c1f1cddbb0c5fc6cb0a6ca17cf2"
    assert awswaf_scrypt_digest("fixture-input", "deadbeef", s_nonce, 16).hex() == s_digest_hex
    assert awswaf_has_leading_zero_bits(bytes.fromhex(s_digest_hex), 8)


def test_awswaf_network_bandwidth_and_modes() -> None:
    assert awswaf_inner_challenge_type(NB_INPUT) == "NetworkBandwidth"
    assert len(solve_awswaf_network_bandwidth(1)) == 1368
    assert len(base64.b64decode(solve_awswaf_network_bandwidth(2))) == 10 * 0x400

    nb = parse_awswaf_challenge({"challenge": {"input": NB_INPUT}, "difficulty": 2})
    sha = parse_awswaf_challenge(
        {"challenge": {"input": SHA_INPUT}, "challenge_type": SHA_TYPE, "difficulty": 12}
    )
    scrypt = parse_awswaf_challenge(
        {"challenge": {"input": "fixture-input"}, "challenge_type": SCRYPT_TYPE, "difficulty": 4, "memory": 16}
    )
    assert awswaf_challenge_mode(nb) == "network_bandwidth"
    assert awswaf_challenge_mode(sha) == "sha2"
    assert awswaf_challenge_mode(scrypt) == "scrypt"
    assert awswaf_endpoint_type(SHA_TYPE) == "verify"
    assert awswaf_endpoint_type(SCRYPT_TYPE) == "verify"
    assert awswaf_endpoint_type("ha9faaffd" + "c" * 60) == "mp_verify"


def test_awswaf_signals_aes_gcm_checksum_roundtrip() -> None:
    crypto = parse_awswaf_crypto_config(
        {"key": "00" * 32, "identifier": "AwsWafEncryptedSignals", "signalVersion": "2.4.0"}
    )
    signals = {"b": 2, "a": 1}
    assert awswaf_signals_checksum(signals) == "cf41ce83"
    signal_array, checksum, encrypted = encode_awswaf_signals(
        signals,
        crypto,
        nonce=b"\x01" * 12,
    )
    assert checksum == "cf41ce83"
    assert encrypted == (
        "AQEBAQEBAQEBAQEB::c8ea52b18ae5ad9f615c391c8dfae709::"
        "1626f75b19ec40ce41cdc6e799154d459e07ce613d9b"
    )
    assert signal_array == [
        {"name": "AwsWafEncryptedSignals", "value": {"Present": encrypted}}
    ]
    decoded_checksum, decoded_signals = decode_awswaf_signal(encrypted, crypto.key)
    assert decoded_checksum == checksum
    assert decoded_signals == {"a": 1, "b": 2}

    browser_signals = build_awswaf_signals(signal_version="2.4.0", screen_w=1366, screen_h=768)
    assert browser_signals["navigator"]["webdriver"] is False
    assert browser_signals["screen"]["width"] == 1366


def test_awswaf_parse_js_html_urls_and_solve_challenge() -> None:
    inner = base64.b64decode(SHA_INPUT).decode("utf-8")
    assert json.loads(inner)["region"] == "us-east-1"
    js = f"""
    const a = parseInt('12') + parseInt('16');
    const challengeType = '{SHA_TYPE}';
    const input = '{SHA_INPUT}';
    obj['hmac']='fixturehmac'; obj['region']='us-east-1';
    """
    parsed = parse_awswaf_challenge_js(js)
    assert parsed.input == SHA_INPUT
    assert parsed.challenge_type == SHA_TYPE
    assert parsed.difficulty == 12
    assert parsed.memory == 16
    assert parsed.region == "us-east-1"

    solution = solve_awswaf_challenge(parsed, checksum=CHECKSUM, max_attempts=10_000)
    assert solution.solution == "2605"
    assert solution.mode == "sha2"
    assert verify_awswaf_solution(parsed, solution)

    html = """
    <script src="https://d8c14d4960ca.edge.sdk.awswaf.com/abc/challenge.js"></script>
    """
    url = extract_awswaf_script_url(html, page_url="https://target.example/")
    assert url == "https://d8c14d4960ca.edge.sdk.awswaf.com/abc/challenge.js"
    assert awswaf_challenge_base(url) == "https://d8c14d4960ca.edge.sdk.awswaf.com/abc"


def test_awswaf_solver_core_result() -> None:
    ret = asyncio.run(
        AwsWafSolver().solve(
            challenge_json={
                "challenge": {"input": SHA_INPUT, "hmac": "fixturehmac", "region": "us-east-1"},
                "challenge_type": SHA_TYPE,
                "difficulty": 12,
                "memory": 16,
            },
            checksum=CHECKSUM,
            max_attempts=10_000,
        )
    )
    assert ret.ok is True
    assert ret.provider == "awswaf"
    assert ret.captcha_type == "encrypted_telemetry_scrypt_sha2_network_pow"
    assert ret.verify_code == "solved"
    assert ret.diagnostics["mode"] == "sha2"
    assert ret.diagnostics["solution"] == "2605"
    payload = json.loads(ret.ticket or "{}")
    assert payload["solution"] == "2605"
    assert payload["challenge"]["region"] == "us-east-1"


def test_awswaf_verify_payload_builder_merges_encrypted_signals() -> None:
    crypto = parse_awswaf_crypto_config(
        {"key": "11" * 32, "identifier": "AwsWafEncryptedSignals", "signalVersion": "2.4.0"}
    )
    signal_array, checksum, encrypted = encode_awswaf_signals(
        {"version": "2.4.0", "fixture": True},
        crypto,
        nonce=b"\x02" * 12,
    )
    challenge = parse_awswaf_challenge(
        {"challenge": {"input": SHA_INPUT, "hmac": "fixturehmac", "region": "us-east-1"}, "challenge_type": SHA_TYPE, "difficulty": 8}
    )
    solution = solve_awswaf_challenge(challenge, checksum=checksum, max_attempts=10_000)

    payload = build_awswaf_verify_payload(solution, signals=signal_array)

    assert payload["challenge"] == {
        "input": SHA_INPUT,
        "hmac": "fixturehmac",
        "region": "us-east-1",
    }
    assert payload["solution"].isdigit()
    assert payload["checksum"] == checksum
    assert payload["client"] == "Browser"
    assert payload["signals"] == [{"name": "AwsWafEncryptedSignals", "value": {"Present": encrypted}}]
    decoded_checksum, decoded_signals = decode_awswaf_signal(
        payload["signals"][0]["value"]["Present"],
        crypto.key,
    )
    assert decoded_checksum == checksum
    assert decoded_signals["fixture"] is True


def test_awswaf_mp_verify_payload_builder_uses_same_solved_body_shape() -> None:
    crypto = parse_awswaf_crypto_config({"key": "22" * 32, "identifier": "AwsWafEncryptedSignals"})
    signal_array, checksum, _encrypted = encode_awswaf_signals(
        {"version": "2.4.0", "mp": True},
        crypto,
        nonce=b"\x03" * 12,
    )
    challenge = parse_awswaf_challenge(
        {"challenge": {"input": NB_INPUT, "hmac": "mphmac", "region": "us-east-1"}, "challenge_type": MP_TYPE, "difficulty": 1}
    )
    solution = solve_awswaf_challenge(challenge, checksum=checksum, max_attempts=10)

    payload = build_awswaf_mp_verify_payload(solution, signals={"array": signal_array})

    assert awswaf_endpoint_type(MP_TYPE) == "mp_verify"
    assert payload["challenge"]["input"] == NB_INPUT
    assert payload["solution"] == solve_awswaf_network_bandwidth(1)
    assert payload["checksum"] == checksum
    assert payload["signals"][0]["name"] == "AwsWafEncryptedSignals"


def test_awswaf_solver_mock_submit_verify_parses_token_cookie() -> None:
    with awswaf_mock_server(token="verify-token") as (base_url, captured):
        ret = asyncio.run(
            AwsWafSolver().solve(
                challenge_json={
                    "challenge": {"input": SHA_INPUT, "hmac": "fixturehmac", "region": "us-east-1"},
                    "challenge_type": SHA_TYPE,
                    "difficulty": 8,
                },
                crypto_json={"key": "33" * 32, "identifier": "AwsWafEncryptedSignals"},
                signals_json={"version": "2.4.0", "fixture": "verify"},
                submit=True,
                submit_url=f"{base_url}/verify",
                max_attempts=10_000,
            )
        )

    assert ret.ok is True
    assert ret.verify_code == "verified"
    assert ret.diagnostics["endpoint_type"] == "verify"
    assert ret.diagnostics["submitted"] is True
    assert ret.diagnostics["submit_token_received"] is True
    assert ret.raw["submitResponse"]["awsWafToken"] == "verify-token"
    ticket = json.loads(ret.ticket or "{}")
    assert ticket[AWSWAF_TOKEN_COOKIE] == "verify-token"
    assert len(captured) == 1
    assert captured[0]["path"] == "/verify"
    body = captured[0]["json"]
    assert body["client"] == "Browser"
    assert body["solution"].isdigit()
    assert body["signals"][0]["name"] == "AwsWafEncryptedSignals"
    decoded_checksum, decoded_signals = decode_awswaf_signal(
        body["signals"][0]["value"]["Present"],
        bytes.fromhex("33" * 32),
    )
    assert body["checksum"] == decoded_checksum
    assert decoded_signals["fixture"] == "verify"


def test_awswaf_solver_mock_submit_mp_verify_endpoint() -> None:
    with awswaf_mock_server(token="mp-token") as (base_url, captured):
        ret = asyncio.run(
            AwsWafSolver().solve(
                challenge_json={
                    "challenge": {"input": NB_INPUT, "hmac": "mphmac", "region": "us-east-1"},
                    "challenge_type": MP_TYPE,
                    "difficulty": 1,
                },
                crypto_json={"key": "44" * 32, "identifier": "AwsWafEncryptedSignals"},
                signals_json={"version": "2.4.0", "fixture": "mp"},
                submit=True,
                submit_url=f"{base_url}/mp_verify",
                max_attempts=10,
            )
        )

    assert ret.ok is True
    assert ret.verify_code == "verified"
    assert ret.diagnostics["endpoint_type"] == "mp_verify"
    assert ret.raw["submitResponse"]["awsWafToken"] == "mp-token"
    assert len(captured) == 1
    assert captured[0]["path"] == "/mp_verify"
    body = captured[0]["json"]
    assert body["solution"] == solve_awswaf_network_bandwidth(1)
    assert body["signals"][0]["name"] == "AwsWafEncryptedSignals"
    ticket = json.loads(ret.ticket or "{}")
    assert ticket[AWSWAF_TOKEN_COOKIE] == "mp-token"
    assert ticket["endpoint_type"] == "mp_verify"


def test_awswaf_solver_submit_parses_json_token_and_sets_origin_headers() -> None:
    with awswaf_mock_server(token=None, json_token_field="awsWafToken", json_token="json-token") as (
        base_url,
        captured,
    ):
        ret = asyncio.run(
            AwsWafSolver().solve(
                challenge_json={
                    "challenge": {"input": SHA_INPUT, "hmac": "fixturehmac", "region": "us-east-1"},
                    "challenge_type": SHA_TYPE,
                    "difficulty": 8,
                },
                submit=True,
                submit_url=f"{base_url}/verify",
                checksum=CHECKSUM,
                max_attempts=10_000,
            )
        )

    assert ret.ok is True
    assert ret.verify_code == "verified"
    ticket = json.loads(ret.ticket or "{}")
    assert ticket[AWSWAF_TOKEN_COOKIE] == "json-token"
    assert captured[0]["headers"]["Origin"] == base_url
    assert captured[0]["headers"]["Referer"] == base_url + "/"


def test_awswaf_cli_stress_mock_submit(capsys) -> None:
    challenge = {
        "challenge": {"input": SHA_INPUT, "hmac": "fixturehmac", "region": "us-east-1"},
        "challenge_type": SHA_TYPE,
        "difficulty": 8,
    }
    with awswaf_mock_server(token="stress-token") as (base_url, captured):
        code = asyncio.run(
            amain(
                [
                    "stress",
                    "awswaf",
                    "--challenge-json",
                    json.dumps(challenge),
                    "--checksum",
                    CHECKSUM,
                    "--submit",
                    "--submit-url",
                    f"{base_url}/verify",
                    "--max-attempts",
                    "10000",
                    "--runs",
                    "1",
                    "--concurrency",
                    "1",
                ]
            )
        )

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["summary"]["ok"] == 1
    assert out["summary"]["fail"] == 0
    assert len(captured) == 1
    assert captured[0]["path"] == "/verify"
