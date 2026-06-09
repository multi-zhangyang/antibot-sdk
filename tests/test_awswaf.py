from __future__ import annotations

import asyncio
import base64
import json

from antibot_sdk.providers.awswaf import (
    AwsWafSolver,
    awswaf_challenge_base,
    awswaf_challenge_mode,
    awswaf_endpoint_type,
    awswaf_has_leading_zero_bits,
    awswaf_inner_challenge_type,
    awswaf_sha2_digest,
    awswaf_signals_checksum,
    awswaf_scrypt_digest,
    build_awswaf_signals,
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
