from __future__ import annotations

import asyncio
import base64
import json

import pytest

from antibot_sdk.providers.vercel_botid import (
    IV_BYTES,
    SALT_BYTES,
    VercelBotIdSolver,
    build_botid_fingerprint,
    decrypt_botid_fingerprint,
    encrypt_botid_fingerprint,
    generate_x_is_human,
    generate_x_is_human_payload,
    parse_botid_script,
    solve_vercel_botid_script,
)

SCRIPT_FIXTURE = r"""
window.V_C = window.V_C || [];
(() => {
  var k = '', a = '';
  function W(G) {
    return a = (btoa("ignored-a"), "Zu8vAs" + "n" + "S", btoa("ignored-b"), "Zu8vAs" + "n" + "S"),
      !!G["navigator"]["webdriver"];
  }
  function t(G) {
    return k = (btoa("ignored-k"), "YuwH2m" + "B" + "s", btoa("ignored-k2"), "YuwH2m" + "B" + "s"), {
      "v": "Google Inc. (Intel)",
      "r": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
    };
  }
  function J() {
    let G = window;
    return {
      "p": false,
      "S": 1.1816022976617755,
      "w": t(G),
      "s": W(G),
      "h": false,
      "b": false,
      "d": false
    };
  }
  window["V_C"]["S"] = async (G, Z, x, X, F) => {
    let Y = J(), B = await D([k, a]["join"](""), Y);
    return {"b": G, "v": x, "e": X, "s": B, "d": Z, "vr": F};
  };
})();
(() => {
  let X = window.V_C.S;
  window.V_C.push(() => X(
    0,
    0,
    0.1735110684448337,
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.fixture.tag",
    "3"
  ));
})();
"""

EXPECTED_KEY = "YuwH2mBsZu8vAsnS"
EXPECTED_SEED = 1.1816022976617755
SALT = bytes(range(SALT_BYTES))
IV = bytes(range(32, 32 + IV_BYTES))


def test_parse_botid_script_fixture() -> None:
    context = parse_botid_script(SCRIPT_FIXTURE)

    assert context.key == EXPECTED_KEY
    assert context.key_left == "YuwH2mBs"
    assert context.key_right == "Zu8vAsnS"
    assert context.seed == EXPECTED_SEED
    assert context.arg1 == 0
    assert context.arg2 == 0
    assert context.rand == 0.1735110684448337
    assert context.signature == "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.fixture.tag"
    assert context.version == "3"
    assert context.tail_payload == {
        "b": 0,
        "v": 0.1735110684448337,
        "e": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.fixture.tag",
        "d": 0,
        "vr": "3",
    }


def test_fingerprint_payload_and_aes_gcm_roundtrip() -> None:
    context = parse_botid_script(SCRIPT_FIXTURE)
    fingerprint = build_botid_fingerprint(
        context,
        webgl={
            "v": "Google Inc. (Intel)",
            "r": "ANGLE (Intel, fixture GPU, D3D11)",
        },
    )

    assert fingerprint == {
        "p": False,
        "S": EXPECTED_SEED,
        "w": {"v": "Google Inc. (Intel)", "r": "ANGLE (Intel, fixture GPU, D3D11)"},
        "s": False,
        "h": False,
        "b": False,
        "d": False,
    }

    encrypted = encrypt_botid_fingerprint(context.key, fingerprint, salt=SALT, iv=IV)
    raw = base64.b64decode(encrypted)
    assert raw[:SALT_BYTES] == SALT
    assert raw[SALT_BYTES : SALT_BYTES + IV_BYTES] == IV
    assert decrypt_botid_fingerprint(context.key, encrypted) == fingerprint

    encrypted_again = encrypt_botid_fingerprint(context.key, fingerprint, salt=SALT, iv=IV)
    assert encrypted_again == encrypted
    with pytest.raises(ValueError):
        decrypt_botid_fingerprint("wrong-key", encrypted)


def test_generate_x_is_human_header_json_structure() -> None:
    context = parse_botid_script(SCRIPT_FIXTURE)
    header = generate_x_is_human(context, salt=SALT, iv=IV)
    payload = json.loads(header)

    assert list(payload) == ["b", "v", "e", "s", "d", "vr"]
    assert payload["b"] == 0
    assert payload["v"] == 0.1735110684448337
    assert payload["e"].startswith("eyJ")
    assert payload["d"] == 0
    assert payload["vr"] == "3"
    assert decrypt_botid_fingerprint(context.key, payload["s"]) == build_botid_fingerprint(context)

    payload2 = generate_x_is_human_payload(SCRIPT_FIXTURE, salt=SALT.hex(), iv=base64.b64encode(IV).decode())
    assert payload2 == payload


def test_solution_and_async_solver_are_local_only() -> None:
    solution = solve_vercel_botid_script(SCRIPT_FIXTURE, salt=SALT, iv=IV)
    assert solution.context.key == EXPECTED_KEY
    assert solution.payload["s"] == solution.encrypted_fingerprint
    assert decrypt_botid_fingerprint(solution.context.key, solution.encrypted_fingerprint) == solution.fingerprint

    result = asyncio.run(VercelBotIdSolver().solve(script_js=SCRIPT_FIXTURE, salt=SALT, iv=IV))
    assert result.ok is True
    assert result.provider == "vercel_botid"
    assert result.captcha_type == "x_is_human_aes_gcm_fingerprint"
    assert result.capability == "protocol_solver"
    assert result.verify_code == "solved"
    assert result.diagnostics["browser"] == "not_used"
    assert result.diagnostics["key_length"] == len(EXPECTED_KEY)
    assert json.loads(result.ticket or "{}")["s"] == solution.encrypted_fingerprint


def test_input_validation_and_network_stub() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_botid_script("")
    with pytest.raises(ValueError, match="5-argument"):
        parse_botid_script('window.V_C.push(() => X(0, 0, 0.1, "not-a-jwe", "3"));')
    with pytest.raises(ValueError, match="salt"):
        encrypt_botid_fingerprint(EXPECTED_KEY, {"S": 1}, salt=b"short", iv=IV)

    result = asyncio.run(VercelBotIdSolver().solve(script_url="http://127.0.0.1/unused.js"))
    assert result.ok is False
    assert "disabled by default" in result.errors[0]

    submit = asyncio.run(VercelBotIdSolver().solve(script_js=SCRIPT_FIXTURE, salt=SALT, iv=IV, submit=True))
    assert submit.ok is False
    assert submit.verify_code == "submit_stub"
    assert submit.ticket
