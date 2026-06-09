from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from antibot_sdk.providers.awswaf import parse_awswaf_challenge_vm_result, run_awswaf_challenge_vm

RUNNER = Path("src/antibot_sdk/vendor/awswaf/challenge_vm_runner.mjs")
SHA_INPUT = "eyJjaGFsbGVuZ2VfdHlwZSI6Ikhhc2hjYXNoIiwicmVnaW9uIjoidXMtZWFzdC0xIn0="
MP_INPUT = "eyJjaGFsbGVuZ2VfdHlwZSI6Ikhhc2hjYXNoIiwicmVnaW9uIjoiZXUtd2VzdC0xIn0="
SHA_TYPE = "h7b0c470f" + "a" * 60
SCRYPT_TYPE = "h72f957df" + "b" * 60
MP_TYPE = "ha9faaffd" + "c" * 60

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node executable is required")


def run_awswaf_vm(script: str, **kwargs: Any) -> dict[str, Any]:
    return run_awswaf_challenge_vm(
        script,
        page_url=kwargs.pop("page_url", "https://target.example/login"),
        script_url=kwargs.pop(
            "script_url",
            "https://d8c14d4960ca.edge.sdk.awswaf.com/abc/challenge.js",
        ),
        settle_ms=kwargs.pop("settle_ms", 250),
        timeout_sec=kwargs.pop("timeout_sec", 5),
        **kwargs,
    )


def test_awswaf_challenge_vm_extracts_sha2_fetch_and_globals() -> None:
    script = f"""
    window.awsWafChallenge = {{
      challenge: {{input: "{SHA_INPUT}", hmac: "fixturehmac", region: "us-east-1"}},
      challenge_type: "{SHA_TYPE}",
      difficulty: parseInt("12"),
      memory: parseInt("16"),
      crypto: {{
        identifier: "AwsWafEncryptedSignals",
        signalVersion: "2.4.0",
        typeNames: {{"{SHA_TYPE}": "verify"}}
      }}
    }};
    crypto.subtle.digest("SHA-256", new TextEncoder().encode("fixture")).then((buf) => {{
      window.awsWafChallenge.digestFirstByte = new Uint8Array(buf)[0];
      return fetch("/verify", {{
        method: "POST",
        headers: {{"content-type": "application/json"}},
        body: JSON.stringify(window.awsWafChallenge)
      }});
    }}).then(() => postMessage({{kind: "awswaf-ready", cfg: window.awsWafChallenge}}, "*"));
    """
    data = run_awswaf_vm(script)

    assert data["errors"] == []
    assert data["requests"][0]["kind"] == "fetch"
    assert data["requests"][0]["method"] == "POST"
    assert data["requests"][0]["url"] == "https://target.example/verify"
    assert data["messages"][0]["data"]["kind"] == "awswaf-ready"
    extracted = data["extracted"]
    assert extracted["challenge"] == {
        "input": SHA_INPUT,
        "hmac": "fixturehmac",
        "region": "us-east-1",
    }
    assert extracted["challenge_type"] == SHA_TYPE
    assert extracted["difficulty"] == 12
    assert extracted["memory"] == 16
    assert extracted["endpoint_type"] == "verify"
    assert extracted["crypto"]["identifier"] == "AwsWafEncryptedSignals"
    assert extracted["crypto"]["signalVersion"] == "2.4.0"
    assert any(item["path"] == "global.awsWafChallenge" for item in data["globals"])
    parsed = parse_awswaf_challenge_vm_result(data)
    assert parsed.input == SHA_INPUT
    assert parsed.challenge_type == SHA_TYPE


def test_awswaf_challenge_vm_extracts_scrypt_xhr_query_payload() -> None:
    script = f"""
    window.awsWafScryptConfig = {{
      challenge: {{input: "fixture-input", hmac: "scrypt-hmac", region: "ap-southeast-1"}},
      challengeType: "{SCRYPT_TYPE}",
      difficulty: 8,
      memory: 16,
      signalIdentifier: "AwsWafEncryptedSignals"
    }};
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "https://d8c14d4960ca.edge.sdk.awswaf.com/abc/verify");
    xhr.setRequestHeader("content-type", "application/x-www-form-urlencoded");
    xhr.send(new URLSearchParams({{
      challenge: JSON.stringify(window.awsWafScryptConfig.challenge),
      challenge_type: window.awsWafScryptConfig.challengeType,
      difficulty: String(window.awsWafScryptConfig.difficulty),
      memory: String(window.awsWafScryptConfig.memory)
    }}));
    """
    data = run_awswaf_vm(script)

    assert data["errors"] == []
    assert data["requests"][0]["kind"] == "xhr"
    assert data["requests"][0]["headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert "challenge_type=h72f957df" in data["requests"][0]["body"]
    extracted = data["extracted"]
    assert extracted["challenge"]["input"] == "fixture-input"
    assert extracted["challenge"]["hmac"] == "scrypt-hmac"
    assert extracted["challenge"]["region"] == "ap-southeast-1"
    assert extracted["challenge_type"] == SCRYPT_TYPE
    assert extracted["difficulty"] == 8
    assert extracted["memory"] == 16
    assert extracted["endpoint_type"] == "verify"
    assert extracted["crypto"]["identifier"] == "AwsWafEncryptedSignals"


def test_awswaf_challenge_vm_extracts_mp_verify_beacon_and_postmessage() -> None:
    script = f"""
    window.awsWafMpConfig = {{
      challenge: {{input: "{MP_INPUT}", hmac: "mp-hmac", region: "eu-west-1"}},
      challengeType: "{MP_TYPE}",
      difficulty: 4,
      memory: 32,
      endpointType: "mp_verify",
      cryptoConfig: {{
        identifier: "AwsWafEncryptedSignals",
        signalVersion: "2.5.0",
        typeNames: {{"{MP_TYPE}": "mp_verify"}}
      }}
    }};
    navigator.sendBeacon("/mp_verify", JSON.stringify({{
      challenge: window.awsWafMpConfig.challenge,
      challenge_type: window.awsWafMpConfig.challengeType,
      endpoint_type: window.awsWafMpConfig.endpointType
    }}));
    window.parent.postMessage({{type: "awswaf:mp", config: window.awsWafMpConfig}}, "*");
    """
    data = run_awswaf_vm(script, page_url="https://target.example/protected")

    assert data["errors"] == []
    assert data["requests"][0]["kind"] == "beacon"
    assert data["requests"][0]["url"] == "https://target.example/mp_verify"
    assert data["messages"][0]["data"]["type"] == "awswaf:mp"
    extracted = data["extracted"]
    assert extracted["challenge"]["input"] == MP_INPUT
    assert extracted["challenge"]["hmac"] == "mp-hmac"
    assert extracted["challenge"]["region"] == "eu-west-1"
    assert extracted["challenge_type"] == MP_TYPE
    assert extracted["endpoint_type"] == "mp_verify"
    assert extracted["crypto"]["identifier"] == "AwsWafEncryptedSignals"
    assert extracted["crypto"]["signalVersion"] == "2.5.0"
    assert extracted["crypto"]["typeNames"][MP_TYPE] == "mp_verify"
    assert data["diagnostics"]["requestCount"] == 1
    assert data["diagnostics"]["messageCount"] >= 1


def test_awswaf_challenge_vm_dynamic_script_append_and_late_src() -> None:
    script = """
    const first = document.createElement("script");
    first.src = "/nested.js";
    document.head.append(first);
    const late = document.createElement("script");
    document.body.append(late);
    late.src = "/late.js";
    window.postMessage({
      type: "script-counts",
      scripts: document.scripts.length,
      tagScripts: document.getElementsByTagName("script").length
    }, "*");
    """
    data = run_awswaf_vm(
        script,
        resources={
            "https://target.example/nested.js": "fetch('/nested-hit', {method: 'POST', body: 'nested=1'});",
            "https://target.example/late.js": "fetch('/late-hit', {method: 'POST', body: 'late=1'});",
        },
        settle_ms=250,
    )

    assert data["errors"] == []
    by_url = {item["url"]: item for item in data["requests"]}
    assert by_url["https://target.example/nested.js"]["kind"] == "script"
    assert by_url["https://target.example/late.js"]["kind"] == "script"
    assert by_url["https://target.example/nested-hit"]["body"] == "nested=1"
    assert by_url["https://target.example/late-hit"]["body"] == "late=1"
    assert data["messages"][0]["data"] == {"type": "script-counts", "scripts": 3, "tagScripts": 3}


def test_awswaf_challenge_vm_parses_raw_query_json_and_sanitizes_endpoint_type() -> None:
    raw_body = (
        f'challenge={{"input":"{SHA_INPUT}","hmac":"raw-hmac","region":"us-east-1"}}'
        f"&challenge_type={SHA_TYPE}&difficulty=8&memory=16"
    )
    script = f"""
    window.awsWafTypeNameOnly = {{
      challenge: {{input: "{SHA_INPUT}", hmac: "type-hmac", region: "us-east-1"}},
      typeName: "{SHA_TYPE}",
      difficulty: 8,
      memory: 16
    }};
    fetch("/verify", {{
      method: "POST",
      headers: {{"content-type": "application/x-www-form-urlencoded"}},
      body: {raw_body!r}
    }});
    """
    data = run_awswaf_vm(script)

    assert data["errors"] == []
    extracted = data["extracted"]
    assert extracted["challenge"] == {
        "input": SHA_INPUT,
        "hmac": "type-hmac",
        "region": "us-east-1",
    }
    assert extracted["challenge_type"] == SHA_TYPE
    assert extracted["difficulty"] == 8
    assert extracted["memory"] == 16
    assert extracted["endpoint_type"] == "verify"
    assert extracted["endpoint_type"] in {"verify", "mp_verify"}


def test_awswaf_vm_runner_is_included_as_wheel_artifact() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "src/antibot_sdk/vendor/awswaf/**/*.mjs" in pyproject
