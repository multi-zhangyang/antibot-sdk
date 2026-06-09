from __future__ import annotations

import asyncio
import base64
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from antibot_sdk.providers.vercel_botid import (
    IV_BYTES,
    SALT_BYTES,
    VercelBotIdSolver,
    build_botid_fingerprint,
    decrypt_botid_fingerprint,
    encrypt_botid_fingerprint,
    generate_x_is_human,
    generate_x_is_human_raw_vm,
    generate_x_is_human_payload,
    parse_botid_script,
    solve_vercel_botid_raw_vm,
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

RAW_VM_SCRIPT_FIXTURE = r"""
window.V_C = window.V_C || [];
window.V_C.L = Date.now();
var k = "", a = "";
async function D(G, Z) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(G),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(Z))
  );
  return btoa(String.fromCharCode(...salt, ...iv, ...new Uint8Array(cipher)));
}
function t(G) {
  k = "YuwH2m" + "B" + "s";
  const canvas = G.document.createElement("canvas");
  const gl = canvas.getContext("webgl");
  const ext = gl.getExtension("WEBGL_debug_renderer_info");
  return {
    "v": gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
    "r": gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
  };
}
function W(G) {
  a = "Zu8vAs" + "n" + "S";
  return !!G.navigator.webdriver;
}
function J() {
  let G = window;
  return {
    "p": false,
    "S": 0.5908011488308877 * 2,
    "w": t(G),
    "s": W(G),
    "h": false,
    "b": false,
    "d": false
  };
}
window.V_C.S = async (G, Z, x, X, F) => {
  let Y = J(), B = await D([k, a].join(""), Y);
  return {"b": G, "v": x, "e": X, "s": B, "d": Z, "vr": F};
};
(() => {
  let X = window.V_C.S;
  window.V_C.push(() => X(
    0,
    0,
    0.40549597232944556 * 0.4278983770123972,
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.fixture.tag",
    "3"
  ));
})();
"""

EXPECTED_KEY = "YuwH2mBsZu8vAsnS"
EXPECTED_SEED = 1.1816022976617755
SALT = bytes(range(SALT_BYTES))
IV = bytes(range(32, 32 + IV_BYTES))


class _BotIdSubmitHandler(BaseHTTPRequestHandler):
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
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = raw.decode("utf-8", errors="replace")
        header = self.headers.get("X-Is-Human", "")
        errors = []
        payload: dict[str, Any] = {}
        fingerprint: dict[str, Any] = {}
        try:
            payload = json.loads(header)
            fingerprint = decrypt_botid_fingerprint(EXPECTED_KEY, payload["s"])
        except Exception as exc:  # pragma: no cover - surfaced in call record for assertions
            errors.append(str(exc))
        type(self).calls.append(
            {
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
                "payload": payload,
                "fingerprint": fingerprint,
                "errors": errors,
            }
        )
        if (
            self.path != "/api/contact/test?via=1"
            or self.headers.get("X-Path") != "/api/contact/test"
            or self.headers.get("X-Method") != "POST"
            or self.headers.get("X-Fixture") != "1"
            or body != {"message": "hello"}
            or errors
        ):
            self._write(b"not human", 403, {"Content-Type": "text/plain"})
            return
        self._write(b'{"accepted":true}', 200, {"Content-Type": "application/json"})


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

    assert fingerprint["S"] == pytest.approx(EXPECTED_SEED)
    assert fingerprint == {
        "p": False,
        "S": fingerprint["S"],
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


def test_submit_flow_posts_x_is_human_route_headers_to_local_mock() -> None:
    _BotIdSubmitHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BotIdSubmitHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        submit_url = f"http://127.0.0.1:{server.server_port}/api/contact/test?via=1"
        result = asyncio.run(
            VercelBotIdSolver().solve(
                script_js=SCRIPT_FIXTURE,
                salt=SALT,
                iv=IV,
                submit=True,
                submit_url=submit_url,
                x_path="/api/contact/test",
                x_method="POST",
                submit_json={"message": "hello"},
                success_contains="accepted",
                headers={"X-Fixture": "1"},
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert result.ok is True
    assert result.verify_code == "submitted"
    assert result.ticket
    assert result.diagnostics["submitted"] is True
    assert result.diagnostics["submit_status"] == 200
    assert result.diagnostics["submit_ok"] is True
    assert result.diagnostics["submit_reason"] == "accepted"
    assert result.raw["submitRequest"] == {
        "url": submit_url,
        "method": "POST",
        "xPath": "/api/contact/test",
        "xMethod": "POST",
        "bodyKind": "json",
        "headerPrefix": result.ticket[:48],
    }
    assert result.raw["submitResponse"]["bodyPrefix"] == '{"accepted":true}'

    assert len(_BotIdSubmitHandler.calls) == 1
    call = _BotIdSubmitHandler.calls[0]
    assert call["headers"]["X-Is-Human"] == result.ticket
    assert call["headers"]["X-Path"] == "/api/contact/test"
    assert call["headers"]["X-Method"] == "POST"
    assert call["headers"]["X-Fixture"] == "1"
    assert call["body"] == {"message": "hello"}
    assert call["errors"] == []
    assert call["payload"] == json.loads(result.ticket)
    assert call["fingerprint"] == build_botid_fingerprint(parse_botid_script(SCRIPT_FIXTURE))


@pytest.mark.skipif(not shutil.which("node"), reason="node executable is required for raw VM mode")
def test_raw_vm_solver_executes_obfuscated_style_c_js_without_browser() -> None:
    vm_data = solve_vercel_botid_raw_vm(
        RAW_VM_SCRIPT_FIXTURE,
        script_url="https://example.test/_vercel/botid/c.js?i=1&v=3&h=example.test",
        profile={
            "webgl": {
                "v": "Google Inc. (Intel)",
                "r": "ANGLE (Intel, fixture GPU, D3D11)",
            }
        },
        timeout_sec=5,
    )
    payload = vm_data["payload"]

    assert payload["b"] == 0
    assert payload["d"] == 0
    assert payload["vr"] == "3"
    assert payload["e"].startswith("eyJ")
    assert payload["v"] == pytest.approx(0.1735110684448337)

    fingerprint = decrypt_botid_fingerprint(EXPECTED_KEY, payload["s"])
    assert fingerprint == {
        "p": False,
        "S": EXPECTED_SEED,
        "w": {"v": "Google Inc. (Intel)", "r": "ANGLE (Intel, fixture GPU, D3D11)"},
        "s": False,
        "h": False,
        "b": False,
        "d": False,
    }

    header = generate_x_is_human_raw_vm(RAW_VM_SCRIPT_FIXTURE, timeout_sec=5)
    assert json.loads(header)["vr"] == "3"

    result = asyncio.run(
        VercelBotIdSolver().solve(
            script_js=RAW_VM_SCRIPT_FIXTURE,
            raw_vm=True,
            profile={"webgl": {"v": "Google Inc. (Intel)", "r": "ANGLE (Intel, fixture GPU, D3D11)"}},
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.verify_code == "solved"
    assert result.diagnostics["mode"] == "raw_vm"
    assert json.loads(result.ticket or "{}")["vr"] == "3"


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
    assert submit.verify_code == "missing_submit_url"
    assert submit.ticket
