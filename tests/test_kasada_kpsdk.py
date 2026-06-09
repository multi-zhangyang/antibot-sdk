from __future__ import annotations

import asyncio
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from antibot_sdk.cli import amain
from antibot_sdk.providers.kasada_kpsdk import (
    CAPTCHA_TYPE,
    CAPABILITY,
    PROVIDER,
    KasadaKpsdkSolver,
    extract_kasada_sdk_urls,
    extract_kpsdk_headers,
    parse_kpsdk_done_messages,
    run_kasada_kpsdk_vm,
)

SCRIPT_FIXTURE = r"""
window.KPSDK = {
  version: "j-1.0.0",
  configured: null,
  ready: false,
  configure(c) {
    this.configured = c;
    this.ready = true;
    return true;
  },
  isReady() {
    return this.ready === true;
  }
};
window.addEventListener("message", function (ev) {
  window.__fixtureLastMessage = ev.data;
});
window.postMessage("KPSDK:DONE:fixture-ct", location.origin);
const nativeFetch = window.fetch;
window.fetch = function (url, opts = {}) {
  opts.headers = {
    ...(opts.headers || {}),
    "x-kpsdk-ct": "ct-fixture",
    "x-kpsdk-cd": "cd-fixture",
    "x-kpsdk-v": "j-1.0.0"
  };
  return nativeFetch(url, opts);
};
window.dispatchEvent(new Event("kpsdk-ready"));
"""

HEADERS_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const nativeFetch = window.fetch;
window.fetch = function (url, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set("X-KPSDK-CT", "ct-headers");
  headers.set("x-kpsdk-cd", "cd-headers");
  return nativeFetch(url, { ...opts, headers });
};
window.postMessage("KPSDK:DONE:headers", location.origin);
"""

REQUEST_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const nativeFetch = window.fetch;
window.fetch = function (url, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set("x-kpsdk-ct", "ct-request");
  headers.set("x-kpsdk-cd", "cd-request");
  const req = new Request(url, { ...opts, method: opts.method || "POST", headers, body: "body-fixture" });
  return nativeFetch(req);
};
window.postMessage("KPSDK:DONE:request", location.origin);
"""

XHR_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const nativeOpen = window.XMLHttpRequest.prototype.open;
const nativeSend = window.XMLHttpRequest.prototype.send;
window.XMLHttpRequest.prototype.open = function (method, url) {
  this.__fixtureUrl = url;
  return nativeOpen.call(this, method, url);
};
window.XMLHttpRequest.prototype.send = function (body) {
  this.setRequestHeader("x-kpsdk-ct", "ct-xhr");
  this.setRequestHeader("x-kpsdk-cd", "cd-xhr");
  return nativeSend.call(this, body);
};
window.postMessage("KPSDK:DONE:xhr", location.origin);
"""


pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node executable is required")


def test_kasada_vm_runner_captures_headers_and_done_message() -> None:
    data = run_kasada_kpsdk_vm(
        SCRIPT_FIXTURE,
        script_url="https://target.example/kpsdk/p.js",
        page_url="https://target.example/login",
        request_url="https://target.example/api/protected",
        request_method="POST",
        request_headers={"X-Input": "ok"},
        config={"site": "fixture"},
        profile={"language": "en-US"},
        timeout_sec=5,
    )
    diagnostics = data["diagnostics"]
    assert diagnostics["kpsdkPresent"] is True
    assert diagnostics["kpsdkReady"] is True
    assert diagnostics["messageCount"] >= 1
    assert diagnostics["fetchCount"] == 1
    assert parse_kpsdk_done_messages(data["messages"])[0]["ct"] == "fixture-ct"
    assert extract_kpsdk_headers(data) == {
        "x-kpsdk-cd": "cd-fixture",
        "x-kpsdk-ct": "ct-fixture",
        "x-kpsdk-v": "j-1.0.0",
    }
    assert data["request"]["last"]["url"] == "https://target.example/api/protected"
    assert data["request"]["last"]["method"] == "POST"


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        (HEADERS_FIXTURE, {"x-kpsdk-cd": "cd-headers", "x-kpsdk-ct": "ct-headers"}),
        (REQUEST_FIXTURE, {"x-kpsdk-cd": "cd-request", "x-kpsdk-ct": "ct-request"}),
    ],
)
def test_kasada_vm_runner_supports_headers_and_request_objects(script: str, expected: dict[str, str]) -> None:
    data = run_kasada_kpsdk_vm(
        script,
        page_url="https://target.example/",
        request_url="https://target.example/api",
        request_method="POST",
        request_headers={"Accept": "application/json"},
        timeout_sec=5,
    )
    assert extract_kpsdk_headers(data) == expected
    assert data["request"]["last"]["url"] == "https://target.example/api"
    assert data["request"]["last"]["method"] == "POST"


def test_kasada_vm_runner_can_trigger_xhr_transport() -> None:
    data = run_kasada_kpsdk_vm(
        XHR_FIXTURE,
        page_url="https://target.example/",
        request_url="https://target.example/api",
        request_method="POST",
        request_transport="xhr",
        request_headers={"Accept": "application/json"},
        timeout_sec=5,
    )
    assert data["request"]["transport"] == "xhr"
    assert extract_kpsdk_headers(data) == {"x-kpsdk-cd": "cd-xhr", "x-kpsdk-ct": "ct-xhr"}
    assert data["request"]["last"]["url"] == "https://target.example/api"


def test_parse_done_and_extract_headers_fallback() -> None:
    messages = [
        {"data": "noise", "origin": "https://a"},
        {"data": "KPSDK:DONE:ct-one", "origin": "https://a", "at": 1},
        "KPSDK:DONE:ct-two",
    ]
    parsed = parse_kpsdk_done_messages(messages)
    assert [item["ct"] for item in parsed] == ["ct-one", "ct-two"]
    assert extract_kpsdk_headers({"fetches": [{"headers": {"X-KPSDK-CT": "ct", "Other": "no"}}]}) == {
        "x-kpsdk-ct": "ct"
    }


def test_extract_kasada_sdk_urls() -> None:
    html = """
    <script src="/149e/p.js"></script>
    <script src="https://static.example/kpsdk/ips.js"></script>
    <script src="/normal.js"></script>
    """
    assert extract_kasada_sdk_urls(html, "https://target.example/login") == [
        "https://target.example/149e/p.js",
        "https://static.example/kpsdk/ips.js",
    ]


def test_kasada_solver_schema_and_ticket() -> None:
    result = asyncio.run(
        KasadaKpsdkSolver().solve(
            script_js=SCRIPT_FIXTURE,
            page_url="https://target.example/",
            request_url="https://target.example/api/protected",
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.provider == PROVIDER
    assert result.captcha_type == CAPTCHA_TYPE
    assert result.capability == CAPABILITY
    assert result.verify_code == "headers"
    assert result.diagnostics["browser"] == "not_used"
    assert result.diagnostics["mode"] == "browserless_vm_primitive"
    assert result.diagnostics["header_keys"] == ["x-kpsdk-cd", "x-kpsdk-ct", "x-kpsdk-v"]
    assert json.loads(result.ticket or "{}")["headers"]["x-kpsdk-ct"] == "ct-fixture"


def test_kasada_solver_done_only_and_network_guard() -> None:
    done_only = 'window.KPSDK={isReady(){return true}}; window.postMessage("KPSDK:DONE:only", location.origin);'
    result = asyncio.run(KasadaKpsdkSolver().solve(script_js=done_only, timeout_sec=5))
    assert result.ok is True
    assert result.verify_code == "done"

    blocked = asyncio.run(
        KasadaKpsdkSolver().solve(script_url="http://127.0.0.1:9/p.js", allow_network=False)
    )
    assert blocked.ok is False
    assert "disabled" in " ".join(blocked.errors)


class _ScriptHandler(BaseHTTPRequestHandler):
    script = SCRIPT_FIXTURE

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/p.js":
            self.send_response(404)
            self.end_headers()
            return
        raw = self.script.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_kasada_solver_fetches_script_url_when_allowed() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ScriptHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/p.js"
        result = asyncio.run(
            KasadaKpsdkSolver().solve(
                script_url=url,
                allow_network=True,
                page_url="https://target.example/",
                request_url="https://target.example/api",
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert result.ok is True
    assert result.verify_code == "headers"
    assert result.raw["scriptResponse"]["status"] == 200


def test_kasada_cli_auto_explicit_provider_fetches_script_url(capsys) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ScriptHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/p.js"
        code = asyncio.run(
            amain(["auto", url, "--provider", "kasada_kpsdk", "--timeout", "5", "--raw"])
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert data["provider"] == "kasada_kpsdk"
    assert data["verify_code"] == "done"
    assert data["raw"]["scriptResponse"]["status"] == 200


def test_kasada_cli_solve_and_stress(tmp_path, capsys) -> None:
    fixture = tmp_path / "kasada_fixture.js"
    fixture.write_text(SCRIPT_FIXTURE, encoding="utf-8")
    solve_code = asyncio.run(
        amain(
            [
                "solve",
                "kasada_kpsdk",
                "--script-js",
                f"@{fixture}",
                "--page-url",
                "https://target.example/",
                "--request-url",
                "https://target.example/api",
                "--raw",
            ]
        )
    )
    solve_out = capsys.readouterr().out
    assert solve_code == 0
    assert json.loads(solve_out)["provider"] == "kasada_kpsdk"

    stress_code = asyncio.run(
        amain(
            [
                "stress",
                "kasada_kpsdk",
                "--script-js",
                f"@{fixture}",
                "--page-url",
                "https://target.example/",
                "--request-url",
                "https://target.example/api",
                "--runs",
                "2",
                "--concurrency",
                "2",
            ]
        )
    )
    stress_out = capsys.readouterr().out
    assert stress_code == 0
    summary = json.loads(stress_out)["summary"]
    assert summary["ok"] == 2
    assert summary["fail"] == 0
