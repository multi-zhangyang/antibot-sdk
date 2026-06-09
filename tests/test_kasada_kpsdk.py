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

SHIM_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
new PerformanceObserver(function (list) {
  window.__observerCount = (window.__observerCount || 0) + list.getEntries().length;
}).observe({ entryTypes: ["resource"], buffered: true });
document.body.style.display = "block";
window.addEventListener("load", function () {
  throw new Error("safe-load");
});
queueMicrotask(function () {
  const ok = document.hasFocus()
    && document.visibilityState === "visible"
    && document.defaultView === window
    && !!document.documentElement
    && matchMedia("(min-width: 1000px)").matches
    && getComputedStyle(document.body).display === "block"
    && navigator.connection.effectiveType === "4g"
    && !!navigator.permissions
    && !!navigator.mediaDevices;
  fetch("https://target.example/kpsdk/micro", {
    method: "POST",
    body: new URLSearchParams({ ok: ok ? "1" : "0" })
  });
});
const cancelled = requestAnimationFrame(function () {
  window.__cancelledShouldNotRun = true;
});
cancelAnimationFrame(cancelled);
requestAnimationFrame(function () {
  const resourceCount = performance.getEntriesByType("resource").length;
  navigator.permissions.query({ name: "notifications" }).then(function () {});
  navigator.mediaDevices.enumerateDevices().then(function () {});
  navigator.sendBeacon(
    "https://target.example/kpsdk/beacon",
    new URLSearchParams({ resource: resourceCount >= 1 ? "1" : "0" })
  );
});
setImmediate(function () {
  throw new Error("safe-immediate");
});
window.postMessage("KPSDK:DONE:shim", location.origin);
"""

BODY_SERIALIZATION_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const fd = new FormData();
fd.append("field", "value");
fd.append("blob", new Blob(["blob-value"], { type: "text/plain" }), "blob.txt");
fetch("https://target.example/kpsdk/form", { method: "POST", body: fd });
fetch("https://target.example/kpsdk/blob", {
  method: "POST",
  body: new Blob(["plain-blob"], { type: "text/plain" })
});
fetch("https://target.example/kpsdk/bytes", {
  method: "POST",
  body: new Uint8Array([65, 66])
});
navigator.sendBeacon(
  "https://target.example/kpsdk/params",
  new URLSearchParams({ a: "1", b: "two" })
);
window.postMessage("KPSDK:DONE:body", location.origin);
"""

DYNAMIC_SCRIPT_WORKER_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const first = document.createElement("script");
first.addEventListener("load", function () {
  fetch("https://target.example/kpsdk/loaded", { method: "POST", body: "loaded=1" });
});
first.src = "https://target.example/kpsdk/child.js";
document.head.appendChild(first);

const late = document.createElement("script");
document.body.appendChild(late);
late.onload = function () {
  fetch("https://target.example/kpsdk/late", { method: "POST", body: "late=1" });
};
late.src = "https://target.example/kpsdk/late.js";

const workerUrl = URL.createObjectURL(
  new Blob(["self.onmessage=function(){}"], { type: "application/javascript" })
);
const worker = new Worker(workerUrl);
worker.postMessage("ping");
worker.terminate();
URL.revokeObjectURL(workerUrl);
window.postMessage("KPSDK:DONE:dynamic", location.origin);
"""

SCRIPT_ENUM_RESPONSE_SHAREDWORKER_FIXTURE = r"""
window.KPSDK = { isReady() { return true; } };
const script = document.createElement("script");
script.src = "https://target.example/kpsdk/enumerated.js";
document.head.appendChild(script);
const shared = new SharedWorker("https://target.example/kpsdk/shared-worker.js");
shared.port.start();
fetch("https://target.example/kpsdk/response").then(function (res) {
  fetch("https://target.example/kpsdk/probe", {
    method: "POST",
    body: JSON.stringify({
      scripts: document.scripts.length,
      tagScripts: document.getElementsByTagName("script").length,
      responseInstance: res instanceof Response,
      sharedPort: !!(shared.port && shared.port.postMessage && shared.port.start && shared.port.close)
    })
  });
});
window.postMessage("KPSDK:DONE:enum", location.origin);
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


def test_kasada_vm_runner_browser_api_shims_and_safe_callbacks() -> None:
    data = run_kasada_kpsdk_vm(
        SHIM_FIXTURE,
        page_url="https://target.example/login",
        script_url="https://target.example/kpsdk/p.js",
        profile={"innerWidth": 1440, "screen_width": 1440},
        settle_ms=120,
        timeout_sec=5,
    )
    bodies_by_url = {item["url"]: item["body"] for item in data["fetches"]}
    assert bodies_by_url["https://target.example/kpsdk/micro"] == "ok=1"
    assert bodies_by_url["https://target.example/kpsdk/beacon"] == "resource=1"
    assert parse_kpsdk_done_messages(data["messages"])[0]["ct"] == "shim"
    assert data["diagnostics"]["kpsdkReady"] is True
    assert data["diagnostics"]["errorCount"] >= 2
    assert {item["source"] for item in data["errors"]} >= {"window.load", "setImmediate"}


def test_kasada_vm_runner_serializes_modern_request_bodies() -> None:
    data = run_kasada_kpsdk_vm(
        BODY_SERIALIZATION_FIXTURE,
        page_url="https://target.example/",
        settle_ms=80,
        timeout_sec=5,
    )
    bodies_by_url = {item["url"]: item["body"] for item in data["fetches"]}
    assert bodies_by_url["https://target.example/kpsdk/form"] == "field=value&blob=blob-value"
    assert bodies_by_url["https://target.example/kpsdk/blob"] == "plain-blob"
    assert bodies_by_url["https://target.example/kpsdk/bytes"] == "AB"
    assert bodies_by_url["https://target.example/kpsdk/params"] == "a=1&b=two"
    assert parse_kpsdk_done_messages(data["messages"])[0]["ct"] == "body"


def test_kasada_vm_runner_dynamic_script_and_worker_stubs() -> None:
    data = run_kasada_kpsdk_vm(
        DYNAMIC_SCRIPT_WORKER_FIXTURE,
        page_url="https://target.example/",
        settle_ms=120,
        timeout_sec=5,
    )
    by_kind = {(item["kind"], item["url"]): item for item in data["fetches"]}
    assert ("script", "https://target.example/kpsdk/child.js") in by_kind
    assert ("script", "https://target.example/kpsdk/late.js") in by_kind
    assert ("worker", next(item["url"] for item in data["fetches"] if item["kind"] == "worker")) in by_kind
    assert by_kind[("fetch", "https://target.example/kpsdk/loaded")]["body"] == "loaded=1"
    assert by_kind[("fetch", "https://target.example/kpsdk/late")]["body"] == "late=1"
    assert parse_kpsdk_done_messages(data["messages"])[0]["ct"] == "dynamic"


def test_kasada_vm_runner_enumerates_scripts_response_and_sharedworker_port() -> None:
    data = run_kasada_kpsdk_vm(
        SCRIPT_ENUM_RESPONSE_SHAREDWORKER_FIXTURE,
        page_url="https://target.example/",
        settle_ms=120,
        timeout_sec=5,
    )
    bodies_by_url = {item["url"]: item["body"] for item in data["fetches"]}
    probe = json.loads(bodies_by_url["https://target.example/kpsdk/probe"])
    assert probe == {
        "scripts": 2,
        "tagScripts": 2,
        "responseInstance": True,
        "sharedPort": True,
    }
    assert ("worker", "https://target.example/kpsdk/shared-worker.js") in {
        (item["kind"], item["url"]) for item in data["fetches"]
    }
    assert parse_kpsdk_done_messages(data["messages"])[0]["ct"] == "enum"


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
