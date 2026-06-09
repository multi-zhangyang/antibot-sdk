from __future__ import annotations

import asyncio
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from antibot_sdk.cli import amain
from antibot_sdk.providers.perimeterx import (
    CAPTCHA_TYPE,
    CAPABILITY,
    PROVIDER,
    PerimeterXSolver,
    extract_perimeterx_sdk_urls,
    extract_px_requests,
    parse_px_cookies,
    parse_px_response,
    run_perimeterx_px_vm,
)

PX_FIXTURE = r"""
window._pxAppId = "PXFIXTURE";
window._pxVid = "vid-fixture";
const payload = {
  appId: window._pxAppId,
  pxvid: window._pxVid,
  pxhd: "hd-fixture",
  events: [{t: "load", ts: Date.now()}],
  ua: navigator.userAgent
};
fetch("__PX_COLLECTOR__", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-px-authorization": "auth-fixture"
  },
  body: JSON.stringify(payload)
});
document.cookie = "_px3=fixture-px3; Path=/; SameSite=Lax";
document.cookie = "_pxvid=fixture-vid; Path=/; SameSite=Lax";
"""

XHR_FIXTURE = r"""
window._pxAppId = "PXFIXTURE";
const xhr = new XMLHttpRequest();
xhr.open("POST", "__PX_COLLECTOR__");
xhr.setRequestHeader("content-type", "application/x-www-form-urlencoded");
xhr.send("_px=1&pxvid=vid-fixture&appId=PXFIXTURE");
"""

BEACON_IMAGE_FIXTURE = r"""
navigator.sendBeacon("__PX_COLLECTOR__", "_px=1&pxvid=vid-fixture");
new Image().src = "__PX_COLLECTOR__?pxvid=vid-fixture&_px=1";
"""

DYNAMIC_SCRIPT_FIXTURE = r"""
window._pxAppId = "PXFIXTURE";
const s = document.createElement("script");
s.src = "__PX_COLLECTOR__?script=1&pxvid=vid-fixture";
s.onload = () => {
  fetch("__PX_COLLECTOR__", {
    method: "POST",
    body: new URLSearchParams({
      appId: window._pxAppId,
      pxvid: "vid-fixture",
      focus: String(document.hasFocus()),
      visibility: document.visibilityState
    })
  });
};
s.addEventListener("load", () => {
  navigator.sendBeacon(
    "__PX_COLLECTOR__",
    new Blob(["pxvid=vid-fixture&_px=blob-listener"], {type: "text/plain"})
  );
});
document.head.appendChild(s);
"""

RAF_ENV_FIXTURE = r"""
window._pxAppId = "PXFIXTURE";
const cancelled = requestAnimationFrame(() => {
  fetch("__PX_COLLECTOR__", {method: "POST", body: "cancelled=1&pxvid=vid-fixture"});
});
cancelAnimationFrame(cancelled);
const observer = new PerformanceObserver((list) => {
  window.__pxObserved = list.getEntries().length;
});
observer.observe({entryTypes: ["resource"]});
queueMicrotask(() => {
  const mq = matchMedia("(min-width: 800px) and (pointer: fine)");
  const style = getComputedStyle(document.documentElement);
  const entries = performance.getEntriesByType("navigation").length;
  requestAnimationFrame((ts) => {
    setImmediate(() => {
      fetch("__PX_COLLECTOR__", {
        method: "POST",
        body: JSON.stringify({
          appId: window._pxAppId,
          pxvid: "vid-fixture",
          raf: typeof ts === "number",
          mq: mq.matches,
          display: style.getPropertyValue("display"),
          entries,
          observed: window.__pxObserved || 0,
          effectiveType: navigator.connection.effectiveType
        })
      });
    });
  });
});
"""

SERIALIZED_BODY_FIXTURE = r"""
window._pxAppId = "PXFIXTURE";
const params = new URLSearchParams({appId: window._pxAppId, pxvid: "vid-fixture", via: "urlsearch"});
fetch("__PX_COLLECTOR__", {method: "POST", body: params});

const fd = new FormData();
fd.append("appId", window._pxAppId);
fd.append("pxvid", "vid-fixture");
fd.append("_px", "formdata");
navigator.sendBeacon("__PX_COLLECTOR__", fd);

const blob = new Blob(["appId=PXFIXTURE&pxvid=vid-fixture&_px=blob"], {type: "text/plain"});
const blobUrl = URL.createObjectURL(blob);
const worker = new Worker(blobUrl);
worker.postMessage({pxvid: "vid-fixture"});
URL.revokeObjectURL(blobUrl);
const xhr = new XMLHttpRequest();
xhr.open("POST", "__PX_COLLECTOR__");
xhr.send(blob);

navigator.permissions.query({name: "notifications"}).then((permission) => {
  return navigator.mediaDevices.enumerateDevices().then(() => {
    fetch("__PX_COLLECTOR__", {
      method: "POST",
      body: new URLSearchParams({pxvid: "vid-fixture", permission: permission.state})
    });
  });
});
"""

COOKIE_ONLY_FIXTURE = r"""
document.cookie = "_px2=fixture-px2; Path=/";
"""

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node executable is required")


def test_perimeterx_vm_captures_fetch_request_and_cookies() -> None:
    data = run_perimeterx_px_vm(
        PX_FIXTURE,
        script_url="https://client.px-cloud.net/PXFIXTURE/main.min.js",
        page_url="https://target.example/login",
        collector_url="https://collector.example/api/v2/collector",
        config={"px_app_id": "PXFIXTURE"},
        timeout_sec=5,
    )
    assert data["diagnostics"]["hasPxCookie"] is True
    assert data["cookies"]["_px3"] == "fixture-px3"
    assert data["cookies"]["_pxvid"] == "fixture-vid"
    requests = extract_px_requests(data, collector_hint="https://collector.example/api/v2/collector")
    assert len(requests) == 1
    assert requests[0]["kind"] == "fetch"
    assert requests[0]["method"] == "POST"
    assert requests[0]["url"] == "https://collector.example/api/v2/collector"
    assert "PXFIXTURE" in requests[0]["body"]


@pytest.mark.parametrize(
    ("script", "expected_kind"),
    [(XHR_FIXTURE, "xhr"), (BEACON_IMAGE_FIXTURE, "beacon")],
)
def test_perimeterx_vm_captures_xhr_beacon_and_image(script: str, expected_kind: str) -> None:
    data = run_perimeterx_px_vm(
        script,
        page_url="https://target.example/",
        collector_url="https://collector.example/api/v2/collector",
        timeout_sec=5,
    )
    requests = extract_px_requests(data, collector_hint="https://collector.example/api/v2/collector")
    assert requests
    assert requests[0]["kind"] == expected_kind
    if expected_kind == "beacon":
        assert {item["kind"] for item in requests} >= {"beacon", "image"}


def test_perimeterx_vm_dynamic_script_callback_and_blob_beacon() -> None:
    data = run_perimeterx_px_vm(
        DYNAMIC_SCRIPT_FIXTURE,
        page_url="https://target.example/",
        collector_url="https://collector.example/api/v2/collector",
        settle_ms=150,
        timeout_sec=5,
    )
    assert data["errors"] == []
    requests = extract_px_requests(data, collector_hint="https://collector.example/api/v2/collector")
    assert [item["kind"] for item in requests][:1] == ["script"]
    assert {item["kind"] for item in requests} == {"script", "fetch", "beacon"}
    assert requests[0]["url"] == "https://collector.example/api/v2/collector?script=1&pxvid=vid-fixture"
    bodies = {item["kind"]: item["body"] for item in requests}
    assert "focus=true" in bodies["fetch"]
    assert "visibility=visible" in bodies["fetch"]
    assert bodies["beacon"] == "pxvid=vid-fixture&_px=blob-listener"


def test_perimeterx_vm_raf_matchmedia_performance_and_connection() -> None:
    data = run_perimeterx_px_vm(
        RAF_ENV_FIXTURE,
        page_url="https://target.example/",
        collector_url="https://collector.example/api/v2/collector",
        settle_ms=200,
        timeout_sec=5,
    )
    assert data["errors"] == []
    requests = extract_px_requests(data, collector_hint="https://collector.example/api/v2/collector")
    assert len(requests) == 1
    assert "cancelled=1" not in requests[0]["body"]
    body = json.loads(requests[0]["body"])
    assert body["raf"] is True
    assert body["mq"] is True
    assert body["display"] == "block"
    assert body["entries"] >= 1
    assert body["effectiveType"] == "4g"


def test_perimeterx_vm_serializes_urlsearchparams_formdata_blob_and_worker_stub() -> None:
    data = run_perimeterx_px_vm(
        SERIALIZED_BODY_FIXTURE,
        page_url="https://target.example/",
        collector_url="https://collector.example/api/v2/collector",
        settle_ms=200,
        timeout_sec=5,
    )
    assert data["errors"] == []
    assert [item["kind"] for item in data["requests"]] == ["fetch", "beacon", "worker", "xhr", "fetch"]
    assert data["requests"][2]["url"].startswith("blob:https://target.example/")
    requests = extract_px_requests(data, collector_hint="https://collector.example/api/v2/collector")
    assert [item["kind"] for item in requests] == ["fetch", "beacon", "xhr", "fetch"]
    assert requests[0]["body"] == "appId=PXFIXTURE&pxvid=vid-fixture&via=urlsearch"
    assert requests[1]["body"] == "appId=PXFIXTURE&pxvid=vid-fixture&_px=formdata"
    assert requests[2]["body"] == "appId=PXFIXTURE&pxvid=vid-fixture&_px=blob"
    assert "permission=prompt" in requests[3]["body"]


def test_px_cookie_response_and_url_helpers() -> None:
    cookies = parse_px_cookies("_px3=abc123; Path=/; SameSite=Lax")
    assert cookies[0].name == "_px3"
    assert cookies[0].value == "abc123"
    parsed = parse_px_response(
        '{"_px3":"body-px3","redirectUrl":"https://px-captcha.example/block"}',
        headers={"set-cookie": "_pxvid=header-vid; Path=/"},
    )
    assert parsed["cookies"] == {"_pxvid": "header-vid", "_px3": "body-px3"}
    assert parsed["challenge_url"].startswith("https://px-captcha.example")
    html = '<script src="https://client.px-cloud.net/PXFIXTURE/main.min.js"></script><script>"/api/v2/collector"</script>'
    assert extract_perimeterx_sdk_urls(html, "https://target.example/") == [
        "https://client.px-cloud.net/PXFIXTURE/main.min.js",
        "https://target.example/api/v2/collector",
    ]


def test_perimeterx_solver_schema_cookie() -> None:
    result = asyncio.run(
        PerimeterXSolver().solve(
            script_js=PX_FIXTURE,
            page_url="https://target.example/",
            collector_url="https://collector.example/api/v2/collector",
            config={"px_app_id": "PXFIXTURE"},
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.provider == PROVIDER
    assert result.captcha_type == CAPTCHA_TYPE
    assert result.capability == CAPABILITY
    assert result.verify_code == "cookie"
    assert result.diagnostics["browser"] == "not_used"
    assert result.diagnostics["px_request_count"] == 1
    assert json.loads(result.ticket or "{}")["cookies"]["_px3"] == "fixture-px3"


def test_perimeterx_solver_signals_only_and_network_guard() -> None:
    result = asyncio.run(
        PerimeterXSolver().solve(
            script_js=XHR_FIXTURE,
            page_url="https://target.example/",
            collector_url="https://collector.example/api/v2/collector",
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.verify_code == "signals"
    assert json.loads(result.ticket or "{}")["requests"][0]["kind"] == "xhr"

    blocked = asyncio.run(PerimeterXSolver().solve(script_url="http://127.0.0.1:9/px.js", allow_network=False))
    assert blocked.ok is False
    assert "disabled" in " ".join(blocked.errors)


class _PXHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/px.js":
            self.send_response(404)
            self.end_headers()
            return
        raw = PX_FIXTURE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        type(self).calls.append({"path": self.path, "headers": dict(self.headers), "body": raw.decode("utf-8")})
        body = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "_px3=mock-px3; Path=/; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_perimeterx_solver_fetches_script_and_submits_to_local_mock() -> None:
    _PXHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PXHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        result = asyncio.run(
            PerimeterXSolver().solve(
                script_url=f"{base}/px.js",
                allow_network=True,
                page_url="https://target.example/",
                collector_url=f"{base}/api/v2/collector",
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert result.ok is True
    assert result.verify_code == "submitted_cookie"
    assert json.loads(result.ticket or "{}")["cookies"]["_px3"] == "mock-px3"
    assert result.raw["scriptResponse"]["status"] == 200
    assert _PXHandler.calls and "PXFIXTURE" in _PXHandler.calls[0]["body"]


def test_perimeterx_cli_solve_and_stress(tmp_path, capsys) -> None:
    fixture = tmp_path / "px_fixture.js"
    fixture.write_text(COOKIE_ONLY_FIXTURE, encoding="utf-8")
    solve_code = asyncio.run(
        amain([
            "solve",
            "perimeterx",
            "--script-js",
            f"@{fixture}",
            "--page-url",
            "https://target.example/",
            "--raw",
        ])
    )
    solve_out = capsys.readouterr().out
    assert solve_code == 0
    assert json.loads(solve_out)["provider"] == "perimeterx"

    stress_code = asyncio.run(
        amain([
            "stress",
            "perimeterx",
            "--script-js",
            f"@{fixture}",
            "--page-url",
            "https://target.example/",
            "--runs",
            "2",
            "--concurrency",
            "2",
        ])
    )
    stress_out = capsys.readouterr().out
    assert stress_code == 0
    summary = json.loads(stress_out)["summary"]
    assert summary["ok"] == 2
    assert summary["fail"] == 0
