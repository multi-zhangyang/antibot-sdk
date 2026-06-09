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
