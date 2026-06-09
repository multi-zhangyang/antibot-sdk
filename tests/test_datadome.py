from __future__ import annotations

import asyncio
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from antibot_sdk.cli import amain
from antibot_sdk.providers.datadome import (
    CAPTCHA_TYPE,
    CAPABILITY,
    PROVIDER,
    DataDomeSolver,
    extract_datadome_requests,
    extract_datadome_sdk_urls,
    parse_datadome_cookie,
    parse_datadome_response,
    run_datadome_tag_vm,
)

TAG_FIXTURE = r"""
window.ddoptions = {
  endpoint: "__DATADOME_ENDPOINT__",
  ajaxListenerPath: true
};
const payload = {
  jsData: {
    ua: navigator.userAgent,
    screen: [screen.width, screen.height],
    t: Date.now()
  },
  ddjskey: "fixture-ddjskey",
  events: []
};
fetch(window.ddoptions.endpoint, {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "x-datadome-clientid": "fixture-client"
  },
  body: "payload=" + btoa(JSON.stringify(payload))
});
document.cookie = "datadome=fixture-cookie; Path=/; SameSite=Lax";
"""

XHR_FIXTURE = r"""
window.ddoptions = { endpoint: "__DATADOME_ENDPOINT__" };
const xhr = new XMLHttpRequest();
xhr.open("POST", window.ddoptions.endpoint);
xhr.setRequestHeader("content-type", "application/json");
xhr.send(JSON.stringify({ddjskey: "fixture", jsData: {ua: navigator.userAgent}}));
"""

BEACON_IMAGE_FIXTURE = r"""
navigator.sendBeacon("__DATADOME_ENDPOINT__", "beacon=1&ddjskey=fixture");
new Image().src = "__DATADOME_ENDPOINT__?img=1&ddjskey=fixture";
"""

DONE_ONLY_COOKIE_FIXTURE = r"""
document.cookie = "datadome=vm-cookie-only; Path=/";
"""

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node executable is required")


def test_datadome_tag_vm_captures_fetch_request_and_cookie() -> None:
    data = run_datadome_tag_vm(
        TAG_FIXTURE,
        script_url="https://js.datadome.co/tags.js",
        page_url="https://target.example/login",
        endpoint_url="https://api-js.datadome.co/js/",
        timeout_sec=5,
    )
    assert data["diagnostics"]["hasDatadomeCookie"] is True
    assert data["cookies"]["datadome"] == "fixture-cookie"
    requests = extract_datadome_requests(data, endpoint_hint="https://api-js.datadome.co/js/")
    assert len(requests) == 1
    assert requests[0]["kind"] == "fetch"
    assert requests[0]["method"] == "POST"
    assert requests[0]["url"] == "https://api-js.datadome.co/js/"
    assert "payload=" in requests[0]["body"]


@pytest.mark.parametrize(
    ("script", "expected_kind"),
    [
        (XHR_FIXTURE, "xhr"),
        (BEACON_IMAGE_FIXTURE, "beacon"),
    ],
)
def test_datadome_tag_vm_captures_xhr_beacon_and_image(script: str, expected_kind: str) -> None:
    data = run_datadome_tag_vm(
        script,
        page_url="https://target.example/",
        endpoint_url="https://api-js.datadome.co/js/",
        timeout_sec=5,
    )
    requests = extract_datadome_requests(data, endpoint_hint="https://api-js.datadome.co/js/")
    assert requests
    assert requests[0]["kind"] == expected_kind
    if expected_kind == "beacon":
        assert {item["kind"] for item in requests} >= {"beacon", "image"}


def test_datadome_cookie_response_and_url_helpers() -> None:
    assert parse_datadome_cookie("datadome=abc123; Path=/; SameSite=Lax").value == "abc123"
    parsed = parse_datadome_response(
        '{"cookie":"datadome=body-cookie; Path=/","captchaUrl":"https://geo.captcha-delivery.com/captcha/"}',
        headers={"x-dd-b": "fixture"},
    )
    assert parsed["cookie"] == "body-cookie"
    assert parsed["challenge_url"].startswith("https://geo.captcha-delivery.com")
    html = '<script src="https://js.datadome.co/tags.js"></script><script>"/js/"</script>'
    assert extract_datadome_sdk_urls(html, "https://target.example/") == [
        "https://js.datadome.co/tags.js",
        "https://target.example/js/",
    ]


def test_datadome_solver_schema_signals_and_cookie() -> None:
    result = asyncio.run(
        DataDomeSolver().solve(
            script_js=TAG_FIXTURE,
            page_url="https://target.example/",
            endpoint_url="https://api-js.datadome.co/js/",
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.provider == PROVIDER
    assert result.captcha_type == CAPTCHA_TYPE
    assert result.capability == CAPABILITY
    assert result.verify_code == "cookie"
    assert result.ticket == "fixture-cookie"
    assert result.diagnostics["browser"] == "not_used"
    assert result.diagnostics["datadome_request_count"] == 1


def test_datadome_solver_signals_only_and_network_guard() -> None:
    result = asyncio.run(
        DataDomeSolver().solve(
            script_js=XHR_FIXTURE,
            page_url="https://target.example/",
            endpoint_url="https://api-js.datadome.co/js/",
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.verify_code == "signals"
    assert json.loads(result.ticket or "{}")["requests"][0]["kind"] == "xhr"

    blocked = asyncio.run(DataDomeSolver().solve(script_url="http://127.0.0.1:9/tags.js", allow_network=False))
    assert blocked.ok is False
    assert "disabled" in " ".join(blocked.errors)


class _DataDomeHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/tags.js":
            self.send_response(404)
            self.end_headers()
            return
        raw = TAG_FIXTURE.encode("utf-8")
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
        self.send_header("Set-Cookie", "datadome=mock-cookie; Path=/; SameSite=Lax")
        self.send_header("x-set-cookie", "datadome=mock-cookie; Path=/; SameSite=Lax")
        self.send_header("x-dd-b", "fixture")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_datadome_solver_fetches_script_and_submits_to_local_mock() -> None:
    _DataDomeHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DataDomeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        result = asyncio.run(
            DataDomeSolver().solve(
                script_url=f"{base}/tags.js",
                allow_network=True,
                page_url="https://target.example/",
                endpoint_url=f"{base}/js/",
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
    assert result.ticket == "mock-cookie"
    assert result.raw["scriptResponse"]["status"] == 200
    assert _DataDomeHandler.calls and "payload=" in _DataDomeHandler.calls[0]["body"]


def test_datadome_cli_solve_and_stress(tmp_path, capsys) -> None:
    fixture = tmp_path / "datadome_fixture.js"
    fixture.write_text(DONE_ONLY_COOKIE_FIXTURE, encoding="utf-8")
    solve_code = asyncio.run(
        amain(
            [
                "solve",
                "datadome",
                "--script-js",
                f"@{fixture}",
                "--page-url",
                "https://target.example/",
                "--raw",
            ]
        )
    )
    solve_out = capsys.readouterr().out
    assert solve_code == 0
    assert json.loads(solve_out)["provider"] == "datadome"

    stress_code = asyncio.run(
        amain(
            [
                "stress",
                "datadome",
                "--script-js",
                f"@{fixture}",
                "--page-url",
                "https://target.example/",
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
