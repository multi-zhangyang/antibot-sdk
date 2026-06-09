from __future__ import annotations

import asyncio
import base64
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from antibot_sdk.cli import amain
from antibot_sdk.providers.hcaptcha_hsw import (
    CAPTCHA_TYPE,
    CAPABILITY,
    PROVIDER,
    HCaptchaHswSolver,
    build_hcaptcha_req,
    extract_hcaptcha_hsw_urls,
    parse_hcaptcha_hsw_result,
    run_hcaptcha_hsw_vm,
)

HSW_FIXTURE = r"""
window.hsw = async function(req) {
  const payload = {
    sitekey: req.sitekey || '',
    host: req.host || '',
    rqdata: req.rqdata || '',
    ua: navigator.userAgent,
    motion: !!req.motionData
  };
  return btoa(JSON.stringify(payload));
};
"""

MODULE_FIXTURE = r"""
module.exports.hsw = function(req, suffix) {
  return { n: 'module-' + req.sitekey + '-' + suffix, reqKeys: Object.keys(req).sort() };
};
"""

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node executable is required")


def test_hcaptcha_hsw_vm_calls_window_hsw() -> None:
    req = build_hcaptcha_req(sitekey="site-fixture", host="target.example", rqdata="rq-fixture", motion_data={"st": 1})
    data = run_hcaptcha_hsw_vm(
        HSW_FIXTURE,
        req=req,
        page_url="https://target.example/form",
        timeout_sec=5,
    )
    assert data["functionName"] == "hsw"
    decoded = json.loads(base64.b64decode(data["valueString"]).decode("utf-8"))
    assert decoded["sitekey"] == "site-fixture"
    assert decoded["host"] == "target.example"
    assert decoded["rqdata"] == "rq-fixture"
    assert decoded["motion"] is True


def test_hcaptcha_hsw_vm_supports_module_exports_and_extra_args() -> None:
    data = run_hcaptcha_hsw_vm(
        MODULE_FIXTURE,
        req={"sitekey": "site-fixture"},
        function_name="module.exports.hsw",
        args=["suffix-fixture"],
        timeout_sec=5,
    )
    parsed = parse_hcaptcha_hsw_result(data)
    assert parsed["n"] == "module-site-fixture-suffix-fixture"
    assert parsed["raw"]["reqKeys"] == ["sitekey"]


def test_hcaptcha_hsw_url_and_req_helpers() -> None:
    html = '<script src="https://newassets.hcaptcha.com/captcha/v1/hsw.js"></script><script>"/checksiteconfig"</script>'
    assert extract_hcaptcha_hsw_urls(html, "https://target.example/") == [
        "https://newassets.hcaptcha.com/captcha/v1/hsw.js",
        "https://target.example/checksiteconfig",
    ]
    req = build_hcaptcha_req(sitekey="s", host="h", rqdata="r", extra={"v": "1"})
    assert req == {"v": "1", "sitekey": "s", "host": "h", "rqdata": "r"}


def test_hcaptcha_hsw_solver_schema() -> None:
    result = asyncio.run(
        HCaptchaHswSolver().solve(
            script_js=HSW_FIXTURE,
            sitekey="site-fixture",
            host="target.example",
            rqdata="rq-fixture",
            motion_json={"st": 1},
            page_url="https://target.example/form",
            timeout_sec=5,
        )
    )
    assert result.ok is True
    assert result.provider == PROVIDER
    assert result.captcha_type == CAPTCHA_TYPE
    assert result.capability == CAPABILITY
    assert result.verify_code == "n"
    assert result.diagnostics["browser"] == "not_used"
    decoded = json.loads(base64.b64decode(result.ticket or "").decode("utf-8"))
    assert decoded["sitekey"] == "site-fixture"


def test_hcaptcha_hsw_solver_network_guard_and_script_url() -> None:
    blocked = asyncio.run(HCaptchaHswSolver().solve(script_url="http://127.0.0.1:9/hsw.js", allow_network=False))
    assert blocked.ok is False
    assert "disabled" in " ".join(blocked.errors)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            raw = HSW_FIXTURE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/hsw.js"
        result = asyncio.run(
            HCaptchaHswSolver().solve(
                script_url=url,
                allow_network=True,
                req_json='{"sitekey":"net-site","host":"target.example"}',
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert result.ok is True
    assert result.raw["scriptResponse"]["status"] == 200
    decoded = json.loads(base64.b64decode(result.ticket or "").decode("utf-8"))
    assert decoded["sitekey"] == "net-site"


def test_hcaptcha_hsw_cli_solve_and_stress(tmp_path, capsys) -> None:
    fixture = tmp_path / "hsw_fixture.js"
    fixture.write_text(HSW_FIXTURE, encoding="utf-8")
    solve_code = asyncio.run(
        amain([
            "solve",
            "hcaptcha_hsw",
            "--script-js",
            f"@{fixture}",
            "--sitekey",
            "site-fixture",
            "--host",
            "target.example",
            "--raw",
        ])
    )
    solve_out = capsys.readouterr().out
    assert solve_code == 0
    assert json.loads(solve_out)["provider"] == "hcaptcha_hsw"

    stress_code = asyncio.run(
        amain([
            "stress",
            "hcaptcha_hsw",
            "--script-js",
            f"@{fixture}",
            "--sitekey",
            "site-fixture",
            "--host",
            "target.example",
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
