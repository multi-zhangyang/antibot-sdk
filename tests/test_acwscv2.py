from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from antibot_sdk.providers.acwscv2 import (
    COOKIE_NAME,
    DEFAULT_SHUFFLE,
    AcwScV2Solver,
    extract_acw_arg1,
    hex_xor,
    parse_acwscv2_challenge,
    parse_acwscv2_challenge_html,
    solve_acwscv2_cookie,
    solve_acwscv2_value,
    unbox,
    verify_acwscv2_solution,
)

ARG1 = "7530FD758E1B265BFB08716F1222A054B35EF7EF"
EXPECTED_UNBOXED = "55AFBB77E805F21612D1EB8567425070FF323FBE"
EXPECTED_COOKIE = "65afac17e880921014c4ead657413970d8b23ccb"
FALLBACK_ARG1 = "982DF33FB3F6DB5996EF34E3BE0DB1A47D53256F"
FALLBACK_COOKIE = "65b36ef53b6f9048bb2a67ac834de83db8add116"
DYNAMIC_CIPHER = "w4ERwrrDu8OHVMOewrXCj8KLHsKYJRcnLFQsw68sw6deBsOiw4Q4IsKfIMKLXRM1w713wpN6X8OZwpA="


DYNAMIC_HTML = f"""
<html><script>
var arg1='{ARG1}';
var _0x4818=['YQ==','Yg==','Yw==','ZA==','{DYNAMIC_CIPHER}'];
(function(_0x4c97f0,_0x1742fd){{while(--_0x1742fd){{_0x4c97f0['push'](_0x4c97f0['shift']());}}}}(_0x4818,0x6));
var _0x55f3=function(_0x4c97f0,_0x1742fd){{return _0x1742fd;}};
var l=function(){{
  var _0x5e8b26=_0x55f3('0x3', '\x4b\x33\x79\x21');
  String['prototype'][_0x55f3('0x14', 'dummy')]=function(){{
    var _0x4b082b=[0xf,0x23,0x1d,0x18,0x21,0x10,0x1,0x26,0xa,0x9,0x13,0x1f,0x28,0x1b,0x16,0x17,0x19,0xd,0x6,0xb,0x27,0x12,0x14,0x8,0xe,0x15,0x20,0x1a,0x2,0x1e,0x7,0x4,0x11,0x5,0x3,0x1c,0x22,0x25,0xc,0x24];
    return _0x4b082b;
  }};
  arg2=arg1[_0x55f3('0x19', 'dummy')]()[_0x55f3('0x1b', 'dummy')](_0x5e8b26);
}};
function setCookie(name,value){{document.cookie=name+'='+value;}}
function reload(x) {{setCookie("{COOKIE_NAME}", x);document.location.reload();}}
</script></html>
"""

FALLBACK_HTML = f"""
<html><script>
var arg1='{FALLBACK_ARG1}';
function setCookie(name,value){{document.cookie=name+'='+value;}}
function reload(x) {{setCookie("{COOKIE_NAME}", x);document.location.reload();}}
</script></html>
"""


def test_acwscv2_dynamic_parser_and_cookie_fixture() -> None:
    challenge = parse_acwscv2_challenge_html(DYNAMIC_HTML, page_url="https://target.example/protected")

    assert challenge.arg1 == ARG1
    assert challenge.page_url == "https://target.example/protected"
    assert challenge.array_name == "_0x4818"
    assert challenge.rotation == 6
    assert challenge.key_source == "dynamic"
    assert challenge.decoder_keys[3] == "K3y!"
    assert challenge.shuffle == DEFAULT_SHUFFLE
    assert challenge.xor_key == "3000176000856006061501533003690027800375"

    assert extract_acw_arg1(DYNAMIC_HTML) == ARG1
    assert unbox(ARG1, DEFAULT_SHUFFLE) == EXPECTED_UNBOXED
    assert hex_xor(EXPECTED_UNBOXED, challenge.xor_key) == EXPECTED_COOKIE

    solution = solve_acwscv2_cookie(challenge)
    assert solution.cookie_value == EXPECTED_COOKIE
    assert solution.cookie_header == f"{COOKIE_NAME}={EXPECTED_COOKIE}"
    assert solution.ticket_payload["cookie_value"] == EXPECTED_COOKIE
    assert solve_acwscv2_value(DYNAMIC_HTML) == EXPECTED_COOKIE
    assert verify_acwscv2_solution(DYNAMIC_HTML, solution)
    assert verify_acwscv2_solution(DYNAMIC_HTML, f"{COOKIE_NAME}={EXPECTED_COOKIE}; Path=/")
    assert not verify_acwscv2_solution(DYNAMIC_HTML, f"{COOKIE_NAME}={'0' * 40}; Path=/")


def test_acwscv2_static_fallback_for_minimal_challenge() -> None:
    challenge = parse_acwscv2_challenge_html(FALLBACK_HTML)
    assert challenge.arg1 == FALLBACK_ARG1
    assert challenge.key_source == "static"
    assert challenge.shuffle == DEFAULT_SHUFFLE
    assert solve_acwscv2_cookie(challenge).cookie_value == FALLBACK_COOKIE

    parsed = parse_acwscv2_challenge({"arg1": FALLBACK_ARG1})
    assert parsed.key_source == "provided"
    assert solve_acwscv2_value(parsed) == FALLBACK_COOKIE


class _AcwHandler(BaseHTTPRequestHandler):
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

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        parsed = urlsplit(self.path)
        if parsed.path != "/protected":
            self._write(b"not found", 404, {"Content-Type": "text/plain"})
            return
        cookie = self.headers.get("Cookie", "")
        if f"{COOKIE_NAME}={EXPECTED_COOKIE}" in cookie:
            self._write(b"upstream ok", 200, {"Content-Type": "text/plain"})
            return
        self._write(DYNAMIC_HTML.encode("utf-8"), 403, {"Content-Type": "text/html; charset=utf-8"})


def test_acwscv2_solver_local_retry_flow() -> None:
    _AcwHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AcwHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(AcwScV2Solver().solve(base_url=base_url, submit=True, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "acwscv2"
    assert ret.captcha_type == "aliyun_acw_sc_v2_js_cookie"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["arg1"] == ARG1
    assert ret.diagnostics["key_source"] == "dynamic"
    assert ret.diagnostics["cookie_value"] == EXPECTED_COOKIE
    assert ret.diagnostics["submit_status"] == 200
    assert ret.diagnostics["blocked_again"] is False

    ticket = json.loads(ret.ticket or "{}")
    assert ticket["cookie_header"] == f"{COOKIE_NAME}={EXPECTED_COOKIE}"

    assert _AcwHandler.calls[0]["method"] == "GET"
    assert _AcwHandler.calls[0]["path"] == "/protected"
    assert _AcwHandler.calls[1]["method"] == "GET"
    assert _AcwHandler.calls[1]["path"] == "/protected"
    assert f"{COOKIE_NAME}={EXPECTED_COOKIE}" in _AcwHandler.calls[1]["headers"].get("Cookie", "")
