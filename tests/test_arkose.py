from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.arkose import (
    DEFAULT_USER_AGENT,
    ArkoseSolver,
    arkose_build_bda,
    arkose_build_public_key_request,
    arkose_decode_bda,
    arkose_decrypt,
    arkose_encrypt,
    arkose_time_key,
    arkose_x64hash128,
    parse_arkose_token,
    parse_arkose_token_response,
)

PKEY = "476068BF-9607-4799-B53D-966BE98E2B81"
NOW = 1_700_000_000
SALT = "abcdefgh"
TOKEN = (
    "token=arkose-session-token|r=session-fixture|pk="
    + PKEY
    + "|surl=http://127.0.0.1|at=40|sup=1"
)


class _ArkoseHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, data: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        body = {key: values[-1] for key, values in form.items()}
        decoded = arkose_decode_bda(body["bda"], user_agent=body["userbrowser"], now=NOW)
        call = {"path": self.path, "headers": dict(self.headers), "body": body, "decoded": decoded}
        type(self).calls.append(call)
        ok = (
            self.path == f"/fc/gt2/public_key/{PKEY}"
            and body.get("public_key") == PKEY
            and body.get("capi_version") == "1.5.5"
            and body.get("data[blob]") == "blob-fixture"
            and any(item.get("key") == "enhanced_fp" for item in decoded)
        )
        self._json(
            {
                "token": TOKEN.replace("http://127.0.0.1", f"http://127.0.0.1:{self.server.server_port}"),
                "challenge_url": "/fc/gc/",
                "mbio": False,
                "kbio": False,
                "tbio": False,
            },
            200 if ok else 403,
        )


def test_arkose_murmur_and_crypto_vectors() -> None:
    assert arkose_x64hash128("hello", 31) == "e4c67dbb6870107c1129fe575d609dfb"
    assert arkose_x64hash128("DNT:unknown, CFP:test", 38) == "fe06de66f5ae53d28dc313bf7f479a4c"
    assert arkose_time_key("ua-fixture", now=NOW) == "ua-fixture1699984800"
    encrypted = arkose_encrypt("hello", "key", salt=SALT)
    assert json.loads(encrypted) == {
        "ct": "UsOEBhLZrJwoqe56dnUpYQ==",
        "iv": "aed3aed076a9c6918042eff94594a256",
        "s": "6162636465666768",
    }
    assert arkose_decrypt(encrypted, "key") == "hello"


def test_arkose_bda_build_decode_and_request_shape() -> None:
    bda = arkose_build_bda(
        pkey=PKEY,
        user_agent=DEFAULT_USER_AGENT,
        surl="https://client-api.arkoselabs.com",
        site="https://target.example/login",
        now=NOW,
        salt=SALT,
    )
    decoded = arkose_decode_bda(bda, user_agent=DEFAULT_USER_AGENT, now=NOW)
    by_key = {item["key"]: item["value"] for item in decoded}
    assert by_key["api_type"] == "js"
    assert by_key["n"] == "MTcwMDAwMDAwMA=="
    assert by_key["f"]
    assert by_key["ife_hash"]
    enhanced = {item["key"]: item["value"] for item in by_key["enhanced_fp"]}
    assert enhanced["document__referrer"] == "https://target.example/login"
    assert enhanced["client_config__surl"] == "https://client-api.arkoselabs.com"

    request = arkose_build_public_key_request(
        pkey=PKEY,
        surl="https://client-api.arkoselabs.com",
        site="https://target.example/login",
        data={"blob": "blob-fixture"},
        now=NOW,
        salt=SALT,
    )
    assert request.url == f"https://client-api.arkoselabs.com/fc/gt2/public_key/{PKEY}"
    assert request.body["data[blob]"] == "blob-fixture"
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded; charset=UTF-8"


def test_arkose_token_parse_and_offline_solver() -> None:
    info = parse_arkose_token(TOKEN)
    assert info.token == "arkose-session-token"
    assert info.session_id == "session-fixture"
    assert info.public_key == PKEY
    assert info.suppressed is True
    response = parse_arkose_token_response({"token": TOKEN, "mbio": False})
    assert response.token_info is not None
    assert response.token_info.analytics_tier == "40"

    result = asyncio.run(
        ArkoseSolver().solve(
            pkey=PKEY,
            site="https://target.example/login",
            now=NOW,
            salt=SALT,
        )
    )
    assert result.ok is True
    assert result.verify_code == "bda_built"
    assert result.ticket
    assert arkose_decode_bda(result.ticket, user_agent=DEFAULT_USER_AGENT, now=NOW)


def test_arkose_public_key_submit_flow_local_server() -> None:
    _ArkoseHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ArkoseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        result = asyncio.run(
            ArkoseSolver().solve(
                pkey=PKEY,
                surl=base,
                site="https://target.example/login",
                data={"blob": "blob-fixture"},
                submit=True,
                now=NOW,
                salt=SALT,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert result.ok is True
    assert result.provider == "arkose"
    assert result.captcha_type == "arkose_funcaptcha_bda_token"
    assert result.capability == "arkose_bda_token"
    assert result.verify_code == "token"
    assert result.ticket and "arkose-session-token" in result.ticket
    assert result.diagnostics["token_present"] is True
    assert result.diagnostics["session_id"] == "session-fixture"
    assert result.diagnostics["suppressed"] is True
    assert len(_ArkoseHandler.calls) == 1
    assert _ArkoseHandler.calls[0]["body"]["data[blob]"] == "blob-fixture"
