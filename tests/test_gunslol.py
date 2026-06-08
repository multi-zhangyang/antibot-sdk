from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.gunslol import (
    GunsLolSolver,
    base64url_encode_unpadded,
    extract_gunslol_gs_sets,
    parse_gunslol_2xa,
    solve_gunslol_challenge,
    verify_gunslol_solution,
)

README_CHALLENGE = {
    "o09": "3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a",
    "_n": "auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2",
    "_org_ts": "1777135187",
    "_2xa": "oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA",
}
README_SEAL = "c88a698743d20cfdc8e57f9117d6bc4e8f6d9be865810ad0bcd5a6fd26a05419"
README_OO = "UQViMDk2NgEAAABD-WCuD2rtiQ"


def _fast_challenge() -> dict[str, str]:
    n = "0123456789abcdef0123456789abcdef"
    org_ts = "1777135187"
    seal = "f" + "0" * 63
    target = hashlib.sha256((seal + n + org_ts).encode("ascii")).hexdigest()
    blob = b"\xa1\x40\x01" + b"\x00" + b"\x00" + b"unitkey!" + (b"0" * 63) + (b"\x00" * 8)
    return {"o09": target, "_n": n, "_org_ts": org_ts, "_2xa": base64url_encode_unpadded(blob)}


def test_gunslol_readme_fixture_solve_and_verify() -> None:
    parsed = parse_gunslol_2xa(README_CHALLENGE)
    solution = solve_gunslol_challenge(README_CHALLENGE, timeout_sec=10, workers=1)

    assert parsed.dd == 5
    assert parsed.total_space == 16**5
    assert solution is not None
    assert solution.seal == README_SEAL
    assert solution.oo == README_OO
    assert solution.submit_body == {"seal": README_SEAL, "_oo": README_OO}
    assert verify_gunslol_solution(README_CHALLENGE, solution)


def test_gunslol_extract_gs_sets_from_html() -> None:
    html = f"""
    <html><script>
    window._gs_sets = {{
      "o09": "{README_CHALLENGE['o09']}",
      _n: '{README_CHALLENGE['_n']}',
      _org_ts: "{README_CHALLENGE['_org_ts']}",
      _2xa: "{README_CHALLENGE['_2xa']}"
    }};
    </script></html>
    """

    assert extract_gunslol_gs_sets(html) == README_CHALLENGE


def test_gunslol_fast_fixture_is_tiny_and_valid() -> None:
    challenge = _fast_challenge()
    solution = solve_gunslol_challenge(challenge, timeout_sec=2, workers=1)

    assert solution is not None
    assert solution.seal == "f" + "0" * 63
    assert solution.attempts == 16
    assert verify_gunslol_solution(challenge, solution)


class _GunsLolHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    challenge = _fast_challenge()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/page":
            self._json({"error": "not-found"}, 404)
            return
        c = self.challenge
        body = f"""
        <!doctype html><script>
        const _gs_sets = {{ o09: "{c['o09']}", _n: "{c['_n']}", _org_ts: "{c['_org_ts']}", _2xa: "{c['_2xa']}" }};
        </script>
        """.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/verify":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8"))
        self.calls.append(payload)
        ok = verify_gunslol_solution(self.challenge, payload)
        self._json({"ok": ok, "token": "gunslol-token"}, 200 if ok else 400)


def test_gunslol_solver_protocol_flow_local_server() -> None:
    _GunsLolHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GunsLolHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            GunsLolSolver().solve(
                page_url=f"{base}/page",
                verify_url=f"{base}/verify",
                submit=True,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "gunslol"
    assert ret.captcha_type == "seal_pow_blake3"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "gunslol-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["dd"] == 1
    assert _GunsLolHandler.calls[0]["seal"] == "f" + "0" * 63
    assert verify_gunslol_solution(_GunsLolHandler.challenge, _GunsLolHandler.calls[0])
