from __future__ import annotations

import asyncio
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.donatello import (
    DonatelloSolver,
    donatello_canvas_hashes,
    donatello_channel_metrics,
    extract_donatello_challenge_id,
    parse_donatello_challenge,
    parse_donatello_task,
    render_donatello_task,
    solve_donatello_challenge,
    verify_donatello_solution,
)

FIRST_TASK = "X:2:000000:FFFFFF;R:FF0000:4:4:2:2;L:00FF00:0:10:20:10:2"
SECOND_TASK = "R:FFFFFF:3:3:1:1;L:FF0000:5:0:5:20:2;C:00FF00:3:12:12"
CHALLENGE = {"id": "donatello-fixture", "first_task": FIRST_TASK, "second_task": SECOND_TASK}


def test_donatello_canvas_hash_fixture() -> None:
    shapes = parse_donatello_task(FIRST_TASK)
    assert [shape.kind for shape in shapes] == ["X", "R", "L"]

    hashes = donatello_canvas_hashes(FIRST_TASK)
    assert hashes.red == "690d80fd57791f4717168768cdc7bbfd634a1bddb711ff9aeb16d6fdf1f7933e"
    assert hashes.green == "d65ce6edb8f789e7a75abeca6346b740ff5e2577a247a9ede5416ea803bffc24"
    assert hashes.blue == "e05402b0a6375944cd69c587647ca1ada307d111f837e935c49be16909c5d560"
    assert hashes.alpha == "c323c96b39b5155a4788a606c6fc05571befd551e693af4ec6b7f369cc42a834"
    assert hashes.combined == "3c92c1f19799b1a31651a4b9315c62a61b7a998598559fedfa776d78990ae8fc"


def test_donatello_solution_and_metrics_fixture() -> None:
    challenge = parse_donatello_challenge(CHALLENGE)
    solution = solve_donatello_challenge(challenge)
    body = solution.verify_body

    assert body["id"] == "donatello-fixture"
    assert body["totalHash1"] == "3c92c1f19799b1a31651a4b9315c62a61b7a998598559fedfa776d78990ae8fc"
    assert re.fullmatch(r"[0-9a-f]{64}", body["totalHash2"])
    assert isinstance(json.loads(body["metrics2"]), list)
    assert len(json.loads(body["metrics2"])) == 15
    assert verify_donatello_solution(CHALLENGE, solution)

    alpha = render_donatello_task(SECOND_TASK)["a"]
    assert donatello_channel_metrics(alpha) == body["metrics2"]


def test_donatello_extract_challenge_id() -> None:
    assert extract_donatello_challenge_id('const challenge_id = "abc-123";') == "abc-123"
    assert extract_donatello_challenge_id("<div data-challenge-id='xyz'></div>") == "xyz"


class _DonatelloHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path})
        if self.path == "/":
            body = b'<script>const challenge_id = "donatello-fixture";</script>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/challenge?id=donatello-fixture":
            self._json(CHALLENGE)
            return
        self._json({"error": "not_found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append({"method": "POST", "path": self.path, "payload": payload})
        if self.path == "/challenge" and verify_donatello_solution(CHALLENGE, payload):
            self._json({"status": "ok", "noise_detected": False})
            return
        self._json({"error": "bad_solution"}, 400)


def test_donatello_protocol_flow_local_server() -> None:
    _DonatelloHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DonatelloHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(DonatelloSolver().solve(base_url=base, submit=True, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "donatello"
    assert ret.captcha_type == "canvas_fingerprint_challenge"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "verified"
    assert ret.randstr == "donatello-fixture"
    assert json.loads(ret.ticket or "{}")["status"] == "ok"
    assert _DonatelloHandler.calls[0] == {"method": "GET", "path": "/"}
    assert _DonatelloHandler.calls[1] == {"method": "GET", "path": "/challenge?id=donatello-fixture"}
    assert _DonatelloHandler.calls[2]["path"] == "/challenge"
