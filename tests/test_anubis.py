from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from antibot_sdk.providers.anubis import (
    ANUBIS_TEST_COOKIE,
    AnubisSolver,
    anubis_hash_hex,
    parse_anubis_challenge,
    parse_anubis_challenge_page,
    solve_anubis_challenge,
    verify_anubis_solution,
)


def test_anubis_known_go_fixture() -> None:
    solution = solve_anubis_challenge("hunter", difficulty=0, max_attempts=10)

    assert solution is not None
    assert solution.nonce == 0
    assert solution.response == "2652bdba8fb4d2ab39ef28d8534d7694c557a4ae146c1e9237bd8d950280500e"
    assert anubis_hash_hex("hunter", 0) == solution.response
    assert verify_anubis_solution("hunter", 0, 0, solution.response) is True


def test_anubis_json_and_html_parse() -> None:
    payload = {
        "rules": {"algorithm": "fast", "difficulty": 2},
        "challenge": {"id": "cid", "randomData": "abc", "method": "fast"},
    }
    ch = parse_anubis_challenge(payload, redir="/target")
    assert ch.random_data == "abc"
    assert ch.challenge_id == "cid"
    assert ch.difficulty == 2
    assert ch.redir == "/target"

    html = """
    <script id="anubis_challenge" type="application/json">{"rules":{"algorithm":"fast","difficulty":1},"challenge":{"id":"hcid","randomData":"def"}}</script>
    <script id="anubis_base_prefix" type="application/json">"/guard"</script>
    """
    parsed = parse_anubis_challenge_page(html)
    assert parsed.random_data == "def"
    assert parsed.challenge_id == "hcid"
    assert parsed.base_prefix == "/guard"


def test_anubis_difficulty_prefix_solution() -> None:
    solution = solve_anubis_challenge("anubis-test", difficulty=3, max_attempts=500_000, timeout_sec=5)

    assert solution is not None
    assert solution.response.startswith("000")
    assert verify_anubis_solution("anubis-test", 3, solution.nonce, solution.response)


class _AnubisHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    seq = 0
    spent: set[str] = set()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        parsed = urlparse(self.path)
        if parsed.path == "/.within.website/x/cmd/anubis/api/make-challenge":
            with self.lock:
                type(self).seq += 1
                cid = f"anubis-{type(self).seq}"
            random_data = f"random-{cid}"
            body = json.dumps(
                {
                    "rules": {"algorithm": "fast", "difficulty": 2},
                    "challenge": random_data,
                    "id": cid,
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"{ANUBIS_TEST_COOKIE}={cid}; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/.within.website/x/cmd/anubis/api/pass-challenge":
            qs = parse_qs(parsed.query)
            cid = (qs.get("id") or [""])[0]
            nonce = (qs.get("nonce") or [""])[0]
            response = (qs.get("response") or [""])[0]
            redir = (qs.get("redir") or ["/"])[0]
            cookie = self.headers.get("Cookie", "")
            ok = ANUBIS_TEST_COOKIE in cookie and cid and cid not in type(self).spent
            ok = ok and verify_anubis_solution(f"random-{cid}", 2, nonce, response)
            if ok:
                type(self).spent.add(cid)
                self.send_response(302)
                self.send_header("Location", redir)
                self.send_header("Set-Cookie", "techaro.lol-anubis=jwt-test-token; Path=/")
                self.end_headers()
            else:
                self.send_response(400)
                self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


def test_anubis_solver_local_make_and_pass_flow() -> None:
    _AnubisHandler.seq = 0
    _AnubisHandler.spent = set()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AnubisHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            AnubisSolver().solve(
                base_url=base,
                redir="/ok",
                submit=True,
                timeout_sec=5,
                max_attempts=500_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "anubis"
    assert ret.captcha_type == "proof_of_work"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "passed"
    assert ret.ticket == "jwt-test-token"
    assert ret.raw["passResponse"]["status"] == 302
