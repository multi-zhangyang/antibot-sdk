from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.activehashcash import (
    ActiveHashcashSolver,
    activehashcash_hash_hex,
    activehashcash_hash_matches,
    build_activehashcash_submit_body,
    count_leading_zero_bits_hex,
    extract_activehashcash_from_html,
    parse_activehashcash_challenge,
    parse_activehashcash_stamp,
    solve_activehashcash_challenge,
    solve_activehashcash_counter,
    verify_activehashcash_solution,
)

RESOURCE = "active.example"
BITS = 12
DATE = "260609"
RAND = "ActiveHashcash01"
STAMP = "1:12:260609:active.example:sha256:ActiveHashcash01:15910"
HASH_HEX = "0003f3eef4a908a01734d7b45467c97eb1a3a57fff1306197638ba91e79ae1cd"


class _ActiveHashcashHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    submit_calls: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/session/new":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        options = json.dumps({"resource": RESOURCE, "bits": BITS, "date": DATE, "rand": RAND})
        html = (
            '<form action="/session" method="post">'
            f'<input type="hidden" name="hashcash" id="hashcash" data-hashcash=\'{options}\' value="">'
            "</form>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/session":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            payload = json.loads(raw.decode("utf-8") or "{}")
        else:
            payload = {k: v[-1] for k, v in parse_qs(raw.decode("utf-8")).items()}
        type(self).submit_calls.append(payload)
        if not verify_activehashcash_solution({"resource": RESOURCE, "bits": BITS, "date": DATE}, payload.get("hashcash", "")):
            self._json({"ok": False, "reason": "invalid_hashcash"}, 422)
            return
        self._json({"ok": True, "accepted": True})


def test_activehashcash_parse_and_verify_upstream_fixture() -> None:
    upstream = "1:8:260326:test:sha256:DijFBDmOOfmEMXjk:450"
    parsed = parse_activehashcash_stamp(upstream)

    assert parsed["version"] == "1"
    assert parsed["ext"] == "sha256"
    assert activehashcash_hash_hex(upstream) == "003ff378d8e7f6b4da9d9ff5bd434c94517c89299ae2ab0633c2432ec33ec5bd"
    assert verify_activehashcash_solution({"resource": "test", "bits": 8, "date": "260326"}, upstream)
    assert not verify_activehashcash_solution({"resource": "wrong", "bits": 8, "date": "260326"}, upstream)


def test_activehashcash_solve_fixture() -> None:
    challenge = parse_activehashcash_challenge({"resource": RESOURCE, "bits": BITS, "date": DATE, "rand": RAND})
    solution = solve_activehashcash_challenge(challenge, timeout_sec=5, max_attempts=100_000)

    assert solution is not None
    assert solution.stamp == STAMP
    assert solution.counter == "15910"
    assert solution.hash_hex == HASH_HEX
    assert solution.attempts == 15911
    assert count_leading_zero_bits_hex(HASH_HEX) >= BITS
    assert activehashcash_hash_matches(HASH_HEX, BITS)
    assert verify_activehashcash_solution(challenge, solution)
    assert not verify_activehashcash_solution(challenge, STAMP[:-1] + "9")
    assert build_activehashcash_submit_body(challenge, solution) == {"hashcash": STAMP}

    counter, digest, attempts = solve_activehashcash_counter(
        "1:12:260609:active.example:sha256:ActiveHashcash01",
        bits=BITS,
        max_attempts=100_000,
        deadline_epoch=None,
    )
    assert (counter, digest, attempts) == (15910, HASH_HEX, 15911)


def test_activehashcash_stamp_parser_accepts_colon_in_resource() -> None:
    challenge = parse_activehashcash_challenge(
        {"resource": "http://active.example:3000/login", "bits": 8, "date": DATE, "rand": RAND}
    )
    solution = solve_activehashcash_challenge(challenge, timeout_sec=5, max_attempts=10_000)

    assert solution is not None
    parsed = parse_activehashcash_stamp(solution.stamp)
    assert parsed["resource"] == "http://active.example:3000/login"
    assert verify_activehashcash_solution(challenge, solution)


def test_activehashcash_extracts_hidden_field_html() -> None:
    options = json.dumps({"resource": RESOURCE, "bits": BITS, "date": DATE, "rand": RAND})
    html = f'<input type="hidden" name="custom_hashcash" data-hashcash=\'{options}\' value="">'
    extracted = extract_activehashcash_from_html(html)
    challenge = parse_activehashcash_challenge(extracted)

    assert extracted["resource"] == RESOURCE
    assert extracted["bits"] == BITS
    assert extracted["responseField"] == "custom_hashcash"
    assert challenge.response_field == "custom_hashcash"


def test_activehashcash_solver_protocol_flow_local_server() -> None:
    _ActiveHashcashHandler.challenge_calls = 0
    _ActiveHashcashHandler.submit_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ActiveHashcashHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            ActiveHashcashSolver().solve(
                challenge_url=f"{base}/session/new",
                submit_url=f"{base}/session",
                submit=True,
                timeout_sec=5,
                max_attempts=100_000,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "activehashcash"
    assert ret.captcha_type == "rails_hashcash_sha256"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["counter"] == "15910"
    assert _ActiveHashcashHandler.challenge_calls == 1
    assert _ActiveHashcashHandler.submit_calls[0]["hashcash"] == STAMP
