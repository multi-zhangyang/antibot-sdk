from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from antibot_sdk.providers.spow import (
    SpowSolver,
    build_spow_submit_body,
    count_leading_zero_bits_bytes,
    create_spow_challenge,
    extract_spow_from_html,
    parse_spow_challenge,
    sign_spow_challenge,
    solve_spow_challenge,
    solve_spow_counter,
    spow_hash_hex,
    spow_hash_matches,
    verify_spow_challenge_signature,
    verify_spow_solution,
)

SECRET = "MySecureTestSecret1337"
SALT = "Rhs5wflYb9mpiDQX"
EXPIRES = 4_102_444_800
DIFFICULTY = 16
SIGNATURE = "98s0pbxra8SGKIv4R4ijlASdcp5JDhUeJtBQyKv0Yc4"
CHALLENGE = f"1:{DIFFICULTY}:{EXPIRES}:{SALT}:{SIGNATURE}:"
COUNTER = "96113"
SOLUTION = CHALLENGE + COUNTER
HASH_HEX = "0000896d769a2f202cadcef5bee4016bf4ff299f401e8eaae3202a8e1fd50441"


class _SpowHandler(BaseHTTPRequestHandler):
    challenge_calls = 0
    verify_calls: list[dict[str, Any]] = []

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
        if self.path != "/get_pow":
            self._json({"error": "not-found"}, 404)
            return
        type(self).challenge_calls += 1
        self._json({"pow": CHALLENGE, "responseField": "pow"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/post_form":
            self._json({"error": "not-found"}, 404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            payload = json.loads(raw.decode("utf-8") or "{}")
        else:
            payload = {k: v[-1] for k, v in parse_qs(raw.decode("utf-8")).items()}
        type(self).verify_calls.append(payload)
        if not verify_spow_solution(CHALLENGE, payload.get("pow", ""), secret=SECRET):
            self._json({"ok": False, "reason": "invalid_pow"}, 422)
            return
        self._json({"ok": True, "accepted": True})


def test_spow_signature_and_pow_fixture() -> None:
    challenge = create_spow_challenge(difficulty=DIFFICULTY, expires=EXPIRES, salt=SALT, secret=SECRET)
    parsed = parse_spow_challenge(CHALLENGE, secret=SECRET)
    solution = solve_spow_challenge(parsed, secret=SECRET, timeout_sec=5, max_attempts=200_000, workers=2)

    assert challenge.challenge_string == CHALLENGE
    assert sign_spow_challenge(1, DIFFICULTY, EXPIRES, SALT, SECRET) == SIGNATURE
    assert parsed.version == 1
    assert parsed.difficulty == DIFFICULTY
    assert parsed.signature_valid is True
    assert verify_spow_challenge_signature(parsed, SECRET)
    assert not verify_spow_challenge_signature(parsed, "wrong")
    assert solution is not None
    assert solution.counter == COUNTER
    assert solution.solution == SOLUTION
    assert solution.hash_hex == HASH_HEX
    assert spow_hash_hex(CHALLENGE, COUNTER) == HASH_HEX
    assert count_leading_zero_bits_bytes(bytes.fromhex(HASH_HEX)) >= DIFFICULTY
    assert spow_hash_matches(HASH_HEX, DIFFICULTY)
    assert verify_spow_solution(parsed, solution, secret=SECRET)
    assert not verify_spow_solution(parsed, CHALLENGE + "96112", secret=SECRET)
    assert build_spow_submit_body(parsed, solution) == {"pow": SOLUTION}


def test_spow_counter_solver_matches_first_counter() -> None:
    counter, digest, attempts = solve_spow_counter(
        CHALLENGE,
        max_attempts=200_000,
        workers=2,
        deadline_epoch=None,
    )

    assert counter == int(COUNTER)
    assert digest == HASH_HEX
    assert attempts >= int(COUNTER) + 1


def test_spow_extracts_html_challenge() -> None:
    html = (
        '<div class="leptos-captcha" data-pow-challenge="'
        + CHALLENGE
        + '"></div><input type="hidden" name="custom_pow" id="pow" value="">'
    )
    extracted = extract_spow_from_html(html)
    parsed = parse_spow_challenge(extracted, secret=SECRET)

    assert extracted["pow"] == CHALLENGE
    assert extracted["responseField"] == "custom_pow"
    assert parsed.response_field == "custom_pow"
    assert parsed.signature_valid is True


def test_spow_solver_protocol_flow_local_server() -> None:
    _SpowHandler.challenge_calls = 0
    _SpowHandler.verify_calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SpowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            SpowSolver().solve(
                challenge_url=f"{base}/get_pow",
                verify_url=f"{base}/post_form",
                submit=True,
                secret=SECRET,
                timeout_sec=5,
                max_attempts=200_000,
                workers=2,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "spow"
    assert ret.captcha_type == "signed_hashcash_pow"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["counter"] == COUNTER
    assert ret.diagnostics["signature_valid"] is True
    assert _SpowHandler.challenge_calls == 1
    assert _SpowHandler.verify_calls[0]["pow"] == SOLUTION
