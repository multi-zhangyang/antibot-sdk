from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.silentchallenge import (
    SilentChallengeSolver,
    count_leading_zero_bits_bytes,
    generate_silentchallenge_motion,
    generate_silentchallenge_signals,
    score_silentchallenge_motion,
    score_silentchallenge_signals,
    silent_balloon_hash_bytes,
    silent_balloon_hash_hex,
    solve_silentchallenge_pow,
    verify_silentchallenge_pow,
)

FIXTURE_CHALLENGE = {
    "challengeId": "fixture-id",
    "pow": {
        "challengeId": "fixture-id",
        "prefix": "fixture-prefix-",
        "difficulty": 8,
        "spaceCost": 8,
        "timeCost": 1,
        "delta": 3,
    },
    "ttl": 120_000,
}


class _SilentChallengeHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    issued_at = 0.0

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        payload = json.loads(raw.decode("utf-8") or "{}") if raw else {}
        if self.path == "/challenge":
            type(self).issued_at = time.monotonic()
            self._json(FIXTURE_CHALLENGE)
            return
        if self.path == "/challenge/fixture-id/verify":
            type(self).calls.append(payload)
            if (time.monotonic() - type(self).issued_at) * 1000 < 50:
                self._json({"cleared": False, "error": "Too fast"}, 400)
                return
            if not verify_silentchallenge_pow(FIXTURE_CHALLENGE, payload.get("nonce")):
                self._json({"cleared": False, "error": "Insufficient proof of work"}, 400)
                return
            motion_score = score_silentchallenge_motion(payload.get("motion") or {})["score"]
            signal_score = score_silentchallenge_signals(payload.get("signals") or {}, dict(self.headers))["score"]
            combined = motion_score * 0.3 + signal_score * 0.25 + 0.15
            if motion_score < 0.3 or signal_score < 0.3 or combined < 0.5:
                self._json({"cleared": False, "score": combined, "error": "low score"}, 400)
                return
            self._json(
                {
                    "cleared": True,
                    "score": combined,
                    "flags": ["vm: No VM response"],
                    "token": "silent-token",
                }
            )
            return
        self._json({"error": "not-found"}, 404)


def test_silentchallenge_balloon_fixture() -> None:
    digest = silent_balloon_hash_bytes("fixture-prefix-269", 8, 1, 3)
    assert digest.hex() == "008d7af48e4b4a31436732d1d9b78cfabbbc4ab8dc7c3a22d9e50d554cf2358a"
    assert silent_balloon_hash_hex("abc", 8, 1, 3) == "3fa1852173284dc6daba5705eb26b067110e7837e6ce6c500d242fa592f63f13"
    assert count_leading_zero_bits_bytes(digest) == 8


def test_silentchallenge_synthetic_attestation_scores() -> None:
    motion = generate_silentchallenge_motion()
    signals = generate_silentchallenge_signals(now_ms=1_800_000_000_000)
    motion_score = score_silentchallenge_motion(motion)
    signal_score = score_silentchallenge_signals(
        signals,
        {
            "user-agent": signals["navigator"]["ua"],
            "accept": "application/json",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip",
        },
    )

    assert motion_score["score"] >= 0.7
    assert signal_score == {"score": 1.0, "flags": [], "verdict": "trusted"}


def test_silentchallenge_pow_solver_fixture() -> None:
    solution = solve_silentchallenge_pow(FIXTURE_CHALLENGE, timeout_sec=5)

    assert solution is not None
    assert solution.nonce == 269
    assert solution.leading_zero_bits == 8
    assert solution.attempts == 270
    assert verify_silentchallenge_pow(FIXTURE_CHALLENGE, solution.nonce)
    assert solution.submit_body["nonce"] == 269
    assert solution.submit_body["signals"]["navigator"]["vendor"] == "Google Inc."


def test_silentchallenge_solver_protocol_flow_local_server() -> None:
    _SilentChallengeHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SilentChallengeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(
            SilentChallengeSolver().solve(
                base_url=base,
                submit=True,
                timeout_sec=5,
                min_submit_ms=60,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "silentchallenge"
    assert ret.captcha_type == "passive_pow"
    assert ret.capability == "protocol_solver"
    assert ret.ticket == "silent-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["vm_response"] == "not_used"
    assert ret.diagnostics["nonce"] == 269
    assert _SilentChallengeHandler.calls[0]["nonce"] == 269
    assert _SilentChallengeHandler.calls[0]["signals"]["automation"]["globals"] == 0
