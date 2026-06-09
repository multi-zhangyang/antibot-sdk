from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, quote

from antibot_sdk.providers.albireo import (
    AlbireoSolver,
    albireo_hmac_b64,
    albireo_pow_hash,
    make_albireo_cookie,
    parse_albireo_challenge,
    parse_albireo_challenge_cookie,
    parse_albireo_challenge_html,
    solve_albireo_challenge,
    solve_albireo_nonce,
    verify_albireo_pow,
    verify_albireo_solution,
)

SECRET = "albireo-test-secret"
CHALLENGE = "albireo-fixture"
TS = "4102444800000"
FP_NONCE = "fpnoncefixture"


def test_albireo_pow_fixture() -> None:
    nonce, digest, attempts = solve_albireo_nonce(CHALLENGE, 3, max_attempts=10_000)
    assert nonce == 508
    assert attempts == 509
    assert digest == "0002c9691ece2efacea3150519c5865165f656b4386efcab4d326cde32108886"
    assert albireo_pow_hash(CHALLENGE, nonce) == digest
    assert verify_albireo_pow(CHALLENGE, nonce, digest, 3)


def test_albireo_v2_cookie_and_html_parse() -> None:
    cookie = make_albireo_cookie(secret=SECRET, challenge=CHALLENGE, timestamp=TS, difficulty=3, fp_nonce=FP_NONCE)
    assert cookie.endswith(albireo_hmac_b64(SECRET, f"{CHALLENGE}.{TS}.3.{FP_NONCE}"))

    html = f'<script>const CHALLENGE="{CHALLENGE}",DIFFICULTY=3,ORIG="/docs",FP_NONCE="{FP_NONCE}";</script>'
    parsed = parse_albireo_challenge_html(html, cookie_value=quote(cookie))
    assert parsed.variant == "cf_v2"
    assert parsed.challenge == CHALLENGE
    assert parsed.difficulty == 3
    assert parsed.fp_nonce == FP_NONCE
    assert parsed.original_path == "/docs"

    solution = solve_albireo_challenge(parsed, max_attempts=10_000)
    assert solution.nonce == 508
    assert solution.verify_body["fp_nonce"] == FP_NONCE
    assert solution.verify_body["fp_score"] == "0"
    assert verify_albireo_solution(parsed, solution)


def test_albireo_v1_cookie_parse() -> None:
    cookie = make_albireo_cookie(secret=SECRET, challenge=CHALLENGE, timestamp=TS)
    parsed = parse_albireo_challenge_cookie(cookie, difficulty=2, original_path="/v1")
    assert parsed.variant == "v1"
    assert parsed.difficulty == 2
    solution = solve_albireo_challenge(parsed, max_attempts=10_000)
    assert solution.nonce == 460
    assert "fp_nonce" not in solution.verify_body
    assert verify_albireo_solution(parsed, solution)


def test_albireo_accepts_raw_html_and_full_cookie_headers() -> None:
    v2_cookie = make_albireo_cookie(secret=SECRET, challenge=CHALLENGE, timestamp=TS, difficulty=3, fp_nonce=FP_NONCE)
    parsed = parse_albireo_challenge_cookie(
        f"Set-Cookie: albireo_challenge={quote(v2_cookie)}; Path=/; HttpOnly; SameSite=Lax",
        original_path="/headers",
    )
    assert parsed.variant == "cf_v2"
    assert parsed.challenge == CHALLENGE
    assert parsed.fp_nonce == FP_NONCE
    assert parsed.original_path == "/headers"

    html = f'<script>const CHALLENGE="{CHALLENGE}",DIFFICULTY=3,ORIG="/inline",FP_NONCE="{FP_NONCE}";</script>'
    inline = asyncio.run(AlbireoSolver().solve(challenge_json=html, max_attempts=10_000))
    assert inline.ok is True
    assert inline.verify_code == "solved"
    assert inline.diagnostics["variant"] == "cf_v2"
    assert inline.diagnostics["original_path"] == "/inline"
    assert json.loads(inline.ticket or "{}")["fp_nonce"] == FP_NONCE

    cookie_inline = asyncio.run(AlbireoSolver().solve(challenge_json=f"albireo_challenge={v2_cookie}; Path=/", max_attempts=10_000))
    assert cookie_inline.ok is True
    assert cookie_inline.diagnostics["fp_nonce_present"] is True

    assert parse_albireo_challenge({"cookie": f"Cookie: albireo_challenge={v2_cookie}; other=1"}).challenge == CHALLENGE


class _AlbireoHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    variant = "cf_v2"
    difficulty = 3

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if not self.headers.get("Accept-Language") or not self.headers.get("Sec-Fetch-Mode"):
            self._write(b"Forbidden", 403)
            return
        if type(self).variant == "cf_v2":
            cookie = make_albireo_cookie(
                secret=SECRET,
                challenge=CHALLENGE,
                timestamp=str(int(time.time() * 1000)),
                difficulty=type(self).difficulty,
                fp_nonce=FP_NONCE,
            )
            html = f'<script>const CHALLENGE="{CHALLENGE}",DIFFICULTY={type(self).difficulty},ORIG="/protected",FP_NONCE="{FP_NONCE}";</script>'
        else:
            cookie = make_albireo_cookie(secret=SECRET, challenge=CHALLENGE, timestamp=str(int(time.time() * 1000)))
            html = f'<script>const CHALLENGE = "{CHALLENGE}"; const DIFFICULTY = {type(self).difficulty}; const ORIGINAL_PATH = "/protected";</script>'
        self._write(
            html.encode("utf-8"),
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": f"albireo_challenge={quote(cookie)}; Path=/; HttpOnly; SameSite=Lax",
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = parse_qs(self.rfile.read(length).decode("utf-8"))
        body = {key: values[-1] for key, values in payload.items()}
        type(self).calls.append({"method": "POST", "path": self.path, "payload": body, "headers": dict(self.headers)})
        cookie_header = self.headers.get("Cookie", "")
        cookie_value = ""
        for part in cookie_header.split(";"):
            if part.strip().startswith("albireo_challenge="):
                cookie_value = part.strip().split("=", 1)[1]
        parsed = parse_albireo_challenge_cookie(cookie_value, difficulty=type(self).difficulty, original_path="/protected")
        ok = verify_albireo_solution(parsed, body)
        if parsed.fp_nonce and body.get("fp_nonce") != parsed.fp_nonce:
            ok = False
        if ok:
            self._write(
                json.dumps({"success": True, "redirect": body.get("original_path") or "/"}).encode("utf-8"),
                200,
                {
                    "Content-Type": "application/json",
                    "Set-Cookie": "albireo_solved=true; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
                },
            )
            return
        self._write(b"POW Failed", 403)


def _run_solver_against_handler(*, variant: str, difficulty: int) -> tuple[Any, list[dict[str, Any]]]:
    _AlbireoHandler.calls = []
    _AlbireoHandler.variant = variant
    _AlbireoHandler.difficulty = difficulty
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AlbireoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(AlbireoSolver().solve(base_url=base, submit=True, timeout_sec=5, max_attempts=20_000))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()
    return ret, list(_AlbireoHandler.calls)


def test_albireo_solver_cf_v2_local_server() -> None:
    ret, calls = _run_solver_against_handler(variant="cf_v2", difficulty=3)
    assert ret.ok is True
    assert ret.provider == "albireo"
    assert ret.captcha_type == "serverless_signed_pow"
    assert ret.verify_code == "verified"
    assert ret.randstr == CHALLENGE
    assert ret.diagnostics["variant"] == "cf_v2"
    assert ret.diagnostics["fp_nonce_present"] is True
    assert json.loads(ret.ticket or "{}")["albireo_solved"] is True
    assert calls[0]["headers"]["Sec-Fetch-Mode"] == "navigate"
    assert calls[1]["payload"]["fp_nonce"] == FP_NONCE


def test_albireo_solver_v1_local_server() -> None:
    ret, calls = _run_solver_against_handler(variant="v1", difficulty=2)
    assert ret.ok is True
    assert ret.verify_code == "verified"
    assert ret.diagnostics["variant"] == "v1"
    assert ret.diagnostics["difficulty"] == 2
    assert "fp_nonce" not in calls[1]["payload"]
