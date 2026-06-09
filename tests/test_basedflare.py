from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from antibot_sdk.providers.basedflare import (
    BasedFlareSolver,
    basedflare_argon2_digest,
    basedflare_checkdiff_lua,
    basedflare_sha256_digest,
    parse_basedflare_challenge,
    parse_basedflare_challenge_html,
    solve_basedflare_pow,
    verify_basedflare_solution,
)

USER_KEY = "00112233445566778899aabbccddeeff"
CHALLENGE_HASH = "a" * 64
EXPIRY = 2_000_000_000
SIGNATURE = "b" * 64
COMBINED_CHALLENGE = f"{USER_KEY}#{CHALLENGE_HASH}#{EXPIRY}#{SIGNATURE}"
SHA_DIFFICULTY_BITS = 12
SHA_DIFFICULTY_BYTES = 2
SHA_ANSWER = "72"
SHA_DIGEST = "0012f6c2a9fb1a4ff76a21c002ebd3d066c228b0929b6b8a2f5a4b888da8b9e8"

ARGON_CHALLENGE_HASH = "b" * 64
ARGON_COMBINED_CHALLENGE = f"{USER_KEY}#{ARGON_CHALLENGE_HASH}#{EXPIRY}#{SIGNATURE}"
ARGON_ANSWER = "3"
ARGON_DIGEST = "099d464cc8afa9fb1fc4bbac54fb4b7864ebe8b4af6da8d490e9b2df104d2219"

HMAC_SECRET = "fixture-hmac-secret"


def _challenge_json(*, mode: str = "sha256") -> dict[str, Any]:
    combined = ARGON_COMBINED_CHALLENGE if mode == "argon2" else COMBINED_CHALLENGE
    kb = 8 if mode == "argon2" else 6000
    return {
        "ch": combined,
        "ca": False,
        "pow": f"{mode}#{SHA_DIFFICULTY_BYTES}#1#{kb}",
    }


def _challenge_html(*, mode: str = "sha256", difficulty_bits: int = SHA_DIFFICULTY_BITS) -> str:
    combined = ARGON_COMBINED_CHALLENGE if mode == "argon2" else COMBINED_CHALLENGE
    kb = 8 if mode == "argon2" else 6000
    return f"""
    <!doctype html>
    <html>
      <head lang="en-US" data-langjson='{{"Hold on...":"Hold on..."}}'>
        <script src="/.basedflare/js/a2.min.js"></script>
        <script src="/.basedflare/js/ch.min.js"></script>
      </head>
      <body
        data-pow="{combined}"
        data-diff="{difficulty_bits}"
        data-time="1"
        data-kb="{kb}"
        data-mode="{mode}">
        <form method="post"><textarea name="pow_response"></textarea></form>
      </body>
    </html>
    """


def _cookie_value(answer: str) -> str:
    sig = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        f"{USER_KEY}{CHALLENGE_HASH}{EXPIRY}{answer}".encode("utf-8"),
        hashlib.sha3_256,
    ).hexdigest()
    return f"{USER_KEY}#{CHALLENGE_HASH}#{EXPIRY}#{answer}#{sig}"


def test_basedflare_parse_json_and_html_challenge() -> None:
    parsed_json = parse_basedflare_challenge(_challenge_json())

    assert parsed_json.user_key == USER_KEY
    assert parsed_json.challenge_hash == CHALLENGE_HASH
    assert parsed_json.expiry == EXPIRY
    assert parsed_json.signature == SIGNATURE
    assert parsed_json.mode == "sha256"
    assert parsed_json.difficulty_bytes == SHA_DIFFICULTY_BYTES
    # JSON auto-refresh path exposes ceil(bit_difficulty / 8). The SDK should preserve that
    # value; effective_difficulty_bits uses bytes*8 when no real bit difficulty is known.
    assert parsed_json.difficulty_bits is None
    assert parsed_json.effective_difficulty_bits == SHA_DIFFICULTY_BYTES * 8
    assert parsed_json.argon_time == 1
    assert parsed_json.argon_kb == 6000

    parsed_json_override = parse_basedflare_challenge(
        _challenge_json(),
        difficulty_bits=SHA_DIFFICULTY_BITS,
    )
    assert parsed_json_override.difficulty_bits == SHA_DIFFICULTY_BITS

    html = _challenge_html(difficulty_bits=SHA_DIFFICULTY_BITS)
    parsed_html = parse_basedflare_challenge_html(html, page_url="https://target.example/protected")
    assert parsed_html.user_key == USER_KEY
    assert parsed_html.challenge_hash == CHALLENGE_HASH
    assert parsed_html.mode == "sha256"
    assert parsed_html.difficulty_bits == SHA_DIFFICULTY_BITS
    assert parsed_html.difficulty_bytes is None
    assert parsed_html.effective_difficulty_bits == SHA_DIFFICULTY_BITS
    assert parsed_html.page_url == "https://target.example/protected"

    parsed_dispatch = parse_basedflare_challenge(
        {"html": html, "page_url": "https://target.example/protected"}
    )
    assert parsed_dispatch.challenge_hash == CHALLENGE_HASH
    assert parsed_dispatch.difficulty_bits == SHA_DIFFICULTY_BITS


def test_basedflare_lua_checkdiff_edge_compatibility() -> None:
    assert not basedflare_checkdiff_lua("", 0)
    assert basedflare_checkdiff_lua("f" * 64, 0)

    # Mirror haproxy-protection's Lua exactly, including its unusual hex-nibble/bit mix.
    assert basedflare_checkdiff_lua("2" + "f" * 63, 1)
    assert not basedflare_checkdiff_lua("1" + "f" * 63, 1)
    assert basedflare_checkdiff_lua("0" + "f" * 63, 4)
    assert not basedflare_checkdiff_lua("1" + "0" * 63, 4)

    # diff=8 only requires the first hex character to be zero in upstream Lua.
    assert basedflare_checkdiff_lua("0f" + "a" * 62, 8)
    assert not basedflare_checkdiff_lua("10" + "a" * 62, 8)

    # diff=12 and diff=16 both require two leading zero hex characters.
    assert basedflare_checkdiff_lua("00f" + "a" * 61, 12)
    assert not basedflare_checkdiff_lua("0f0" + "a" * 61, 12)
    assert basedflare_checkdiff_lua("00f" + "a" * 61, 16)

    # diff=18 checks the third nibble with mask 0x03, so 0/4/8/c pass and 2 fails.
    assert basedflare_checkdiff_lua("004" + "a" * 61, 18)
    assert basedflare_checkdiff_lua("00c" + "a" * 61, 18)
    assert not basedflare_checkdiff_lua("002" + "a" * 61, 18)


def test_basedflare_sha256_solve_and_verify_fixture() -> None:
    challenge = parse_basedflare_challenge(
        _challenge_json(),
        difficulty_bits=SHA_DIFFICULTY_BITS,
    )

    assert basedflare_sha256_digest(USER_KEY, CHALLENGE_HASH, SHA_ANSWER) == SHA_DIGEST
    assert basedflare_checkdiff_lua(SHA_DIGEST, SHA_DIFFICULTY_BITS)
    assert not verify_basedflare_solution(challenge, "71")

    solution = solve_basedflare_pow(challenge, start=70, max_attempts=20, workers=1)

    assert solution.answer == SHA_ANSWER
    assert solution.digest_hex == SHA_DIGEST
    assert solution.pow_response == f"{COMBINED_CHALLENGE}#{SHA_ANSWER}"
    assert getattr(solution, "attempts_hint", getattr(solution, "attempts", None)) == 3
    assert verify_basedflare_solution(challenge, solution)
    assert verify_basedflare_solution(challenge, solution.pow_response)
    assert verify_basedflare_solution(challenge, {"answer": SHA_ANSWER})
    assert verify_basedflare_solution(challenge, f"_basedflare_pow={_cookie_value(SHA_ANSWER)}; Path=/")
    assert not verify_basedflare_solution(challenge, f"_basedflare_pow={_cookie_value('71')}; Path=/")


def test_basedflare_argon2_low_difficulty_verify_fixture() -> None:
    challenge = parse_basedflare_challenge(
        _challenge_json(mode="argon2"),
        difficulty_bits=8,
    )

    assert challenge.mode == "argon2"
    assert challenge.argon_time == 1
    assert challenge.argon_kb == 8
    assert (
        basedflare_argon2_digest(
            USER_KEY,
            ARGON_CHALLENGE_HASH,
            ARGON_ANSWER,
            argon_time=1,
            argon_kb=8,
        )
        == ARGON_DIGEST
    )
    assert basedflare_checkdiff_lua(ARGON_DIGEST, 8)
    assert verify_basedflare_solution(challenge, ARGON_ANSWER)
    assert not verify_basedflare_solution(challenge, "2")


class _BasedFlareHandler(BaseHTTPRequestHandler):
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
        type(self).calls.append(
            {"method": "GET", "path": self.path, "headers": dict(self.headers)}
        )
        parsed = urlsplit(self.path)
        if parsed.path == "/.basedflare/bot-check":
            body = json.dumps(_challenge_json(), separators=(",", ":")).encode("utf-8")
            self._write(body, 403, {"Content-Type": "application/json; charset=utf-8"})
            return
        if parsed.path == "/protected":
            self._write(b"upstream ok", 200, {"Content-Type": "text/plain"})
            return
        self._write(b"not found", 404, {"Content-Type": "text/plain"})

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        pow_response = form.get("pow_response", [""])[0]
        type(self).calls.append(
            {
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "pow_response": pow_response,
            }
        )
        challenge = parse_basedflare_challenge(
            _challenge_json(),
            difficulty_bits=SHA_DIFFICULTY_BITS,
        )
        if urlsplit(self.path).path != "/.basedflare/bot-check" or not verify_basedflare_solution(
            challenge,
            pow_response,
        ):
            self._write(b"rejected", 403, {"Content-Type": "text/plain"})
            return

        answer = pow_response.rsplit("#", 1)[-1]
        cookie_value = _cookie_value(answer)
        self._write(
            b"",
            302,
            {
                "Location": "/protected",
                "Set-Cookie": (
                    f"_basedflare_pow={cookie_value}; Expires=Wed, 18-May-33 03:33:20 GMT; "
                    "Path=/; SameSite=None"
                ),
            },
        )


def test_basedflare_solver_protocol_flow_local_mock_server() -> None:
    _BasedFlareHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BasedFlareHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(
            BasedFlareSolver().solve(
                base_url=base_url,
                submit=True,
                difficulty_bits=SHA_DIFFICULTY_BITS,
                start=70,
                max_attempts=20,
                timeout_sec=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "basedflare"
    assert ret.captcha_type == "haproxy_pow_cookie"
    assert ret.capability == "protocol_solver"
    assert ret.verify_code == "verified"
    assert ret.diagnostics["browser"] == "not_used"
    assert ret.diagnostics["mode"] == "sha256"
    assert ret.diagnostics["difficulty_bits"] == SHA_DIFFICULTY_BITS
    assert ret.diagnostics["answer"] == SHA_ANSWER
    assert ret.diagnostics["digest_hex"] == SHA_DIGEST

    ticket = json.loads(ret.ticket or "{}")
    assert ticket["pow_response"] == f"{COMBINED_CHALLENGE}#{SHA_ANSWER}"
    assert ticket["_basedflare_pow"] == _cookie_value(SHA_ANSWER)

    assert _BasedFlareHandler.calls[0]["method"] == "GET"
    assert urlsplit(_BasedFlareHandler.calls[0]["path"]).path == "/.basedflare/bot-check"
    assert "application/json" in _BasedFlareHandler.calls[0]["headers"]["Accept"]
    assert _BasedFlareHandler.calls[1]["method"] == "POST"
    assert urlsplit(_BasedFlareHandler.calls[1]["path"]).path == "/.basedflare/bot-check"
    assert _BasedFlareHandler.calls[1]["pow_response"] == ticket["pow_response"]
