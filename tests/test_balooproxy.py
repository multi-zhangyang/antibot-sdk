from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.balooproxy import (
    BalooProxySolver,
    balooproxy_access_hash,
    balooproxy_digest,
    derive_balooproxy_stage2_challenge,
    hex_suffix_by_index,
    parse_balooproxy_challenge,
    parse_balooproxy_challenge_html,
    solve_balooproxy_challenge,
    solve_balooproxy_suffix,
    validate_balooproxy_suffix,
    verify_balooproxy_solution,
)

PUBLIC_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
DIFFICULTY = 4
SUFFIX = "04d2"
COOKIE_VALUE = PUBLIC_SALT + SUFFIX
CHALLENGE_HEX = hashlib.sha256(COOKIE_VALUE.encode("utf-8")).hexdigest()
ACCESS_HEX = hashlib.sha256((SUFFIX + PUBLIC_SALT).encode("utf-8")).hexdigest()


def _challenge_html(public_salt: str = PUBLIC_SALT, difficulty: int = DIFFICULTY, challenge: str = CHALLENGE_HEX) -> str:
    return f'''<!doctypehtml><html lang=en><meta charset=UTF-8>
    <title>Completing challenge ...</title>
    <div class=placeholder-container><div class=placeholder-label>publicSalt:</div>
      <div class=placeholder id=publicSalt onclick='ctc("publicSalt")'><span>{public_salt}</span></div>
    </div>
    <div class=placeholder-container><div class=placeholder-label>challenge:</div>
      <div class=placeholder id=challenge onclick='ctc("challenge")'><span>{challenge}</span></div>
    </div>
    <script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>
    <script>
    function solved(e){{document.cookie="_2__bProxy_v={public_salt}"+e.solution+"; SameSite=Lax; path=/; Secure",location.href=location.href}}
    new BalooPow("{public_salt}",{difficulty},"{challenge}",!1).Solve().then(e=>{{if(e.match == ""){{solved(e)}}}});
    </script></html>'''


def test_balooproxy_baloo_pow_fixture() -> None:
    assert hex_suffix_by_index(1234, DIFFICULTY) == SUFFIX
    assert balooproxy_digest(PUBLIC_SALT, SUFFIX) == CHALLENGE_HEX
    assert balooproxy_access_hash(PUBLIC_SALT, SUFFIX) == ACCESS_HEX
    assert validate_balooproxy_suffix(SUFFIX, DIFFICULTY)

    suffix, cookie_value, digest_hex, attempts = solve_balooproxy_suffix(
        PUBLIC_SALT,
        CHALLENGE_HEX,
        DIFFICULTY,
        max_attempts=2_000,
    )

    assert suffix == SUFFIX
    assert cookie_value == COOKIE_VALUE
    assert digest_hex == CHALLENGE_HEX
    assert attempts == 1235


def test_balooproxy_html_json_and_solution_parse() -> None:
    html = _challenge_html()
    parsed = parse_balooproxy_challenge_html(html, page_url="https://target.example/protected")
    assert parsed.public_salt == PUBLIC_SALT
    assert parsed.challenge == CHALLENGE_HEX
    assert parsed.difficulty == DIFFICULTY
    assert parsed.numeric is False
    assert parsed.cookie_name == "_2__bProxy_v"
    assert parsed.page_url == "https://target.example/protected"

    solution = solve_balooproxy_challenge(parsed, max_attempts=2_000)
    assert solution.suffix == SUFFIX
    assert solution.cookie_value == COOKIE_VALUE
    assert solution.cookie_header == f"_2__bProxy_v={COOKIE_VALUE}"
    assert solution.digest_hex == CHALLENGE_HEX
    assert solution.access_hex == ACCESS_HEX
    assert verify_balooproxy_solution(parsed, solution)
    assert verify_balooproxy_solution(parsed, {"cookie_value": COOKIE_VALUE})
    assert verify_balooproxy_solution(parsed, f"_2__bProxy_v={COOKIE_VALUE}; Path=/")
    assert not verify_balooproxy_solution(parsed, f"_2__bProxy_v={PUBLIC_SALT}ffff")

    parsed_json = parse_balooproxy_challenge(
        {
            "publicSalt": PUBLIC_SALT,
            "challenge": CHALLENGE_HEX,
            "difficulty": DIFFICULTY,
        }
    )
    assert parsed_json.public_salt == PUBLIC_SALT


def test_balooproxy_stage2_derivation_matches_source_formula() -> None:
    derived = derive_balooproxy_stage2_challenge(
        ip="203.0.113.9",
        tls_fingerprint="771,4865-4866-4867",
        user_agent="Mozilla/5.0 fixture",
        hour="13",
        js_secret="agentF-js-secret",
        day="2026-06-09",
        difficulty=3,
    )
    assert derived.js_otp == "23f9645e4a0f52b80fd4e1ab21107225680ebc9cc4938a3e38d11adc2c9b40de"
    assert derived.encrypted_ip == "9abe9b472e5964ec1045e4aa732ec5ca2c666c885e0904580c054ae12788afc1"
    assert derived.public_salt == "9abe9b472e5964ec1045e4aa732ec5ca2c666c885e0904580c054ae12788a"
    assert derived.suffix == "fc1"
    assert derived.challenge == "d0fa9cfc3347372231c4c8c7d28e45f2dc7d5e12bf7dc876a9513371bf89f7b0"
    assert verify_balooproxy_solution(derived.as_challenge(), derived.public_salt + derived.suffix)


class _BalooProxyHandler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []

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
        cookie = self.headers.get("Cookie", "")
        type(self).calls.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if f"_2__bProxy_v={COOKIE_VALUE}" in cookie and verify_balooproxy_solution(
            {"publicSalt": PUBLIC_SALT, "challenge": CHALLENGE_HEX, "difficulty": DIFFICULTY},
            COOKIE_VALUE,
        ):
            self._write(b"upstream ok", 200, {"Content-Type": "text/plain"})
            return
        self._write(_challenge_html().encode("utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"})


def test_balooproxy_solver_local_cookie_flow() -> None:
    _BalooProxyHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BalooProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/protected"
    try:
        ret = asyncio.run(
            BalooProxySolver().solve(base_url=base, submit=True, timeout_sec=5, max_attempts=2_000)
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "balooproxy"
    assert ret.captcha_type == "balooproxy_js_suffix_sha256_cookie"
    assert ret.verify_code == "verified"
    assert json.loads(ret.ticket or "{}") == {"_2__bProxy_v": COOKIE_VALUE}
    assert ret.diagnostics["difficulty"] == DIFFICULTY
    assert ret.diagnostics["suffix"] == SUFFIX
    assert ret.diagnostics["cookie_value"] == COOKIE_VALUE
    assert _BalooProxyHandler.calls[0]["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert _BalooProxyHandler.calls[1]["headers"]["Cookie"] == f"_2__bProxy_v={COOKIE_VALUE}"
