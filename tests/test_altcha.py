from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from antibot_sdk.providers.altcha import (
    AltchaChallenge,
    AltchaSolver,
    AltchaV2Challenge,
    altcha_hash_hex,
    altcha_v2_derive_key_hex,
    altcha_v2_hmac_hex,
    challenge_from_altcha_header,
    parse_altcha_payload_b64,
    solve_altcha_challenge,
    solve_altcha_v2_challenge,
    verify_altcha_v2_solution,
)


def _challenge(number: int = 4321) -> dict[str, Any]:
    salt = "salt:test"
    algorithm = "SHA-256"
    return {
        "algorithm": algorithm,
        "challenge": altcha_hash_hex(salt, number, algorithm),
        "salt": salt,
        "signature": "sig-test",
        "maxnumber": 9000,
    }


def test_altcha_hash_and_payload_solution() -> None:
    data = _challenge(4321)

    solution = solve_altcha_challenge(data, max_number=9000)

    assert solution is not None
    assert solution.number == 4321
    assert solution.payload()["challenge"] == data["challenge"]
    assert parse_altcha_payload_b64(solution.payload_b64()) == solution.payload()
    assert solution.authorization_header().startswith("Altcha challenge=")
    assert solution.authorization_header(style="kv").startswith("Altcha algorithm=SHA-256")


def test_altcha_header_challenge_parse_and_solve() -> None:
    data = _challenge(123)
    header = (
        'Altcha algorithm=SHA-256, challenge="%s", salt="%s", signature="%s", maxnumber=1000'
        % (data["challenge"], data["salt"], data["signature"])
    )

    challenge = challenge_from_altcha_header(header)
    solution = solve_altcha_challenge(challenge)

    assert isinstance(challenge, AltchaChallenge)
    assert challenge.salt == data["salt"]
    assert solution is not None
    assert solution.number == 123


def test_altcha_official_json_header_parse_and_solve() -> None:
    data = _challenge(321)
    header = "Altcha challenge=" + json.dumps(data, separators=(",", ":"))

    challenge = challenge_from_altcha_header(header)
    solution = solve_altcha_challenge(challenge)

    assert solution is not None
    assert solution.number == 321
    assert challenge.challenge == data["challenge"]


class _AltchaHandler(BaseHTTPRequestHandler):
    challenge = _challenge(789)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/altcha/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(self.challenge).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_altcha_solver_protocol_flow_local_server() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AltchaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/altcha/challenge"
    try:
        ret = asyncio.run(AltchaSolver().solve(challenge_url=url, timeout_sec=5))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    payload = parse_altcha_payload_b64(str(ret.ticket))
    assert ret.ok is True
    assert ret.provider == "altcha"
    assert ret.captcha_type == "proof_of_work"
    assert ret.capability == "protocol_solver"
    assert payload["number"] == 789
    assert payload["challenge"] == _AltchaHandler.challenge["challenge"]
    assert ret.verify_code == "789"


V2_VECTOR_BASE = {
    "nonce": "39baf91a19d671f8231217f9e28342a6",
    "salt": "5e00d5d152e1a5db7d44fb6404a40a5e",
    "keyPrefix": "",
}


def _v2_params(**kwargs: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        **V2_VECTOR_BASE,
        "algorithm": "PBKDF2/SHA-256",
        "cost": 1,
        "keyLength": 32,
    }
    params.update(kwargs)
    return params


def test_altcha_v2_official_kdf_vectors() -> None:
    assert altcha_v2_derive_key_hex({"parameters": _v2_params()}, 123) == (
        "722ede188d41e7a7c9fd5447dca6cbb84e09c15724dbaadfb5bfb37d2cd4effa"
    )
    assert altcha_v2_derive_key_hex({"parameters": _v2_params(cost=2)}, 123) == (
        "cba117f9a790022a55589d5008c9f003e49c011ff7fe34fc838788a1825524f7"
    )
    assert altcha_v2_derive_key_hex({"parameters": _v2_params(algorithm="SHA-256")}, 123) == (
        "6deccc5eecdb14c99d57129ef8f2f7d3e71812d8bd022c1caaf9e56512ec186c"
    )
    assert altcha_v2_derive_key_hex({"parameters": _v2_params(algorithm="SCRYPT", cost=16384, memoryCost=8)}, 123) == (
        "1cc78d75577b791a65ba2b27894aec3c6af99b64155e79f50f4725fd43341070"
    )
    assert altcha_v2_derive_key_hex(
        {"parameters": _v2_params(algorithm="ARGON2ID", cost=1, memoryCost=16384)},
        123,
    ) == "e5231033e21615aae48d8bc9b8e5e6c8f6538756f99dbcd5666f6e20832f30de"


def test_altcha_v2_prefix_solver_and_payload() -> None:
    challenge = {"parameters": _v2_params(keyPrefix="722ede")}

    solution = solve_altcha_v2_challenge(challenge, strategy="prefix", max_counter=200, timeout_sec=10)

    assert solution is not None
    assert isinstance(solution.challenge, AltchaV2Challenge)
    assert solution.counter == 123
    assert solution.prefix_matched is True
    assert solution.derived_key.startswith("722ede")
    assert solution.payload()["solution"]["counter"] == 123
    assert verify_altcha_v2_solution(challenge, solution, enforce_key_prefix=True)
    assert not verify_altcha_v2_solution(challenge, {"counter": 124, "derivedKey": solution.derived_key})


def test_altcha_v2_verify_compatible_fast_path() -> None:
    # Mirrors upstream ALTCHA v2 verifySolution(): without keySignature it re-derives
    # and compares the submitted derivedKey, but does not re-check keyPrefix.
    challenge = {"parameters": _v2_params(keyPrefix="ffff")}

    solution = solve_altcha_v2_challenge(challenge, strategy="auto", max_counter=10)

    assert solution is not None
    assert solution.counter == 0
    assert solution.strategy == "verify-compatible"
    assert solution.prefix_matched is False
    assert verify_altcha_v2_solution(challenge, solution)
    assert not verify_altcha_v2_solution(challenge, solution, enforce_key_prefix=True)


class _AltchaV2Handler(BaseHTTPRequestHandler):
    hmac_secret = "signature.secret"
    parameters = _v2_params(keyPrefix="722e")
    challenge = {
        "parameters": parameters,
        "signature": altcha_v2_hmac_hex(
            json.dumps(parameters, sort_keys=True, separators=(",", ":")),
            hmac_secret,
        ),
    }

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        if self.path != "/altcha/v2/challenge":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(self.challenge).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_altcha_v2_solver_protocol_flow_local_server() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AltchaV2Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/altcha/v2/challenge"
    try:
        ret = asyncio.run(
            AltchaSolver().solve(
                challenge_url=url,
                timeout_sec=10,
                v2_strategy="prefix",
                max_number=200,
                hmac_signature_secret=_AltchaV2Handler.hmac_secret,
            )
        )
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    payload = parse_altcha_payload_b64(str(ret.ticket))
    assert ret.ok is True
    assert ret.provider == "altcha"
    assert ret.capability == "protocol_solver"
    assert ret.diagnostics["version"] == "v2"
    assert ret.diagnostics["signature_valid"] is True
    assert ret.diagnostics["prefix_matched"] is True
    assert payload["solution"]["counter"] == 123
    assert payload["solution"]["derivedKey"].startswith("722e")
    assert verify_altcha_v2_solution(
        payload["challenge"],
        payload["solution"],
        hmac_signature_secret=_AltchaV2Handler.hmac_secret,
        enforce_key_prefix=True,
    )
