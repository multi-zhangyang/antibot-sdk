from __future__ import annotations

import json

from antibot_sdk.providers.wicketkeeper import (
    WicketkeeperChallenge,
    WicketkeeperSolver,
    solve_wicketkeeper_challenge,
    verify_wicketkeeper_work,
    wicketkeeper_hash_hex,
)

FIXTURE = WicketkeeperChallenge(challenge="hunter", difficulty=4, token="challenge.jwt")
FIXTURE_NONCE = "73720"
FIXTURE_RESPONSE = "000021aed34dbacfb31c00533eecdc3099fe858b8377273a12cc9cdfecfaebe4"


def test_wicketkeeper_pow_fixture() -> None:
    assert wicketkeeper_hash_hex("hunter", FIXTURE_NONCE) == FIXTURE_RESPONSE
    assert verify_wicketkeeper_work(FIXTURE, FIXTURE_NONCE, FIXTURE_RESPONSE)

    solution = solve_wicketkeeper_challenge(FIXTURE, max_attempts=100_000, timeout_sec=5)
    assert solution is not None
    assert solution.nonce == FIXTURE_NONCE
    assert solution.response == FIXTURE_RESPONSE
    assert solution.submit_body == {
        "token": "challenge.jwt",
        "nonce": FIXTURE_NONCE,
        "response": FIXTURE_RESPONSE,
    }


def test_wicketkeeper_solver_mock_challenge_and_siteverify(monkeypatch) -> None:
    calls: list[tuple[str, dict | None]] = []

    class Resp:
        def __init__(self, url: str, payload: dict, status: int = 200):
            self.url = url
            self._payload = payload
            self.status_code = status
            self.text = json.dumps(payload)

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise RuntimeError(f"status {self.status_code}")

        def json(self) -> dict:
            return self._payload

    def fake_get(url, **kwargs):  # noqa: ANN001, ANN202
        calls.append((url, None))
        assert url.endswith("/v0/challenge")
        return Resp(
            url,
            {
                "challenge": FIXTURE.challenge,
                "difficulty": FIXTURE.difficulty,
                "token": FIXTURE.token,
            },
        )

    def fake_post(url, *, json=None, **kwargs):  # noqa: ANN001, ANN202
        calls.append((url, dict(json or {})))
        assert url.endswith("/v0/siteverify")
        assert verify_wicketkeeper_work(FIXTURE, json["nonce"], json["response"])
        return Resp(url, {"success": True, "token": "success.jwt", "challenge": FIXTURE.challenge})

    monkeypatch.setattr("antibot_sdk.providers.wicketkeeper.requests.get", fake_get)
    monkeypatch.setattr("antibot_sdk.providers.wicketkeeper.requests.post", fake_post)

    ret = WicketkeeperSolver()._solve_sync(
        base_url="https://captcha.example",
        max_attempts=100_000,
        timeout_sec=5,
    )

    assert ret.ok
    assert ret.provider == "wicketkeeper"
    assert ret.ticket == "success.jwt"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonce"] == FIXTURE_NONCE
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["challenge", "siteverify"]
