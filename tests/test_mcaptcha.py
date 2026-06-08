from __future__ import annotations

import json

from antibot_sdk.providers.mcaptcha import (
    MCaptchaConfig,
    MCaptchaSolver,
    bincode_serialize_string,
    mcaptcha_score,
    solve_mcaptcha_config,
    verify_mcaptcha_work,
)

FIXTURE = MCaptchaConfig(
    key="site-key",
    string="python-rust-crosscheck",
    difficulty_factor=50,
    salt="13b9bb30d3eef8ed0fd295b9e0df87",
    max_recorded_nonce=0,
)
FIXTURE_NONCE = 72
FIXTURE_RESULT = "335129049831425857963529320439312822525"


def test_mcaptcha_bincode_string_serialization() -> None:
    raw = bincode_serialize_string("abc")
    assert raw[:8] == b"\x03\x00\x00\x00\x00\x00\x00\x00"
    assert raw[8:] == b"abc"


def test_mcaptcha_pow_matches_official_rust_fixture() -> None:
    # Generated with mcaptcha_pow_sha256 0.5.0:
    # ConfigBuilder::salt(FIXTURE.salt).prove_work(&FIXTURE.string, 50)
    assert mcaptcha_score(FIXTURE.salt, FIXTURE.string, FIXTURE_NONCE) == int(FIXTURE_RESULT)
    assert verify_mcaptcha_work(FIXTURE, FIXTURE_NONCE, FIXTURE_RESULT)

    solution = solve_mcaptcha_config(FIXTURE, max_attempts=1_000, timeout_sec=5)
    assert solution is not None
    assert solution.nonce == FIXTURE_NONCE
    assert solution.result == FIXTURE_RESULT
    assert solution.submit_body["key"] == "site-key"
    assert solution.submit_body["worker_type"] == "python"


def test_mcaptcha_solver_mock_config_verify_siteverify(monkeypatch) -> None:
    calls: list[tuple[str, dict]] = []

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

    def fake_post(url, *, json=None, **kwargs):  # noqa: ANN001, ANN202
        calls.append((url, dict(json or {})))
        if url.endswith("/config"):
            assert json == {"key": "site-key"}
            return Resp(
                url,
                {
                    "string": FIXTURE.string,
                    "difficulty_factor": FIXTURE.difficulty_factor,
                    "salt": FIXTURE.salt,
                    "max_recorded_nonce": 0,
                },
            )
        if url.endswith("/verify"):
            assert verify_mcaptcha_work(FIXTURE, json["nonce"], json["result"])
            return Resp(url, {"token": "mcaptcha-token"})
        if url.endswith("/siteverify"):
            assert json == {"secret": "owner-secret", "key": "site-key", "token": "mcaptcha-token"}
            return Resp(url, {"valid": True})
        raise AssertionError(url)

    monkeypatch.setattr("antibot_sdk.providers.mcaptcha.requests.post", fake_post)

    ret = MCaptchaSolver()._solve_sync(
        base_url="https://captcha.example",
        sitekey="site-key",
        secret="owner-secret",
        siteverify=True,
        max_attempts=1_000,
        timeout_sec=5,
    )

    assert ret.ok
    assert ret.provider == "mcaptcha"
    assert ret.ticket == "mcaptcha-token"
    assert ret.verify_code == "validated"
    assert ret.diagnostics["nonce"] == FIXTURE_NONCE
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["config", "verify", "siteverify"]
