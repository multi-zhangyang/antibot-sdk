import asyncio

from antibot_sdk import TurnstileChallengeSession
from antibot_sdk.harness import ChallengeAgentLoop, VisionChallengePolicy, evaluate_result
from antibot_sdk.providers.turnstile import (
    TURNSTILE_TOKEN_SELECTORS,
    TURNSTILE_VERIFIER_EVENT_MARKERS,
)
from antibot_sdk.vision import StaticVisionBackend


def _run(session):
    return asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([])),
            max_steps=3,
        ).run()
    )


def test_turnstile_session_submits_and_requires_real_verifier_event() -> None:
    state = {"token": ""}

    async def read_tokens():
        return [state["token"]] if state["token"] else []

    async def submit():
        state["token"] = "turnstile-vendor-token-" + "x" * 40

    diagnostics = {}
    session = TurnstileChallengeSession(
        object(),
        token_reader=read_tokens,
        submitter=submit,
        network_events=[
            {"url": "https://challenges.cloudflare.com/turnstile/v0/siteverify"}
        ],
        diagnostics=diagnostics,
        verification_wait_ms=0,
    )

    result = _run(session)

    assert result.accepted is True
    assert result.verification.provider == "cloudflare"
    assert result.verification.token_length == len(state["token"])
    assert result.verification.verifier_events == ("/turnstile/", "siteverify")
    assert diagnostics["turnstile_session_verification"]["accepted"] is True
    replay = evaluate_result(result.to_dict(), source="turnstile-live-run-1.json")
    assert replay.provider == "cloudflare"
    assert replay.result_ok is True
    assert replay.evidence_accepted is True


def test_turnstile_session_rejects_token_without_verifier_evidence() -> None:
    token = "turnstile-vendor-token-" + "x" * 40
    session = TurnstileChallengeSession(
        object(),
        token_reader=lambda: [token],
        network_events=[],
        verification_wait_ms=0,
    )

    result = _run(session)

    assert result.accepted is False
    assert result.verification.token_length == len(token)
    assert "turnstile_verifier_evidence_not_observed" in result.verification.gaps


def test_turnstile_vendor_pass_is_accepted_without_network_capture() -> None:
    token = "turnstile-vendor-token-" + "x" * 40
    session = TurnstileChallengeSession(
        object(),
        token_reader=lambda: [token],
        vendor_pass_reader=lambda: True,
        verification_wait_ms=0,
    )

    result = _run(session)

    assert result.accepted is True
    assert result.verification.vendor_pass is True
    assert result.verification.verifier_events == ()


def test_turnstile_site_verification_failure_is_not_hidden_by_token() -> None:
    token = "turnstile-vendor-token-" + "x" * 40
    session = TurnstileChallengeSession(
        object(),
        token_reader=lambda: [token],
        site_verification_reader=lambda: False,
        verification_wait_ms=0,
    )

    result = _run(session)

    assert result.accepted is False
    assert "turnstile_site_verification_failed" in result.verification.gaps


def test_turnstile_testing_token_is_rejected_even_when_demo_verifies_it() -> None:
    session = TurnstileChallengeSession(
        object(),
        token_reader=lambda: ["XXXX.DUMMY.TOKEN.XXXX"],
        site_verification_reader=lambda: True,
        verification_wait_ms=0,
    )

    result = _run(session)

    assert result.accepted is False
    assert "turnstile_test_token_rejected" in result.verification.gaps


def test_turnstile_defaults_are_provider_specific_and_stable() -> None:
    assert TURNSTILE_TOKEN_SELECTORS[0] == 'input[name="cf-turnstile-response"]'
    assert "/turnstile/" in TURNSTILE_VERIFIER_EVENT_MARKERS
    assert "siteverify" in TURNSTILE_VERIFIER_EVENT_MARKERS
