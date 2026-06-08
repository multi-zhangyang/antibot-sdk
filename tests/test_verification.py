import asyncio

from antibot_sdk.verification import FailureClassifier, SubmitFlow, verify_submit_flow


def test_failure_classifier_common_reasons():
    cls, reason = FailureClassifier.classify(
        token="tok_" + "A" * 32,
        raw={"body": "invalid-input-response"},
    )
    assert cls == "token_rejected"
    assert "token" in reason

    cls, _ = FailureClassifier.classify(
        token="tok_" + "A" * 32,
        raw={"body": "score too low"},
    )
    assert cls == "low_score"


def test_verify_submit_flow_without_token_fails_fast(tmp_path):
    ret = asyncio.run(
        verify_submit_flow(
            SubmitFlow(
                provider="recaptcha",
                url="file:///tmp/nonexistent.html",
                output_dir=str(tmp_path),
            )
        )
    )
    assert not ret.ok
    assert not ret.token_collected
    assert ret.failure_class == "token_missing"
    assert ret.artifacts["out"].endswith("verification_run.json")
