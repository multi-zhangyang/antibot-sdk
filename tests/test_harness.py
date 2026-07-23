import asyncio
import json
from types import SimpleNamespace

import pytest

from antibot_sdk.harness import (
    CaptchaHarness,
    HarnessBudget,
    HarnessDecision,
    HarnessTool,
    HarnessToolRegistry,
    PydanticAIPlanner,
    ReplayReport,
    evaluate_replays,
    evaluate_result,
)
from antibot_sdk.models import CaptchaResult


class _StaticPlanner:
    name = "static"

    def __init__(self, decision: HarnessDecision):
        self.decision = decision

    async def plan(self, _episode):
        return self.decision


class _RecordingAgent:
    def __init__(self, output):
        self.output = output
        self.prompt = None

    async def run(self, prompt):
        self.prompt = prompt
        return SimpleNamespace(output=self.output)


def test_harness_routes_provider_and_records_completed_episode() -> None:
    calls = []

    async def runner(target_url, provider, options):
        calls.append((target_url, provider, options))
        return CaptchaResult(
            provider=provider,
            ok=True,
            captcha_type="slider",
            capability="solver",
            ticket="vendor-ticket",
            diagnostics={
                "tencent_verification_responses": [
                    {"error_code": "0", "accepted": True}
                ]
            },
        )

    result = asyncio.run(
        CaptchaHarness(runner).solve(
            "https://cloud.tencent.com/product/captcha",
            provider="auto",
            options={"profile": "cloud_product"},
        )
    )

    assert result.ok is True
    assert calls == [
        (
            "https://cloud.tencent.com/product/captcha",
            "tencent",
            {"profile": "cloud_product"},
        )
    ]
    trace = result.diagnostics["harness"]
    assert trace["state"] == "completed"
    assert trace["provider_actions"] == 1
    assert trace["evidence"]["accepted"] is True
    assert [event["kind"] for event in trace["events"]] == [
        "request_observed",
        "planner_started",
        "plan_created",
        "tool_started",
        "provider_result_received",
        "evidence_evaluated",
    ]


def test_harness_requires_real_hcaptcha_vendor_evidence() -> None:
    async def runner(_target_url, _provider, _options):
        return CaptchaResult(
            provider="hcaptcha",
            ok=True,
            captcha_type="hcaptcha",
            capability="browser_flow",
            ticket="P1_" + "x" * 80,
            diagnostics={
                "hcaptcha_verification_responses": [
                    {"pass": False, "token_len": 0},
                ]
            },
        )

    result = asyncio.run(
        CaptchaHarness(runner).solve(
            "https://accounts.hcaptcha.com/demo",
            provider="hcaptcha",
        )
    )

    assert result.ok is False
    assert "hcaptcha_checkcaptcha_pass_true_not_observed" in result.errors
    assert result.diagnostics["harness"]["state"] == "failed"


def test_harness_requires_real_recaptcha_vendor_token() -> None:
    async def runner(_target_url, _provider, _options):
        return CaptchaResult(
            provider="recaptcha",
            ok=True,
            captcha_type="recaptcha_v2",
            capability="browser_flow",
            diagnostics={"challenge_visible": False},
        )

    result = asyncio.run(
        CaptchaHarness(runner).solve(
            "https://2captcha.com/demo/recaptcha-v2",
            provider="recaptcha",
        )
    )

    assert result.ok is False
    assert "recaptcha_vendor_token_not_captured" in result.errors


def test_harness_accepts_hcaptcha_pass_true_and_never_records_secret_options() -> None:
    received = {}

    async def runner(_target_url, _provider, options):
        received.update(options)
        return CaptchaResult(
            provider="hcaptcha",
            ok=True,
            captcha_type="hcaptcha",
            capability="browser_flow",
            ticket="P1_" + "v" * 80,
            diagnostics={
                "hcaptcha_verification_responses": [
                    {"pass": True, "token_len": 83},
                ],
                "site_verification": {"ok": True},
            },
        )

    secret = "sk-private-value"
    result = asyncio.run(
        CaptchaHarness(runner).solve(
            "https://accounts.hcaptcha.com/demo",
            provider="hcaptcha",
            options={
                "vision_api_key": secret,
                "proxy_server": "http://user:pass@proxy.test:8080",
            },
        )
    )

    assert result.ok is True
    assert received["vision_api_key"] == secret
    assert result.diagnostics["harness"]["evidence"]["vendor_pass"] is True
    assert result.diagnostics["harness"]["evidence"]["site_verified"] is True
    assert secret not in str(result.diagnostics["harness"])
    assert "user:pass" not in str(result.diagnostics["harness"])


def test_harness_persists_attached_episode_to_provider_output_json(tmp_path) -> None:
    output_json = tmp_path / "result.json"

    async def runner(_target_url, provider, _options):
        return CaptchaResult(
            provider=provider,
            ok=True,
            captcha_type="slider",
            capability="solver",
            ticket="vendor-ticket",
            artifacts={"output_json": str(output_json)},
            diagnostics={
                "tencent_verification_responses": [
                    {"error_code": "0", "accepted": True}
                ]
            },
        )

    result = asyncio.run(
        CaptchaHarness(runner).solve(
            "https://cloud.tencent.com/product/captcha",
            provider="tencent",
        )
    )
    persisted = json.loads(output_json.read_text(encoding="utf-8"))

    assert result.diagnostics["harness"]["state"] == "completed"
    assert persisted["diagnostics"]["harness"]["state"] == "completed"
    assert persisted["diagnostics"]["harness"]["evidence"]["accepted"] is True
    assert not list(tmp_path.glob(".*.tmp"))


def test_harness_rejects_planner_provider_outside_registered_tools() -> None:
    calls = 0

    async def runner(_target_url, _provider, _options):
        nonlocal calls
        calls += 1
        raise AssertionError("provider runner must not execute")

    planner = _StaticPlanner(
        HarnessDecision(action="solve_provider", provider="unregistered")
    )
    result = asyncio.run(
        CaptchaHarness(runner, planner=planner).solve(
            "https://example.test/captcha",
            provider="auto",
        )
    )

    assert result.ok is False
    assert calls == 0
    assert "provider is not registered" in result.errors[0]


def test_harness_enforces_total_timeout() -> None:
    async def runner(_target_url, _provider, _options):
        await asyncio.sleep(1)
        raise AssertionError("unreachable")

    result = asyncio.run(
        CaptchaHarness(
            runner,
            planner=_StaticPlanner(
                HarnessDecision(action="solve_provider", provider="tencent")
            ),
        ).solve(
            "https://example.test/captcha",
            provider="tencent",
            budget=HarnessBudget(timeout_sec=0.01),
        )
    )

    assert result.ok is False
    assert result.errors == ["harness timeout exhausted"]


def test_harness_tool_registry_rejects_duplicate_names() -> None:
    async def handler(_episode, _arguments):
        return None

    tools = HarnessToolRegistry()
    tool = HarnessTool("observe", "capture state", handler)
    tools.register(tool)

    with pytest.raises(ValueError, match="already registered"):
        tools.register(tool)


def test_pydantic_ai_planner_sends_only_routing_context() -> None:
    planner = object.__new__(PydanticAIPlanner)
    agent = _RecordingAgent(
        SimpleNamespace(
            action="solve_provider",
            provider="hcaptcha",
            strategy="provider_native",
            rationale="host match",
            confidence=0.99,
        )
    )
    planner._agent = agent
    episode = SimpleNamespace(
        request=SimpleNamespace(
            target_url="https://accounts.hcaptcha.com/demo?secret=not-for-planner",
            provider="auto",
        ),
        budget=SimpleNamespace(max_steps=6),
        steps=1,
    )

    decision = asyncio.run(planner.plan(episode))
    prompt = json.loads(agent.prompt)

    assert decision.provider == "hcaptcha"
    assert prompt["target"] == {"host": "accounts.hcaptcha.com", "path": "/demo"}
    assert "secret" not in agent.prompt


def test_pydantic_ai_planner_rejects_unregistered_provider_output() -> None:
    planner = object.__new__(PydanticAIPlanner)
    planner._agent = _RecordingAgent(
        SimpleNamespace(
            action="solve_provider",
            provider="arbitrary_tool",
            strategy="provider_native",
            rationale="invalid model choice",
            confidence=0.8,
        )
    )
    episode = SimpleNamespace(
        request=SimpleNamespace(target_url="https://example.test/captcha", provider="auto"),
        budget=SimpleNamespace(max_steps=6),
        steps=0,
    )

    decision = asyncio.run(planner.plan(episode))

    assert decision.action == "fail"
    assert decision.provider is None
    assert decision.confidence == 0.0


def test_replay_evaluator_keeps_multi_challenge_pass_attribution_ambiguous(
    tmp_path,
) -> None:
    payload = {
        "provider": "hcaptcha",
        "ok": True,
        "elapsed_ms": 38658,
        "diagnostics": {
            "hcaptcha_challenges": [
                {
                    "request_type": "image_drag_drop",
                    "shape_type": None,
                    "prompt": "drag the block",
                },
                {
                    "request_type": "image_label_area_select",
                    "shape_type": "point",
                    "prompt": "select by count",
                },
            ],
            "hcaptcha_verification_responses": [
                {"pass": False, "token_len": 0},
                {"pass": True, "token_len": 2107},
            ],
            "site_verification": {"ok": True},
            "challenge_engine": {
                "vision_tasks": [
                    {
                        "backend": {
                            "model": "vision-model",
                            "finish_reason": "stop",
                            "usage": {
                                "total_tokens": 588,
                                "completion_tokens": 31,
                            },
                        }
                    }
                ],
                "vision_canvas_alignment": [
                    {"score": 0.9964, "attempt_scores": [0.0441, 0.9964]}
                ],
            },
        },
    }
    result_path = tmp_path / "run" / "result.json"
    result_path.parent.mkdir()
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    run = evaluate_result(payload)
    report = evaluate_replays([tmp_path]).to_dict()

    assert run.evidence_accepted is True
    assert run.vendor_passes == 1
    assert run.vendor_failures == 1
    assert run.attribution == "multi_challenge_ambiguous"
    assert run.total_tokens == 588
    assert report["summary"]["alignment_poll_runs"] == 1
    assert report["challenge_matrix"]["image_drag_drop"][
        "single_challenge_vendor_pass_runs"
    ] == 0
    assert report["challenge_matrix"]["image_drag_drop"][
        "ambiguous_vendor_pass_runs"
    ] == 1


def test_replay_evaluator_reports_recaptcha_rounds_and_userverify() -> None:
    payload = {
        "provider": "recaptcha",
        "ok": True,
        "ticket": "token-value",
        "diagnostics": {
            "token_len": 11,
            "recaptcha_attempts": 2,
            "recaptcha_rounds": [
                {
                    "prompt": "Select all images with buses",
                    "candidate_count": 9,
                    "selected_count": 2,
                    "dynamic": True,
                    "refresh_observed": True,
                },
                {
                    "prompt": "Select all squares with motorcycles",
                    "candidate_count": 16,
                    "selected_count": 3,
                    "dynamic": False,
                    "action": "verify",
                },
            ],
            "site_verification": {"ok": True},
            "harness": {"evidence": {"accepted": True}},
        },
        "raw": {
            "token_len": 11,
            "events": [
                {"url": "https://www.google.com/recaptcha/api2/userverify", "status": 200}
            ],
        },
    }

    run = evaluate_result(payload)
    report = ReplayReport((run,)).to_dict()

    assert run.recaptcha_round_count == 2
    assert run.recaptcha_attempts == 2
    assert run.recaptcha_dynamic_rounds == 1
    assert run.recaptcha_refresh_count == 1
    assert run.recaptcha_action_labels == ("refresh", "verify")
    assert run.recaptcha_userverify_observed is True
    assert run.token_length == 11
    assert run.attribution == "multi_challenge_ambiguous"
    assert set(run.challenge_types) == {
        "recaptcha_image_grid:dynamic_3x3",
        "recaptcha_image_grid:static_4x4",
    }
    assert report["summary"]["recaptcha_userverify_runs"] == 1
    assert report["summary"]["recaptcha_rounds"] == 2
    assert report["challenge_matrix"]["recaptcha_image_grid:dynamic_3x3"][
        "evidence_accepted_runs"
    ] == 1
