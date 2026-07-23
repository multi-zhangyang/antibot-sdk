import asyncio

import pytest

from antibot_sdk.harness import (
    BenchmarkPolicy,
    CaptchaHarness,
    ChallengeActionRejected,
    ChallengeExecutor,
    CoveragePolicy,
    ChallengeAction,
    ChallengeAffordance,
    ChallengeCandidate,
    ChallengeObservation,
    EvidencePolicy,
    HarnessDecision,
    ProviderAdapter,
    ProviderAdapterRegistry,
    ReplayReport,
    default_adapter_registry,
    evaluate_result,
)
from antibot_sdk.models import BrowserResult, CaptchaResult
from antibot_sdk.vision import (
    StaticVisionBackend,
    VisionSolvePolicy,
    VisionAnswer,
    VisionPoint,
    VisionTask,
    solve_vision_task,
)


def _grid_observation() -> ChallengeObservation:
    return ChallengeObservation(
        observation_id="obs-grid-1",
        provider="generic-provider",
        kind="binary",
        modality="image",
        prompt="select matching objects",
        candidate_count=9,
        candidates=tuple(
            ChallengeCandidate(index=index, row=index // 3, column=index % 3)
            for index in range(9)
        ),
        grid_rows=3,
        grid_columns=3,
        min_answers=0,
        max_answers=9,
    )


def test_challenge_action_is_scoped_to_exact_observation() -> None:
    observation = _grid_observation()

    assert (
        ChallengeAction(
            observation_id=observation.observation_id,
            kind="select",
            payload={"selected": [0, 4, 8]},
            confidence=0.9,
        ).validate(observation)
        == ()
    )
    assert "action_observation_mismatch" in ChallengeAction(
        observation_id="stale-observation",
        kind="select",
        payload={"selected": [0]},
    ).validate(observation)
    assert "select_index_out_of_range" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="select",
        payload={"selected": [9]},
    ).validate(observation)
    assert "select_indexes_must_be_unique" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="select",
        payload={"selected": [1, 1]},
    ).validate(observation)
    assert "uncertain_action_must_not_answer_or_submit" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="select",
        payload={"selected": [0]},
        uncertain=True,
    ).validate(observation)


def test_challenge_geometry_and_choices_are_validated_generically() -> None:
    observation = ChallengeObservation(
        observation_id="obs-spatial-1",
        provider="generic-provider",
        kind="point",
        modality="image",
        width=320,
        height=200,
        choices=("left", "right"),
    )

    assert ChallengeAction(
        observation_id=observation.observation_id,
        kind="point",
        payload={"points": [{"x": 100, "y": 80}]},
    ).validate(observation) == ()
    assert "points_0_x_out_of_bounds" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="point",
        payload={"points": [{"x": 321, "y": 80}]},
    ).validate(observation)
    assert "choice_not_in_observation_choices" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="choice",
        payload={"choice": "center"},
    ).validate(observation)


def test_challenge_rejects_wrong_action_kind_stale_phase_and_edge_point() -> None:
    observation = ChallengeObservation(
        observation_id="obs-kind-1",
        provider="generic-provider",
        kind="point",
        modality="image",
        width=320,
        height=200,
        min_answers=2,
    )

    assert "action_kind_not_supported_for_observation" in ChallengeAction(
        observation_id=observation.observation_id,
        kind="select",
        payload={"selected": [0]},
    ).validate(observation)
    point_errors = ChallengeAction(
        observation_id=observation.observation_id,
        kind="point",
        payload={"points": [{"x": 320, "y": 80}]},
    ).validate(observation)
    assert "points_0_x_out_of_bounds" in point_errors
    assert "point_answer_count_below_minimum" in point_errors

    replaced = ChallengeObservation(
        observation_id="obs-replaced",
        provider="generic-provider",
        kind="point",
        modality="image",
        phase="replaced",
    )
    assert "observation_not_actionable" in ChallengeAction(
        observation_id=replaced.observation_id,
        kind="submit",
    ).validate(replaced)


def test_interactive_scene_actions_are_observation_scoped_and_capability_checked() -> None:
    observation = ChallengeObservation(
        observation_id="scene-1",
        provider="generic-browser",
        kind="interactive",
        modality="image",
        width=400,
        height=300,
        affordances=(
            ChallengeAffordance(
                affordance_id="input-0",
                role="textbox",
                label="answer",
                x=20,
                y=30,
                width=180,
                height=40,
                actions=("type", "press"),
            ),
            ChallengeAffordance(
                affordance_id="button-0",
                role="button",
                label="Verify",
                x=220,
                y=230,
                width=120,
                height=44,
                actions=("click",),
            ),
            ChallengeAffordance(
                affordance_id="disabled-0",
                role="button",
                label="Unavailable",
                enabled=False,
                actions=("click",),
            ),
        ),
        allowed_actions=("click", "type", "press", "wait", "fail"),
    )

    assert ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"affordance_id": "button-0"},
    ).validate(observation) == ()
    assert ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"point": {"x": 110, "y": 90}},
    ).validate(observation) == ()
    assert ChallengeAction(
        observation_id="scene-1",
        kind="type",
        payload={"affordance_id": "input-0", "text": "answer"},
    ).validate(observation) == ()
    assert ChallengeAction(
        observation_id="scene-1",
        kind="press",
        payload={"affordance_id": "input-0", "key": "Enter"},
    ).validate(observation) == ()
    assert ChallengeAction(
        observation_id="scene-1",
        kind="wait",
        payload={"milliseconds": 250},
    ).validate(observation) == ()

    disabled_errors = ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"affordance_id": "disabled-0"},
    ).validate(observation)
    assert "click_affordance_disabled" in disabled_errors
    assert "click_not_supported_by_affordance" in ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"affordance_id": "input-0"},
    ).validate(observation)
    assert "click_affordance_not_found" in ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"affordance_id": "stale-target"},
    ).validate(observation)
    assert "click_not_supported_by_affordance" in ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"affordance_id": "input-without-actions"},
    ).validate(
        ChallengeObservation(
            observation_id="scene-1b",
            provider="generic-browser",
            kind="interactive",
            modality="image",
            affordances=(
                ChallengeAffordance(
                    affordance_id="input-without-actions",
                    role="textbox",
                ),
            ),
            allowed_actions=("click", "fail"),
        )
    )
    assert "click_point_x_out_of_bounds" in ChallengeAction(
        observation_id="scene-1",
        kind="click",
        payload={"point": {"x": 401, "y": 90}},
    ).validate(observation)
    assert "action_kind_not_supported_for_observation" in ChallengeAction(
        observation_id="scene-1",
        kind="submit",
    ).validate(observation)


def test_interactive_scene_rejects_duplicate_or_out_of_bounds_affordances() -> None:
    duplicate = ChallengeAffordance(affordance_id="same", role="button")
    with pytest.raises(ValueError, match="ids must be unique"):
        ChallengeObservation(
            observation_id="scene-duplicate",
            provider="generic-browser",
            kind="interactive",
            modality="image",
            affordances=(duplicate, duplicate),
        )
    with pytest.raises(ValueError, match="exceeds observation width"):
        ChallengeObservation(
            observation_id="scene-bounds",
            provider="generic-browser",
            kind="interactive",
            modality="image",
            width=100,
            height=100,
            affordances=(
                ChallengeAffordance(
                    affordance_id="outside",
                    role="button",
                    x=80,
                    y=20,
                    width=30,
                    height=20,
                ),
            ),
        )


def test_challenge_executor_translates_and_records_vision_answer() -> None:
    diagnostics = {}
    executor = ChallengeExecutor(diagnostics)
    observation = ChallengeObservation(
        observation_id="obs-executor",
        provider="generic-provider",
        kind="point",
        modality="image",
        width=320,
        height=200,
        min_answers=1,
    )
    executor.observe(observation)

    result = executor.require_vision(
        observation,
        VisionAnswer(
            kind="point",
            points=(VisionPoint(x=120, y=80),),
            confidence=0.9,
        ),
    )

    assert result.valid is True
    assert diagnostics["challenge_actions"][0]["kind"] == "point"
    assert diagnostics["challenge_actions"][0]["payload"] == {
        "points": [{"x": 120, "y": 80}]
    }
    with pytest.raises(ChallengeActionRejected, match="vision_answer_kind_mismatch"):
        executor.require_vision(
            observation,
            VisionAnswer(kind="binary", selected=(0,)),
        )


def test_default_adapter_registry_resolves_aliases_and_evidence_policies() -> None:
    registry = default_adapter_registry()

    assert registry.resolve("Google_reCAPTCHA").provider == "recaptcha"
    assert registry.resolve("turnstile").provider == "cloudflare"
    assert registry.resolve("hcaptcha").evidence.require_vendor_pass is True
    assert registry.resolve("tencent").evidence.require_token is True
    assert registry.resolve("geetest").evidence.require_token is True
    assert set(registry.names()) >= {"hcaptcha", "recaptcha", "tencent"}


def test_default_adapter_registry_is_frozen_but_clone_is_extensible() -> None:
    from antibot_sdk.harness import DEFAULT_ADAPTER_REGISTRY

    with pytest.raises(RuntimeError, match="frozen"):
        DEFAULT_ADAPTER_REGISTRY.register(ProviderAdapter(provider="unexpected"))
    clone = DEFAULT_ADAPTER_REGISTRY.clone()
    clone.register(ProviderAdapter(provider="custom-extension"))
    assert clone.resolve("custom-extension") is not None


def test_adapter_evidence_policy_uses_declared_vendor_response_key() -> None:
    registry = ProviderAdapterRegistry(
        (
            ProviderAdapter(
                provider="declared-vendor",
                evidence=EvidencePolicy(
                    require_token=True,
                    require_vendor_pass=True,
                    vendor_response_key="declared_events",
                    vendor_pass_field="accepted",
                ),
            ),
        )
    )
    result = CaptchaResult(
        provider="declared-vendor",
        ok=True,
        ticket="vendor-token",
        diagnostics={"declared_events": [{"accepted": True}]},
    )

    verification = registry.verify_result(result, "declared-vendor")

    assert verification.accepted is True
    assert verification.vendor_pass is True
    assert verification.vendor_failures == 0


def test_adapter_registry_rejects_duplicate_aliases() -> None:
    registry = ProviderAdapterRegistry(
        (ProviderAdapter(provider="one", aliases=("shared",)),)
    )

    with pytest.raises(ValueError, match="already registered"):
        registry.register(ProviderAdapter(provider="two", aliases=("shared",)))


class _StaticPlanner:
    name = "static"

    async def plan(self, _episode):
        return HarnessDecision(action="solve_provider", provider="custom-captcha")


def test_harness_accepts_a_custom_provider_adapter_without_core_branching() -> None:
    adapters = ProviderAdapterRegistry(
        (
            ProviderAdapter(
                provider="custom-captcha",
                modalities=("image", "protocol"),
                challenge_kinds=("binary", "token"),
                evidence=EvidencePolicy(require_token=True),
            ),
        )
    )

    async def runner(_target_url, provider, _options):
        return CaptchaResult(
            provider=provider,
            ok=True,
            ticket="vendor-issued-token",
        )

    result = asyncio.run(
        CaptchaHarness(runner, planner=_StaticPlanner(), adapters=adapters).solve(
            "https://example.test/challenge",
            provider="custom-captcha",
        )
    )

    assert result.ok is True
    assert result.diagnostics["harness"]["adapter"] == "custom-captcha"
    assert result.diagnostics["harness"]["evidence"]["token_length"] == 19


class _AliasPlanner:
    name = "alias"

    async def plan(self, _episode):
        return HarnessDecision(action="solve_provider", provider="turnstile")


def test_harness_canonicalizes_adapter_alias_before_provider_execution() -> None:
    providers = []

    async def runner(_target_url, provider, _options):
        providers.append(provider)
        return BrowserResult(
            ok=True,
            state="clear",
            url="https://example.test/challenge",
            cf_clearance="clearance-" + "x" * 40,
        )

    result = asyncio.run(
        CaptchaHarness(runner, planner=_AliasPlanner()).solve(
            "https://example.test/challenge",
            provider="turnstile",
        )
    )

    assert result.ok is True
    assert providers == ["cloudflare"]
    assert result.diagnostics["harness"]["adapter"] == "cloudflare"


def test_cloudflare_adapter_rejects_clear_page_without_challenge_evidence() -> None:
    verification = default_adapter_registry().verify_result(
        BrowserResult(
            ok=True,
            state="clear",
            url="https://example.test/ordinary-page",
        ),
        "cloudflare",
    )

    assert verification.accepted is False
    assert "cloudflare_session_evidence_not_captured" in verification.gaps


def test_cloudflare_adapter_rejects_testing_token() -> None:
    verification = default_adapter_registry().verify_result(
        BrowserResult(
            ok=True,
            state="clear",
            url="https://example.test/turnstile-demo",
            turnstile_token="XXXX.DUMMY.TOKEN.XXXX",
            diagnostics={"site_verification": {"ok": True}},
        ),
        "turnstile",
    )

    assert verification.accepted is False
    assert "cloudflare_test_token_rejected" in verification.gaps


def test_shared_vision_policy_retries_and_recovers_without_provider_logic() -> None:
    task = VisionTask(
        kind="binary",
        prompt="select buses",
        images=(),
        candidate_count=9,
        min_answers=0,
        max_answers=9,
    )
    backend = StaticVisionBackend(
        [
            {"selected": [], "confidence": 0.1},
            {"selected": [2, 5], "confidence": 0.9},
        ]
    )
    diagnostics = {}

    outcome = asyncio.run(
        solve_vision_task(
            backend,
            task,
            policy=VisionSolvePolicy(
                min_confidence=0.35,
                retries=2,
                require_confidence=True,
            ),
            diagnostics=diagnostics,
        )
    )

    assert outcome.answer.selected == (2, 5)
    assert outcome.uncertain is False
    assert len(backend.calls) == 2
    assert diagnostics["vision_inference_retries"][0]["attempt"] == 2


def test_shared_vision_policy_returns_uncertain_only_for_safe_provider_fallback() -> None:
    task = VisionTask(
        kind="binary",
        prompt="select buses",
        images=(),
        candidate_count=9,
        min_answers=0,
        max_answers=9,
    )
    backend = StaticVisionBackend([{"selected": [], "confidence": 0.0}])

    outcome = asyncio.run(
        solve_vision_task(
            backend,
            task,
            policy=VisionSolvePolicy(
                retries=1,
                require_confidence=True,
                allow_uncertain=True,
            ),
        )
    )

    assert outcome.uncertain is True
    assert outcome.answer.selected == ()


def test_replay_matrix_prefers_provider_neutral_observations_and_actions() -> None:
    payload = {
        "provider": "custom-captcha",
        "ok": False,
        "diagnostics": {
            "challenge_observations": [
                {
                    "schema_version": 1,
                    "observation_id": "obs-1",
                    "provider": "custom-captcha",
                    "kind": "binary",
                    "modality": "image",
                    "prompt": "select buses",
                    "grid_rows": 3,
                    "grid_columns": 3,
                    "dynamic": True,
                },
                {
                    "schema_version": 1,
                    "observation_id": "obs-2",
                    "provider": "custom-captcha",
                    "kind": "point",
                    "modality": "image",
                    "prompt": "click the center",
                    "metadata": {"shape_type": "point"},
                },
            ],
            "challenge_actions": [
                {
                    "observation_id": "obs-1",
                    "kind": "select",
                    "payload": {"selected": []},
                    "valid": True,
                    "executed": True,
                },
                {
                    "observation_id": "obs-2",
                    "kind": "point",
                    "valid": False,
                    "executed": False,
                    "errors": ["points_0_x_out_of_bounds"],
                },
            ],
            "harness": {"adapter": "custom-captcha", "evidence": {"accepted": False}},
        },
    }

    run = evaluate_result(payload)
    report = ReplayReport((run,)).to_dict()

    assert run.challenge_types == (
        "image:binary:dynamic_3x3",
        "image:point:point",
    )
    assert run.observation_count == 2
    assert run.action_count == 2
    assert run.invalid_action_count == 1
    assert run.executed_action_count == 1
    assert run.unexecuted_action_count == 1
    assert run.modalities == ("image",)
    assert run.normalized_kinds == ("binary", "point")
    assert run.adapter == "custom-captcha"
    assert report["summary"]["normalized_observations"] == 2
    assert report["summary"]["invalid_actions"] == 1


def test_replay_reads_recaptcha_session_rounds_and_preserves_action_trace() -> None:
    payload = {
        "provider": "recaptcha",
        "ok": True,
        "diagnostics": {
            "token_len": 120,
            "recaptcha_session_observations": [
                {
                    "observation_id": "session-obs-1",
                    "prompt": "Select all images with buses",
                    "candidate_count": 9,
                    "dynamic": False,
                    "phase": "presented",
                    "action": "select",
                },
                {
                    "observation_id": "session-obs-2",
                    "prompt": "Select all images with buses",
                    "candidate_count": 9,
                    "dynamic": False,
                    "phase": "answering",
                    "action": "submit",
                },
            ],
            "challenge_observations": [
                {
                    "observation_id": "session-obs-1",
                    "provider": "recaptcha",
                    "kind": "binary",
                    "modality": "image",
                    "prompt": "Select all images with buses",
                    "candidate_count": 9,
                    "min_answers": 0,
                    "max_answers": 9,
                    "grid_rows": 3,
                    "grid_columns": 3,
                },
                {
                    "observation_id": "session-obs-2",
                    "provider": "recaptcha",
                    "kind": "binary",
                    "modality": "image",
                    "prompt": "Select all images with buses",
                    "candidate_count": 9,
                    "min_answers": 0,
                    "max_answers": 9,
                    "grid_rows": 3,
                    "grid_columns": 3,
                    "phase": "answering",
                },
            ],
            "challenge_actions": [
                {
                    "observation_id": "session-obs-1",
                    "kind": "select",
                    "payload": {"selected": [2]},
                    "valid": True,
                    "executed": True,
                },
                {
                    "observation_id": "session-obs-2",
                    "kind": "submit",
                    "payload": {},
                    "valid": True,
                    "executed": True,
                },
            ],
        },
        "raw": {
            "events": [{"url": "https://www.google.com/recaptcha/api2/userverify"}]
        },
    }

    run = evaluate_result(payload)

    assert run.evidence_accepted is True
    assert run.recaptcha_round_count == 1
    assert run.recaptcha_action_labels == ("select", "submit")
    assert run.vision_task_count == 1
    assert run.executed_action_count == 2


def test_replay_reports_generic_interactive_affordances_actions_and_scene_replacements() -> None:
    payload = {
        "provider": "new-vendor",
        "ok": True,
        "diagnostics": {
            "challenge_observations": [
                {
                    "observation_id": "interactive-1",
                    "provider": "new-vendor",
                    "kind": "interactive",
                    "modality": "image",
                    "prompt": "Enter the code",
                    "width": 400,
                    "height": 300,
                    "affordances": [
                        {
                            "affordance_id": "input",
                            "role": "textbox",
                            "actions": ["type", "press"],
                            "x": 10,
                            "y": 10,
                            "width": 100,
                            "height": 30,
                        },
                        {
                            "affordance_id": "verify",
                            "role": "button",
                            "actions": ["click"],
                            "x": 200,
                            "y": 200,
                            "width": 80,
                            "height": 30,
                        },
                    ],
                    "allowed_actions": ["type", "press", "click", "wait", "fail"],
                },
                {
                    "observation_id": "interactive-2",
                    "provider": "new-vendor",
                    "kind": "interactive",
                    "modality": "image",
                    "prompt": "Enter the code",
                    "width": 400,
                    "height": 300,
                    "dynamic": True,
                    "affordances": [
                        {
                            "affordance_id": "verify",
                            "role": "button",
                            "actions": ["click"],
                            "x": 200,
                            "y": 200,
                            "width": 80,
                            "height": 30,
                        }
                    ],
                    "allowed_actions": ["click", "fail"],
                },
            ],
            "challenge_actions": [
                {
                    "observation_id": "interactive-1",
                    "kind": "type",
                    "payload": {"affordance_id": "input", "text": "7"},
                    "valid": True,
                    "executed": True,
                },
                {
                    "observation_id": "interactive-2",
                    "kind": "click",
                    "payload": {"affordance_id": "verify"},
                    "valid": True,
                    "executed": True,
                },
            ],
            "action_planning_outcomes": [
                {
                    "observation_id": "interactive-1",
                    "backend": {"backend": "static_action"},
                    "errors": [],
                }
            ],
            "session": {
                "browser_scene_replacements": 1,
                "browser_scene_observations": [
                    {"dynamic": False},
                    {"dynamic": True},
                ],
            },
            "harness": {"adapter": "new-vendor", "evidence": {"accepted": True}},
        },
    }

    run = evaluate_result(payload)
    report = ReplayReport((run,)).to_dict()

    assert run.normalized_kinds == ("interactive",)
    assert run.affordance_count == 3
    assert run.affordance_roles == ("textbox", "button")
    assert run.action_kinds == ("type", "click")
    assert run.action_planner_backends == ("static_action",)
    assert run.dynamic_scene_replacement_count == 1
    assert run.action_planning_error_count == 0
    assert report["summary"]["affordances"] == 3
    assert report["summary"]["dynamic_scene_replacements"] == 1
    assert report["summary"]["action_planner_backends"] == ["static_action"]


def test_replay_uses_browser_session_diagnostics_as_legacy_interactive_fallback() -> None:
    run = evaluate_result(
        {
            "provider": "new-vendor",
            "ok": False,
            "diagnostics": {
                "session": {
                    "browser_scene_observations": [
                        {
                            "prompt": "Click the matching symbol",
                            "affordance_count": 2,
                            "dynamic": False,
                        },
                        {
                            "prompt": "Click the matching symbol",
                            "affordance_count": 1,
                            "dynamic": True,
                        },
                    ],
                    "browser_scene_replacements": 1,
                }
            },
        }
    )

    assert run.challenge_types == ("image:interactive",)
    assert run.normalized_kinds == ("interactive",)
    assert run.modalities == ("image",)
    assert run.observation_count == 2
    assert run.vision_task_count == 2
    assert run.affordance_count == 3
    assert run.dynamic_scene_replacement_count == 1


def _benchmark_payload(index: int, *, accepted: bool = True) -> dict:
    prompts = ("select buses", "select cars", "select bicycles")
    return {
        "provider": "benchmark-vendor",
        "ok": accepted,
        "diagnostics": {
            "challenge_observations": [
                {
                    "observation_id": f"benchmark-observation-{index}",
                    "provider": "benchmark-vendor",
                    "kind": "binary",
                    "modality": "image",
                    "prompt": prompts[index % len(prompts)],
                }
            ],
            "challenge_actions": [
                {
                    "observation_id": f"benchmark-observation-{index}",
                    "kind": "select",
                    "payload": {"selected": []},
                    "valid": True,
                    "executed": accepted,
                    "uncertain": False,
                }
            ],
            "harness": {
                "adapter": "benchmark-vendor",
                "evidence": {"accepted": accepted},
            },
        },
    }


def test_benchmark_gate_requires_independent_clean_evidence_runs_and_target_rate() -> None:
    runs = tuple(
        evaluate_result(_benchmark_payload(index), source=f"benchmark-{index}.json")
        for index in range(20)
    )
    report = ReplayReport(runs)
    assessment = report.assess_benchmark(
        "benchmark-vendor",
        BenchmarkPolicy(min_runs=20, min_prompt_families=3, min_challenge_instances=20),
    )

    assert assessment.qualified is True
    assert assessment.status == "qualified"
    assert assessment.success_rate == 1.0
    assert assessment.independent_runs == 20
    assert report.to_dict()["benchmark"]["benchmark-vendor"]["status"] == "qualified"

    failed_runs = tuple(
        evaluate_result(
            _benchmark_payload(index, accepted=index < 18),
            source=f"benchmark-failed-{index}.json",
        )
        for index in range(20)
    )
    failed = ReplayReport(failed_runs).assess_benchmark(
        "benchmark-vendor",
        BenchmarkPolicy(min_runs=20, min_prompt_families=3, min_challenge_instances=20),
    )
    assert failed.qualified is False
    assert failed.status == "failed"
    assert "success_rate_below_target" in failed.reasons


def test_benchmark_gate_does_not_count_duplicate_sources_as_independent_runs() -> None:
    runs = tuple(
        evaluate_result(_benchmark_payload(index), source="same-run.json")
        for index in range(20)
    )
    assessment = ReplayReport(runs).assess_benchmark(
        "benchmark-vendor",
        BenchmarkPolicy(min_runs=2, min_prompt_families=3, min_challenge_instances=2),
    )

    assert assessment.independent_runs == 1
    assert assessment.status == "insufficient_samples"
    assert assessment.qualified is False
    assert "insufficient_independent_runs" in assessment.reasons


def test_challenge_benchmark_qualifies_fixed_slider_without_qualifying_platform() -> None:
    runs = []
    for index in range(20):
        payload = _benchmark_payload(index)
        observation = payload["diagnostics"]["challenge_observations"][0]
        observation["kind"] = "slider"
        observation["prompt"] = "Align the puzzle piece with the missing slot"
        action = payload["diagnostics"]["challenge_actions"][0]
        action["kind"] = "drag"
        action["payload"] = {
            "paths": [
                {
                    "start": {"x": 10, "y": 20},
                    "end": {"x": 100 + index, "y": 20},
                }
            ]
        }
        runs.append(evaluate_result(payload, source=f"slider-{index}.json"))

    report = ReplayReport(tuple(runs))
    platform = report.assess_benchmark("benchmark-vendor")
    scoped = report.assess_challenge_benchmark("benchmark-vendor", "image:slider")

    assert platform.qualified is False
    assert "insufficient_prompt_families" in platform.reasons
    assert "insufficient_challenge_families" in platform.reasons
    assert scoped.qualified is True
    assert scoped.independent_runs == 20
    assert scoped.success_rate == 1.0


def test_platform_benchmark_accepts_two_real_families_as_diversity() -> None:
    runs = []
    for index in range(40):
        payload = _benchmark_payload(index)
        observation = payload["diagnostics"]["challenge_observations"][0]
        action = payload["diagnostics"]["challenge_actions"][0]
        if index < 20:
            observation["kind"] = "slider"
            observation["prompt"] = "Align the puzzle piece with the missing slot"
            action["kind"] = "drag"
            action["payload"] = {
                "paths": [
                    {
                        "start": {"x": 10, "y": 20},
                        "end": {"x": 100 + index, "y": 20},
                    }
                ]
            }
        else:
            observation["kind"] = "point"
            observation["prompt"] = ""
            observation["min_answers"] = 1
            observation["max_answers"] = 1
            observation["width"] = 300
            observation["height"] = 200
            action["kind"] = "point"
            action["payload"] = {"points": [{"x": 50, "y": 60}]}
        runs.append(evaluate_result(payload, source=f"two-family-{index}.json"))

    assessment = ReplayReport(tuple(runs)).assess_benchmark("benchmark-vendor")

    assert assessment.qualified is True
    assert assessment.challenge_families == 2
    assert assessment.success_rate == 1.0


def test_replay_coverage_does_not_call_one_sample_generalized() -> None:
    payload = {
        "provider": "custom-captcha",
        "ok": True,
        "diagnostics": {
            "challenge_observations": [
                {
                    "observation_id": "obs-coverage",
                    "provider": "custom-captcha",
                    "kind": "binary",
                    "modality": "image",
                    "prompt": "select buses",
                }
            ],
            "challenge_actions": [
                {
                    "observation_id": "obs-coverage",
                    "kind": "select",
                    "payload": {"selected": []},
                    "valid": True,
                    "executed": False,
                }
            ],
            "harness": {"adapter": "custom-captcha", "evidence": {"accepted": True}},
        },
    }

    report = ReplayReport((evaluate_result(payload),))
    coverage = report.assess_coverage()

    assert coverage.generalized is False
    assert coverage.status == "live_verified_limited_matrix"
    assert "insufficient_independent_runs" in coverage.reasons


def test_replay_evidence_fallback_requires_provider_material() -> None:
    cloudflare = evaluate_result(
        {
            "provider": "cloudflare",
            "ok": True,
            "turnstile_token": "XXXX.DUMMY.TOKEN.XXXX",
        }
    )
    clear = evaluate_result(
        {
            "provider": "cloudflare",
            "ok": True,
            "cf_clearance": "clearance-" + "x" * 24,
        }
    )
    tencent = evaluate_result(
        {
            "provider": "tencent",
            "ok": True,
            "ticket": "vendor-ticket",
            "diagnostics": {
                "tencent_verification_responses": [
                    {"error_code": "0", "accepted": True}
                ]
            },
        }
    )
    tencent_without_verify = evaluate_result(
        {"provider": "tencent", "ok": True, "ticket": "vendor-ticket"}
    )

    assert cloudflare.evidence_accepted is False
    assert clear.evidence_accepted is True
    assert tencent.evidence_accepted is True
    assert tencent_without_verify.evidence_accepted is False


def test_replay_recovers_cloudflare_provider_and_clearance_from_harness_result() -> None:
    clearance = "clearance-" + "x" * 40
    run = evaluate_result(
        {
            "ok": True,
            "state": "clear",
            "cf_clearance": clearance,
            "diagnostics": {
                "harness": {
                    "adapter": "cloudflare",
                    "evidence": {"accepted": True},
                }
            },
        },
        source="cloudflare-harness.json",
    )

    assert run.provider == "cloudflare"
    assert run.evidence_accepted is True
    assert run.token_length == len(clearance)


def test_replay_coverage_requires_clean_matrix_before_generalized() -> None:
    runs = []
    for index, prompt in enumerate(("select buses", "select cars", "select bicycles")):
        runs.append(
            evaluate_result(
                {
                    "provider": "custom-captcha",
                    "ok": True,
                    "diagnostics": {
                        "challenge_observations": [
                            {
                                "observation_id": f"obs-{index}",
                                "provider": "custom-captcha",
                                "kind": "binary",
                                "modality": "image",
                                "prompt": prompt,
                                "candidate_count": 1,
                                "min_answers": 0,
                                "max_answers": 1,
                            }
                        ],
                        "challenge_actions": [
                            {
                                "observation_id": f"obs-{index}",
                                "kind": "select",
                                "payload": {
                                    "selected": [2] if index == 2 else []
                                },
                                "valid": index != 2,
                                "executed": index != 2,
                            }
                        ],
                        "harness": {
                            "adapter": "custom-captcha",
                            "evidence": {"accepted": True},
                        },
                    },
                }
            )
        )

    report = ReplayReport(tuple(runs))
    assert report.assess_coverage().generalized is False
    assert "invalid_actions_observed" in report.assess_coverage().reasons
    assert report.assess_coverage(
        CoveragePolicy(min_runs=3, min_prompt_families=2, min_challenge_instances=3, min_evidence_runs=3)
    ).status == "live_verified_limited_matrix"


def test_replay_coverage_marks_only_complete_clean_matrix_generalized() -> None:
    runs = tuple(
        evaluate_result(
            {
                "provider": "custom-captcha",
                "ok": True,
                "diagnostics": {
                    "challenge_observations": [
                        {
                            "observation_id": f"clean-{index}",
                            "provider": "custom-captcha",
                            "kind": "binary",
                            "modality": "image",
                            "prompt": prompt,
                        }
                    ],
                    "challenge_actions": [
                        {
                            "observation_id": f"clean-{index}",
                            "kind": "select",
                            "payload": {"selected": []},
                            "valid": True,
                            "executed": True,
                            "uncertain": False,
                        }
                    ],
                    "harness": {
                        "adapter": "custom-captcha",
                        "evidence": {"accepted": True},
                    },
                },
            }
        )
        for index, prompt in enumerate(("select buses", "select cars", "select bicycles"))
    )

    coverage = ReplayReport(runs).assess_coverage()

    assert coverage.generalized is True
    assert coverage.status == "generalized"
    assert coverage.reasons == ()


def test_replay_independently_rejects_tampered_valid_and_executed_flags() -> None:
    run = evaluate_result(
        {
            "provider": "custom-captcha",
            "ok": True,
            "diagnostics": {
                "challenge_observations": [
                    {
                        "observation_id": "tampered-1",
                        "provider": "custom-captcha",
                        "kind": "binary",
                        "modality": "image",
                        "candidate_count": 1,
                    }
                ],
                "challenge_actions": [
                    {
                        "observation_id": "tampered-1",
                        "kind": "select",
                        "payload": {"selected": [3]},
                        "valid": True,
                        "executed": True,
                    }
                ],
                "harness": {"evidence": {"accepted": True}},
            },
        }
    )

    assert run.invalid_action_count == 1
    assert run.executed_action_count == 0
    assert run.unexecuted_action_count == 1
    assert any("recorded_validity_mismatch" in item for item in run.trace_integrity_errors)
    assert any("invalid_action_marked_executed" in item for item in run.trace_integrity_errors)
    coverage = ReplayReport((run,)).assess_coverage()
    assert "trace_integrity_errors_observed" in coverage.reasons
