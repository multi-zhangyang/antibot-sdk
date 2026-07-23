import asyncio
import json

from antibot_sdk.harness import (
    ChallengeAction,
    ChallengeAffordance,
    ChallengeAgentLoop,
    CaptchaHarness,
    ChallengeLoopResult,
    ChallengeSession,
    ChallengeStrategyRegistry,
    StaticActionPlanningBackend,
    TokenChallengeSession,
    VisionChallengePolicy,
)
from antibot_sdk.harness.contracts import ChallengeObservation, VendorVerification
from antibot_sdk.vision import StaticVisionBackend, VisionSolvePolicy, VisionTask


class _Session:
    def __init__(self, observations, tasks, *, accepted=True):
        self.observations = list(observations)
        self.tasks = dict(tasks)
        self.actions = []
        self.verify_calls = 0
        self.accepted = accepted

    async def observe(self):
        return self.observations.pop(0) if self.observations else None

    async def vision_task(self, observation):
        return self.tasks.get(observation.observation_id)

    async def execute(self, action):
        self.actions.append(action)

    async def verify(self):
        self.verify_calls += 1
        return VendorVerification(
            provider="generic-provider",
            accepted=self.accepted,
            token_length=32 if self.accepted else 0,
            gaps=() if self.accepted else ("vendor_pass_not_observed",),
        )


class _DiagnosticSession(_Session):
    def __init__(self, observations, tasks):
        super().__init__(observations, tasks)
        self.diagnostics = {"events": []}

    async def execute(self, action):
        await super().execute(action)
        self.diagnostics["events"].append({"kind": action.kind})


def _binary_observation(observation_id: str, *, phase: str = "presented"):
    return ChallengeObservation(
        observation_id=observation_id,
        provider="generic-provider",
        kind="binary",
        modality="image",
        prompt="select buses",
        candidate_count=3,
        min_answers=1,
        max_answers=1,
        phase=phase,
    )


def test_agent_loop_reobserves_after_dynamic_answer_before_submit() -> None:
    first = _binary_observation("obs-1")
    answering = _binary_observation("obs-2", phase="answering")
    session = _Session(
        [first, answering],
        {
            "obs-1": VisionTask(
                kind="binary",
                prompt="select buses",
                images=(),
                candidate_count=3,
                min_answers=1,
                max_answers=1,
            )
        },
    )
    backend = StaticVisionBackend([{"selected": [1], "confidence": 0.9}])
    assert isinstance(session, ChallengeSession)

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(backend),
            max_steps=4,
        ).run()
    )

    assert result.accepted is True
    assert result.status == "verified"
    assert [action.kind for action in session.actions] == ["select", "submit"]
    assert result.diagnostics["challenge_actions"][0]["executed"] is True
    assert result.diagnostics["challenge_actions"][1]["executed"] is True
    assert [item["observation_id"] for item in result.diagnostics["challenge_observations"]] == [
        "obs-1",
        "obs-2",
    ]


def test_agent_loop_session_diagnostics_snapshot_is_json_serializable() -> None:
    observation = _binary_observation("diagnostic-1")
    session = _DiagnosticSession(
        [observation],
        {
            "diagnostic-1": VisionTask(
                kind="binary",
                prompt="select buses",
                images=(),
                candidate_count=3,
                min_answers=1,
                max_answers=1,
            )
        },
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([{"selected": [1], "confidence": 0.9}])
            ),
            max_steps=3,
        ).run()
    )

    assert result.diagnostics["session"] is not session.diagnostics
    assert result.diagnostics["session"]["events"] == [{"kind": "select"}]
    json.dumps(result.to_dict())


def test_agent_loop_continues_when_submit_produces_replacement_challenge() -> None:
    observations = [
        _binary_observation("replace-1"),
        _binary_observation("replace-2", phase="answering"),
        _binary_observation("replace-3"),
        _binary_observation("replace-4", phase="answering"),
    ]
    tasks = {
        observation_id: VisionTask(
            kind="binary",
            prompt="select buses",
            images=(),
            candidate_count=3,
            min_answers=1,
            max_answers=1,
        )
        for observation_id in ("replace-1", "replace-3")
    }
    session = _Session(observations, tasks)
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend(
                    [
                        {"selected": [0], "confidence": 0.9},
                        {"selected": [2], "confidence": 0.9},
                    ]
                )
            ),
            max_steps=6,
        ).run()
    )

    assert result.accepted is True
    assert [action.kind for action in session.actions] == [
        "select",
        "submit",
        "select",
        "submit",
    ]
    assert result.steps == 4


def test_agent_loop_unknown_challenge_is_explicit_unsupported_failure() -> None:
    observation = ChallengeObservation(
        observation_id="unknown-1",
        provider="new-vendor",
        kind="unknown",
        modality="image",
        prompt="new challenge family",
    )
    session = _Session([observation], {})
    backend = StaticVisionBackend([])

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(backend),
            max_steps=2,
        ).run()
    )

    assert isinstance(result, ChallengeLoopResult)
    assert result.status == "unsupported"
    assert result.accepted is False
    assert session.actions == []
    assert result.diagnostics["challenge_actions"][0]["kind"] == "fail"
    assert result.diagnostics["challenge_actions"][0]["executed"] is False
    assert "challenge kind is not registered" in result.errors[0]


def test_custom_strategy_adds_slider_without_agent_loop_branch() -> None:
    presented = ChallengeObservation(
        observation_id="slider-1",
        provider="new-vendor",
        kind="slider",
        modality="image",
        width=300,
        height=120,
    )
    answering = ChallengeObservation(
        observation_id="slider-2",
        provider="new-vendor",
        kind="slider",
        modality="image",
        width=300,
        height=120,
        phase="answering",
    )
    session = _Session([presented, answering], {})
    strategies = ChallengeStrategyRegistry()

    async def slider_strategy(_session, observation, _diagnostics):
        return ChallengeAction(
            observation_id=observation.observation_id,
            kind="drag",
            payload={
                "paths": [
                    {
                        "start": {"x": 20, "y": 60},
                        "end": {"x": 230, "y": 60},
                    }
                ]
            },
        )

    strategies.register("slider", slider_strategy)
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([]), strategies=strategies),
            max_steps=3,
        ).run()
    )

    assert result.accepted is True
    assert [action.kind for action in session.actions] == ["drag", "submit"]
    assert strategies.names() == ("slider",)


def test_agent_loop_rejects_reused_observation_after_action() -> None:
    observation = _binary_observation("stale-1")
    session = _Session(
        [observation, observation],
        {
            "stale-1": VisionTask(
                kind="binary",
                prompt="select buses",
                images=(),
                candidate_count=3,
                min_answers=1,
                max_answers=1,
            )
        },
        accepted=False,
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([{"selected": [1], "confidence": 0.9}])
            ),
            max_steps=3,
        ).run()
    )

    assert result.status == "failed"
    assert "stale_observation_repeated_after_action" in result.errors
    assert len(session.actions) == 1


def test_captcha_harness_exposes_session_mode_without_provider_runner() -> None:
    first = _binary_observation("session-1")
    answering = _binary_observation("session-2", phase="answering")
    session = _Session(
        [first, answering],
        {
            "session-1": VisionTask(
                kind="binary",
                prompt="select buses",
                images=(),
                candidate_count=3,
                min_answers=1,
                max_answers=1,
            )
        },
    )
    result = asyncio.run(
        CaptchaHarness().solve_session(
            session,
            StaticVisionBackend([{"selected": [1], "confidence": 0.9}]),
        )
    )

    assert result.accepted is True
    assert [action.kind for action in session.actions] == ["select", "submit"]


def test_token_session_uses_real_token_reader_and_submitter() -> None:
    state = {"token": ""}
    diagnostics = {}

    async def read_tokens():
        return [state["token"]] if state["token"] else []

    async def submit():
        state["token"] = "turnstile-token-" + "x" * 40

    session = TokenChallengeSession(
        object(),
        provider="cloudflare",
        token_reader=read_tokens,
        submitter=submit,
        vendor_pass_reader=lambda: True,
        verifier_event_markers=("/turnstile/",),
        network_events=[{"url": "https://challenges.cloudflare.com/turnstile/verify"}],
        diagnostics=diagnostics,
        verification_wait_ms=0,
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([])),
            max_steps=3,
        ).run()
    )

    assert result.accepted is True
    assert result.verification.vendor_pass is True
    assert result.verification.verifier_events == ("/turnstile/",)
    assert result.diagnostics["challenge_actions"][0]["kind"] == "submit"
    assert result.diagnostics["challenge_actions"][0]["executed"] is True
    assert diagnostics["token_session_verification"]["token_length"] == len(state["token"])
    assert result.diagnostics["harness"]["evidence"]["token_length"] == len(state["token"])


def test_token_session_without_vendor_token_is_an_explicit_failure() -> None:
    session = TokenChallengeSession(
        object(),
        provider="recaptcha",
        token_reader=lambda: [],
        verification_wait_ms=0,
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([])),
            max_steps=2,
        ).run()
    )

    assert result.accepted is False
    assert result.verification.gaps == ("recaptcha_vendor_token_not_captured",)


def _interactive_observation(
    observation_id: str,
    affordances: tuple[ChallengeAffordance, ...],
    *,
    kind: str = "interactive",
    allowed_actions: tuple[str, ...] = ("click", "type", "press", "wait", "fail"),
) -> ChallengeObservation:
    return ChallengeObservation(
        observation_id=observation_id,
        provider="unrecognized-provider",
        kind=kind,
        modality="image",
        prompt="Complete the visible interaction",
        width=400,
        height=300,
        affordances=affordances,
        allowed_actions=allowed_actions,
    )


def test_generic_action_backend_runs_multistep_scene_without_provider_strategy() -> None:
    observations = [
        _interactive_observation(
            "scene-step-1",
            (
                ChallengeAffordance(
                    affordance_id="next",
                    role="button",
                    label="Next",
                    actions=("click",),
                ),
            ),
        ),
        _interactive_observation(
            "scene-step-2",
            (
                ChallengeAffordance(
                    affordance_id="answer",
                    role="textbox",
                    label="Answer",
                    actions=("type", "press"),
                ),
            ),
        ),
        _interactive_observation(
            "scene-step-3",
            (
                ChallengeAffordance(
                    affordance_id="verify",
                    role="button",
                    label="Verify",
                    actions=("click",),
                ),
            ),
        ),
    ]
    tasks = {
        item.observation_id: VisionTask(
            kind="interactive",
            prompt=item.prompt,
            images=(),
            width=item.width,
            height=item.height,
        )
        for item in observations
    }
    session = _Session(observations, tasks)
    action_backend = StaticActionPlanningBackend(
        [
            {
                "action": "click",
                "payload": {"affordance_id": "next"},
                "confidence": 0.95,
            },
            {
                "action": "type",
                "payload": {"affordance_id": "answer", "text": "7"},
                "confidence": 0.93,
            },
            {
                "action": "click",
                "payload": {"affordance_id": "verify"},
                "confidence": 0.97,
            },
        ]
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=action_backend,
            ),
            max_steps=5,
        ).run()
    )

    assert result.accepted is True
    assert [action.kind for action in session.actions] == ["click", "type", "click"]
    assert all(item["executed"] for item in result.diagnostics["challenge_actions"])
    assert len(action_backend.calls) == 3


def test_generic_action_backend_handles_unknown_structure_via_declared_actions() -> None:
    observation = _interactive_observation(
        "unknown-scene-1",
        (
            ChallengeAffordance(
                affordance_id="novel-control",
                role="switch",
                label="Continue",
                actions=("click",),
            ),
        ),
        kind="unknown",
        allowed_actions=("click", "reload", "fail"),
    )
    session = _Session(
        [observation],
        {
            observation.observation_id: VisionTask(
                kind="interactive",
                prompt=observation.prompt,
                images=(),
                width=400,
                height=300,
            )
        },
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=StaticActionPlanningBackend(
                    [
                        {
                            "action": "click",
                            "payload": {"affordance_id": "novel-control"},
                            "confidence": 0.9,
                        }
                    ]
                ),
            ),
            max_steps=2,
        ).run()
    )

    assert result.accepted is True
    assert session.actions[0].kind == "click"


def test_unknown_structure_without_affordances_fails_without_calling_model() -> None:
    observation = _interactive_observation(
        "unknown-empty",
        (),
        kind="unknown",
        allowed_actions=("reload", "fail"),
    )
    session = _Session(
        [observation],
        {
            observation.observation_id: VisionTask(
                kind="interactive",
                prompt=observation.prompt,
                images=(),
                width=400,
                height=300,
            )
        },
        accepted=False,
    )
    backend = StaticActionPlanningBackend(
        [{"action": "reload", "payload": {}, "confidence": 0.99}]
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([]), action_backend=backend),
            max_steps=2,
        ).run()
    )

    assert result.status == "unsupported"
    assert session.actions == []
    assert backend.calls == []
    assert "unknown observation has no declared affordances" in result.errors


def test_invalid_model_action_payload_is_retried_and_never_executed() -> None:
    observation = _interactive_observation(
        "invalid-model-action",
        (
            ChallengeAffordance(
                affordance_id="button",
                role="button",
                label="Continue",
                actions=("click",),
            ),
        ),
        allowed_actions=("click", "fail"),
    )
    session = _Session(
        [observation],
        {
            observation.observation_id: VisionTask(
                kind="interactive",
                prompt=observation.prompt,
                images=(),
                width=400,
                height=300,
            )
        },
        accepted=False,
    )
    backend = StaticActionPlanningBackend(
        [
            {
                "action": "click",
                "payload": {"affordance_id": "not-present"},
                "confidence": 0.9,
            },
            {
                "action": "type",
                "payload": {"affordance_id": "button", "text": "unsafe"},
                "confidence": 0.9,
            },
        ]
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(StaticVisionBackend([]), action_backend=backend),
            max_steps=2,
        ).run()
    )

    assert result.accepted is False
    assert session.actions == []
    assert len(backend.calls) == 2
    assert len(result.diagnostics["action_planning_errors"]) == 2


def test_low_confidence_generic_action_reloads_without_executing_proposal() -> None:
    observation = _interactive_observation(
        "uncertain-scene",
        (
            ChallengeAffordance(
                affordance_id="risky",
                role="button",
                label="Possibly correct",
                actions=("click",),
            ),
        ),
        allowed_actions=("click", "reload", "fail"),
    )
    session = _Session(
        [observation],
        {
            observation.observation_id: VisionTask(
                kind="interactive",
                prompt=observation.prompt,
                images=(),
                width=400,
                height=300,
            )
        },
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=StaticActionPlanningBackend(
                    [
                        {
                            "action": "click",
                            "payload": {"affordance_id": "risky"},
                            "confidence": 0.1,
                        }
                    ]
                ),
                solve_policy=VisionSolvePolicy(
                    min_confidence=0.5,
                    retries=1,
                    require_confidence=True,
                    allow_uncertain=True,
                ),
            ),
            max_steps=2,
        ).run()
    )

    assert [action.kind for action in session.actions] == ["reload"]
    assert result.diagnostics["challenge_actions"][0]["uncertain"] is True
