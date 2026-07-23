"""Generic multimodal action planning for interactive challenge scenes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence, runtime_checkable

from ..vision import (
    OpenAICompatibleVisionBackend,
    VisionBackendError,
    VisionSolvePolicy,
    VisionTask,
)
from .contracts import ChallengeAction, ChallengeObservation


@dataclass(frozen=True, slots=True)
class ActionBackendResponse:
    payload: dict[str, Any]
    diagnostics: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ActionPlanningBackend(Protocol):
    async def propose(
        self,
        observation: ChallengeObservation,
        task: VisionTask,
        *,
        history: Sequence[dict[str, Any]] = (),
    ) -> ActionBackendResponse:
        """Propose one JSON action for the exact observation."""


class StaticActionPlanningBackend:
    """Deterministic action backend for offline interaction matrices."""

    def __init__(self, proposals: Sequence[dict[str, Any]]) -> None:
        self._proposals = list(proposals)
        self.calls: list[tuple[ChallengeObservation, VisionTask]] = []

    async def propose(
        self,
        observation: ChallengeObservation,
        task: VisionTask,
        *,
        history: Sequence[dict[str, Any]] = (),
    ) -> ActionBackendResponse:
        del history
        self.calls.append((observation, task))
        if not self._proposals:
            raise VisionBackendError("static action backend has no proposal left")
        return ActionBackendResponse(self._proposals.pop(0), {"backend": "static_action"})


class OpenAICompatibleActionPlanningBackend:
    """Use an existing OpenAI-compatible vision gateway for action JSON."""

    def __init__(self, backend: OpenAICompatibleVisionBackend) -> None:
        self.backend = backend

    async def propose(
        self,
        observation: ChallengeObservation,
        task: VisionTask,
        *,
        history: Sequence[dict[str, Any]] = (),
    ) -> ActionBackendResponse:
        payload, diagnostics = await self.backend.complete_json(
            task,
            instruction=action_instruction(observation, history=history),
        )
        return ActionBackendResponse(payload, diagnostics)


@dataclass(frozen=True, slots=True)
class ActionSolveOutcome:
    action: ChallengeAction | None
    uncertain: bool = False
    errors: tuple[str, ...] = ()
    diagnostics: dict[str, Any] = field(default_factory=dict)


def action_instruction(
    observation: ChallengeObservation,
    *,
    history: Sequence[dict[str, Any]] = (),
) -> str:
    """Build a provider-neutral one-action prompt from the scene contract."""

    affordances = [
        {
            "id": item.affordance_id,
            "role": item.role,
            "label": item.label[:200],
            "bounds": (
                {"x": item.x, "y": item.y, "width": item.width, "height": item.height}
                if item.x is not None
                else None
            ),
            "candidate_index": item.candidate_index,
            "enabled": item.enabled,
            "actions": list(item.actions),
        }
        for item in observation.affordances
    ]
    schemas = {
        "click": '{"action":"click","payload":{"affordance_id":"id"}}',
        "type": '{"action":"type","payload":{"affordance_id":"id","text":"..."}}',
        "press": '{"action":"press","payload":{"key":"Enter"}}',
        "wait": '{"action":"wait","payload":{"milliseconds":500}}',
        "select": '{"action":"select","payload":{"selected":[0]}}',
        "point": '{"action":"point","payload":{"points":[{"x":10,"y":20}]}}',
        "box": '{"action":"box","payload":{"boxes":[{"x1":1,"y1":2,"x2":30,"y2":40}]}}',
        "choice": '{"action":"choice","payload":{"choice":"label"}}',
        "drag": '{"action":"drag","payload":{"paths":[{"start":{"x":1,"y":2},"end":{"x":30,"y":40}}]}}',
        "submit": '{"action":"submit","payload":{}}',
        "reload": '{"action":"reload","payload":{}}',
        "noop": '{"action":"noop","payload":{}}',
        "fail": '{"action":"fail","payload":{}}',
    }
    allowed = list(observation.supported_actions)
    history_payload = [
        {
            key: value
            for key, value in item.items()
            if key in {"observation_id", "kind", "valid", "executed", "uncertain"}
        }
        for item in history[-6:]
        if isinstance(item, dict)
    ]
    return (
        "You are an interactive CAPTCHA agent. Inspect the supplied scene and return exactly one "
        "JSON object describing the next action. Use only an allowed action and only the current "
        "observation's affordance IDs or pixel coordinates. Never claim success or invent a token. "
        "If the scene is not certain, use reload, noop, or fail. "
        f"Observation id: {observation.observation_id}. "
        f"Challenge kind: {observation.kind}; modality: {observation.modality}. "
        f"Prompt: {observation.prompt!r}. "
        f"Canvas: {observation.width}x{observation.height}. "
        f"Allowed actions: {json.dumps(allowed, ensure_ascii=True)}. "
        f"Affordances: {json.dumps(affordances, ensure_ascii=True)}. "
        f"Recent action history: {json.dumps(history_payload, ensure_ascii=True)}. "
        "Available JSON forms: "
        + " ".join(schemas[action] for action in allowed if action in schemas)
        + " Return fields action, payload, confidence (0..1), and optional rationale."
    )


def parse_action_proposal(
    observation: ChallengeObservation,
    response: ActionBackendResponse,
) -> ChallengeAction:
    payload = response.payload
    if not isinstance(payload, dict):
        raise VisionBackendError("action planner response must be an object")
    kind = payload.get("action", payload.get("kind"))
    if not isinstance(kind, str):
        raise VisionBackendError("action planner response is missing action")
    action_payload = payload.get("payload", {})
    if not isinstance(action_payload, dict):
        raise VisionBackendError("action planner payload must be an object")
    confidence = payload.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise VisionBackendError("action planner confidence must be numeric")
        if not 0 <= float(confidence) <= 1:
            raise VisionBackendError("action planner confidence must be between 0 and 1")
    uncertain = payload.get("uncertain", False)
    if not isinstance(uncertain, bool):
        raise VisionBackendError("action planner uncertain must be boolean")
    rationale = payload.get("rationale", "")
    if not isinstance(rationale, str):
        raise VisionBackendError("action planner rationale must be a string")
    try:
        action = ChallengeAction(
            observation_id=observation.observation_id,
            kind=kind,
            payload=action_payload,
            confidence=confidence,
            uncertain=uncertain,
            rationale=rationale,
        )
    except (TypeError, ValueError) as exc:
        raise VisionBackendError(f"action planner action is malformed: {exc}") from exc
    errors = action.validate(observation)
    if errors:
        raise VisionBackendError("action planner action rejected: " + ", ".join(errors))
    return action


async def solve_challenge_action(
    backend: ActionPlanningBackend,
    observation: ChallengeObservation,
    task: VisionTask,
    *,
    policy: VisionSolvePolicy | None = None,
    history: Sequence[dict[str, Any]] = (),
    diagnostics: dict[str, Any] | None = None,
) -> ActionSolveOutcome:
    effective = policy or VisionSolvePolicy(
        min_confidence=0.35,
        retries=2,
        require_confidence=True,
        allow_uncertain=True,
    )
    errors: list[str] = []
    last_action: ChallengeAction | None = None
    backend_diagnostics: dict[str, Any] = {}
    for attempt in range(1, effective.retries + 1):
        try:
            response = await backend.propose(observation, task, history=history)
            backend_diagnostics = dict(response.diagnostics)
            action = parse_action_proposal(observation, response)
            last_action = action
            if (
                effective.require_confidence
                and action.confidence is None
            ) or (
                action.confidence is not None
                and action.confidence < effective.min_confidence
            ):
                value = "missing" if action.confidence is None else f"{action.confidence:.3f}"
                raise VisionBackendError(
                    f"action confidence {value} is below {effective.min_confidence:.3f}"
                )
            return ActionSolveOutcome(
                action=action,
                diagnostics=backend_diagnostics,
            )
        except VisionBackendError as exc:
            message = f"attempt {attempt}: {type(exc).__name__}: {exc}"
            errors.append(message)
            if diagnostics is not None:
                diagnostics.setdefault("action_planning_errors", []).append(
                    {"attempt": attempt, "error": message}
                )
    if last_action is not None and effective.allow_uncertain:
        return ActionSolveOutcome(
            action=last_action,
            uncertain=True,
            errors=tuple(errors),
            diagnostics=backend_diagnostics,
        )
    raise VisionBackendError(errors[-1] if errors else "action planner returned no proposal")


__all__ = [
    "ActionBackendResponse",
    "ActionPlanningBackend",
    "ActionSolveOutcome",
    "OpenAICompatibleActionPlanningBackend",
    "StaticActionPlanningBackend",
    "action_instruction",
    "parse_action_proposal",
    "solve_challenge_action",
]
