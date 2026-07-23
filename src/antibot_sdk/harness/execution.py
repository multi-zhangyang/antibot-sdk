"""Provider-neutral action construction and trace recording."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..vision import VisionAnswer
from .contracts import ChallengeAction, ChallengeObservation


class ChallengeActionRejected(ValueError):
    """Raised before browser input when an action does not match its observation."""

    def __init__(self, errors: tuple[str, ...]) -> None:
        self.errors = errors
        super().__init__("challenge action rejected: " + ", ".join(errors))


@dataclass(frozen=True, slots=True)
class ActionValidation:
    action: ChallengeAction
    valid: bool
    errors: tuple[str, ...] = ()
    trace_index: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.action.observation_id,
            "kind": self.action.kind,
            "payload": self.action.payload,
            "confidence": self.action.confidence,
            "uncertain": self.action.uncertain,
            "valid": self.valid,
            "errors": list(self.errors),
            "executed": False,
        }


def action_from_vision(
    observation: ChallengeObservation,
    answer: VisionAnswer,
    *,
    rationale: str = "",
) -> ChallengeAction:
    """Translate a normalized vision answer into the common action IR."""

    if answer.kind != observation.kind:
        raise ChallengeActionRejected(("vision_answer_kind_mismatch",))
    payload: dict[str, Any]
    action_kind: str
    if answer.kind == "binary":
        action_kind = "select"
        payload = {"selected": list(answer.selected)}
    elif answer.kind == "point":
        action_kind = "point"
        payload = {
            "points": [{"x": point.x, "y": point.y} for point in answer.points]
        }
    elif answer.kind == "bounding_box":
        action_kind = "box"
        payload = {
            "boxes": [
                {
                    "x1": box.x1,
                    "y1": box.y1,
                    "x2": box.x2,
                    "y2": box.y2,
                }
                for box in answer.boxes
            ]
        }
    elif answer.kind == "multiple_choice":
        action_kind = "choice"
        payload = (
            {"choice": answer.choices[0]}
            if len(answer.choices) == 1
            else {"choices": list(answer.choices)}
        )
    elif answer.kind == "drag_drop":
        action_kind = "drag"
        payload = {
            "paths": [
                {
                    "start": {"x": path.start.x, "y": path.start.y},
                    "end": {"x": path.end.x, "y": path.end.y},
                }
                for path in answer.paths
            ]
        }
    else:
        raise ChallengeActionRejected(("vision_answer_kind_not_actionable",))
    return ChallengeAction(
        observation_id=observation.observation_id,
        kind=action_kind,  # type: ignore[arg-type]
        payload=payload,
        confidence=answer.confidence,
        rationale=rationale,
    )


class ChallengeExecutor:
    """Validate and record observations/actions before a provider executes them."""

    def __init__(self, diagnostics: dict[str, Any]) -> None:
        self.diagnostics = diagnostics

    def observe(self, observation: ChallengeObservation) -> None:
        self.diagnostics.setdefault("challenge_observations", []).append(
            observation.to_dict()
        )

    def validate(
        self,
        observation: ChallengeObservation,
        action: ChallengeAction,
    ) -> ActionValidation:
        errors = action.validate(observation)
        records = self.diagnostics.setdefault("challenge_actions", [])
        result = ActionValidation(
            action=action,
            valid=not errors,
            errors=errors,
            trace_index=len(records),
        )
        records.append(result.to_dict())
        if errors:
            self.diagnostics.setdefault("challenge_action_errors", []).extend(errors)
        return result

    def mark_executed(self, validation: ActionValidation) -> None:
        if not validation.valid:
            raise ChallengeActionRejected(validation.errors)
        records = self.diagnostics.get("challenge_actions")
        if not isinstance(records, list) or not 0 <= validation.trace_index < len(records):
            raise RuntimeError("challenge action trace is unavailable")
        record = records[validation.trace_index]
        if not isinstance(record, dict) or (
            record.get("observation_id") != validation.action.observation_id
            or record.get("kind") != validation.action.kind
        ):
            raise RuntimeError("challenge action trace does not match validation")
        record["executed"] = True

    def require(
        self,
        observation: ChallengeObservation,
        action: ChallengeAction,
    ) -> ActionValidation:
        result = self.validate(observation, action)
        if not result.valid:
            raise ChallengeActionRejected(result.errors)
        return result

    def require_vision(
        self,
        observation: ChallengeObservation,
        answer: VisionAnswer,
        *,
        rationale: str = "",
    ) -> ActionValidation:
        return self.require(
            observation,
            action_from_vision(observation, answer, rationale=rationale),
        )


__all__ = [
    "ActionValidation",
    "ChallengeActionRejected",
    "ChallengeExecutor",
    "action_from_vision",
]
