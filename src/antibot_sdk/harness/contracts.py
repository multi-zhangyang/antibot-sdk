"""Provider-neutral challenge observations, actions, and verification evidence.

The browser providers are allowed to use vendor-specific DOM and protocol
details internally, but the Harness records only this small intermediate
representation.  That makes replay, policy checks, and future adapters work
across hCaptcha, reCAPTCHA, Turnstile, and non-image providers without making
one provider's JSON format the system contract.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ChallengeKind = Literal[
    "binary",
    "point",
    "bounding_box",
    "multiple_choice",
    "drag_drop",
    "slider",
    "token",
    "interactive",
    "unknown",
]
ChallengeModality = Literal["image", "audio", "text", "behavior", "protocol", "unknown"]
ChallengePhase = Literal["presented", "answering", "submitted", "replaced", "verified", "failed"]
ActionKind = Literal[
    "select",
    "point",
    "box",
    "choice",
    "drag",
    "click",
    "type",
    "press",
    "wait",
    "submit",
    "reload",
    "noop",
    "fail",
]

_KIND_ACTIONS: dict[str, frozenset[str]] = {
    "binary": frozenset(("select", "submit", "reload", "noop", "fail")),
    "point": frozenset(("point", "submit", "reload", "noop", "fail")),
    "bounding_box": frozenset(("box", "submit", "reload", "noop", "fail")),
    "multiple_choice": frozenset(("choice", "submit", "reload", "noop", "fail")),
    "drag_drop": frozenset(("drag", "submit", "reload", "noop", "fail")),
    "slider": frozenset(("drag", "submit", "reload", "noop", "fail")),
    "token": frozenset(("submit", "reload", "noop", "fail")),
    "interactive": frozenset(
        (
            "select",
            "point",
            "choice",
            "drag",
            "click",
            "type",
            "press",
            "wait",
            "submit",
            "reload",
            "noop",
            "fail",
        )
    ),
    "unknown": frozenset(("reload", "noop", "fail")),
}
_MODALITIES = frozenset(("image", "audio", "text", "behavior", "protocol", "unknown"))
_PHASES = frozenset(("presented", "answering", "submitted", "replaced", "verified", "failed"))
_ACTION_KINDS = frozenset(
    (
        "select",
        "point",
        "box",
        "choice",
        "drag",
        "click",
        "type",
        "press",
        "wait",
        "submit",
        "reload",
        "noop",
        "fail",
    )
)


@dataclass(frozen=True, slots=True)
class ChallengeCandidate:
    """One selectable candidate in an image/grid challenge."""

    index: int
    row: int | None = None
    column: int | None = None
    x: float | None = None
    y: float | None = None
    width: float | None = None
    height: float | None = None
    image_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool) or self.index < 0:
            raise ValueError("challenge candidate index must be a non-negative integer")
        for name in ("row", "column"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(f"challenge candidate {name} must be a non-negative integer")
        for name in ("x", "y", "width", "height"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise ValueError(f"challenge candidate {name} must be finite")
        if self.width is not None and self.width <= 0:
            raise ValueError("challenge candidate width must be positive")
        if self.height is not None and self.height <= 0:
            raise ValueError("challenge candidate height must be positive")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ChallengeAffordance:
    """One observation-scoped interactive target exposed by an adapter."""

    affordance_id: str
    role: str
    label: str = ""
    x: float | None = None
    y: float | None = None
    width: float | None = None
    height: float | None = None
    candidate_index: int | None = None
    enabled: bool = True
    actions: tuple[ActionKind, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.affordance_id, str) or not self.affordance_id.strip():
            raise ValueError("challenge affordance_id must not be empty")
        if not isinstance(self.role, str) or not self.role.strip():
            raise ValueError("challenge affordance role must not be empty")
        if not isinstance(self.label, str):
            raise ValueError("challenge affordance label must be a string")
        coordinates = (self.x, self.y, self.width, self.height)
        if any(value is not None for value in coordinates):
            if not all(
                value is not None
                and not isinstance(value, bool)
                and isinstance(value, (int, float))
                and math.isfinite(float(value))
                for value in coordinates
            ):
                raise ValueError("challenge affordance bounds must be four finite numbers")
            if self.x < 0 or self.y < 0:
                raise ValueError("challenge affordance origin must be non-negative")
            if self.width <= 0 or self.height <= 0:
                raise ValueError("challenge affordance dimensions must be positive")
        if self.candidate_index is not None and (
            not isinstance(self.candidate_index, int)
            or isinstance(self.candidate_index, bool)
            or self.candidate_index < 0
        ):
            raise ValueError("challenge affordance candidate_index must be non-negative")
        if not isinstance(self.enabled, bool):
            raise ValueError("challenge affordance enabled must be boolean")
        if not isinstance(self.actions, tuple) or any(
            not isinstance(action, str) or action not in _ACTION_KINDS
            for action in self.actions
        ):
            raise ValueError("challenge affordance actions must be known action kinds")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("challenge affordance actions must be unique")
        if not isinstance(self.metadata, dict):
            raise ValueError("challenge affordance metadata must be an object")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ChallengeObservation:
    """A vendor-neutral snapshot of one challenge state."""

    observation_id: str
    provider: str
    kind: ChallengeKind
    modality: ChallengeModality
    prompt: str = ""
    candidate_count: int | None = None
    candidates: tuple[ChallengeCandidate, ...] = ()
    grid_rows: int | None = None
    grid_columns: int | None = None
    width: int | None = None
    height: int | None = None
    dynamic: bool = False
    min_answers: int | None = None
    max_answers: int | None = None
    choices: tuple[str, ...] = ()
    affordances: tuple[ChallengeAffordance, ...] = ()
    allowed_actions: tuple[ActionKind, ...] = ()
    phase: ChallengePhase = "presented"
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, str) or not self.observation_id.strip():
            raise ValueError("challenge observation_id must not be empty")
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("challenge provider must not be empty")
        if not isinstance(self.kind, str) or self.kind not in _KIND_ACTIONS:
            raise ValueError(f"unsupported challenge kind: {self.kind}")
        if not isinstance(self.modality, str) or self.modality not in _MODALITIES:
            raise ValueError(f"unsupported challenge modality: {self.modality}")
        if not isinstance(self.phase, str) or self.phase not in _PHASES:
            raise ValueError(f"unsupported challenge phase: {self.phase}")
        for name in (
            "candidate_count",
            "grid_rows",
            "grid_columns",
            "width",
            "height",
            "min_answers",
            "max_answers",
        ):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise ValueError(f"challenge {name} must be an integer")
        if not isinstance(self.prompt, str):
            raise ValueError("challenge prompt must be a string")
        if not isinstance(self.dynamic, bool):
            raise ValueError("challenge dynamic must be boolean")
        if not isinstance(self.choices, tuple) or not all(
            isinstance(choice, str) for choice in self.choices
        ):
            raise ValueError("challenge choices must be a tuple of strings")
        if not isinstance(self.affordances, tuple) or not all(
            isinstance(affordance, ChallengeAffordance)
            for affordance in self.affordances
        ):
            raise ValueError("challenge affordances must be a tuple")
        if not isinstance(self.allowed_actions, tuple) or any(
            not isinstance(action, str) or action not in _ACTION_KINDS
            for action in self.allowed_actions
        ):
            raise ValueError("challenge allowed_actions must be known action kinds")
        if len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("challenge allowed_actions must be unique")
        if not isinstance(self.metadata, dict):
            raise ValueError("challenge metadata must be an object")
        if not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool):
            raise ValueError("challenge schema_version must be an integer")
        if self.candidate_count is not None and self.candidate_count < 0:
            raise ValueError("challenge candidate_count must be non-negative")
        if self.grid_rows is not None and self.grid_rows < 1:
            raise ValueError("challenge grid_rows must be positive")
        if self.grid_columns is not None and self.grid_columns < 1:
            raise ValueError("challenge grid_columns must be positive")
        if self.width is not None and self.width < 1:
            raise ValueError("challenge width must be positive")
        if self.height is not None and self.height < 1:
            raise ValueError("challenge height must be positive")
        if self.min_answers is not None and self.min_answers < 0:
            raise ValueError("challenge min_answers must be non-negative")
        if self.max_answers is not None and self.max_answers < 0:
            raise ValueError("challenge max_answers must be non-negative")
        if (
            self.min_answers is not None
            and self.max_answers is not None
            and self.min_answers > self.max_answers
        ):
            raise ValueError("challenge min_answers must not exceed max_answers")
        indexes = [candidate.index for candidate in self.candidates]
        if len(set(indexes)) != len(indexes):
            raise ValueError("challenge candidate indexes must be unique")
        if self.candidate_count is not None and any(
            index >= self.candidate_count for index in indexes
        ):
            raise ValueError("challenge candidate index exceeds candidate_count")
        if self.candidates and self.candidate_count is not None and (
            len(self.candidates) != self.candidate_count
        ):
            raise ValueError("challenge candidates must match candidate_count")
        affordance_ids = [item.affordance_id for item in self.affordances]
        if len(set(affordance_ids)) != len(affordance_ids):
            raise ValueError("challenge affordance ids must be unique")
        if self.candidate_count is not None and any(
            item.candidate_index is not None
            and item.candidate_index >= self.candidate_count
            for item in self.affordances
        ):
            raise ValueError("challenge affordance candidate index exceeds candidate_count")
        for item in self.affordances:
            if (
                self.width is not None
                and item.x is not None
                and item.width is not None
                and item.x + item.width > self.width
            ):
                raise ValueError("challenge affordance exceeds observation width")
            if (
                self.height is not None
                and item.y is not None
                and item.height is not None
                and item.y + item.height > self.height
            ):
                raise ValueError("challenge affordance exceeds observation height")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidates"] = [candidate.to_dict() for candidate in self.candidates]
        value["affordances"] = [item.to_dict() for item in self.affordances]
        return value

    @property
    def supported_actions(self) -> tuple[ActionKind, ...]:
        actions = self.allowed_actions or tuple(_KIND_ACTIONS[self.kind])
        return tuple(sorted(actions))

    def validate_action(self, action: "ChallengeAction") -> tuple[str, ...]:
        """Validate an action against this exact observation.

        Coordinates and candidate indexes are observation-scoped.  A planner
        cannot accidentally reuse coordinates after a dynamic tile refresh.
        """

        errors: list[str] = []
        if action.observation_id != self.observation_id:
            errors.append("action_observation_mismatch")
        if self.phase not in {"presented", "answering"}:
            errors.append("observation_not_actionable")
        supported_actions = frozenset(self.supported_actions)
        if action.kind != "fail" and action.kind not in supported_actions:
            errors.append("action_kind_not_supported_for_observation")
        if action.uncertain and action.kind not in {"reload", "noop", "fail"}:
            errors.append("uncertain_action_must_not_answer_or_submit")
        if action.kind == "select":
            selected = action.payload.get("selected")
            if not isinstance(selected, list):
                errors.append("select_selected_must_be_list")
            else:
                if not all(isinstance(item, int) and not isinstance(item, bool) for item in selected):
                    errors.append("select_indexes_must_be_integers")
                else:
                    if len(set(selected)) != len(selected):
                        errors.append("select_indexes_must_be_unique")
                    if self.candidate_count is not None and any(
                        item < 0 or item >= self.candidate_count for item in selected
                    ):
                        errors.append("select_index_out_of_range")
                    if self.max_answers is not None and len(selected) > self.max_answers:
                        errors.append("select_answer_count_exceeds_maximum")
                    if self.min_answers is not None and len(selected) < self.min_answers:
                        errors.append("select_answer_count_below_minimum")
        elif action.kind == "point":
            points = action.payload.get("points")
            errors.extend(_validate_coordinates(points, self, "points"))
            if isinstance(points, list):
                errors.extend(_answer_count_errors(len(points), self, "point"))
        elif action.kind == "box":
            boxes = action.payload.get("boxes")
            if not isinstance(boxes, list) or not boxes:
                errors.append("box_boxes_must_be_non_empty_list")
            else:
                for index, box in enumerate(boxes):
                    if not isinstance(box, dict):
                        errors.append(f"box_{index}_must_be_object")
                        continue
                    values = [box.get(name) for name in ("x1", "y1", "x2", "y2")]
                    if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
                        errors.append(f"box_{index}_coordinates_must_be_numbers")
                        continue
                    x1, y1, x2, y2 = (float(value) for value in values)
                    if x2 <= x1 or y2 <= y1:
                        errors.append(f"box_{index}_must_have_positive_area")
                    errors.extend(_coordinate_bounds((x1, y1), self, f"box_{index}.top_left"))
                    errors.extend(
                        _coordinate_bounds(
                            (x2, y2),
                            self,
                            f"box_{index}.bottom_right",
                            allow_edge=True,
                        )
                    )
                errors.extend(_answer_count_errors(len(boxes), self, "box"))
        elif action.kind == "choice":
            raw_choices = action.payload.get("choices")
            if raw_choices is None:
                raw_choices = [action.payload.get("choice")]
            if not isinstance(raw_choices, list) or not raw_choices:
                errors.append("choices_must_be_non_empty_list")
            elif not all(isinstance(item, str) and item.strip() for item in raw_choices):
                errors.append("choices_must_be_non_empty_strings")
            else:
                normalized = [item.casefold() for item in raw_choices]
                if len(set(normalized)) != len(normalized):
                    errors.append("choices_must_be_unique")
                allowed = {item.casefold() for item in self.choices}
                if allowed and any(item not in allowed for item in normalized):
                    errors.append("choice_not_in_observation_choices")
                errors.extend(_answer_count_errors(len(raw_choices), self, "choice"))
        elif action.kind == "drag":
            paths = action.payload.get("paths")
            if not isinstance(paths, list) or not paths:
                errors.append("drag_paths_must_be_non_empty_list")
            else:
                for index, path in enumerate(paths):
                    if not isinstance(path, dict):
                        errors.append(f"drag_{index}_must_be_object")
                        continue
                    for point_name in ("start", "end"):
                        point = path.get(point_name)
                        if not isinstance(point, dict):
                            errors.append(f"drag_{index}_{point_name}_must_be_object")
                            continue
                        values = (point.get("x"), point.get("y"))
                        if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
                            errors.append(f"drag_{index}_{point_name}_coordinates_must_be_numbers")
                        else:
                            errors.extend(
                                _coordinate_bounds(
                                    (float(values[0]), float(values[1])),
                                    self,
                                    f"drag_{index}.{point_name}",
                                )
                            )
                errors.extend(_answer_count_errors(len(paths), self, "drag"))
        elif action.kind == "click":
            errors.extend(_validate_click(action.payload, self))
        elif action.kind == "type":
            errors.extend(_validate_type(action.payload, self))
        elif action.kind == "press":
            errors.extend(_validate_press(action.payload, self))
        elif action.kind == "wait":
            milliseconds = action.payload.get("milliseconds")
            if (
                not isinstance(milliseconds, int)
                or isinstance(milliseconds, bool)
                or not 1 <= milliseconds <= 30_000
            ):
                errors.append("wait_milliseconds_must_be_between_1_and_30000")
            if set(action.payload) - {"milliseconds"}:
                errors.append("wait_payload_has_unknown_fields")
        elif action.kind in {"submit", "reload", "noop", "fail"}:
            if action.payload:
                errors.append(f"{action.kind}_payload_must_be_empty")
        else:
            errors.append("unsupported_action_kind")
        return tuple(dict.fromkeys(errors))


@dataclass(frozen=True, slots=True)
class ChallengeAction:
    """A typed action proposed for one observation."""

    observation_id: str
    kind: ActionKind
    payload: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    uncertain: bool = False
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, str) or not self.observation_id.strip():
            raise ValueError("challenge action observation_id must not be empty")
        if not isinstance(self.kind, str) or self.kind not in _ACTION_KINDS:
            raise ValueError(f"unsupported challenge action kind: {self.kind}")
        if not isinstance(self.payload, dict):
            raise ValueError("challenge action payload must be an object")
        if self.confidence is not None:
            if (
                isinstance(self.confidence, bool)
                or not isinstance(self.confidence, (int, float))
                or not math.isfinite(float(self.confidence))
                or not 0 <= self.confidence <= 1
            ):
                raise ValueError("challenge action confidence must be between 0 and 1")
        if not isinstance(self.uncertain, bool):
            raise ValueError("challenge action uncertain must be boolean")
        if not isinstance(self.rationale, str):
            raise ValueError("challenge action rationale must be a string")

    def validate(self, observation: ChallengeObservation) -> tuple[str, ...]:
        return observation.validate_action(self)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VendorVerification:
    """Normalized vendor/site evidence extracted from a provider result."""

    provider: str
    accepted: bool
    token_length: int = 0
    vendor_pass: bool | None = None
    vendor_failures: int = 0
    site_verified: bool | None = None
    verifier_events: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _coordinate_bounds(
    point: tuple[float, float],
    observation: ChallengeObservation,
    label: str,
    *,
    allow_edge: bool = False,
) -> list[str]:
    if observation.width is not None and not (
        0 <= point[0] <= observation.width
        if allow_edge
        else 0 <= point[0] < observation.width
    ):
        return [f"{label}_x_out_of_bounds"]
    if observation.height is not None and not (
        0 <= point[1] <= observation.height
        if allow_edge
        else 0 <= point[1] < observation.height
    ):
        return [f"{label}_y_out_of_bounds"]
    return []


def _answer_count_errors(
    count: int,
    observation: ChallengeObservation,
    label: str,
) -> list[str]:
    errors: list[str] = []
    if observation.min_answers is not None and count < observation.min_answers:
        errors.append(f"{label}_answer_count_below_minimum")
    if observation.max_answers is not None and count > observation.max_answers:
        errors.append(f"{label}_answer_count_exceeds_maximum")
    return errors


def _validate_coordinates(
    value: Any, observation: ChallengeObservation, label: str
) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{label}_must_be_non_empty_list"]
    errors: list[str] = []
    for index, point in enumerate(value):
        if not isinstance(point, dict):
            errors.append(f"{label}_{index}_must_be_object")
            continue
        values = (point.get("x"), point.get("y"))
        if not all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in values):
            errors.append(f"{label}_{index}_coordinates_must_be_numbers")
            continue
        errors.extend(_coordinate_bounds((float(values[0]), float(values[1])), observation, f"{label}_{index}"))
    return errors


def _affordance(
    observation: ChallengeObservation,
    affordance_id: Any,
    action_kind: str,
) -> tuple[ChallengeAffordance | None, list[str]]:
    if not isinstance(affordance_id, str) or not affordance_id.strip():
        return None, [f"{action_kind}_affordance_id_must_be_non_empty_string"]
    target = next(
        (
            item
            for item in observation.affordances
            if item.affordance_id == affordance_id
        ),
        None,
    )
    if target is None:
        return None, [f"{action_kind}_affordance_not_found"]
    errors: list[str] = []
    if not target.enabled:
        errors.append(f"{action_kind}_affordance_disabled")
    if not target.actions or action_kind not in target.actions:
        errors.append(f"{action_kind}_not_supported_by_affordance")
    return target, errors


def _validate_click(
    payload: dict[str, Any], observation: ChallengeObservation
) -> list[str]:
    errors: list[str] = []
    affordance_id = payload.get("affordance_id")
    point = payload.get("point")
    if (affordance_id is None) == (point is None):
        errors.append("click_requires_exactly_one_target")
    elif affordance_id is not None:
        _target, target_errors = _affordance(observation, affordance_id, "click")
        errors.extend(target_errors)
    elif not isinstance(point, dict):
        errors.append("click_point_must_be_object")
    else:
        values = (point.get("x"), point.get("y"))
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in values
        ):
            errors.append("click_point_coordinates_must_be_numbers")
        else:
            errors.extend(
                _coordinate_bounds(
                    (float(values[0]), float(values[1])), observation, "click_point"
                )
            )
    if set(payload) - {"affordance_id", "point"}:
        errors.append("click_payload_has_unknown_fields")
    return errors


def _validate_type(
    payload: dict[str, Any], observation: ChallengeObservation
) -> list[str]:
    _target, errors = _affordance(observation, payload.get("affordance_id"), "type")
    text = payload.get("text")
    if not isinstance(text, str) or not text:
        errors.append("type_text_must_be_non_empty_string")
    elif len(text) > 10_000:
        errors.append("type_text_exceeds_limit")
    if set(payload) - {"affordance_id", "text"}:
        errors.append("type_payload_has_unknown_fields")
    return errors


def _validate_press(
    payload: dict[str, Any], observation: ChallengeObservation
) -> list[str]:
    errors: list[str] = []
    if "affordance_id" in payload:
        _target, target_errors = _affordance(
            observation, payload.get("affordance_id"), "press"
        )
        errors.extend(target_errors)
    key = payload.get("key")
    if not isinstance(key, str) or not key.strip() or len(key) > 64:
        errors.append("press_key_must_be_non_empty_string")
    if set(payload) - {"affordance_id", "key"}:
        errors.append("press_payload_has_unknown_fields")
    return errors


__all__ = [
    "ActionKind",
    "ChallengeAction",
    "ChallengeAffordance",
    "ChallengeCandidate",
    "ChallengeKind",
    "ChallengeModality",
    "ChallengeObservation",
    "ChallengePhase",
    "VendorVerification",
]
