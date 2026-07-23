from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from .contracts import (
    ChallengeAction,
    ChallengeAffordance,
    ChallengeCandidate,
    ChallengeObservation,
)


@dataclass(frozen=True, slots=True)
class ReplayRun:
    source: str
    provider: str
    result_ok: bool
    evidence_accepted: bool
    elapsed_ms: int
    challenge_types: tuple[str, ...]
    prompts: tuple[str, ...]
    vision_task_count: int
    models: tuple[str, ...]
    finish_reasons: tuple[str, ...]
    total_tokens: int
    completion_tokens: int
    alignment_scores: tuple[float, ...]
    alignment_poll_count: int
    vendor_passes: int
    vendor_failures: int
    site_verified: bool | None
    attribution: str
    recaptcha_round_count: int = 0
    recaptcha_attempts: int = 0
    recaptcha_dynamic_rounds: int = 0
    recaptcha_refresh_count: int = 0
    recaptcha_action_labels: tuple[str, ...] = ()
    recaptcha_userverify_observed: bool = False
    token_length: int = 0
    adapter: str | None = None
    observation_count: int = 0
    action_count: int = 0
    invalid_action_count: int = 0
    executed_action_count: int = 0
    unexecuted_action_count: int = 0
    trace_integrity_error_count: int = 0
    trace_integrity_errors: tuple[str, ...] = ()
    modalities: tuple[str, ...] = ()
    normalized_kinds: tuple[str, ...] = ()
    uncertain_count: int = 0
    prompt_families: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    affordance_count: int = 0
    affordance_roles: tuple[str, ...] = ()
    action_kinds: tuple[str, ...] = ()
    action_planner_backends: tuple[str, ...] = ()
    action_planning_error_count: int = 0
    dynamic_scene_replacement_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoveragePolicy:
    """Minimum evidence required before a replay matrix is called generalized."""

    min_runs: int = 3
    min_prompt_families: int = 2
    min_challenge_instances: int = 3
    min_evidence_runs: int = 3
    require_success: bool = True
    reject_invalid_actions: bool = True
    reject_uncertain_actions: bool = True
    reject_unexecuted_actions: bool = True
    require_normalized_trace: bool = True
    require_action_trace: bool = True

    def __post_init__(self) -> None:
        for name in (
            "min_runs",
            "min_prompt_families",
            "min_challenge_instances",
            "min_evidence_runs",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"coverage {name} must be positive")


@dataclass(frozen=True, slots=True)
class BenchmarkPolicy:
    """Evidence gate for claiming a provider has crossed a success-rate target."""

    min_runs: int = 20
    target_success_rate: float = 0.95
    min_prompt_families: int = 3
    min_challenge_families: int = 2
    min_challenge_instances: int = 20
    require_vendor_evidence: bool = True
    require_clean_trace: bool = True

    def __post_init__(self) -> None:
        for name in (
            "min_runs",
            "min_prompt_families",
            "min_challenge_families",
            "min_challenge_instances",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"benchmark {name} must be positive")
        if (
            isinstance(self.target_success_rate, bool)
            or not isinstance(self.target_success_rate, (int, float))
            or not 0 <= float(self.target_success_rate) <= 1
        ):
            raise ValueError("benchmark target_success_rate must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class BenchmarkAssessment:
    """Conservative provider qualification result based on independent replay runs."""

    provider: str
    status: str
    qualified: bool
    independent_runs: int
    successful_runs: int
    failed_runs: int
    success_rate: float
    target_success_rate: float
    prompt_families: int
    challenge_families: int
    challenge_instances: int
    evidence_runs: int
    invalid_actions: int
    unexecuted_actions: int
    uncertain_actions: int
    integrity_errors: int
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageAssessment:
    """A conservative capability label derived from replay evidence."""

    status: str
    generalized: bool
    runs: int
    prompt_families: int
    challenge_instances: int
    evidence_runs: int
    successful_runs: int
    invalid_actions: int
    executed_actions: int
    unexecuted_actions: int
    integrity_errors: int
    uncertain_actions: int
    normalized_runs: int
    action_runs: int
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ReplayReport:
    runs: tuple[ReplayRun, ...]

    def assess_benchmark(
        self,
        provider: str,
        policy: BenchmarkPolicy | None = None,
    ) -> BenchmarkAssessment:
        """Assess one provider without treating duplicate or weak traces as runs."""

        effective = policy or BenchmarkPolicy()
        normalized_provider = str(provider).strip().casefold()
        selected = tuple(
            run
            for run in self.runs
            if run.provider.strip().casefold() == normalized_provider
        )
        # A replay source is the unit of independence. Duplicate source paths
        # are retained for diagnostics but counted once for qualification.
        independent: dict[str, ReplayRun] = {}
        for run in selected:
            source = str(run.source).strip() or f"memory:{id(run)}"
            independent.setdefault(source, run)
        runs = tuple(independent.values())
        successful = tuple(
            run
            for run in runs
            if run.result_ok
            and run.evidence_accepted
            and (
                not effective.require_clean_trace
                or (
                    run.invalid_action_count == 0
                    and run.unexecuted_action_count == 0
                    and run.uncertain_count == 0
                    and run.trace_integrity_error_count == 0
                )
            )
        )
        prompt_families = {
            family
            for run in runs
            for family in (run.prompt_families or _prompt_families(run.prompts))
            if family
        }
        challenge_instances = {
            observation_id
            for run in runs
            for observation_id in run.observation_ids
            if observation_id
        }
        if not challenge_instances:
            # Legacy results do not carry ids. Each observed instance is still
            # counted, but cannot be mistaken for a distinct id across runs.
            challenge_instance_count = sum(run.observation_count for run in runs)
        else:
            challenge_instance_count = len(challenge_instances)
        evidence_runs = sum(run.evidence_accepted for run in runs)
        challenge_families = {
            challenge_type
            for run in runs
            for challenge_type in run.challenge_types
            if challenge_type
        }
        invalid_actions = sum(run.invalid_action_count for run in runs)
        unexecuted_actions = sum(run.unexecuted_action_count for run in runs)
        uncertain_actions = sum(run.uncertain_count for run in runs)
        integrity_errors = sum(run.trace_integrity_error_count for run in runs)
        success_rate = len(successful) / len(runs) if runs else 0.0
        reasons: list[str] = []
        if len(runs) < effective.min_runs:
            reasons.append("insufficient_independent_runs")
        if (
            len(prompt_families) < effective.min_prompt_families
            and len(challenge_families) < effective.min_challenge_families
        ):
            reasons.append("insufficient_prompt_families")
            reasons.append("insufficient_challenge_families")
        if challenge_instance_count < effective.min_challenge_instances:
            reasons.append("insufficient_challenge_instances")
        if effective.require_vendor_evidence and evidence_runs < len(runs):
            reasons.append("vendor_evidence_missing")
        if success_rate < effective.target_success_rate:
            reasons.append("success_rate_below_target")
        if effective.require_clean_trace:
            if invalid_actions:
                reasons.append("invalid_actions_observed")
            if unexecuted_actions:
                reasons.append("unexecuted_actions_observed")
            if uncertain_actions:
                reasons.append("uncertain_actions_observed")
            if integrity_errors:
                reasons.append("trace_integrity_errors_observed")
        qualified = not reasons
        if qualified:
            status = "qualified"
        elif len(runs) < effective.min_runs or challenge_instance_count < effective.min_challenge_instances:
            status = "insufficient_samples"
        else:
            status = "failed"
        return BenchmarkAssessment(
            provider=normalized_provider,
            status=status,
            qualified=qualified,
            independent_runs=len(runs),
            successful_runs=len(successful),
            failed_runs=len(runs) - len(successful),
            success_rate=round(success_rate, 4),
            target_success_rate=float(effective.target_success_rate),
            prompt_families=len(prompt_families),
            challenge_families=len(challenge_families),
            challenge_instances=challenge_instance_count,
            evidence_runs=evidence_runs,
            invalid_actions=invalid_actions,
            unexecuted_actions=unexecuted_actions,
            uncertain_actions=uncertain_actions,
            integrity_errors=integrity_errors,
            reasons=tuple(dict.fromkeys(reasons)),
        )

    def assess_challenge_benchmark(
        self,
        provider: str,
        challenge_type: str,
        policy: BenchmarkPolicy | None = None,
    ) -> BenchmarkAssessment:
        """Assess one fixed challenge family without weakening the platform gate.

        Prompt diversity is not meaningful inside a non-prompt family such as
        a slider.  The scoped gate still requires 20 independent instances,
        real vendor evidence, a clean action trace, and at least 95% success.
        The provider-wide assessment remains unchanged and therefore cannot be
        qualified by a single challenge family.
        """

        normalized_provider = str(provider).strip().casefold()
        normalized_type = str(challenge_type).strip()
        scoped_runs = tuple(
            replace(
                run,
                prompt_families=run.prompt_families or (normalized_type,),
            )
            for run in self.runs
            if run.provider.strip().casefold() == normalized_provider
            and normalized_type in run.challenge_types
        )
        scoped = ReplayReport(
            scoped_runs
        )
        effective = policy or replace(
            BenchmarkPolicy(),
            min_prompt_families=1,
            min_challenge_families=1,
        )
        return scoped.assess_benchmark(normalized_provider, effective)

    def assess_coverage(
        self,
        policy: CoveragePolicy | None = None,
    ) -> CoverageAssessment:
        effective = policy or CoveragePolicy()
        prompt_families = {
            family
            for run in self.runs
            for family in (run.prompt_families or _prompt_families(run.prompts))
            if family
        }
        challenge_instances = sum(run.observation_count for run in self.runs)
        evidence_runs = sum(run.evidence_accepted for run in self.runs)
        successful_runs = sum(run.result_ok for run in self.runs)
        invalid_actions = sum(run.invalid_action_count for run in self.runs)
        executed_actions = sum(run.executed_action_count for run in self.runs)
        unexecuted_actions = sum(run.unexecuted_action_count for run in self.runs)
        integrity_errors = sum(run.trace_integrity_error_count for run in self.runs)
        uncertain_actions = sum(run.uncertain_count for run in self.runs)
        normalized_runs = sum(run.observation_count > 0 for run in self.runs)
        action_runs = sum(run.executed_action_count > 0 for run in self.runs)
        reasons: list[str] = []
        if len(self.runs) < effective.min_runs:
            reasons.append("insufficient_independent_runs")
        if len(prompt_families) < effective.min_prompt_families:
            reasons.append("insufficient_prompt_families")
        if challenge_instances < effective.min_challenge_instances:
            reasons.append("insufficient_challenge_instances")
        if effective.require_normalized_trace and normalized_runs < effective.min_runs:
            reasons.append("insufficient_normalized_trace")
        if effective.require_action_trace and action_runs < effective.min_runs:
            reasons.append("insufficient_action_trace")
        if evidence_runs < effective.min_evidence_runs:
            reasons.append("insufficient_vendor_evidence")
        if effective.require_success and successful_runs < effective.min_runs:
            reasons.append("insufficient_successful_runs")
        if effective.reject_invalid_actions and invalid_actions:
            reasons.append("invalid_actions_observed")
        if effective.reject_unexecuted_actions and unexecuted_actions:
            reasons.append("unexecuted_actions_observed")
        if integrity_errors:
            reasons.append("trace_integrity_errors_observed")
        if effective.reject_uncertain_actions and uncertain_actions:
            reasons.append("uncertain_actions_observed")
        generalized = not reasons
        if generalized:
            status = "generalized"
        elif evidence_runs:
            status = "live_verified_limited_matrix"
        else:
            status = "live_sample"
        return CoverageAssessment(
            status=status,
            generalized=generalized,
            runs=len(self.runs),
            prompt_families=len(prompt_families),
            challenge_instances=challenge_instances,
            evidence_runs=evidence_runs,
            successful_runs=successful_runs,
            invalid_actions=invalid_actions,
            executed_actions=executed_actions,
            unexecuted_actions=unexecuted_actions,
            integrity_errors=integrity_errors,
            uncertain_actions=uncertain_actions,
            normalized_runs=normalized_runs,
            action_runs=action_runs,
            reasons=tuple(reasons),
        )

    def to_dict(self) -> dict[str, Any]:
        elapsed = [run.elapsed_ms for run in self.runs]
        challenge_matrix: dict[str, dict[str, int]] = {}
        for run in self.runs:
            for challenge_type in run.challenge_types:
                row = challenge_matrix.setdefault(
                    challenge_type,
                    {
                        "observed_runs": 0,
                        "single_challenge_vendor_pass_runs": 0,
                        "ambiguous_vendor_pass_runs": 0,
                    },
                )
                row["observed_runs"] += 1
                if run.vendor_passes:
                    if run.attribution == "single_challenge":
                        row["single_challenge_vendor_pass_runs"] += 1
                    else:
                        row["ambiguous_vendor_pass_runs"] += 1
                if run.provider == "recaptcha" and run.evidence_accepted:
                    row["evidence_accepted_runs"] = row.get("evidence_accepted_runs", 0) + 1
        challenge_scopes = sorted(
            {
                (run.provider.strip().casefold(), challenge_type)
                for run in self.runs
                for challenge_type in run.challenge_types
                if run.provider.strip() and challenge_type
            }
        )
        return {
            "schema_version": 1,
            "summary": {
                "runs": len(self.runs),
                "result_ok_runs": sum(run.result_ok for run in self.runs),
                "evidence_accepted_runs": sum(run.evidence_accepted for run in self.runs),
                "vendor_pass_runs": sum(run.vendor_passes > 0 for run in self.runs),
                "vendor_fail_only_runs": sum(
                    run.vendor_failures > 0 and run.vendor_passes == 0 for run in self.runs
                ),
                "alignment_poll_runs": sum(
                    run.alignment_poll_count > len(run.alignment_scores)
                    for run in self.runs
                ),
                "total_tokens": sum(run.total_tokens for run in self.runs),
                "mean_elapsed_ms": round(mean(elapsed), 2) if elapsed else 0,
                "recaptcha_userverify_runs": sum(
                    run.recaptcha_userverify_observed for run in self.runs
                ),
                "recaptcha_token_runs": sum(
                    run.provider == "recaptcha" and run.token_length > 0 for run in self.runs
                ),
                "recaptcha_rounds": sum(run.recaptcha_round_count for run in self.runs),
                "normalized_observation_runs": sum(
                    run.observation_count > 0 for run in self.runs
                ),
                "normalized_observations": sum(
                    run.observation_count for run in self.runs
                ),
                "proposed_actions": sum(run.action_count for run in self.runs),
                "validated_actions": sum(
                    run.action_count - run.invalid_action_count for run in self.runs
                ),
                "executed_actions": sum(
                    run.executed_action_count for run in self.runs
                ),
                "unexecuted_actions": sum(
                    run.unexecuted_action_count for run in self.runs
                ),
                "trace_integrity_errors": sum(
                    run.trace_integrity_error_count for run in self.runs
                ),
                "invalid_actions": sum(run.invalid_action_count for run in self.runs),
                "uncertain_actions": sum(run.uncertain_count for run in self.runs),
                "affordances": sum(run.affordance_count for run in self.runs),
                "dynamic_scene_replacements": sum(
                    run.dynamic_scene_replacement_count for run in self.runs
                ),
                "action_kinds": sorted(
                    {
                        kind
                        for run in self.runs
                        for kind in run.action_kinds
                    }
                ),
                "action_planner_backends": sorted(
                    {
                        backend
                        for run in self.runs
                        for backend in run.action_planner_backends
                    }
                ),
                "action_planning_errors": sum(
                    run.action_planning_error_count for run in self.runs
                ),
            },
            "coverage": self.assess_coverage().to_dict(),
            "benchmark": {
                provider: self.assess_benchmark(provider).to_dict()
                for provider in sorted({run.provider for run in self.runs})
            },
            "challenge_benchmark": {
                f"{provider}:{challenge_type}": {
                    **self.assess_challenge_benchmark(provider, challenge_type).to_dict(),
                    "challenge_type": challenge_type,
                }
                for provider, challenge_type in challenge_scopes
            },
            "challenge_matrix": challenge_matrix,
            "runs": [run.to_dict() for run in self.runs],
        }


def _challenge_type(item: dict[str, Any]) -> str:
    request_type = str(item.get("request_type") or "unknown")
    shape_type = item.get("shape_type")
    return f"{request_type}:{shape_type}" if shape_type else request_type


def _recaptcha_challenge_type(item: dict[str, Any]) -> str:
    count = int(item.get("candidate_count") or 0)
    grid = {9: "3x3", 16: "4x4"}.get(count, f"{count}_tiles" if count else "unknown_grid")
    mode = "dynamic" if item.get("dynamic") else "static"
    return f"recaptcha_image_grid:{mode}_{grid}"


def _normalized_challenge_type(item: dict[str, Any]) -> str:
    modality = str(item.get("modality") or "unknown")
    kind = str(item.get("kind") or "unknown")
    rows = item.get("grid_rows")
    columns = item.get("grid_columns")
    if isinstance(rows, int) and isinstance(columns, int):
        mode = "dynamic" if item.get("dynamic") else "static"
        return f"{modality}:{kind}:{mode}_{rows}x{columns}"
    shape = item.get("metadata", {}).get("shape_type") if isinstance(item.get("metadata"), dict) else None
    return f"{modality}:{kind}:{shape}" if shape else f"{modality}:{kind}"


def _prompt_family(prompt: str) -> str:
    normalized = " ".join(str(prompt).casefold().split())
    if not normalized:
        return ""
    # Remove volatile counts and punctuation while retaining semantic words.
    import re

    normalized = re.sub(r"\b\d+\b", "#", normalized)
    normalized = re.sub(r"[^a-z0-9# ]+", " ", normalized)
    return " ".join(normalized.split())


def _prompt_families(prompts: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            family for family in (_prompt_family(item) for item in prompts) if family
        )
    )


_CHALLENGE_KINDS = {
    "binary",
    "point",
    "bounding_box",
    "multiple_choice",
    "drag_drop",
    "slider",
    "token",
    "interactive",
    "unknown",
}
_CHALLENGE_MODALITIES = {"image", "audio", "text", "behavior", "protocol", "unknown"}
_CHALLENGE_PHASES = {"presented", "answering", "submitted", "replaced", "verified", "failed"}
_ACTION_KINDS = {
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
}


def _optional_int(item: dict[str, Any], name: str) -> int | None:
    value = item.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name}_must_be_integer")
    return value


def _parse_observation(item: dict[str, Any]) -> ChallengeObservation:
    observation_id = item.get("observation_id")
    provider = item.get("provider")
    kind = item.get("kind")
    modality = item.get("modality")
    phase = item.get("phase", "presented")
    if not isinstance(observation_id, str) or not observation_id.strip():
        raise ValueError("observation_id_missing")
    if not isinstance(provider, str) or not provider.strip():
        raise ValueError("provider_missing")
    if kind not in _CHALLENGE_KINDS:
        raise ValueError("challenge_kind_invalid")
    if modality not in _CHALLENGE_MODALITIES:
        raise ValueError("challenge_modality_invalid")
    if phase not in _CHALLENGE_PHASES:
        raise ValueError("challenge_phase_invalid")
    raw_candidates = item.get("candidates", [])
    if not isinstance(raw_candidates, list):
        raise ValueError("candidates_must_be_list")
    candidates = tuple(
        ChallengeCandidate(
            index=candidate["index"],
            row=candidate.get("row"),
            column=candidate.get("column"),
            x=candidate.get("x"),
            y=candidate.get("y"),
            width=candidate.get("width"),
            height=candidate.get("height"),
            image_sha256=candidate.get("image_sha256"),
        )
        for candidate in raw_candidates
        if isinstance(candidate, dict) and "index" in candidate
    )
    if len(candidates) != len(raw_candidates):
        raise ValueError("candidate_record_invalid")
    if not all(
        isinstance(candidate.index, int) and not isinstance(candidate.index, bool)
        for candidate in candidates
    ):
        raise ValueError("candidate_index_invalid")
    candidate_count = _optional_int(item, "candidate_count")
    if candidate_count is not None and candidates and len(candidates) != candidate_count:
        raise ValueError("candidate_count_mismatch")
    if len({candidate.index for candidate in candidates}) != len(candidates):
        raise ValueError("candidate_indexes_not_unique")
    raw_choices = item.get("choices", [])
    if not isinstance(raw_choices, (list, tuple)) or not all(
        isinstance(choice, str) for choice in raw_choices
    ):
        raise ValueError("observation_choices_invalid")
    metadata = item.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("observation_metadata_invalid")
    prompt = item.get("prompt", "")
    if not isinstance(prompt, str):
        raise ValueError("observation_prompt_invalid")
    dynamic = item.get("dynamic", False)
    if not isinstance(dynamic, bool):
        raise ValueError("observation_dynamic_invalid")
    raw_affordances = item.get("affordances", [])
    if not isinstance(raw_affordances, list):
        raise ValueError("affordances_must_be_list")
    affordances = tuple(
        ChallengeAffordance(
            affordance_id=affordance["affordance_id"],
            role=affordance["role"],
            label=affordance.get("label", ""),
            x=affordance.get("x"),
            y=affordance.get("y"),
            width=affordance.get("width"),
            height=affordance.get("height"),
            candidate_index=affordance.get("candidate_index"),
            enabled=affordance.get("enabled", True),
            actions=tuple(affordance.get("actions", ())),
            metadata=affordance.get("metadata", {}),
        )
        for affordance in raw_affordances
        if isinstance(affordance, dict)
        and "affordance_id" in affordance
        and "role" in affordance
    )
    if len(affordances) != len(raw_affordances):
        raise ValueError("affordance_record_invalid")
    raw_allowed_actions = item.get("allowed_actions", [])
    if not isinstance(raw_allowed_actions, (list, tuple)):
        raise ValueError("allowed_actions_must_be_list")
    return ChallengeObservation(
        observation_id=observation_id,
        provider=provider,
        kind=kind,
        modality=modality,
        prompt=prompt,
        candidate_count=candidate_count,
        candidates=candidates,
        grid_rows=_optional_int(item, "grid_rows"),
        grid_columns=_optional_int(item, "grid_columns"),
        width=_optional_int(item, "width"),
        height=_optional_int(item, "height"),
        dynamic=dynamic,
        min_answers=_optional_int(item, "min_answers"),
        max_answers=_optional_int(item, "max_answers"),
        choices=tuple(raw_choices),
        affordances=affordances,
        allowed_actions=tuple(raw_allowed_actions),
        phase=phase,
        metadata=metadata,
        schema_version=int(item.get("schema_version") or 1),
    )


def _revalidate_action_trace(
    observations: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> tuple[int, int, int, tuple[str, ...]]:
    by_id: dict[str, ChallengeObservation] = {}
    integrity_errors: list[str] = []
    for index, item in enumerate(observations):
        try:
            observation = _parse_observation(item)
            if observation.observation_id in by_id:
                raise ValueError("duplicate_observation_id")
            by_id[observation.observation_id] = observation
        except (KeyError, TypeError, ValueError) as exc:
            integrity_errors.append(f"observation_{index}:{exc}")

    invalid_count = 0
    executed_count = 0
    unexecuted_count = 0
    for index, item in enumerate(actions):
        invalid = False
        observation_id = item.get("observation_id")
        observation = by_id.get(observation_id) if isinstance(observation_id, str) else None
        if observation is None:
            integrity_errors.append(f"action_{index}:observation_not_found")
            invalid = True
        kind = item.get("kind")
        if kind not in _ACTION_KINDS:
            integrity_errors.append(f"action_{index}:action_kind_invalid")
            invalid = True
        payload = item.get("payload", {})
        if not isinstance(payload, dict):
            integrity_errors.append(f"action_{index}:payload_must_be_object")
            invalid = True
            payload = {}
        confidence = item.get("confidence")
        uncertain = item.get("uncertain", False)
        if not isinstance(uncertain, bool):
            integrity_errors.append(f"action_{index}:uncertain_must_be_boolean")
            invalid = True
            uncertain = False
        if not invalid and observation is not None:
            try:
                action = ChallengeAction(
                    observation_id=observation_id,
                    kind=kind,
                    payload=payload,
                    confidence=confidence,
                    uncertain=uncertain,
                    rationale=str(item.get("rationale") or ""),
                )
                recomputed_errors = action.validate(observation)
                if recomputed_errors:
                    invalid = True
                    integrity_errors.extend(
                        f"action_{index}:{error}" for error in recomputed_errors
                    )
            except (TypeError, ValueError) as exc:
                invalid = True
                integrity_errors.append(f"action_{index}:{exc}")
        recorded_valid = item.get("valid")
        if not isinstance(recorded_valid, bool):
            integrity_errors.append(f"action_{index}:recorded_validity_missing")
            invalid = True
        elif recorded_valid == invalid:
            integrity_errors.append(f"action_{index}:recorded_validity_mismatch")
            invalid = True
        raw_executed = item.get("executed")
        executed = raw_executed is True
        if not isinstance(raw_executed, bool):
            integrity_errors.append(f"action_{index}:executed_state_missing")
        if executed and invalid:
            integrity_errors.append(f"action_{index}:invalid_action_marked_executed")
        if invalid:
            invalid_count += 1
        if executed and not invalid:
            executed_count += 1
        else:
            unexecuted_count += 1
    return (
        invalid_count,
        executed_count,
        unexecuted_count,
        tuple(dict.fromkeys(integrity_errors)),
    )


def evaluate_result(payload: dict[str, Any], *, source: str = "memory") -> ReplayRun:
    if not isinstance(payload, dict):
        raise TypeError("replay payload must be a JSON object")
    diagnostics = payload.get("diagnostics")
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    engine = diagnostics.get("challenge_engine")
    engine = engine if isinstance(engine, dict) else {}
    challenges = [
        item
        for item in diagnostics.get("hcaptcha_challenges", [])
        if isinstance(item, dict)
    ]
    tasks = [item for item in engine.get("vision_tasks", []) if isinstance(item, dict)]
    alignments = [
        item
        for item in engine.get("vision_canvas_alignment", [])
        if isinstance(item, dict)
    ]
    responses = [
        item
        for item in diagnostics.get("hcaptcha_verification_responses", [])
        if isinstance(item, dict)
    ]
    tencent_responses = [
        item
        for item in diagnostics.get("tencent_verification_responses", [])
        if isinstance(item, dict)
    ]
    arkose_responses = [
        item
        for item in diagnostics.get("arkose_verification_responses", [])
        if isinstance(item, dict)
    ]
    observations = [
        item
        for item in diagnostics.get("challenge_observations", [])
        if isinstance(item, dict)
    ]
    recaptcha_rounds = [
        item
        for item in diagnostics.get("recaptcha_rounds", [])
        if isinstance(item, dict)
    ]
    if not recaptcha_rounds:
        # The session adapter records one row per normalized observation. Keep
        # the legacy field as the preferred source for old runs, while making
        # new session traces visible to the reCAPTCHA matrix summary.
        recaptcha_rounds = [
            item
            for item in diagnostics.get("recaptcha_session_observations", [])
            if isinstance(item, dict)
        ]
    if not observations:
        observations = [
            item
            for item in diagnostics.get("arkose_session_observations", [])
            if isinstance(item, dict)
        ]
    actions = [
        item
        for item in diagnostics.get("challenge_actions", [])
        if isinstance(item, dict)
    ]
    session_diagnostics = diagnostics.get("session")
    session_diagnostics = session_diagnostics if isinstance(session_diagnostics, dict) else {}
    browser_observations = [
        item
        for item in session_diagnostics.get("browser_scene_observations", [])
        if isinstance(item, dict)
    ]
    action_planning_outcomes = [
        item
        for item in diagnostics.get("action_planning_outcomes", [])
        if isinstance(item, dict)
    ]
    (
        invalid_action_count,
        executed_action_count,
        unexecuted_action_count,
        trace_integrity_errors,
    ) = _revalidate_action_trace(observations, actions)
    raw = payload.get("raw")
    raw = raw if isinstance(raw, dict) else {}
    raw_events = [item for item in raw.get("events", []) if isinstance(item, dict)]
    recaptcha_userverify_observed = any(
        "/recaptcha/api2/userverify" in str(item.get("url") or "")
        for item in raw_events
    )

    total_tokens = 0
    completion_tokens = 0
    models: list[str] = []
    finish_reasons: list[str] = []
    for task in tasks:
        backend = task.get("backend")
        if not isinstance(backend, dict):
            continue
        usage = backend.get("usage")
        if isinstance(usage, dict):
            total_tokens += int(usage.get("total_tokens") or 0)
            completion_tokens += int(usage.get("completion_tokens") or 0)
        if backend.get("model"):
            models.append(str(backend["model"]))
        if backend.get("finish_reason"):
            finish_reasons.append(str(backend["finish_reason"]))

    scores = tuple(
        float(item["score"])
        for item in alignments
        if isinstance(item.get("score"), (int, float))
    )
    poll_count = sum(
        len(item.get("attempt_scores", []))
        for item in alignments
        if isinstance(item.get("attempt_scores"), list)
    )
    site = diagnostics.get("site_verification")
    site_verified = site.get("ok") if isinstance(site, dict) else None
    harness = diagnostics.get("harness")
    harness = harness if isinstance(harness, dict) else {}
    evidence = harness.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    harness_adapter = harness.get("adapter")
    if isinstance(harness_adapter, dict):
        harness_adapter = harness_adapter.get("provider")
    provider = str(
        payload.get("provider")
        or diagnostics.get("provider")
        or harness_adapter
        or "unknown"
    )
    vendor_passes = sum(item.get("pass") is True for item in responses) + sum(
        item.get("accepted") is True
        and str(item.get("error_code") or "") == "0"
        for item in tencent_responses
    ) + sum(item.get("pass") is True for item in arkose_responses)
    vendor_failures = sum(item.get("pass") is False for item in responses) + sum(
        item.get("accepted") is False for item in tencent_responses
    ) + sum(item.get("pass") is False for item in arkose_responses)
    challenge_types = (
        tuple(dict.fromkeys(_normalized_challenge_type(item) for item in observations))
        if observations
        else tuple(
            dict.fromkeys(
                [_challenge_type(item) for item in challenges]
                + [_recaptcha_challenge_type(item) for item in recaptcha_rounds]
            )
        )
        if challenges or recaptcha_rounds
        else ("image:interactive",)
        if browser_observations
        else ()
    )
    prompts = tuple(
        dict.fromkeys(
            (
                [
                    str(item.get("prompt"))
                    for item in observations
                    if isinstance(item.get("prompt"), str) and item.get("prompt")
                ]
                if observations
                else [
                    str(item.get("prompt"))
                    for item in challenges
                    if isinstance(item.get("prompt"), str) and item.get("prompt")
                ]
                + [
                    str(item.get("prompt"))
                    for item in recaptcha_rounds
                    if isinstance(item.get("prompt"), str) and item.get("prompt")
                ]
                + [
                    str(item.get("prompt"))
                    for item in browser_observations
                    if isinstance(item.get("prompt"), str) and item.get("prompt")
                ]
            )
        )
    )
    token_length = int(
        diagnostics.get("token_len")
        or raw.get("token_len")
        or (
            len(payload.get("turnstile_token"))
            if isinstance(payload.get("turnstile_token"), str)
            else 0
        )
        or (
            len(payload.get("cf_clearance"))
            if isinstance(payload.get("cf_clearance"), str)
            else 0
        )
        or (len(payload.get("ticket")) if isinstance(payload.get("ticket"), str) else 0)
        or max(
            (int(item.get("token_len") or 0) for item in responses),
            default=0,
        )
        or 0
    )
    evidence_accepted = bool(evidence.get("accepted")) if evidence else False
    if not evidence:
        if provider == "hcaptcha":
            evidence_accepted = bool(payload.get("ok")) and vendor_passes > 0 and token_length > 0
        elif provider == "recaptcha":
            evidence_accepted = (
                bool(payload.get("ok"))
                and token_length > 0
                and recaptcha_userverify_observed
            )
        elif provider == "arkose":
            evidence_accepted = (
                bool(payload.get("ok"))
                and token_length > 0
                and any(item.get("pass") is True for item in arkose_responses)
            )
        elif provider in {"tencent", "geetest"}:
            tencent_session = diagnostics.get("tencent_session_verification")
            tencent_session = tencent_session if isinstance(tencent_session, dict) else {}
            if provider == "tencent":
                evidence_accepted = (
                    bool(payload.get("ok"))
                    and token_length > 0
                    and (
                        any(
                            item.get("accepted") is True
                            and str(item.get("error_code") or "") == "0"
                            for item in tencent_responses
                        )
                        or tencent_session.get("accepted") is True
                        or str(raw.get("error_code") or "") == "0"
                    )
                )
            else:
                evidence_accepted = bool(payload.get("ok")) and token_length > 0
        elif provider in {"cloudflare", "turnstile"}:
            clearance = payload.get("cf_clearance") or raw.get("cf_clearance")
            turnstile_token = payload.get("turnstile_token") or raw.get("turnstile_token")
            evidence_accepted = bool(payload.get("ok")) and bool(
                clearance
                or (
                    isinstance(turnstile_token, str)
                    and "dummy.token" not in turnstile_token.casefold()
                )
                or site_verified is True
            )
    uncertain_count = sum(bool(item.get("uncertain")) for item in actions)
    if not uncertain_count:
        # Legacy reCAPTCHA traces predate action-level uncertainty fields.
        uncertain_count = sum(bool(item.get("uncertain")) for item in recaptcha_rounds)
    normalized_prompts = _prompt_families(prompts)
    affordance_count = sum(
        len(item.get("affordances", []))
        for item in observations
        if isinstance(item.get("affordances", []), list)
    )
    if not observations:
        affordance_count = sum(
            int(item.get("affordance_count") or 0) for item in browser_observations
        )
    affordance_roles = tuple(
        dict.fromkeys(
            str(affordance.get("role"))
            for item in observations
            for affordance in item.get("affordances", [])
            if isinstance(affordance, dict) and affordance.get("role")
        )
    )
    action_kinds = tuple(
        dict.fromkeys(
            str(item.get("kind")) for item in actions if isinstance(item.get("kind"), str)
        )
    )
    action_planner_backends = tuple(
        dict.fromkeys(
            str(backend.get("backend"))
            for item in action_planning_outcomes
            for backend in (item.get("backend"),)
            if isinstance(backend, dict) and backend.get("backend")
        )
    )
    raw_action_planning_errors = diagnostics.get("action_planning_errors")
    action_planning_error_count = (
        len(raw_action_planning_errors)
        if isinstance(raw_action_planning_errors, list)
        else sum(
            len(item.get("errors", []))
            for item in action_planning_outcomes
            if isinstance(item.get("errors", []), list)
        )
    )
    dynamic_scene_replacement_count = sum(
        bool(item.get("dynamic") or item.get("scene_changed_since_previous"))
        for item in observations
    )
    dynamic_scene_replacement_count = max(
        dynamic_scene_replacement_count,
        sum(
            bool(item.get("dynamic") or item.get("scene_changed_since_previous"))
            for item in browser_observations
        ),
        int(session_diagnostics.get("browser_scene_replacements") or 0),
    )
    normalized_visual_tasks = sum(
        item.get("modality") == "image"
        and item.get("phase", "presented") == "presented"
        for item in observations
    )
    if not observations:
        normalized_visual_tasks = len(browser_observations)
    return ReplayRun(
        source=source,
        provider=provider,
        result_ok=bool(payload.get("ok")),
        evidence_accepted=evidence_accepted,
        elapsed_ms=int(payload.get("elapsed_ms") or 0),
        challenge_types=challenge_types,
        prompts=prompts,
        vision_task_count=len(tasks) or normalized_visual_tasks,
        models=tuple(dict.fromkeys(models)),
        finish_reasons=tuple(dict.fromkeys(finish_reasons)),
        total_tokens=total_tokens,
        completion_tokens=completion_tokens,
        alignment_scores=scores,
        alignment_poll_count=poll_count,
        vendor_passes=vendor_passes,
        vendor_failures=vendor_failures,
        site_verified=site_verified,
        attribution=(
            "single_challenge"
            if (
                int(diagnostics.get("recaptcha_attempts") or bool(recaptcha_rounds))
                if provider == "recaptcha"
                else len(observations) or len(browser_observations) or len(challenges)
            )
            == 1
            else "multi_challenge_ambiguous"
        ),
        recaptcha_round_count=sum(
            item.get("phase") in {None, "presented"} for item in recaptcha_rounds
        ),
        recaptcha_attempts=int(diagnostics.get("recaptcha_attempts") or 0),
        recaptcha_dynamic_rounds=sum(
            bool(item.get("dynamic")) for item in recaptcha_rounds
        ),
        recaptcha_refresh_count=sum(
            bool(item.get("refresh_observed")) for item in recaptcha_rounds
        ),
        recaptcha_action_labels=tuple(
            dict.fromkeys(
                label
                for item in recaptcha_rounds
                for label in (
                    str(item.get("action"))
                    if item.get("action")
                    else "refresh"
                    if item.get("refresh_observed")
                    else None,
                )
                if label
            )
        ),
        recaptcha_userverify_observed=recaptcha_userverify_observed,
        token_length=token_length,
        adapter=str(harness.get("adapter")) if harness.get("adapter") else None,
        observation_count=len(observations) or len(browser_observations),
        action_count=len(actions),
        invalid_action_count=invalid_action_count,
        executed_action_count=executed_action_count,
        unexecuted_action_count=unexecuted_action_count,
        trace_integrity_error_count=len(trace_integrity_errors),
        trace_integrity_errors=trace_integrity_errors,
        modalities=(
            tuple(
                dict.fromkeys(
                    str(item.get("modality") or "unknown") for item in observations
                )
            )
            if observations
            else ("image",)
            if browser_observations
            else ()
        ),
        normalized_kinds=(
            tuple(
                dict.fromkeys(str(item.get("kind") or "unknown") for item in observations)
            )
            if observations
            else ("interactive",)
            if browser_observations
            else ()
        ),
        uncertain_count=uncertain_count,
        prompt_families=normalized_prompts,
        observation_ids=tuple(
            dict.fromkeys(
                str(item.get("observation_id"))
                for item in observations
                if isinstance(item.get("observation_id"), str)
                and item.get("observation_id")
            )
        ),
        affordance_count=affordance_count,
        affordance_roles=affordance_roles,
        action_kinds=action_kinds,
        action_planner_backends=action_planner_backends,
        action_planning_error_count=action_planning_error_count,
        dynamic_scene_replacement_count=dynamic_scene_replacement_count,
    )


def _result_paths(inputs: Iterable[str | Path]) -> list[Path]:
    paths: list[Path] = []
    for value in inputs:
        path = Path(value).expanduser().resolve()
        if path.is_dir():
            paths.extend(path.rglob("result.json"))
        elif path.is_file():
            paths.append(path)
        else:
            raise FileNotFoundError(f"replay input does not exist: {path}")
    return sorted(dict.fromkeys(paths))


def evaluate_replays(inputs: Iterable[str | Path]) -> ReplayReport:
    runs = []
    for path in _result_paths(inputs):
        payload = json.loads(path.read_text(encoding="utf-8"))
        runs.append(evaluate_result(payload, source=str(path)))
    return ReplayReport(tuple(runs))
