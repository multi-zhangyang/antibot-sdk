"""Provider-neutral challenge agent loop.

The loop deliberately knows nothing about hCaptcha, reCAPTCHA, or a vendor's
wire format.  A provider adapter owns observation/media translation and DOM or
protocol execution; this module owns sequencing, action validation, retries,
and verification gates.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol, runtime_checkable

from ..vision import VisionBackend, VisionSolvePolicy, VisionTask, solve_vision_task
from .contracts import ChallengeAction, ChallengeObservation, VendorVerification
from .execution import (
    ChallengeActionRejected,
    ChallengeExecutor,
    action_from_vision,
)
from .multimodal import ActionPlanningBackend, solve_challenge_action

LoopStatus = Literal["verified", "failed", "unsupported", "timeout"]


@runtime_checkable
class ChallengeSession(Protocol):
    """Adapter boundary for one live challenge episode."""

    async def observe(self) -> ChallengeObservation | None:
        """Return the current state, or ``None`` when no challenge remains."""

    async def vision_task(self, observation: ChallengeObservation) -> VisionTask | None:
        """Return normalized media for a visual observation, if available."""

    async def execute(self, action: ChallengeAction) -> None:
        """Execute one already validated action against the current state."""

    async def verify(self) -> VendorVerification:
        """Collect vendor/site evidence without inferring success from UI state."""


@dataclass(frozen=True, slots=True)
class ChallengeLoopResult:
    status: LoopStatus
    verification: VendorVerification
    diagnostics: dict[str, Any]
    steps: int
    elapsed_ms: int
    errors: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.status == "verified" and self.verification.accepted

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.verification.provider,
            "ok": self.accepted,
            "status": self.status,
            "accepted": self.accepted,
            "verification": self.verification.to_dict(),
            "diagnostics": self.diagnostics,
            "steps": self.steps,
            "elapsed_ms": self.elapsed_ms,
            "errors": list(self.errors),
        }


ChallengeStrategy = Callable[
    [ChallengeSession, ChallengeObservation, dict[str, Any]],
    Awaitable[ChallengeAction],
]


class ChallengeStrategyRegistry:
    """Map normalized challenge kinds to independently replaceable policies."""

    def __init__(self) -> None:
        self._strategies: dict[str, ChallengeStrategy] = {}

    def register(self, kind: str, strategy: ChallengeStrategy) -> None:
        key = kind.strip().casefold()
        if not key:
            raise ValueError("challenge strategy kind must not be empty")
        if key in self._strategies:
            raise ValueError(f"challenge strategy already registered: {kind}")
        self._strategies[key] = strategy

    def resolve(self, kind: str) -> ChallengeStrategy | None:
        return self._strategies.get(kind.strip().casefold())

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._strategies))


class VisionChallengePolicy:
    """Default policy for normalized visual observations."""

    def __init__(
        self,
        backend: VisionBackend,
        *,
        solve_policy: VisionSolvePolicy | None = None,
        strategies: ChallengeStrategyRegistry | None = None,
        action_backend: ActionPlanningBackend | None = None,
    ) -> None:
        self.backend = backend
        self.action_backend = action_backend
        self.solve_policy = solve_policy or VisionSolvePolicy(
            require_confidence=True,
            allow_uncertain=True,
        )
        self.strategies = strategies or ChallengeStrategyRegistry()
        if strategies is None:
            for kind in (
                "binary",
                "point",
                "bounding_box",
                "multiple_choice",
                "drag_drop",
            ):
                self.strategies.register(kind, self._solve_visual)
            self.strategies.register("token", self._submit_token)
            if self.action_backend is not None:
                self.strategies.register("interactive", self._solve_interactive)
                self.strategies.register("unknown", self._solve_interactive)

    async def decide(
        self,
        session: ChallengeSession,
        observation: ChallengeObservation,
        diagnostics: dict[str, Any],
    ) -> ChallengeAction:
        if observation.phase == "answering":
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="submit",
                rationale="observation is ready for vendor verification",
            )
        strategy = self.strategies.resolve(observation.kind)
        if strategy is None:
            # A caller-supplied registry extends the built-in visual policy;
            # it does not need to duplicate every default strategy.  Provider
            # adapters can register only their specialized kinds (for example
            # a slider action) while point/binary scenes keep the shared
            # vision implementation.
            if observation.kind in {
                "binary",
                "point",
                "bounding_box",
                "multiple_choice",
                "drag_drop",
            }:
                return await self._solve_visual(session, observation, diagnostics)
            if observation.kind == "token":
                return await self._submit_token(session, observation, diagnostics)
            if observation.kind == "interactive" and self.action_backend is not None:
                return await self._solve_interactive(session, observation, diagnostics)
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="challenge kind is not registered in the strategy policy",
            )
        return await strategy(session, observation, diagnostics)

    async def _solve_visual(
        self,
        session: ChallengeSession,
        observation: ChallengeObservation,
        diagnostics: dict[str, Any],
    ) -> ChallengeAction:
        task = await session.vision_task(observation)
        if task is None:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="adapter did not provide normalized media for observation",
            )
        outcome = await solve_vision_task(
            self.backend,
            task,
            policy=self.solve_policy,
            diagnostics=diagnostics,
        )
        diagnostics.setdefault("vision_answers", []).append(
            {
                "observation_id": observation.observation_id,
                "kind": outcome.answer.kind,
                "confidence": outcome.answer.confidence,
                "diagnostics": outcome.answer.diagnostics,
            }
        )
        if outcome.uncertain:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="reload",
                uncertain=True,
                rationale="vision answer is syntactically valid but below confidence policy",
            )
        translator = getattr(session, "translate_vision_answer", None)
        if callable(translator):
            action = translator(observation, outcome.answer)
            if not isinstance(action, ChallengeAction):
                raise TypeError("session vision translator must return ChallengeAction")
            return action
        return action_from_vision(observation, outcome.answer)

    async def _submit_token(
        self,
        _session: ChallengeSession,
        observation: ChallengeObservation,
        _diagnostics: dict[str, Any],
    ) -> ChallengeAction:
        return ChallengeAction(
            observation_id=observation.observation_id,
            kind="submit",
            rationale="token observation is ready for vendor verification",
        )

    async def _solve_interactive(
        self,
        session: ChallengeSession,
        observation: ChallengeObservation,
        diagnostics: dict[str, Any],
    ) -> ChallengeAction:
        if self.action_backend is None:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="interactive observation requires an action planning backend",
            )
        if observation.kind == "unknown" and not observation.affordances:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="unknown observation has no declared affordances",
            )
        task = await session.vision_task(observation)
        if task is None:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="adapter did not provide media for interactive observation",
            )
        history = diagnostics.get("challenge_actions", [])
        outcome = await solve_challenge_action(
            self.action_backend,
            observation,
            task,
            policy=self.solve_policy,
            history=history if isinstance(history, list) else (),
            diagnostics=diagnostics,
        )
        diagnostics.setdefault("action_planning_outcomes", []).append(
            {
                "observation_id": observation.observation_id,
                "uncertain": outcome.uncertain,
                "errors": list(outcome.errors),
                "backend": outcome.diagnostics,
            }
        )
        if outcome.uncertain:
            for kind in ("reload", "noop"):
                if kind in observation.supported_actions:
                    return ChallengeAction(
                        observation_id=observation.observation_id,
                        kind=kind,  # type: ignore[arg-type]
                        uncertain=True,
                        rationale="interactive action proposal is below confidence policy",
                    )
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                uncertain=True,
                rationale="interactive action proposal is below confidence policy",
            )
        if outcome.action is None:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="fail",
                rationale="interactive action backend returned no action",
            )
        return outcome.action


class ChallengeAgentLoop:
    """Run a bounded observation/action/verification episode."""

    def __init__(
        self,
        session: ChallengeSession,
        policy: VisionChallengePolicy,
        *,
        max_steps: int = 12,
        timeout_sec: float = 180.0,
    ) -> None:
        if max_steps < 1:
            raise ValueError("challenge loop max_steps must be positive")
        if timeout_sec <= 0:
            raise ValueError("challenge loop timeout_sec must be positive")
        self.session = session
        self.policy = policy
        self.max_steps = max_steps
        self.timeout_sec = timeout_sec

    async def run(self) -> ChallengeLoopResult:
        started = time.monotonic()
        diagnostics: dict[str, Any] = {
            "loop": {
                "max_steps": self.max_steps,
                "timeout_sec": self.timeout_sec,
                "policy": type(self.policy).__name__,
            }
        }
        session_diagnostics = getattr(self.session, "diagnostics", None)
        if isinstance(session_diagnostics, dict):
            # Adapters may expose redacted, provider-neutral diagnostics (for
            # example DOM scene replacement counts). Keep them beside the
            # normalized executor trace instead of silently dropping them.
            #
            # This must be a new mapping. Keeping the adapter's root mapping
            # here creates a self-reference when a provider merges the loop
            # trace back into its own diagnostics after the run.
            diagnostics["session"] = dict(session_diagnostics)
        executor = ChallengeExecutor(diagnostics)
        errors: list[str] = []
        steps = 0
        status: LoopStatus = "failed"
        seen_observations: set[str] = set()
        try:
            while steps < self.max_steps:
                remaining = self.timeout_sec - (time.monotonic() - started)
                if remaining <= 0:
                    status = "timeout"
                    errors.append("challenge_loop_timeout")
                    break
                observation = await asyncio.wait_for(
                    self.session.observe(), timeout=max(0.01, remaining)
                )
                if observation is None:
                    verification = await self._verify(remaining)
                    status = "verified" if verification.accepted else "failed"
                    if not verification.accepted:
                        errors.extend(verification.gaps)
                    return self._result(
                        status,
                        verification,
                        diagnostics,
                        steps,
                        started,
                        errors,
                    )
                if observation.observation_id in seen_observations:
                    status = "failed"
                    errors.append("stale_observation_repeated_after_action")
                    break
                seen_observations.add(observation.observation_id)
                executor.observe(observation)
                steps += 1
                if observation.phase in {"submitted", "verified", "failed"}:
                    verification = await self._verify(remaining)
                    status = "verified" if verification.accepted else "failed"
                    if not verification.accepted:
                        errors.extend(verification.gaps)
                    return self._result(
                        status,
                        verification,
                        diagnostics,
                        steps,
                        started,
                        errors,
                    )

                remaining = self.timeout_sec - (time.monotonic() - started)
                action = await asyncio.wait_for(
                    self.policy.decide(self.session, observation, diagnostics),
                    timeout=max(0.01, remaining),
                )
                validation = executor.require(observation, action)
                if action.kind == "fail":
                    status = "unsupported"
                    errors.append(action.rationale or "unsupported_challenge_kind")
                    break
                remaining = self.timeout_sec - (time.monotonic() - started)
                if remaining <= 0:
                    status = "timeout"
                    errors.append("challenge_loop_timeout_before_execute")
                    break
                await asyncio.wait_for(
                    self.session.execute(action), timeout=max(0.01, remaining)
                )
                executor.mark_executed(validation)
                # A submit can produce another challenge asynchronously.  The
                # next loop iteration must observe that replacement before the
                # session is considered verified.
            else:
                status = "failed"
                errors.append("challenge_loop_step_budget_exhausted")
        except asyncio.TimeoutError:
            status = "timeout"
            errors.append("challenge_loop_timeout")
        except ChallengeActionRejected as exc:
            status = "failed"
            errors.extend(exc.errors)
        except Exception as exc:
            status = "failed"
            errors.append(f"{type(exc).__name__}: {exc}")

        verification = await self._verify(
            max(0.01, self.timeout_sec - (time.monotonic() - started))
        )
        if verification.accepted and status == "failed":
            status = "verified"
        if not verification.accepted:
            errors.extend(verification.gaps)
        return self._result(status, verification, diagnostics, steps, started, errors)

    async def _verify(self, remaining: float) -> VendorVerification:
        if remaining <= 0:
            return VendorVerification(
                provider="unknown",
                accepted=False,
                gaps=("challenge_loop_timeout_before_verify",),
            )
        try:
            return await asyncio.wait_for(
                self.session.verify(), timeout=max(0.01, remaining)
            )
        except asyncio.TimeoutError:
            return VendorVerification(
                provider="unknown",
                accepted=False,
                gaps=("challenge_verification_timeout",),
            )
        except Exception as exc:
            return VendorVerification(
                provider="unknown",
                accepted=False,
                gaps=(f"challenge_verification_error:{type(exc).__name__}",),
            )

    def _result(
        self,
        status: LoopStatus,
        verification: VendorVerification,
        diagnostics: dict[str, Any],
        steps: int,
        started: float,
        errors: list[str],
    ) -> ChallengeLoopResult:
        session_diagnostics = getattr(self.session, "diagnostics", None)
        if isinstance(session_diagnostics, dict):
            # Refresh the snapshot at the result boundary so keys created by
            # the adapter during execution are retained without ever storing
            # the adapter's root mapping itself.
            diagnostics["session"] = dict(session_diagnostics)
        harness_trace = diagnostics.setdefault("harness", {})
        if isinstance(harness_trace, dict):
            harness_trace.setdefault("adapter", verification.provider)
            harness_trace["evidence"] = {
                "accepted": verification.accepted,
                "provider": verification.provider,
                "token_length": verification.token_length,
                "vendor_pass": verification.vendor_pass,
                "vendor_failures": verification.vendor_failures,
                "site_verified": verification.site_verified,
                "verifier_events": list(verification.verifier_events),
                "gaps": list(verification.gaps),
            }
        return ChallengeLoopResult(
            status=status,
            verification=verification,
            diagnostics=diagnostics,
            steps=steps,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            errors=tuple(dict.fromkeys(errors)),
        )


__all__ = [
    "ChallengeAgentLoop",
    "ChallengeLoopResult",
    "ChallengeSession",
    "ChallengeStrategyRegistry",
    "VisionChallengePolicy",
]
