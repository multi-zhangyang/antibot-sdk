from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from ..models import BrowserResult, CaptchaResult
from ..vision import VisionBackend, VisionSolvePolicy
from .adapters import DEFAULT_ADAPTER_REGISTRY, ProviderAdapterRegistry
from .agent import (
    ChallengeAgentLoop,
    ChallengeLoopResult,
    ChallengeSession,
    ChallengeStrategyRegistry,
    VisionChallengePolicy,
)
from .models import (
    HarnessBudget,
    HarnessDecision,
    HarnessEpisode,
    HarnessEvent,
    HarnessEvidence,
    HarnessRequest,
    HarnessState,
)
from .multimodal import ActionPlanningBackend
from .planners import HarnessPlanner, HeuristicPlanner

SolveResult = BrowserResult | CaptchaResult
ProviderRunner = Callable[[str, str, dict[str, Any]], Awaitable[SolveResult]]

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "cookie",
    "password",
    "proxy",
    "secret",
    "ticket",
    "token",
)


def _safe_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): (
                "***"
                if any(part in str(key).lower() for part in _SENSITIVE_KEY_PARTS)
                else _safe_payload(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_payload(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)[:300]


class HarnessToolHandler(Protocol):
    async def __call__(self, episode: HarnessEpisode, arguments: dict[str, Any]) -> Any: ...


@dataclass(frozen=True, slots=True)
class HarnessTool:
    name: str
    description: str
    handler: HarnessToolHandler


class HarnessToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, HarnessTool] = {}

    def register(self, tool: HarnessTool) -> None:
        if not tool.name.strip():
            raise ValueError("harness tool name must not be empty")
        if tool.name in self._tools:
            raise ValueError(f"harness tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    async def invoke(
        self,
        name: str,
        episode: HarnessEpisode,
        arguments: dict[str, Any],
    ) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"unknown harness tool: {name}")
        return await tool.handler(episode, dict(arguments))


def _extract_evidence(
    result: SolveResult,
    provider: str,
    adapters: ProviderAdapterRegistry = DEFAULT_ADAPTER_REGISTRY,
) -> HarnessEvidence:
    verification = adapters.verify_result(result, provider)
    return HarnessEvidence(
        accepted=verification.accepted,
        result_ok=bool(result.ok),
        vendor_pass=verification.vendor_pass,
        vendor_failures=verification.vendor_failures,
        token_length=verification.token_length,
        site_verified=verification.site_verified,
        gaps=verification.gaps,
        adapter=verification.provider,
        verifier_events=verification.verifier_events,
    )


class CaptchaHarness:
    """Auditable episode runtime around deterministic provider solver tools."""

    def __init__(
        self,
        provider_runner: ProviderRunner | None = None,
        *,
        planner: HarnessPlanner | None = None,
        budget: HarnessBudget | None = None,
        tools: HarnessToolRegistry | None = None,
        adapters: ProviderAdapterRegistry | None = None,
    ) -> None:
        self.provider_runner = provider_runner
        self.planner = planner or HeuristicPlanner()
        self.budget = budget or HarnessBudget()
        self.tools = tools or HarnessToolRegistry()
        self.adapters = adapters or DEFAULT_ADAPTER_REGISTRY
        if self.provider_runner is not None and "provider.solve" not in self.tools.names():
            self.tools.register(
                HarnessTool(
                    name="provider.solve",
                    description="Run one existing provider solver and return its unmodified result",
                    handler=self._run_provider,
                )
            )

    async def _run_provider(
        self,
        episode: HarnessEpisode,
        arguments: dict[str, Any],
    ) -> SolveResult:
        provider = str(arguments.get("provider") or "").lower()
        if self.provider_runner is None:
            raise RuntimeError("provider runner is not configured")
        adapter = self.adapters.resolve(provider)
        if adapter is None:
            raise ValueError(f"provider is not registered in the harness: {provider}")
        provider = adapter.provider
        return await self.provider_runner(
            episode.request.target_url,
            provider,
            dict(episode.request.options),
        )

    async def solve_session(
        self,
        session: ChallengeSession,
        vision_backend: VisionBackend,
        *,
        strategies: ChallengeStrategyRegistry | None = None,
        solve_policy: VisionSolvePolicy | None = None,
        action_backend: ActionPlanningBackend | None = None,
        budget: HarnessBudget | None = None,
    ) -> ChallengeLoopResult:
        """Run the provider-neutral loop without a black-box provider solver."""

        run_budget = budget or self.budget
        return await ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                vision_backend,
                solve_policy=solve_policy,
                strategies=strategies,
                action_backend=action_backend,
            ),
            max_steps=run_budget.max_steps,
            timeout_sec=run_budget.timeout_sec,
        ).run()

    async def solve(
        self,
        target_url: str,
        *,
        provider: str = "auto",
        options: dict[str, Any] | None = None,
        budget: HarnessBudget | None = None,
    ) -> SolveResult:
        if not isinstance(target_url, str) or not target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider must be a non-empty string")
        run_budget = budget or self.budget
        request = HarnessRequest(
            target_url=target_url,
            provider=provider.strip().lower(),
            options=dict(options or {}),
        )
        episode = HarnessEpisode(uuid.uuid4().hex, request, run_budget)
        started = time.monotonic()

        def transition(state: HarnessState, kind: str, payload: dict[str, Any]) -> None:
            episode.state = state
            episode.steps += 1
            episode.events.append(
                HarnessEvent(
                    sequence=len(episode.events) + 1,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    state=state,
                    kind=kind,
                    payload=_safe_payload(payload),
                )
            )
            if episode.steps > run_budget.max_steps:
                raise RuntimeError("harness step budget exhausted")

        parsed = urlparse(target_url)
        transition(
            HarnessState.OBSERVING,
            "request_observed",
            {
                "target_host": parsed.hostname or "",
                "target_path": parsed.path,
                "provider_hint": request.provider,
                "option_names": sorted(request.options),
            },
        )
        transition(HarnessState.PLANNING, "planner_started", {"planner": self.planner.name})
        try:
            remaining = max(0.01, run_budget.timeout_sec - (time.monotonic() - started))
            decision = await asyncio.wait_for(self.planner.plan(episode), timeout=remaining)
            adapter = self.adapters.resolve(decision.provider)
            episode.adapter = adapter.provider if adapter else None
            transition(
                HarnessState.PLANNING,
                "plan_created",
                {
                    "action": decision.action,
                    "provider": decision.provider,
                    "strategy": decision.strategy,
                    "rationale": decision.rationale,
                    "confidence": decision.confidence,
                    "adapter": adapter.to_dict() if adapter else None,
                },
            )
            if decision.action != "solve_provider" or not decision.provider:
                return self._failure_result(episode, decision, "planner did not select a solver")
            episode.provider_actions += 1
            if episode.provider_actions > run_budget.max_provider_actions:
                raise RuntimeError("harness provider action budget exhausted")
            transition(
                HarnessState.ACTING,
                "tool_started",
                {"tool": "provider.solve", "provider": decision.provider},
            )
            remaining = max(0.01, run_budget.timeout_sec - (time.monotonic() - started))
            result = await asyncio.wait_for(
                self.tools.invoke(
                    "provider.solve",
                    episode,
                    {"provider": decision.provider},
                ),
                timeout=remaining,
            )
            transition(
                HarnessState.VERIFYING,
                "provider_result_received",
                {"provider": decision.provider, "result_ok": result.ok},
            )
            episode.evidence = _extract_evidence(result, decision.provider, self.adapters)
            final_state = (
                HarnessState.COMPLETED if episode.evidence.accepted else HarnessState.FAILED
            )
            transition(
                final_state,
                "evidence_evaluated",
                episode.evidence.to_dict(),
            )
            if not episode.evidence.accepted and result.ok:
                result.ok = False
                result.errors.extend(gap for gap in episode.evidence.gaps if gap not in result.errors)
            self._attach_episode(result, episode)
            return result
        except asyncio.TimeoutError:
            decision = HarnessDecision(action="fail", rationale="harness timeout exhausted")
            return self._failure_result(episode, decision, "harness timeout exhausted")
        except Exception as exc:
            decision = HarnessDecision(action="fail", rationale=str(exc))
            return self._failure_result(
                episode,
                decision,
                f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _attach_episode(result: SolveResult, episode: HarnessEpisode) -> None:
        result.diagnostics = dict(result.diagnostics)
        result.diagnostics["harness"] = episode.to_dict()
        output_json = result.artifacts.get("output_json")
        if not isinstance(output_json, str) or not output_json.strip():
            return
        target = Path(output_json).expanduser()
        pending = target.with_name(f".{target.name}.{episode.episode_id}.tmp")
        try:
            pending.write_text(
                json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            pending.replace(target)
        except (OSError, TypeError, ValueError) as exc:
            result.diagnostics["harness_artifact_error"] = (
                f"{type(exc).__name__}: unable to persist attached harness trace"
            )
        finally:
            try:
                pending.unlink(missing_ok=True)
            except OSError:
                pass

    def _failure_result(
        self,
        episode: HarnessEpisode,
        decision: HarnessDecision,
        error: str,
    ) -> CaptchaResult:
        if episode.state != HarnessState.FAILED:
            episode.state = HarnessState.FAILED
            episode.events.append(
                HarnessEvent(
                    sequence=len(episode.events) + 1,
                    elapsed_ms=episode.events[-1].elapsed_ms if episode.events else 0,
                    state=HarnessState.FAILED,
                    kind="episode_failed",
                    payload={"error": error, "rationale": decision.rationale[:500]},
                )
            )
        result = CaptchaResult(
            provider=decision.provider or episode.request.provider or "unknown",
            ok=False,
            captcha_type=None,
            capability="agent_harness",
            diagnostics={},
            errors=[error],
        )
        self._attach_episode(result, episode)
        return result
