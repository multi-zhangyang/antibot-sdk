from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from ..profiles import detect_provider_for_url
from .adapters import DEFAULT_ADAPTER_REGISTRY, SUPPORTED_ADAPTER_PROVIDERS
from .models import HarnessDecision, HarnessEpisode

SUPPORTED_HARNESS_PROVIDERS = SUPPORTED_ADAPTER_PROVIDERS


@runtime_checkable
class HarnessPlanner(Protocol):
    name: str

    async def plan(self, episode: HarnessEpisode) -> HarnessDecision:
        """Choose one registered action without executing it."""


class HeuristicPlanner:
    """Deterministic provider router used when no model planner is configured."""

    name = "heuristic"

    async def plan(self, episode: HarnessEpisode) -> HarnessDecision:
        requested = episode.request.provider.strip().lower()
        if requested == "auto":
            provider = detect_provider_for_url(episode.request.target_url)
        else:
            adapter = DEFAULT_ADAPTER_REGISTRY.resolve(requested)
            provider = adapter.provider if adapter else requested
        if provider not in SUPPORTED_HARNESS_PROVIDERS:
            return HarnessDecision(
                action="fail",
                rationale="no supported provider could be selected from the request",
                confidence=1.0,
            )
        return HarnessDecision(
            action="solve_provider",
            provider=provider,
            strategy=(
                DEFAULT_ADAPTER_REGISTRY.resolve(provider).strategies[0]
                if DEFAULT_ADAPTER_REGISTRY.resolve(provider)
                else "provider_native"
            ),
            rationale=f"route the episode to the registered {provider} adapter and solver tool",
            confidence=1.0,
        )


class PydanticAIPlanner:
    """Optional typed planner backed by Pydantic AI and an OpenAI-compatible model."""

    name = "pydantic_ai"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_sec: float = 30.0,
    ) -> None:
        if not base_url.strip() or not api_key.strip() or not model.strip():
            raise ValueError("base_url, api_key and model are required for PydanticAIPlanner")
        try:
            from openai import AsyncOpenAI
            from pydantic import BaseModel, Field
            from pydantic_ai import Agent
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider
        except ImportError as exc:
            raise RuntimeError(
                "PydanticAIPlanner requires the agent extra: "
                "install with `pip install -e '.[agent]'` or `uv sync --extra agent`"
            ) from exc

        class PlannerOutput(BaseModel):
            action: str = Field(pattern="^(solve_provider|fail)$")
            provider: str | None = None
            strategy: str = "provider_native"
            rationale: str = ""
            confidence: float | None = Field(default=None, ge=0, le=1)

        normalized = base_url.rstrip("/")
        if not normalized.endswith("/v1"):
            normalized += "/v1"
        client = AsyncOpenAI(
            base_url=normalized,
            api_key=api_key,
            timeout=max(1.0, timeout_sec),
        )
        chat_model = OpenAIChatModel(
            model,
            provider=OpenAIProvider(openai_client=client),
        )
        self._agent = Agent(
            chat_model,
            output_type=PlannerOutput,
            instructions=(
                "You route a CAPTCHA solving episode to exactly one registered provider tool. "
                "Use only the provider hint, URL host/path, and the supplied provider list. "
                "Never claim that a CAPTCHA passed, never create tokens, and never modify user "
                "options. Return fail when the provider cannot be identified reliably."
            ),
        )

    async def plan(self, episode: HarnessEpisode) -> HarnessDecision:
        parsed = urlparse(episode.request.target_url)
        prompt = json.dumps(
            {
                "provider_hint": episode.request.provider,
                "target": {
                    "host": parsed.hostname or "",
                    "path": parsed.path,
                },
                "registered_providers": list(SUPPORTED_HARNESS_PROVIDERS),
                "adapter_capabilities": list(DEFAULT_ADAPTER_REGISTRY.describe()),
                "remaining_steps": episode.budget.max_steps - episode.steps,
            },
            ensure_ascii=True,
        )
        result = await self._agent.run(prompt)
        output: Any = result.output
        provider = str(output.provider).lower() if output.provider else None
        action = str(output.action)
        if action == "solve_provider" and provider not in SUPPORTED_HARNESS_PROVIDERS:
            return HarnessDecision(
                action="fail",
                rationale="model selected a provider outside the registered tool set",
                confidence=0.0,
            )
        return HarnessDecision(
            action="solve_provider" if action == "solve_provider" else "fail",
            provider=provider,
            strategy=str(output.strategy),
            rationale=str(output.rationale)[:500],
            confidence=output.confidence,
        )
