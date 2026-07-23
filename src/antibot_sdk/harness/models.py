from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal


class HarnessState(str, Enum):
    CREATED = "created"
    OBSERVING = "observing"
    PLANNING = "planning"
    ACTING = "acting"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


HarnessAction = Literal["solve_provider", "fail"]


@dataclass(frozen=True, slots=True)
class HarnessBudget:
    timeout_sec: float = 300.0
    max_steps: int = 6
    max_provider_actions: int = 2

    def __post_init__(self) -> None:
        if self.timeout_sec <= 0:
            raise ValueError("harness timeout_sec must be positive")
        if self.max_steps < 1:
            raise ValueError("harness max_steps must be at least 1")
        if self.max_provider_actions < 1:
            raise ValueError("harness max_provider_actions must be at least 1")


@dataclass(frozen=True, slots=True)
class HarnessRequest:
    target_url: str
    provider: str = "auto"
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HarnessDecision:
    action: HarnessAction
    provider: str | None = None
    strategy: str = "provider_native"
    rationale: str = ""
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class HarnessEvent:
    sequence: int
    elapsed_ms: int
    state: HarnessState
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass(frozen=True, slots=True)
class HarnessEvidence:
    accepted: bool
    result_ok: bool
    vendor_pass: bool | None = None
    vendor_failures: int = 0
    token_length: int = 0
    site_verified: bool | None = None
    gaps: tuple[str, ...] = ()
    adapter: str | None = None
    verifier_events: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HarnessEpisode:
    episode_id: str
    request: HarnessRequest
    budget: HarnessBudget
    state: HarnessState = HarnessState.CREATED
    steps: int = 0
    provider_actions: int = 0
    events: list[HarnessEvent] = field(default_factory=list)
    evidence: HarnessEvidence | None = None
    adapter: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "state": self.state.value,
            "steps": self.steps,
            "provider_actions": self.provider_actions,
            "adapter": self.adapter,
            "budget": asdict(self.budget),
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "events": [event.to_dict() for event in self.events],
        }
