"""Provider-neutral session for passive token challenges.

Some CAPTCHA providers complete a behavior or risk check without exposing an
image question. The browser receives a token in a hidden field or callback;
the harness must observe that token and, when requested, invoke a real page
submitter. This adapter never fabricates a token and never treats a missing
field as success.
"""

from __future__ import annotations

import hashlib
import inspect
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from .contracts import ChallengeAction, ChallengeObservation, VendorVerification

TokenReader = Callable[[], Awaitable[Iterable[str]] | Iterable[str]]
TokenSubmitter = Callable[[], Awaitable[None] | None]
VendorPassReader = Callable[[], Awaitable[bool | None] | bool | None]


class TokenChallengeSession:
    """Run a real hidden-field/callback token flow through the agent loop."""

    def __init__(
        self,
        page: Any,
        *,
        provider: str,
        token_selectors: tuple[str, ...] = (),
        token_reader: TokenReader | None = None,
        submitter: TokenSubmitter | None = None,
        vendor_pass_reader: VendorPassReader | None = None,
        verifier_event_markers: tuple[str, ...] = (),
        network_events: list[dict[str, Any]] | None = None,
        diagnostics: dict[str, Any] | None = None,
        verification_wait_ms: int = 3000,
    ) -> None:
        if not provider.strip():
            raise ValueError("token session provider must not be empty")
        if not token_selectors and token_reader is None:
            raise ValueError("token session requires token_selectors or token_reader")
        if verification_wait_ms < 0:
            raise ValueError("token session verification_wait_ms must be non-negative")
        self.page = page
        self.provider = provider.strip().casefold()
        self.token_selectors = tuple(
            selector.strip() for selector in token_selectors if selector.strip()
        )
        self.token_reader = token_reader
        self.submitter = submitter
        self.vendor_pass_reader = vendor_pass_reader
        self.verifier_event_markers = tuple(verifier_event_markers)
        self.network_events = network_events if network_events is not None else []
        self.diagnostics = diagnostics if diagnostics is not None else {}
        self.verification_wait_sec = verification_wait_ms / 1000
        self._sequence = 0
        self._submitted = False
        self._current: ChallengeObservation | None = None

    async def _read_tokens(self) -> list[str]:
        if self.token_reader is not None:
            value = self.token_reader()
            if inspect.isawaitable(value):
                value = await value
            return _normalize_tokens(value)

        frames = getattr(self.page, "frames", ())
        if not frames and hasattr(self.page, "locator"):
            frames = (self.page,)
        tokens: list[str] = []
        for frame in frames:
            for selector in self.token_selectors:
                try:
                    locator = frame.locator(selector)
                    count = await locator.count()
                    for index in range(count):
                        value = await locator.nth(index).input_value(timeout=300)
                        if isinstance(value, str):
                            tokens.append(value)
                except Exception:
                    continue
        return _normalize_tokens(tokens)

    async def observe(self) -> ChallengeObservation | None:
        if await self._read_tokens() or self._submitted:
            self._current = None
            return None
        self._sequence += 1
        observation = ChallengeObservation(
            observation_id=hashlib.sha256(
                f"{self.provider}|token|{self._sequence}".encode("utf-8")
            ).hexdigest()[:24],
            provider=self.provider,
            kind="token",
            modality="protocol",
            phase="presented",
            metadata={
                "token_selectors": len(self.token_selectors),
                "token_reader": self.token_reader is not None,
                "passive": self.submitter is None,
            },
        )
        self._current = observation
        self.diagnostics.setdefault("token_session_observations", []).append(
            observation.to_dict()
        )
        return observation

    async def vision_task(self, _observation: ChallengeObservation) -> None:
        return None

    async def execute(self, action: ChallengeAction) -> None:
        if self._current is None or self._current.observation_id != action.observation_id:
            raise ValueError("token action does not target the current observation")
        if action.kind == "submit":
            if self.submitter is None:
                raise RuntimeError(
                    "token session has no submitter for an empty token flow"
                )
            value = self.submitter()
            if inspect.isawaitable(value):
                await value
            self._submitted = True
            self.diagnostics["token_session_submit_executed"] = True
        elif action.kind == "noop":
            self.diagnostics["token_session_noop"] = True
        else:
            raise ValueError(f"unsupported token session action: {action.kind}")
        self._current = None

    async def verify(self) -> VendorVerification:
        deadline = time.monotonic() + self.verification_wait_sec
        tokens: list[str] = []
        while True:
            tokens = await self._read_tokens()
            if tokens or time.monotonic() >= deadline:
                break
            wait = getattr(self.page, "wait_for_timeout", None)
            if wait is None:
                break
            await wait(200)

        token_length = max((len(token) for token in tokens), default=0)
        vendor_pass: bool | None = None
        if self.vendor_pass_reader is not None:
            value = self.vendor_pass_reader()
            if inspect.isawaitable(value):
                value = await value
            vendor_pass = value if isinstance(value, bool) else None
        event_urls = tuple(
            str(item.get("url"))
            for item in self.network_events
            if isinstance(item, dict) and item.get("url")
        )
        verifier_events = tuple(
            marker
            for marker in self.verifier_event_markers
            if any(marker in url for url in event_urls)
        )
        gaps: list[str] = []
        if token_length == 0:
            gaps.append(f"{self.provider}_vendor_token_not_captured")
        if self.vendor_pass_reader is not None and vendor_pass is not True:
            gaps.append(f"{self.provider}_vendor_pass_not_observed")
        accepted = token_length > 0 and not gaps
        self.diagnostics["token_session_verification"] = {
            "accepted": accepted,
            "token_length": token_length,
            "vendor_pass": vendor_pass,
            "verifier_events": list(verifier_events),
            "gaps": gaps,
        }
        return VendorVerification(
            provider=self.provider,
            accepted=accepted,
            token_length=token_length,
            vendor_pass=vendor_pass,
            verifier_events=verifier_events,
            gaps=tuple(gaps),
        )


def _normalize_tokens(value: Iterable[str] | Any) -> list[str]:
    if isinstance(value, (str, bytes)):
        value = (value,)
    if not isinstance(value, Iterable):
        return []
    return list(
        dict.fromkeys(
            item.strip()
            for item in value
            if isinstance(item, str) and len(item.strip()) > 20
        )
    )


__all__ = ["TokenChallengeSession", "TokenReader", "TokenSubmitter", "VendorPassReader"]
