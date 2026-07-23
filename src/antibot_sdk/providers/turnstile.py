"""Cloudflare Turnstile adapter for the provider-neutral challenge Harness.

Turnstile is a passive browser flow: the vendor writes a response token into a
hidden field (or a callback), and the relying site normally verifies it.  This
adapter owns the Cloudflare selectors and evidence rules while reusing the
generic token/action state machine.  It never manufactures a token and does
not infer success from a disappearing widget.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from ..harness.contracts import VendorVerification
from ..harness.token import (
    TokenChallengeSession,
    TokenReader,
    TokenSubmitter,
    VendorPassReader,
)

SiteVerificationReader = Callable[[], Awaitable[bool | None] | bool | None]

TURNSTILE_TOKEN_SELECTORS = (
    'input[name="cf-turnstile-response"]',
    'textarea[name="cf-turnstile-response"]',
    'input[name="g-recaptcha-response"]',
    'textarea[name="g-recaptcha-response"]',
    '[name="cf-turnstile-response"]',
)
TURNSTILE_VERIFIER_EVENT_MARKERS = (
    "/turnstile/",
    "/challenge-platform/",
    "siteverify",
)
TURNSTILE_TEST_TOKEN_MARKERS = ("dummy.token",)


class TurnstileChallengeSession(TokenChallengeSession):
    """Run a real Cloudflare Turnstile token flow with an evidence gate.

    A token alone proves that the widget produced a vendor response, but not
    that the relying site accepted it.  By default the session therefore also
    requires one of the following independently observable signals:

    * a configured ``vendor_pass_reader`` returning ``True``;
    * a configured site verification reader returning ``True``; or
    * a captured network event matching one of the Turnstile verifier markers.

    This strict default is intentional.  Callers that only need token capture
    can use :class:`~antibot_sdk.harness.TokenChallengeSession` explicitly.
    """

    def __init__(
        self,
        page: Any,
        *,
        token_selectors: tuple[str, ...] = TURNSTILE_TOKEN_SELECTORS,
        token_reader: TokenReader | None = None,
        submitter: TokenSubmitter | None = None,
        vendor_pass_reader: VendorPassReader | None = None,
        site_verification_reader: SiteVerificationReader | None = None,
        verifier_event_markers: tuple[str, ...] = TURNSTILE_VERIFIER_EVENT_MARKERS,
        network_events: list[dict[str, Any]] | None = None,
        diagnostics: dict[str, Any] | None = None,
        verification_wait_ms: int = 3000,
        require_verifier_evidence: bool = True,
    ) -> None:
        if (
            not verifier_event_markers
            and require_verifier_evidence
            and site_verification_reader is None
            and vendor_pass_reader is None
        ):
            raise ValueError(
                "Turnstile session requires verifier markers or a pass reader"
            )
        if not isinstance(require_verifier_evidence, bool):
            raise ValueError("Turnstile require_verifier_evidence must be boolean")
        self.site_verification_reader = site_verification_reader
        self.require_verifier_evidence = require_verifier_evidence
        self._observed_tokens: tuple[str, ...] = ()
        self._turnstile_diagnostics = diagnostics if diagnostics is not None else {}
        effective_reader = token_reader or _page_token_reader(page, token_selectors)
        super().__init__(
            page,
            provider="cloudflare",
            token_selectors=token_selectors,
            token_reader=effective_reader,
            submitter=submitter,
            vendor_pass_reader=vendor_pass_reader,
            verifier_event_markers=verifier_event_markers,
            network_events=network_events,
            diagnostics=self._turnstile_diagnostics,
            verification_wait_ms=verification_wait_ms,
        )
        self._turnstile_diagnostics.setdefault(
            "turnstile_session",
            {
                "token_selectors": list(token_selectors),
                "require_verifier_evidence": require_verifier_evidence,
                "verifier_event_markers": list(verifier_event_markers),
            },
        )

    async def verify(self) -> VendorVerification:
        base = await super().verify()
        site_verified: bool | None = None
        if self.site_verification_reader is not None:
            value = self.site_verification_reader()
            if inspect.isawaitable(value):
                value = await value
            site_verified = value if isinstance(value, bool) else None

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
        gaps = list(base.gaps)
        if any(
            marker in token.casefold()
            for token in self._observed_tokens
            for marker in TURNSTILE_TEST_TOKEN_MARKERS
        ):
            gaps.append("turnstile_test_token_rejected")
        if site_verified is False:
            gaps.append("turnstile_site_verification_failed")
        has_verifier_evidence = bool(
            base.vendor_pass is True or site_verified is True or verifier_events
        )
        if self.require_verifier_evidence and not has_verifier_evidence:
            gaps.append("turnstile_verifier_evidence_not_observed")
        accepted = base.token_length > 0 and not gaps
        self._turnstile_diagnostics["turnstile_session_verification"] = {
            "accepted": accepted,
            "token_length": base.token_length,
            "vendor_pass": base.vendor_pass,
            "site_verified": site_verified,
            "verifier_events": list(verifier_events),
            "gaps": list(dict.fromkeys(gaps)),
        }
        return VendorVerification(
            provider="cloudflare",
            accepted=accepted,
            token_length=base.token_length,
            vendor_pass=base.vendor_pass,
            vendor_failures=base.vendor_failures,
            site_verified=site_verified,
            verifier_events=verifier_events,
            gaps=tuple(dict.fromkeys(gaps)),
        )

    async def _read_tokens(self) -> list[str]:
        tokens = await super()._read_tokens()
        self._observed_tokens = tuple(tokens)
        return tokens


def _page_token_reader(page: Any, selectors: tuple[str, ...]) -> TokenReader:
    """Create a reader that handles frames plus closed-over shadow wrappers."""

    async def read() -> Iterable[str]:
        values: list[str] = []
        frames = getattr(page, "frames", ())
        if not frames and hasattr(page, "locator"):
            frames = (page,)
        for frame in frames:
            for selector in selectors:
                try:
                    locator = frame.locator(selector)
                    count = await locator.count()
                    for index in range(count):
                        value = await locator.nth(index).input_value(timeout=300)
                        if isinstance(value, str):
                            values.append(value)
                except Exception:
                    continue

        script = _shadow_token_script(selectors)
        execute_script = getattr(page, "execute_script", None)
        if callable(execute_script):
            try:
                response = execute_script(script, return_by_value=True)
            except TypeError:
                response = execute_script(script)
            if inspect.isawaitable(response):
                response = await response
            values.extend(_script_tokens(response))
        return tuple(
            dict.fromkeys(
                value.strip()
                for value in values
                if isinstance(value, str) and len(value.strip()) > 20
            )
        )

    return read


def _shadow_token_script(selectors: tuple[str, ...]) -> str:
    encoded = json.dumps(list(selectors), ensure_ascii=True)
    return f"""
(() => {{
  const selectors = {encoded};
  const values = [];
  const visit = (root, depth) => {{
    if (!root || depth > 6) return;
    try {{
      for (const selector of selectors) {{
        const nodes = root.querySelectorAll ? root.querySelectorAll(selector) : [];
        for (const node of nodes) {{
          const value = node && (node.value ?? node.textContent);
          if (value && String(value).length > 20) values.push(String(value));
        }}
      }}
      const nodes = root.querySelectorAll ? root.querySelectorAll('*') : [];
      for (const node of nodes) if (node.shadowRoot) visit(node.shadowRoot, depth + 1);
    }} catch (_) {{}}
  }};
  visit(document, 0);
  return [...new Set(values)];
}})()
""".strip()


def _script_tokens(value: Any) -> tuple[str, ...]:
    if isinstance(value, dict):
        for key in ("value", "result", "returnValue"):
            if key in value:
                return _script_tokens(value[key])
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


__all__ = [
    "TURNSTILE_TOKEN_SELECTORS",
    "TURNSTILE_VERIFIER_EVENT_MARKERS",
    "TURNSTILE_TEST_TOKEN_MARKERS",
    "SiteVerificationReader",
    "TurnstileChallengeSession",
]
