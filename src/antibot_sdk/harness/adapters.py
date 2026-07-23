"""Provider adapter registry and evidence policies.

An adapter describes what a provider can emit and what constitutes proof.  It
does not solve a challenge itself; browser/protocol providers remain the
execution backends.  Keeping this registry separate lets new vendors plug
into the Harness without teaching the planner another set of hard-coded
conditions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import BrowserResult, CaptchaResult
from .contracts import VendorVerification


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    require_token: bool = False
    require_session_evidence: bool = False
    reject_test_tokens: bool = False
    require_vendor_pass: bool = False
    vendor_response_key: str | None = None
    vendor_pass_field: str = "pass"
    verifier_event_markers: tuple[str, ...] = ()
    vendor_pass_gap: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    provider: str
    aliases: tuple[str, ...] = ()
    category: str = "browser_flow"
    modalities: tuple[str, ...] = ("protocol",)
    challenge_kinds: tuple[str, ...] = ("unknown",)
    strategies: tuple[str, ...] = ("provider_native",)
    evidence: EvidencePolicy = field(default_factory=EvidencePolicy)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = asdict(self.evidence)
        return value


class ProviderAdapterRegistry:
    """Case-insensitive provider/alias registry with explicit duplicate checks."""

    def __init__(self, adapters: tuple[ProviderAdapter, ...] = ()) -> None:
        self._adapters: dict[str, ProviderAdapter] = {}
        self._aliases: dict[str, str] = {}
        self._frozen = False
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ProviderAdapter) -> None:
        if self._frozen:
            raise RuntimeError("provider adapter registry is frozen")
        key = _normalize(adapter.provider)
        if not key:
            raise ValueError("provider adapter name must not be empty")
        if key in self._adapters or key in self._aliases:
            raise ValueError(f"provider adapter already registered: {adapter.provider}")
        self._adapters[key] = adapter
        for alias in adapter.aliases:
            alias_key = _normalize(alias)
            if not alias_key or alias_key in self._adapters or alias_key in self._aliases:
                raise ValueError(f"provider adapter alias already registered: {alias}")
            self._aliases[alias_key] = key

    def resolve(self, provider: str | None) -> ProviderAdapter | None:
        key = _normalize(provider or "")
        canonical = self._aliases.get(key, key)
        return self._adapters.get(canonical)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def describe(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._adapters[key].to_dict() for key in self.names())

    def clone(self) -> "ProviderAdapterRegistry":
        return ProviderAdapterRegistry(tuple(self._adapters[key] for key in self.names()))

    def freeze(self) -> "ProviderAdapterRegistry":
        self._frozen = True
        return self

    def verify_result(self, result: BrowserResult | CaptchaResult, provider: str) -> VendorVerification:
        adapter = self.resolve(provider)
        if adapter is None:
            return VendorVerification(
                provider=provider,
                accepted=False,
                gaps=("provider_adapter_not_registered",),
            )
        diagnostics = result.diagnostics if isinstance(result.diagnostics, dict) else {}
        response_key = adapter.evidence.vendor_response_key
        responses = diagnostics.get(response_key, []) if response_key else []
        normalized = [item for item in responses if isinstance(item, dict)]
        pass_field = adapter.evidence.vendor_pass_field
        vendor_pass = (
            any(item.get(pass_field) is True for item in normalized)
            if normalized
            else None
        )
        vendor_failures = sum(item.get(pass_field) is False for item in normalized)
        token = ""
        clearance = ""
        if isinstance(result, CaptchaResult):
            token = result.ticket or ""
        elif isinstance(result, BrowserResult):
            token = result.turnstile_token or ""
            clearance = result.cf_clearance or ""
        site = diagnostics.get("site_verification")
        site_verified = site.get("ok") if isinstance(site, dict) else None
        raw_events = result.raw.get("events", []) if isinstance(result.raw, dict) else []
        event_urls = tuple(
            str(item.get("url"))
            for item in raw_events
            if isinstance(item, dict) and item.get("url")
        )
        verifier_events = tuple(
            marker
            for marker in adapter.evidence.verifier_event_markers
            if any(marker in url for url in event_urls)
        )
        gaps: list[str] = []
        accepted = bool(result.ok)
        if adapter.evidence.reject_test_tokens and _is_test_token(token):
            accepted = False
            gaps.append(f"{adapter.provider}_test_token_rejected")
            token = ""
        if adapter.evidence.require_session_evidence and not (
            clearance or token or site_verified is True
        ):
            accepted = False
            gaps.append(f"{adapter.provider}_session_evidence_not_captured")
        if adapter.evidence.require_vendor_pass and vendor_pass is not True:
            accepted = False
            gaps.append(
                adapter.evidence.vendor_pass_gap
                or f"{adapter.provider}_vendor_pass_not_observed"
            )
        if adapter.evidence.require_token and not token:
            accepted = False
            gaps.append(f"{adapter.provider}_vendor_token_not_captured")
        if adapter.evidence.verifier_event_markers and not verifier_events:
            # A provider can expose a valid token without retaining raw network
            # events, so this is diagnostic context rather than a hard gate.
            gaps.append(f"{adapter.provider}_verifier_event_not_recorded")
        return VendorVerification(
            provider=adapter.provider,
            accepted=accepted,
            token_length=len(token),
            vendor_pass=vendor_pass,
            vendor_failures=vendor_failures,
            site_verified=site_verified,
            verifier_events=verifier_events,
            gaps=tuple(dict.fromkeys(gaps)),
        )


def _normalize(value: str) -> str:
    return "-".join(value.strip().casefold().replace("_", "-").split())


def _is_test_token(value: str) -> bool:
    normalized = str(value).strip().casefold()
    return "dummy.token" in normalized


def default_adapter_registry() -> ProviderAdapterRegistry:
    return ProviderAdapterRegistry(
        (
            ProviderAdapter(
                provider="aliyun",
                category="solver",
                modalities=("image", "protocol"),
                challenge_kinds=("slider", "token"),
            ),
            ProviderAdapter(
                provider="arkose",
                aliases=("arkose-labs", "arkoselabs", "funcaptcha", "fun-captcha"),
                modalities=("image", "behavior", "protocol"),
                challenge_kinds=(
                    "binary",
                    "point",
                    "multiple_choice",
                    "drag_drop",
                    "token",
                    "interactive",
                ),
                strategies=("provider_native", "vision"),
                evidence=EvidencePolicy(
                    require_token=True,
                    require_vendor_pass=True,
                    vendor_response_key="arkose_verification_responses",
                    vendor_pass_gap="arkose_fc_ca_pass_true_not_observed",
                    verifier_event_markers=("/fc/ca/",),
                ),
            ),
            ProviderAdapter(
                provider="cloudflare",
                aliases=("turnstile", "cf"),
                modalities=("behavior", "protocol"),
                challenge_kinds=("token", "unknown"),
                strategies=("provider_native", "browser_flow"),
                evidence=EvidencePolicy(
                    require_session_evidence=True,
                    reject_test_tokens=True,
                    verifier_event_markers=("/turnstile/", "/challenge-platform/"),
                ),
            ),
            ProviderAdapter(
                provider="geetest",
                modalities=("image", "behavior", "protocol"),
                challenge_kinds=("slider", "multiple_choice", "token"),
                evidence=EvidencePolicy(require_token=True),
            ),
            ProviderAdapter(
                provider="hcaptcha",
                modalities=("image", "audio", "protocol"),
                challenge_kinds=("binary", "point", "bounding_box", "multiple_choice", "drag_drop", "token"),
                strategies=("provider_native", "vision", "local_onnx"),
                evidence=EvidencePolicy(
                    require_token=True,
                    require_vendor_pass=True,
                    vendor_response_key="hcaptcha_verification_responses",
                    vendor_pass_gap="hcaptcha_checkcaptcha_pass_true_not_observed",
                ),
            ),
            ProviderAdapter(
                provider="recaptcha",
                aliases=("re-captcha", "google-recaptcha"),
                modalities=("image", "audio", "protocol"),
                challenge_kinds=("binary", "point", "token"),
                strategies=("provider_native", "vision", "audio"),
                evidence=EvidencePolicy(
                    require_token=True,
                    verifier_event_markers=("/recaptcha/api2/userverify",),
                ),
            ),
            ProviderAdapter(
                provider="tencent",
                modalities=("image", "behavior", "protocol"),
                challenge_kinds=("slider", "point", "token"),
                evidence=EvidencePolicy(
                    require_token=True,
                    require_vendor_pass=True,
                    vendor_response_key="tencent_verification_responses",
                    vendor_pass_field="accepted",
                    vendor_pass_gap="tencent_cap_union_new_verify_pass_not_observed",
                ),
            ),
        )
    )


DEFAULT_ADAPTER_REGISTRY = default_adapter_registry().freeze()
SUPPORTED_ADAPTER_PROVIDERS = DEFAULT_ADAPTER_REGISTRY.names()


__all__ = [
    "DEFAULT_ADAPTER_REGISTRY",
    "EvidencePolicy",
    "ProviderAdapter",
    "ProviderAdapterRegistry",
    "SUPPORTED_ADAPTER_PROVIDERS",
    "default_adapter_registry",
]
