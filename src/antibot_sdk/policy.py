from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


def _norm_code(value: Any) -> str:
    text = str(value or "").strip()
    return text.upper() if text and len(text) <= 12 and text.replace("_", "").isalnum() else text


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A compact runtime decision that can be used by providers and reports."""

    provider: str
    ok: bool
    codes: list[str] = field(default_factory=list)
    failure_class: str = "unknown"
    recoverable: bool = False
    should_retry_session: bool = False
    reason: str = ""
    env_overrides: dict[str, str] = field(default_factory=dict)
    profile_overrides: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AliyunPolicyEngine:
    """Heuristics for Aliyun attempt/session failure handling.

    The engine is intentionally deterministic and conservative: it does not try
    to solve the CAPTCHA by itself; it only classifies observed runtime output
    and returns retry/override suggestions that the SDK can apply or expose.
    """

    success_codes = {"T001"}
    reputation_codes = {"F001"}
    geometry_codes = {"F015"}

    @staticmethod
    def extract_codes(raw: dict[str, Any] | None = None, errors: Iterable[Any] | None = None) -> list[str]:
        raw = raw or {}
        codes: list[str] = []
        attempts = raw.get("attempts") if isinstance(raw, dict) else []
        for attempt in attempts or []:
            if not isinstance(attempt, dict):
                continue
            code = (
                attempt.get("verifyFailureCode")
                or attempt.get("verifyCode")
                or attempt.get("error")
                or ""
            )
            if code:
                codes.append(_norm_code(code))
        if not codes and isinstance(raw, dict):
            verify = raw.get("verifyResponse") or {}
            code = verify.get("VerifyCode") or raw.get("verifyFailureCode")
            if code:
                codes.append(_norm_code(code))
            err = raw.get("error")
            if isinstance(err, dict) and err.get("message"):
                codes.append(_norm_code(err["message"]))
            elif err:
                codes.append(_norm_code(err))
            wd = raw.get("watchdog")
            if isinstance(wd, dict) and wd.get("label"):
                codes.append(_norm_code(f"watchdog timeout: {wd.get('label')}"))
        for err in errors or []:
            if err:
                codes.append(_norm_code(err))
        return [c for c in codes if c]

    @staticmethod
    def _is_timeout(code: str) -> bool:
        c = code.lower()
        return (
            "timeout" in c
            or "watchdog" in c
            or "captcha not ready" in c
            or "navigation timeout" in c
        )

    @staticmethod
    def _is_transient(code: str) -> bool:
        c = code.lower()
        return (
            code in {"", "NONE", "UNKNOWN"}
            or AliyunPolicyEngine._is_timeout(code)
            or "gap not found" in c
            or "captcha images not found" in c
            or "candidate rejected" in c
            or "image fetch" in c
            or "net::" in c
        )

    def decide(
        self,
        raw: dict[str, Any] | None = None,
        *,
        codes: Iterable[Any] | None = None,
        errors: Iterable[Any] | None = None,
        has_proxy: bool = False,
    ) -> PolicyDecision:
        xs = [_norm_code(c) for c in codes] if codes is not None else self.extract_codes(raw, errors)
        xs = [c for c in xs if c]
        upper = [c.upper() for c in xs]
        notes: list[str] = []

        if any(c in self.success_codes for c in upper):
            return PolicyDecision(
                provider="aliyun",
                ok=True,
                codes=xs,
                failure_class="success",
                reason="VerifyCode=T001",
            )

        f001_count = sum(1 for c in upper if c in self.reputation_codes)
        f015_count = sum(1 for c in upper if c in self.geometry_codes)
        timeout_count = sum(1 for c in xs if self._is_timeout(c))
        transient_count = sum(1 for c in xs if self._is_transient(c))

        if f001_count >= 2:
            notes.append("F001 连续出现时，单纯继续同一页面 attempt 收益低，优先换 session/出口。")
            return PolicyDecision(
                provider="aliyun",
                ok=False,
                codes=xs,
                failure_class="reputation_or_session",
                recoverable=True,
                should_retry_session=True,
                reason="repeated F001",
                profile_overrides={
                    "style": "organic",
                    "warmPoints": 8,
                    "pressHoldMs": 180,
                    "postDownMs": 180,
                    "releaseHoldMs": 320,
                },
                notes=notes + (["当前已使用代理，下一轮应重新取出口。"] if has_proxy else ["未使用代理时建议接入代理池或冷却。"]),
            )

        if timeout_count:
            return PolicyDecision(
                provider="aliyun",
                ok=False,
                codes=xs,
                failure_class="watchdog_or_timeout",
                recoverable=True,
                should_retry_session=True,
                reason="timeout/watchdog/captcha-not-ready",
                env_overrides={
                    "ALIYUN_WATCHDOG_ENABLED": "1",
                    "LISTENER_RETRY_DELAY_MS": "400",
                },
                notes=["超时类失败优先快速释放浏览器并换 session，避免 200s+ 长尾。"],
            )

        if transient_count >= 2:
            return PolicyDecision(
                provider="aliyun",
                ok=False,
                codes=xs,
                failure_class="transient_candidate_or_dom",
                recoverable=True,
                should_retry_session=True,
                reason="multiple transient failures",
                env_overrides={
                    "LISTENER_MAX_REFRESHES": "4",
                    "LISTENER_ENFORCE_CANDIDATE_FILTER": "1",
                },
                notes=["多次 NONE/gap/candidate 异常通常是当前 puzzle 或页面态质量差。"],
            )

        if f015_count:
            return PolicyDecision(
                provider="aliyun",
                ok=False,
                codes=xs,
                failure_class="geometry_or_delta",
                recoverable=True,
                should_retry_session=False,
                reason="F015 geometry mismatch",
                env_overrides={
                    "LISTENER_AUTO_DELTA": "1",
                    "LISTENER_MAX_VERIFY_REFRESHES": "1",
                    "LISTENER_VERIFY_REFRESH_CODES": "F015",
                },
                notes=["F015 更像距离/对齐问题，优先同 puzzle auto-delta 或刷新 puzzle，而不是直接换 session。"],
            )

        if transient_count:
            return PolicyDecision(
                provider="aliyun",
                ok=False,
                codes=xs,
                failure_class="single_transient",
                recoverable=True,
                should_retry_session=False,
                reason="single transient failure",
                notes=["单次临时失败先由 attempt retry 消化；连续出现再换 session。"],
            )

        return PolicyDecision(
            provider="aliyun",
            ok=False,
            codes=xs,
            failure_class="hard_or_unknown",
            recoverable=False,
            should_retry_session=False,
            reason="no recoverable policy matched",
        )


def aliyun_policy_decision(
    raw: dict[str, Any] | None = None,
    *,
    codes: Iterable[Any] | None = None,
    errors: Iterable[Any] | None = None,
    has_proxy: bool = False,
) -> PolicyDecision:
    return AliyunPolicyEngine().decide(raw, codes=codes, errors=errors, has_proxy=has_proxy)
