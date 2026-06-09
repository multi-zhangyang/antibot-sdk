from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AliyunSiteProfile:
    """Runtime profile used by the Aliyun Node bridge."""

    name: str
    url_patterns: tuple[str, ...] = ()
    site_profile: str | None = None
    headless: bool | str | None = None
    selectors: dict[str, str] = field(default_factory=dict)
    profile: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    verify_wait_ms: int | None = None
    captcha_wait_ms: int | None = None
    max_attempts: int | None = None
    session_retries: int | None = None
    session_retry_delay_sec: float | None = None
    session_retry_max_attempts: int | None = None
    proxy_max_attempts: int | None = None
    proxy_session_retries: int | None = None
    proxy_session_retry_max_attempts: int | None = None

    def matches(self, url: str | None) -> bool:
        if not url:
            return False
        u = url.lower()
        host = (urlparse(url).hostname or "").lower()
        return any(pattern in u or pattern in host for pattern in self.url_patterns)


ALIYUN_SITE_PROFILES: dict[str, AliyunSiteProfile] = {
    "qoder_signup": AliyunSiteProfile(
        name="qoder_signup",
        url_patterns=("qoder.com/users/sign-up", "qoder.com"),
        site_profile="qoder_signup",
        headless=True,
        verify_wait_ms=12_000,
        captcha_wait_ms=120_000,
        max_attempts=5,
        session_retries=1,
        session_retry_delay_sec=3.0,
        session_retry_max_attempts=2,
        proxy_max_attempts=3,
        proxy_session_retries=2,
        proxy_session_retry_max_attempts=2,
        profile={
            "maxAttempts": 5,
            "totalMs": 2000,
            "steps": 100,
            "baseDelta": 8,
            "alignPuzzle": 1,
            "alignTolerancePx": 0.8,
            "alignIters": 6,
            "warmPoints": 0,
            "pressHoldMs": 220,
            "pressHoldJitterMs": 80,
            "postDownMs": 240,
            "releaseHoldMs": 340,
            "releaseHoldJitterMs": 120,
            "rawMin": 160,
            "rawMax": 240,
        },
        env={
            "LISTENER_AUTO_PROFILE": "0",
            "LISTENER_MAX_REFRESHES": "4",
            "LISTENER_MAX_VERIFY_REFRESHES": "0",
            "LISTENER_VERIFY_REFRESH_CODES": "F015",
            "LISTENER_AUTO_DELTA": "0",
            "LISTENER_ENFORCE_CANDIDATE_FILTER": "1",
            "LISTENER_SLOT_ONLY": "1",
            "LISTENER_RETRY_DELAY_MS": "700",
            "LISTENER_RETRY_JITTER_MS": "500",
        },
    ),
}


def aliyun_profile_for_url(target_url: str | None, requested: str | None = "auto") -> AliyunSiteProfile | None:
    if requested and requested != "auto":
        return ALIYUN_SITE_PROFILES.get(requested)
    for profile in ALIYUN_SITE_PROFILES.values():
        if profile.matches(target_url):
            return profile
    return None


def detect_provider_for_url(url: str | None) -> str:
    """Cheap URL router for the lean SDK."""

    if not url:
        return "unknown"
    parsed = urlparse(url)
    u = url.lower()
    host = (parsed.hostname or "").lower()
    if aliyun_profile_for_url(url, "auto") or any(x in u or x in host for x in ("aliyun", "alibaba", "cloudauth")):
        return "aliyun"
    if any(x in u or x in host for x in ("tencent", "gtimg", "qcloud", "tcaptcha", "turing.captcha")):
        return "tencent"
    if any(
        x in u or x in host
        for x in ("geetest", "gcaptcha4", "gt4.geetest", "static.geetest.com/v4")
    ):
        return "geetest"
    if any(x in u or x in host for x in ("cloudflare", "cf-challenge", "cf_clearance", "cdn-cgi", "turnstile")):
        return "cloudflare"
    return "unknown"


def list_profiles() -> dict[str, dict[str, Any]]:
    from .vendor.tencent.site_profiles import PROFILES as TENCENT_PROFILES

    return {
        "cloudflare": {
            "managed": {"mode": "managed", "headless": "false"},
            "auto": {"mode": "auto", "headless": "auto"},
            "scrape": {"mode": "scrape", "headless": "true"},
        },
        "aliyun": {name: asdict(profile) for name, profile in ALIYUN_SITE_PROFILES.items()},
        "tencent": {name: profile.to_dict() for name, profile in TENCENT_PROFILES.items()},
        "geetest": {
            "v4_demo": {
                "target_url": "https://www.geetest.com/en/adaptive-captcha-demo",
                "captcha_type": "geetest_v4_ai",
                "headless": "true",
                "runtime_hosts": ("gcaptcha4.geetest.com", "static.geetest.com/v4", "gt4.geetest.com"),
            },
            "v4_slide_demo": {
                "target_url": "https://gt4.geetest.com/demov4/slide-popup-zh.html",
                "captcha_type": "geetest_v4_slide",
                "headless": "true",
                "click_selector": "#btn",
            },
        },
    }
