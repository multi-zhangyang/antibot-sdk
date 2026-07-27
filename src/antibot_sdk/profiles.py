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
        parsed = urlparse(url)
        surface = f"{parsed.hostname or ''}{parsed.path or ''}".lower()
        return any(pattern in surface for pattern in self.url_patterns)


# Aliyun challenge behavior is selected from the live component structure. Host-page
# setup remains an explicit runtime concern through selectors and pre-captcha actions.
ALIYUN_SITE_PROFILES: dict[str, AliyunSiteProfile] = {}


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
    host = (parsed.hostname or "").lower()
    surface = f"{host}{parsed.path or ''}".lower()
    if aliyun_profile_for_url(url, "auto") or any(
        x in surface for x in ("aliyun", "alibaba", "cloudauth")
    ):
        return "aliyun"
    if any(
        x in surface for x in ("tencent", "gtimg", "qcloud", "tcaptcha", "turing.captcha")
    ):
        return "tencent"
    if any(
        x in surface
        for x in ("geetest", "gcaptcha4", "gt4.geetest", "static.geetest.com/v4")
    ):
        return "geetest"
    if any(
        x in surface
        for x in ("google.com/recaptcha", "gstatic.com/recaptcha", "recaptcha.net/recaptcha")
    ):
        return "recaptcha"
    if any(x in surface for x in ("hcaptcha.com", "hcaptcha.net")):
        return "hcaptcha"
    if any(
        x in surface
        for x in (
            "arkoselabs.com",
            "funcaptcha.com",
            "client-api.arkoselabs.com",
            "client-api.arkoselabs.cn",
            "arkoselabs",
            "funcaptcha",
        )
    ):
        return "arkose"
    if any(
        x in surface
        for x in ("cloudflare", "cf-challenge", "cf_clearance", "cdn-cgi", "turnstile")
    ):
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
        "recaptcha": {
            "live_v2_demo": {
                "target_url": "https://2captcha.com/demo/recaptcha-v2",
                "captcha_type": "recaptcha_v2",
                "headless": "true",
                "sitekey": "6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u",
            },
        },
        "hcaptcha": {
            "official_demo": {
                "target_url": "https://accounts.hcaptcha.com/demo",
                "captcha_type": "hcaptcha",
                "headless": "true",
                "sitekey": "a5f74b19-9e45-40e0-b45d-47ff91b7a6c2",
                "submit_selector": "#hcaptcha-demo-submit",
                "success_selector": ".hcaptcha-success",
                "success_text": "Verification Success!",
            },
        },
        "arkose": {
            "official_demo": {
                "target_url": "https://demo.arkoselabs.com/",
                "captcha_type": "funcaptcha",
                "headless": "true",
                "note": "Official demo may not render a challenge; success requires live /fc/ca/ pass evidence.",
            },
        },
    }
