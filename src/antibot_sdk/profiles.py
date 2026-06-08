from __future__ import annotations

from dataclasses import dataclass, field
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
        return any(p in u or p in host for p in self.url_patterns)


ALIYUN_SITE_PROFILES: dict[str, AliyunSiteProfile] = {
    # 这是从 aliyun-captcha-repro/qoder_test.js 收敛出来的站点级 profile。
    # 关键点：Qoder 的滑块不是首屏出现，必须先走注册表单两段提交，之后
    # 才会加载完整的 #aliyunCaptcha-sliding-* DOM。
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


def aliyun_profile_for_url(
    target_url: str | None,
    requested: str | None = "auto",
) -> AliyunSiteProfile | None:
    """Resolve an Aliyun site profile by explicit name or URL."""

    if requested and requested != "auto":
        return ALIYUN_SITE_PROFILES.get(requested)
    for profile in ALIYUN_SITE_PROFILES.values():
        if profile.matches(target_url):
            return profile
    return None


def detect_provider_for_url(url: str | None) -> str:
    """Cheap URL-level router for the SDK auto mode."""

    if not url:
        return "browser"
    u = url.lower()
    host = (urlparse(url).hostname or "").lower()
    if aliyun_profile_for_url(url, "auto") or "aliyun" in u or "alibaba" in u:
        return "aliyun"
    if any(x in u or x in host for x in ("ajcaptcha", "anji-plus", "/captcha/get", "/captcha/check")):
        return "ajcaptcha"
    if any(x in u or x in host for x in ("altcha", "altcha.org")):
        return "altcha"
    if any(x in u or x in host for x in ("anubis", ".within.website/x/cmd/anubis", "techaro.lol-anubis")):
        return "anubis"
    if any(x in u or x in host for x in ("friendlycaptcha", "friendlycaptcha.com", "frc-captcha")):
        return "friendlycaptcha"
    if any(x in u or x in host for x in ("trycap.dev", "cap.js", "cap-widget", "capjs")):
        return "cap"
    if any(x in u or x in host for x in ("mcaptcha", "/api/v1/pow/config", "/api/v1/pow/verify")):
        return "mcaptcha"
    if any(x in u or x in host for x in ("p-captcha", "pcaptcha", "quadraticresidueproblem")):
        return "pcaptcha"
    if any(x in u or x in host for x in ("pow_captcha", "powcaptcha", "taketest", "/powcaptcha/")):
        return "powcaptcha"
    if any(x in u or x in host for x in ("privatecaptcha", "private-captcha", "api.privatecaptcha.com", "/privatecaptcha/")):
        return "privatecaptcha"
    if any(x in u or x in host for x in ("wicketkeeper", "/v0/challenge", "/v0/siteverify")):
        return "wicketkeeper"
    if any(x in u or x in host for x in ("geetest", "gcaptcha4", "gt4.geetest")):
        return "geetest"
    if any(x in u or x in host for x in ("yidun", "necaptcha", "dun.163.com", "c.dun.163.com")):
        return "yidun"
    if any(x in u or x in host for x in ("hcaptcha", "h-captcha", "js.hcaptcha.com")):
        return "hcaptcha"
    if any(x in u or x in host for x in ("recaptcha", "g-recaptcha", "grecaptcha", "recaptcha.net")):
        return "recaptcha"
    if any(x in u or x in host for x in ("turnstile", "challenges.cloudflare.com")):
        return "turnstile"
    if any(x in u or x in host for x in ("tencent", "gtimg", "turing.captcha", "tcaptcha")):
        return "tencent"
    if any(x in u or x in host for x in ("cloudflare", "turnstile", "cf-challenge")):
        return "cloudflare"
    return "browser"


def list_profiles() -> dict[str, Any]:
    return {
        "aliyun": {
            name: {
                "patterns": list(profile.url_patterns),
                "siteProfile": profile.site_profile,
                "maxAttempts": profile.max_attempts,
                "sessionRetries": profile.session_retries,
                "proxyMaxAttempts": profile.proxy_max_attempts,
                "proxySessionRetries": profile.proxy_session_retries,
            }
            for name, profile in ALIYUN_SITE_PROFILES.items()
        },
        "geetest": {
            "generic_v4": {
                "patterns": ["geetest", "gcaptcha4"],
                "mode": "browser-hook-slide-solver-alpha",
                "successFields": ["lot_number", "captcha_output", "pass_token", "gen_time"],
            }
        },
        "ajcaptcha": {
            "generic_block_puzzle": {
                "patterns": ["ajcaptcha", "anji-plus", "/captcha/get", "/captcha/check"],
                "mode": "http-protocol-solver",
                "successFields": ["captchaVerification", "token"],
                "endpoints": ["/captcha/get", "/captcha/check"],
            }
        },
        "altcha": {
            "generic_pow": {
                "patterns": ["altcha", "altcha.org"],
                "mode": "proof-of-work-protocol-solver",
                "successFields": ["altcha base64 payload", "Authorization: Altcha ..."],
            }
        },
        "anubis": {
            "generic_pow": {
                "patterns": ["anubis", ".within.website/x/cmd/anubis", "techaro.lol-anubis"],
                "mode": "anubis-sha256-pow-protocol-solver",
                "successFields": ["pass-challenge params", "Anubis auth cookie"],
                "endpoints": ["/make-challenge", "/pass-challenge"],
            }
        },
        "friendlycaptcha": {
            "classic_pow": {
                "patterns": ["friendlycaptcha", "friendlycaptcha.com", "frc-captcha"],
                "mode": "friendly-pow-protocol-solver",
                "successFields": ["frc-captcha-solution"],
                "endpoints": ["/api/v1/puzzle"],
            }
        },
        "cap": {
            "sha256_pow": {
                "patterns": ["trycap.dev", "cap.js", "cap-widget", "capjs"],
                "mode": "cap-sha256-pow-protocol-solver",
                "successFields": ["/redeem body", "Cap token"],
                "endpoints": ["/challenge", "/redeem"],
            }
        },
        "mcaptcha": {
            "sha256_pow": {
                "patterns": ["mcaptcha", "/api/v1/pow/config", "/api/v1/pow/verify"],
                "mode": "mcaptcha-sha256-pow-protocol-solver",
                "successFields": ["verify body", "mCaptcha token"],
                "endpoints": ["/api/v1/pow/config", "/api/v1/pow/verify", "/api/v1/pow/siteverify"],
            }
        },
        "pcaptcha": {
            "quadratic_residue_pow": {
                "patterns": ["p-captcha", "pcaptcha", "QuadraticResidueProblem"],
                "mode": "quadratic-residue-protocol-solver",
                "successFields": ["answer", "{id, answer}"],
                "endpoints": ["/api/challenge", "/api/validate"],
            }
        },
        "powcaptcha": {
            "buffer_reconstruction_pow": {
                "patterns": ["pow_captcha", "powcaptcha", "takeTest"],
                "mode": "buffer-reconstruction-mixed-radix-protocol-solver",
                "successFields": ["answer base64", "answerHex"],
                "endpoints": ["challenge endpoint returning quiz bytes/json", "verify endpoint accepting answer"],
            }
        },
        "privatecaptcha": {
            "compute_pow": {
                "patterns": ["privatecaptcha", "private-captcha", "api.privatecaptcha.com"],
                "mode": "blake2b-compute-puzzle-protocol-solver",
                "successFields": ["private-captcha-solution", "g-recaptcha-response compat"],
                "endpoints": ["/puzzle", "/verify", "/siteverify"],
            }
        },
        "wicketkeeper": {
            "jwt_pow": {
                "patterns": ["wicketkeeper", "/v0/challenge", "/v0/siteverify"],
                "mode": "wicketkeeper-jwt-pow-protocol-solver",
                "successFields": ["hidden input JSON", "success JWT"],
                "endpoints": ["/v0/challenge", "/v0/siteverify"],
            }
        },
        "yidun": {
            "generic_jigsaw": {
                "patterns": ["yidun", "necaptcha", "dun.163.com", "c.dun.163.com"],
                "mode": "browser-hook-slide-solver-alpha",
                "successFields": ["validate", "token", "zoneId"],
            }
        },
        "hcaptcha": {
            "generic_widget": {
                "patterns": ["hcaptcha", "h-captcha", "js.hcaptcha.com"],
                "mode": "browser-hook-observer",
                "successFields": ["h-captcha-response", "callback token"],
            }
        },
        "recaptcha": {
            "generic_widget_enterprise": {
                "patterns": ["recaptcha", "g-recaptcha", "grecaptcha", "recaptcha.net"],
                "mode": "browser-hook-observer",
                "successFields": ["g-recaptcha-response", "callback/execute token"],
            }
        },
        "turnstile": {
            "generic_widget": {
                "patterns": ["turnstile", "challenges.cloudflare.com"],
                "mode": "browser-hook-observer",
                "successFields": ["cf-turnstile-response", "callback token"],
            }
        },
    }
