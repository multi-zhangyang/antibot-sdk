from __future__ import annotations

from .capabilities import CAPABILITY_MATRIX, list_capabilities
from .client import AntibotClient
from .models import BrowserResult, CaptchaResult
from .policy import AliyunPolicyEngine, PolicyDecision, aliyun_policy_decision
from .profiles import AliyunSiteProfile, aliyun_profile_for_url, detect_provider_for_url, list_profiles
from .providers.aliyun import AliyunCaptchaSolver, discover_chrome, is_recoverable_attempt_codes
from .providers.browser import BrowserAutomation
from .providers.cloudflare import RunnerConfig, RunResult, diagnose_environment, run_once
from .providers.geetest import (
    DEFAULT_GEETEST_DEMO_URL,
    DEFAULT_GEETEST_SLIDE_DEMO_URL,
    DEFAULT_GEETEST_GOBANG_DEMO_URL,
    GeetestV4ParseError,
    GeetestV4Solver,
    detect_geetest_slide_gap,
    find_geetest_match_swap,
    find_geetest_winlinze_move,
    geetest_query,
    geetest_v4_success_from_events,
    is_geetest_success_payload,
    normalize_geetest_variant,
    latest_geetest_success,
    parse_geetest_jsonp,
    parse_geetest_v4_event,
)
from .providers.tencent import TencentCaptchaSolver
from .proxy import ProxyConfig, normalize_proxy_server, normalize_proxy_url, parse_proxy, redacted_proxy
from .stress import compact_result, run_stress

__all__ = [
    "AliyunCaptchaSolver",
    "AliyunPolicyEngine",
    "AliyunSiteProfile",
    "AntibotClient",
    "BrowserAutomation",
    "BrowserResult",
    "CAPABILITY_MATRIX",
    "CaptchaResult",
    "DEFAULT_GEETEST_DEMO_URL",
    "DEFAULT_GEETEST_SLIDE_DEMO_URL",
    "DEFAULT_GEETEST_GOBANG_DEMO_URL",
    "GeetestV4ParseError",
    "GeetestV4Solver",
    "detect_geetest_slide_gap",
    "find_geetest_match_swap",
    "find_geetest_winlinze_move",
    "PolicyDecision",
    "ProxyConfig",
    "RunnerConfig",
    "RunResult",
    "TencentCaptchaSolver",
    "aliyun_policy_decision",
    "aliyun_profile_for_url",
    "compact_result",
    "detect_provider_for_url",
    "diagnose_environment",
    "discover_chrome",
    "geetest_query",
    "geetest_v4_success_from_events",
    "is_geetest_success_payload",
    "normalize_geetest_variant",
    "latest_geetest_success",
    "is_recoverable_attempt_codes",
    "list_capabilities",
    "list_profiles",
    "normalize_proxy_server",
    "normalize_proxy_url",
    "parse_geetest_jsonp",
    "parse_geetest_v4_event",
    "parse_proxy",
    "redacted_proxy",
    "run_once",
    "run_stress",
]
