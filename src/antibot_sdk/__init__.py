from __future__ import annotations

from .capabilities import CAPABILITY_MATRIX, list_capabilities
from .client import AntibotClient
from .models import BrowserResult, CaptchaResult
from .policy import AliyunPolicyEngine, PolicyDecision, aliyun_policy_decision
from .profiles import AliyunSiteProfile, aliyun_profile_for_url, detect_provider_for_url, list_profiles
from .providers.aliyun import AliyunCaptchaSolver, discover_chrome, is_recoverable_attempt_codes
from .providers.browser import BrowserAutomation
from .providers.cloudflare import RunnerConfig, RunResult, diagnose_environment, run_once
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
    "is_recoverable_attempt_codes",
    "list_capabilities",
    "list_profiles",
    "normalize_proxy_server",
    "normalize_proxy_url",
    "parse_proxy",
    "redacted_proxy",
    "run_once",
    "run_stress",
]
