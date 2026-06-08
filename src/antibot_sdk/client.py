from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.browser import BrowserAutomation
from .providers.geetest import GeeTestCaptchaSolver
from .providers.tencent import TencentCaptchaSolver


class AntibotClient:
    """Unified SDK facade."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.browser = BrowserAutomation()
        self.tencent = TencentCaptchaSolver()
        self.aliyun = AliyunCaptchaSolver()
        self.geetest = GeeTestCaptchaSolver()

    async def __aenter__(self) -> "AntibotClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def open(self, url: str, **kwargs: Any) -> BrowserResult:
        kwargs.setdefault("browser_binary", self.browser_binary)
        return await self.browser.open(url, **kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        return await self.tencent.solve(**kwargs)

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        return await self.aliyun.solve(**kwargs)

    async def solve_geetest(self, **kwargs: Any) -> CaptchaResult:
        return await self.geetest.solve(**kwargs)

    async def solve_auto(self, target_url: str, **kwargs: Any) -> BrowserResult | CaptchaResult:
        provider = kwargs.pop("provider", None) or detect_provider_for_url(target_url)
        if provider == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if provider == "geetest":
            gt_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_geetest(target_url=target_url, **gt_kwargs)
        if provider == "tencent":
            ten_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "profile",
                    "appid",
                    "headless",
                    "proxy_server",
                    "pool_size",
                    "browser_max_uses",
                    "locale",
                    "timezone_id",
                    "user_agent",
                    "timeout_sec",
                    "verbose",
                }
                and v is not None
            }
            if ten_kwargs.get("headless") == "new":
                ten_kwargs["headless"] = True
            return await self.solve_tencent(target_url=target_url, **ten_kwargs)
        browser_kwargs = dict(kwargs)
        if "proxy_server" in browser_kwargs and "proxy" not in browser_kwargs:
            browser_kwargs["proxy"] = browser_kwargs.pop("proxy_server")
        if browser_kwargs.get("headless") is None:
            browser_kwargs.pop("headless", None)
        for k in (
            "site_profile",
            "out",
            "output_dir",
            "timeout_sec",
            "chrome_path",
            "max_attempts",
            "captcha_wait_ms",
            "verify_wait_ms",
            "trigger_selectors",
            "auto_trigger",
            "locale",
            "timezone_id",
        ):
            browser_kwargs.pop(k, None)
        return await self.open(target_url, **browser_kwargs)
