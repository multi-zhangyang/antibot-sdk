from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.ajcaptcha import AJCaptchaSolver
from .providers.browser import BrowserAutomation
from .providers.geetest import GeeTestCaptchaSolver
from .providers.hcaptcha import HCaptchaSolver
from .providers.recaptcha import ReCaptchaSolver
from .providers.tencent import TencentCaptchaSolver
from .providers.turnstile import TurnstileSolver
from .providers.yidun import YidunCaptchaSolver


class AntibotClient:
    """Unified SDK facade."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.browser = BrowserAutomation()
        self.ajcaptcha = AJCaptchaSolver()
        self.tencent = TencentCaptchaSolver()
        self.aliyun = AliyunCaptchaSolver()
        self.geetest = GeeTestCaptchaSolver()
        self.turnstile = TurnstileSolver()
        self.hcaptcha = HCaptchaSolver()
        self.recaptcha = ReCaptchaSolver()
        self.yidun = YidunCaptchaSolver()

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

    async def solve_ajcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.ajcaptcha.solve(**kwargs)

    async def solve_geetest(self, **kwargs: Any) -> CaptchaResult:
        return await self.geetest.solve(**kwargs)

    async def solve_turnstile(self, **kwargs: Any) -> CaptchaResult:
        return await self.turnstile.solve(**kwargs)

    async def solve_hcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.hcaptcha.solve(**kwargs)

    async def solve_recaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.recaptcha.solve(**kwargs)

    async def solve_yidun(self, **kwargs: Any) -> CaptchaResult:
        return await self.yidun.solve(**kwargs)

    async def solve_auto(self, target_url: str, **kwargs: Any) -> BrowserResult | CaptchaResult:
        provider = kwargs.pop("provider", None) or detect_provider_for_url(target_url)
        if provider == "ajcaptcha":
            aj_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "get_path",
                    "check_path",
                    "verify_path",
                    "captcha_type",
                    "client_uid",
                    "canonical_width",
                    "point_y",
                    "timeout_sec",
                    "max_attempts",
                    "proxy_server",
                    "output_dir",
                    "save_images",
                    "min_score",
                    "use_returned_point",
                    "verify_after_check",
                    "headers",
                }
                and v is not None
            }
            aj_kwargs.setdefault("base_url", target_url)
            return await self.solve_ajcaptcha(**aj_kwargs)
        if provider == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if provider == "recaptcha":
            rc_kwargs = {
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
            return await self.solve_recaptcha(target_url=target_url, **rc_kwargs)
        if provider == "hcaptcha":
            hc_kwargs = {
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
            return await self.solve_hcaptcha(target_url=target_url, **hc_kwargs)
        if provider == "turnstile":
            ts_kwargs = {
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
            return await self.solve_turnstile(target_url=target_url, **ts_kwargs)
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
        if provider == "yidun":
            yd_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "slide_solve",
                    "slide_max_attempts",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_yidun(target_url=target_url, **yd_kwargs)
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
