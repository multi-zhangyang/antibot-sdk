from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.browser import BrowserAutomation
from .providers.tencent import TencentCaptchaSolver


class AntibotClient:
    """SDK facade for Cloudflare browser flows plus Aliyun/Tencent sliders."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.browser = BrowserAutomation()
        self.aliyun = AliyunCaptchaSolver()
        self.tencent = TencentCaptchaSolver()

    async def __aenter__(self) -> "AntibotClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def open(self, url: str, **kwargs: Any) -> BrowserResult:
        if self.browser_binary and not kwargs.get("browser_binary"):
            kwargs["browser_binary"] = self.browser_binary
        return await self.browser.open(url, **kwargs)

    async def solve_cloudflare(self, target_url: str | None = None, **kwargs: Any) -> BrowserResult:
        url = target_url or kwargs.pop("url", None)
        if not url:
            raise ValueError("solve_cloudflare requires target_url")
        kwargs.setdefault("mode", "auto")
        return await self.open(url, **kwargs)

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        if self.browser_binary and not kwargs.get("chrome_path"):
            kwargs["chrome_path"] = self.browser_binary
        return await self.aliyun.solve(**kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        return await self.tencent.solve(**kwargs)

    async def solve_auto(self, target_url: str, *, provider: str = "auto", **kwargs: Any):
        selected = detect_provider_for_url(target_url) if provider == "auto" else provider
        if selected == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if selected == "tencent":
            return await self.solve_tencent(target_url=target_url, **kwargs)
        if selected == "cloudflare":
            return await self.solve_cloudflare(target_url=target_url, **kwargs)
        return CaptchaResult(
            provider=selected or "unknown",
            ok=False,
            captcha_type=None,
            capability="solver",
            diagnostics={"target_url": target_url, "requested_provider": provider},
            errors=["unsupported_provider: SDK supports cloudflare browser flow plus aliyun/tencent sliders"],
        )

    async def auto(self, url: str, *, provider: str = "auto", **kwargs: Any):
        return await self.solve_auto(url, provider=provider, **kwargs)
