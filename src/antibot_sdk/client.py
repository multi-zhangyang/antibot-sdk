from __future__ import annotations

from typing import Any

from .models import CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.tencent import TencentCaptchaSolver


class AntibotClient:
    """Lean SDK facade: only Aliyun slider and Tencent slider are exposed."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.aliyun = AliyunCaptchaSolver()
        self.tencent = TencentCaptchaSolver()

    async def __aenter__(self) -> "AntibotClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        if self.browser_binary and not kwargs.get("chrome_path"):
            kwargs["chrome_path"] = self.browser_binary
        return await self.aliyun.solve(**kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        return await self.tencent.solve(**kwargs)

    async def solve_auto(self, target_url: str, *, provider: str = "auto", **kwargs: Any) -> CaptchaResult:
        selected = detect_provider_for_url(target_url) if provider == "auto" else provider
        if selected == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if selected == "tencent":
            return await self.solve_tencent(target_url=target_url, **kwargs)
        return CaptchaResult(
            provider=selected or "unknown",
            ok=False,
            captcha_type=None,
            capability="solver",
            diagnostics={"target_url": target_url, "requested_provider": provider},
            errors=["unsupported_provider: lean build only supports aliyun and tencent"],
        )

    async def auto(self, url: str, *, provider: str = "auto", **kwargs: Any) -> CaptchaResult:
        return await self.solve_auto(url, provider=provider, **kwargs)
