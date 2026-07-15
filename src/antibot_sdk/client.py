from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.browser import BrowserAutomation
from .providers.geetest import GeetestV4Solver
from .providers.tencent import TencentCaptchaSolver


class AntibotClient:
    """SDK facade for Cloudflare browser flows plus Aliyun/Tencent/GeeTest flows."""

    def __init__(
        self,
        *,
        profile: str = "windows-chrome",
        browser_binary: str | None = None,
        default_proxy: str | None = None,
        use_env_proxy: bool | None = None,
    ):
        self.profile = profile
        self.browser_binary = browser_binary
        self.default_proxy = default_proxy
        self.use_env_proxy = use_env_proxy
        self.browser = BrowserAutomation()
        self.aliyun = AliyunCaptchaSolver()
        self.geetest = GeetestV4Solver()
        self.tencent = TencentCaptchaSolver()

    def _with_defaults(self, kwargs: dict[str, Any], *, browser_key: str = "browser_binary") -> dict[str, Any]:
        out = dict(kwargs)
        if self.browser_binary and not out.get(browser_key):
            out[browser_key] = self.browser_binary
        if self.default_proxy:
            # Cloudflare uses `proxy`; captcha solvers use `proxy_server`.
            if not out.get("proxy") and not out.get("proxy_server"):
                out["proxy"] = self.default_proxy
                out["proxy_server"] = self.default_proxy
        if self.use_env_proxy is not None and "use_env_proxy" not in out:
            out["use_env_proxy"] = self.use_env_proxy
        return out

    async def __aenter__(self) -> "AntibotClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def open(self, url: str, **kwargs: Any) -> BrowserResult:
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        kwargs.pop("proxy_server", None)
        return await self.browser.open(url, **kwargs)

    async def solve_cloudflare(self, target_url: str | None = None, **kwargs: Any) -> BrowserResult:
        url = target_url or kwargs.pop("url", None)
        if not url:
            raise ValueError("solve_cloudflare requires target_url")
        kwargs.setdefault("mode", "auto")
        return await self.open(url, **kwargs)

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        kwargs = self._with_defaults(kwargs, browser_key="chrome_path")
        # Aliyun solver expects proxy_server.
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        kwargs.pop("use_env_proxy", None)
        return await self.aliyun.solve(**kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        kwargs.pop("browser_binary", None)
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        kwargs.pop("use_env_proxy", None)
        return await self.tencent.solve(**kwargs)

    async def solve_geetest(self, target_url: str | None = None, **kwargs: Any) -> CaptchaResult:
        if target_url is not None and not kwargs.get("target_url"):
            kwargs["target_url"] = target_url
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        kwargs.pop("use_env_proxy", None)
        return await self.geetest.solve(**kwargs)

    async def solve_auto(self, target_url: str, *, provider: str = "auto", **kwargs: Any):
        selected = detect_provider_for_url(target_url) if provider == "auto" else provider
        if selected == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if selected == "tencent":
            return await self.solve_tencent(target_url=target_url, **kwargs)
        if selected == "geetest":
            return await self.solve_geetest(target_url=target_url, **kwargs)
        if selected == "cloudflare":
            return await self.solve_cloudflare(target_url=target_url, **kwargs)
        return CaptchaResult(
            provider=selected or "unknown",
            ok=False,
            captcha_type=None,
            capability="solver",
            diagnostics={"target_url": target_url, "requested_provider": provider},
            errors=[
                "unsupported_provider: SDK supports cloudflare/geetest browser flows plus aliyun/tencent sliders"
            ],
        )

    async def auto(self, url: str, *, provider: str = "auto", **kwargs: Any):
        return await self.solve_auto(url, provider=provider, **kwargs)
