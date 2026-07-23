from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from .models import (
    BatchItemResult,
    BatchResult,
    BrowserResult,
    CaptchaResult,
    SolveRequest,
)
from .profiles import detect_provider_for_url

if TYPE_CHECKING:
    from .harness import CaptchaHarness, HarnessBudget, HarnessPlanner
    from .providers.aliyun import AliyunCaptchaSolver
    from .providers.browser import BrowserAutomation
    from .providers.geetest import GeetestV4Solver
    from .providers.arkose import ArkoseCaptchaSolver
    from .providers.tencent import TencentCaptchaSolver
    from .providers.widgets import CaptchaWidgetSolver

SolveResult = BrowserResult | CaptchaResult

_PROVIDER_METHODS = {
    "aliyun": "solve_aliyun",
    "cloudflare": "solve_cloudflare",
    "geetest": "solve_geetest",
    "hcaptcha": "solve_hcaptcha",
    "recaptcha": "solve_recaptcha",
    "arkose": "solve_arkose",
    "tencent": "solve_tencent",
}


class AntibotClient:
    """Async facade over the SDK's solver and page-level browser-flow providers."""

    def __init__(
        self,
        *,
        browser_binary: str | None = None,
        default_proxy: str | None = None,
        use_env_proxy: bool | None = None,
    ):
        self.browser_binary = browser_binary
        self.default_proxy = default_proxy
        self.use_env_proxy = use_env_proxy
        self._browser: BrowserAutomation | None = None
        self._aliyun: AliyunCaptchaSolver | None = None
        self._geetest: GeetestV4Solver | None = None
        self._tencent: TencentCaptchaSolver | None = None
        self._widgets: CaptchaWidgetSolver | None = None
        self._arkose: ArkoseCaptchaSolver | None = None
        self._harness: CaptchaHarness | None = None

    @property
    def browser(self) -> BrowserAutomation:
        if self._browser is None:
            from .providers.browser import BrowserAutomation

            self._browser = BrowserAutomation()
        return self._browser

    @browser.setter
    def browser(self, value: BrowserAutomation) -> None:
        self._browser = value

    @property
    def aliyun(self) -> AliyunCaptchaSolver:
        if self._aliyun is None:
            from .providers.aliyun import AliyunCaptchaSolver

            self._aliyun = AliyunCaptchaSolver()
        return self._aliyun

    @aliyun.setter
    def aliyun(self, value: AliyunCaptchaSolver) -> None:
        self._aliyun = value

    @property
    def geetest(self) -> GeetestV4Solver:
        if self._geetest is None:
            from .providers.geetest import GeetestV4Solver

            self._geetest = GeetestV4Solver()
        return self._geetest

    @geetest.setter
    def geetest(self, value: GeetestV4Solver) -> None:
        self._geetest = value

    @property
    def tencent(self) -> TencentCaptchaSolver:
        if self._tencent is None:
            from .providers.tencent import TencentCaptchaSolver

            self._tencent = TencentCaptchaSolver()
        return self._tencent

    @tencent.setter
    def tencent(self, value: TencentCaptchaSolver) -> None:
        self._tencent = value

    @property
    def widgets(self) -> CaptchaWidgetSolver:
        if self._widgets is None:
            from .providers.widgets import CaptchaWidgetSolver

            self._widgets = CaptchaWidgetSolver()
        return self._widgets

    @widgets.setter
    def widgets(self, value: CaptchaWidgetSolver) -> None:
        self._widgets = value

    @property
    def arkose(self) -> ArkoseCaptchaSolver:
        if self._arkose is None:
            from .providers.arkose import ArkoseCaptchaSolver

            self._arkose = ArkoseCaptchaSolver()
        return self._arkose

    @arkose.setter
    def arkose(self, value: ArkoseCaptchaSolver) -> None:
        self._arkose = value

    @property
    def harness(self) -> CaptchaHarness:
        if self._harness is None:
            from .harness import CaptchaHarness

            self._harness = CaptchaHarness(self._run_provider_tool)
        return self._harness

    @harness.setter
    def harness(self, value: CaptchaHarness) -> None:
        self._harness = value

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

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
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
        return await self.aliyun.solve(**kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        return await self.tencent.solve(**kwargs)

    async def solve_geetest(self, target_url: str | None = None, **kwargs: Any) -> CaptchaResult:
        if target_url is not None and not kwargs.get("target_url"):
            kwargs["target_url"] = target_url
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        return await self.geetest.solve(**kwargs)

    async def _solve_widget(
        self,
        provider: str,
        target_url: str | None = None,
        **kwargs: Any,
    ) -> CaptchaResult:
        url = target_url or kwargs.pop("url", None)
        if not url:
            raise ValueError(f"solve_{provider} requires target_url")
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        return await self.widgets.solve(target_url=url, provider=provider, **kwargs)

    async def solve_recaptcha(
        self,
        target_url: str | None = None,
        **kwargs: Any,
    ) -> CaptchaResult:
        return await self._solve_widget("recaptcha", target_url, **kwargs)

    async def solve_hcaptcha(
        self,
        target_url: str | None = None,
        **kwargs: Any,
    ) -> CaptchaResult:
        return await self._solve_widget("hcaptcha", target_url, **kwargs)

    async def solve_arkose(
        self,
        target_url: str | None = None,
        **kwargs: Any,
    ) -> CaptchaResult:
        url = target_url or kwargs.pop("url", None)
        if not url:
            raise ValueError("solve_arkose requires target_url")
        kwargs = self._with_defaults(kwargs, browser_key="browser_binary")
        if kwargs.get("proxy") and not kwargs.get("proxy_server"):
            kwargs["proxy_server"] = kwargs.pop("proxy")
        else:
            kwargs.pop("proxy", None)
        return await self.arkose.solve(target_url=url, **kwargs)

    async def solve(
        self,
        target_url: str,
        *,
        provider: str = "auto",
        **kwargs: Any,
    ) -> SolveResult:
        """Route one request to a provider while preserving provider-specific options."""

        if not isinstance(target_url, str) or not target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider must be a non-empty string")
        provider = provider.strip().lower()
        selected = detect_provider_for_url(target_url) if provider == "auto" else provider
        method_name = _PROVIDER_METHODS.get(selected)
        if method_name:
            method = getattr(self, method_name)
            return await method(target_url=target_url, **kwargs)
        return CaptchaResult(
            provider=selected or "unknown",
            ok=False,
            captcha_type=None,
            capability="solver",
            diagnostics={"target_url": target_url, "requested_provider": provider},
            errors=[
                "unsupported_provider: expected one of " + ", ".join(_PROVIDER_METHODS)
            ],
        )

    async def solve_auto(
        self,
        target_url: str,
        *,
        provider: str = "auto",
        **kwargs: Any,
    ) -> SolveResult:
        return await self.solve(target_url, provider=provider, **kwargs)

    async def _run_provider_tool(
        self,
        target_url: str,
        provider: str,
        options: dict[str, Any],
    ) -> SolveResult:
        return await self.solve(target_url, provider=provider, **options)

    async def solve_agent(
        self,
        target_url: str,
        *,
        provider: str = "auto",
        planner: HarnessPlanner | None = None,
        budget: HarnessBudget | None = None,
        **kwargs: Any,
    ) -> SolveResult:
        """Run one auditable harness episode over the registered provider tools."""

        if planner is None:
            harness = self.harness
        else:
            from .harness import CaptchaHarness

            harness = CaptchaHarness(self._run_provider_tool, planner=planner)
        return await harness.solve(
            target_url,
            provider=provider,
            options=kwargs,
            budget=budget,
        )

    async def solve_harness(
        self,
        target_url: str,
        *,
        provider: str = "auto",
        planner: HarnessPlanner | None = None,
        budget: HarnessBudget | None = None,
        **kwargs: Any,
    ) -> SolveResult:
        return await self.solve_agent(
            target_url,
            provider=provider,
            planner=planner,
            budget=budget,
            **kwargs,
        )

    async def solve_batch(
        self,
        requests: Iterable[SolveRequest | dict[str, Any]],
        *,
        concurrency: int = 3,
        default_timeout_sec: float | None = None,
    ) -> BatchResult:
        """Solve multiple independent requests with bounded concurrency.

        Input order is retained. Provider failures and unexpected exceptions are
        represented on their corresponding item and do not cancel sibling work.
        """

        batch = [SolveRequest.from_value(value) for value in requests]
        if not batch:
            return BatchResult(
                ok=True,
                total=0,
                succeeded=0,
                failed=0,
                elapsed_ms=0,
                concurrency=0,
            )
        limit = max(1, min(int(concurrency), len(batch)))
        semaphore = asyncio.Semaphore(limit)
        batch_started = time.monotonic()

        async def run_item(index: int, request: SolveRequest) -> BatchItemResult:
            item_started = time.monotonic()
            request_id = request.request_id or str(index)
            selected = (
                detect_provider_for_url(request.target_url)
                if request.provider == "auto"
                else request.provider.lower()
            )
            try:
                async with semaphore:
                    operation = self.solve(
                        request.target_url,
                        provider=request.provider,
                        **dict(request.options),
                    )
                    timeout = request.timeout_sec or default_timeout_sec
                    result = (
                        await asyncio.wait_for(operation, timeout=timeout)
                        if timeout is not None
                        else await operation
                    )
                return BatchItemResult(
                    index=index,
                    request_id=request_id,
                    provider=selected,
                    ok=result.ok,
                    elapsed_ms=int((time.monotonic() - item_started) * 1000),
                    result=result,
                    errors=list(result.errors),
                )
            except asyncio.TimeoutError:
                timeout = request.timeout_sec or default_timeout_sec
                return BatchItemResult(
                    index=index,
                    request_id=request_id,
                    provider=selected,
                    ok=False,
                    elapsed_ms=int((time.monotonic() - item_started) * 1000),
                    error_type="TimeoutError",
                    errors=[f"timeout after {timeout}s"],
                )
            except Exception as exc:
                return BatchItemResult(
                    index=index,
                    request_id=request_id,
                    provider=selected,
                    ok=False,
                    elapsed_ms=int((time.monotonic() - item_started) * 1000),
                    error_type=type(exc).__name__,
                    errors=[str(exc)],
                )

        items = await asyncio.gather(
            *(run_item(index, request) for index, request in enumerate(batch))
        )
        succeeded = sum(1 for item in items if item.ok)
        return BatchResult(
            ok=succeeded == len(items),
            total=len(items),
            succeeded=succeeded,
            failed=len(items) - succeeded,
            elapsed_ms=int((time.monotonic() - batch_started) * 1000),
            concurrency=limit,
            items=items,
        )

    async def auto(self, url: str, *, provider: str = "auto", **kwargs: Any) -> SolveResult:
        return await self.solve_auto(url, provider=provider, **kwargs)
