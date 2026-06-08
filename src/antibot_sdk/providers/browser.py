from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..models import BrowserResult
from ..proxy import normalize_proxy_url
from .cloudflare import RunnerConfig, diagnose_environment, run_once


class BrowserAutomation:
    """Pydoll/CDP browser automation provider."""

    async def open(
        self,
        url: str,
        *,
        mode: str = "auto",
        headless: str | bool = "auto",
        selectors: dict[str, str] | None = None,
        clicks: list[str] | None = None,
        screenshot: str | None = None,
        html_output: str | None = None,
        output_json: str | None = None,
        proxy: str | None = None,
        profile_dir: str | None = None,
        browser_binary: str | None = None,
        user_agent: str | None = None,
        platform: str | None = None,
        max_wait: int = 90,
        captcha_wait: float = 8.0,
        **kwargs: Any,
    ) -> BrowserResult:
        if isinstance(headless, bool):
            headless_value = "true" if headless else "false"
        else:
            headless_value = headless
        normalized_proxy = normalize_proxy_url(proxy) if proxy else None
        cfg = RunnerConfig(
            url=url,
            mode=mode,  # type: ignore[arg-type]
            headless=headless_value,  # type: ignore[arg-type]
            browser_binary=browser_binary,
            proxy=normalized_proxy,
            profile_dir=profile_dir,
            user_agent=user_agent,
            platform=platform,
            max_wait=max_wait,
            captcha_wait=captcha_wait,
            screenshot=screenshot,
            html_output=html_output,
            output_json=output_json,
            selectors=selectors or {},
            clicks=clicks or [],
            **kwargs,
        )
        ret = await run_once(cfg)
        raw = asdict(ret)
        return BrowserResult(
            ok=ret.ok,
            state=ret.state,
            url=ret.url,
            final_url=ret.final_url,
            title=ret.title,
            selectors=ret.selectors,
            artifacts=ret.artifacts,
            diagnostics=ret.diagnostics,
            errors=ret.errors,
            raw=raw,
        )

    @staticmethod
    def diagnose(browser_binary: str | None = None) -> dict[str, Any]:
        return diagnose_environment(browser_binary)
