from __future__ import annotations

import time
import asyncio
from typing import Any

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy
from ..vendor.tencent.browser_pool import BrowserPool
from ..vendor.tencent.solve_optimized import solve_one
from ..vendor.tencent.site_profiles import get_profile, profile_for_url


def _proxy(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server)
    return cfg.playwright() if cfg else None


class TencentCaptchaSolver:
    """Tencent sliding puzzle solver adapter."""

    def create_pool(
        self,
        *,
        target_url: str | None = None,
        profile: str | None = "cloud_product",
        headless: bool = True,
        proxy_server: str | None = None,
        pool_size: int = 1,
        browser_max_uses: int = 1,
        locale: str | None = None,
        timezone_id: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[BrowserPool, Any]:
        prof = profile_for_url(target_url, profile) if target_url else get_profile(profile)
        pool = BrowserPool(
            size=pool_size,
            max_uses=browser_max_uses,
            headless=headless,
            proxy=_proxy(proxy_server),
            locale=locale or prof.default_locale,
            timezone_id=timezone_id or ("America/New_York" if prof.name == "matrix_ai_detect" else "Asia/Shanghai"),
            user_agent=user_agent,
        )
        return pool, prof

    def _result_from_raw(
        self,
        raw: dict[str, Any] | None,
        *,
        prof: Any,
        target_url: str | None = None,
        profile: str | None = None,
        appid: str | None = None,
        headless: bool = True,
        pool_size: int = 1,
        browser_max_uses: int = 1,
        timeout_sec: int | None = None,
        pool_id: str | None = None,
        proxy_server: str | None = None,
        started: float | None = None,
        error: str | None = None,
        error_type: str | None = None,
    ) -> CaptchaResult:
        elapsed_ms = int((time.monotonic() - started) * 1000) if started else None
        if error:
            return CaptchaResult(
                provider="tencent",
                ok=False,
                captcha_type="slider",
                capability="solver",
                elapsed_ms=elapsed_ms,
                diagnostics={
                    "profile": getattr(prof, "name", None) or profile,
                    "target_url": target_url or getattr(prof, "target_url", None),
                    "appid": appid or getattr(prof, "appid", None),
                    "headless": headless,
                    "pool_size": pool_size,
                    "browser_max_uses": browser_max_uses,
                    "timeout_sec": timeout_sec,
                    "pool_id": pool_id,
                    "proxy": redacted_proxy(proxy_server),
                },
                raw={"error": error, "type": error_type or "Error"},
                errors=[error],
            )

        raw = raw or {}
        ok = bool(raw.get("ok") or raw.get("ticket"))
        return CaptchaResult(
            provider="tencent",
            ok=ok,
            captcha_type="slider",
            capability="solver",
            ticket=raw.get("ticket"),
            randstr=raw.get("randstr"),
            verify_code=str(raw.get("error_code") or "") or None,
            elapsed_ms=raw.get("elapsed_ms") or elapsed_ms,
            diagnostics={
                "profile": raw.get("profile") or getattr(prof, "name", None) or profile,
                "target_url": raw.get("target_url") or target_url or getattr(prof, "target_url", None),
                "appid": raw.get("appid") or appid or getattr(prof, "appid", None),
                "method": raw.get("method"),
                "gap_x": raw.get("gap_x"),
                "conf": raw.get("conf"),
                "rate": raw.get("rate"),
                "init_x": raw.get("init_x"),
                "pool_id": pool_id,
                "proxy": redacted_proxy(proxy_server),
            },
            raw=raw,
            errors=[] if ok else [str(raw.get("error") or raw.get("error_code") or "solve_failed")],
        )

    async def solve_with_pool(
        self,
        pool: BrowserPool,
        *,
        target_url: str | None = None,
        profile: str | None = "cloud_product",
        appid: str | None = None,
        prof: Any = None,
        headless: bool = True,
        pool_size: int | None = None,
        browser_max_uses: int | None = None,
        proxy_server: str | None = None,
        timeout_sec: int | None = None,
        verbose: bool = False,
    ) -> CaptchaResult:
        """Solve one Tencent captcha using an already-started BrowserPool.

        This is the stable path for pressure tests and services: one pool is
        reused, while every run still receives a fresh BrowserContext/Page.
        """
        started = time.monotonic()
        prof = prof or (profile_for_url(target_url, profile) if target_url else get_profile(profile))
        try:
            solve_coro = solve_one(
                pool,
                target_url=target_url,
                profile_name=profile,
                appid=appid,
                verbose=verbose,
            )
            raw = await asyncio.wait_for(solve_coro, timeout=timeout_sec) if timeout_sec else await solve_coro
            return self._result_from_raw(
                raw,
                prof=prof,
                target_url=target_url,
                profile=profile,
                appid=appid,
                headless=headless,
                pool_size=pool_size or pool.size,
                browser_max_uses=browser_max_uses or pool.max_uses,
                timeout_sec=timeout_sec,
                pool_id=getattr(pool, "pool_id", None),
                proxy_server=proxy_server,
                started=started,
            )
        except asyncio.TimeoutError:
            return self._result_from_raw(
                None,
                prof=prof,
                target_url=target_url,
                profile=profile,
                appid=appid,
                headless=headless,
                pool_size=pool_size or pool.size,
                browser_max_uses=browser_max_uses or pool.max_uses,
                timeout_sec=timeout_sec,
                pool_id=getattr(pool, "pool_id", None),
                proxy_server=proxy_server,
                started=started,
                error=f"timeout after {timeout_sec}s",
                error_type="TimeoutError",
            )
        except Exception as e:
            return self._result_from_raw(
                None,
                prof=prof,
                target_url=target_url,
                profile=profile,
                appid=appid,
                headless=headless,
                pool_size=pool_size or pool.size,
                browser_max_uses=browser_max_uses or pool.max_uses,
                timeout_sec=timeout_sec,
                pool_id=getattr(pool, "pool_id", None),
                proxy_server=proxy_server,
                started=started,
                error=str(e),
                error_type=type(e).__name__,
            )

    async def solve(
        self,
        *,
        target_url: str | None = None,
        profile: str | None = "cloud_product",
        appid: str | None = None,
        headless: bool = True,
        proxy_server: str | None = None,
        pool_size: int = 1,
        browser_max_uses: int = 1,
        locale: str | None = None,
        timezone_id: str | None = None,
        user_agent: str | None = None,
        timeout_sec: int | None = None,
        verbose: bool = False,
    ) -> CaptchaResult:
        started = time.monotonic()
        pool: BrowserPool | None = None
        prof = None
        try:
            pool, prof = self.create_pool(
                target_url=target_url,
                profile=profile,
                headless=headless,
                proxy_server=proxy_server,
                pool_size=pool_size,
                browser_max_uses=browser_max_uses,
                locale=locale,
                timezone_id=timezone_id,
                user_agent=user_agent,
            )
            await pool.start()
            return await self.solve_with_pool(
                pool,
                target_url=target_url,
                profile=profile,
                appid=appid,
                prof=prof,
                headless=headless,
                pool_size=pool_size,
                browser_max_uses=browser_max_uses,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                verbose=verbose,
            )
        except Exception as e:
            return self._result_from_raw(
                None,
                prof=prof,
                target_url=target_url,
                profile=profile,
                appid=appid,
                headless=headless,
                pool_size=pool_size,
                browser_max_uses=browser_max_uses,
                timeout_sec=timeout_sec,
                pool_id=getattr(pool, "pool_id", None) if pool else None,
                proxy_server=proxy_server,
                started=started,
                error=str(e),
                error_type=type(e).__name__,
            )
        finally:
            if pool is not None:
                try:
                    await pool.stop()
                except Exception:
                    pass
