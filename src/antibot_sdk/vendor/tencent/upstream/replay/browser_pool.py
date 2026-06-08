#!/usr/bin/env python3
"""
BrowserPool — 复用 browser process，减少启动开销.

实现要点:
  - 懒启动 browser，避免低配机器一次拉起 4 个 Chromium 导致冷启动卡死
  - 每个 browser 运行 max_uses 次后强制重启，避免 tdc.js 指纹碰撞
  - 每次 solve 仍创建全新 context/page，sess/collect 不跨题复用
"""

import asyncio, time, os
from dataclasses import dataclass, field
from typing import Optional
from playwright.async_api import async_playwright, Browser, BrowserContext


@dataclass
class PooledBrowser:
    browser: Browser
    uses: int = 0
    created_at: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class BrowserPool:
    """Async browser pool with health rotation."""

    def __init__(
        self,
        size: int = 4,
        max_uses: int = 3,
        headless: bool = True,
        xvfb: bool = False,
        initial_size: int = 0,
        proxy: Optional[dict] = None,
        locale: str = "zh-CN",
        timezone_id: str = "Asia/Shanghai",
        user_agent: Optional[str] = None,
    ):
        self.size = size
        self.max_uses = max_uses
        self.headless = headless
        self.xvfb = xvfb
        self.initial_size = initial_size
        self.proxy = proxy
        self.locale = locale
        self.timezone_id = timezone_id
        self.user_agent = user_agent
        self._pool: list[PooledBrowser] = []
        self._lock = asyncio.Lock()
        self._playwright = None
        self._args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]

    async def start(self):
        self._playwright = await async_playwright().start()
        for _ in range(max(0, min(self.initial_size, self.size))):
            b = await self._launch_one()
            self._pool.append(PooledBrowser(browser=b))

    async def _launch_one(self) -> Browser:
        env = os.environ.copy()
        if self.xvfb:
            # if DISPLAY not set, let caller ensure xvfb-run or similar
            pass
        launch_kw = {
            "headless": self.headless,
            "args": self._args,
            "env": env,
        }
        if self.proxy:
            launch_kw["proxy"] = self.proxy
        return await self._playwright.chromium.launch(**launch_kw)

    async def acquire(self) -> tuple[Browser, BrowserContext]:
        while True:
            async with self._lock:
                # 1) reuse an unlocked healthy browser that has remaining budget
                for pb in self._pool:
                    if (
                        not pb.lock.locked()
                        and pb.uses < self.max_uses
                        and pb.browser.is_connected()
                    ):
                        await pb.lock.acquire()
                        pb.uses += 1
                        return pb.browser, await self._new_context(pb.browser)

                # 2) grow lazily until size limit
                if len(self._pool) < self.size:
                    b = await self._launch_one()
                    pb = PooledBrowser(browser=b, uses=1)
                    await pb.lock.acquire()
                    self._pool.append(pb)
                    return pb.browser, await self._new_context(pb.browser)

                # 3) rotate the oldest unlocked exhausted/unhealthy browser
                unlocked = [pb for pb in self._pool if not pb.lock.locked()]
                if unlocked:
                    oldest = min(unlocked, key=lambda x: x.created_at)
                    try:
                        await oldest.browser.close()
                    except Exception:
                        pass
                    oldest.browser = await self._launch_one()
                    oldest.uses = 1
                    oldest.created_at = time.time()
                    await oldest.lock.acquire()
                    return oldest.browser, await self._new_context(oldest.browser)
            await asyncio.sleep(0.2)

    async def _new_context(self, browser: Browser) -> BrowserContext:
        kw = {
            "viewport": {"width": 1366, "height": 768},
            "locale": self.locale,
            "timezone_id": self.timezone_id,
        }
        if self.user_agent:
            kw["user_agent"] = self.user_agent
        return await browser.new_context(**kw)

    async def release(self, pb_browser: Browser, ctx: BrowserContext):
        try:
            await ctx.close()
        except Exception:
            pass
        for pb in self._pool:
            if pb.browser == pb_browser:
                if pb.lock.locked():
                    pb.lock.release()
                return

    async def stop(self):
        for pb in self._pool:
            try:
                await pb.browser.close()
            except Exception:
                pass
        self._pool.clear()
        if self._playwright:
            await self._playwright.stop()
