#!/usr/bin/env python3
"""
BrowserPool — 复用 browser process，减少启动开销.

实现要点:
  - 懒启动 browser，避免低配机器一次拉起 4 个 Chromium 导致冷启动卡死
  - 每个 browser 运行 max_uses 次后强制重启，避免 tdc.js 指纹碰撞
  - 每次 solve 仍创建全新 context/page，sess/collect 不跨题复用
"""

import asyncio, time, os, signal, subprocess, uuid
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
        pool_id: Optional[str] = None,
        launch_timeout_ms: int = 45000,
        close_timeout_sec: float = 8.0,
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
        self.pool_id = pool_id or f"antibot-tencent-{os.getpid()}-{uuid.uuid4().hex[:10]}"
        self.launch_timeout_ms = launch_timeout_ms
        self.close_timeout_sec = close_timeout_sec
        self._pool: list[PooledBrowser] = []
        self._lock = asyncio.Lock()
        self._stop_lock = asyncio.Lock()
        self._playwright = None
        self._closed = False
        self._marker_arg = f"--antibot-pool-id={self.pool_id}"
        self._args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            self._marker_arg,
        ]

    async def start(self):
        if self._playwright is not None:
            self._closed = False
            return
        self._closed = False
        self._playwright = await async_playwright().start()
        for _ in range(max(0, min(self.initial_size, self.size))):
            b = await self._launch_one()
            self._pool.append(PooledBrowser(browser=b))

    async def _launch_one(self) -> Browser:
        if self._closed:
            raise RuntimeError("browser pool is closed")
        if self._playwright is None:
            raise RuntimeError("browser pool is not started")
        env = os.environ.copy()
        if self.xvfb:
            # if DISPLAY not set, let caller ensure xvfb-run or similar
            pass
        launch_kw = {
            "headless": self.headless,
            "args": self._args,
            "env": env,
            "timeout": self.launch_timeout_ms,
        }
        if self.proxy:
            launch_kw["proxy"] = self.proxy
        return await self._playwright.chromium.launch(**launch_kw)

    async def acquire(self) -> tuple[Browser, BrowserContext]:
        while True:
            if self._closed:
                raise RuntimeError("browser pool is closed")
            async with self._lock:
                if self._closed:
                    raise RuntimeError("browser pool is closed")
                # 1) reuse an unlocked healthy browser that has remaining budget
                for pb in self._pool:
                    if (
                        not pb.lock.locked()
                        and pb.uses < self.max_uses
                        and pb.browser.is_connected()
                    ):
                        await pb.lock.acquire()
                        pb.uses += 1
                        try:
                            ctx = await self._new_context(pb.browser)
                        except BaseException:
                            if pb.lock.locked():
                                pb.lock.release()
                            raise
                        return pb.browser, ctx

                # 2) grow lazily until size limit
                if len(self._pool) < self.size:
                    b = await self._launch_one()
                    pb = PooledBrowser(browser=b, uses=1)
                    await pb.lock.acquire()
                    self._pool.append(pb)
                    try:
                        ctx = await self._new_context(pb.browser)
                    except BaseException:
                        if pb.lock.locked():
                            pb.lock.release()
                        try:
                            await pb.browser.close()
                        except Exception:
                            pass
                        try:
                            self._pool.remove(pb)
                        except ValueError:
                            pass
                        raise
                    return pb.browser, ctx

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
                    try:
                        ctx = await self._new_context(oldest.browser)
                    except BaseException:
                        if oldest.lock.locked():
                            oldest.lock.release()
                        raise
                    return oldest.browser, ctx
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
            await asyncio.wait_for(ctx.close(), timeout=self.close_timeout_sec)
        except Exception:
            pass
        for pb in self._pool:
            if pb.browser == pb_browser:
                if pb.lock.locked():
                    pb.lock.release()
                return

    async def _close_browser(self, browser: Browser) -> None:
        try:
            await asyncio.wait_for(browser.close(), timeout=self.close_timeout_sec)
        except Exception:
            pass

    def _marked_process_tree_pids(self) -> set[int]:
        """Return Chromium pids launched by this pool marker plus descendants.

        Playwright exposes no stable public browser PID in Python.  A unique,
        harmless Chromium switch gives us a deterministic cleanup handle for
        timeout paths without touching unrelated Playwright tasks.
        """
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid=,ppid=,cmd="],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return set()
        children: dict[int, list[int]] = {}
        roots: set[int] = set()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                pid_s, ppid_s, cmd = line.split(None, 2)
                pid, ppid = int(pid_s), int(ppid_s)
            except ValueError:
                continue
            children.setdefault(ppid, []).append(pid)
            if self._marker_arg in cmd and pid != os.getpid():
                roots.add(pid)
        targets = set(roots)
        stack = list(roots)
        while stack:
            pid = stack.pop()
            for child in children.get(pid, []):
                if child not in targets and child != os.getpid():
                    targets.add(child)
                    stack.append(child)
        return targets

    def _kill_marked_process_tree(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            pids = self._marked_process_tree_pids()
            if not pids:
                return
            for pid in sorted(pids, reverse=True):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
                except Exception:
                    pass
            time.sleep(0.6 if sig == signal.SIGTERM else 0.1)

    async def stop(self):
        async with self._stop_lock:
            self._closed = True
            browsers = [pb.browser for pb in self._pool]
            self._pool.clear()
            for browser in browsers:
                await self._close_browser(browser)
            if self._playwright:
                try:
                    await asyncio.wait_for(self._playwright.stop(), timeout=self.close_timeout_sec)
                except Exception:
                    pass
                finally:
                    self._playwright = None
            # Fallback for cancelled/timeout paths where Playwright loses the
            # close handshake.  The marker is unique per BrowserPool instance.
            await asyncio.to_thread(self._kill_marked_process_tree)
