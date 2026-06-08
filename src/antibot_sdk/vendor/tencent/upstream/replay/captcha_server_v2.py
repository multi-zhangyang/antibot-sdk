#!/usr/bin/env python3
"""
腾讯滑动拼图验证码 — FastAPI 服务 v2.

入口:
  cd /root/re-workspace/tencent-captcha/replay
  python3 captcha_server_v2.py

实现:
  - 复用 solve_optimized.py 的运行时几何推导 / 双路 verify 捕获 / reload 重试
  - BrowserPool 懒启动，默认最多 2 个 browser process
  - 每次请求仍使用全新 browser context/page，避免 sess/collect 串题

环境变量:
  TCAPTCHA_POOL_SIZE=2
  TCAPTCHA_BROWSER_MAX_USES=2
  TCAPTCHA_HEADLESS=1
"""

import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Body, FastAPI
from pydantic import BaseModel

try:
    from .browser_pool import BrowserPool
    from .solve_optimized import solve_one, _proxy_from_env
except ImportError:
    from browser_pool import BrowserPool
    from solve_optimized import solve_one, _proxy_from_env


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


POOL_SIZE = max(1, _int_env("TCAPTCHA_POOL_SIZE", 2))
MAX_USES = max(1, _int_env("TCAPTCHA_BROWSER_MAX_USES", 2))
HEADLESS = os.getenv("TCAPTCHA_HEADLESS", "1") != "0"

_pool: Optional[BrowserPool] = None
_semaphore = asyncio.Semaphore(POOL_SIZE)
_stats: dict[str, Any] = {
    "total": 0,
    "ok": 0,
    "fail": 0,
    "total_ms": 0.0,
    "last": None,
    "last_error": None,
}


class SolveResp(BaseModel):
    ok: bool
    profile: Optional[str] = None
    target_url: Optional[str] = None
    appid: Optional[str] = None
    fp: Optional[str] = None
    ticket: Optional[str] = None
    randstr: Optional[str] = None
    gap_x: Optional[int] = None
    conf: Optional[float] = None
    method: Optional[str] = None
    rate: Optional[float] = None
    init_x: Optional[float] = None
    elapsed_ms: Optional[int] = None
    error_code: Optional[str] = None
    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class SolveReq(BaseModel):
    target_url: Optional[str] = None
    profile: Optional[str] = None
    appid: Optional[str] = None
    verbose: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    _pool = BrowserPool(size=POOL_SIZE, max_uses=MAX_USES, headless=HEADLESS, proxy=_proxy_from_env())
    await _pool.start()
    print(f"[+] BrowserPool ready size={POOL_SIZE} max_uses={MAX_USES} headless={HEADLESS}", flush=True)
    try:
        yield
    finally:
        await _pool.stop()
        print("[-] BrowserPool stopped", flush=True)


app = FastAPI(title="TencentCaptcha Solver v2", lifespan=lifespan)


@app.post("/solve", response_model=SolveResp)
async def solve_endpoint(req: Optional[SolveReq] = Body(default=None)):
    global _pool
    if _pool is None:
        return SolveResp(ok=False, error="pool not ready")

    async with _semaphore:
        _stats["total"] += 1
        t0 = time.time()
        try:
            ret = await solve_one(
                _pool,
                verbose=bool(req.verbose) if req else False,
                target_url=req.target_url if req else None,
                profile_name=req.profile if req else None,
                appid=req.appid if req else None,
            )
        except Exception as e:
            ret = None
            err = str(e)
        else:
            err = None

        elapsed_ms = int((time.time() - t0) * 1000)
        _stats["last"] = time.time()

        if ret and ret.get("ticket"):
            _stats["ok"] += 1
            _stats["total_ms"] += ret.get("elapsed_ms") or elapsed_ms
            data = dict(ret)
            data["ok"] = True
            return SolveResp(**data)

        _stats["fail"] += 1
        error_code = str(ret.get("error_code")) if ret and ret.get("error_code") is not None else None
        raw = ret.get("raw") if ret and isinstance(ret.get("raw"), dict) else None
        msg = err or error_code or "solve failed"
        _stats["last_error"] = {"error": msg, "raw": raw, "elapsed_ms": elapsed_ms}
        return SolveResp(ok=False, error=msg, error_code=error_code, raw=raw, elapsed_ms=elapsed_ms)


@app.get("/stats")
def stats_endpoint():
    avg = (_stats["total_ms"] / _stats["ok"]) if _stats["ok"] else 0.0
    return {
        "total": _stats["total"],
        "ok": _stats["ok"],
        "fail": _stats["fail"],
        "success_rate": round(_stats["ok"] / _stats["total"] * 100, 1) if _stats["total"] else 0.0,
        "avg_ms": round(avg, 0),
        "last": _stats["last"],
        "last_error": _stats["last_error"],
        "pool_size": len(_pool._pool) if _pool else 0,
        "pool_limit": POOL_SIZE,
        "max_uses": MAX_USES,
        "headless": HEADLESS,
    }


@app.get("/health")
def health_endpoint():
    return {
        "healthy": _pool is not None,
        "pool_size": len(_pool._pool) if _pool else 0,
        "pool_limit": POOL_SIZE,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=_int_env("TCAPTCHA_PORT", 8999))
