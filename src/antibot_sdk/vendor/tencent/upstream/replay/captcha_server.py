#!/usr/bin/env python3
"""
腾讯滑动拼图验证码 - FastAPI 服务
单次运行: python captcha_server.py
接口: POST /solve -> {ticket, randstr, gap_x, conf, elapsed_ms}
并发上限: 2 (Semaphore), 避免 Chromium 吃满 CPU
"""

import asyncio, json, time, random, requests
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel
from playwright.sync_api import sync_playwright
from captcha_recognizer.slider import Slider

BASE = "https://turing.captcha.qcloud.com"
RATE = 340 / 672
TARGET_URL = "https://cloud.tencent.com/product/captcha"

# runtime stats
_stats = {
    "total": 0,
    "ok": 0,
    "fail": 0,
    "total_ms": 0.0,
    "last": None,
}

_semaphore = asyncio.Semaphore(2)


def detect_gap(bg_bytes: bytes) -> tuple[int, float]:
    slider = Slider()
    bbox, conf = slider.identify(source=bg_bytes)
    return int(bbox[0]), float(conf)


def solve_once(headless: bool = True) -> Optional[dict]:
    t0 = time.time()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-blink-features=AutomationControlled"],
        )
        page = browser.new_page(
            viewport={"width": 1366, "height": 768},
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
        )
        result = None
        try:
            page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=60000)
            time.sleep(3)
            page.evaluate(
                """()=>{
                    var xp="//text()[contains(.,'滑动拼图验证')]/following::*[contains(text(),'立即体验')][1]";
                    var r=document.evaluate(xp,document,null,XPathResult.FIRST_ORDERED_NODE_TYPE,null);
                    var b=r.singleNodeValue;
                    if(b){ b.scrollIntoView({block:'center'}); b.click(); }
                }"""
            )
            time.sleep(5)

            iframe = None
            frame = None
            bg_url = None
            for _ in range(20):
                try:
                    el = page.query_selector("iframe#tcaptcha_iframe_dy")
                    if el:
                        f = el.content_frame()
                        if f:
                            # try evaluate quickly
                            f.evaluate("()=>{}")
                            iframe = el
                            frame = f
                            break
                except Exception:
                    pass
                time.sleep(0.5)
            if not frame:
                raise RuntimeError("no stable iframe")

            # hook verify response + get bg_url (retry on detached)
            for _ in range(5):
                try:
                    frame.evaluate(
                        """()=>{
                            window.__vr = null;
                            const oo = XMLHttpRequest.prototype.open;
                            const os = XMLHttpRequest.prototype.send;
                            XMLHttpRequest.prototype.open = function(m, url){ this._u = url; return oo.apply(this, arguments); };
                            XMLHttpRequest.prototype.send = function(body){
                                const s = this;
                                const ol = s.onload;
                                s.onload = function(){
                                    if(s._u && s._u.includes('cap_union_new_verify')){
                                        window.__vr = {status: s.status, text: s.responseText};
                                    }
                                    if(ol) ol.call(this);
                                };
                                return os.apply(this, arguments);
                            };
                        }"""
                    )
                    bg_url = frame.evaluate(
                        """()=>{
                            var bg = document.querySelector('.tc-bg-img');
                            if(bg) return getComputedStyle(bg).backgroundImage.slice(4,-1).replace(/"/g,'');
                            return null;
                        }"""
                    )
                    if bg_url:
                        break
                except Exception:
                    time.sleep(0.5)
            if not bg_url:
                raise RuntimeError("no bg_url")

            bg_bytes = requests.get(bg_url, timeout=15).content
            gap_x, conf = detect_gap(bg_bytes)
            if conf < 0.85:
                raise RuntimeError("low conf")

            dist_css = (gap_x - 50) * RATE
            box = iframe.bounding_box()
            thumb = frame.evaluate(
                """()=>{
                    var d = document.querySelector('.tc-drag-thumb');
                    if(!d) d = document.querySelector('.tc-slider-normal');
                    if(!d) return null;
                    var r = d.getBoundingClientRect();
                    return {x:r.x, y:r.y, w:r.width, h:r.height};
                }"""
            )
            if not thumb:
                raise RuntimeError("no slider")
            sx = box["x"] + thumb["x"] + thumb["w"] * 0.5
            sy = box["y"] + thumb["y"] + thumb["h"] * 0.5

            page.mouse.move(sx, sy)
            time.sleep(random.uniform(0.1, 0.3))
            page.mouse.down()
            n = random.randint(28, 35)
            for i in range(1, n + 1):
                jitter = random.gauss(0, 0.8)
                page.mouse.move(sx + dist_css * i / n, sy + jitter)
                time.sleep(random.uniform(0.008, 0.016))
            page.mouse.up()
            time.sleep(3)

            for _ in range(8):
                try:
                    vr = frame.evaluate("()=>window.__vr")
                except Exception:
                    break
                if vr:
                    try:
                        res = json.loads(vr.get("text", "{}"))
                    except Exception:
                        break
                    if res.get("errorCode") == "0" and res.get("ticket"):
                        result = {
                            "ticket": res["ticket"],
                            "randstr": res.get("randstr", ""),
                            "gap_x": gap_x,
                            "conf": conf,
                            "elapsed_ms": int((time.time() - t0) * 1000),
                        }
                        break
                    break
                time.sleep(0.5)
        finally:
            browser.close()
    return result


app = FastAPI(title="TencentCaptcha Solver")


class SolveResp(BaseModel):
    ok: bool
    ticket: Optional[str] = None
    randstr: Optional[str] = None
    gap_x: Optional[int] = None
    conf: Optional[float] = None
    elapsed_ms: Optional[int] = None
    error: Optional[str] = None


@app.post("/solve", response_model=SolveResp)
async def solve_endpoint():
    async with _semaphore:
        _stats["total"] += 1
        err = None
        try:
            ret = await asyncio.to_thread(solve_once, headless=True)
        except Exception as e:
            ret = None
            err = str(e)
        _stats["last"] = time.time()
        if ret and ret.get("ticket"):
            _stats["ok"] += 1
            _stats["total_ms"] += ret.get("elapsed_ms", 0)
            return SolveResp(ok=True, **ret)
        else:
            _stats["fail"] += 1
            return SolveResp(ok=False, error=err or "solve failed")


@app.get("/stats")
def stats_endpoint():
    avg = (_stats["total_ms"] / _stats["ok"]) if _stats["ok"] else 0.0
    return {
        "total": _stats["total"],
        "ok": _stats["ok"],
        "fail": _stats["fail"],
        "success_rate": round(_stats["ok"] / _stats["total"] * 100, 1) if _stats["total"] else 0.0,
        "avg_ms": round(avg, 0),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8999)
