#!/usr/bin/env python3
"""
腾讯滑动拼图验证码 - 最终稳定版
策略: 每次独立浏览器 + iframe detached 自动重试 + code=50 刷新重试
成功率目标: >85%
"""

import json, time, random, requests
from typing import Optional
from playwright.sync_api import sync_playwright
from captcha_recognizer.slider import Slider

BASE = "https://turing.captcha.qcloud.com"
RATE = 340 / 672
TARGET_URL = "https://cloud.tencent.com/product/captcha"


def detect_gap(bg_bytes: bytes) -> tuple[int, float]:
    slider = Slider()
    bbox, conf = slider.identify(source=bg_bytes)
    return int(bbox[0]), float(conf)


def solve_one(headless: bool = True, verbose: bool = True) -> Optional[dict]:
    """单次求解,含最多1次内部刷新重试。"""
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
            if verbose:
                print("[+] nav")
            page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=60000)
            time.sleep(2)
            page.evaluate(
                """()=>{
                    var xp="//text()[contains(.,'滑动拼图验证')]/following::*[contains(text(),'立即体验')][1]";
                    var r=document.evaluate(xp,document,null,XPathResult.FIRST_ORDERED_NODE_TYPE,null);
                    var b=r.singleNodeValue;
                    if(b){ b.scrollIntoView({block:'center'}); b.click(); }
                }"""
            )
            time.sleep(5)

            def get_frame():
                el = page.query_selector("iframe#tcaptcha_iframe_dy")
                return el, (el.content_frame() if el else None)

            iframe, frame = get_frame()
            if not frame:
                if verbose:
                    print("[!] no iframe")
                raise RuntimeError("no iframe")

            def inject_hook():
                return frame.evaluate(
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

            def get_bg_url():
                try:
                    return frame.evaluate(
                        """()=>{
                            var bg = document.querySelector('.tc-bg-img');
                            if(bg) return getComputedStyle(bg).backgroundImage.slice(4,-1).replace(/"/g,'');
                            return null;
                        }"""
                    )
                except Exception:
                    return None

            def perform_drag(gap_x: int) -> bool:
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
                    return False
                dist_css = (gap_x - 50) * RATE
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
                return True

            def read_verify() -> Optional[dict]:
                for _ in range(8):
                    try:
                        vr = frame.evaluate("()=>window.__vr")
                    except Exception:
                        return None
                    if vr:
                        try:
                            return json.loads(vr.get("text", "{}"))
                        except Exception:
                            return None
                    time.sleep(0.5)
                return None

            # --- main attempt ---
            for attempt in range(1, 3):
                if verbose:
                    print(f"[+] attempt {attempt}")
                inject_hook()
                bg_url = get_bg_url()
                if not bg_url:
                    if verbose:
                        print("[!] no bg_url")
                    raise RuntimeError("no bg_url")

                bg_bytes = requests.get(bg_url, timeout=15).content
                gap_x, conf = detect_gap(bg_bytes)
                if verbose:
                    print(f"    gap={gap_x} conf={conf:.3f}")
                if conf < 0.85:
                    if verbose:
                        print("[!] low conf")
                    raise RuntimeError("low conf")

                if not perform_drag(gap_x):
                    if verbose:
                        print("[!] drag failed")
                    raise RuntimeError("drag failed")
                time.sleep(3)

                res = read_verify()
                if not res:
                    if verbose:
                        print("[!] no verify response")
                    raise RuntimeError("no verify")
                code = res.get("errorCode")
                if verbose:
                    print(f"    code={code}")
                if code == "0" and res.get("ticket"):
                    result = {
                        "ticket": res["ticket"],
                        "randstr": res.get("randstr", ""),
                        "gap_x": gap_x,
                        "conf": conf,
                    }
                    if verbose:
                        print("[+] PASS")
                    break

                # retry: click refresh and loop
                if attempt == 1:
                    try:
                        frame.evaluate("()=>{var r=document.getElementById('reload');if(r)r.click();}")
                        time.sleep(4)
                        # re-acquire frame in case it was replaced
                        iframe, frame = get_frame()
                        if not frame:
                            if verbose:
                                print("[!] frame lost after refresh")
                            raise RuntimeError("frame lost")
                    except Exception as e:
                        if verbose:
                            print(f"[!] refresh err: {e}")
                        raise
                else:
                    if verbose:
                        print("[-] FAIL")

        except Exception as e:
            if verbose:
                print(f"[!] exception: {e}")

        browser.close()
        return result


def benchmark(n: int = 10):
    ok = 0
    for i in range(n):
        print(f"\n===== Run {i+1}/{n} =====")
        ret = solve_one(headless=True, verbose=True)
        print("Result:", json.dumps(ret, ensure_ascii=False, indent=2) if ret else "None")
        if ret and ret.get("ticket"):
            ok += 1
        time.sleep(2)
    print(f"\n===== Summary: {ok}/{n} passed ({ok/n*100:.1f}%) =====")


if __name__ == "__main__":
    benchmark(10)
