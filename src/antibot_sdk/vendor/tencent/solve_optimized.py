#!/usr/bin/env python3
"""
腾讯滑动拼图验证码 — 优化版
改进:
  1. BrowserPool 懒启动复用 browser process (减少冷启动卡死和空闲资源占用)
  2. crack_tcaptcha ease-in-out cubic 轨迹 + 随机微停顿
  3. 缺口检测双保险 (captcha-recognizer + OpenCV Sobel 备援)
  4. 从运行时 DOM + 背景图尺寸动态推导 rate/init_x，不再硬编码 340/672/50
  5. Playwright network response + iframe XHR 双路捕获 verify 响应
  6. code=50 自动 reload 重试一次；每次仍使用全新 context/page
"""

import asyncio
import contextlib
import io
import json
import os
import random
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
from PIL import Image
from playwright.async_api import Frame, Page

try:
    from .browser_pool import BrowserPool
    from .gap_detect import detect_gap
    from .site_profiles import SiteProfile, get_profile, profile_for_url
except ImportError:
    from browser_pool import BrowserPool
    from gap_detect import detect_gap
    from site_profiles import SiteProfile, get_profile, profile_for_url

# crack_tcaptcha trajectory
try:
    from crack_tcaptcha.trajectory import generate_slide_trajectory
except ImportError:
    import sys, os
    for pattern in ["../venv/lib/python*/site-packages", "venv/lib/python*/site-packages"]:
        import glob
        matches = glob.glob(pattern)
        if matches:
            sys.path.insert(0, matches[0])
            break
    from crack_tcaptcha.trajectory import generate_slide_trajectory

DEFAULT_RATE = 340 / 672
DEFAULT_INIT_X = 50.0
DEFAULT_PROFILE = get_profile(os.getenv("TCAPTCHA_PROFILE", "cloud_product"))
TARGET_URL = os.getenv("TCAPTCHA_TARGET_URL", DEFAULT_PROFILE.target_url)
TARGET_APPID = os.getenv("TCAPTCHA_APPID", DEFAULT_PROFILE.appid or "")
VERIFY_PATH = "cap_union_new_verify"
MAX_ATTEMPTS = int(os.getenv("TCAPTCHA_MAX_ATTEMPTS", "2"))
PAGE_RETRIES = int(os.getenv("TCAPTCHA_PAGE_RETRIES", "2"))
FRAME_WAIT_SEC = float(os.getenv("TCAPTCHA_FRAME_WAIT_SEC", "18"))

BG_SELECTOR = ".tc-bg-img, .tencent-captcha-dy__verify-bg-img"
SLIDER_SELECTOR = (
    ".tc-slider-normal, .tc-drag-thumb, "
    ".tencent-captcha-dy__slider-block, .tencent-captcha-dy__slider-block--normal"
)
PIECE_SELECTOR = ".tc-fg-item, .tencent-captcha-dy__fg-item"
RELOAD_SELECTOR = (
    "#reload, .tc-action--refresh, "
    ".tencent-captcha-dy__footer-icon--refresh"
)


@dataclass
class RuntimeGeometry:
    rate: float
    init_x: float
    start_x: float
    start_y: float
    end_x: float
    end_y: float
    raw_width: int
    css_width: float


@dataclass
class CaptchaFrame:
    frame: Frame
    iframe_element: Optional[object] = None

    async def offset(self) -> tuple[float, float]:
        if not self.iframe_element:
            return 0.0, 0.0
        box = await self.iframe_element.bounding_box()
        if not box:
            raise RuntimeError("iframe detached")
        return float(box["x"]), float(box["y"])


async def _fetch_bytes(url: str, timeout: int = 15) -> bytes:
    if url.startswith("data:image/"):
        import base64

        _, data = url.split(",", 1)
        return base64.b64decode(data)

    def _get() -> bytes:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.content

    return await asyncio.to_thread(_get)


async def _fetch_bg_bytes(frame: Frame, url: str) -> bytes:
    """优先在验证码 frame 内 fetch 背景图。

    原因:
      - 保留同源 cookie / referer / credentials 行为
      - 兼容相对 URL / blob: URL
      - requests 只作为网络兜底
    """
    if url.startswith("data:image/"):
        return await _fetch_bytes(url)

    try:
        arr = await frame.evaluate(
            """async (url)=>{
                const r = await fetch(url, {credentials: 'include', cache: 'no-store'});
                if (!r.ok) throw new Error('fetch status ' + r.status);
                const b = await r.arrayBuffer();
                return Array.from(new Uint8Array(b));
            }""",
            url,
        )
        return bytes(arr)
    except Exception:
        return await _fetch_bytes(url)


def _image_width(buf: bytes) -> int:
    with Image.open(io.BytesIO(buf)) as im:
        return int(im.width)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_matrix_fp_file() -> Path:
    # Prefer the fp that was already warmed by tencent-ai-detect; otherwise keep a
    # local reusable fp under this project.  This mirrors browser localStorage.
    ctf_root = Path(__file__).resolve().parents[2]
    sibling = ctf_root / "tencent-ai-detect" / "replay" / ".tmp" / "guest_fp.txt"
    if sibling.exists():
        return sibling
    return _project_root() / "notes" / "matrix_guest_fp.txt"


def _stable_fp() -> str:
    env_fp = os.getenv("TCAPTCHA_FP", "").strip().lower()
    if env_fp:
        return env_fp
    fp_file = Path(os.getenv("TCAPTCHA_FP_FILE", str(_default_matrix_fp_file())))
    if fp_file.exists():
        fp = fp_file.read_text(encoding="utf-8").strip().lower()
        if fp:
            return fp
    fp = "".join(random.choice("0123456789abcdef") for _ in range(32))
    try:
        fp_file.parent.mkdir(parents=True, exist_ok=True)
        fp_file.write_text(fp + "\n", encoding="utf-8")
    except Exception:
        pass
    return fp


def _public_fp_marker(fp: str) -> Optional[str]:
    """Do not expose the reusable Matrix guest fp in API/benchmark output."""
    return "<redacted>" if fp else None


def _proxy_from_env() -> Optional[dict]:
    server = os.getenv("TCAPTCHA_PROXY_SERVER", "").strip()
    if not server:
        return None
    username = os.getenv("TCAPTCHA_PROXY_USER", "")
    password = os.getenv("TCAPTCHA_PROXY_PASS", "")
    parsed = urllib.parse.urlparse(server)
    if parsed.username or parsed.password:
        username = username or urllib.parse.unquote(parsed.username or "")
        password = password or urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        server = f"{parsed.scheme}://{host}{port}"
    cfg = {"server": server}
    if username or password:
        cfg.update({"username": username, "password": password})
    return cfg


async def _click_trigger(page: Page) -> bool:
    """点击示例页触发按钮或朱雀AI检测页触发检测。

    兼容:
      - 腾讯云产品页: “滑动拼图验证” 后面的 “立即体验”
      - 本地 demo.html/raw/test.html: “点击验证”
      - 朱雀AI检测页: 填充 textarea → 点击检测
      - 已自动弹出的场景: 不做点击，后续 wait_frame 会接管
    """
    url = page.url
    clicked = False

    # --- 朱雀AI检测页 (matrix.tencent.com/ai-detect) ---
    if "matrix.tencent.com/ai-detect" in url:
        for _ in range(10):
            await asyncio.sleep(0.5)
            # 等待 textarea 就绪
            textarea = await page.query_selector("textarea.el-textarea__inner")
            if textarea:
                break
        if not textarea:
            # 可能是 iframe 内独立运行，返回 False 让 wait_frame 接管
            await asyncio.sleep(2)
            return False
        await textarea.fill("A" * 360)
        await asyncio.sleep(0.8)
        submit = await page.query_selector("button.submit-btn")
        if submit:
            await submit.click()
            await asyncio.sleep(4)
            return True
        await asyncio.sleep(2)
        return False

    # --- 腾讯云产品页等 ---
    for _ in range(4):
        await asyncio.sleep(1.5)
        clicked = bool(await page.evaluate(
            """()=>{
            const visible = (el) => {
                if(!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 1 && r.height > 1 && cs.visibility !== 'hidden' && cs.display !== 'none';
            };
            const clickEl = (el) => {
                try {
                    el.scrollIntoView({block:'center', inline:'center'});
                    el.click();
                    return true;
                } catch(e) { return false; }
            };
            const xps = [
                "//text()[contains(.,'滑动拼图验证')]/following::*[contains(text(),'立即体验')][1]",
                "//*[contains(text(),'点击验证')]",
                "//*[contains(text(),'立即体验')]",
                "//*[contains(text(),'体验')]"
            ];
            for (const xp of xps) {
                const r = document.evaluate(xp, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                const el = r.singleNodeValue;
                if (visible(el) && clickEl(el)) return true;
            }
            const nodes = Array.from(document.querySelectorAll('button,a,div,span'));
            const keys = ['点击验证', '立即体验', '开始验证', '验证'];
            for (const k of keys) {
                const el = nodes.find(e => visible(e) && (e.innerText || '').trim().includes(k));
                if (el && clickEl(el)) return true;
            }
            return false;
        }"""
        ))
        if clicked:
            await asyncio.sleep(4)
            return True
    # 可能是验证码已自动弹出；交给 _wait_frame 判定。
    await asyncio.sleep(2)
    return False


async def _wait_frame(page: Page) -> CaptchaFrame:
    """等待验证码渲染完成。

    两条路径:
      1. 旧模板: iframe#tcaptcha_iframe_dy 内部含 .tc-bg-img
      2. 新模板: tgJCap 直接把 .tencent-captcha-dy__verify-bg-img 渲染到主页面
    """
    async def ready(frame: Frame) -> bool:
        try:
            return bool(
                await frame.evaluate(
                    """(sels)=>{
                        const visible = (e) => {
                            if(!e) return false;
                            const r = e.getBoundingClientRect();
                            const cs = getComputedStyle(e);
                            return r.width > 1 && r.height > 1 &&
                                   cs.display !== 'none' && cs.visibility !== 'hidden';
                        };
                        return visible(document.querySelector(sels.bg)) &&
                               visible(document.querySelector(sels.slider));
                    }""",
                    {"bg": BG_SELECTOR, "slider": SLIDER_SELECTOR},
                )
            )
        except Exception:
            return False

    loops = max(1, int(FRAME_WAIT_SEC / 0.3))
    for _ in range(loops):
        if await ready(page.main_frame):
            return CaptchaFrame(frame=page.main_frame, iframe_element=None)

        # Prefer the known dy iframe element so page coordinates can be offset exactly.
        known = await page.query_selector("iframe#tcaptcha_iframe_dy")
        if known:
            try:
                frame = await known.content_frame()
                if frame and await ready(frame):
                    return CaptchaFrame(frame=frame, iframe_element=known)
            except Exception:
                pass

        # Fallback for alternate iframe ids/templates.
        for frame in page.frames:
            if frame is page.main_frame:
                continue
            if await ready(frame):
                owner = None
                try:
                    owner = await frame.frame_element()
                except Exception:
                    pass
                return CaptchaFrame(frame=frame, iframe_element=owner)
        await asyncio.sleep(0.3)
    raise RuntimeError("no stable captcha frame")


async def _inject_xhr_hook(frame: Frame) -> None:
    await frame.evaluate(
        """()=>{
            if (window.__tc_hooked) {
                window.__vr = null;
                return;
            }
            window.__tc_hooked = true;
            window.__vr = null;
            const oo = XMLHttpRequest.prototype.open;
            const os = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(m, url){
                this._tc_u = String(url || "");
                return oo.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function(body){
                const xhr = this;
                function cap(){
                    try {
                        if(xhr._tc_u && xhr._tc_u.includes('cap_union_new_verify')){
                            window.__vr = {status: xhr.status, text: xhr.responseText};
                        }
                    } catch(e) {}
                }
                xhr.addEventListener('load', cap);
                xhr.addEventListener('readystatechange', function(){
                    if (xhr.readyState === 4) cap();
                });
                return os.apply(this, arguments);
            };
            if (window.fetch && !window.fetch.__tc_hooked) {
                const of = window.fetch;
                const nf = function(input, init){
                    const u = typeof input === 'string' ? input : (input && input.url) || '';
                    return of.apply(this, arguments).then(async function(resp){
                        try {
                            if(String(u).includes('cap_union_new_verify')){
                                const clone = resp.clone();
                                window.__vr = {status: clone.status, text: await clone.text()};
                            }
                        } catch(e) {}
                        return resp;
                    });
                };
                nf.__tc_hooked = true;
                window.fetch = nf;
            }
        }"""
    )


async def _bg_url(frame: Frame) -> str:
    for _ in range(12):
        try:
            url = await frame.evaluate(
                """()=>{
                    const bg = document.querySelector('%s');
                    if(!bg) return null;
                    const v = getComputedStyle(bg).backgroundImage || "";
                    const m = v.match(/^url\\(["']?(.*?)["']?\\)$/);
                    if (!m) return null;
                    try { return new URL(m[1], document.baseURI).href; }
                    catch(e) { return m[1]; }
                }""" % BG_SELECTOR
            )
            if url:
                return url
        except Exception:
            pass
        await asyncio.sleep(0.3)
    raise RuntimeError("no bg_url")


async def _runtime_geometry(
    target: CaptchaFrame,
    bg_bytes: bytes,
    gap_x: int,
) -> RuntimeGeometry:
    """从页面真实渲染推导坐标映射。

    dy-ele 运行链路:
      getRate() = $(#tcOperation).width() / bg_elem_cfg.size_2d[0]
      DynAnswerType_POS = floor(curCSSPosition / rate)

    因此需要拖动 slider 的 CSS 距离:
      dist_css = (gap_x - piece_init_x_raw) * rate
    """
    raw_width = _image_width(bg_bytes)
    dom = await target.frame.evaluate(
        """()=>{
            const rectObj = (e) => {
                if(!e) return null;
                const r = e.getBoundingClientRect();
                const cs = getComputedStyle(e);
                return {
                    x:r.x, y:r.y, w:r.width, h:r.height,
                    left:parseFloat(cs.left || "NaN"),
                    top:parseFloat(cs.top || "NaN"),
                    cls:String(e.className || "")
                };
            };
            const bg = document.querySelector('%s');
            const slider = document.querySelector('%s');
            const pieces = Array.from(document.querySelectorAll('%s'))
                .filter(e => !e.classList.contains('tc-slider-normal'))
                .filter(e => !e.classList.contains('tencent-captcha-dy__slider-block'))
                .filter(e => !e.classList.contains('tencent-captcha-dy__slider-block--normal'))
                .map(rectObj)
                .filter(r => r && r.w > 35 && r.h > 35)
                .sort((a,b) => (b.h*b.w) - (a.h*a.w));
            return {bg: rectObj(bg), slider: rectObj(slider), piece: pieces[0] || null};
        }""" % (BG_SELECTOR, SLIDER_SELECTOR, PIECE_SELECTOR)
    )
    if not dom or not dom.get("bg") or not dom.get("slider"):
        raise RuntimeError("no geometry")

    bg = dom["bg"]
    slider = dom["slider"]
    piece = dom.get("piece") or {}
    css_width = float(bg.get("w") or 0)
    if raw_width <= 0 or css_width <= 0:
        rate = DEFAULT_RATE
    else:
        rate = css_width / raw_width

    piece_left = piece.get("left")
    if piece_left is None or not isinstance(piece_left, (int, float)) or piece_left != piece_left:
        # fallback: relative x against bg left
        if piece.get("x") is not None and bg.get("x") is not None:
            piece_left = float(piece["x"]) - float(bg["x"])
        else:
            piece_left = DEFAULT_INIT_X * rate
    init_x = float(piece_left) / rate if rate else DEFAULT_INIT_X
    if not (30 <= init_x <= 80):
        init_x = DEFAULT_INIT_X

    off_x, off_y = await target.offset()
    start_x = off_x + float(slider["x"]) + float(slider["w"]) * 0.5
    start_y = off_y + float(slider["y"]) + float(slider["h"]) * 0.5
    dist_css = (float(gap_x) - init_x) * rate
    return RuntimeGeometry(
        rate=rate,
        init_x=init_x,
        start_x=start_x,
        start_y=start_y,
        end_x=start_x + dist_css,
        end_y=start_y,
        raw_width=raw_width,
        css_width=css_width,
    )


def _install_verify_capture(page: Page) -> dict:
    state = {"res": None}

    async def _capture(resp):
        if VERIFY_PATH not in resp.url:
            return
        try:
            state["res"] = json.loads(await resp.text())
        except Exception as e:
            state["res"] = {"errorCode": "parseError", "errorMessage": str(e)}

    def _on_response(resp):
        asyncio.create_task(_capture(resp))

    page.on("response", _on_response)
    return state


async def _read_verify(frame: Frame, state: dict) -> Optional[dict]:
    for _ in range(12):
        if state.get("res"):
            return state["res"]
        try:
            vr = await frame.evaluate("()=>window.__vr")
            if vr:
                try:
                    return json.loads(vr.get("text", "{}"))
                except Exception:
                    return {"errorCode": "parseError", "errorMessage": str(vr)[:300]}
        except Exception:
            # frame 可能在 verify 后立刻刷新/销毁；继续等 Playwright response 捕获。
            pass
        await asyncio.sleep(0.4)
    return state.get("res")


async def _drag(page: Page, geo: RuntimeGeometry) -> None:
    traj = generate_slide_trajectory(
        int(geo.start_x),
        int(geo.start_y),
        int(geo.end_x),
        int(geo.end_y),
        duration_ms=random.randint(900, 1700),
        interval_ms=random.randint(24, 36),
    )
    await page.mouse.move(geo.start_x, geo.start_y)
    await asyncio.sleep(random.uniform(0.1, 0.3))
    await page.mouse.down()
    prev_t = 0
    for pt in traj.points:
        delay_ms = pt.t - prev_t
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
        await page.mouse.move(pt.x, pt.y)
        prev_t = pt.t
    await asyncio.sleep(random.uniform(0.05, 0.16))
    await page.mouse.up()


async def _consume_playwright_on_cancel(coro):
    """Await a Playwright coroutine and consume its terminal exception on cancel.

    Cancelling a navigation while closing the browser can otherwise produce a
    noisy "Future exception was never retrieved" warning from Playwright's
    internal future.  The caller still receives CancelledError for timeout
    handling; this helper only drains the underlying operation.
    """
    task = asyncio.create_task(coro)
    try:
        return await task
    except asyncio.CancelledError:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        raise


async def solve_one(
    pool: BrowserPool,
    headless: Optional[bool] = None,
    verbose: bool = True,
    use_xvfb: bool = False,
    target_url: Optional[str] = None,
    profile_name: Optional[str] = None,
    appid: Optional[str] = None,
) -> Optional[dict]:
    """单次求解，从 pool 取 browser/context，用完归还.

    headless/use_xvfb 保留为兼容旧调用；实际启动参数由 BrowserPool 决定。
    """
    resolved_url = target_url or TARGET_URL
    profile = profile_for_url(resolved_url, profile_name)
    resolved_appid = appid or os.getenv("TCAPTCHA_APPID") or profile.appid or TARGET_APPID
    browser, ctx = await pool.acquire()
    try:
        stable_fp = _stable_fp() if profile.needs_stable_fp else ""
        if stable_fp:
            await ctx.add_init_script(
                "try{if(location.hostname==='matrix.tencent.com')localStorage.setItem('fp', %s)}catch(e){}"
                % json.dumps(stable_fp)
            )
        last = None
        for page_try in range(1, PAGE_RETRIES + 2):
            page = None
            for context_try in range(1, 3):
                try:
                    page = await ctx.new_page()
                    break
                except Exception as e:
                    msg = str(e)
                    target_closed = "Target page, context or browser has been closed" in msg or "has been closed" in msg
                    if not target_closed or context_try >= 2:
                        raise
                    if verbose:
                        print("[!] context closed before new_page; reacquiring browser", flush=True)
                    try:
                        await asyncio.shield(pool.release(browser, ctx))
                    except Exception:
                        pass
                    browser, ctx = await pool.acquire()
            if page is None:
                raise RuntimeError("new_page failed")
            try:
                result = await _solve_on_page(
                    page,
                    target_url=resolved_url,
                    verbose=verbose,
                    profile=profile,
                    appid=resolved_appid,
                    stable_fp=stable_fp,
                )
            finally:
                try:
                    await asyncio.shield(page.close())
                except Exception:
                    pass
            last = result
            if result and result.get("ticket"):
                return result
            code = str(result.get("error_code")) if result else "unknown"
            if code in {"no_frame", "nav_error"} and page_try <= PAGE_RETRIES:
                if verbose:
                    print(f"[!] page retry {page_try}/{PAGE_RETRIES}: {code}", flush=True)
                await asyncio.sleep(random.uniform(1.5, 3.0))
                continue
            return result
        return last
    finally:
        try:
            await asyncio.shield(pool.release(browser, ctx))
        except Exception:
            pass


async def _solve_on_page(
    page: Page,
    target_url: str = TARGET_URL,
    verbose: bool = True,
    profile: Optional[SiteProfile] = None,
    appid: Optional[str] = None,
    stable_fp: str = "",
) -> Optional[dict]:
    """基于页面执行一次求解。

    策略:
      1. 导航到目标页（绝句或腾讯云产品页等）
      2. 如果是朱雀 AI 检测页 -> 设置 fp -> 直接 tc.show() -> 等待回调
      3. 回调若是 direct pass (ret=0, ticket) -> 直接返回
      4. 回调若触发滑块 (bgUrl != "none" + slider) -> 走视觉求解流程
      5. 其他页 -> 走旧 trigger + wait_frame + drag 流程
    """
    t0 = time.time()
    result = None
    try:
        profile = profile or profile_for_url(target_url)
        appid = appid or os.getenv("TCAPTCHA_APPID") or profile.appid or TARGET_APPID
        if verbose:
            print(f"[+] nav profile={profile.name} appid={appid or '-'}", flush=True)
        await _consume_playwright_on_cancel(
            page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
        )

        # ------------------------------------------------------------------
        # Branch: 朱雀 AI 检测页 — 优先走 native appid 获取 ticket。
        # ------------------------------------------------------------------
        is_zhuque = profile.flow == "matrix_ai_detect" or "matrix.tencent.com/ai-detect" in target_url
        if is_zhuque:
            await page.wait_for_selector("textarea.el-textarea__inner", timeout=45000)
            await page.wait_for_function("()=>window.TencentCaptcha", timeout=45000)
            # 确保 fp 存在；真实浏览器会长期复用 localStorage.fp。
            fp = stable_fp or _stable_fp()
            await page.evaluate("""(fp)=>{
                if(fp) localStorage.setItem("fp", fp);
                if(!localStorage.getItem("fp")){
                    const f = Array.from({length:32},()=>"0123456789abcdef"[Math.floor(Math.random()*16)]).join("");
                    localStorage.setItem("fp", f);
                }
            }""", fp)

            # 填充文本触发页面初始化逻辑。这里不提交 Matrix 检测，只证明该站点 appid 的 ticket 获取。
            ta = await page.query_selector("textarea.el-textarea__inner")
            if ta:
                await ta.fill("A" * 360)
                await asyncio.sleep(0.3)
                await page.evaluate("""()=>{
                    const ta = document.querySelector('textarea.el-textarea__inner');
                    if(ta) ta.dispatchEvent(new Event('input', {bubbles: true}));
                }""")
                await asyncio.sleep(0.3)

            if not appid:
                raise RuntimeError("matrix profile requires appid")
            # 直接调用 tc.show() 获取 ticket；此站正常多为 invisible/direct-pass。
            if verbose:
                print("[+] invoking matrix tc.show()...", flush=True)
            tc_res = await page.evaluate("""({appid})=>{
                return new Promise((resolve) => {
                    const opts = window.__TencentCaptchaOpts__ || {ready(){}, needFeedBack:true, loading:false};
                    const tc = new window.TencentCaptcha(appid, function(res){
                        resolve(res);
                    }, opts);
                    tc.show();
                    setTimeout(()=>resolve({ret: -1, error: "tc_show_timeout"}), 45000);
                });
            }""", {"appid": appid})
            if verbose:
                print(f"    tc callback ret={tc_res.get('ret')} ticket_len={len(tc_res.get('ticket',''))}", flush=True)

            ret = tc_res.get("ret")
            ticket = tc_res.get("ticket")
            randstr = tc_res.get("randstr", "")

            # direct pass (ret=0 && ticket) — 无视觉题，直接返回
            if ret == 0 and ticket:
                elapsed = int((time.time() - t0) * 1000)
                if verbose:
                    print(f"[+] direct pass (no slider)", flush=True)
                return {
                    "ok": True,
                    "profile": profile.name,
                    "target_url": target_url,
                    "appid": appid,
                    "fp": _public_fp_marker(stable_fp),
                    "ticket": ticket,
                    "randstr": randstr,
                    "elapsed_ms": elapsed,
                    "method": "matrix_direct_pass" if is_zhuque else "direct_pass",
                }

            # 有 ticket 但 ret!=0 也不是成功，继续等待iframe里的实际挑战
            # tc.show() 弹出 iframe#tcaptcha_iframe_dy，等待实际加载
            await asyncio.sleep(3)

        # ------------------------------------------------------------------
        # Common path: 等待 iframe + 视觉求解（兼容所有页面）
        # ------------------------------------------------------------------
        if not is_zhuque:
            await _click_trigger(page)

        verify_state = _install_verify_capture(page)
        target = await _wait_frame(page)

        for attempt in range(1, MAX_ATTEMPTS + 1):
            verify_state["res"] = None
            if verbose:
                print(f"[+] attempt {attempt}", flush=True)
            await _inject_xhr_hook(target.frame)
            bg_url = await _bg_url(target.frame)
            bg_bytes = await _fetch_bg_bytes(target.frame, bg_url)
            gap_x, conf, method = detect_gap(bg_bytes)
            if conf < 0.55:
                raise RuntimeError("low conf")

            geo = await _runtime_geometry(target, bg_bytes, gap_x)
            if verbose:
                print(
                    "    "
                    f"gap={gap_x} conf={conf:.3f} method={method} "
                    f"rate={geo.rate:.6f} init_x={geo.init_x:.2f}",
                    flush=True,
                )

            await _drag(page, geo)
            await asyncio.sleep(2.5)
            res = await _read_verify(target.frame, verify_state)
            if not res:
                raise RuntimeError("no verify")

            code = str(res.get("errorCode"))
            if verbose:
                print(f"    code={code}", flush=True)
            if code == "0" and res.get("ticket"):
                elapsed = int((time.time() - t0) * 1000)
                result = {
                    "ok": True,
                    "profile": profile.name,
                    "target_url": target_url,
                    "appid": appid,
                    "fp": _public_fp_marker(stable_fp),
                    "ticket": res["ticket"],
                    "randstr": res.get("randstr", ""),
                    "gap_x": gap_x,
                    "conf": conf,
                    "method": method,
                    "rate": geo.rate,
                    "init_x": geo.init_x,
                    "elapsed_ms": elapsed,
                }
                if verbose:
                    print("[+] PASS", flush=True)
                break

            result = {"error_code": code, "raw": res}
            if attempt < MAX_ATTEMPTS and code in {"50", "12", "9", "51"}:
                try:
                    await target.frame.evaluate(
                        "()=>{const r=document.querySelector('%s'); if(r) r.click();}" % RELOAD_SELECTOR
                    )
                except Exception:
                    pass
                await asyncio.sleep(4)
                target = await _wait_frame(page)
                continue
            break

    except Exception as e:
        if verbose:
            print(f"[!] exception: {e}", flush=True)
        msg = str(e)
        code = "no_frame" if "no stable captcha frame" in msg else "nav_error"
        result = {
            "error_code": code,
            "error": msg,
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
    return result


async def benchmark(pool: BrowserPool, n: int = 10):
    ok = 0
    times = []
    details = []
    for i in range(n):
        print(f"\n===== Run {i+1}/{n} =====")
        t0 = time.time()
        ret = await solve_one(pool, verbose=True)
        print("Result:", json.dumps(ret, ensure_ascii=False, indent=2) if ret else "None")
        if ret and ret.get("ticket"):
            ok += 1
            times.append(ret["elapsed_ms"])
            details.append(
                {
                    "run": i + 1,
                    "ok": True,
                    "elapsed_ms": ret.get("elapsed_ms"),
                    "gap_x": ret.get("gap_x"),
                    "conf": ret.get("conf"),
                    "method": ret.get("method"),
                    "rate": ret.get("rate"),
                    "init_x": ret.get("init_x"),
                    "ticket_len": len(ret.get("ticket") or ""),
                }
            )
        else:
            details.append(
                {
                    "run": i + 1,
                    "ok": False,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                    "error_code": ret.get("error_code") if ret else None,
                    "error": ret.get("error") if ret else None,
                    "raw": ret.get("raw") if ret else None,
                }
            )
        await asyncio.sleep(1)

    avg = sum(times) / len(times) if times else 0
    summary = {
        "total": n,
        "ok": ok,
        "fail": n - ok,
        "success_rate": round(ok / n * 100, 1) if n else 0.0,
        "avg_ms": round(avg, 0),
        "details": details,
    }
    print(f"\n===== Summary: {ok}/{n} passed ({ok/n*100:.1f}%) avg={avg:.0f}ms =====")
    bench_json = os.getenv("TCAPTCHA_BENCH_JSON")
    if bench_json:
        Path(bench_json).parent.mkdir(parents=True, exist_ok=True)
        Path(bench_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] wrote {bench_json}")


async def main():
    profile = get_profile(os.getenv("TCAPTCHA_PROFILE", "cloud_product"))
    locale = os.getenv("TCAPTCHA_LOCALE", profile.default_locale)
    pool = BrowserPool(
        size=int(os.getenv("TCAPTCHA_POOL_SIZE", "2")),
        max_uses=int(os.getenv("TCAPTCHA_BROWSER_MAX_USES", "2")),
        headless=os.getenv("TCAPTCHA_HEADLESS", "1") != "0",
        proxy=_proxy_from_env(),
        locale=locale,
        timezone_id=os.getenv("TCAPTCHA_TIMEZONE", "America/New_York" if profile.name == "matrix_ai_detect" else "Asia/Shanghai"),
    )
    await pool.start()
    try:
        await benchmark(pool, n=int(os.getenv("TCAPTCHA_BENCH_N", "10")))
    finally:
        await pool.stop()


if __name__ == "__main__":
    asyncio.run(main())
