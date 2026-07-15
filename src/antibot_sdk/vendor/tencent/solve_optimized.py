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
MAX_ATTEMPTS = int(os.getenv("TCAPTCHA_MAX_ATTEMPTS", "3"))
PAGE_RETRIES = int(os.getenv("TCAPTCHA_PAGE_RETRIES", "2"))
FRAME_WAIT_SEC = float(os.getenv("TCAPTCHA_FRAME_WAIT_SEC", "25"))

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

    # --- 腾讯云产品页 / local harness 等 ---
    # Official product page binds public demos to stable element ids (see captcha.js):
    #   #captcha_click -> 199999861 (slide)
    #   #vtt_click     -> 199999726
    #   #text_click    -> 199999888
    #   #noFeel_click  -> 199999399
    # Prefer these ids first so we never click marketing CTAs that also say 立即体验.
    for selector in (
        "#captcha_click",
        "#vtt_click",
        "button#captcha_click",
        "a#captcha_click",
        "text=滑动拼图验证",
        "text=点击验证",
    ):
        try:
            loc = page.locator(selector).first
            if await loc.count():
                await loc.scroll_into_view_if_needed(timeout=2500)
                await loc.click(timeout=3000, force=True)
                await asyncio.sleep(3.5)
                return True
        except Exception:
            pass

    for _ in range(5):
        await asyncio.sleep(1.2)
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
            // Stable ids first.
            for (const id of ['captcha_click', 'vtt_click']) {
                const el = document.getElementById(id);
                if (visible(el) && clickEl(el)) return true;
            }
            const xps = [
                "//text()[contains(.,'滑动拼图验证')]/following::*[contains(text(),'立即体验') or self::button or self::a][1]",
                "//*[contains(text(),'滑动拼图验证')]/following::*[contains(text(),'立即体验')][1]",
                "//*[contains(text(),'滑动拼图')]/following::*[contains(text(),'立即体验')][1]",
                "//*[contains(text(),'点击验证')]",
                "//*[contains(@class,'captcha-box')]//*[contains(text(),'立即体验')]",
            ];
            for (const xp of xps) {
                const r = document.evaluate(xp, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                const el = r.singleNodeValue;
                if (visible(el) && clickEl(el)) return true;
            }
            // Fallback: short CTAs only, avoid nav mega-menus.
            const nodes = Array.from(document.querySelectorAll('button,a,div,span')).filter(visible);
            for (const k of ['点击验证', '开始验证', '滑动拼图验证']) {
                const el = nodes.find(e => {
                  const t = (e.innerText || '').trim();
                  return t === k || (t.includes(k) && t.length <= 16);
                });
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

    支持滑动拼图（bg+slider）与文字点选（bg + 请依次点击 instruction，无 slider）。
    """
    async def ready(frame: Frame) -> bool:
        try:
            return bool(
                await frame.evaluate(
                    """(sels)=>{
                        const visible = (e, minH) => {
                            if(!e) return false;
                            const r = e.getBoundingClientRect();
                            const cs = getComputedStyle(e);
                            // Some templates briefly report height=0 while the
                            // bg image is decoding; accept width-first readiness
                            // and only require a small min height.
                            return r.width > 20 && r.height >= minH &&
                                   cs.display !== 'none' && cs.visibility !== 'hidden' &&
                                   Number(cs.opacity || '1') > 0.05;
                        };
                        const bg = document.querySelector(sels.bg);
                        const slider = document.querySelector(sels.slider);
                        const text = (document.body && document.body.innerText) || '';
                        const isWordClick = /请依次点击/.test(text);
                        if (isWordClick) {
                          return visible(bg, 1);
                        }
                        // Slider can lag one frame behind bg; require bg strongly,
                        // slider more loosely.
                        // Word-click templates share drag_ele.html and may briefly
                        // show slider placeholder text. Treat bg-ready as enough;
                        // solver will wait for real instruction afterwards.
                        if (visible(bg, 1) && !slider) return true;
                        return visible(bg, 1) && visible(slider, 1);
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


def _parse_word_click_targets(instruction: str) -> list[str]:
    """Extract ordered CJK chars from '请依次点击：X Y Z'."""
    import re

    text = instruction or ""
    m = re.search(r"请依次点击[:：]\s*(.+)", text)
    payload = m.group(1) if m else text
    # Stop at common trailing UI noise.
    payload = payload.split("AI生成", 1)[0].split("确定", 1)[0]
    return re.findall(r"[\u4e00-\u9fff]", payload)


async def _challenge_kind(frame: Frame) -> str:
    """Return 'word_click' | 'slider' | 'unknown'."""
    try:
        return str(
            await frame.evaluate(
                """()=>{
                    // Prefer stable instruction nodes over body text (body races during load).
                    const instr = document.querySelector('#instructionText, #instruction, .tc-instruction-text');
                    const instrText = instr ? ((instr.innerText || instr.textContent || '').trim()) : '';
                    if (/请依次点击/.test(instrText)) return 'word_click';
                    const text = (document.body && document.body.innerText) || '';
                    if (/请依次点击/.test(text) && document.querySelector('.tc-bg-img')) return 'word_click';
                    const slider = document.querySelector(
                      '.tc-slider-normal, .tc-drag-thumb, .tencent-captcha-dy__slider-block, .tencent-captcha-dy__slider-block--normal'
                    );
                    if (slider) return 'slider';
                    // Fallback: if only bg + confirm button (no slider), treat as word_click shell.
                    const bg = document.querySelector('.tc-bg-img, .tencent-captcha-dy__verify-bg-img');
                    const hasConfirm = Array.from(document.querySelectorAll('div,button,span'))
                      .some(e => ((e.innerText || '').trim() === '确定'));
                    if (bg && hasConfirm && !slider) return 'word_click';
                    return 'unknown';
                }"""
            )
        )
    except Exception:
        return "unknown"


async def _resolve_captcha_frame(page: Page) -> CaptchaFrame | None:
    """Re-resolve the live captcha frame (iframe can navigate qcloud → gtimg)."""
    # Prefer known iframe element for stable page-coordinate offsets.
    for sel in ("iframe#tcaptcha_iframe_dy", "iframe[src*='template']", "iframe[src*='tcaptcha']", "iframe[src*='drag_ele']"):
        try:
            el = await page.query_selector(sel)
            if not el:
                continue
            frame = await el.content_frame()
            if frame:
                return CaptchaFrame(frame=frame, iframe_element=el)
        except Exception:
            continue
    for frame in page.frames:
        if frame is page.main_frame:
            continue
        u = frame.url or ""
        if any(x in u for x in ("template", "tcaptcha", "drag_ele", "captcha.gtimg", "captcha.qcloud")):
            owner = None
            try:
                owner = await frame.frame_element()
            except Exception:
                owner = None
            return CaptchaFrame(frame=frame, iframe_element=owner)
    return None


async def _word_click_instruction(page: Page, frame: Frame | None = None) -> str:
    # Shared drag_ele template first paints a slider placeholder instruction
    # ("拖动下方滑块完成拼图") for ~8-12s before the real word-click prompt arrives.
    # Prefer Playwright frame locators (more resilient than evaluate on detaching docs).
    deadline = time.time() + 25.0
    while time.time() < deadline:
        try:
            # Always re-bind: iframe host/src can switch mid-load.
            target = await _resolve_captcha_frame(page)
            fr = target.frame if target else frame
            if fr is None:
                await asyncio.sleep(0.3)
                continue
            # 1) locator path
            for sel in ("#instructionText", "#instruction", ".tc-instruction-text", ".tc-title"):
                try:
                    loc = fr.locator(sel).first
                    if await loc.count():
                        text = (await loc.inner_text(timeout=800)).strip()
                        if "请依次点击" in text:
                            return text
                except Exception:
                    pass
            # 2) evaluate fallback
            try:
                text = str(
                    await fr.evaluate(
                        """()=>{
                            const nodes = [
                              document.querySelector('#instructionText'),
                              document.querySelector('#instruction'),
                              document.querySelector('.tc-instruction-text'),
                              document.querySelector('.tc-title'),
                            ].filter(Boolean);
                            for (const n of nodes) {
                              const t = (n.innerText || n.textContent || '').trim();
                              if (/请依次点击/.test(t)) return t;
                            }
                            const body = (document.body && document.body.innerText) || '';
                            const m = body.match(/请依次点击[:：][^\n]*/);
                            return m ? m[0].trim() : '';
                        }"""
                    )
                    or ""
                )
                if text:
                    return text
            except Exception:
                pass
        except Exception:
            pass
        await asyncio.sleep(0.35)
    return ""


async def _click_word_targets(
    page: Page,
    target: CaptchaFrame,
    bg_bytes: bytes,
    targets: list[str],
    *,
    verbose: bool = False,
) -> dict:
    """Locate chars via crack_tcaptcha siamese OCR and click them in order."""
    from crack_tcaptcha.solvers.word_ocr import locate_chars_by_siamese

    points = await asyncio.to_thread(locate_chars_by_siamese, bg_bytes, targets)
    raw_w = _image_width(bg_bytes)
    with Image.open(io.BytesIO(bg_bytes)) as im:
        raw_h = int(im.height)

    # Playwright bounding_box() is already in page coordinates (includes iframe offset).
    bg_loc = target.frame.locator(".tc-bg-img, .tencent-captcha-dy__verify-bg-img").first
    box = await bg_loc.bounding_box()
    if not box or box.get("width", 0) < 20 or box.get("height", 0) < 20:
        raise RuntimeError("word_click: missing bg geometry")
    sx = float(box["width"]) / max(1, raw_w)
    sy = float(box["height"]) / max(1, raw_h)

    clicks: list[dict] = []
    for idx, (px, py) in enumerate(points):
        cx = float(box["x"]) + float(px) * sx + random.uniform(-1.0, 1.0)
        cy = float(box["y"]) + float(py) * sy + random.uniform(-1.0, 1.0)
        if verbose:
            print(f"    click[{idx}] raw=({px},{py}) page=({cx:.1f},{cy:.1f})", flush=True)
        await page.mouse.move(cx, cy)
        await asyncio.sleep(random.uniform(0.06, 0.16))
        await page.mouse.down()
        await asyncio.sleep(random.uniform(0.03, 0.08))
        await page.mouse.up()
        clicks.append({"raw": [int(px), int(py)], "page": [round(cx, 1), round(cy, 1)]})
        await asyncio.sleep(random.uniform(0.28, 0.6))

    # Confirm button (文字点选 needs 确定). Prefer dedicated action nodes.
    confirm_clicked = False
    for sel in (
        "#tcStatus .tc-status--right",
        ".tc-status--right",
        "text=确定",
        "#verifyBtn",
        ".tc-action--confirm",
    ):
        try:
            loc = target.frame.locator(sel).first
            if await loc.count():
                # Prefer clicking the visible 确定 text node when using broad containers.
                if sel in {"#tcStatus .tc-status--right", ".tc-status--right"}:
                    try:
                        await loc.locator("text=确定").first.click(timeout=1500, force=True)
                    except Exception:
                        await loc.click(timeout=1500, force=True)
                else:
                    await loc.click(timeout=1500, force=True)
                cbox = await loc.bounding_box()
                clicks.append({"confirm_selector": sel, "box": cbox})
                confirm_clicked = True
                break
        except Exception:
            continue
    if not confirm_clicked:
        # Last resort: page-level mouse click from frame evaluate rect + iframe offset.
        confirm = await target.frame.evaluate(
            """()=>{
                const nodes = Array.from(document.querySelectorAll('div,button,span,a'));
                const el = nodes.find(e => ((e.innerText || '').trim() === '确定' || ((e.innerText || '').includes('确定') && (e.innerText || '').trim().length <= 4)));
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return {x:r.x + r.width/2, y:r.y + r.height/2, w:r.width, h:r.height};
            }"""
        )
        if confirm and confirm.get("w", 0) > 5:
            off_x, off_y = await target.offset()
            cx = off_x + float(confirm["x"]) + random.uniform(-0.8, 0.8)
            cy = off_y + float(confirm["y"]) + random.uniform(-0.8, 0.8)
            await page.mouse.click(cx, cy)
            clicks.append({"confirm": [round(cx, 1), round(cy, 1)]})
            confirm_clicked = True
    if not confirm_clicked and verbose:
        print("    warn: confirm button not clicked", flush=True)
    return {
        "targets": targets,
        "points": [[int(a), int(b)] for a, b in points],
        "scale": {"sx": sx, "sy": sy, "raw_w": raw_w, "raw_h": raw_h, "box": box},
        "clicks": clicks,
        "method": "word_siamese",
        "confirm_clicked": confirm_clicked,
    }


async def _drag(page: Page, geo: RuntimeGeometry) -> None:
    # Keep overshoot tiny: Tencent maps final CSS position; large overshoot hurts rate.
    overshoot = random.uniform(0.4, 1.8)
    end_x = geo.end_x + overshoot
    traj = generate_slide_trajectory(
        int(geo.start_x),
        int(geo.start_y),
        int(end_x),
        int(geo.end_y + random.uniform(-0.8, 0.8)),
        duration_ms=random.randint(1000, 1800),
        interval_ms=random.randint(22, 34),
    )
    await page.mouse.move(
        geo.start_x + random.uniform(-1.0, 1.0),
        geo.start_y + random.uniform(-0.8, 0.8),
    )
    await asyncio.sleep(random.uniform(0.10, 0.28))
    await page.mouse.down()
    await asyncio.sleep(random.uniform(0.03, 0.10))
    prev_t = 0
    for idx, pt in enumerate(traj.points):
        delay_ms = pt.t - prev_t
        if delay_ms > 0:
            # Occasional micro-pauses mid-drag.
            if 0.35 < (idx / max(1, len(traj.points))) < 0.75 and random.random() < 0.06:
                delay_ms += random.randint(12, 40)
            await asyncio.sleep(delay_ms / 1000.0)
        y = pt.y + random.uniform(-0.25, 0.25)
        await page.mouse.move(pt.x, y)
        prev_t = pt.t
    # Settle back to exact target after tiny overshoot.
    await page.mouse.move(
        geo.end_x + random.uniform(-0.25, 0.25),
        geo.end_y + random.uniform(-0.30, 0.30),
    )
    await asyncio.sleep(random.uniform(0.08, 0.20))
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
            # Reload-worthy reject codes also benefit from a full page restart.
            if code in {"no_frame", "nav_error", "9", "50", "12", "51"} and page_try <= PAGE_RETRIES:
                if verbose:
                    print(f"[!] page retry {page_try}/{PAGE_RETRIES}: {code}", flush=True)
                await asyncio.sleep(random.uniform(1.5, 3.5))
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
        async def _show_with_appid() -> bool:
            if not appid:
                return False
            try:
                await page.wait_for_function(
                    "() => typeof window.TencentCaptcha === 'function'",
                    timeout=8000,
                )
                return bool(
                    await page.evaluate(
                        """(appid) => {
                            try {
                              // Destroy any previous popup remnants first.
                              try {
                                const old = document.querySelector('#tcaptcha_iframe_dy, iframe[id*="tcaptcha"]');
                                if (old && old.parentElement) old.parentElement.remove();
                              } catch (e) {}
                              const cap = new window.TencentCaptcha(String(appid), function(){}, {});
                              cap.show();
                              return true;
                            } catch (e) { return false; }
                        }""",
                        str(appid),
                    )
                )
            except Exception:
                return False

        if not is_zhuque:
            # Prefer explicit public-demo show() when appid is known and SDK is present.
            # This avoids product-page CTA fragility and works for local harness.
            shown = await _show_with_appid()
            if not shown:
                await _click_trigger(page)
            else:
                await asyncio.sleep(1.2)

        verify_state = _install_verify_capture(page)
        try:
            target = await _wait_frame(page)
        except RuntimeError:
            # One more show/click cycle before failing the page attempt.
            if not is_zhuque:
                if not await _show_with_appid():
                    await _click_trigger(page)
                else:
                    await asyncio.sleep(1.2)
            target = await _wait_frame(page)

        for attempt in range(1, MAX_ATTEMPTS + 1):
            verify_state["res"] = None
            if verbose:
                print(f"[+] attempt {attempt}", flush=True)
            await _inject_xhr_hook(target.frame)
            kind = await _challenge_kind(target.frame)
            bg_url = await _bg_url(target.frame)
            bg_bytes = await _fetch_bg_bytes(target.frame, bg_url)

            meta: dict = {"kind": kind}
            if kind == "word_click":
                # Wait for bg layout to settle (height can be 0 for a few frames).
                try:
                    await target.frame.wait_for_function(
                        """() => {
                          const bg = document.querySelector('.tc-bg-img, .tencent-captcha-dy__verify-bg-img');
                          if (!bg) return false;
                          const r = bg.getBoundingClientRect();
                          return r.width > 20 && r.height > 20;
                        }""",
                        timeout=8000,
                    )
                except Exception:
                    pass
                instruction = await _word_click_instruction(page, target.frame)
                # iframe may have navigated while waiting for instruction; rebind.
                rebound = await _resolve_captcha_frame(page)
                if rebound is not None:
                    target = rebound
                targets = _parse_word_click_targets(instruction)
                if not targets:
                    # Re-check kind; some appids briefly render generic shell text.
                    kind = await _challenge_kind(target.frame)
                    if kind != "word_click":
                        # fall through to slider path below by reassigning
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
                        rate = geo.rate
                        init_x = geo.init_x
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
                                "rate": rate,
                                "init_x": init_x,
                                "elapsed_ms": elapsed,
                                "captcha_kind": kind,
                            }
                            if verbose:
                                print("[+] PASS", flush=True)
                            break
                        result = {"error_code": code, "raw": res, "captcha_kind": kind}
                        if attempt < MAX_ATTEMPTS and code in {"50", "12", "9", "51", "52", "1", "21", "100"}:
                            await asyncio.sleep(random.uniform(2.0, 3.5))
                            target = await _wait_frame(page)
                            continue
                        break
                    raise RuntimeError(f"word_click: empty targets from {instruction!r}")
                # refresh bg after layout settle
                bg_url = await _bg_url(target.frame)
                bg_bytes = await _fetch_bg_bytes(target.frame, bg_url)
                if verbose:
                    print(f"    word_click targets={targets} instr={instruction!r}", flush=True)
                click_info = await _click_word_targets(
                    page, target, bg_bytes, targets, verbose=verbose
                )
                meta.update(click_info)
                method = click_info.get("method") or "word_siamese"
                gap_x = None
                conf = None
                rate = None
                init_x = None
            else:
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
                rate = geo.rate
                init_x = geo.init_x

            await asyncio.sleep(2.5 if kind != "word_click" else 2.0)
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
                    "rate": rate,
                    "init_x": init_x,
                    "elapsed_ms": elapsed,
                    "captcha_kind": kind,
                    "meta": meta,
                }
                if verbose:
                    print("[+] PASS", flush=True)
                break

            result = {"error_code": code, "raw": res, "captcha_kind": kind, "meta": meta}
            # Retry more aggressively on common reject/refresh codes.
            if attempt < MAX_ATTEMPTS and code in {"50", "12", "9", "51", "52", "1", "21", "100"}:
                reloaded = False
                try:
                    reloaded = bool(
                        await target.frame.evaluate(
                            "()=>{const r=document.querySelector('%s'); if(r){r.click(); return true;} return false;}"
                            % RELOAD_SELECTOR
                        )
                    )
                except Exception:
                    reloaded = False
                if not reloaded:
                    # Some templates destroy the frame after reject; re-trigger page.
                    try:
                        if appid:
                            await page.evaluate(
                                """(appid)=>{
                                    try {
                                      const old=document.querySelector('#tcaptcha_iframe_dy, iframe[id*="tcaptcha"]');
                                      if(old && old.parentElement) old.parentElement.remove();
                                    } catch(e) {}
                                    if (window.TencentCaptcha) {
                                      new window.TencentCaptcha(String(appid), function(){}, {}).show();
                                      return true;
                                    }
                                    return false;
                                }""",
                                str(appid),
                            )
                        else:
                            await _click_trigger(page)
                    except Exception:
                        pass
                await asyncio.sleep(random.uniform(2.2, 4.2))
                try:
                    target = await _wait_frame(page)
                except Exception:
                    # Force page-level retry outside attempt loop.
                    result = {"error_code": code, "raw": res, "error": "frame_lost_after_reject"}
                    break
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
