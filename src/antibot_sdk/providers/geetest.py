from __future__ import annotations

import asyncio
import json
import math
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cv2
import numpy as np

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy


GEETEST_SUCCESS_KEYS = ("lot_number", "captcha_output", "pass_token", "gen_time")

DEFAULT_TRIGGER_SELECTORS = (
    ".geetest_btn",
    ".geetest_box",
    ".geetest_radar_btn",
    ".geetest_holder",
    ".geetest_panel",
    ".gt4-public-click",
    "[class*='geetest']",
    "[id*='geetest']",
)


GEETEST_HOOK_JS = r"""
(() => {
  if (window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.installed) return;
  const safe = (value, depth = 0) => {
    if (depth > 4) return '[depth]';
    if (value === null || value === undefined) return value;
    const t = typeof value;
    if (t === 'string' || t === 'number' || t === 'boolean') return value;
    if (t === 'function') return `[Function:${value.name || 'anonymous'}]`;
    if (value instanceof Element) {
      const r = value.getBoundingClientRect();
      return { tag: value.tagName, id: value.id || '', className: String(value.className || ''), rect: { x: r.x, y: r.y, width: r.width, height: r.height } };
    }
    if (Array.isArray(value)) return value.slice(0, 30).map(x => safe(x, depth + 1));
    if (t === 'object') {
      const out = {};
      for (const k of Object.keys(value).slice(0, 80)) {
        try { out[k] = safe(value[k], depth + 1); } catch (e) { out[k] = `[throws:${e && e.message}]`; }
      }
      return out;
    }
    return String(value);
  };
  const state = {
    installed: true,
    at: new Date().toISOString(),
    configs: [],
    events: [],
    validates: [],
    errors: [],
    methodCalls: [],
    instances: [],
    _instances: [],
    pushEvent(type, detail) { this.events.push({ at: Date.now(), type, detail: safe(detail) }); },
    pushValidate(source, instance) {
      try {
        if (!instance || typeof instance.getValidate !== 'function') return null;
        const value = instance.getValidate();
        this.validates.push({ at: Date.now(), source, value: safe(value) });
        return value;
      } catch (e) {
        this.errors.push({ at: Date.now(), source, message: e && e.message });
        return null;
      }
    },
    collectValidates(source = 'collect') {
      const ret = [];
      for (const inst of this._instances) ret.push(this.pushValidate(source, inst));
      return ret;
    },
    snapshot() {
      this.collectValidates('snapshot');
      return {
        installed: true,
        at: this.at,
        configs: this.configs.slice(-10),
        events: this.events.slice(-80),
        validates: this.validates.slice(-20),
        errors: this.errors.slice(-20),
        methodCalls: this.methodCalls.slice(-120),
        instances: this.instances.slice(-10),
      };
    },
    showAll() {
      const ret = [];
      for (const inst of this._instances) {
        try {
          if (inst && typeof inst.showCaptcha === 'function') {
            inst.showCaptcha();
            ret.push({ ok: true, method: 'showCaptcha' });
          }
        } catch (e) { ret.push({ ok: false, method: 'showCaptcha', error: e && e.message }); }
      }
      return ret;
    },
  };
  window.__ANTIBOT_GEETEST = state;

  const wrapMethod = (obj, name, instanceId) => {
    if (!obj || typeof obj[name] !== 'function' || obj[name].__antibotWrapped) return;
    const original = obj[name];
    const wrapped = function(...args) {
      state.methodCalls.push({ at: Date.now(), instanceId, method: name, args: safe(args) });
      if (name === 'onSuccess' && typeof args[0] === 'function') {
        const cb = args[0];
        args[0] = function(...cbArgs) {
          state.pushEvent('onSuccess', cbArgs);
          state.pushValidate('onSuccess', obj);
          return cb.apply(this, cbArgs);
        };
      } else if (name === 'onReady' && typeof args[0] === 'function') {
        const cb = args[0];
        args[0] = function(...cbArgs) {
          state.pushEvent('onReady', cbArgs);
          return cb.apply(this, cbArgs);
        };
      } else if (name === 'onNextReady' && typeof args[0] === 'function') {
        const cb = args[0];
        args[0] = function(...cbArgs) {
          state.pushEvent('onNextReady', cbArgs);
          return cb.apply(this, cbArgs);
        };
      } else if (['onError', 'onFail', 'onClose'].includes(name) && typeof args[0] === 'function') {
        const cb = args[0];
        args[0] = function(...cbArgs) {
          state.pushEvent(name, cbArgs);
          return cb.apply(this, cbArgs);
        };
      }
      const ret = original.apply(this, args);
      if (name === 'getValidate') {
        state.validates.push({ at: Date.now(), source: 'getValidate-call', value: safe(ret) });
      }
      return ret;
    };
    wrapped.__antibotWrapped = true;
    obj[name] = wrapped;
  };

  const wrapCaptchaObj = (obj, config) => {
    if (!obj || obj.__antibotWrapped) return obj;
    const instanceId = state.instances.length + 1;
    const methods = ['appendTo', 'bindForm', 'showCaptcha', 'verify', 'reset', 'destroy', 'getValidate', 'onReady', 'onNextReady', 'onSuccess', 'onError', 'onFail', 'onClose'];
    for (const name of methods) wrapMethod(obj, name, instanceId);
    try { obj.__antibotWrapped = true; } catch {}
    state._instances.push(obj);
    state.instances.push({ id: instanceId, config: safe(config), methods: methods.filter(name => typeof obj[name] === 'function') });
    state.pushEvent('instance-wrapped', { instanceId });
    return obj;
  };

  const wrapInit = (fn) => {
    if (typeof fn !== 'function' || fn.__antibotWrapped) return fn;
    const wrapped = function(config, callback, ...rest) {
      state.configs.push({ at: Date.now(), config: safe(config) });
      state.pushEvent('initGeetest4-call', config);
      const wrappedCallback = function(captchaObj, ...cbRest) {
        state.pushEvent('initGeetest4-callback', { hasCaptchaObj: !!captchaObj });
        const wrappedObj = wrapCaptchaObj(captchaObj, config);
        if (typeof callback === 'function') return callback.call(this, wrappedObj, ...cbRest);
        return undefined;
      };
      return fn.call(this, config, wrappedCallback, ...rest);
    };
    wrapped.__antibotWrapped = true;
    return wrapped;
  };

  let current = window.initGeetest4;
  try {
    Object.defineProperty(window, 'initGeetest4', {
      configurable: true,
      enumerable: true,
      get() { return current; },
      set(v) {
        state.pushEvent('initGeetest4-set', { type: typeof v });
        current = wrapInit(v);
      },
    });
    if (current) current = wrapInit(current);
  } catch (e) {
    state.errors.push({ at: Date.now(), source: 'defineProperty', message: e && e.message });
    if (typeof window.initGeetest4 === 'function') window.initGeetest4 = wrapInit(window.initGeetest4);
  }
})();
"""


def is_geetest_success_payload(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return all(bool(value.get(k)) for k in GEETEST_SUCCESS_KEYS)


def latest_geetest_success(state: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None
    for item in reversed(state.get("validates") or []):
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if is_geetest_success_payload(value):
            return value
    return None


def _headless(value: bool | str | None) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return value.lower() not in {"0", "false", "headed", "no"}


def _interesting_url(url: str) -> bool:
    u = url.lower()
    return any(x in u for x in ("geetest", "gcaptcha4", "/gt4/", "captcha_v4", "captcha4"))


def _css_url(value: str | None) -> str:
    if not value:
        return ""
    m = re.search(r"url\([\"']?(.*?)[\"']?\)", value)
    return m.group(1) if m else ""


def detect_geetest_slide_gap(bg_bytes: bytes, slice_bytes: bytes) -> dict[str, Any]:
    """Detect GeeTest v4 slide distance from background and slice image bytes.

    Returns the slider element displacement in source-image pixels. GeeTest's
    slice PNG normally has transparent padding; template matching is done on
    the non-transparent part and then converted back to full-slice origin.
    """

    bg_arr = np.frombuffer(bg_bytes, dtype=np.uint8)
    slice_arr = np.frombuffer(slice_bytes, dtype=np.uint8)
    bg = cv2.imdecode(bg_arr, cv2.IMREAD_COLOR)
    piece = cv2.imdecode(slice_arr, cv2.IMREAD_UNCHANGED)
    if bg is None or piece is None:
        raise ValueError("failed to decode geetest slide images")
    if piece.ndim != 3 or piece.shape[2] < 4:
        raise ValueError("geetest slice image has no alpha channel")

    rgb = piece[:, :, :3]
    alpha = piece[:, :, 3]
    mask = ((alpha > 30).astype(np.uint8)) * 255
    ys, xs = np.where(mask > 0)
    if len(xs) == 0 or len(ys) == 0:
        raise ValueError("geetest slice alpha mask is empty")

    trim_x0, trim_x1 = int(xs.min()), int(xs.max()) + 1
    trim_y0, trim_y1 = int(ys.min()), int(ys.max()) + 1
    template = rgb[trim_y0:trim_y1, trim_x0:trim_x1]
    template_mask = mask[trim_y0:trim_y1, trim_x0:trim_x1]

    res = cv2.matchTemplate(bg, template, cv2.TM_CCORR_NORMED, mask=template_mask)
    _min_val, max_val, _min_loc, max_loc = cv2.minMaxLoc(res)
    raw_x, raw_y = int(max_loc[0]), int(max_loc[1])
    distance_x = max(0, raw_x - trim_x0)
    distance_y = max(0, raw_y - trim_y0)
    return {
        "distance_x": distance_x,
        "distance_y": distance_y,
        "match_x": raw_x,
        "match_y": raw_y,
        "score": float(max_val),
        "bg_size": {"width": int(bg.shape[1]), "height": int(bg.shape[0])},
        "slice_size": {"width": int(piece.shape[1]), "height": int(piece.shape[0])},
        "trim": {
            "x0": trim_x0,
            "y0": trim_y0,
            "x1": trim_x1,
            "y1": trim_y1,
        },
    }


class GeeTestCaptchaSolver:
    """GeeTest v4 browser observer/collector.

    This provider is a first-stage SDK integration: it hooks the official
    initGeetest4 flow, captures config/runtime events, calls showCaptcha when
    possible, and returns the v4 success payload if the page reaches onSuccess.
    """

    async def solve(
        self,
        *,
        target_url: str,
        headless: bool | str | None = True,
        proxy_server: str | None = None,
        timeout_sec: int = 90,
        wait_after_load_ms: int = 1000,
        trigger_selectors: list[str] | None = None,
        auto_trigger: bool = True,
        slide_solve: bool = True,
        slide_max_attempts: int = 3,
        output_dir: str | None = None,
        screenshot: bool = True,
        save_html: bool = True,
        browser_binary: str | None = None,
        user_agent: str | None = None,
        locale: str | None = "zh-CN",
        timezone_id: str | None = "Asia/Shanghai",
    ) -> CaptchaResult:
        started = time.monotonic()
        output_root = Path(output_dir or f"/tmp/antibot-geetest-{int(time.time() * 1000)}")
        output_root.mkdir(parents=True, exist_ok=True)
        out = output_root / "geetest_run.json"
        artifacts = {"out": str(out), "outputDir": str(output_root)}
        raw: dict[str, Any] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "targetUrl": target_url,
            "net": [],
            "triggerSelectors": list(trigger_selectors or DEFAULT_TRIGGER_SELECTORS),
        }
        overall_deadline = time.monotonic() + max(1, timeout_sec)

        browser = None
        playwright = None
        response_tasks: list[asyncio.Task] = []

        async def write_raw() -> None:
            out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

        try:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {
                "headless": _headless(headless),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ],
            }
            if browser_binary:
                launch_kwargs["executable_path"] = browser_binary
            proxy_cfg = parse_proxy(proxy_server).playwright() if proxy_server else None
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg

            browser = await playwright.chromium.launch(**launch_kwargs)
            context_kwargs: dict[str, Any] = {
                "locale": locale,
                "timezone_id": timezone_id,
                "ignore_https_errors": True,
            }
            if user_agent:
                context_kwargs["user_agent"] = user_agent
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.add_init_script(GEETEST_HOOK_JS)

            def on_request(req: Any) -> None:
                if _interesting_url(req.url) and len(raw["net"]) < 300:
                    raw["net"].append({
                        "at": int(time.time() * 1000),
                        "type": "request",
                        "method": req.method,
                        "url": req.url,
                    })

            async def record_response(resp: Any) -> None:
                try:
                    if not _interesting_url(resp.url) or len(raw["net"]) >= 300:
                        return
                    entry = {
                        "at": int(time.time() * 1000),
                        "type": "response",
                        "status": resp.status,
                        "url": resp.url,
                    }
                    ctype = (resp.headers or {}).get("content-type", "")
                    if "json" in ctype or "text" in ctype:
                        try:
                            entry["body"] = (await resp.text())[:2000]
                        except Exception as e:
                            entry["bodyError"] = str(e)
                    raw["net"].append(entry)
                except Exception:
                    return

            page.on("request", on_request)
            page.on("response", lambda resp: response_tasks.append(asyncio.create_task(record_response(resp))))

            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=max(1000, int((overall_deadline - time.monotonic()) * 1000)),
            )
            if wait_after_load_ms > 0:
                await page.wait_for_timeout(wait_after_load_ms)

            raw["title"] = await page.title()
            raw["finalUrl"] = page.url

            if auto_trigger:
                raw["showCaptchaCalls"] = await page.evaluate(
                    "() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.showAll ? window.__ANTIBOT_GEETEST.showAll() : []"
                )
                raw["triggerClicks"] = await page.evaluate(
                    """async (selectors) => {
                      const ret = [];
                      const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
                      const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const cs = getComputedStyle(el);
                        return r.width > 3 && r.height > 3 && cs.display !== 'none' && cs.visibility !== 'hidden';
                      };
                      const challengeVisible = () => visible(document.querySelector('.geetest_bg')) && visible(document.querySelector('.geetest_btn'));
                      if (challengeVisible()) return ret;
                      for (const sel of selectors) {
                        let nodes = [];
                        try { nodes = Array.from(document.querySelectorAll(sel)); } catch (e) { ret.push({ selector: sel, error: e.message }); continue; }
                        for (const el of nodes.slice(0, 5)) {
                          if (!visible(el)) continue;
                          const r = el.getBoundingClientRect();
                          try {
                            el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                            el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                            el.click();
                            el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                            ret.push({ selector: sel, tag: el.tagName, id: el.id || '', className: String(el.className || ''), rect: { x: r.x, y: r.y, width: r.width, height: r.height } });
                            await sleep(250);
                            if (challengeVisible()) return ret;
                          } catch (e) { ret.push({ selector: sel, error: e.message }); }
                          if (ret.length >= 12) return ret;
                        }
                      }
                      return ret;
                    }""",
                    raw["triggerSelectors"],
                )

            if slide_solve:
                remaining_sec = int(overall_deadline - time.monotonic())
                if remaining_sec > 3:
                    raw["slideAttempts"] = await self._solve_slide_challenge(
                        page,
                        output_root=output_root,
                        max_attempts=max(1, slide_max_attempts),
                        total_timeout_sec=max(3, remaining_sec),
                    )
                else:
                    raw["slideAttempts"] = [{"ok": False, "error": "no time left for slide solve"}]

            state: dict[str, Any] | None = None
            success: dict[str, Any] | None = None
            while time.monotonic() < overall_deadline:
                state = await page.evaluate(
                    "() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.snapshot ? window.__ANTIBOT_GEETEST.snapshot() : null"
                )
                success = latest_geetest_success(state)
                if success:
                    break
                await page.wait_for_timeout(500)

            if response_tasks:
                await asyncio.gather(*response_tasks, return_exceptions=True)

            raw["state"] = state or {}
            raw["success"] = success
            raw["ok"] = bool(success)
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)

            if screenshot:
                p = output_root / "geetest_page.png"
                try:
                    await page.screenshot(path=str(p), full_page=True)
                    artifacts["screenshot"] = str(p)
                except Exception as e:
                    raw["screenshotError"] = str(e)
            if save_html:
                p = output_root / "geetest_page.html"
                try:
                    p.write_text(await page.content(), encoding="utf-8")
                    artifacts["html"] = str(p)
                except Exception as e:
                    raw["htmlError"] = str(e)

            await write_raw()
            return self._result(raw, artifacts, proxy_server)
        except Exception as e:
            raw["ok"] = False
            raw["error"] = {"message": str(e), "type": type(e).__name__}
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            await write_raw()
            return self._result(raw, artifacts, proxy_server)
        finally:
            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except Exception:
                    pass

    async def _solve_slide_challenge(
        self,
        page: Any,
        *,
        output_root: Path,
        max_attempts: int,
        total_timeout_sec: int,
    ) -> list[dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        deadline = time.monotonic() + total_timeout_sec
        for attempt_no in range(1, max_attempts + 1):
            if time.monotonic() >= deadline:
                break
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "slide"}
            try:
                await self._ensure_slide_visible(page)
                await page.wait_for_selector(".geetest_bg", state="visible", timeout=8000)
                await page.wait_for_selector(".geetest_slice_bg", state="visible", timeout=8000)
                await page.wait_for_selector(".geetest_btn", state="visible", timeout=8000)
                await page.wait_for_timeout(700)
                info = await self._slide_dom_info(page)
                attempt["dom"] = info
                bg_url = _css_url(info.get("bgImage"))
                slice_url = _css_url(info.get("sliceImage"))
                attempt["bgUrl"] = bg_url
                attempt["sliceUrl"] = slice_url
                if not bg_url or not slice_url:
                    attempt["ok"] = False
                    attempt["error"] = "missing geetest slide image url"
                    attempts.append(attempt)
                    break

                bg_bytes = await self._fetch_bytes(page, bg_url)
                slice_bytes = await self._fetch_bytes(page, slice_url)
                bg_path = output_root / f"geetest_slide_bg_{attempt_no}.png"
                slice_path = output_root / f"geetest_slide_slice_{attempt_no}.png"
                bg_path.write_bytes(bg_bytes)
                slice_path.write_bytes(slice_bytes)
                attempt["artifacts"] = {"bg": str(bg_path), "slice": str(slice_path)}

                detection = detect_geetest_slide_gap(bg_bytes, slice_bytes)
                attempt["detection"] = detection
                bg_size = detection.get("bg_size") or {}
                bg_width = max(1, int(bg_size.get("width") or 1))
                bg_rect = info.get("bgRect") or {}
                display_width = float(bg_rect.get("width") or bg_width)
                distance = float(detection["distance_x"]) * display_width / bg_width
                attempt["distance"] = distance

                drag_result = await self._drag_geetest_slider(page, distance)
                attempt["drag"] = drag_result
                await page.wait_for_timeout(1800)
                await page.evaluate(
                    "() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.collectValidates ? window.__ANTIBOT_GEETEST.collectValidates('after-drag') : []"
                )
                outcome = await self._slide_outcome(page)
                attempt["outcome"] = outcome
                attempt["ok"] = bool(outcome.get("success"))
                attempts.append(attempt)
                if attempt["ok"]:
                    break

                if attempt_no < max_attempts:
                    await self._refresh_slide(page)
            except Exception as e:
                attempt["ok"] = False
                attempt["error"] = str(e)
                attempt["errorType"] = type(e).__name__
                attempts.append(attempt)
                if attempt_no < max_attempts:
                    try:
                        await self._refresh_slide(page)
                    except Exception:
                        pass
        return attempts

    async def _slide_dom_info(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            """() => {
              const one = (selector) => document.querySelector(selector);
              const rect = (el) => {
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return { x: r.x, y: r.y, width: r.width, height: r.height };
              };
              const bg = one('.geetest_bg');
              const slice = one('.geetest_slice_bg');
              const btn = one('.geetest_btn');
              const track = one('.geetest_track') || one('.geetest_slider');
              return {
                bgImage: bg ? getComputedStyle(bg).backgroundImage : '',
                sliceImage: slice ? getComputedStyle(slice).backgroundImage : '',
                bgRect: rect(bg),
                sliceRect: rect(one('.geetest_slice')),
                btnRect: rect(btn),
                trackRect: rect(track),
              };
            }"""
        )

    async def _ensure_slide_visible(self, page: Any) -> None:
        await page.evaluate(
            """async () => {
              const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none' && cs.visibility !== 'hidden';
              };
              if (visible(document.querySelector('.geetest_bg'))) return;
              try {
                if (window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.showAll) {
                  window.__ANTIBOT_GEETEST.showAll();
                  await sleep(350);
                }
              } catch {}
              if (visible(document.querySelector('.geetest_bg'))) return;
              const selectors = ['.geetest_holder', '.geetest_btn_click', '#captcha', '[class*="geetest_holder"]'];
              for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (!visible(el)) continue;
                const r = el.getBoundingClientRect();
                try {
                  el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                  el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                  el.click();
                  el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                  await sleep(500);
                  if (visible(document.querySelector('.geetest_bg'))) return;
                } catch {}
              }
            }"""
        )

    async def _fetch_bytes(self, page: Any, url: str) -> bytes:
        resp = await page.context.request.get(url, timeout=15000)
        if not resp.ok:
            raise RuntimeError(f"failed to fetch geetest asset: {resp.status} {url}")
        return await resp.body()

    async def _drag_geetest_slider(self, page: Any, distance: float) -> dict[str, Any]:
        btn = await page.evaluate(
            """() => {
              const el = document.querySelector('.geetest_btn');
              if (!el) return null;
              const r = el.getBoundingClientRect();
              return { x: r.x, y: r.y, width: r.width, height: r.height };
            }"""
        )
        if not btn:
            return {"ok": False, "error": "geetest slider button not found"}
        start_x = float(btn["x"]) + float(btn["width"]) / 2
        start_y = float(btn["y"]) + float(btn["height"]) / 2
        await page.mouse.move(start_x, start_y)
        await page.wait_for_timeout(random.randint(80, 220))
        await page.mouse.down()

        trace: list[dict[str, float]] = []
        steps = random.randint(42, 62)
        for i in range(steps):
            t = (i + 1) / steps
            if t < 0.76:
                ease = 1 - (1 - t / 0.76) ** 3
                current = distance * 0.88 * ease
            else:
                ease = (t - 0.76) / 0.24
                current = distance * 0.88 + distance * 0.12 * (1 - (1 - ease) ** 2)
            if i > steps - 8:
                current += random.uniform(-1.1, 1.1)
            y = start_y + math.sin(t * math.pi * random.uniform(1.5, 3.2)) * random.uniform(0.2, 1.4)
            x = start_x + current
            await page.mouse.move(x, y)
            trace.append({"x": round(x, 2), "y": round(y, 2), "t": round(t, 3)})
            await page.wait_for_timeout(random.randint(8, 24))

        await page.mouse.move(
            start_x + distance + random.uniform(-0.35, 0.35),
            start_y + random.uniform(-0.55, 0.55),
        )
        hold_ms = random.randint(220, 620)
        await page.wait_for_timeout(hold_ms)
        await page.mouse.up()
        return {
            "ok": True,
            "distance": distance,
            "start": {"x": start_x, "y": start_y},
            "steps": steps,
            "holdMs": hold_ms,
            "traceSample": trace[:: max(1, len(trace) // 8)][:10],
        }

    async def _slide_outcome(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            r"""() => {
              const text = (document.body && document.body.innerText || '').replace(/\s+/g, ' ').trim();
              const box = document.querySelector('.geetest_box');
              const fail = /验证失败|try again|fail/i.test(text);
              const successText = /验证成功|验证通过|success/i.test(text);
              const hidden = !box || getComputedStyle(box).display === 'none' || getComputedStyle(box).visibility === 'hidden';
              const validates = window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.validates || [];
              const latest = validates.length ? validates[validates.length - 1].value : null;
              const payloadOk = latest && latest.lot_number && latest.captcha_output && latest.pass_token && latest.gen_time;
              return {
                success: Boolean(payloadOk || successText || (hidden && !fail)),
                fail,
                popupHidden: hidden,
                text: text.slice(0, 500),
                latestValidate: latest || null,
              };
            }"""
        )

    async def _refresh_slide(self, page: Any) -> None:
        clicked = await page.evaluate(
            """() => {
              const selectors = ['.geetest_refresh', '.geetest_refresh_tips'];
              for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (!el) continue;
                try { el.click(); return true; } catch {}
              }
              return false;
            }"""
        )
        if clicked:
            await page.wait_for_timeout(1200)

    def _result(
        self,
        raw: dict[str, Any],
        artifacts: dict[str, str],
        proxy_server: str | None,
    ) -> CaptchaResult:
        success = raw.get("success") if isinstance(raw.get("success"), dict) else None
        ok = bool(success)
        state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
        configs = state.get("configs") if isinstance(state, dict) else []
        first_config = configs[0].get("config") if configs and isinstance(configs[0], dict) else {}
        error = raw.get("error") or {}
        return CaptchaResult(
            provider="geetest",
            ok=ok,
            ticket=success.get("pass_token") if success else None,
            randstr=success.get("lot_number") if success else None,
            verify_code="success" if ok else "pending",
            elapsed_ms=raw.get("elapsedMs"),
            artifacts=artifacts,
            diagnostics={
                "target_url": raw.get("targetUrl"),
                "final_url": raw.get("finalUrl"),
                "title": raw.get("title"),
                "captcha_id": first_config.get("captchaId") or first_config.get("captcha_id"),
                "product": first_config.get("product"),
                "configs": len(configs or []),
                "events": len(state.get("events") or []) if isinstance(state, dict) else 0,
                "validates": len(state.get("validates") or []) if isinstance(state, dict) else 0,
                "slide_attempts": len(raw.get("slideAttempts") or []),
                "slide_solved": any((a or {}).get("ok") for a in raw.get("slideAttempts") or []),
                "net_events": len(raw.get("net") or []),
                "trigger_clicks": len(raw.get("triggerClicks") or []),
                "proxy": redacted_proxy(proxy_server),
                "error": error,
            },
            raw=raw,
            errors=[] if ok else [str(error.get("message") or "geetest_not_solved")],
        )
