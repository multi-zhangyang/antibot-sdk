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


DEFAULT_TRIGGER_SELECTORS = (
    ".yidun_slider",
    ".yidun_control",
    ".yidun",
    ".j-captcha",
    ".j-pop",
    "[class*='yidun']",
    "[id*='captcha']",
)

YIDUN_STEALTH_JS = r"""
(() => {
  try { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); } catch {}
  try { window.chrome = window.chrome || { runtime: {} }; } catch {}
  try { Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] }); } catch {}
  try { Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] }); } catch {}
})();
"""

# Important: initNECaptcha is both callable and has static methods such as `.use()`.
# A plain wrapper breaks the official loader with `s.use is not a function`, so this
# hook uses Proxy and forwards property access to the original function.
YIDUN_HOOK_JS = r"""
(() => {
  if (window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.installed) return;
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
      for (const k of Object.keys(value).slice(0, 100)) {
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
    snapshot() {
      return {
        installed: true,
        at: this.at,
        configs: this.configs.slice(-20),
        events: this.events.slice(-120),
        validates: this.validates.slice(-40),
        errors: this.errors.slice(-20),
        methodCalls: this.methodCalls.slice(-120),
        instances: this.instances.slice(-20),
      };
    },
    popAll() {
      const ret = [];
      for (const inst of this._instances) {
        for (const method of ['popUp', 'verify']) {
          try {
            if (inst && typeof inst[method] === 'function') {
              inst[method]();
              ret.push({ ok: true, method });
              break;
            }
          } catch (e) { ret.push({ ok: false, method, error: e && e.message }); }
        }
      }
      return ret;
    },
    refreshAll() {
      const ret = [];
      for (const inst of this._instances) {
        try {
          if (inst && typeof inst.refresh === 'function') {
            inst.refresh();
            ret.push({ ok: true, method: 'refresh' });
          }
        } catch (e) { ret.push({ ok: false, method: 'refresh', error: e && e.message }); }
      }
      return ret;
    },
  };
  window.__ANTIBOT_YIDUN = state;

  const wrapCaptchaObj = (obj, config) => {
    if (!obj || obj.__antibotWrapped) return obj;
    const instanceId = state.instances.length + 1;
    const methods = ['verify', 'refresh', 'destroy', 'popUp', 'close', 'getValidate', 'onVerify', 'onReady', 'onError', 'onClose'];
    for (const name of methods) {
      if (!obj || typeof obj[name] !== 'function' || obj[name].__antibotWrapped) continue;
      const original = obj[name];
      const wrapped = function(...args) {
        state.methodCalls.push({ at: Date.now(), instanceId, method: name, args: safe(args) });
        const ret = original.apply(this, args);
        if (name === 'getValidate') {
          state.validates.push({ at: Date.now(), source: 'getValidate-call', value: safe(ret) });
        }
        return ret;
      };
      wrapped.__antibotWrapped = true;
      obj[name] = wrapped;
    }
    try { obj.__antibotWrapped = true; } catch {}
    state._instances.push(obj);
    state.instances.push({
      id: instanceId,
      config: safe(config),
      keys: Object.keys(obj).slice(0, 100),
      methods: methods.filter(name => typeof obj[name] === 'function'),
    });
    state.pushEvent('instance-wrapped', { instanceId });
    return obj;
  };

  const wrapInit = (fn) => {
    if (typeof fn !== 'function' || fn.__antibotProxy) return fn;
    const proxy = new Proxy(fn, {
      apply(target, thisArg, argArray) {
        const config = argArray[0];
        const callback = argArray[1];
        state.configs.push({ at: Date.now(), config: safe(config) });
        state.pushEvent('initNECaptcha-call', config);
        if (config && typeof config.onVerify === 'function' && !config.__antibotOnVerifyWrapped) {
          const originalVerify = config.onVerify;
          config.onVerify = function(...args) {
            state.pushEvent('onVerify', args);
            state.validates.push({ at: Date.now(), source: 'onVerify', value: safe(args) });
            return originalVerify.apply(this, args);
          };
          config.__antibotOnVerifyWrapped = true;
        }
        if (typeof callback === 'function') {
          argArray[1] = function(captchaObj, ...rest) {
            state.pushEvent('initNECaptcha-callback', { hasCaptchaObj: !!captchaObj });
            const wrappedObj = wrapCaptchaObj(captchaObj, config);
            return callback.call(this, wrappedObj, ...rest);
          };
        }
        return Reflect.apply(target, thisArg, argArray);
      },
      get(target, prop, receiver) {
        if (prop === '__antibotProxy' || prop === '__antibotWrapped') return true;
        return Reflect.get(target, prop, receiver);
      },
      set(target, prop, value, receiver) { return Reflect.set(target, prop, value, receiver); },
      has(target, prop) { return Reflect.has(target, prop); },
      ownKeys(target) { return Reflect.ownKeys(target); },
      getOwnPropertyDescriptor(target, prop) { return Reflect.getOwnPropertyDescriptor(target, prop); },
    });
    return proxy;
  };

  let current = window.initNECaptcha;
  try {
    Object.defineProperty(window, 'initNECaptcha', {
      configurable: true,
      enumerable: true,
      get() { return current; },
      set(v) {
        state.pushEvent('initNECaptcha-set', { type: typeof v });
        current = wrapInit(v);
      },
    });
    if (current) current = wrapInit(current);
  } catch (e) {
    state.errors.push({ at: Date.now(), source: 'defineProperty', message: e && e.message });
    if (typeof window.initNECaptcha === 'function') window.initNECaptcha = wrapInit(window.initNECaptcha);
  }
})();
"""


def _headless(value: bool | str | None) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return value.lower() not in {"0", "false", "headed", "no"}


def _interesting_url(url: str) -> bool:
    u = url.lower()
    return any(
        x in u
        for x in (
            "yidun",
            "necaptcha",
            "c.dun.163.com/api/v3",
            "cstaticdun",
            "captcha",
            "dun.163.com/trial",
        )
    )


def _parse_jsonp(body: str | None) -> dict[str, Any] | None:
    if not body:
        return None
    text = body.strip()
    if not text:
        return None
    if not text.startswith("{"):
        m = re.match(r"^[^(]*\((.*)\)\s*;?\s*$", text, flags=re.S)
        if not m:
            return None
        text = m.group(1)
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _find_yidun_success(value: Any, depth: int = 0) -> dict[str, Any] | None:
    if depth > 5:
        return None
    if isinstance(value, dict):
        validate = value.get("validate") or value.get("ticket")
        token = value.get("token") or value.get("randstr")
        result = value.get("result")
        if validate and (result is True or token or value.get("zoneId") or value.get("zone_id")):
            return {
                "validate": validate,
                "token": token,
                "zoneId": value.get("zoneId") or value.get("zone_id"),
                "result": True if result is None else bool(result),
            }
        for v in value.values():
            found = _find_yidun_success(v, depth + 1)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_yidun_success(item, depth + 1)
            if found:
                return found
    return None


def latest_yidun_success(raw: dict[str, Any] | None, state: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        for item in reversed(raw.get("checkResponses") or []):
            parsed = item.get("parsed") if isinstance(item, dict) else None
            found = _find_yidun_success(parsed)
            if found:
                return found
    if isinstance(state, dict):
        for item in reversed(state.get("validates") or []):
            if isinstance(item, dict):
                found = _find_yidun_success(item.get("value"))
                if found:
                    return found
    return None


def detect_yidun_slide_gap(bg_bytes: bytes, front_bytes: bytes) -> dict[str, Any]:
    """Detect NetEase Yidun jigsaw gap from background and front image bytes.

    Yidun's front PNG contains transparent padding and the panel positions that
    full image slightly left of the slider knob. This function returns the
    desired **front image left** in source/display pixels; the caller must add the
    knob/front visual offset before dragging the slider.
    """

    bg_arr = np.frombuffer(bg_bytes, dtype=np.uint8)
    front_arr = np.frombuffer(front_bytes, dtype=np.uint8)
    bg = cv2.imdecode(bg_arr, cv2.IMREAD_COLOR)
    front = cv2.imdecode(front_arr, cv2.IMREAD_UNCHANGED)
    if bg is None or front is None:
        raise ValueError("failed to decode yidun slide images")
    if front.ndim != 3 or front.shape[2] < 4:
        raise ValueError("yidun front image has no alpha channel")

    alpha = front[:, :, 3]
    mask = ((alpha > 30).astype(np.uint8)) * 255
    ys, xs = np.where(mask > 0)
    if len(xs) == 0 or len(ys) == 0:
        raise ValueError("yidun front alpha mask is empty")

    trim_x0, trim_x1 = int(xs.min()), int(xs.max()) + 1
    trim_y0, trim_y1 = int(ys.min()), int(ys.max()) + 1
    template_rgb = front[:, :, :3][trim_y0:trim_y1, trim_x0:trim_x1]
    template_mask = mask[trim_y0:trim_y1, trim_x0:trim_x1]

    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(bg, cv2.COLOR_BGR2HSV)
    dark = 255 - gray
    maps = {
        "shadow_dark": dark,
        "shadow_dark_blur": cv2.GaussianBlur(dark, (3, 3), 0),
        "shadow_dark_low_sat": cv2.normalize(
            dark.astype(np.float32) * (255 - hsv[:, :, 1]).astype(np.float32),
            None,
            0,
            255,
            cv2.NORM_MINMAX,
        ).astype(np.uint8),
        "edge": cv2.Canny(gray, 35, 120),
    }

    candidates: list[dict[str, Any]] = []
    color_res = cv2.matchTemplate(bg, template_rgb, cv2.TM_CCORR_NORMED, mask=template_mask)
    _min_val, color_score, _min_loc, color_loc = cv2.minMaxLoc(color_res)
    candidates.append(
        {
            "name": "color_template",
            "score": float(color_score),
            "distance_x": int(color_loc[0] - trim_x0),
            "distance_y": int(color_loc[1] - trim_y0),
            "match_x": int(color_loc[0]),
            "match_y": int(color_loc[1]),
        }
    )

    expected_match_y = trim_y0
    y_band = max(24, int((trim_y1 - trim_y0) * 0.50))

    def push_best_candidate(name: str, image: np.ndarray, ylo: int, yhi: int) -> None:
        res = cv2.matchTemplate(image, template_mask, cv2.TM_CCORR_NORMED)
        ylo = max(0, ylo)
        yhi = min(res.shape[0] - 1, yhi)
        if yhi < ylo:
            return
        band = res[ylo : yhi + 1, :]
        _min_val, score, _min_loc, loc = cv2.minMaxLoc(band)
        match_x, match_y = int(loc[0]), int(loc[1]) + ylo
        item = {
            "name": name,
            "score": float(score),
            "distance_x": int(match_x - trim_x0),
            "distance_y": int(match_y - trim_y0),
            "match_x": match_x,
            "match_y": match_y,
        }
        if item not in candidates:
            candidates.append(item)

    for name, image in maps.items():
        # First force a narrow vertical band where the full front PNG should
        # align with the bg. Some backgrounds have a stronger dark pattern at
        # another y; if we only keep the global maximum, that false candidate
        # hides the real hole.
        push_best_candidate(name, image, expected_match_y - 8, expected_match_y + 8)
        push_best_candidate(name, image, expected_match_y - y_band, expected_match_y + y_band)

    shadow_valid = [
        c
        for c in candidates
        if c["name"] not in {"edge", "color_template"}
        and 18 <= int(c["distance_x"]) <= max(18, bg.shape[1] - 35)
    ]
    aligned = [c for c in shadow_valid if abs(int(c["distance_y"])) <= 8]
    if aligned:
        shadow_choice = max(aligned, key=lambda c: float(c["score"]))
        color_aligned = [
            c
            for c in candidates
            if c["name"] == "color_template"
            and float(c["score"]) >= 0.86
            and abs(int(c["distance_y"])) <= 8
            and 18 <= int(c["distance_x"]) <= max(18, bg.shape[1] - 35)
        ]
        # Prefer a strong aligned shadow: color matching often locks on to
        # repeated sky/sea texture elsewhere. If the aligned shadow itself is
        # weak, a high-score color match is a useful fallback for light holes.
        if float(shadow_choice["score"]) >= 0.865 or not color_aligned:
            chosen = shadow_choice
        else:
            chosen = max(color_aligned, key=lambda c: float(c["score"]))
    else:
        color_aligned = [
            c
            for c in candidates
            if c["name"] == "color_template"
            and float(c["score"]) >= 0.86
            and abs(int(c["distance_y"])) <= 8
            and 18 <= int(c["distance_x"]) <= max(18, bg.shape[1] - 35)
        ]
        if color_aligned:
            chosen = max(color_aligned, key=lambda c: float(c["score"]))
        else:
            near = [c for c in shadow_valid if abs(int(c["distance_y"])) <= 16]
            pool = near or shadow_valid or candidates
            chosen = max(pool, key=lambda c: (-abs(int(c["distance_y"])), float(c["score"])))

    return {
        "distance_x": int(chosen["distance_x"]),
        "distance_y": int(chosen["distance_y"]),
        "match_x": int(chosen["match_x"]),
        "match_y": int(chosen["match_y"]),
        "score": float(chosen["score"]),
        "method": chosen["name"],
        "candidates": candidates,
        "bg_size": {"width": int(bg.shape[1]), "height": int(bg.shape[0])},
        "front_size": {"width": int(front.shape[1]), "height": int(front.shape[0])},
        "trim": {"x0": trim_x0, "y0": trim_y0, "x1": trim_x1, "y1": trim_y1},
    }


class YidunCaptchaSolver:
    """NetEase Yidun jigsaw browser solver alpha."""

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
        output_root = Path(output_dir or f"/tmp/antibot-yidun-{int(time.time() * 1000)}")
        output_root.mkdir(parents=True, exist_ok=True)
        out = output_root / "yidun_run.json"
        artifacts = {"out": str(out), "outputDir": str(output_root)}
        raw: dict[str, Any] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "targetUrl": target_url,
            "net": [],
            "checkResponses": [],
            "getResponses": [],
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
                "viewport": {"width": 1280, "height": 900},
            }
            context_kwargs["user_agent"] = user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
            )
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.add_init_script(YIDUN_STEALTH_JS)
            await page.add_init_script(YIDUN_HOOK_JS)

            def on_request(req: Any) -> None:
                if _interesting_url(req.url) and len(raw["net"]) < 400:
                    raw["net"].append(
                        {
                            "at": int(time.time() * 1000),
                            "type": "request",
                            "method": req.method,
                            "url": req.url,
                        }
                    )

            async def record_response(resp: Any) -> None:
                try:
                    if not _interesting_url(resp.url) or len(raw["net"]) >= 400:
                        return
                    entry: dict[str, Any] = {
                        "at": int(time.time() * 1000),
                        "type": "response",
                        "status": resp.status,
                        "url": resp.url,
                    }
                    ctype = (resp.headers or {}).get("content-type", "")
                    should_read = "json" in ctype or "text" in ctype or "javascript" in ctype
                    if should_read:
                        try:
                            body = await resp.text()
                            entry["body"] = body[:2500]
                            parsed = _parse_jsonp(body)
                            if parsed is not None:
                                entry["parsed"] = parsed
                                if "/api/v3/check" in resp.url:
                                    raw["checkResponses"].append(
                                        {"at": entry["at"], "url": resp.url, "parsed": parsed}
                                    )
                                elif "/api/v3/get" in resp.url:
                                    raw["getResponses"].append(
                                        {"at": entry["at"], "url": resp.url, "parsed": parsed}
                                    )
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
                raw["triggerClicks"] = await self._auto_trigger(page, raw["triggerSelectors"])

            if slide_solve:
                remaining_sec = int(overall_deadline - time.monotonic())
                raw["slideAttempts"] = await self._solve_slide_challenge(
                    page,
                    output_root=output_root,
                    max_attempts=max(1, slide_max_attempts),
                    total_timeout_sec=max(3, remaining_sec),
                )
            else:
                raw["slideAttempts"] = []

            state: dict[str, Any] | None = None
            success: dict[str, Any] | None = None
            while time.monotonic() < overall_deadline:
                state = await self._state(page)
                success = latest_yidun_success(raw, state)
                if success:
                    break
                if raw.get("slideAttempts"):
                    break
                await page.wait_for_timeout(500)

            if response_tasks:
                await asyncio.gather(*response_tasks, return_exceptions=True)
            state = await self._state(page)
            success = latest_yidun_success(raw, state)
            raw["state"] = state or {}
            raw["success"] = success
            raw["ok"] = bool(success)
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)

            if screenshot:
                p = output_root / "yidun_page.png"
                try:
                    await page.screenshot(path=str(p), full_page=True)
                    artifacts["screenshot"] = str(p)
                except Exception as e:
                    raw["screenshotError"] = str(e)
            if save_html:
                p = output_root / "yidun_page.html"
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

    async def _state(self, page: Any) -> dict[str, Any] | None:
        return await page.evaluate(
            "() => window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.snapshot "
            "? window.__ANTIBOT_YIDUN.snapshot() : null"
        )

    async def _auto_trigger(self, page: Any, selectors: list[str]) -> list[dict[str, Any]]:
        return await page.evaluate(
            """async (selectors) => {
              const ret = [];
              const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none' && cs.visibility !== 'hidden';
              };
              if (visible(document.querySelector('.yidun_slider'))) return ret;
              try {
                if (window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.popAll) {
                  ret.push({ selector: '__state__.popAll', calls: window.__ANTIBOT_YIDUN.popAll() });
                  await sleep(400);
                  if (visible(document.querySelector('.yidun_slider'))) return ret;
                }
              } catch (e) { ret.push({ selector: '__state__.popAll', error: e && e.message }); }
              for (const sel of selectors) {
                let nodes = [];
                try { nodes = Array.from(document.querySelectorAll(sel)); }
                catch (e) { ret.push({ selector: sel, error: e.message }); continue; }
                for (const el of nodes.slice(0, 5)) {
                  if (!visible(el)) continue;
                  const r = el.getBoundingClientRect();
                  try {
                    el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                    el.click();
                    ret.push({ selector: sel, tag: el.tagName, id: el.id || '', className: String(el.className || ''), rect: { x: r.x, y: r.y, width: r.width, height: r.height } });
                    await sleep(300);
                    if (visible(document.querySelector('.yidun_slider'))) return ret;
                  } catch (e) { ret.push({ selector: sel, error: e.message }); }
                  if (ret.length >= 12) return ret;
                }
              }
              return ret;
            }""",
            selectors,
        )

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
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "jigsaw"}
            try:
                info = await self._ensure_slide_visible(page)
                attempt["dom"] = info
                bg_url = info.get("bgSrc") or ""
                front_url = info.get("frontSrc") or ""
                attempt["bgUrl"] = bg_url
                attempt["frontUrl"] = front_url
                if not bg_url or not front_url:
                    attempt["ok"] = False
                    attempt["error"] = "missing yidun image url"
                    attempts.append(attempt)
                    break

                bg_bytes = await self._fetch_bytes(page, bg_url)
                front_bytes = await self._fetch_bytes(page, front_url)
                bg_path = output_root / f"yidun_slide_bg_{attempt_no}.jpg"
                front_path = output_root / f"yidun_slide_front_{attempt_no}.png"
                bg_path.write_bytes(bg_bytes)
                front_path.write_bytes(front_bytes)
                attempt["artifacts"] = {"bg": str(bg_path), "front": str(front_path)}

                detection = detect_yidun_slide_gap(bg_bytes, front_bytes)
                attempt["detection"] = detection
                bg_size = detection.get("bg_size") or {}
                bg_width = max(1, int(bg_size.get("width") or 1))
                bg_rect = info.get("bgRect") or {}
                front_rect = info.get("frontRect") or {}
                slider_rect = info.get("sliderRect") or {}
                display_width = float(bg_rect.get("width") or bg_width)
                desired_front_left = float(detection["distance_x"]) * display_width / bg_width
                visual_offset = max(
                    0.0,
                    (float(front_rect.get("width") or detection["front_size"]["width"])
                    - float(slider_rect.get("width") or 40))
                    / 2.0,
                )
                distance = desired_front_left + visual_offset
                attempt["distance"] = distance
                attempt["visualOffset"] = visual_offset

                drag_result = await self._drag_yidun_slider(page, distance)
                attempt["drag"] = drag_result
                await page.wait_for_timeout(2800)
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

    async def _ensure_slide_visible(self, page: Any) -> dict[str, Any]:
        await page.wait_for_selector(".yidun_slider", state="visible", timeout=15000)
        slider = page.locator(".yidun_slider").first
        try:
            await slider.scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        box = await slider.bounding_box()
        if box:
            await page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            await page.wait_for_timeout(750)
        for _ in range(12):
            info = await self._slide_dom_info(page)
            bg_rect = info.get("bgRect") or {}
            if info.get("bgSrc") and info.get("frontSrc") and float(bg_rect.get("width") or 0) > 10:
                return info
            try:
                await page.evaluate(
                    "() => window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.popAll "
                    "? window.__ANTIBOT_YIDUN.popAll() : []"
                )
            except Exception:
                pass
            if box:
                await page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            await page.wait_for_timeout(500)
        return await self._slide_dom_info(page)

    async def _slide_dom_info(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            """() => {
              const rect = (el) => {
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return { x: r.x, y: r.y, width: r.width, height: r.height };
              };
              const bg = document.querySelector('.yidun_bg-img');
              const front = document.querySelector('.yidun_jigsaw');
              const slider = document.querySelector('.yidun_slider');
              const control = document.querySelector('.yidun_control');
              const panel = document.querySelector('.yidun_panel');
              const tips = document.querySelector('.yidun_tips__text');
              const root = document.querySelector('.yidun');
              return {
                bgSrc: bg ? bg.src : '',
                frontSrc: front ? front.src : '',
                bgRect: rect(bg),
                frontRect: rect(front),
                sliderRect: rect(slider),
                controlRect: rect(control),
                panelRect: rect(panel),
                frontStyle: front ? (front.getAttribute('style') || '') : '',
                sliderStyle: slider ? (slider.getAttribute('style') || '') : '',
                tips: tips ? tips.textContent : '',
                rootClass: root ? String(root.className || '') : '',
              };
            }"""
        )

    async def _fetch_bytes(self, page: Any, url: str) -> bytes:
        resp = await page.context.request.get(url, timeout=15000)
        if not resp.ok:
            raise RuntimeError(f"failed to fetch yidun asset: {resp.status} {url}")
        return await resp.body()

    async def _drag_yidun_slider(self, page: Any, distance: float) -> dict[str, Any]:
        btn = await page.evaluate(
            """() => {
              const el = document.querySelector('.yidun_slider');
              if (!el) return null;
              const r = el.getBoundingClientRect();
              return { x: r.x, y: r.y, width: r.width, height: r.height };
            }"""
        )
        if not btn:
            return {"ok": False, "error": "yidun slider button not found"}
        start_x = float(btn["x"]) + float(btn["width"]) / 2
        start_y = float(btn["y"]) + float(btn["height"]) / 2
        await page.mouse.move(start_x - random.uniform(2, 8), start_y + random.uniform(-2, 2))
        await page.wait_for_timeout(random.randint(120, 280))
        await page.mouse.move(start_x, start_y + random.uniform(-1, 1), steps=random.randint(2, 5))
        await page.wait_for_timeout(random.randint(260, 620))
        await page.mouse.down()
        await page.wait_for_timeout(random.randint(320, 760))

        trace: list[dict[str, float]] = []
        steps = random.randint(85, 125)
        duration_ms = random.randint(1700, 2700)
        overshoot = random.uniform(0.4, 2.4) if distance > 80 else random.uniform(0.1, 1.2)
        last = 0.0
        sigmoid_lo = 1 / (1 + math.exp(4.68))
        sigmoid_hi = 1 / (1 + math.exp(-4.32))
        for i in range(steps):
            t = (i + 1) / steps
            ease = 1 / (1 + math.exp(-9 * (t - 0.52)))
            ease = (ease - sigmoid_lo) / (sigmoid_hi - sigmoid_lo)
            current = distance * ease
            if t > 0.82:
                current += overshoot * (1 - (1 - t) / 0.18)
            if i > steps - 12:
                current += random.uniform(-0.65, 0.45)
            if current < last - 0.9:
                current = last - random.uniform(0, 0.4)
            last = current
            y = (
                start_y
                + math.sin(t * math.pi * random.uniform(1.1, 2.8)) * random.uniform(0.2, 1.8)
                + random.uniform(-0.25, 0.25)
            )
            x = start_x + current
            await page.mouse.move(x, y)
            trace.append({"x": round(x, 2), "y": round(y, 2), "t": round(t, 3)})
            await page.wait_for_timeout(max(4, int(duration_ms / steps + random.randint(-6, 8))))

        for dx in (
            distance + overshoot * 0.65,
            distance + overshoot * 0.25,
            distance + random.uniform(-0.25, 0.25),
        ):
            await page.mouse.move(start_x + dx, start_y + random.uniform(-0.5, 0.5), steps=random.randint(1, 3))
            await page.wait_for_timeout(random.randint(40, 120))
        hold_ms = random.randint(520, 1150)
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
              const root = document.querySelector('.yidun');
              const cls = root ? String(root.className || '') : '';
              const tips = document.querySelector('.yidun_tips__text');
              const tip = tips ? tips.textContent : '';
              const fail = /失败|重试|error|fail/i.test(tip) || /yidun--error/.test(cls);
              const successText = /验证成功|验证通过|success/i.test(text) || /yidun--success/.test(cls);
              const validates = window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.validates || [];
              const latest = validates.length ? validates[validates.length - 1].value : null;
              const payloadOk = JSON.stringify(latest || {}).indexOf('validate') >= 0;
              return { success: Boolean(successText || payloadOk), fail, tip, className: cls, latestValidate: latest || null };
            }"""
        )

    async def _refresh_slide(self, page: Any) -> None:
        await page.wait_for_timeout(900)
        refreshed = await page.evaluate(
            """() => {
              const btn = document.querySelector('.yidun_refresh');
              if (btn) { try { btn.click(); return 'click'; } catch {} }
              try {
                if (window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.refreshAll) {
                  window.__ANTIBOT_YIDUN.refreshAll();
                  return 'instance';
                }
              } catch {}
              return '';
            }"""
        )
        await page.wait_for_timeout(1600 if refreshed else 900)

    def _result(
        self,
        raw: dict[str, Any],
        artifacts: dict[str, str],
        proxy_server: str | None,
    ) -> CaptchaResult:
        success = raw.get("success") if isinstance(raw.get("success"), dict) else None
        ok = bool(success and success.get("validate"))
        state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
        configs = state.get("configs") if isinstance(state, dict) else []
        first_config = configs[0].get("config") if configs and isinstance(configs[0], dict) else {}
        error = raw.get("error") or {}
        return CaptchaResult(
            provider="yidun",
            ok=ok,
            ticket=success.get("validate") if success else None,
            randstr=success.get("token") if success else None,
            verify_code="success" if ok else "pending",
            elapsed_ms=raw.get("elapsedMs"),
            artifacts=artifacts,
            diagnostics={
                "target_url": raw.get("targetUrl"),
                "final_url": raw.get("finalUrl"),
                "title": raw.get("title"),
                "captcha_id": first_config.get("captchaId") or first_config.get("captcha_id"),
                "mode": first_config.get("mode"),
                "captcha_type": first_config.get("captchaType") or first_config.get("captcha_type"),
                "configs": len(configs or []),
                "events": len(state.get("events") or []) if isinstance(state, dict) else 0,
                "validates": len(state.get("validates") or []) if isinstance(state, dict) else 0,
                "slide_attempts": len(raw.get("slideAttempts") or []),
                "slide_solved": any((a or {}).get("ok") for a in raw.get("slideAttempts") or []),
                "check_responses": len(raw.get("checkResponses") or []),
                "net_events": len(raw.get("net") or []),
                "trigger_clicks": len(raw.get("triggerClicks") or []),
                "proxy": redacted_proxy(proxy_server),
                "error": error,
            },
            raw=raw,
            errors=[] if ok else [str(error.get("message") or "yidun_not_solved")],
        )
