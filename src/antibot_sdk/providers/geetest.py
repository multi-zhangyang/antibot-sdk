from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    snapshot() {
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

            await page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_sec * 1000)
            if wait_after_load_ms > 0:
                await page.wait_for_timeout(wait_after_load_ms)

            raw["title"] = await page.title()
            raw["finalUrl"] = page.url

            if auto_trigger:
                raw["showCaptchaCalls"] = await page.evaluate(
                    "() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.showAll ? window.__ANTIBOT_GEETEST.showAll() : []"
                )
                raw["triggerClicks"] = await page.evaluate(
                    """(selectors) => {
                      const ret = [];
                      const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const cs = getComputedStyle(el);
                        return r.width > 3 && r.height > 3 && cs.display !== 'none' && cs.visibility !== 'hidden';
                      };
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
                          } catch (e) { ret.push({ selector: sel, error: e.message }); }
                          if (ret.length >= 12) return ret;
                        }
                      }
                      return ret;
                    }""",
                    raw["triggerSelectors"],
                )

            state: dict[str, Any] | None = None
            success: dict[str, Any] | None = None
            deadline = time.monotonic() + max(1, timeout_sec)
            while time.monotonic() < deadline:
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
                "net_events": len(raw.get("net") or []),
                "trigger_clicks": len(raw.get("triggerClicks") or []),
                "proxy": redacted_proxy(proxy_server),
                "error": error,
            },
            raw=raw,
            errors=[] if ok else [str(error.get("message") or "geetest_not_solved")],
        )
