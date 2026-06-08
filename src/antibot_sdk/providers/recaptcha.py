from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy
from .cloudflare import discover_browser_binary


RECAPTCHA_TOKEN_MIN_LEN = 20

DEFAULT_RECAPTCHA_TRIGGER_SELECTORS = (
    ".g-recaptcha",
    "[data-sitekey]",
    "iframe[src*='google.com/recaptcha']",
    "iframe[src*='recaptcha.net/recaptcha']",
    "textarea[name='g-recaptcha-response']",
)


RECAPTCHA_HOOK_JS = r"""
(() => {
  if (window.__ANTIBOT_RECAPTCHA && window.__ANTIBOT_RECAPTCHA.installed) return;
  const safe = (value, depth = 0) => {
    if (depth > 4) return '[depth]';
    if (value === null || value === undefined) return value;
    const t = typeof value;
    if (t === 'string' || t === 'number' || t === 'boolean') return value;
    if (t === 'function') return `[Function:${value.name || 'anonymous'}]`;
    if (value instanceof Element) {
      const r = value.getBoundingClientRect();
      return { tag: value.tagName, id: value.id || '', className: String(value.className || ''), name: value.getAttribute('name') || '', rect: { x: r.x, y: r.y, width: r.width, height: r.height } };
    }
    if (Array.isArray(value)) return value.slice(0, 50).map(x => safe(x, depth + 1));
    if (t === 'object') {
      const out = {};
      for (const k of Object.keys(value).slice(0, 140)) {
        try { out[k] = safe(value[k], depth + 1); } catch (e) { out[k] = `[throws:${e && e.message}]`; }
      }
      return out;
    }
    return String(value);
  };
  const looksToken = (v) => typeof v === 'string' && v.length >= 20 && /^[A-Za-z0-9._:-]+$/.test(v);
  const state = {
    installed: true,
    at: new Date().toISOString(),
    apis: [],
    renders: [],
    executes: [],
    callbacks: [],
    events: [],
    methodCalls: [],
    responses: [],
    errors: [],
    widgets: [],
    original: {},
    pushEvent(type, detail) { this.events.push({ at: Date.now(), type, detail: safe(detail) }); },
    pushToken(source, token, meta = {}) {
      if (!token) return null;
      const value = String(token);
      this.responses.push({ at: Date.now(), source, token: value, looksToken: looksToken(value), meta: safe(meta) });
      return value;
    },
    scanInputs() {
      const ret = [];
      const sels = [
        'textarea[name="g-recaptcha-response"]',
        'input[name="g-recaptcha-response"]',
        '[name="g-recaptcha-response"]',
        'textarea[name="recaptcha-token"]',
        'input[name="recaptcha-token"]',
      ];
      for (const sel of sels) {
        for (const el of Array.from(document.querySelectorAll(sel))) {
          const token = el.value || el.getAttribute('value') || '';
          ret.push({ selector: sel, token, node: safe(el), looksToken: looksToken(token) });
          if (token) this.pushToken('input-scan', token, { selector: sel });
        }
      }
      return ret;
    },
    scanWidgets() {
      const ret = [];
      const selectors = ['.g-recaptcha', '[data-sitekey]', 'iframe[src*="google.com/recaptcha"]', 'iframe[src*="recaptcha.net/recaptcha"]'];
      const seen = new Set();
      for (const sel of selectors) {
        for (const el of Array.from(document.querySelectorAll(sel))) {
          if (seen.has(el)) continue;
          seen.add(el);
          const r = el.getBoundingClientRect();
          ret.push({
            selector: sel,
            tag: el.tagName,
            id: el.id || '',
            className: String(el.className || ''),
            sitekey: el.getAttribute('data-sitekey') || '',
            size: el.getAttribute('data-size') || '',
            theme: el.getAttribute('data-theme') || '',
            badge: el.getAttribute('data-badge') || '',
            action: el.getAttribute('data-action') || '',
            callback: el.getAttribute('data-callback') || '',
            src: el.getAttribute('src') || '',
            visible: r.width > 2 && r.height > 2 && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden',
            rect: { x: r.x, y: r.y, width: r.width, height: r.height },
          });
        }
      }
      this.widgets = ret;
      return ret;
    },
    latestToken() {
      this.scanInputs();
      for (let i = this.responses.length - 1; i >= 0; i--) {
        const item = this.responses[i];
        if (item && item.token) return item.token;
      }
      return '';
    },
    executeAll() {
      const ret = [];
      const apis = [];
      if (window.grecaptcha) apis.push({ apiName: 'grecaptcha', api: window.grecaptcha });
      if (window.grecaptcha && window.grecaptcha.enterprise) apis.push({ apiName: 'grecaptcha.enterprise', api: window.grecaptcha.enterprise });
      for (const {apiName, api} of apis) {
        if (!api || typeof api.execute !== 'function') continue;
        for (const exec of this.executes.slice(-10)) {
          if (!exec.sitekey) continue;
          try {
            const value = api.execute(exec.sitekey, exec.action ? { action: exec.action } : undefined);
            ret.push({ ok: true, mode: 'sitekey', apiName, sitekey: exec.sitekey, action: exec.action || '', value: safe(value) });
          } catch (e) { ret.push({ ok: false, mode: 'sitekey', apiName, sitekey: exec.sitekey, action: exec.action || '', error: e && e.message }); }
        }
        for (const render of this.renders) {
          try {
            const id = render.widgetId;
            if (id !== undefined && id !== null && id !== '') {
              const value = api.execute(id);
              ret.push({ ok: true, mode: 'widgetId', apiName, widgetId: id, value: safe(value) });
            }
          } catch (e) { ret.push({ ok: false, mode: 'widgetId', apiName, widgetId: render.widgetId, error: e && e.message }); }
        }
      }
      return ret;
    },
    snapshot() {
      return {
        installed: true,
        at: this.at,
        apis: this.apis.slice(-20),
        renders: this.renders.slice(-40),
        executes: this.executes.slice(-60),
        callbacks: this.callbacks.slice(-50),
        events: this.events.slice(-160),
        methodCalls: this.methodCalls.slice(-220),
        responses: this.responses.slice(-60),
        errors: this.errors.slice(-50),
        widgets: this.scanWidgets(),
        inputs: this.scanInputs(),
        latestToken: this.latestToken(),
      };
    },
  };
  window.__ANTIBOT_RECAPTCHA = state;

  const wrapCallbackValue = (value, key, widgetMeta) => {
    if (typeof value === 'function' && !value.__antibotWrapped) {
      const original = value;
      const wrapped = function(...args) {
        state.callbacks.push({ at: Date.now(), key, args: safe(args), widget: safe(widgetMeta) });
        state.pushEvent(`callback:${key}`, args);
        if (key === 'callback' && args[0]) state.pushToken('callback', args[0], { widget: widgetMeta });
        return original.apply(this, args);
      };
      wrapped.__antibotWrapped = true;
      return wrapped;
    }
    return value;
  };

  const wrapOptions = (opts, widgetMeta) => {
    if (!opts || typeof opts !== 'object') return opts;
    const out = opts;
    for (const key of ['callback', 'expired-callback', 'error-callback']) {
      out[key] = wrapCallbackValue(out[key], key, widgetMeta);
    }
    return out;
  };

  const wrapApi = (api, apiName) => {
    if (!api || (typeof api !== 'object' && typeof api !== 'function') || api.__antibotWrapped) return api;
    const original = api;
    state.apis.push({ at: Date.now(), apiName, keys: Object.keys(original).slice(0, 40) });
    const wrapMethod = (name) => {
      if (typeof original[name] !== 'function' || original[name].__antibotWrapped) return;
      const fn = original[name];
      const wrapped = function(...args) {
        state.methodCalls.push({ at: Date.now(), apiName, method: name, args: safe(args) });
        if (name === 'render') {
          const container = args[0];
          const opts = args[1] || {};
          const widgetMeta = {
            apiName,
            container: safe(container),
            sitekey: opts.sitekey || (container && container.getAttribute && container.getAttribute('data-sitekey')) || '',
            size: opts.size || (container && container.getAttribute && container.getAttribute('data-size')) || '',
            theme: opts.theme || (container && container.getAttribute && container.getAttribute('data-theme')) || '',
            badge: opts.badge || (container && container.getAttribute && container.getAttribute('data-badge')) || '',
            action: opts.action || (container && container.getAttribute && container.getAttribute('data-action')) || '',
            tabindex: opts.tabindex || (container && container.getAttribute && container.getAttribute('data-tabindex')) || '',
            callbackName: typeof opts.callback === 'string' ? opts.callback : '',
          };
          args[1] = wrapOptions(opts, widgetMeta);
          const widgetId = fn.apply(this, args);
          state.renders.push({ at: Date.now(), widgetId: safe(widgetId), ...safe(widgetMeta) });
          state.pushEvent('render', { apiName, widgetId, widgetMeta });
          return widgetId;
        }
        if (name === 'execute') {
          const sitekey = typeof args[0] === 'string' ? args[0] : '';
          const action = args[1] && typeof args[1] === 'object' ? (args[1].action || '') : '';
          const widgetId = sitekey ? '' : safe(args[0]);
          state.executes.push({ at: Date.now(), apiName, sitekey, action, widgetId, args: safe(args) });
          const ret = fn.apply(this, args);
          if (ret && typeof ret.then === 'function') {
            ret.then((token) => {
              state.pushEvent('execute-resolved', { apiName, sitekey, action, token });
              if (typeof token === 'string') state.pushToken('execute-resolved', token, { apiName, sitekey, action });
            }).catch((e) => state.errors.push({ at: Date.now(), source: `${apiName}.execute`, message: e && e.message || String(e), sitekey, action }));
          } else if (typeof ret === 'string') {
            state.pushToken('execute-return', ret, { apiName, sitekey, action });
          }
          return ret;
        }
        const ret = fn.apply(this, args);
        if (name === 'getResponse') state.pushToken('getResponse', ret, { apiName, args: safe(args) });
        return ret;
      };
      wrapped.__antibotWrapped = true;
      original[name] = wrapped;
    };
    for (const name of ['render', 'execute', 'reset', 'getResponse', 'ready']) wrapMethod(name);
    if (original.enterprise) {
      original.enterprise = wrapApi(original.enterprise, 'grecaptcha.enterprise');
    }
    try {
      let enterpriseCurrent = original.enterprise;
      Object.defineProperty(original, 'enterprise', {
        configurable: true,
        enumerable: true,
        get() { return enterpriseCurrent; },
        set(v) {
          state.pushEvent('enterprise-set', { type: typeof v, keys: v && Object.keys(v).slice(0, 20) });
          enterpriseCurrent = wrapApi(v, 'grecaptcha.enterprise');
        },
      });
      if (enterpriseCurrent) enterpriseCurrent = wrapApi(enterpriseCurrent, 'grecaptcha.enterprise');
    } catch (e) {
      state.errors.push({ at: Date.now(), source: 'enterprise.defineProperty', message: e && e.message });
    }
    try { original.__antibotWrapped = true; } catch {}
    return original;
  };

  let current = window.grecaptcha;
  try {
    Object.defineProperty(window, 'grecaptcha', {
      configurable: true,
      enumerable: true,
      get() { return current; },
      set(v) {
        state.pushEvent('grecaptcha-set', { type: typeof v, keys: v && Object.keys(v).slice(0, 30) });
        state.original.grecaptcha = v;
        current = wrapApi(v, 'grecaptcha');
      },
    });
    if (current) current = wrapApi(current, 'grecaptcha');
  } catch (e) {
    state.errors.push({ at: Date.now(), source: 'defineProperty:grecaptcha', message: e && e.message });
    if (window.grecaptcha) window.grecaptcha = wrapApi(window.grecaptcha, 'grecaptcha');
  }
})();
"""


def is_recaptcha_token(value: Any, *, min_len: int = RECAPTCHA_TOKEN_MIN_LEN) -> bool:
    if not isinstance(value, str):
        return False
    token = value.strip()
    if len(token) < min_len:
        return False
    return all(ch.isalnum() or ch in "._:-" for ch in token)


def latest_recaptcha_token(state: dict[str, Any] | None) -> str | None:
    if not isinstance(state, dict):
        return None
    latest = state.get("latestToken")
    if is_recaptcha_token(latest):
        return str(latest)
    for source in ("responses", "inputs"):
        for item in reversed(state.get(source) or []):
            if not isinstance(item, dict):
                continue
            token = item.get("token")
            if is_recaptcha_token(token):
                return str(token)
    return None


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
            "google.com/recaptcha",
            "recaptcha.net/recaptcha",
            "www.recaptcha.net",
            "/recaptcha/",
            "api2/anchor",
            "api2/reload",
            "enterprise/anchor",
            "enterprise/reload",
        )
    )


class ReCaptchaSolver:
    """reCAPTCHA / reCAPTCHA Enterprise browser observer/collector."""

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
        locale: str | None = "en-US",
        timezone_id: str | None = "America/New_York",
    ) -> CaptchaResult:
        started = time.monotonic()
        output_root = Path(output_dir or f"/tmp/antibot-recaptcha-{int(time.time() * 1000)}")
        output_root.mkdir(parents=True, exist_ok=True)
        out = output_root / "recaptcha_run.json"
        artifacts = {"out": str(out), "outputDir": str(output_root)}
        raw: dict[str, Any] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "targetUrl": target_url,
            "net": [],
            "triggerSelectors": list(trigger_selectors or DEFAULT_RECAPTCHA_TRIGGER_SELECTORS),
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
            binary = browser_binary or discover_browser_binary()
            if binary:
                launch_kwargs["executable_path"] = binary
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
            await page.add_init_script(RECAPTCHA_HOOK_JS)

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
                    if "json" in ctype or "text" in ctype or "javascript" in ctype:
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
                raw["executeCalls"] = await page.evaluate(
                    "() => window.__ANTIBOT_RECAPTCHA && window.__ANTIBOT_RECAPTCHA.executeAll ? window.__ANTIBOT_RECAPTCHA.executeAll() : []"
                )
                raw["triggerClicks"] = await self._trigger_visible_widgets(page, raw["triggerSelectors"])

            state: dict[str, Any] | None = None
            token: str | None = None
            deadline = time.monotonic() + max(1, timeout_sec)
            while time.monotonic() < deadline:
                state = await page.evaluate(
                    "() => window.__ANTIBOT_RECAPTCHA && window.__ANTIBOT_RECAPTCHA.snapshot ? window.__ANTIBOT_RECAPTCHA.snapshot() : null"
                )
                token = latest_recaptcha_token(state)
                if token:
                    break
                await page.wait_for_timeout(500)

            if response_tasks:
                await asyncio.gather(*response_tasks, return_exceptions=True)

            raw["state"] = state or {}
            raw["token"] = token
            raw["ok"] = bool(token)
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)

            if screenshot:
                p = output_root / "recaptcha_page.png"
                try:
                    await page.screenshot(path=str(p), full_page=True)
                    artifacts["screenshot"] = str(p)
                except Exception as e:
                    raw["screenshotError"] = str(e)
            if save_html:
                p = output_root / "recaptcha_page.html"
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

    async def _trigger_visible_widgets(self, page: Any, selectors: list[str]) -> list[dict[str, Any]]:
        return await page.evaluate(
            """async (selectors) => {
              const sleep = (ms) => new Promise(r => setTimeout(r, ms));
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
                for (const el of nodes.slice(0, 8)) {
                  if (!visible(el)) continue;
                  const r = el.getBoundingClientRect();
                  try {
                    el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                    el.click();
                    el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 }));
                    await sleep(120);
                    ret.push({ selector: sel, tag: el.tagName, id: el.id || '', className: String(el.className || ''), rect: { x: r.x, y: r.y, width: r.width, height: r.height } });
                  } catch (e) { ret.push({ selector: sel, error: e.message }); }
                  if (ret.length >= 16) return ret;
                }
              }
              return ret;
            }""",
            selectors,
        )

    def _result(
        self,
        raw: dict[str, Any],
        artifacts: dict[str, str],
        proxy_server: str | None,
    ) -> CaptchaResult:
        token = raw.get("token") if is_recaptcha_token(raw.get("token")) else None
        ok = bool(token)
        state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
        renders = state.get("renders") if isinstance(state, dict) else []
        executes = state.get("executes") if isinstance(state, dict) else []
        widgets = state.get("widgets") if isinstance(state, dict) else []
        first_render = renders[0] if renders and isinstance(renders[0], dict) else {}
        first_execute = executes[0] if executes and isinstance(executes[0], dict) else {}
        first_widget = widgets[0] if widgets and isinstance(widgets[0], dict) else {}
        error = raw.get("error") or {}
        sitekey = first_execute.get("sitekey") or first_render.get("sitekey") or first_widget.get("sitekey") or None
        action = first_execute.get("action") or first_render.get("action") or first_widget.get("action")
        api_name = first_execute.get("apiName") or first_render.get("apiName")
        return CaptchaResult(
            provider="recaptcha",
            ok=ok,
            ticket=token,
            verify_code="success" if ok else "pending",
            elapsed_ms=raw.get("elapsedMs"),
            artifacts=artifacts,
            diagnostics={
                "target_url": raw.get("targetUrl"),
                "final_url": raw.get("finalUrl"),
                "title": raw.get("title"),
                "sitekey": sitekey,
                "render_sitekey": first_render.get("sitekey") or first_widget.get("sitekey"),
                "execute_sitekey": first_execute.get("sitekey"),
                "action": action,
                "api": api_name,
                "size": first_render.get("size") or first_widget.get("size"),
                "theme": first_render.get("theme") or first_widget.get("theme"),
                "renders": len(renders or []),
                "executes": len(executes or []),
                "widgets": len(widgets or []),
                "responses": len(state.get("responses") or []) if isinstance(state, dict) else 0,
                "callbacks": len(state.get("callbacks") or []) if isinstance(state, dict) else 0,
                "net_events": len(raw.get("net") or []),
                "trigger_clicks": len(raw.get("triggerClicks") or []),
                "execute_calls": len(raw.get("executeCalls") or []),
                "proxy": redacted_proxy(proxy_server),
                "error": error,
            },
            raw=raw,
            errors=[] if ok else [str(error.get("message") or "recaptcha_not_solved")],
        )
