from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .models import CaptchaResult
from .proxy import parse_proxy, redacted_proxy
from .providers.cloudflare import discover_browser_binary

VerificationState = Literal["passed", "failed", "unknown"]
FailureClass = Literal[
    "none",
    "token_missing",
    "token_rejected",
    "action_mismatch",
    "hostname_mismatch",
    "low_score",
    "session_binding_failed",
    "form_flow_failed",
    "image_challenge_required",
    "navigation_failed",
    "timeout",
    "unknown",
]

TOKEN_FIELD_BY_PROVIDER = {
    "turnstile": "cf-turnstile-response",
    "hcaptcha": "h-captcha-response",
    "recaptcha": "g-recaptcha-response",
}


@dataclass(slots=True)
class SubmitFlow:
    """Declarative browser-side submit flow for token-based CAPTCHA pages."""

    provider: str
    url: str
    token: str | None = None
    token_field: str | None = None
    submit_selector: str | None = None
    success_selector: str | None = None
    failure_selector: str | None = None
    expected_url_contains: str | None = None
    token_value_selector: str | None = None
    prefill: dict[str, str] = field(default_factory=dict)
    clicks: list[str] = field(default_factory=list)
    wait_after_submit_ms: int = 2000
    timeout_sec: int = 60
    output_dir: str | None = None
    headless: bool | str | None = True
    proxy_server: str | None = None
    browser_binary: str | None = None
    user_agent: str | None = None
    locale: str | None = "en-US"
    timezone_id: str | None = "America/New_York"


@dataclass(slots=True)
class VerificationResult:
    provider: str
    ok: bool
    state: VerificationState
    token_collected: bool = False
    server_verified: bool = False
    flow_passed: bool = False
    failure_class: FailureClass = "unknown"
    reason: str = ""
    elapsed_ms: int | None = None
    token: str | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class FailureClassifier:
    """Heuristic classifier for submit/verify failures."""

    @staticmethod
    def classify(*, token: str | None, raw: dict[str, Any], text: str = "") -> tuple[FailureClass, str]:
        if not token:
            return "token_missing", "no token was collected/provided"
        error = raw.get("error") if isinstance(raw, dict) else {}
        error_text = json.dumps(error, ensure_ascii=False, default=str).lower() if error else ""
        reason_text = str(raw.get("reason") or "").lower() if isinstance(raw, dict) else ""
        body_text = (text or "").lower()
        raw_text_fields: list[str] = []
        if isinstance(raw, dict):
            for key in ("body", "bodyText", "text", "message", "statusText", "verifyResponse", "response", "oracle"):
                val = raw.get(key)
                if val not in (None, "", [], {}):
                    raw_text_fields.append(json.dumps(val, ensure_ascii=False, default=str).lower())
        # Avoid matching structural keys like "timeout_sec"; timeout classification
        # should come from an actual error/reason/body message.
        if any(x in "\n".join([error_text, reason_text, body_text, *raw_text_fields]) for x in ("timeout", "timed out")):
            return "timeout", "timeout while submitting or observing result"
        hay = "\n".join([
            body_text,
            error_text,
            reason_text,
            *raw_text_fields,
        ])
        if any(x in hay for x in ("invalid-input-response", "invalid token", "token invalid", "captcha invalid", "invalid captcha", "recaptcha failed", "hcaptcha failed", "turnstile failed")):
            return "token_rejected", "server/page indicated token rejection"
        if any(x in hay for x in ("action mismatch", "expected action", "invalid action")):
            return "action_mismatch", "server/page indicated action mismatch"
        if any(x in hay for x in ("hostname mismatch", "invalid hostname", "domain mismatch")):
            return "hostname_mismatch", "server/page indicated hostname/domain mismatch"
        if any(x in hay for x in ("low score", "score too low", "risk score", "bot score")):
            return "low_score", "server/page indicated low score"
        if any(x in hay for x in ("session", "csrf", "state mismatch", "nonce")) and any(x in hay for x in ("invalid", "mismatch", "expired", "missing")):
            return "session_binding_failed", "token likely failed session/csrf binding"
        if any(x in hay for x in ("select all", "image challenge", "checkbox", "try again", "challenge")):
            return "image_challenge_required", "interactive challenge appears required"
        if any(x in hay for x in ("navigation failed", "net::", "page.goto")):
            return "navigation_failed", "navigation failed"
        return "unknown", "no specific failure signature matched"


class SuccessOracle:
    """Browser-side oracle for deciding whether a submitted flow actually passed."""

    @staticmethod
    async def evaluate(page: Any, flow: SubmitFlow) -> tuple[VerificationState, dict[str, Any]]:
        checks: dict[str, Any] = {}
        if flow.success_selector:
            checks["success_selector"] = await _selector_state(page, flow.success_selector)
            if checks["success_selector"].get("visible"):
                return "passed", checks
        if flow.failure_selector:
            checks["failure_selector"] = await _selector_state(page, flow.failure_selector)
            if checks["failure_selector"].get("visible"):
                return "failed", checks
        if flow.expected_url_contains:
            url = page.url
            checks["expected_url_contains"] = {
                "needle": flow.expected_url_contains,
                "url": url,
                "matched": flow.expected_url_contains in url,
            }
            if checks["expected_url_contains"]["matched"]:
                return "passed", checks
        return "unknown", checks


async def _selector_state(page: Any, selector: str) -> dict[str, Any]:
    return await page.evaluate(
        r"""(selector) => {
          const el = document.querySelector(selector);
          if (!el) return { exists: false, visible: false };
          const r = el.getBoundingClientRect();
          const cs = getComputedStyle(el);
          return {
            exists: true,
            visible: r.width > 1 && r.height > 1 && cs.display !== 'none' && cs.visibility !== 'hidden',
            text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 500),
            value: el.value || '',
            rect: { x: r.x, y: r.y, width: r.width, height: r.height },
          };
        }""",
        selector,
    )


def _headless(value: bool | str | None) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return value.lower() not in {"0", "false", "headed", "no"}


def _default_token_field(provider: str) -> str:
    return TOKEN_FIELD_BY_PROVIDER.get(provider, "captcha-response")


def _token_from_captcha(result: CaptchaResult | None) -> str | None:
    if not result:
        return None
    return result.ticket or result.randstr or (result.raw or {}).get("token")


async def verify_submit_flow(
    flow: SubmitFlow,
    *,
    captcha_result: CaptchaResult | None = None,
) -> VerificationResult:
    """Submit a token into a real page and classify whether the flow passed."""

    started = time.monotonic()
    token = flow.token or _token_from_captcha(captcha_result)
    output_root = Path(flow.output_dir or f"/tmp/antibot-verify-{flow.provider}-{int(time.time() * 1000)}")
    output_root.mkdir(parents=True, exist_ok=True)
    out = output_root / "verification_run.json"
    artifacts = {"out": str(out), "outputDir": str(output_root)}
    raw: dict[str, Any] = {
        "at": datetime.now(timezone.utc).isoformat(),
        "provider": flow.provider,
        "url": flow.url,
        "tokenCollected": bool(token),
        "captchaResult": _compact_captcha(captcha_result),
        "flow": _compact_flow(flow),
        "events": [],
    }

    async def write_raw() -> None:
        out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

    if not token:
        failure_class, reason = FailureClassifier.classify(token=token, raw=raw)
        raw["failureClass"] = failure_class
        raw["reason"] = reason
        raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
        await write_raw()
        return VerificationResult(
            provider=flow.provider,
            ok=False,
            state="failed",
            token_collected=False,
            server_verified=False,
            flow_passed=False,
            failure_class=failure_class,
            reason=reason,
            elapsed_ms=raw["elapsedMs"],
            token=None,
            artifacts=artifacts,
            diagnostics={"proxy": redacted_proxy(flow.proxy_server), "token_field": flow.token_field or _default_token_field(flow.provider)},
            raw=raw,
            errors=[reason],
        )

    browser = None
    playwright = None
    try:
        from playwright.async_api import async_playwright

        playwright = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": _headless(flow.headless),
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        }
        binary = flow.browser_binary or discover_browser_binary()
        if binary:
            launch_kwargs["executable_path"] = binary
        proxy_cfg = parse_proxy(flow.proxy_server).playwright() if flow.proxy_server else None
        if proxy_cfg:
            launch_kwargs["proxy"] = proxy_cfg
        browser = await playwright.chromium.launch(**launch_kwargs)
        context_kwargs: dict[str, Any] = {
            "locale": flow.locale,
            "timezone_id": flow.timezone_id,
            "ignore_https_errors": True,
        }
        if flow.user_agent:
            context_kwargs["user_agent"] = flow.user_agent
        context = await browser.new_context(**context_kwargs)
        page = await context.new_page()
        page.on("request", lambda req: raw["events"].append({"type": "request", "method": req.method, "url": req.url, "at": int(time.time() * 1000)}) if len(raw["events"]) < 300 else None)
        page.on("response", lambda resp: raw["events"].append({"type": "response", "status": resp.status, "url": resp.url, "at": int(time.time() * 1000)}) if len(raw["events"]) < 300 else None)

        await page.goto(flow.url, wait_until="domcontentloaded", timeout=flow.timeout_sec * 1000)
        raw["title"] = await page.title()
        raw["initialUrl"] = page.url

        raw["prefill"] = []
        for selector, value in flow.prefill.items():
            raw["prefill"].append(await _fill_or_set(page, selector, value))
        raw["preClicks"] = []
        for selector in flow.clicks:
            raw["preClicks"].append(await _click(page, selector))

        token_field = flow.token_field or _default_token_field(flow.provider)
        inject = await page.evaluate(
            """({field, token, explicitSelector}) => {
              const selectors = [];
              if (explicitSelector) selectors.push(explicitSelector);
              selectors.push(`[name="${field}"]`, `textarea[name="${field}"]`, `input[name="${field}"]`);
              if (field !== 'g-recaptcha-response') selectors.push('[name="g-recaptcha-response"]');
              if (field !== 'h-captcha-response') selectors.push('[name="h-captcha-response"]');
              if (field !== 'cf-turnstile-response') selectors.push('[name="cf-turnstile-response"]');
              const touched = [];
              for (const sel of selectors) {
                let nodes = [];
                try { nodes = Array.from(document.querySelectorAll(sel)); } catch { continue; }
                for (const el of nodes) {
                  try {
                    el.value = token;
                    el.setAttribute('value', token);
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    touched.push({ selector: sel, tag: el.tagName, name: el.getAttribute('name') || '' });
                  } catch (e) { touched.push({ selector: sel, error: e.message }); }
                }
              }
              if (!touched.length) {
                const form = document.querySelector('form') || document.body;
                const ta = document.createElement('textarea');
                ta.name = field;
                ta.style.display = 'none';
                ta.value = token;
                form.appendChild(ta);
                touched.push({ selector: 'created', tag: 'TEXTAREA', name: field });
              }
              return touched;
            }""",
            {"field": token_field, "token": token, "explicitSelector": flow.token_value_selector},
        )
        raw["tokenInjection"] = inject

        if flow.submit_selector:
            raw["submit"] = await _click(page, flow.submit_selector)
        else:
            raw["submit"] = await page.evaluate(
                """() => {
                  const form = document.querySelector('form');
                  if (form) {
                    if (form.requestSubmit) form.requestSubmit();
                    else form.submit();
                    return { mode: 'form', ok: true };
                  }
                  return { mode: 'none', ok: false, error: 'no submit_selector and no form' };
                }"""
            )
        await page.wait_for_timeout(max(0, flow.wait_after_submit_ms))
        state, oracle = await SuccessOracle.evaluate(page, flow)
        raw["oracle"] = oracle
        raw["state"] = state
        raw["finalUrl"] = page.url
        raw["titleAfter"] = await page.title()
        try:
            raw["bodyText"] = (await page.locator("body").inner_text(timeout=3000))[:5000]
        except Exception as e:
            raw["bodyTextError"] = str(e)

        p = output_root / "verification_page.png"
        try:
            await page.screenshot(path=str(p), full_page=True)
            artifacts["screenshot"] = str(p)
        except Exception as e:
            raw["screenshotError"] = str(e)
        p = output_root / "verification_page.html"
        try:
            p.write_text(await page.content(), encoding="utf-8")
            artifacts["html"] = str(p)
        except Exception as e:
            raw["htmlError"] = str(e)

        if state == "passed":
            failure_class: FailureClass = "none"
            reason = "success oracle matched"
        else:
            failure_class, reason = FailureClassifier.classify(token=token, raw=raw, text=raw.get("bodyText") or "")
            if failure_class == "unknown" and state == "failed":
                failure_class, reason = "form_flow_failed", "failure selector matched"
            elif failure_class == "unknown":
                reason = "token submitted but success oracle did not match"
        raw["failureClass"] = failure_class
        raw["reason"] = reason
        raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
        await write_raw()
        return VerificationResult(
            provider=flow.provider,
            ok=state == "passed",
            state=state,
            token_collected=True,
            server_verified=state == "passed",
            flow_passed=state == "passed",
            failure_class=failure_class,
            reason=reason,
            elapsed_ms=raw["elapsedMs"],
            token=token,
            artifacts=artifacts,
            diagnostics={
                "proxy": redacted_proxy(flow.proxy_server),
                "token_field": token_field,
                "oracle": oracle,
                "submit": raw.get("submit"),
                "initial_url": raw.get("initialUrl"),
                "final_url": raw.get("finalUrl"),
            },
            raw=raw,
            errors=[] if state == "passed" else [reason],
        )
    except asyncio.TimeoutError:
        raw["error"] = {"type": "TimeoutError", "message": f"timeout after {flow.timeout_sec}s"}
        failure_class, reason = "timeout", raw["error"]["message"]
    except Exception as e:
        raw["error"] = {"type": type(e).__name__, "message": str(e)}
        failure_class, reason = FailureClassifier.classify(token=token, raw=raw)
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

    raw["failureClass"] = failure_class
    raw["reason"] = reason
    raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
    await write_raw()
    return VerificationResult(
        provider=flow.provider,
        ok=False,
        state="failed",
        token_collected=bool(token),
        server_verified=False,
        flow_passed=False,
        failure_class=failure_class,
        reason=reason,
        elapsed_ms=raw["elapsedMs"],
        token=token,
        artifacts=artifacts,
        diagnostics={"proxy": redacted_proxy(flow.proxy_server), "token_field": flow.token_field or _default_token_field(flow.provider)},
        raw=raw,
        errors=[reason],
    )


async def _fill_or_set(page: Any, selector: str, value: str) -> dict[str, Any]:
    try:
        await page.fill(selector, value, timeout=3000)
        return {"selector": selector, "ok": True, "mode": "fill"}
    except Exception:
        return await page.evaluate(
            """({selector, value}) => {
              const el = document.querySelector(selector);
              if (!el) return { selector, ok: false, error: 'not found' };
              el.value = value;
              el.setAttribute('value', value);
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              return { selector, ok: true, mode: 'set' };
            }""",
            {"selector": selector, "value": value},
        )


async def _click(page: Any, selector: str) -> dict[str, Any]:
    try:
        await page.click(selector, timeout=5000)
        return {"selector": selector, "ok": True, "mode": "click"}
    except Exception as e:
        return {"selector": selector, "ok": False, "error": str(e)}


def _compact_captcha(result: CaptchaResult | None) -> dict[str, Any] | None:
    if not result:
        return None
    return {
        "provider": result.provider,
        "ok": result.ok,
        "verify_code": result.verify_code,
        "token_present": bool(result.ticket or result.raw.get("token")),
        "diagnostics": result.diagnostics,
        "artifacts": result.artifacts,
        "errors": result.errors,
    }


def _compact_flow(flow: SubmitFlow) -> dict[str, Any]:
    return {
        "provider": flow.provider,
        "url": flow.url,
        "token_present": bool(flow.token),
        "token_field": flow.token_field,
        "submit_selector": flow.submit_selector,
        "success_selector": flow.success_selector,
        "failure_selector": flow.failure_selector,
        "expected_url_contains": flow.expected_url_contains,
        "prefill_keys": list(flow.prefill),
        "clicks": flow.clicks,
        "timeout_sec": flow.timeout_sec,
        "proxy": redacted_proxy(flow.proxy_server),
    }
