# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pydoll-python>=2.23.0",
# ]
# ///
"""Prototype product: robust Pydoll anti-bot browser runner.

Use as a CLI:
    uv run scripts/pydoll_antibot_runner.py https://example.com --selector title=h1

Or import run_once()/diagnose_environment() from another script.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata as metadata
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

from pydoll.browser import Chrome
from pydoll.browser.options import ChromiumOptions
from pydoll.commands import EmulationCommands, PageCommands
from pydoll.exceptions import (
    ElementNotFound,
    FailedToStartBrowser,
    NavigationError,
    PageLoadTimeout,
    WaitElementTimeout,
)
from pydoll.protocol.fetch.events import FetchEvent, RequestPausedEvent
from pydoll.protocol.network.types import ErrorReason

LOG = logging.getLogger("pydoll-antibot-runner")

ChallengeState = Literal["clear", "challenge", "blocked", "unknown"]
HeadlessMode = Literal["auto", "true", "false"]

CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "performing security verification",
    "checking if the site connection is secure",
    "enable javascript and cookies to continue",
    "cf-browser-verification",
    "_cf_chl_opt",
    "cf_chl_opt",
)

CLEAR_MARKERS = (
    "you bypassed the cloudflare challenge",
    "nowsecure by nodriver",
)

BLOCK_MARKERS = (
    "attention required",
    "access denied",
    "error 1020",
    "you have been blocked",
    "datadome",
    "perimeterx",
    "akamai bot manager",
)

DEFAULT_BLOCKED_RESOURCE_TYPES = {"Image", "Font", "Media"}


@dataclass(slots=True)
class RunnerConfig:
    url: str
    mode: Literal["auto", "turnstile", "managed", "scrape", "diagnose"] = "auto"
    headless: HeadlessMode = "auto"
    browser_binary: str | None = None
    proxy: str | None = None
    profile_dir: str | None = None
    accept_languages: str = "en-US,en"
    user_agent: str | None = None
    platform: str | None = None
    viewport: str = "1920,1080"
    startup_timeout: int = 45
    navigation_timeout: int = 90
    max_wait: int = 90
    captcha_wait: float = 8.0
    screenshot: str | None = None
    html_output: str | None = None
    output_json: str | None = None
    selectors: dict[str, str] = field(default_factory=dict)
    clicks: list[str] = field(default_factory=list)
    wait_after_click: float = 3.0
    block_resources: bool = False
    block_stylesheets: bool = False
    inject_fingerprint_patch: bool = True
    human_probe: bool = True
    verbose: bool = False


@dataclass(slots=True)
class RunResult:
    ok: bool
    url: str
    final_url: str = ""
    title: str = ""
    state: ChallengeState = "unknown"
    elapsed_sec: float = 0.0
    browser_binary: str = ""
    headless: bool = True
    pydoll_version: str = ""
    selectors: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def pydoll_version() -> str:
    try:
        return metadata.version("pydoll-python")
    except metadata.PackageNotFoundError:
        return "unknown"


def _path_is_executable(path: str | Path | None) -> bool:
    if not path:
        return False
    p = Path(path)
    return p.is_file() and os.access(str(p), os.X_OK)


def discover_browser_binary(explicit: str | None = None) -> str | None:
    """Find a Chromium/Chrome binary without assuming google-chrome-stable exists."""
    candidates: list[str] = []
    for value in (
        explicit,
        os.environ.get("PYDOLL_BROWSER_BINARY"),
        os.environ.get("CHROME_BINARY"),
        os.environ.get("CHROME_PATH"),
    ):
        if value:
            candidates.append(value)

    # Prefer regular Google Chrome if present. Snap Chromium is discovered later because
    # it often fails in containerized/root CI profiles.
    for name in ("google-chrome-stable", "google-chrome", "chrome"):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    # Playwright's Chrome for Testing is common in CI and is more reliable than Snap Chromium.
    for root in (Path.home() / ".cache" / "ms-playwright", Path("/ms-playwright")):
        if root.exists():
            for path in sorted(root.glob("chromium-*/chrome-linux*/chrome"), reverse=True):
                candidates.append(str(path))

    for name in ("chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _path_is_executable(candidate):
            return candidate
    return None


def detect_chrome_major(binary: str | None) -> str:
    if not binary:
        return "120"
    try:
        proc = subprocess.run(
            [binary, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=3,
            check=False,
        )
        for token in proc.stdout.replace("/", " ").split():
            if token and token[0].isdigit() and "." in token:
                return token.split(".", 1)[0]
    except Exception:
        pass
    return "120"


def default_user_agent(binary: str | None) -> str:
    major = detect_chrome_major(binary)
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    )


def infer_platform(user_agent: str) -> str:
    if "Windows" in user_agent:
        return "Win32"
    if "Macintosh" in user_agent or "Mac OS X" in user_agent:
        return "MacIntel"
    return "Linux x86_64"


def user_agent_metadata(user_agent: str) -> dict[str, Any]:
    major = "120"
    if "Chrome/" in user_agent:
        major = user_agent.split("Chrome/", 1)[1].split(".", 1)[0]
    elif "Chromium/" in user_agent:
        major = user_agent.split("Chromium/", 1)[1].split(".", 1)[0]
    platform = "Windows" if "Windows" in user_agent else "macOS" if "Macintosh" in user_agent else "Linux"
    return {
        "brands": [
            {"brand": "Chromium", "version": major},
            {"brand": "Google Chrome", "version": major},
            {"brand": "Not_A Brand", "version": "99"},
        ],
        "fullVersionList": [
            {"brand": "Chromium", "version": f"{major}.0.0.0"},
            {"brand": "Google Chrome", "version": f"{major}.0.0.0"},
            {"brand": "Not_A Brand", "version": "99.0.0.0"},
        ],
        "platform": platform,
        "platformVersion": "10.0.0" if platform == "Windows" else "",
        "architecture": "x86",
        "model": "",
        "mobile": False,
        "bitness": "64",
        "wow64": False,
    }


def add_argument_once(options: ChromiumOptions, argument: str) -> None:
    try:
        options.add_argument(argument)
    except Exception:
        # ChromiumOptions raises when duplicated; duplicates are harmless for our use.
        pass


def resolve_headless(mode: str, requested: HeadlessMode) -> bool:
    if requested == "true":
        return True
    if requested == "false":
        # Without DISPLAY, headed Chrome crashes on VPS/container hosts.
        # Force headless unless the caller already has a virtual display.
        if not os.environ.get("DISPLAY"):
            LOG.warning("headless=false requested but DISPLAY is unset; forcing headless")
            return True
        return False
    # Managed challenges historically prefer headed browsers. On headless VPS
    # hosts (no DISPLAY), fall back to headless instead of hard-failing.
    if mode == "managed":
        if os.environ.get("DISPLAY"):
            return False
        LOG.info("managed mode without DISPLAY; using headless fallback")
        return True
    return True


def build_options(config: RunnerConfig, headless: bool) -> tuple[ChromiumOptions, str | None]:
    options = ChromiumOptions()
    options.headless = headless
    options.start_timeout = config.startup_timeout

    browser_binary = discover_browser_binary(config.browser_binary)
    if browser_binary:
        options.binary_location = browser_binary

    width, height = _parse_viewport(config.viewport)
    user_agent = config.user_agent or default_user_agent(browser_binary)
    primary_lang = config.accept_languages.split(",", 1)[0].strip() or "en-US"

    for argument in (
        f"--window-size={width},{height}",
        f"--user-agent={user_agent}",
        f"--lang={primary_lang}",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--use-gl=swiftshader",
        "--enable-unsafe-swiftshader",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--password-store=basic",
        "--use-mock-keychain",
    ):
        add_argument_once(options, argument)

    if config.profile_dir:
        profile = Path(config.profile_dir).expanduser().resolve()
        profile.mkdir(parents=True, exist_ok=True)
        add_argument_once(options, f"--user-data-dir={profile}")

    if config.proxy:
        # Chromium rejects credentials embedded in --proxy-server. Callers that
        # still pass auth URLs must bridge them first (see run_once).
        from ..proxy import chromium_proxy_server, parse_proxy

        cfg = parse_proxy(config.proxy)
        if cfg is not None and not cfg.has_auth:
            server = chromium_proxy_server(config.proxy)
            if server:
                add_argument_once(options, f"--proxy-server={server}")
        elif cfg is not None and cfg.has_auth:
            LOG.warning(
                "Ignoring authenticated proxy in build_options; bridge it first "
                "(proxy-chain local anonymize)."
            )

    fake_engagement_time = int(time.time()) - random.randint(14, 45) * 24 * 60 * 60
    options.browser_preferences = {
        "profile": {
            "last_engagement_time": fake_engagement_time,
            "exit_type": "Normal",
            "exited_cleanly": True,
            "password_manager_enabled": False,
            "default_content_setting_values": {
                "notifications": 2,
                "geolocation": 2,
                "media_stream_camera": 2,
                "media_stream_mic": 2,
            },
        },
        "credentials_enable_service": False,
    }
    options.set_accept_languages(config.accept_languages)
    options.block_notifications = True
    options.block_popups = True
    options.password_manager_enabled = False
    options.webrtc_leak_protection = True
    return options, browser_binary


def _parse_viewport(raw: str) -> tuple[int, int]:
    try:
        width_s, height_s = raw.lower().replace("x", ",").split(",", 1)
        width, height = int(width_s), int(height_s)
    except Exception as exc:
        raise argparse.ArgumentTypeError("viewport must look like 1920,1080") from exc
    if width < 640 or height < 480:
        raise argparse.ArgumentTypeError("viewport is too small for challenge pages")
    return width, height


def classify_page(title: str, url: str, html: str = "") -> ChallengeState:
    title_l = (title or "").lower()
    url_l = (url or "").lower()
    html_l = (html[:200_000] or "").lower()
    haystack = "\n".join([title_l, url_l, html_l])

    if any(marker in haystack for marker in BLOCK_MARKERS):
        return "blocked"

    # Known success/demo pages can legitimately contain words like Cloudflare,
    # challenge, Turnstile, or cf-chl inside documentation/scripts. Treat visible
    # success markers as clear before applying challenge-page heuristics.
    if any(marker in html_l for marker in CLEAR_MARKERS):
        return "clear"

    if "just a moment" in title_l or "attention required" in title_l:
        return "challenge"

    if any(marker in haystack for marker in CHALLENGE_MARKERS):
        return "challenge"

    if title or url:
        return "clear"
    return "unknown"


def js_value(response: Any, default: Any = None) -> Any:
    try:
        result = response.get("result", {}).get("result", {})
        return result.get("value", default)
    except AttributeError:
        return default


def fingerprint_patch_source(accept_languages: str) -> str:
    primary = accept_languages.split(",")[0].strip() or "en-US"
    languages_json = json.dumps([part.strip() for part in accept_languages.split(",") if part.strip()])
    primary_json = json.dumps(primary)
    # Deterministic per page context; avoids unstable random noise on repeated reads.
    seed = random.randint(10_000, 99_999)
    return f"""
(() => {{
  if (globalThis.__pydollAntibotPatchInstalled) return;
  Object.defineProperty(globalThis, '__pydollAntibotPatchInstalled', {{ value: true }});
  const languages = {languages_json};
  const primaryLanguage = {primary_json};
  const stableSeed = {seed};
  const defineGetter = (obj, prop, getter) => {{
    try {{ Object.defineProperty(obj, prop, {{ get: getter, configurable: true }}); }} catch (_) {{}}
  }};

  try {{ delete Navigator.prototype.webdriver; }} catch (_) {{}}
  if ('webdriver' in Navigator.prototype) {{
    defineGetter(Navigator.prototype, 'webdriver', () => undefined);
  }}
  if (!globalThis.chrome) {{
    try {{ Object.defineProperty(globalThis, 'chrome', {{ value: {{ runtime: {{}} }}, configurable: true }}); }} catch (_) {{}}
  }}

  try {{
    const originalQuery = navigator.permissions && navigator.permissions.query;
    if (originalQuery) {{
      navigator.permissions.query = function(params) {{
        if (params && params.name === 'notifications') {{
          return Promise.resolve({{ state: Notification.permission }});
        }}
        return originalQuery.apply(this, arguments);
      }};
    }}
  }} catch (_) {{}}

  const patchWebGL = (Proto) => {{
    if (!Proto || !Proto.prototype || Proto.prototype.__pydollPatched) return;
    const original = Proto.prototype.getParameter;
    Object.defineProperty(Proto.prototype, '__pydollPatched', {{ value: true }});
    Proto.prototype.getParameter = function(parameter) {{
      if (parameter === 37445) return 'Intel Inc.';
      if (parameter === 37446) return 'Intel Iris OpenGL Engine';
      return original.apply(this, arguments);
    }};
  }};
  try {{ patchWebGL(WebGLRenderingContext); patchWebGL(WebGL2RenderingContext); }} catch (_) {{}}

  try {{
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {{
      const imageData = originalGetImageData.apply(this, arguments);
      for (let i = 0; i < imageData.data.length; i += Math.max(4, Math.floor(imageData.data.length / 64))) {{
        imageData.data[i] = (imageData.data[i] + ((stableSeed + i) % 3)) & 255;
      }}
      return imageData;
    }};
  }} catch (_) {{}}

  try {{
    const originalFloat = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function(array) {{
      originalFloat.apply(this, arguments);
      for (let i = 0; i < array.length; i += 16) array[i] += (((stableSeed + i) % 7) - 3) / 1000;
    }};
  }} catch (_) {{}}
}})();
""".strip()


async def install_new_document_patch(tab: Any, source: str) -> bool:
    """Install a patch before navigation; falls back to runtime execution when needed."""
    try:
        await tab._execute_command(  # pydoll 2.23.0 exposes the CDP command but not a public wrapper.
            PageCommands.add_script_to_evaluate_on_new_document(source, run_immediately=True)
        )
        return True
    except Exception as exc:
        LOG.debug("Page.addScriptToEvaluateOnNewDocument failed: %s", exc)
        try:
            await tab.execute_script(source, return_by_value=False)
            return False
        except Exception as runtime_exc:
            LOG.debug("runtime script patch failed: %s", runtime_exc)
            return False


async def apply_user_agent_override(tab: Any, config: RunnerConfig, browser_binary: str | None) -> dict[str, Any]:
    user_agent = config.user_agent or default_user_agent(browser_binary)
    platform = config.platform or infer_platform(user_agent)
    accept_language = config.accept_languages.replace(",", ",")
    info = {"user_agent": user_agent, "platform": platform, "ok": False}
    try:
        await tab._execute_command(
            EmulationCommands.set_user_agent_override(
                user_agent=user_agent,
                accept_language=accept_language,
                platform=platform,
                user_agent_metadata=user_agent_metadata(user_agent),
            )
        )
        info["ok"] = True
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


async def enable_resource_blocking(tab: Any, block_stylesheets: bool = False) -> None:
    block_types = set(DEFAULT_BLOCKED_RESOURCE_TYPES)
    if block_stylesheets:
        block_types.add("Stylesheet")

    async def block_handler(event: RequestPausedEvent) -> None:
        params = event.get("params", {})
        request_id = params.get("requestId")
        resource_type = params.get("resourceType")
        if not request_id:
            return
        try:
            if resource_type in block_types:
                await tab.fail_request(request_id, ErrorReason.BLOCKED_BY_CLIENT)
            else:
                await tab.continue_request(request_id)
        except Exception as exc:
            LOG.debug("request interception failed: %s", exc)

    await tab.enable_fetch_events()
    await tab.on(FetchEvent.REQUEST_PAUSED, block_handler)


async def safe_title(tab: Any) -> str:
    try:
        return await tab.title
    except Exception:
        return ""


async def safe_url(tab: Any) -> str:
    try:
        return await tab.current_url
    except Exception:
        return ""


async def safe_html(tab: Any, limit: int | None = None) -> str:
    try:
        html = await tab.page_source
        return html if limit is None else html[:limit]
    except Exception:
        return ""


async def manual_turnstile_probe(tab: Any) -> int:
    """Fallback probe for visible Turnstile-like controls inside shadow roots."""
    clicks = 0
    selectors = (
        'input[type="checkbox"]',
        '[role="checkbox"]',
        '.ctp-checkbox-label',
        'label.ctp-checkbox-label',
    )
    try:
        roots = await tab.find_shadow_roots(deep=True, timeout=3)
    except Exception as exc:
        LOG.debug("shadow root probe failed: %s", exc)
        roots = []

    for root in roots:
        for selector in selectors:
            try:
                element = await root.query(selector, timeout=1, raise_exc=False)
                if element:
                    await element.click(humanize=True)
                    clicks += 1
                    await asyncio.sleep(random.uniform(0.8, 1.5))
                    break
            except Exception as exc:
                LOG.debug("manual checkbox probe failed: %s", exc)
    return clicks


async def wait_until_stable(tab: Any, max_wait: int, human_probe: bool = True) -> tuple[ChallengeState, dict[str, Any]]:
    started = time.monotonic()
    last_state: ChallengeState = "unknown"
    probes = 0
    samples: list[dict[str, Any]] = []
    while time.monotonic() - started <= max_wait:
        title = await safe_title(tab)
        url = await safe_url(tab)
        html = await safe_html(tab, limit=80_000)
        state = classify_page(title, url, html)
        last_state = state
        samples.append({"t": round(time.monotonic() - started, 2), "title": title[:80], "state": state})
        if state in {"clear", "blocked"}:
            # Avoid false clear during early navigation by observing a short stable window.
            await asyncio.sleep(1.0)
            title2 = await safe_title(tab)
            html2 = await safe_html(tab, limit=80_000)
            state2 = classify_page(title2, await safe_url(tab), html2)
            if state2 == state:
                return state, {"samples": samples, "manual_probe_clicks": probes}
            last_state = state2
        if human_probe and state == "challenge" and probes == 0:
            probes += await manual_turnstile_probe(tab)
        await asyncio.sleep(2.0)
    return last_state, {"samples": samples, "manual_probe_clicks": probes}


async def perform_clicks(tab: Any, selectors: list[str], wait_after_click: float = 3.0) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for selector in selectors:
        record: dict[str, Any] = {"selector": selector, "ok": False}
        try:
            element = await tab.query(selector, timeout=8, raise_exc=False)
            if not element:
                record["error"] = "not found"
            else:
                await element.click(humanize=True)
                await asyncio.sleep(wait_after_click)
                record["ok"] = True
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        actions.append(record)
    return actions


async def extract_selectors(tab: Any, selectors: dict[str, str]) -> dict[str, Any]:
    extracted: dict[str, Any] = {}
    for key, selector in selectors.items():
        try:
            elements = await tab.query(selector, timeout=5, find_all=True, raise_exc=False)
            if not elements:
                extracted[key] = None
                continue
            values: list[str | None] = []
            for element in elements:
                value = None
                if selector.lstrip().lower().startswith("meta"):
                    value = element.get_attribute("content")
                if value is None:
                    try:
                        response = await element.execute_script(
                            "return this.getAttribute('content') || this.value || this.textContent || ''",
                            return_by_value=True,
                        )
                        value = js_value(response, "")
                    except Exception:
                        value = await element.text
                values.append(value.strip() if isinstance(value, str) else value)
            extracted[key] = values[0] if len(values) == 1 else values
        except (ElementNotFound, WaitElementTimeout):
            extracted[key] = None
        except Exception as exc:
            extracted[key] = {"error": str(exc)}
    return extracted


async def run_once(config: RunnerConfig) -> RunResult:
    from ..proxy import prepare_chromium_proxy, redacted_proxy

    started = time.monotonic()
    headless = resolve_headless(config.mode, config.headless)
    proxy_bridge = None
    effective_config = config
    proxy_diag: dict[str, Any] = {"requested": redacted_proxy(config.proxy)}

    if config.proxy:
        try:
            local_proxy, proxy_bridge, proxy_diag = await prepare_chromium_proxy(config.proxy)
            if local_proxy:
                effective_config = RunnerConfig(**{**asdict(config), "proxy": local_proxy})
        except Exception as exc:
            proxy_diag = {
                "requested": redacted_proxy(config.proxy),
                "error": f"{type(exc).__name__}: {exc}",
                "hint": "Authenticated proxies need `antibot install-js-deps` (proxy-chain) for Cloudflare/Pydoll.",
            }
            result_errors_early = [
                f"proxy bridge failed: {exc}. For auth proxies run `uv run antibot install-js-deps`."
            ]
            headless = resolve_headless(config.mode, config.headless)
            result = RunResult(
                ok=False,
                url=config.url,
                browser_binary=discover_browser_binary(config.browser_binary) or "",
                headless=headless,
                pydoll_version=pydoll_version(),
                diagnostics=diagnose_environment(config.browser_binary),
                errors=result_errors_early,
            )
            result.diagnostics["proxy"] = proxy_diag
            result.elapsed_sec = round(time.monotonic() - started, 3)
            return result

    options, browser_binary = build_options(effective_config, headless=headless)
    result = RunResult(
        ok=False,
        url=config.url,
        browser_binary=browser_binary or "",
        headless=headless,
        pydoll_version=pydoll_version(),
        diagnostics=diagnose_environment(config.browser_binary),
    )
    result.diagnostics["proxy"] = proxy_diag

    if not browser_binary:
        result.errors.append("No executable Chrome/Chromium binary found")
        result.elapsed_sec = round(time.monotonic() - started, 3)
        if proxy_bridge is not None:
            await proxy_bridge.close()
        return result

    if not headless and not os.environ.get("DISPLAY"):
        result.diagnostics["headed_without_display"] = "Use xvfb-run -a for managed/headed mode"

    try:
        async with Chrome(options=options) as browser:
            tab = await browser.start()
            result.diagnostics["user_agent_override"] = await apply_user_agent_override(
                tab, effective_config, browser_binary
            )
            if effective_config.inject_fingerprint_patch:
                result.diagnostics["new_document_patch"] = await install_new_document_patch(
                    tab, fingerprint_patch_source(effective_config.accept_languages)
                )
            if effective_config.block_resources:
                await enable_resource_blocking(tab, effective_config.block_stylesheets)
                result.diagnostics["resource_blocking"] = {
                    "types": sorted(
                        DEFAULT_BLOCKED_RESOURCE_TYPES
                        | ({"Stylesheet"} if effective_config.block_stylesheets else set())
                    )
                }

            auto_solve_enabled = False
            if effective_config.mode in {"turnstile", "managed"}:
                auto_solve_enabled = True
                await tab.enable_auto_solve_cloudflare_captcha(time_to_wait_captcha=effective_config.captcha_wait)
                async with tab.expect_and_bypass_cloudflare_captcha(time_to_wait_captcha=effective_config.captcha_wait):
                    await tab.go_to(effective_config.url, timeout=effective_config.navigation_timeout)
            else:
                await tab.go_to(effective_config.url, timeout=effective_config.navigation_timeout)
                initial_state = classify_page(
                    await safe_title(tab), await safe_url(tab), await safe_html(tab, limit=80_000)
                )
                result.diagnostics["initial_state"] = initial_state
                if effective_config.mode == "auto" and initial_state == "challenge":
                    auto_solve_enabled = True
                    await tab.enable_auto_solve_cloudflare_captcha(time_to_wait_captcha=effective_config.captcha_wait)
                    if effective_config.human_probe:
                        result.diagnostics["initial_manual_probe_clicks"] = await manual_turnstile_probe(tab)
                    try:
                        async with tab.expect_and_bypass_cloudflare_captcha(
                            time_to_wait_captcha=effective_config.captcha_wait
                        ):
                            await tab.refresh(ignore_cache=True)
                    except Exception as exc:
                        # Some challenge pages are solved in-place; continue into the settle loop.
                        result.diagnostics["auto_retry"] = f"{type(exc).__name__}: {exc}"

            state, wait_diag = await wait_until_stable(tab, effective_config.max_wait, effective_config.human_probe)
            result.diagnostics["auto_solve_enabled"] = auto_solve_enabled
            result.diagnostics["wait"] = wait_diag
            result.state = state
            result.title = await safe_title(tab)
            result.final_url = await safe_url(tab)

            if effective_config.clicks:
                result.diagnostics["clicks"] = await perform_clicks(
                    tab, effective_config.clicks, effective_config.wait_after_click
                )
                post_click_state, post_click_diag = await wait_until_stable(
                    tab, min(effective_config.max_wait, 30), effective_config.human_probe
                )
                result.diagnostics["post_click_wait"] = post_click_diag
                result.state = post_click_state

            if effective_config.selectors:
                result.selectors = await extract_selectors(tab, effective_config.selectors)

            if effective_config.screenshot:
                path = str(Path(effective_config.screenshot).expanduser().resolve())
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                await tab.take_screenshot(path=path, beyond_viewport=True)
                result.artifacts["screenshot"] = path

            if effective_config.html_output:
                path = str(Path(effective_config.html_output).expanduser().resolve())
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(await safe_html(tab), encoding="utf-8")
                result.artifacts["html"] = path

            if auto_solve_enabled:
                await tab.disable_auto_solve_cloudflare_captcha()
            result.ok = state == "clear"
    except FailedToStartBrowser as exc:
        result.errors.append(
            f"Failed to start browser: {exc}. binary={browser_binary!r}; "
            "try --browser-binary with Chrome for Testing or run headed mode under xvfb-run."
        )
    except (NavigationError, PageLoadTimeout) as exc:
        result.errors.append(f"Navigation failed: {exc}")
    except Exception as exc:  # Keep prototype CLI from hiding diagnostic output.
        result.errors.append(f"Unhandled error: {type(exc).__name__}: {exc}")
    finally:
        if proxy_bridge is not None:
            try:
                await proxy_bridge.close()
            except Exception as exc:
                result.diagnostics.setdefault("proxy", {})["close_error"] = f"{type(exc).__name__}: {exc}"
        result.elapsed_sec = round(time.monotonic() - started, 3)

    return result


def diagnose_environment(explicit_binary: str | None = None) -> dict[str, Any]:
    from ..proxy import env_proxy_candidates

    binary = discover_browser_binary(explicit_binary)
    proxy_chain = (
        Path(__file__).resolve().parents[1] / "vendor" / "aliyun" / "node_modules" / "proxy-chain"
    )
    return {
        "python": sys.version.split()[0],
        "pydoll_python": pydoll_version(),
        "browser_binary": binary,
        "browser_binary_exists": _path_is_executable(binary),
        "display": os.environ.get("DISPLAY"),
        "xvfb_run": shutil.which("xvfb-run"),
        "uv": shutil.which("uv"),
        "node": shutil.which("node"),
        "proxy_chain_installed": proxy_chain.exists(),
        "vps_hints": {
            "no_display": not bool(os.environ.get("DISPLAY")),
            "prefer_headless": not bool(os.environ.get("DISPLAY")),
            "auth_proxy_needs_bridge": True,
            "install_js_deps": "uv run antibot install-js-deps",
        },
        "env_proxy": env_proxy_candidates(),
    }


def parse_selector_items(items: Iterable[str]) -> dict[str, str]:
    selectors: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise argparse.ArgumentTypeError("selector must be key=css_or_xpath")
        key, selector = item.split("=", 1)
        key, selector = key.strip(), selector.strip()
        if not key or not selector:
            raise argparse.ArgumentTypeError("selector key and value cannot be empty")
        selectors[key] = selector
    return selectors


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Robust Pydoll anti-bot prototype runner")
    parser.add_argument("url", nargs="?", help="Target URL; omit with --diagnose")
    parser.add_argument("--mode", choices=["auto", "turnstile", "managed", "scrape", "diagnose"], default="auto")
    parser.add_argument("--headless", choices=["auto", "true", "false"], default="auto")
    parser.add_argument("--browser-binary", help="Chrome/Chromium executable path")
    parser.add_argument("--proxy", help="Proxy server, e.g. http://host:port or socks5://host:port")
    parser.add_argument("--profile-dir", help="Persistent Chrome profile directory")
    parser.add_argument("--accept-languages", default="en-US,en")
    parser.add_argument("--user-agent", help="Override browser User-Agent; default is a Chrome desktop persona without HeadlessChrome")
    parser.add_argument("--platform", help="Override navigator.platform via CDP, e.g. Win32, MacIntel, Linux x86_64")
    parser.add_argument("--viewport", default="1920,1080")
    parser.add_argument("--startup-timeout", type=int, default=45)
    parser.add_argument("--navigation-timeout", type=int, default=90)
    parser.add_argument("--max-wait", type=int, default=90)
    parser.add_argument("--captcha-wait", type=float, default=8.0)
    parser.add_argument("--selector", action="append", default=[], help="Extract selector as key=css_or_xpath; repeatable")
    parser.add_argument("--click", action="append", default=[], help="Click CSS/XPath selector after initial settle; repeatable")
    parser.add_argument("--wait-after-click", type=float, default=3.0)
    parser.add_argument("--screenshot", help="Save full-page screenshot path")
    parser.add_argument("--html-output", help="Save final HTML path")
    parser.add_argument("--output-json", help="Save structured JSON result path")
    parser.add_argument("--block-resources", action="store_true", help="Block images/fonts/media after fetch interception")
    parser.add_argument("--block-stylesheets", action="store_true", help="Also block CSS; avoid on challenge pages")
    parser.add_argument("--no-fingerprint-patch", action="store_true")
    parser.add_argument("--no-human-probe", action="store_true")
    parser.add_argument("--diagnose", action="store_true", help="Only print environment diagnostics")
    parser.add_argument("--verbose", action="store_true")
    return parser


def config_from_args(args: argparse.Namespace) -> RunnerConfig:
    if args.diagnose or args.mode == "diagnose":
        return RunnerConfig(url=args.url or "about:blank", mode="diagnose", browser_binary=args.browser_binary)
    if not args.url:
        raise SystemExit("url is required unless --diagnose is used")
    return RunnerConfig(
        url=args.url,
        mode=args.mode,
        headless=args.headless,
        browser_binary=args.browser_binary,
        proxy=args.proxy,
        profile_dir=args.profile_dir,
        accept_languages=args.accept_languages,
        user_agent=args.user_agent,
        platform=args.platform,
        viewport=args.viewport,
        startup_timeout=args.startup_timeout,
        navigation_timeout=args.navigation_timeout,
        max_wait=args.max_wait,
        captcha_wait=args.captcha_wait,
        screenshot=args.screenshot,
        html_output=args.html_output,
        output_json=args.output_json,
        selectors=parse_selector_items(args.selector),
        clicks=args.click,
        wait_after_click=args.wait_after_click,
        block_resources=args.block_resources,
        block_stylesheets=args.block_stylesheets,
        inject_fingerprint_patch=not args.no_fingerprint_patch,
        human_probe=not args.no_human_probe,
        verbose=args.verbose,
    )


def emit_json(data: dict[str, Any], output_path: str | None = None) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if output_path:
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")


async def amain(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="[%(levelname)s] %(message)s")
    config = config_from_args(args)
    if args.diagnose or config.mode == "diagnose":
        emit_json(diagnose_environment(config.browser_binary), args.output_json)
        return 0
    result = await run_once(config)
    payload = asdict(result)
    emit_json(payload, config.output_json)
    return 0 if result.ok else 2


def main() -> None:
    raise SystemExit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
