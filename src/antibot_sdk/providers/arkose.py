"""Arkose Labs FunCaptcha browser session and evidence-gated solver.

Arkose challenges are rendered as changing Canvas/DOM games rather than one
stable image-grid protocol.  This module translates the currently rendered
surface into the Harness observation/action contract and only accepts a run
after both a final callback/field token and a positive ``/fc/ca/`` vendor
response have been observed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlsplit, urlunsplit

from PIL import Image

from ..harness.agent import ChallengeAgentLoop, VisionChallengePolicy
from ..harness.contracts import (
    ChallengeAction,
    ChallengeAffordance,
    ChallengeCandidate,
    ChallengeObservation,
    VendorVerification,
)
from ..models import CaptchaResult
from ..persistence import persist_result
from ..proxy import proxy_free_environment, redacted_proxy, resolve_runtime_proxy
from ..vision import (
    VisionBackend,
    VisionBackendError,
    VisionImage,
    VisionSolvePolicy,
    VisionTask,
)
from .widgets import _discover_browser, _headless, _resolve_vision_backend

ARKOSE_ALIASES = {
    "arkose": "arkose",
    "arkose-labs": "arkose",
    "arkoselabs": "arkose",
    "funcaptcha": "arkose",
    "fun-captcha": "arkose",
}

ARKOSE_HOST_MARKERS = (
    "arkoselabs.com",
    "funcaptcha.com",
    "client-api.arkoselabs.com",
    "client-api.arkoselabs.cn",
)
ARKOSE_URL_MARKERS = ("arkoselabs", "funcaptcha")

ARKOSE_TOKEN_SELECTORS = (
    "input[name='fc-token']",
    "textarea[name='fc-token']",
    "input[name='arkoseToken']",
    "textarea[name='arkoseToken']",
    "input[name='verification-token']",
    "textarea[name='verification-token']",
)

ARKOSE_CHALLENGE_MARKERS = (
    "/fc/gt2/public_key/",
    "/fc/gfct/",
    "/fc/ca/",
    "/fc/a/",
)

ARKOSE_VERIFY_MARKER = "/fc/ca/"

ARKOSE_HOOK_JS = r"""
(() => {
  if (globalThis.__ANTIBOT_ARKOSE_HOOK__) return;
  const state = { tokens: [], events: [], startedAt: Date.now() };
  const tokenValue = (value) => {
    if (typeof value === 'string') return value.trim();
    if (value && typeof value === 'object') {
      for (const key of ['token', 'sessionToken', 'session_token', 'verificationToken']) {
        if (typeof value[key] === 'string') return value[key].trim();
      }
    }
    return '';
  };
  const record = (value, event) => {
    const token = tokenValue(value);
    if (token.length <= 20) return;
    if (!state.tokens.some((item) => item.value === token)) {
      state.tokens.push({ value: token, event, at: Date.now() });
    }
    state.events.push({ event, tokenLength: token.length, at: Date.now() });
    if (state.tokens.length > 20) state.tokens.shift();
    if (state.events.length > 100) state.events.shift();
  };
  const wrapCallback = (config, key) => {
    if (!config || typeof config !== 'object' || typeof config[key] !== 'function') return;
    const original = config[key];
    if (original.__antibotWrapped) return;
    const wrapped = function(value) {
      record(value, key);
      return original.apply(this, arguments);
    };
    Object.defineProperty(wrapped, '__antibotWrapped', { value: true });
    config[key] = wrapped;
  };
  const wrapConfig = (config) => {
    if (!config || typeof config !== 'object') return config;
    for (const key of ['callback', 'onCompleted', 'onComplete', 'onSuccess', 'onToken']) {
      try { wrapCallback(config, key); } catch (_) {}
    }
    return config;
  };
  const wrapInstance = (instance) => {
    if (!instance || (typeof instance !== 'object' && typeof instance !== 'function') || instance.__antibotWrapped) return instance;
    try {
      if (typeof instance.setConfig === 'function') {
        const original = instance.setConfig;
        instance.setConfig = function(config) {
          return original.call(this, wrapConfig(config));
        };
      }
      Object.defineProperty(instance, '__antibotWrapped', { value: true, configurable: true });
    } catch (_) {}
    return instance;
  };
  const wrapConstructor = (Original) => {
    if (typeof Original !== 'function' || Original.__antibotWrapped) return Original;
    const Wrapped = function(config) {
      const target = new.target && new.target !== Wrapped ? new.target : Original;
      return wrapInstance(Reflect.construct(Original, [wrapConfig(config)], target));
    };
    try { Object.setPrototypeOf(Wrapped, Original); } catch (_) {}
    try { Wrapped.prototype = Original.prototype; } catch (_) {}
    Object.defineProperty(Wrapped, '__antibotWrapped', { value: true });
    return Wrapped;
  };
  const wrapSetupCallback = (name) => {
    if (!name || typeof name !== 'string') return;
    let callback;
    try { callback = globalThis[name]; } catch (_) { return; }
    if (typeof callback !== 'function' || callback.__antibotWrapped) return;
    const wrapped = function(instance) {
      return callback.call(this, wrapInstance(instance), ...Array.prototype.slice.call(arguments, 1));
    };
    try { Object.defineProperty(wrapped, '__antibotWrapped', { value: true }); } catch (_) {}
    try { globalThis[name] = wrapped; } catch (_) {}
  };
  const wrapConfiguredCallbacks = () => {
    try {
      for (const script of document.querySelectorAll('script[data-callback]')) {
        wrapSetupCallback(script.getAttribute('data-callback'));
      }
    } catch (_) {}
  };
  let enforcement;
  try {
    enforcement = globalThis.ArkoseEnforcement;
    Object.defineProperty(globalThis, 'ArkoseEnforcement', {
      configurable: true,
      enumerable: true,
      get: () => enforcement,
      set: (value) => { enforcement = typeof value === 'function' ? wrapConstructor(value) : wrapInstance(value); },
    });
    if (enforcement) enforcement = typeof enforcement === 'function' ? wrapConstructor(enforcement) : wrapInstance(enforcement);
  } catch (_) {}
  const readFields = () => {
    for (const selector of [
      "input[name='fc-token']", "textarea[name='fc-token']",
      "input[name='arkoseToken']", "textarea[name='arkoseToken']",
      "input[name='verification-token']", "textarea[name='verification-token']",
    ]) {
      for (const element of document.querySelectorAll(selector)) {
        if (element.value) record(element.value, 'field');
      }
    }
  };
  globalThis.__ANTIBOT_ARKOSE_HOOK__ = state;
  setInterval(() => {
    readFields();
    wrapConfiguredCallbacks();
    try {
      const current = globalThis.ArkoseEnforcement;
      if (current && !current.__antibotWrapped) globalThis.ArkoseEnforcement = current;
    } catch (_) {}
  }, 200);
})();
""".strip()

_SURFACE_SELECTORS = (
    "canvas",
    "[data-e2e='game-core-frame']",
    "[data-testid*='game']",
    "[class*='game-core']",
    "[class*='challenge']",
    "[class*='arkose']",
    "[id*='arkose']",
    "[id*='FunCaptcha']",
)

# Selectors are intentionally ordered by specificity.  A generic challenge or
# Arkose host container is often larger than the actual game canvas, so picking
# the single largest node across all selectors can return a loading shell.
_PRIMARY_SURFACE_SELECTORS = (
    "canvas",
    "[data-e2e='game-core-frame']",
    "[data-testid*='game']",
    "[class*='game-core']",
)
_CONTAINER_SURFACE_SELECTORS = (
    "[class*='challenge']",
    "[class*='arkose']",
    "[id*='arkose']",
    "[id*='FunCaptcha']",
)

_CANDIDATE_SELECTORS = (
    "[data-index]",
    "[data-tile-index]",
    "[class*='tile']",
    "[class*='option'] img",
)

_POSITIVE_RESPONSE_VALUES = frozenset(
    ("answered", "complete", "completed", "ok", "pass", "passed", "solved", "success", "verified")
)
_NEGATIVE_RESPONSE_VALUES = frozenset(
    ("denied", "fail", "failed", "incorrect", "not answered", "not_answered", "rejected", "retry")
)
_PASS_KEYS = frozenset(
    ("challenge_solved", "complete", "completed", "pass", "passed", "solved", "success", "verified")
)


def normalize_arkose_provider(value: str | None) -> str:
    normalized = "-".join(str(value or "").strip().casefold().replace("_", "-").split())
    return ARKOSE_ALIASES.get(normalized, normalized)


def detect_arkose_provider(url: str | None) -> str | None:
    parsed = urlsplit(str(url or ""))
    surface = f"{parsed.hostname or ''}{parsed.path or ''}".casefold()
    return "arkose" if any(
        marker.casefold() in surface
        for marker in (*ARKOSE_HOST_MARKERS, *ARKOSE_URL_MARKERS)
    ) else None


def _redact_event_url(value: str) -> str:
    """Remove query and fragment values that may contain Arkose session tokens."""

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value.split("?", 1)[0].split("#", 1)[0][:500]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))[:500]


def _normalize_tokens(values: Iterable[Any]) -> list[str]:
    return list(
        dict.fromkeys(
            value.strip()
            for value in values
            if isinstance(value, str) and len(value.strip()) > 20
        )
    )


def _browser_frames(page: Any) -> tuple[Any, ...]:
    """Return nested frames before the top-level document.

    Playwright exposes the main frame in ``page.frames`` as well as through
    ``page.main_frame``.  Keeping the main document last prevents a business
    page's generic canvas or challenge-looking container from shadowing the
    actual Arkose iframe.
    """

    raw_frames = getattr(page, "frames", ()) or ()
    try:
        frames = list(raw_frames)
    except TypeError:
        frames = []
    main_frame = getattr(page, "main_frame", None)
    if main_frame is None and not frames:
        return (page,)
    if main_frame is None:
        main_frame = frames[0]
    nested = [frame for frame in frames if frame is not main_frame]

    def depth(frame: Any) -> int:
        value = 0
        seen: set[int] = set()
        parent = getattr(frame, "parent_frame", None)
        while parent is not None and id(parent) not in seen:
            seen.add(id(parent))
            value += 1
            parent = getattr(parent, "parent_frame", None)
        return value

    # Deep challenge frames generally contain the game; the direct Arkose
    # enforcement frame may only contain a loading shell.
    nested.sort(key=depth, reverse=True)
    return tuple(nested + [main_frame])


def _arkose_pass_from_payload(payload: Any) -> bool | None:
    """Extract only explicit Arkose pass/fail semantics from a response body."""

    positive = False
    negative = False

    def visit(value: Any, parent_key: str = "") -> None:
        nonlocal positive, negative
        if isinstance(value, dict):
            for raw_key, item in value.items():
                key = str(raw_key).strip().casefold().replace("-", "_")
                if key in _PASS_KEYS and isinstance(item, bool):
                    positive = positive or item
                    negative = negative or not item
                elif key in {"response", "result", "status"} and isinstance(item, str):
                    normalized = " ".join(item.strip().casefold().replace("-", " ").split())
                    positive = positive or normalized in _POSITIVE_RESPONSE_VALUES
                    negative = negative or normalized in _NEGATIVE_RESPONSE_VALUES
                visit(item, key)
        elif isinstance(value, list):
            for item in value:
                visit(item, parent_key)
        elif isinstance(value, str) and parent_key in {"", "response", "result", "status"}:
            normalized = " ".join(value.strip().casefold().replace("-", " ").split())
            positive_nonlocal = normalized in _POSITIVE_RESPONSE_VALUES
            negative_nonlocal = normalized in _NEGATIVE_RESPONSE_VALUES
            positive = positive or positive_nonlocal
            negative = negative or negative_nonlocal

    visit(payload)
    if negative:
        return False
    if positive:
        return True
    return None


def _arkose_payload_from_text(value: str) -> Any:
    """Decode JSON or a simple form-encoded Arkose response body."""

    text = str(value or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        pass
    try:
        fields = parse_qs(text, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        fields = {}
    if fields:
        return {key: values[-1] if values else "" for key, values in fields.items()}
    return text if text.casefold() in (_POSITIVE_RESPONSE_VALUES | _NEGATIVE_RESPONSE_VALUES) else None


def _response_status_value(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("response", "result", "status"):
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)):
            return str(value)[:100]
    return None


async def _read_arkose_tokens(page: Any) -> list[str]:
    tokens: list[str] = []
    frames = _browser_frames(page)
    for frame in frames:
        for selector in ARKOSE_TOKEN_SELECTORS:
            try:
                locator = frame.locator(selector)
                for index in range(await locator.count()):
                    value = await locator.nth(index).input_value(timeout=300)
                    if isinstance(value, str):
                        tokens.append(value)
            except Exception:
                continue
        try:
            state = await frame.evaluate(
                """() => ({
                  tokens: (globalThis.__ANTIBOT_ARKOSE_HOOK__?.tokens || []).map((item) => item.value),
                  events: globalThis.__ANTIBOT_ARKOSE_HOOK__?.events || []
                })"""
            )
            if isinstance(state, dict):
                tokens.extend(state.get("tokens", ()))
        except Exception:
            continue
    return _normalize_tokens(tokens)


def _network_verification(events: list[dict[str, Any]]) -> tuple[bool | None, int, tuple[str, ...]]:
    responses = [
        item
        for item in events
        if isinstance(item, dict) and ARKOSE_VERIFY_MARKER in str(item.get("url", ""))
    ]
    pass_values = [item.get("pass") for item in responses if isinstance(item.get("pass"), bool)]
    vendor_pass: bool | None
    if any(value is True for value in pass_values):
        vendor_pass = True
    elif any(value is False for value in pass_values):
        vendor_pass = False
    else:
        vendor_pass = None
    failures = sum(value is False for value in pass_values)
    markers = (ARKOSE_VERIFY_MARKER,) if responses else ()
    return vendor_pass, failures, markers


async def _visible(locator: Any) -> bool:
    try:
        return bool(await locator.count()) and bool(await locator.is_visible(timeout=250))
    except Exception:
        return False


async def _surface_is_loading(surface: Any) -> bool:
    """Reject Arkose bootstrap/risk-check shells as visual challenges."""

    try:
        text = " ".join((await surface.inner_text(timeout=300) or "").split()).casefold()
    except Exception:
        text = ""
    loading_markers = (
        "checking your browser",
        "loading challenge",
        "please wait",
        "verifying browser",
    )
    if any(marker in text for marker in loading_markers):
        return True
    try:
        meaningful = surface.locator(
            "canvas, [data-index], [data-tile-index], [data-e2e='game-core-frame'], "
            "[class*='game-core']"
        )
        if await meaningful.count():
            return False
        buttons = surface.locator("button, [role='button']")
        labels: list[str] = []
        for index in range(min(await buttons.count(), 10)):
            item = buttons.nth(index)
            try:
                label = " ".join((await item.inner_text(timeout=200) or "").split())
            except Exception:
                label = ""
            if not label:
                try:
                    label = " ".join((await item.get_attribute("aria-label") or "").split())
                except Exception:
                    label = ""
            if label:
                labels.append(label.casefold())
        # An enforcement shell with only Close/Audio controls is not an
        # actionable puzzle.  Wait for Start Puzzle or the actual game UI.
        return bool(labels) and all(label in {"audio", "close"} for label in labels)
    except Exception:
        return False


async def _largest_visible(frame: Any, selectors: tuple[str, ...]) -> tuple[Any, str] | None:
    best: tuple[Any, str] | None = None
    best_area = 0.0
    for selector in selectors:
        try:
            locator = frame.locator(selector)
            for index in range(min(await locator.count(), 20)):
                item = locator.nth(index)
                if not await _visible(item):
                    continue
                box = await item.bounding_box()
                area = float(box.get("width", 0) * box.get("height", 0)) if box else 0
                if area > best_area:
                    best = (item, selector)
                    best_area = area
        except Exception:
            continue
    return best


async def _frame_has_arkose_markers(frame: Any) -> bool:
    if any(marker in str(getattr(frame, "url", "")).casefold() for marker in ARKOSE_HOST_MARKERS):
        return True
    try:
        return bool(
            await frame.evaluate(
                """() => Boolean(document.querySelector(
                  "iframe[src*='arkose'],iframe[src*='funcaptcha'],script[src*='arkose']," +
                  "[class*='arkose'],[id*='arkose'],[id*='FunCaptcha'],input[name='fc-token']"
                ))"""
            )
        )
    except Exception:
        return False


async def _main_frame_has_direct_surface(frame: Any) -> bool:
    """Check for a challenge surface owned by the top-level document.

    An Arkose iframe embed is a marker, but it is not itself a solvable
    surface.  This narrower check prevents an unrelated business-page canvas
    from being returned when the nested frame has not finished attaching yet.
    """

    try:
        return bool(
            await frame.evaluate(
                """() => Boolean(document.querySelector(
                  "[data-e2e='game-core-frame']," +
                  "[class*='arkose'] canvas,[id*='arkose'] canvas,[id*='FunCaptcha'] canvas"
                ))"""
            )
        )
    except Exception:
        return False


async def _surface_prompt(frame: Any) -> str:
    selectors = (
        "[data-testid*='prompt']",
        "[class*='prompt']",
        "[class*='instruction']",
        "[aria-live='polite']",
        "h1",
        "h2",
    )
    values: list[str] = []
    for selector in selectors:
        try:
            locator = frame.locator(selector)
            for index in range(min(await locator.count(), 6)):
                item = locator.nth(index)
                if await _visible(item):
                    text = " ".join((await item.inner_text(timeout=300) or "").split())
                    if text and text not in values:
                        values.append(text)
        except Exception:
            continue
    if not values:
        try:
            text = " ".join((await frame.locator("body").inner_text(timeout=500) or "").split())
            if text:
                values.append(text)
        except Exception:
            pass
    return " ".join(values)[:500] or "Complete the Arkose Labs visual challenge shown"


async def _controls(frame: Any) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    try:
        locator = frame.locator("button, [role='button']")
        count = min(await locator.count(), 30)
    except Exception:
        return controls
    for index in range(count):
        item = locator.nth(index)
        if not await _visible(item):
            continue
        try:
            label = " ".join((await item.inner_text(timeout=250) or "").split())
        except Exception:
            label = ""
        if not label:
            for attribute in ("aria-label", "title", "data-testid"):
                try:
                    label = " ".join((await item.get_attribute(attribute) or "").split())
                except Exception:
                    label = ""
                if label:
                    break
        try:
            box = await item.bounding_box()
        except Exception:
            box = None
        controls.append(
            {
                "index": index,
                "label": label[:120] or f"button-{index}",
                "box": box,
            }
        )
    return controls


async def _candidate_count(frame: Any) -> tuple[int, str | None]:
    for selector in _CANDIDATE_SELECTORS:
        try:
            locator = frame.locator(selector)
            count = sum(
                1
                for index in range(min(await locator.count(), 30))
                if await _visible(locator.nth(index))
            )
            if count >= 2:
                return count, selector
        except Exception:
            continue
    return 0, None


def _classify_surface(
    prompt: str,
    controls: list[dict[str, Any]],
    candidate_count: int,
) -> tuple[str, tuple[str, ...]]:
    labels = tuple(dict.fromkeys(str(item["label"]) for item in controls))
    control_text = " ".join(labels).casefold()
    prompt_text = prompt.casefold()
    if candidate_count >= 2:
        return "binary", ()
    if any(word in control_text for word in ("rotate", "left", "right")):
        choices = tuple(
            label
            for label in labels
            if any(word in label.casefold() for word in ("rotate", "left", "right"))
        )
        if choices:
            return "multiple_choice", choices
    if any(word in prompt_text for word in ("drag", "move the", "slide")):
        return "drag_drop", ()
    return "point", ()


@dataclass(slots=True)
class _ArkoseState:
    observation: ChallengeObservation
    task: VisionTask
    frame: Any
    surface: Any
    screenshot: bytes
    signature: str
    controls: list[dict[str, Any]]
    candidate_selector: str | None


class ArkoseChallengeSession:
    """Translate one live Arkose game episode into Harness observations/actions."""

    def __init__(
        self,
        page: Any,
        *,
        diagnostics: dict[str, Any] | None = None,
        network_events: list[dict[str, Any]] | None = None,
        output_dir: str | None = None,
        max_rounds: int = 12,
        verification_wait_ms: int = 4000,
    ) -> None:
        if max_rounds < 1:
            raise ValueError("Arkose session max_rounds must be positive")
        if verification_wait_ms < 0:
            raise ValueError("Arkose session verification_wait_ms must be non-negative")
        self.page = page
        self.diagnostics = diagnostics if diagnostics is not None else {}
        self.network_events = network_events if network_events is not None else []
        self.output_root = (
            Path(output_dir).expanduser().resolve() / "vision-replay" if output_dir else None
        )
        self.max_rounds = max_rounds
        self.verification_wait_sec = verification_wait_ms / 1000
        self._sequence = 0
        self._rounds = 0
        self._submitted = False
        self._current: _ArkoseState | None = None
        self._initial_tokens: set[str] = set()
        self._last_scene_signature: str | None = None
        self._navigation_attempts = 0

    @property
    def submitted(self) -> bool:
        return self._submitted

    async def read_tokens(self) -> list[str]:
        return await _read_arkose_tokens(self.page)

    async def read_final_tokens(self) -> list[str]:
        tokens = await self.read_tokens()
        if self._initial_tokens:
            return [token for token in tokens if token not in self._initial_tokens]
        return tokens

    async def _find_surface(self) -> tuple[Any, Any, str] | None:
        frames = _browser_frames(self.page)
        main_frame = getattr(self.page, "main_frame", None)
        if main_frame is None and frames:
            main_frame = frames[-1]
        for frame in frames:
            is_main_frame = frame is main_frame or frame is self.page
            if not await _frame_has_arkose_markers(frame):
                continue
            selectors = _PRIMARY_SURFACE_SELECTORS
            if is_main_frame and not any(
                marker.casefold() in str(getattr(frame, "url", "")).casefold()
                for marker in ARKOSE_HOST_MARKERS
            ):
                if not await _main_frame_has_direct_surface(frame):
                    continue
                # The top-level document is only eligible for a surface that
                # is explicitly nested below an Arkose/game container.
                selectors = (
                    "[data-e2e='game-core-frame']",
                    "[class*='arkose'] canvas",
                    "[id*='arkose'] canvas",
                    "[id*='FunCaptcha'] canvas",
                )
            for selector_group in (selectors, _CONTAINER_SURFACE_SELECTORS):
                found = await _largest_visible(frame, selector_group)
                if found is None:
                    continue
                surface, selector = found
                if selector in _CONTAINER_SURFACE_SELECTORS:
                    # The outer enforcement container exists during gt2
                    # browser verification and often contains only a spinner.
                    # Do not hand that loading state to a vision model as a
                    # solvable challenge; require an actual affordance.
                    try:
                        affordances = surface.locator(
                            "canvas, button, [role='button'], [data-index], [class*='game']"
                        )
                        if not await affordances.count():
                            continue
                    except Exception:
                        continue
                if await _surface_is_loading(surface):
                    continue
                return frame, surface, selector
            try:
                body = frame.locator("body").first
                if not is_main_frame and await _visible(body):
                    affordances = body.locator(
                        "canvas, button, [role='button'], [data-index], [class*='game']"
                    )
                    if await affordances.count() and not await _surface_is_loading(body):
                        return frame, body, "body"
            except Exception:
                continue
        return None

    async def _advance_start_control(self, frame: Any, controls: list[dict[str, Any]]) -> bool:
        """Open the actual puzzle without spending a vision round on chrome."""

        if self._navigation_attempts >= 3:
            return False
        start_words = ("start puzzle", "begin puzzle", "start challenge", "begin challenge")
        match = next(
            (
                item
                for item in controls
                if any(word in str(item.get("label", "")).casefold() for word in start_words)
            ),
            None,
        )
        if match is None:
            return False
        try:
            buttons = frame.locator("button, [role='button']")
            await buttons.nth(int(match["index"])).click(timeout=2500, delay=80)
        except Exception:
            return False
        self._navigation_attempts += 1
        self.diagnostics.setdefault("arkose_navigation_actions", []).append(
            {"kind": "start_puzzle", "control_index": int(match["index"])}
        )
        await self.page.wait_for_timeout(900)
        return True

    async def _advance_reload_control(
        self,
        frame: Any,
        controls: list[dict[str, Any]],
        prompt: str,
    ) -> bool:
        """Reload a vendor-declared error state before invoking vision."""

        prompt_text = prompt.casefold()
        if not any(marker in prompt_text for marker in ("something went wrong", "reload the challenge")):
            return False
        if self._navigation_attempts >= 4:
            return False
        match = next(
            (
                item
                for item in controls
                if any(
                    word in str(item.get("label", "")).casefold()
                    for word in ("reload challenge", "try again", "refresh")
                )
            ),
            None,
        )
        if match is None:
            return False
        try:
            buttons = frame.locator("button, [role='button']")
            await buttons.nth(int(match["index"])).click(timeout=2500, delay=80)
        except Exception:
            return False
        self._navigation_attempts += 1
        self.diagnostics.setdefault("arkose_navigation_actions", []).append(
            {"kind": "reload_challenge", "control_index": int(match["index"])}
        )
        await self.page.wait_for_timeout(900)
        return True

    async def _capture_surface(self, frame: Any, surface: Any) -> tuple[bytes, Any, Any]:
        """Capture a challenge after a short asset-stability window.

        Arkose can expose the final prompt before its image/canvas assets are
        painted.  A single screenshot at that point contains only loading
        spinners and gives a vision model no answerable content.  We only use
        the stability window after navigation or a previous scene, keeping the
        first direct observation inexpensive.
        """

        current_frame = frame
        current_surface = surface

        async def screenshot() -> bytes:
            nonlocal current_frame, current_surface
            for attempt in range(2):
                try:
                    try:
                        value = await current_surface.screenshot(type="png", timeout=5000)
                    except TypeError:
                        value = await current_surface.screenshot(timeout=5000)
                    if not isinstance(value, bytes) or not value:
                        raise VisionBackendError("Arkose challenge surface screenshot is empty")
                    return value
                except Exception:
                    if attempt:
                        raise
                    # Arkose replaces the challenge container while images or
                    # game-core assets load. Re-resolve the locator once before
                    # treating the timeout as a provider failure.
                    refreshed = await self._find_surface()
                    if refreshed is None:
                        raise
                    current_frame, current_surface = refreshed[0], refreshed[1]
                    self.diagnostics["arkose_surface_reacquired"] = (
                        int(self.diagnostics.get("arkose_surface_reacquired") or 0) + 1
                    )
            raise VisionBackendError("Arkose challenge surface screenshot failed")

        wait_for_stability = self._navigation_attempts > 0 or self._last_scene_signature is not None
        current = await screenshot()
        if not wait_for_stability:
            return current, current_frame, current_surface
        last_digest: str | None = None
        stable_samples = 0
        deadline = time.monotonic() + 3.0
        while True:
            digest = hashlib.sha256(current).hexdigest()
            if digest == last_digest:
                stable_samples += 1
            else:
                stable_samples = 0
            last_digest = digest
            if stable_samples >= 1:
                return current, current_frame, current_surface
            if time.monotonic() >= deadline:
                self.diagnostics["arkose_surface_stability_timeout"] = True
                return current, current_frame, current_surface
            wait = getattr(self.page, "wait_for_timeout", None)
            if wait is None:
                return current, current_frame, current_surface
            self.diagnostics["arkose_surface_stability_waits"] = (
                int(self.diagnostics.get("arkose_surface_stability_waits") or 0) + 1
            )
            await wait(250)
            current = await screenshot()

    async def observe(self) -> ChallengeObservation | None:
        vendor_pass, _, _ = _network_verification(self.network_events)
        if vendor_pass is True and await self.read_tokens():
            self._current = None
            return None
        found = await self._find_surface()
        if found is None and self._navigation_attempts:
            # Starting the puzzle replaces the game-core iframe asynchronously;
            # do not report verification failure during that short transition.
            transition_deadline = time.monotonic() + 8
            wait = getattr(self.page, "wait_for_timeout", None)
            while found is None and wait is not None and time.monotonic() < transition_deadline:
                await wait(200)
                found = await self._find_surface()
        if found is None:
            self._current = None
            return None
        if self._rounds >= self.max_rounds:
            self.diagnostics["arkose_max_rounds_exhausted"] = True
            raise VisionBackendError("Arkose session exhausted its challenge-round budget")

        frame, surface, selector = found
        if not self._initial_tokens:
            self._initial_tokens.update(await self.read_tokens())
            self.diagnostics["arkose_initial_token_count"] = len(self._initial_tokens)
        screenshot, frame, surface = await self._capture_surface(frame, surface)
        with Image.open(BytesIO(screenshot)) as image:
            width, height = image.size
        prompt = await _surface_prompt(frame)
        controls = await _controls(frame)
        if await self._advance_reload_control(frame, controls, prompt):
            return await self.observe()
        if await self._advance_start_control(frame, controls):
            return await self.observe()
        candidate_count, candidate_selector = await _candidate_count(frame)
        kind, choices = _classify_surface(prompt, controls, candidate_count)
        digest = hashlib.sha256(screenshot).hexdigest()
        scene_changed = (
            self._last_scene_signature is not None
            and self._last_scene_signature != digest
        )
        if scene_changed:
            self.diagnostics["arkose_scene_replacements"] = (
                int(self.diagnostics.get("arkose_scene_replacements") or 0) + 1
            )
        self._last_scene_signature = digest
        self._sequence += 1
        self._rounds += 1
        observation_id = hashlib.sha256(
            f"arkose|{self._sequence}|{kind}|{prompt}|{digest}".encode("utf-8")
        ).hexdigest()[:24]
        candidates = tuple(
            ChallengeCandidate(index=index) for index in range(candidate_count)
        )
        affordances = tuple(
            ChallengeAffordance(
                affordance_id=f"button:{item['index']}",
                role="button",
                label=str(item["label"]),
                actions=("choice", "click"),
                metadata={"control_index": item["index"]},
            )
            for item in controls
        )
        min_answers = 1
        max_answers = candidate_count if kind == "binary" else 1
        observation = ChallengeObservation(
            observation_id=observation_id,
            provider="arkose",
            kind=kind,  # type: ignore[arg-type]
            modality="image",
            prompt=prompt,
            candidate_count=candidate_count if kind == "binary" else None,
            candidates=candidates if kind == "binary" else (),
            width=width,
            height=height,
            dynamic=scene_changed,
            min_answers=min_answers,
            max_answers=max_answers,
            choices=choices,
            affordances=affordances,
            phase="presented",
            metadata={
                "image_sha256": digest,
                "round": self._rounds,
                "surface_selector": selector,
                "control_count": len(controls),
                "scene_changed_since_previous": scene_changed,
            },
        )
        task = VisionTask(
            kind=kind,  # type: ignore[arg-type]
            prompt=prompt,
            images=(VisionImage(screenshot, label="arkose-challenge.png"),),
            width=width,
            height=height,
            min_answers=min_answers,
            max_answers=max_answers,
            candidate_count=candidate_count if kind == "binary" else None,
            choices=choices,
            metadata={"provider": "arkose", "round": self._rounds},
        )
        engine = self.diagnostics.setdefault("challenge_engine", {})
        if isinstance(engine, dict):
            engine.setdefault("vision_tasks", []).append(
                {
                    "kind": kind,
                    "prompt": prompt,
                    "round": self._rounds,
                    "observation_id": observation_id,
                    "candidate_count": candidate_count if kind == "binary" else None,
                }
            )
        self.diagnostics.setdefault("arkose_session_observations", []).append(
            {
                **observation.to_dict(),
                "observation_id": observation_id,
                "round": self._rounds,
                "kind": kind,
                "prompt": prompt,
                "candidate_count": candidate_count,
                "control_labels": [item["label"] for item in controls],
                "image_sha256": digest,
                "dynamic": scene_changed,
                "scene_changed_since_previous": scene_changed,
            }
        )
        state = _ArkoseState(
            observation=observation,
            task=task,
            frame=frame,
            surface=surface,
            screenshot=screenshot,
            signature=digest,
            controls=controls,
            candidate_selector=candidate_selector,
        )
        self._current = state
        self._save_replay(state)
        return observation

    async def vision_task(self, observation: ChallengeObservation) -> VisionTask | None:
        if self._current is None:
            return None
        if self._current.observation.observation_id != observation.observation_id:
            return None
        return self._current.task

    async def execute(self, action: ChallengeAction) -> None:
        state = self._current
        if state is None or state.observation.observation_id != action.observation_id:
            raise VisionBackendError("Arkose action does not target the current challenge surface")
        validation_errors = action.validate(state.observation)
        if validation_errors:
            raise VisionBackendError(
                "Arkose action rejected: " + ", ".join(validation_errors)
            )

        if action.kind == "select":
            if not state.candidate_selector:
                raise VisionBackendError("Arkose observation has no selectable candidates")
            candidates = state.frame.locator(state.candidate_selector)
            visible = [
                candidates.nth(index)
                for index in range(min(await candidates.count(), 30))
                if await _visible(candidates.nth(index))
            ]
            for index in action.payload.get("selected", []):
                if index >= len(visible):
                    raise VisionBackendError("Arkose candidate set changed before execution")
                await visible[index].click(timeout=2000, delay=80)
                await self.page.wait_for_timeout(100)
        elif action.kind == "point":
            for point in action.payload.get("points", []):
                await state.surface.click(
                    position={"x": float(point["x"]), "y": float(point["y"])},
                    timeout=2500,
                )
                await self.page.wait_for_timeout(100)
        elif action.kind == "choice":
            raw_choices = action.payload.get("choices")
            choices = raw_choices if isinstance(raw_choices, list) else [action.payload.get("choice")]
            buttons = state.frame.locator("button, [role='button']")
            for choice in choices:
                match = next(
                    (
                        item
                        for item in state.controls
                        if str(item["label"]).strip().casefold() == str(choice).strip().casefold()
                    ),
                    None,
                )
                if match is None:
                    raise VisionBackendError(f"Arkose choice is no longer available: {choice}")
                await buttons.nth(int(match["index"])).click(timeout=2500, delay=80)
                await self.page.wait_for_timeout(100)
        elif action.kind == "drag":
            box = await state.surface.bounding_box()
            if not box:
                raise VisionBackendError("Arkose challenge surface bounds are unavailable")
            for path in action.payload.get("paths", []):
                start = path["start"]
                end = path["end"]
                await self.page.mouse.move(box["x"] + start["x"], box["y"] + start["y"])
                await self.page.mouse.down()
                await self.page.mouse.move(
                    box["x"] + end["x"],
                    box["y"] + end["y"],
                    steps=18,
                )
                await self.page.mouse.up()
                await self.page.wait_for_timeout(150)
        elif action.kind in {"submit", "reload"}:
            wanted = (
                ("verify", "submit", "done", "continue")
                if action.kind == "submit"
                else ("reload", "refresh", "try another", "new challenge")
            )
            match = next(
                (
                    item
                    for item in state.controls
                    if any(word in str(item["label"]).casefold() for word in wanted)
                ),
                None,
            )
            if match is None:
                raise VisionBackendError(f"Arkose {action.kind} control is unavailable")
            await state.frame.locator("button, [role='button']").nth(
                int(match["index"])
            ).click(timeout=2500, delay=80)
            self._submitted = self._submitted or action.kind == "submit"
        elif action.kind != "noop":
            raise VisionBackendError(f"unsupported Arkose session action: {action.kind}")

        self.diagnostics.setdefault("arkose_session_actions", []).append(
            {
                "observation_id": action.observation_id,
                "kind": action.kind,
                "confidence": action.confidence,
            }
        )
        self._current = None
        await self.page.wait_for_timeout(350)

    async def verify(self) -> VendorVerification:
        deadline = time.monotonic() + self.verification_wait_sec
        tokens: list[str] = []
        vendor_pass: bool | None = None
        vendor_failures = 0
        verifier_events: tuple[str, ...] = ()
        while True:
            # A gt2/bootstrap value can live in the same hidden field as the
            # final callback token. Once a real challenge surface was observed,
            # an unchanged bootstrap value is not completion evidence.
            tokens = await self.read_final_tokens()
            vendor_pass, vendor_failures, verifier_events = _network_verification(
                self.network_events
            )
            if (tokens and vendor_pass is not None) or time.monotonic() >= deadline:
                break
            wait = getattr(self.page, "wait_for_timeout", None)
            if wait is None:
                break
            await wait(200)

        token_length = max((len(token) for token in tokens), default=0)
        site = self.diagnostics.get("site_verification")
        site_verified = site.get("ok") if isinstance(site, dict) else None
        gaps: list[str] = []
        if token_length == 0:
            gaps.append("arkose_vendor_token_not_captured")
        if vendor_pass is not True:
            gaps.append("arkose_vendor_pass_not_observed")
        if site_verified is False:
            gaps.append("site_verification_not_observed")
        accepted = token_length > 0 and vendor_pass is True and site_verified is not False
        record = {
            "accepted": accepted,
            "submitted": self._submitted,
            "token_length": token_length,
            "token_persisted": False,
            "vendor_pass": vendor_pass,
            "vendor_failures": vendor_failures,
            "verifier_events": list(verifier_events),
            "site_verified": site_verified,
            "gaps": gaps,
        }
        self.diagnostics["arkose_session_verification"] = record
        return VendorVerification(
            provider="arkose",
            accepted=accepted,
            token_length=token_length,
            vendor_pass=vendor_pass,
            vendor_failures=vendor_failures,
            site_verified=site_verified,
            verifier_events=verifier_events,
            gaps=tuple(gaps),
        )

    def _save_replay(self, state: _ArkoseState) -> None:
        if self.output_root is None:
            return
        self.output_root.mkdir(parents=True, exist_ok=True)
        stem = f"arkose-{self._sequence:02d}-{state.signature[:16]}"
        (self.output_root / f"{stem}.png").write_bytes(state.screenshot)
        (self.output_root / f"{stem}.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "observation": state.observation.to_dict(),
                    "vision_task": {
                        "kind": state.task.kind,
                        "prompt": state.task.prompt,
                        "width": state.task.width,
                        "height": state.task.height,
                        "candidate_count": state.task.candidate_count,
                        "choices": list(state.task.choices),
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )


def _merge_loop_diagnostics(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key == "session":
            continue
        if isinstance(value, list):
            target.setdefault(key, []).extend(value)
        elif key not in target:
            target[key] = value


async def _site_verification(
    page: Any,
    *,
    submit_selector: str | None,
    success_selectors: list[str] | None,
    success_text: str | None,
    verification_wait_ms: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "submit_selector": submit_selector,
        "submit_clicked": False,
        "matched_selectors": [],
        "matched_text": False,
    }
    if submit_selector:
        try:
            await page.locator(submit_selector).first.click(timeout=3000)
            result["submit_clicked"] = True
        except Exception as exc:
            result["submit_error"] = f"{type(exc).__name__}: {exc}"
    if verification_wait_ms > 0:
        await page.wait_for_timeout(verification_wait_ms)
    for selector in success_selectors or []:
        try:
            locator = page.locator(selector).first
            if await locator.count() and await locator.is_visible(timeout=300):
                result["matched_selectors"].append(selector)
        except Exception:
            continue
    if success_text:
        try:
            body_text = await page.locator("body").inner_text(timeout=1000)
            result["matched_text"] = success_text in body_text
        except Exception:
            pass
    assertions = bool(success_selectors or success_text)
    if assertions:
        result["ok"] = bool(
            (not submit_selector or result["submit_clicked"])
            and (not success_selectors or result["matched_selectors"])
            and (not success_text or result["matched_text"])
        )
    return result


class ArkoseCaptchaSolver:
    """Run an Arkose widget in Playwright and retain only redacted evidence."""

    async def solve(
        self,
        *,
        target_url: str,
        headless: bool | str | None = True,
        browser_binary: str | None = None,
        proxy_server: str | None = None,
        use_env_proxy: bool | None = None,
        proxy_bypass: str | None = "127.0.0.1,localhost",
        timeout_sec: int = 120,
        wait_after_load_ms: int = 1800,
        click_selectors: list[str] | None = None,
        auto_click: bool = True,
        screenshot: str | None = None,
        html_output: str | None = None,
        output_json: str | None = None,
        output_dir: str | None = None,
        user_agent: str | None = None,
        locale: str | None = None,
        timezone_id: str | None = None,
        solve_challenge: bool = True,
        max_rounds: int = 12,
        vision_backend: VisionBackend | None = None,
        vision_base_url: str | None = None,
        vision_api_key: str | None = None,
        vision_api_key_env: str | None = "ANTIBOT_VISION_API_KEY",
        vision_model: str | None = "gpt-5.4",
        vision_timeout_sec: float = 180,
        vision_min_confidence: float = 0.35,
        vision_retries: int = 2,
        vision_extra_body: dict[str, Any] | None = None,
        submit_selector: str | None = None,
        success_selectors: list[str] | None = None,
        success_text: str | None = None,
        verification_wait_ms: int = 4000,
    ) -> CaptchaResult:
        started = time.monotonic()
        diagnostics: dict[str, Any] = {
            "target_url": target_url,
            "provider": "arkose",
            "proxy": redacted_proxy(proxy_server),
        }
        raw: dict[str, Any] = {"provider": "arkose", "events": []}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        token: str | None = None
        verification = VendorVerification(
            provider="arkose", accepted=False, gaps=("arkose_flow_not_started",)
        )
        page: Any = None
        context: Any = None
        browser: Any = None
        playwright: Any = None
        response_tasks: set[asyncio.Task[Any]] = set()

        if not isinstance(target_url, str) or not target_url.strip():
            return CaptchaResult(
                provider="arkose",
                ok=False,
                captcha_type="funcaptcha",
                capability="browser_flow",
                errors=["target_url must be a non-empty string"],
            )

        try:
            from playwright.async_api import async_playwright

            backend: VisionBackend | None = None
            backend_error: str | None = None
            if solve_challenge:
                try:
                    backend = _resolve_vision_backend(
                        vision_backend,
                        base_url=vision_base_url,
                        api_key=vision_api_key,
                        api_key_env=vision_api_key_env,
                        model=vision_model or "gpt-5.4",
                        timeout_sec=vision_timeout_sec,
                        extra_body=vision_extra_body,
                    )
                except Exception as exc:
                    backend_error = f"{type(exc).__name__}: {exc}"
            diagnostics["vision_backend_configured"] = backend is not None
            diagnostics["challenge_engine"] = {
                "engine": "arkose-open-vocabulary-vision",
                "ready": backend is not None,
                "model": getattr(backend, "model", vision_model or "gpt-5.4") if backend else None,
                "supported_tasks": ["binary", "point", "multiple_choice", "drag_drop"],
                "minimum_confidence": vision_min_confidence,
                "inference_attempts": max(1, vision_retries),
            }
            if backend_error:
                diagnostics["challenge_engine"]["error"] = backend_error

            resolved_proxy = resolve_runtime_proxy(proxy_server, use_env=use_env_proxy)
            if resolved_proxy:
                diagnostics["proxy"] = resolved_proxy.redacted_url
            playwright = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {
                "headless": _headless(headless),
                "env": proxy_free_environment(),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                ],
            }
            executable = _discover_browser(browser_binary)
            if executable:
                launch_kwargs["executable_path"] = executable
            if resolved_proxy:
                proxy_kwargs = resolved_proxy.playwright()
                if proxy_bypass:
                    proxy_kwargs["bypass"] = proxy_bypass
                launch_kwargs["proxy"] = proxy_kwargs
            browser = await playwright.chromium.launch(**launch_kwargs)
            diagnostics["browser_binary"] = executable
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if user_agent:
                context_kwargs["user_agent"] = user_agent
            if locale:
                context_kwargs["locale"] = locale
            if timezone_id:
                context_kwargs["timezone_id"] = timezone_id
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.add_init_script(ARKOSE_HOOK_JS)

            async def consume_response(response: Any) -> None:
                url = str(getattr(response, "url", ""))
                if not any(marker in url.casefold() for marker in ARKOSE_CHALLENGE_MARKERS):
                    return
                event: dict[str, Any] = {
                    "kind": "arkose_response",
                    "url": _redact_event_url(url),
                    "status": getattr(response, "status", None),
                }
                if ARKOSE_VERIFY_MARKER in url:
                    payload: Any = None
                    try:
                        payload = await response.json()
                    except Exception:
                        try:
                            text = await response.text()
                            payload = _arkose_payload_from_text(text)
                        except Exception:
                            payload = None
                    event["pass"] = _arkose_pass_from_payload(payload)
                    status_value = _response_status_value(payload)
                    if status_value is not None:
                        event["response_status"] = status_value
                    diagnostics.setdefault("arkose_verification_responses", []).append(
                        {
                            "url": event["url"],
                            "status": event["status"],
                            "pass": event["pass"],
                            "response_status": status_value,
                            "token_persisted": False,
                        }
                    )
                raw["events"].append(event)
                if len(raw["events"]) > 250:
                    del raw["events"][:-250]

            def schedule_response(response: Any) -> None:
                task = asyncio.create_task(consume_response(response))
                response_tasks.add(task)
                task.add_done_callback(response_tasks.discard)

            page.on("response", schedule_response)
            deadline = time.monotonic() + max(1, int(timeout_sec))
            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=max(1, int((deadline - time.monotonic()) * 1000)),
            )
            await page.wait_for_timeout(
                min(max(0, wait_after_load_ms), max(0, int((deadline - time.monotonic()) * 1000)))
            )
            if auto_click:
                for selector in click_selectors or []:
                    try:
                        await page.locator(selector).first.click(timeout=1500)
                    except Exception:
                        continue

            session = ArkoseChallengeSession(
                page,
                diagnostics=diagnostics,
                network_events=raw["events"],
                output_dir=output_dir,
                max_rounds=max_rounds,
                verification_wait_ms=verification_wait_ms,
            )
            # Arkose may spend several seconds on its browser-risk check
            # before replacing the full-screen shell with the puzzle.
            ready_deadline = min(deadline, time.monotonic() + 30)
            while time.monotonic() < ready_deadline:
                tokens = await session.read_tokens()
                vendor_pass, _, _ = _network_verification(raw["events"])
                if tokens and vendor_pass is True:
                    break
                if await session._find_surface() is not None:
                    break
                await page.wait_for_timeout(200)

            if backend is not None:
                loop_result = await ChallengeAgentLoop(
                    session,
                    VisionChallengePolicy(
                        backend,
                        solve_policy=VisionSolvePolicy(
                            min_confidence=vision_min_confidence,
                            retries=max(1, vision_retries),
                            require_confidence=True,
                            allow_uncertain=True,
                        ),
                    ),
                    max_steps=max(4, max_rounds * 2),
                    timeout_sec=max(0.1, deadline - time.monotonic()),
                ).run()
                _merge_loop_diagnostics(diagnostics, loop_result.diagnostics)
                diagnostics.setdefault("arkose_agent_runs", []).append(
                    {
                        "status": loop_result.status,
                        "accepted": loop_result.accepted,
                        "steps": loop_result.steps,
                        "elapsed_ms": loop_result.elapsed_ms,
                        "errors": list(loop_result.errors),
                        "verification": loop_result.verification.to_dict(),
                    }
                )
                verification = loop_result.verification
                if not loop_result.accepted:
                    errors.extend(loop_result.errors)
            else:
                verification = await session.verify()
                if not verification.accepted:
                    errors.extend(verification.gaps)
                    if await session._find_surface() is not None:
                        errors.append(
                            "arkose_challenge_engine_unavailable"
                            + (f": {backend_error}" if backend_error else "")
                        )

            tokens = await session.read_final_tokens()
            if verification.accepted and tokens:
                token = max(tokens, key=len)

            if token and (submit_selector or success_selectors or success_text):
                site = await _site_verification(
                    page,
                    submit_selector=submit_selector,
                    success_selectors=success_selectors,
                    success_text=success_text,
                    verification_wait_ms=verification_wait_ms,
                )
                diagnostics["site_verification"] = site
                if site.get("ok") is False:
                    errors.append("site_verification_not_observed")
                    verification = VendorVerification(
                        provider="arkose",
                        accepted=False,
                        token_length=verification.token_length,
                        vendor_pass=verification.vendor_pass,
                        vendor_failures=verification.vendor_failures,
                        site_verified=False,
                        verifier_events=verification.verifier_events,
                        gaps=tuple(dict.fromkeys((*verification.gaps, "site_verification_not_observed"))),
                    )

            diagnostics["final_url"] = page.url
            diagnostics["title"] = await page.title()
            diagnostics["token_len"] = len(token or "")
            diagnostics["token_persisted"] = False
            output_root = Path(output_dir).expanduser().resolve() if output_dir else None
            if output_root:
                output_root.mkdir(parents=True, exist_ok=True)

            def artifact_path(value: str) -> Path:
                path = Path(value).expanduser()
                if output_root and not path.is_absolute():
                    path = output_root / path
                return path.resolve()

            if screenshot:
                screenshot_path = artifact_path(screenshot)
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(screenshot_path), full_page=True)
                artifacts["screenshot"] = str(screenshot_path)
            if html_output:
                html_path = artifact_path(html_output)
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_path.write_text(await page.content(), encoding="utf-8")
                artifacts["html"] = str(html_path)
        except Exception as exc:
            errors.append(f"Arkose browser flow failed: {type(exc).__name__}: {exc}")
        finally:
            if response_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tuple(response_tasks), return_exceptions=True),
                        timeout=2,
                    )
                except Exception:
                    pass
            for resource in (context, browser):
                if resource is not None:
                    try:
                        await resource.close()
                    except Exception:
                        pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except Exception:
                    pass

        raw["event_count"] = len(raw["events"])
        raw["token_len"] = len(token or "")
        ok = bool(token) and verification.accepted
        result = CaptchaResult(
            provider="arkose",
            ok=ok,
            captcha_type="funcaptcha",
            capability="browser_flow",
            ticket=token if ok else None,
            verify_code="vendor_pass_and_token_captured" if ok else None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            artifacts=artifacts,
            diagnostics=diagnostics,
            raw=raw,
            errors=list(dict.fromkeys(errors)),
        )
        if output_dir:
            output_path = Path(output_dir).expanduser().resolve()
            output_path.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_path)
        json_target = output_json
        if json_target is None and output_dir:
            json_target = str(Path(output_dir).expanduser().resolve() / "result.json")
        if json_target:
            json_path = Path(json_target).expanduser()
            if output_dir and not json_path.is_absolute():
                json_path = Path(output_dir).expanduser() / json_path
            json_path = json_path.resolve()
            json_path.parent.mkdir(parents=True, exist_ok=True)
            artifacts["output_json"] = str(json_path)
            persist_result(result, json_path)
        return result


__all__ = [
    "ARKOSE_ALIASES",
    "ARKOSE_CHALLENGE_MARKERS",
    "ARKOSE_HOOK_JS",
    "ARKOSE_HOST_MARKERS",
    "ARKOSE_URL_MARKERS",
    "ARKOSE_TOKEN_SELECTORS",
    "ARKOSE_VERIFY_MARKER",
    "ArkoseCaptchaSolver",
    "ArkoseChallengeSession",
    "detect_arkose_provider",
    "normalize_arkose_provider",
]
