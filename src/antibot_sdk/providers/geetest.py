from __future__ import annotations

import asyncio
import base64
import json
import math
import random
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_GEETEST_DEMO_URL = "https://www.geetest.com/en/adaptive-captcha-demo"
DEFAULT_GEETEST_SLIDE_DEMO_URL = "https://gt4.geetest.com/demov4/slide-popup-zh.html"
DEFAULT_GEETEST_GOBANG_DEMO_URL = "https://gt4.geetest.com/demov4/winlinze-popup-en.html"
GEETEST_HOST_MARKERS = (
    "gcaptcha4.geetest.com",
    "static.geetest.com/v4",
    "geetest.com/v4",
    "api.geetest.com",
)
VERIFY_PATH = "/verify"
LOAD_PATH = "/load"
GEETEST_SUCCESS_KEYS = ("lot_number", "captcha_output", "pass_token", "gen_time")
GEETEST_VARIANT_ALIASES = {
    "auto": "auto",
    "observe": "observe",
    "ai": "ai",
    "no-captcha": "ai",
    "nocaptcha": "ai",
    "no_captcha": "ai",
    "slide": "slide",
    "slider": "slide",
    "icon": "icon",
    "gobang": "winlinze",
    "winlinze": "winlinze",
    "iconcrush": "match",
    "icon_crush": "match",
    "match": "match",
}
GEETEST_DEMO_VARIANT_TEXT = {
    "ai": "No CAPTCHA",
    "slide": "Slide CAPTCHA",
    "icon": "Icon CAPTCHA",
    "winlinze": "Gobang CAPTCHA",
    "match": "IconCrush CAPTCHA",
}

DEFAULT_TRIGGER_SELECTORS = (
    ".config-right #captcha .geetest_btn_click[aria-label='Click to verify']",
    ".config-right #captcha .geetest_btn_click",
    ".config-right #captcha .geetest_holder",
    "text=Click to verify",
    "text=Verify",
    "text=点击验证",
    "text=完成验证",
    "#btn",
    "#captcha",
    "[aria-label*='验证']",
    "[aria-label*='verify']",
    ".gt4-public-click",
    ".geetest_btn",
    ".geetest_radar_btn",
    ".geetest_holder",
)

GEETEST_HOOK_JS = r"""
(() => {
  if (window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.installed) return;
  try { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); } catch {}

  const safe = (value, depth = 0) => {
    if (depth > 4) return '[depth]';
    if (value === null || value === undefined) return value;
    const t = typeof value;
    if (t === 'string' || t === 'number' || t === 'boolean') return value;
    if (t === 'function') return `[Function:${value.name || 'anonymous'}]`;
    if (value instanceof Element) {
      const r = value.getBoundingClientRect();
      return {
        tag: value.tagName,
        id: value.id || '',
        className: String(value.className || ''),
        rect: { x: r.x, y: r.y, width: r.width, height: r.height },
      };
    }
    if (Array.isArray(value)) return value.slice(0, 40).map((x) => safe(x, depth + 1));
    if (t === 'object') {
      const out = {};
      for (const k of Object.keys(value).slice(0, 100)) {
        try { out[k] = safe(value[k], depth + 1); }
        catch (e) { out[k] = `[throws:${e && e.message}]`; }
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
    pushEvent(type, detail) {
      this.events.push({ at: Date.now(), type, detail: safe(detail) });
      if (this.events.length > 240) this.events.shift();
    },
    pushValidate(source, instance) {
      try {
        if (!instance || typeof instance.getValidate !== 'function') return null;
        const value = instance.getValidate();
        this.validates.push({ at: Date.now(), source, value: safe(value) });
        if (this.validates.length > 80) this.validates.shift();
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
        configs: this.configs.slice(-20),
        events: this.events.slice(-120),
        validates: this.validates.slice(-40),
        errors: this.errors.slice(-40),
        methodCalls: this.methodCalls.slice(-180),
        instances: this.instances.slice(-20),
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
        } catch (e) {
          ret.push({ ok: false, method: 'showCaptcha', error: e && e.message });
        }
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
      if (state.methodCalls.length > 240) state.methodCalls.shift();
      if (['onSuccess', 'onReady', 'onNextReady', 'onError', 'onFail', 'onClose'].includes(name)
          && typeof args[0] === 'function') {
        const cb = args[0];
        args[0] = function(...cbArgs) {
          state.pushEvent(name, cbArgs);
          if (name === 'onSuccess') state.pushValidate('onSuccess', obj);
          return cb.apply(this, cbArgs);
        };
      }
      const ret = original.apply(this, args);
      if (name === 'getValidate') {
        state.validates.push({ at: Date.now(), source: 'getValidate-call', value: safe(ret) });
        if (state.validates.length > 80) state.validates.shift();
      }
      return ret;
    };
    wrapped.__antibotWrapped = true;
    obj[name] = wrapped;
  };

  const wrapCaptchaObj = (obj, config) => {
    if (!obj || obj.__antibotWrapped) return obj;
    const instanceId = state.instances.length + 1;
    const methods = [
      'appendTo', 'bindForm', 'showCaptcha', 'verify', 'reset', 'destroy', 'getValidate',
      'onReady', 'onNextReady', 'onSuccess', 'onError', 'onFail', 'onClose',
    ];
    for (const name of methods) wrapMethod(obj, name, instanceId);
    try { obj.__antibotWrapped = true; } catch {}
    state._instances.push(obj);
    state.instances.push({
      id: instanceId,
      config: safe(config),
      methods: methods.filter((name) => typeof obj[name] === 'function'),
    });
    state.pushEvent('instance-wrapped', { instanceId });
    return obj;
  };

  const wrapInit = (fn) => {
    if (typeof fn !== 'function' || fn.__antibotWrapped) return fn;
    const wrapped = function(config, callback, ...rest) {
      state.configs.push({ at: Date.now(), config: safe(config) });
      if (state.configs.length > 50) state.configs.shift();
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


class GeetestV4ParseError(ValueError):
    pass


def parse_geetest_jsonp(text: str) -> dict[str, Any]:
    """Parse GeeTest v4 JSONP callback payload."""

    raw = (text or "").strip().rstrip(";")
    if not raw:
        raise GeetestV4ParseError("empty GeeTest JSONP payload")
    if raw.startswith("{"):
        return json.loads(raw)
    match = re.match(r"^[\w.$]+\((.*)\)$", raw, flags=re.S)
    if not match:
        raise GeetestV4ParseError("invalid GeeTest JSONP wrapper")
    return json.loads(match.group(1))


def geetest_query(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return {key: values[-1] for key, values in qs.items() if values}


def parse_geetest_v4_event(url: str, text: str | None = None) -> dict[str, Any] | None:
    """Normalize GeeTest v4 load/verify JSONP response plus URL params."""

    lower_url = url.lower()
    if not any(marker in lower_url for marker in GEETEST_HOST_MARKERS):
        return None
    parsed = urlparse(url)
    query = geetest_query(url)
    kind = "verify" if VERIFY_PATH in parsed.path else "load" if LOAD_PATH in parsed.path else "asset"
    event: dict[str, Any] = {
        "kind": kind,
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path,
        "query": query,
    }
    if text:
        try:
            payload = parse_geetest_jsonp(text)
        except Exception as exc:
            event["parse_error"] = f"{type(exc).__name__}: {exc}"
            return event
        event["response_payload"] = payload
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(payload, dict):
            for key in ("status", "code", "msg", "message"):
                if payload.get(key) is not None:
                    event[f"top_{key}"] = payload.get(key)
        if isinstance(data, dict):
            event["data"] = data
            for key in (
                "captcha_id",
                "lot_number",
                "captcha_type",
                "risk_type",
                "payload",
                "process_token",
                "pow_detail",
                "js",
                "css",
                "static_path",
                "gct_path",
                "imgs",
                "ques",
                "slice",
                "bg",
                "ypos",
                "arrow",
            ):
                if data.get(key) is not None:
                    event[key] = data.get(key)
            challenge = normalize_geetest_challenge(data)
            if challenge:
                event["challenge"] = challenge
            if data.get("result") is not None:
                event["result"] = data.get("result")
            seccode = data.get("seccode")
            if isinstance(seccode, dict):
                event["seccode"] = seccode
                for key in ("captcha_id", "lot_number", "pass_token", "gen_time", "captcha_output"):
                    if seccode.get(key) is not None:
                        event[key] = seccode.get(key)
    for key in ("captcha_id", "lot_number", "risk_type", "payload", "client_type"):
        if query.get(key) is not None and event.get(key) is None:
            event[key] = query.get(key)
    return event


def normalize_geetest_variant(value: str | None) -> str:
    if not value:
        return "auto"
    return GEETEST_VARIANT_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())


def normalize_geetest_challenge(data: dict[str, Any]) -> dict[str, Any]:
    """Keep GeeTest v4 visual challenge fields in one stable structure."""

    challenge: dict[str, Any] = {}
    captcha_type = data.get("captcha_type") or data.get("risk_type")
    if captcha_type is not None:
        challenge["captcha_type"] = captcha_type
    assets: dict[str, Any] = {}
    for key in ("imgs", "ques", "slice", "bg", "ypos", "arrow"):
        if data.get(key) is not None:
            assets[key] = data.get(key)
    if assets:
        challenge["assets"] = assets
    for key in ("lot_number", "process_token", "payload", "payload_protocol", "pow_detail"):
        if data.get(key) is not None:
            challenge[key] = data.get(key)
    return challenge


def is_geetest_success_payload(value: Any) -> bool:
    return isinstance(value, dict) and all(bool(value.get(k)) for k in GEETEST_SUCCESS_KEYS)


def latest_geetest_success(state: dict[str, Any] | list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if isinstance(state, list):
        return geetest_v4_success_from_events(state)
    if not isinstance(state, dict):
        return None
    for item in reversed(state.get("validates") or []):
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if is_geetest_success_payload(value):
            return dict(value)
    return None


def geetest_v4_success_from_events(
    events: list[dict[str, Any]],
    variants: set[str] | None = None,
) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("kind") != "verify":
            continue
        if variants:
            event_variant = normalize_geetest_variant(
                str(event.get("risk_type") or event.get("captcha_type") or "")
            )
            if event_variant not in variants:
                continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        seccode = event.get("seccode") if isinstance(event.get("seccode"), dict) else {}
        result = str(data.get("result") or event.get("result") or event.get("top_status") or "").lower()
        if (result == "success" or seccode.get("pass_token")) and seccode.get("pass_token"):
            solution = {
                "captcha_id": seccode.get("captcha_id") or event.get("captcha_id"),
                "lot_number": seccode.get("lot_number") or event.get("lot_number"),
                "pass_token": seccode.get("pass_token"),
                "gen_time": seccode.get("gen_time"),
                "captcha_output": seccode.get("captcha_output"),
                "result": data.get("result"),
                "risk_type": event.get("risk_type") or (event.get("query") or {}).get("risk_type"),
                "payload": (event.get("query") or {}).get("payload"),
                "source": "verify_jsonp",
            }
            if event.get("captcha_type") is not None:
                solution["captcha_type"] = event.get("captcha_type")
            return solution
    return None


def geetest_v4_success_for_variant(
    events: list[dict[str, Any]],
    requested_variant: str = "auto",
) -> dict[str, Any] | None:
    variant = normalize_geetest_variant(requested_variant)
    if variant in {"auto", "observe"}:
        return geetest_v4_success_from_events(events)
    return geetest_v4_success_from_events(events, {variant})


def _headless(value: bool | str | None) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return value.lower() not in {"0", "false", "headed", "no", "off"}


def _interesting_url(url: str) -> bool:
    u = url.lower()
    return any(x in u for x in ("geetest", "gcaptcha4", "/gt4/", "captcha_v4", "captcha4"))


def _latest_load_event(events: list[dict[str, Any]], *variants: str) -> dict[str, Any] | None:
    wanted = {normalize_geetest_variant(v) for v in variants if v}
    for event in reversed(events):
        if event.get("kind") != "load":
            continue
        variant = normalize_geetest_variant(
            str(event.get("captcha_type") or event.get("risk_type") or "")
        )
        if not wanted or variant in wanted:
            return event
    return None


def find_geetest_winlinze_move(board: list[list[int]]) -> dict[str, Any] | None:
    """Find the deterministic GeeTest Gobang/winlinze move from the 5x5 matrix."""

    if len(board) != 5 or any(len(row) != 5 for row in board):
        raise ValueError("winlinze board must be 5x5")
    lines: list[tuple[str, list[tuple[int, int]]]] = []
    lines.extend((f"row-{row}", [(row, col) for col in range(5)]) for row in range(5))
    lines.extend((f"col-{col}", [(row, col) for row in range(5)]) for col in range(5))
    lines.append(("diag-main", [(idx, idx) for idx in range(5)]))
    lines.append(("diag-anti", [(idx, 4 - idx) for idx in range(5)]))

    for line_name, cells in lines:
        values = [int(board[row][col]) for row, col in cells]
        zeros = [cells[idx] for idx, value in enumerate(values) if value == 0]
        non_zero = [value for value in values if value != 0]
        if len(zeros) != 1 or len(non_zero) != 4 or len(set(non_zero)) != 1:
            continue
        value = non_zero[0]
        line_set = set(cells)
        for row in range(5):
            for col in range(5):
                if (row, col) in line_set:
                    continue
                if int(board[row][col]) == value:
                    return {
                        "source": {"row": row, "col": col},
                        "target": {"row": zeros[0][0], "col": zeros[0][1]},
                        "value": value,
                        "line": {"name": line_name, "cells": [{"row": r, "col": c} for r, c in cells]},
                    }
    return None


def find_geetest_match_swap(board: list[list[int]]) -> dict[str, Any] | None:
    """Find a GeeTest IconCrush/match adjacent swap for a 3x3 matrix."""

    if len(board) != 3 or any(len(row) != 3 for row in board):
        raise ValueError("match board must be 3x3")

    def lines_after(candidate: list[list[int]]) -> list[dict[str, Any]]:
        lines: list[dict[str, Any]] = []
        for x in range(3):
            values = [int(candidate[x][y]) for y in range(3)]
            if len(set(values)) == 1:
                lines.append(
                    {"name": f"x-{x}", "cells": [{"x": x, "y": y} for y in range(3)], "value": values[0]}
                )
        for y in range(3):
            values = [int(candidate[x][y]) for x in range(3)]
            if len(set(values)) == 1:
                lines.append(
                    {"name": f"y-{y}", "cells": [{"x": x, "y": y} for x in range(3)], "value": values[0]}
                )
        return lines

    original_lines = {line["name"] for line in lines_after(board)}
    for x in range(3):
        for y in range(3):
            for nx, ny in ((x + 1, y), (x, y + 1)):
                if nx >= 3 or ny >= 3:
                    continue
                candidate = [list(row) for row in board]
                candidate[x][y], candidate[nx][ny] = candidate[nx][ny], candidate[x][y]
                new_lines = [line for line in lines_after(candidate) if line["name"] not in original_lines]
                if new_lines:
                    return {
                        "source": {"x": x, "y": y},
                        "target": {"x": nx, "y": ny},
                        "line": new_lines[0],
                        "board_after": candidate,
                    }
    return None


def _css_url(value: str | None) -> str:
    if not value or value == "none":
        return ""
    match = re.search(r"url\((.*?)\)", value)
    if not match:
        return ""
    url = match.group(1).strip().strip('"\'')
    return unquote(url)


def _data_url_bytes(url: str) -> bytes | None:
    if not url.startswith("data:"):
        return None
    _head, _sep, payload = url.partition(",")
    if not payload:
        return b""
    if ";base64" in _head:
        return base64.b64decode(payload)
    return unquote(payload).encode()


def _image_dimensions(image_bytes: bytes) -> tuple[int, int]:
    import cv2
    import numpy as np

    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)
    if image is None:
        raise ValueError("failed to decode image dimensions")
    return int(image.shape[1]), int(image.shape[0])


def _finite_score(score: float) -> float:
    if math.isfinite(float(score)):
        return float(score)
    return -1.0


def detect_geetest_slide_gap(
    bg_bytes: bytes,
    slice_bytes: bytes,
    *,
    expected_y: float | None = None,
) -> dict[str, Any]:
    """Detect GeeTest v4 slide distance from background/slice images with CV."""

    import cv2
    import numpy as np

    bg_arr = np.frombuffer(bg_bytes, dtype=np.uint8)
    slice_arr = np.frombuffer(slice_bytes, dtype=np.uint8)
    bg = cv2.imdecode(bg_arr, cv2.IMREAD_COLOR)
    piece = cv2.imdecode(slice_arr, cv2.IMREAD_UNCHANGED)
    if bg is None or piece is None:
        raise ValueError("failed to decode geetest slide images")
    if piece.ndim != 3:
        raise ValueError("invalid geetest slice image")

    if piece.shape[2] >= 4:
        rgb = piece[:, :, :3]
        alpha = piece[:, :, 3]
        mask = ((alpha > 30).astype(np.uint8)) * 255
    else:
        rgb = piece[:, :, :3]
        gray_piece = cv2.cvtColor(rgb, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray_piece, 40, 120)
        mask = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=2)
        if int(mask.sum()) <= 0:
            mask = np.full(gray_piece.shape, 255, dtype=np.uint8)

    ys, xs = np.where(mask > 0)
    if len(xs) == 0 or len(ys) == 0:
        raise ValueError("geetest slice mask is empty")

    trim_x0, trim_x1 = int(xs.min()), int(xs.max()) + 1
    trim_y0, trim_y1 = int(ys.min()), int(ys.max()) + 1
    template = rgb[trim_y0:trim_y1, trim_x0:trim_x1]
    template_mask = mask[trim_y0:trim_y1, trim_x0:trim_x1]
    if template.shape[0] < 8 or template.shape[1] < 8:
        raise ValueError("geetest slice template is too small")
    if bg.shape[0] < template.shape[0] or bg.shape[1] < template.shape[1]:
        raise ValueError("geetest background is smaller than slice template")

    candidates: list[dict[str, Any]] = []

    def push_candidate(name: str, score: float, loc: tuple[int, int]) -> dict[str, Any]:
        raw_x, raw_y = int(loc[0]), int(loc[1])
        item = {
            "name": name,
            "distance_x": max(0, raw_x - trim_x0),
            "distance_y": max(0, raw_y - trim_y0),
            "match_x": raw_x,
            "match_y": raw_y,
            "score": _finite_score(score),
        }
        candidates.append(item)
        return item

    color_res = cv2.matchTemplate(bg, template, cv2.TM_CCORR_NORMED, mask=template_mask)
    _min_val, color_score, _min_loc, color_loc = cv2.minMaxLoc(color_res)
    color_candidate = push_candidate("color_template", color_score, color_loc)

    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(bg, cv2.COLOR_BGR2HSV)
    shadow_maps = {
        "shadow_dark": 255 - gray,
        "shadow_low_sat": cv2.normalize(
            (255 - gray).astype(np.float32) * (255 - hsv[:, :, 1]).astype(np.float32),
            None,
            0,
            255,
            cv2.NORM_MINMAX,
        ).astype(np.uint8),
    }
    bg_edges = cv2.Canny(gray, 45, 135)
    mask_edges = cv2.Canny(template_mask, 40, 120)
    if int(mask_edges.sum()) > 0:
        shadow_maps["edge_shape"] = bg_edges
        edge_template = cv2.dilate(mask_edges, np.ones((2, 2), np.uint8), iterations=1)
    else:
        edge_template = template_mask

    expected_match_y = int(round(float(expected_y) + trim_y0)) if expected_y is not None else None
    y_band = max(18, int((trim_y1 - trim_y0) * 0.45))
    shadow_items: list[dict[str, Any]] = []
    for name, image in shadow_maps.items():
        tmpl = edge_template if name == "edge_shape" else template_mask
        res = cv2.matchTemplate(image, tmpl, cv2.TM_CCORR_NORMED)
        if expected_match_y is not None:
            ylo = max(0, expected_match_y - y_band)
            yhi = min(res.shape[0] - 1, expected_match_y + y_band)
            if yhi <= ylo:
                continue
            band = res[ylo : yhi + 1, :]
            _min_v, score, _min_l, loc = cv2.minMaxLoc(band)
            loc = (int(loc[0]), int(loc[1]) + ylo)
        else:
            _min_v, score, _min_l, loc = cv2.minMaxLoc(res)
        item = push_candidate(name, score, loc)
        if item["distance_x"] > 0:
            shadow_items.append(item)

    def shadow_rank(item: dict[str, Any]) -> float:
        rank = float(item["score"])
        name = str(item.get("name") or "")
        if name == "shadow_low_sat":
            rank += 0.035
        elif name == "shadow_dark":
            rank += 0.012
        if expected_y is not None:
            y_err = abs(float(item["distance_y"]) - float(expected_y))
            rank -= min(0.06, y_err / max(1.0, y_band) * 0.035)
        if float(item["distance_x"]) < 45 and any(
            float(other["distance_x"]) > 70 and float(other["score"]) >= float(item["score"]) - 0.05
            for other in shadow_items
        ):
            rank -= 0.055
        return rank

    shadow_candidate = max(shadow_items, key=shadow_rank) if shadow_items else None

    chosen = color_candidate
    if shadow_candidate:
        diff = abs(float(shadow_candidate["distance_x"]) - float(color_candidate["distance_x"]))
        direct_edge = color_candidate["distance_x"] <= 3 or color_candidate["distance_x"] >= max(
            4, bg.shape[1] - piece.shape[1] + 8
        )
        shadow_strong = shadow_candidate["score"] >= 0.86
        direct_weak = color_candidate["score"] < 0.91
        color_y_err = abs(float(color_candidate["distance_y"]) - float(expected_y)) if expected_y is not None else 0.0
        shadow_y_err = abs(float(shadow_candidate["distance_y"]) - float(expected_y)) if expected_y is not None else 0.0
        if (
            (direct_edge and shadow_candidate["score"] >= 0.82)
            or (expected_y is not None and shadow_y_err + 10 < color_y_err and shadow_candidate["score"] >= color_candidate["score"] - 0.08)
            or (diff > 35 and shadow_strong and direct_weak)
            or (diff > 20 and shadow_rank(shadow_candidate) >= color_candidate["score"] + 0.005)
            or (diff > 70 and shadow_candidate["score"] >= 0.84)
            or (color_candidate["score"] < 0.82 and shadow_rank(shadow_candidate) > color_candidate["score"] + 0.02)
        ):
            chosen = shadow_candidate

    return {
        "gap_x": int(chosen["distance_x"]),
        "distance_x": int(chosen["distance_x"]),
        "distance_y": int(chosen["distance_y"]),
        "match_x": int(chosen["match_x"]),
        "match_y": int(chosen["match_y"]),
        "score": float(chosen["score"]),
        "method": chosen["name"],
        "expected_y": expected_y,
        "candidates": candidates[:10],
        "bg_size": {"width": int(bg.shape[1]), "height": int(bg.shape[0])},
        "slice_size": {"width": int(piece.shape[1]), "height": int(piece.shape[0])},
        "trim": {"x0": trim_x0, "y0": trim_y0, "x1": trim_x1, "y1": trim_y1},
    }


class GeetestV4Solver:
    """GeeTest v4 hook + browser slide solver + success payload collector."""

    async def solve(
        self,
        *,
        target_url: str = DEFAULT_GEETEST_DEMO_URL,
        headless: bool | str | None = True,
        browser_binary: str | None = None,
        proxy_server: str | None = None,
        timeout_sec: int = 90,
        wait_after_load_ms: int = 1200,
        click_selectors: list[str] | None = None,
        screenshot: str | bool | None = None,
        output_json: str | None = None,
        raw_events: bool = False,
        auto_trigger: bool = True,
        variant: str = "auto",
        slide_solve: bool = True,
        slide_max_attempts: int = 3,
        winlinze_max_attempts: int = 2,
        output_dir: str | None = None,
        save_html: bool = False,
        user_agent: str | None = None,
        locale: str | None = "zh-CN",
        timezone_id: str | None = "Asia/Shanghai",
    ) -> CaptchaResult:
        started = time.monotonic()
        deadline = started + max(1, int(timeout_sec))
        events: list[dict[str, Any]] = []
        net: list[dict[str, Any]] = []
        response_tasks: list[asyncio.Task] = []
        success_event = asyncio.Event()
        click_selectors = click_selectors or list(DEFAULT_TRIGGER_SELECTORS)
        requested_variant = normalize_geetest_variant(variant)
        output_root = Path(output_dir or tempfile.mkdtemp(prefix="antibot-geetest-"))
        artifacts: dict[str, str] = {"outputDir": str(output_root)}
        raw: dict[str, Any] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "target_url": target_url,
            "requested_variant": requested_variant,
            "net": net,
            "events": events,
            "trigger_selectors": click_selectors,
        }

        async def capture_response(resp: Any) -> None:
            url = resp.url
            if not _interesting_url(url):
                return
            parsed = urlparse(url)
            entry: dict[str, Any] = {
                "at": int(time.time() * 1000),
                "type": "response",
                "status": getattr(resp, "status", None),
                "url": url,
            }
            if len(net) < 400:
                net.append(entry)
            text = ""
            if LOAD_PATH in parsed.path or VERIFY_PATH in parsed.path:
                try:
                    text = await resp.text()
                    entry["body"] = text[:2200]
                except Exception as exc:
                    entry["body_error"] = f"{type(exc).__name__}: {exc}"
            event = parse_geetest_v4_event(url, text) or {"kind": "asset", "url": url}
            event["status"] = getattr(resp, "status", None)
            if len(events) < 400:
                events.append(event)
            if geetest_v4_success_for_variant(events, requested_variant):
                success_event.set()

        async def drain_response_tasks() -> None:
            nonlocal response_tasks
            if not response_tasks:
                return
            done = [task for task in response_tasks if task.done()]
            if done:
                await asyncio.gather(*done, return_exceptions=True)
                response_tasks = [task for task in response_tasks if not task.done()]

        browser = None
        playwright = None
        context = None
        page = None
        final_url = ""
        title = ""
        state: dict[str, Any] | None = None
        slide_attempts: list[dict[str, Any]] = []
        winlinze_attempts: list[dict[str, Any]] = []
        match_attempts: list[dict[str, Any]] = []
        trigger_clicks: list[dict[str, Any]] = []
        variant_selection: dict[str, Any] = {}
        show_calls: list[dict[str, Any]] = []
        error: dict[str, str] = {}

        async def write_artifacts() -> None:
            raw["event_count_total"] = len(events)
            raw["load_count_total"] = sum(1 for event in events if event.get("kind") == "load")
            raw["verify_count_total"] = sum(1 for event in events if event.get("kind") == "verify")
            raw["net_count_total"] = len(net)
            raw["events"] = events[-80:] if raw_events else _compact_events(events)
            raw["net"] = net[-120:] if raw_events else _compact_net(net)
            raw["state"] = _compact_state(state) if not raw_events else state or {}
            raw["slide_attempts"] = slide_attempts
            raw["winlinze_attempts"] = winlinze_attempts
            raw["match_attempts"] = match_attempts
            raw["trigger_clicks"] = trigger_clicks
            raw["variant_selection"] = variant_selection
            raw["show_captcha_calls"] = show_calls
            raw["final_url"] = final_url
            raw["title"] = title
            raw["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            if error:
                raw["error"] = error
            if output_json:
                path = Path(output_json)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(path)

        try:
            from playwright.async_api import async_playwright

            output_root.mkdir(parents=True, exist_ok=True)
            playwright = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {
                "headless": _headless(headless),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                ],
            }
            if not browser_binary:
                # Prefer full Chromium over headless-shell for captcha canvas/layout.
                for root in (Path.home() / ".cache" / "ms-playwright", Path("/ms-playwright")):
                    if root.exists():
                        found = sorted(root.glob("chromium-*/chrome-linux*/chrome"), reverse=True)
                        if found:
                            browser_binary = str(found[0])
                            break
            if browser_binary:
                launch_kwargs["executable_path"] = browser_binary
            from ..proxy import resolve_runtime_proxy

            proxy = parse_proxy(proxy_server) or resolve_runtime_proxy(None)
            if proxy:
                # Playwright natively supports username/password on proxy dict.
                launch_kwargs["proxy"] = proxy.playwright()

            browser = await playwright.chromium.launch(**launch_kwargs)
            context_kwargs: dict[str, Any] = {
                "ignore_https_errors": True,
                "viewport": {"width": 1365, "height": 900},
            }
            if locale:
                context_kwargs["locale"] = locale
            if timezone_id:
                context_kwargs["timezone_id"] = timezone_id
            if user_agent:
                context_kwargs["user_agent"] = user_agent
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.add_init_script(GEETEST_HOOK_JS)

            def on_request(req: Any) -> None:
                if _interesting_url(req.url) and len(net) < 400:
                    net.append(
                        {
                            "at": int(time.time() * 1000),
                            "type": "request",
                            "method": req.method,
                            "url": req.url,
                        }
                    )

            page.on("request", on_request)
            page.on("response", lambda resp: response_tasks.append(asyncio.create_task(capture_response(resp))))

            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=max(1000, int((deadline - time.monotonic()) * 1000)),
            )
            if wait_after_load_ms > 0:
                await page.wait_for_timeout(wait_after_load_ms)
            final_url = page.url
            title = await page.title()

            if requested_variant not in {"auto", "observe"}:
                variant_selection = await self._select_demo_variant(page, requested_variant)
                await drain_response_tasks()

            if auto_trigger and requested_variant != "observe":
                # Popup demos (slide/winlinze/match) need showCaptcha + DOM trigger
                # before the puzzle is laid out. AI/auto also benefit from the same path.
                show_calls = await self._show_all_captchas(page)
                trigger_clicks = await self._click_triggers(page, click_selectors)
                # Give popup animation time to switch opacity/layout after showCaptcha.
                await page.wait_for_timeout(900)
                if not await self._any_challenge_visible(page, timeout_ms=1200):
                    # Second pass: force show + click again (demo pages can race init).
                    show_calls = list(show_calls or []) + await self._show_all_captchas(page)
                    trigger_clicks = list(trigger_clicks or []) + await self._click_triggers(
                        page, click_selectors
                    )
                    await page.wait_for_timeout(700)
                await drain_response_tasks()

            state = await self._snapshot(page)
            hook_success = self._hook_success_for_requested(state, requested_variant)
            if hook_success:
                success_event.set()

            current_variant = self._current_variant(events, requested_variant=requested_variant)
            if (
                current_variant == "winlinze"
                and not hook_success
                and not geetest_v4_success_for_variant(events, requested_variant)
            ):
                remaining = max(3, int(deadline - time.monotonic()))
                winlinze_attempts = await self._solve_winlinze_challenge(
                    page,
                    events=events,
                    output_root=output_root,
                    max_attempts=max(1, int(winlinze_max_attempts)),
                    total_timeout_sec=remaining,
                )
            if (
                current_variant == "match"
                and not hook_success
                and not geetest_v4_success_for_variant(events, requested_variant)
            ):
                remaining = max(3, int(deadline - time.monotonic()))
                match_attempts = await self._solve_match_challenge(
                    page,
                    events=events,
                    output_root=output_root,
                    max_attempts=max(1, int(winlinze_max_attempts)),
                    total_timeout_sec=remaining,
                )
            if (
                slide_solve
                and current_variant in {"auto", "slide"}
                and not hook_success
                and not geetest_v4_success_for_variant(events, requested_variant)
            ):
                remaining = max(3, int(deadline - time.monotonic()))
                slide_attempts = await self._solve_slide_challenge(
                    page,
                    output_root=output_root,
                    max_attempts=max(1, int(slide_max_attempts)),
                    total_timeout_sec=remaining,
                )

            while time.monotonic() < deadline:
                await drain_response_tasks()
                state = await self._snapshot(page)
                hook_success = self._hook_success_for_requested(state, requested_variant)
                if hook_success or geetest_v4_success_for_variant(events, requested_variant):
                    success_event.set()
                    break
                try:
                    await asyncio.wait_for(success_event.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
                if success_event.is_set():
                    break

            if response_tasks:
                await asyncio.gather(*response_tasks, return_exceptions=True)
            state = await self._snapshot(page)
            final_url = page.url
            title = await page.title()

            if screenshot:
                if isinstance(screenshot, str):
                    shot_path = Path(screenshot)
                else:
                    shot_path = output_root / "geetest_page.png"
                shot_path.parent.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(shot_path), full_page=True)
                artifacts["screenshot"] = str(shot_path)
            if save_html:
                html_path = output_root / "geetest_page.html"
                html_path.write_text(await page.content(), encoding="utf-8")
                artifacts["html"] = str(html_path)
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
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

        solution = self._solution(events, state, requested_variant=requested_variant)
        raw["solution"] = solution
        raw["ok"] = bool(solution)
        await write_artifacts()
        return self._result(
            raw=raw,
            artifacts=artifacts,
            proxy_server=proxy_server,
            solution=solution,
            started=started,
            error=error,
        )

    def _hook_success_for_requested(
        self,
        state: dict[str, Any] | None,
        requested_variant: str,
    ) -> dict[str, Any] | None:
        # Visual puzzle variants should be proven by their own /verify risk_type.
        # Hook validates do not always carry the variant, and old demo instances can
        # still emit a default ai validate after a tab switch.
        variant = normalize_geetest_variant(requested_variant)
        if variant in {"auto", "observe", "ai"}:
            return latest_geetest_success(state)
        return None

    def _current_variant(self, events: list[dict[str, Any]], *, requested_variant: str) -> str:
        variant = normalize_geetest_variant(requested_variant)
        if variant not in {"auto", "observe"}:
            return variant
        latest = _latest_load_event(events)
        if latest:
            return normalize_geetest_variant(
                str(latest.get("captcha_type") or latest.get("risk_type") or "")
            )
        return variant

    async def _select_demo_variant(self, page: Any, variant: str) -> dict[str, Any]:
        variant = normalize_geetest_variant(variant)
        text = GEETEST_DEMO_VARIANT_TEXT.get(variant)
        index = {value: key for key, value in enumerate(["ai", "slide", "icon", "winlinze", "match"])}.get(
            variant
        )
        ret: dict[str, Any] = {"variant": variant}
        if index is None or not text:
            ret["skipped"] = "no_demo_tab_mapping"
            return ret
        selector = f".type-config .tab-item-{index}"
        ret["selector"] = selector
        try:
            await page.evaluate(
                """(selector) => {
                  const el = document.querySelector(selector);
                  if (el) el.scrollIntoView({ block: 'center', inline: 'center' });
                }""",
                selector,
            )
            await page.wait_for_timeout(250)
            loc = page.locator(selector).first
            if await loc.count():
                await loc.click(timeout=3500, force=True)
                ret["mode"] = "locator-force"
            else:
                ret["missing"] = True
                return ret
        except Exception as exc:
            ret["locator_error"] = str(exc)
            try:
                js_ret = await page.evaluate(
                    """async ({ selector, text }) => {
                      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                      const candidates = [
                        document.querySelector(selector),
                        ...Array.from(document.querySelectorAll('.type-config .tab-item')),
                      ].filter(Boolean);
                      const el = candidates.find((node) =>
                        (node.innerText || node.textContent || '').includes(text)
                      ) || candidates[0];
                      if (!el) return { ok: false, error: 'tab not found' };
                      el.scrollIntoView({ block: 'center', inline: 'center' });
                      await sleep(120);
                      const r = el.getBoundingClientRect();
                      const x = r.left + r.width / 2;
                      const y = r.top + r.height / 2;
                      el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: x, clientY: y }));
                      el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: y }));
                      el.click();
                      el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: x, clientY: y }));
                      return { ok: true, text: el.innerText || el.textContent || '' };
                    }""",
                    {"selector": selector, "text": text},
                )
                ret["mode"] = "dom-dispatch"
                ret["dom"] = js_ret
            except Exception as exc2:
                ret["dom_error"] = str(exc2)
        try:
            await page.wait_for_function(
                """({ selector, variant }) => {
                  const active = document.querySelector(selector + ' > button.on')
                    || document.querySelector(selector + ' button.on');
                  const state = window.__ANTIBOT_GEETEST;
                  const configs = state && state.configs || [];
                  const latest = configs.length ? configs[configs.length - 1].config || {} : {};
                  return Boolean(active) || latest.riskType === variant || latest.risk_type === variant;
                }""",
                arg={"selector": selector, "variant": variant},
                timeout=6000,
            )
            ret["active"] = True
        except Exception as exc:
            ret["active"] = False
            ret["active_error"] = str(exc)
        await page.wait_for_timeout(900)
        return ret

    async def _show_all_captchas(self, page: Any) -> list[dict[str, Any]]:
        try:
            ret = await page.evaluate(
                """() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.showAll
                    ? window.__ANTIBOT_GEETEST.showAll()
                    : []"""
            )
            return ret if isinstance(ret, list) else []
        except Exception as exc:
            return [{"ok": False, "error": str(exc)}]

    async def _click_triggers(self, page: Any, selectors: list[str]) -> list[dict[str, Any]]:
        # Text selectors are Playwright-only; DOM querySelector cannot parse them, so handle them first.
        ret: list[dict[str, Any]] = []
        for selector in [s for s in selectors if s.startswith("text=")]:
            try:
                loc = page.locator(selector).first
                if await loc.count():
                    await loc.click(timeout=1800)
                    ret.append({"selector": selector, "mode": "locator"})
                    await page.wait_for_timeout(300)
                    if await self._any_challenge_visible(page):
                        return ret
            except Exception as exc:
                ret.append({"selector": selector, "mode": "locator", "error": str(exc)})
        dom_selectors = [s for s in selectors if not s.startswith("text=")]
        try:
            dom_ret = await page.evaluate(
                """async (selectors) => {
                  const ret = [];
                  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                  const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const cs = getComputedStyle(el);
                    return r.width > 3 && r.height > 3 && cs.display !== 'none'
                      && cs.visibility !== 'hidden' && cs.opacity !== '0';
                  };
                  const challengeVisible = () => visible(document.querySelector('.geetest_box'))
                    || visible(document.querySelector('[class*="geetest_box"]'))
                    || visible(document.querySelector('.geetest_subitem'))
                    || visible(document.querySelector('[class*="geetest_subitem"]'))
                    || visible(document.querySelector('.geetest_bg'))
                    || visible(document.querySelector('[class*="geetest_bg"]'));
                  if (challengeVisible()) return ret;
                  for (const sel of selectors) {
                    let nodes = [];
                    try { nodes = Array.from(document.querySelectorAll(sel)); }
                    catch (e) { ret.push({ selector: sel, error: e.message }); continue; }
                    for (const el of nodes.slice(0, 6)) {
                      if (!visible(el)) continue;
                      const r = el.getBoundingClientRect();
                      try {
                        const x = r.left + r.width / 2;
                        const y = r.top + r.height / 2;
                        el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: x, clientY: y }));
                        el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: y }));
                        el.click();
                        el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: x, clientY: y }));
                        ret.push({
                          selector: sel,
                          tag: el.tagName,
                          id: el.id || '',
                          className: String(el.className || ''),
                          rect: { x: r.x, y: r.y, width: r.width, height: r.height },
                        });
                        await sleep(300);
                        if (challengeVisible()) return ret;
                      } catch (e) { ret.push({ selector: sel, error: e.message }); }
                      if (ret.length >= 16) return ret;
                    }
                  }
                  return ret;
                }""",
                dom_selectors,
            )
            if isinstance(dom_ret, list):
                ret.extend(dom_ret)
        except Exception as exc:
            ret.append({"mode": "dom", "error": str(exc)})
        return ret

    async def _wait_variant_load(
        self,
        events: list[dict[str, Any]],
        variant: str,
        *,
        timeout_sec: float,
    ) -> dict[str, Any] | None:
        deadline = time.monotonic() + max(0.2, timeout_sec)
        variant = normalize_geetest_variant(variant)
        while time.monotonic() < deadline:
            event = _latest_load_event(events, variant)
            if event:
                return event
            await asyncio.sleep(0.15)
        return _latest_load_event(events, variant)

    async def _solve_winlinze_challenge(
        self,
        page: Any,
        *,
        events: list[dict[str, Any]],
        output_root: Path,
        max_attempts: int,
        total_timeout_sec: int,
    ) -> list[dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        deadline = time.monotonic() + max(1, total_timeout_sec)
        for attempt_no in range(1, max_attempts + 1):
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "winlinze"}
            try:
                await self._ensure_challenge_visible(page, "winlinze")
                load_event = await self._wait_variant_load(
                    events,
                    "winlinze",
                    timeout_sec=max(1.0, min(8.0, deadline - time.monotonic())),
                )
                if not load_event:
                    attempt.update({"ok": False, "error": "winlinze load event not observed"})
                    attempts.append(attempt)
                    break
                board = (load_event.get("data") or {}).get("ques")
                if not isinstance(board, list):
                    attempt.update({"ok": False, "error": "winlinze board missing"})
                    attempts.append(attempt)
                    break
                move = find_geetest_winlinze_move(board)
                attempt["board"] = board
                attempt["move"] = move
                if not move:
                    attempt.update({"ok": False, "error": "winlinze move not found"})
                    attempts.append(attempt)
                    break
                cells = [
                    (move["source"]["row"], move["source"]["col"]),
                    (move["target"]["row"], move["target"]["col"]),
                ]
                rects = await self._cell_rects(page, "winlinze", cells)
                attempt["rects"] = rects
                if len(rects) != 2:
                    attempt.update({"ok": False, "error": "winlinze cell rect missing"})
                    attempts.append(attempt)
                    break
                await self._click_cell_pair(page, rects)
                await page.wait_for_timeout(1800)
                await self._collect_validates(page, "after-winlinze")
                outcome = await self._visual_outcome(page)
                attempt["outcome"] = outcome
                attempt["ok"] = bool(outcome.get("successText"))
                try:
                    shot = output_root / f"geetest_winlinze_{attempt_no}.png"
                    await page.screenshot(path=str(shot), full_page=True)
                    attempt["screenshot"] = str(shot)
                except Exception:
                    pass
                attempts.append(attempt)
                if attempt["ok"]:
                    break
            except Exception as exc:
                attempt["ok"] = False
                attempt["error"] = str(exc)
                attempt["errorType"] = type(exc).__name__
                attempts.append(attempt)
        return attempts

    async def _solve_match_challenge(
        self,
        page: Any,
        *,
        events: list[dict[str, Any]],
        output_root: Path,
        max_attempts: int,
        total_timeout_sec: int,
    ) -> list[dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        deadline = time.monotonic() + max(1, total_timeout_sec)
        for attempt_no in range(1, max_attempts + 1):
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "match"}
            try:
                await self._ensure_challenge_visible(page, "match")
                load_event = await self._wait_variant_load(
                    events,
                    "match",
                    timeout_sec=max(1.0, min(8.0, deadline - time.monotonic())),
                )
                if not load_event:
                    attempt.update({"ok": False, "error": "match load event not observed"})
                    attempts.append(attempt)
                    break
                board = (load_event.get("data") or {}).get("ques")
                if not isinstance(board, list):
                    attempt.update({"ok": False, "error": "match board missing"})
                    attempts.append(attempt)
                    break
                move = find_geetest_match_swap(board)
                attempt["board"] = board
                attempt["move"] = move
                if not move:
                    attempt.update({"ok": False, "error": "match swap not found"})
                    attempts.append(attempt)
                    break
                cells = [
                    (move["source"]["x"], move["source"]["y"]),
                    (move["target"]["x"], move["target"]["y"]),
                ]
                rects = await self._cell_rects(page, "match", cells)
                attempt["rects"] = rects
                if len(rects) != 2:
                    attempt.update({"ok": False, "error": "match cell rect missing"})
                    attempts.append(attempt)
                    break
                await self._click_cell_pair(page, rects)
                await page.wait_for_timeout(1800)
                await self._collect_validates(page, "after-match")
                outcome = await self._visual_outcome(page)
                attempt["outcome"] = outcome
                attempt["ok"] = bool(outcome.get("successText"))
                try:
                    shot = output_root / f"geetest_match_{attempt_no}.png"
                    await page.screenshot(path=str(shot), full_page=True)
                    attempt["screenshot"] = str(shot)
                except Exception:
                    pass
                attempts.append(attempt)
                if attempt["ok"]:
                    break
            except Exception as exc:
                attempt["ok"] = False
                attempt["error"] = str(exc)
                attempt["errorType"] = type(exc).__name__
                attempts.append(attempt)
        return attempts

    async def _ensure_challenge_visible(self, page: Any, variant: str) -> None:
        variant = normalize_geetest_variant(variant)
        variant_class = {"winlinze": "winlinze", "match": "match", "icon": "click"}.get(variant, variant)
        try:
            await page.wait_for_function(
                """(variantClass) => {
                  const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const cs = getComputedStyle(el);
                    return r.width > 20 && r.height > 20 && cs.display !== 'none'
                      && cs.visibility !== 'hidden' && cs.opacity !== '0';
                  };
                  return visible(document.querySelector(`[class*="geetest_${variantClass}"]`))
                    || visible(document.querySelector('.geetest_box'))
                    || visible(document.querySelector('[class*="geetest_box"]'));
                }""",
                arg=variant_class,
                timeout=5500,
            )
        except Exception:
            await page.evaluate(
                """async () => {
                  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                  const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const cs = getComputedStyle(el);
                    return r.width > 3 && r.height > 3 && cs.display !== 'none'
                      && cs.visibility !== 'hidden' && cs.opacity !== '0';
                  };
                  const challengeVisible = () => visible(document.querySelector('.geetest_box'))
                    || visible(document.querySelector('[class*="geetest_box"]'))
                    || visible(document.querySelector('.geetest_subitem'))
                    || visible(document.querySelector('[class*="geetest_subitem"]'));
                  const selectors = [
                    '.config-right #captcha .geetest_btn_click',
                    '.config-right #captcha .geetest_holder',
                    '[class*="geetest_btn_click"]',
                    '[class*="geetest_holder"]',
                    '#captcha',
                    '#btn',
                  ];
                  for (const sel of selectors) {
                    const nodes = Array.from(document.querySelectorAll(sel)).slice(0, 6);
                    for (const el of nodes) {
                      if (!visible(el)) continue;
                      const r = el.getBoundingClientRect();
                      const x = r.left + r.width / 2;
                      const y = r.top + r.height / 2;
                      try {
                        el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: x, clientY: y }));
                        el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: y }));
                        el.click();
                        el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: x, clientY: y }));
                        await sleep(450);
                        if (challengeVisible()) return;
                      } catch {}
                    }
                  }
                }"""
            )
            await page.wait_for_timeout(500)

    async def _cell_rects(
        self,
        page: Any,
        variant: str,
        cells: list[tuple[int, int]],
    ) -> list[dict[str, Any]]:
        variant = normalize_geetest_variant(variant)
        variant_class = "winlinze" if variant == "winlinze" else "match"
        return await page.evaluate(
            """({ variantClass, cells }) => {
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none'
                  && cs.visibility !== 'hidden' && cs.opacity !== '0';
              };
              const root = document.querySelector(`[class*="geetest_${variantClass}"]`) || document;
              const ret = [];
              for (const [a, b] of cells) {
                const selectors = [
                  `.geetest_item-${a}-${b}`,
                  `[class*="geetest_item-${a}-${b}"]`,
                ];
                let el = null;
                for (const sel of selectors) {
                  const nodes = Array.from(root.querySelectorAll(sel));
                  el = nodes.find(visible) || null;
                  if (el) break;
                }
                if (!el) continue;
                const r = el.getBoundingClientRect();
                ret.push({
                  a, b,
                  selector: `.geetest_item-${a}-${b}`,
                  x: r.x,
                  y: r.y,
                  width: r.width,
                  height: r.height,
                  cx: r.x + r.width / 2,
                  cy: r.y + r.height / 2,
                  className: String(el.className || ''),
                });
              }
              return ret;
            }""",
            {"variantClass": variant_class, "cells": cells},
        )

    async def _click_cell_pair(self, page: Any, rects: list[dict[str, Any]]) -> None:
        for idx, rect in enumerate(rects[:2]):
            x = float(rect["cx"]) + random.uniform(-2.5, 2.5)
            y = float(rect["cy"]) + random.uniform(-2.5, 2.5)
            await page.mouse.move(x, y)
            await page.wait_for_timeout(random.randint(80, 180))
            await page.mouse.click(x, y)
            if idx == 0:
                await page.wait_for_timeout(random.randint(180, 420))

    async def _collect_validates(self, page: Any, source: str) -> None:
        try:
            await page.evaluate(
                """(source) => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.collectValidates
                  ? window.__ANTIBOT_GEETEST.collectValidates(source)
                  : []""",
                source,
            )
        except Exception:
            pass

    async def _visual_outcome(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            r"""() => {
              const text = (document.body && document.body.innerText || '').replace(/\s+/g, ' ').trim();
              const validates = window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.validates || [];
              let latest = null;
              for (let i = validates.length - 1; i >= 0; i--) {
                const value = validates[i] && validates[i].value;
                if (value && value.lot_number && value.captcha_output && value.pass_token && value.gen_time) {
                  latest = value;
                  break;
                }
              }
              return {
                successText: /Verification Success|验证成功|验证通过|success/i.test(text),
                fail: /验证失败|请重试|try again|fail/i.test(text),
                payloadOk: Boolean(latest),
                latestValidate: latest,
                text: text.slice(0, 600),
              };
            }"""
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
        deadline = time.monotonic() + max(1, total_timeout_sec)
        for attempt_no in range(1, max_attempts + 1):
            if time.monotonic() >= deadline:
                break
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "slide"}
            try:
                await self._ensure_slide_visible(page)
                if not await self._slide_visible(page, timeout_ms=8000):
                    attempt.update({"ok": False, "error": "geetest slide challenge not visible"})
                    attempts.append(attempt)
                    break
                await page.wait_for_timeout(650)
                info = await self._slide_dom_info(page)
                attempt["dom"] = _compact_dom_info(info)
                bg_url = _css_url(info.get("bgImage"))
                slice_url = _css_url(info.get("sliceImage"))
                attempt["bgUrl"] = bg_url
                attempt["sliceUrl"] = slice_url
                if not bg_url or not slice_url:
                    attempt.update({"ok": False, "error": "missing geetest slide image url"})
                    attempts.append(attempt)
                    break

                bg_bytes = await self._fetch_bytes(page, bg_url)
                slice_bytes = await self._fetch_bytes(page, slice_url)
                bg_path = output_root / f"geetest_slide_bg_{attempt_no}.png"
                slice_path = output_root / f"geetest_slide_slice_{attempt_no}.png"
                bg_path.write_bytes(bg_bytes)
                slice_path.write_bytes(slice_bytes)
                attempt["artifacts"] = {"bg": str(bg_path), "slice": str(slice_path)}

                bg_w, bg_h = _image_dimensions(bg_bytes)
                expected_y = self._expected_slide_y(info, bg_width=bg_w, bg_height=bg_h)
                detection = detect_geetest_slide_gap(bg_bytes, slice_bytes, expected_y=expected_y)
                attempt["detection"] = detection
                display_width = float((info.get("bgRect") or {}).get("width") or bg_w)
                distance = float(detection["distance_x"]) * display_width / max(1, bg_w)
                attempt["distance"] = distance

                drag_result = await self._drag_geetest_slider(page, distance)
                attempt["drag"] = drag_result
                await page.wait_for_timeout(1800)
                await page.evaluate(
                    """() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.collectValidates
                      ? window.__ANTIBOT_GEETEST.collectValidates('after-drag')
                      : []"""
                )
                outcome = await self._slide_outcome(page)
                attempt["outcome"] = outcome
                attempt["ok"] = bool(outcome.get("success"))
                attempts.append(attempt)
                if attempt["ok"]:
                    break
                if attempt_no < max_attempts:
                    await self._refresh_slide(page)
            except Exception as exc:
                attempt["ok"] = False
                attempt["error"] = str(exc)
                attempt["errorType"] = type(exc).__name__
                attempts.append(attempt)
                if attempt_no < max_attempts:
                    try:
                        await self._refresh_slide(page)
                    except Exception:
                        pass
        return attempts

    async def _slide_visible(self, page: Any, timeout_ms: int = 1) -> bool:
        try:
            await page.wait_for_function(
                """() => {
                  const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const cs = getComputedStyle(el);
                    return r.width > 20 && r.height > 20 && cs.display !== 'none'
                      && cs.visibility !== 'hidden' && Number(cs.opacity || '1') > 0.05;
                  };
                  // Hash-suffixed classnames still contain geetest_bg / geetest_slice_bg.
                  const bg = document.querySelector('.geetest_bg')
                    || document.querySelector('[class*="geetest_bg"]');
                  const sliceBg = document.querySelector('.geetest_slice_bg')
                    || document.querySelector('[class*="geetest_slice_bg"]');
                  const sub = document.querySelector('.geetest_subitem.geetest_slide')
                    || document.querySelector('[class*="geetest_subitem"][class*="geetest_slide"]');
                  const captcha = document.querySelector('[class*="geetest_captcha"]');
                  const boxShown = captcha && String(captcha.className || '').includes('geetest_boxShow');
                  return visible(bg) || visible(sliceBg) || (boxShown && sub && Number(getComputedStyle(sub).opacity || '0') > 0.05);
                }""",
                timeout=timeout_ms,
            )
            return True
        except Exception:
            return False

    async def _any_challenge_visible(self, page: Any, timeout_ms: int = 1) -> bool:
        try:
            await page.wait_for_function(
                """() => {
                  const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const cs = getComputedStyle(el);
                    return r.width > 20 && r.height > 20 && cs.display !== 'none'
                      && cs.visibility !== 'hidden' && cs.opacity !== '0';
                  };
                  return visible(document.querySelector('.geetest_box'))
                    || visible(document.querySelector('[class*="geetest_box"]'))
                    || visible(document.querySelector('.geetest_subitem'))
                    || visible(document.querySelector('[class*="geetest_subitem"]'))
                    || visible(document.querySelector('.geetest_bg'))
                    || visible(document.querySelector('[class*="geetest_bg"]'));
                }""",
                timeout=timeout_ms,
            )
            return True
        except Exception:
            return False

    async def _slide_dom_info(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            """() => {
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none'
                  && cs.visibility !== 'hidden' && cs.opacity !== '0';
              };
              const rect = (el) => {
                if (!el) return null;
                const r = el.getBoundingClientRect();
                return { x: r.x, y: r.y, width: r.width, height: r.height };
              };
              const css = (el) => el ? getComputedStyle(el) : null;
              const one = (selectors) => {
                for (const sel of selectors) {
                  const nodes = Array.from(document.querySelectorAll(sel));
                  for (const el of nodes) if (visible(el)) return el;
                }
                return null;
              };
              const geetestNodes = Array.from(document.querySelectorAll('[class*="geetest"], [id*="geetest"]'));
              const imageNodes = geetestNodes.map((el) => {
                const s = css(el);
                const r = el.getBoundingClientRect();
                const className = String(el.className || '');
                return {
                  el,
                  className,
                  id: el.id || '',
                  bgImage: s ? s.backgroundImage : '',
                  rect: { x: r.x, y: r.y, width: r.width, height: r.height },
                  visible: visible(el),
                  area: r.width * r.height,
                  isSlice: /slice|piece|jigsaw/i.test(className),
                };
              }).filter((x) => x.visible && x.bgImage && x.bgImage !== 'none');
              const bgNodes = imageNodes.map(({ el, ...x }) => x);
              const bg = one(['.geetest_bg', '[class*="geetest_bg"]'])
                || (imageNodes.filter((x) => !x.isSlice).sort((a, b) => b.area - a.area)[0] || {}).el
                || (imageNodes.sort((a, b) => b.area - a.area)[0] || {}).el
                || null;
              const sliceBg = one([
                '.geetest_slice_bg', '[class*="geetest_slice_bg"]', '.geetest_slice [style*="url"]',
                '[class*="slice"] [style*="url"]',
              ]) || (imageNodes.filter((x) => x.isSlice).sort((a, b) => b.area - a.area)[0] || {}).el;
              const slice = one(['.geetest_slice', '[class*="geetest_slice"]', '[class*="slice"]']);
              const btn = one(['.geetest_btn', '.geetest_slider_button', '[class*="geetest_btn"]', '[class*="slider_button"]']);
              const track = one(['.geetest_track', '.geetest_slider', '[class*="geetest_track"]', '[class*="slider"]']);
              const bgStyle = css(bg);
              const sliceStyle = css(sliceBg || slice);
              return {
                bgImage: bgStyle ? bgStyle.backgroundImage : '',
                sliceImage: sliceStyle ? sliceStyle.backgroundImage : '',
                bgRect: rect(bg),
                sliceRect: rect(slice || sliceBg),
                sliceBgRect: rect(sliceBg),
                btnRect: rect(btn),
                trackRect: rect(track),
                imageCandidates: bgNodes.slice(0, 16),
              };
            }"""
        )

    def _expected_slide_y(
        self,
        info: dict[str, Any],
        *,
        bg_width: int,
        bg_height: int,
    ) -> float | None:
        bg_rect = info.get("bgRect") or {}
        slice_rect = info.get("sliceRect") or info.get("sliceBgRect") or {}
        if not bg_rect or not slice_rect:
            return None
        display_height = float(bg_rect.get("height") or 0)
        display_width = float(bg_rect.get("width") or 0)
        delta_y = float(slice_rect.get("y") or 0) - float(bg_rect.get("y") or 0)
        if display_height > 0:
            return max(0.0, delta_y * bg_height / display_height)
        if display_width > 0:
            return max(0.0, delta_y * bg_width / display_width)
        return None

    async def _ensure_slide_visible(self, page: Any) -> None:
        # Playwright locator clicks are more reliable than pure DOM dispatch for
        # popup demos that gate showCaptcha behind form submit / radar click.
        for selector in ("#btn", ".btn", ".geetest_btn_click", "text=提交", "text=Click to verify"):
            try:
                loc = page.locator(selector).first
                if await loc.count():
                    await loc.click(timeout=1800, force=True)
                    await page.wait_for_timeout(350)
                    if await self._slide_visible(page, timeout_ms=1200):
                        return
            except Exception:
                pass
        await page.evaluate(
            """async () => {
              const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none'
                  && cs.visibility !== 'hidden' && Number(cs.opacity || '1') > 0.05;
              };
              const slideReady = () => {
                const bg = document.querySelector('.geetest_bg')
                  || document.querySelector('[class*="geetest_bg"]');
                const captcha = document.querySelector('[class*="geetest_captcha"]');
                const boxShown = captcha && String(captcha.className || '').includes('geetest_boxShow');
                return visible(bg) || boxShown;
              };
              if (slideReady()) return;
              try {
                if (window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.showAll) {
                  window.__ANTIBOT_GEETEST.showAll();
                  await sleep(450);
                }
              } catch {}
              if (slideReady()) return;
              const selectors = [
                '#btn', '.btn', '.geetest_holder', '.geetest_btn_click', '#captcha',
                '[class*="geetest_holder"]', '[class*="geetest_radar"]', '[class*="geetest_btn_click"]',
                'button[type="submit"]', 'button',
              ];
              for (const sel of selectors) {
                const nodes = Array.from(document.querySelectorAll(sel)).slice(0, 8);
                for (const el of nodes) {
                  if (!visible(el) && sel !== '#btn' && sel !== '.btn') continue;
                  const r = el.getBoundingClientRect();
                  try {
                    const x = r.left + Math.max(r.width, 1) / 2;
                    const y = r.top + Math.max(r.height, 1) / 2;
                    el.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: x, clientY: y }));
                    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: x, clientY: y }));
                    el.click();
                    el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, clientX: x, clientY: y }));
                    await sleep(500);
                    if (slideReady()) return;
                  } catch {}
                }
              }
            }"""
        )
        # Final settle wait for popup opacity transition (subitem starts at opacity 0).
        await self._slide_visible(page, timeout_ms=3500)

    async def _fetch_bytes(self, page: Any, url: str) -> bytes:
        inline = _data_url_bytes(url)
        if inline is not None:
            return inline
        resolved = urljoin(page.url, url)
        resp = await page.context.request.get(resolved, timeout=15000)
        if not resp.ok:
            raise RuntimeError(f"failed to fetch geetest asset: {resp.status} {resolved}")
        return await resp.body()

    async def _drag_geetest_slider(self, page: Any, distance: float) -> dict[str, Any]:
        btn = await page.evaluate(
            """() => {
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none'
                  && cs.visibility !== 'hidden' && cs.opacity !== '0';
              };
              const selectors = ['.geetest_btn', '.geetest_slider_button', '[class*="geetest_btn"]', '[class*="slider_button"]'];
              for (const sel of selectors) {
                for (const el of Array.from(document.querySelectorAll(sel))) {
                  if (!visible(el)) continue;
                  const r = el.getBoundingClientRect();
                  return { x: r.x, y: r.y, width: r.width, height: r.height, selector: sel };
                }
              }
              return null;
            }"""
        )
        if not btn:
            return {"ok": False, "error": "geetest slider button not found"}
        start_x = float(btn["x"]) + float(btn["width"]) / 2
        start_y = float(btn["y"]) + float(btn["height"]) / 2
        await page.mouse.move(start_x + random.uniform(-0.8, 0.8), start_y + random.uniform(-0.6, 0.6))
        await page.wait_for_timeout(random.randint(80, 220))
        await page.mouse.down()

        trace: list[dict[str, float]] = []
        overshoot = random.uniform(2.0, 6.5)
        steps = random.randint(52, 78)
        for i in range(steps):
            t = (i + 1) / steps
            if t < 0.68:
                ease = 1 - (1 - t / 0.68) ** 3
                current = (distance + overshoot) * 0.88 * ease
            elif t < 0.88:
                ease = (t - 0.68) / 0.20
                current = (distance + overshoot) * (0.88 + 0.12 * (1 - (1 - ease) ** 2))
            else:
                ease = (t - 0.88) / 0.12
                current = distance + overshoot * (1 - ease)
            if i > steps - 12:
                current += random.uniform(-0.45, 0.45)
            y = start_y + math.sin(t * math.pi * random.uniform(1.2, 2.6)) * random.uniform(0.1, 1.0)
            x = start_x + current
            await page.mouse.move(x, y)
            trace.append({"x": round(x, 2), "y": round(y, 2), "t": round(t, 3)})
            # Variable cadence: slightly slower mid-drag, snappier settle.
            if t < 0.55:
                await page.wait_for_timeout(random.randint(10, 28))
            elif t < 0.85:
                await page.wait_for_timeout(random.randint(8, 22))
            else:
                await page.wait_for_timeout(random.randint(12, 30))

        await page.mouse.move(
            start_x + distance + random.uniform(-0.2, 0.2),
            start_y + random.uniform(-0.35, 0.35),
        )
        hold_ms = random.randint(280, 760)
        await page.wait_for_timeout(hold_ms)
        await page.mouse.up()
        return {
            "ok": True,
            "selector": btn.get("selector"),
            "distance": distance,
            "overshoot": round(overshoot, 2),
            "start": {"x": start_x, "y": start_y},
            "steps": steps,
            "holdMs": hold_ms,
            "traceSample": trace[:: max(1, len(trace) // 10)][:12],
        }

    async def _slide_outcome(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            r"""() => {
              const text = (document.body && document.body.innerText || '').replace(/\s+/g, ' ').trim();
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none'
                  && cs.visibility !== 'hidden' && cs.opacity !== '0';
              };
              const box = document.querySelector('.geetest_box') || document.querySelector('[class*="geetest_box"]');
              const fail = /验证失败|请重试|try again|fail/i.test(text);
              const successText = /验证成功|验证通过|success/i.test(text);
              const hidden = !visible(box);
              const validates = window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.validates || [];
              const latest = validates.length ? validates[validates.length - 1].value : null;
              const payloadOk = latest && latest.lot_number && latest.captcha_output
                && latest.pass_token && latest.gen_time;
              return {
                success: Boolean(payloadOk),
                payloadOk: Boolean(payloadOk),
                successText,
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
              const selectors = ['.geetest_refresh', '.geetest_refresh_tips', '[class*="geetest_refresh"]'];
              for (const sel of selectors) {
                for (const el of Array.from(document.querySelectorAll(sel))) {
                  try { el.click(); return true; } catch {}
                }
              }
              return false;
            }"""
        )
        if clicked:
            await page.wait_for_timeout(1200)

    async def _snapshot(self, page: Any) -> dict[str, Any] | None:
        try:
            state = await page.evaluate(
                """() => window.__ANTIBOT_GEETEST && window.__ANTIBOT_GEETEST.snapshot
                  ? window.__ANTIBOT_GEETEST.snapshot()
                  : null"""
            )
            return state if isinstance(state, dict) else None
        except Exception:
            return None

    def _solution(
        self,
        events: list[dict[str, Any]],
        state: dict[str, Any] | None,
        requested_variant: str = "auto",
    ) -> dict[str, Any] | None:
        verify_solution = geetest_v4_success_for_variant(events, requested_variant)
        if verify_solution:
            return verify_solution
        hook_solution = self._hook_success_for_requested(state, requested_variant)
        if not hook_solution:
            return None
        solution = dict(hook_solution)
        solution.setdefault("result", "success")
        solution.setdefault("source", "hook_getValidate")
        for event in reversed(events):
            if event.get("captcha_id") and not solution.get("captcha_id"):
                solution["captcha_id"] = event.get("captcha_id")
            if event.get("risk_type") and not solution.get("risk_type"):
                solution["risk_type"] = event.get("risk_type")
            if solution.get("captcha_id") and solution.get("risk_type"):
                break
        if isinstance(state, dict):
            configs = state.get("configs") or []
            for item in reversed(configs):
                cfg = item.get("config") if isinstance(item, dict) else None
                if not isinstance(cfg, dict):
                    continue
                solution.setdefault("captcha_id", cfg.get("captchaId") or cfg.get("captcha_id"))
                solution.setdefault("product", cfg.get("product"))
                break
        return solution

    def _result(
        self,
        *,
        raw: dict[str, Any],
        artifacts: dict[str, str],
        proxy_server: str | None,
        solution: dict[str, Any] | None,
        started: float,
        error: dict[str, str],
    ) -> CaptchaResult:
        ok = bool(solution)
        state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
        slide_attempts = raw.get("slide_attempts") if isinstance(raw.get("slide_attempts"), list) else []
        winlinze_attempts = (
            raw.get("winlinze_attempts") if isinstance(raw.get("winlinze_attempts"), list) else []
        )
        match_attempts = raw.get("match_attempts") if isinstance(raw.get("match_attempts"), list) else []
        diagnostics = {
            "target_url": raw.get("target_url"),
            "final_url": raw.get("final_url"),
            "title": raw.get("title"),
            "requested_variant": raw.get("requested_variant"),
            "captcha_id": (solution or {}).get("captcha_id"),
            "lot_number": (solution or {}).get("lot_number"),
            "risk_type": (solution or {}).get("risk_type"),
            "solution_source": (solution or {}).get("source"),
            "event_count": raw.get("event_count_total", len(raw.get("events") or [])),
            "load_count": raw.get(
                "load_count_total", sum(1 for event in raw.get("events") or [] if event.get("kind") == "load")
            ),
            "verify_count": raw.get(
                "verify_count_total", sum(1 for event in raw.get("events") or [] if event.get("kind") == "verify")
            ),
            "configs": len(state.get("configs") or []) if isinstance(state, dict) else 0,
            "validates": len(state.get("validates") or []) if isinstance(state, dict) else 0,
            "slide_attempts": len(slide_attempts),
            "slide_solved": any((attempt or {}).get("ok") for attempt in slide_attempts),
            "winlinze_attempts": len(winlinze_attempts),
            "winlinze_solved": any((attempt or {}).get("ok") for attempt in winlinze_attempts),
            "match_attempts": len(match_attempts),
            "match_solved": any((attempt or {}).get("ok") for attempt in match_attempts),
            "net_events": raw.get("net_count_total", len(raw.get("net") or [])),
            "proxy": redacted_proxy(proxy_server),
        }
        if error:
            diagnostics["error"] = error
        return CaptchaResult(
            provider="geetest",
            ok=ok,
            captcha_type=f"geetest_v4_browser_{(solution or {}).get('captcha_type') or (solution or {}).get('risk_type') or 'flow'}",
            capability="solver",
            ticket=(solution or {}).get("pass_token"),
            randstr=(solution or {}).get("lot_number"),
            verify_code=(solution or {}).get("result") if ok else None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            artifacts=artifacts,
            diagnostics=diagnostics,
            raw=raw,
            errors=[] if ok else [error.get("message") if error else "geetest_v4_success_not_observed"],
        )


# Backward-compatible name used by earlier prototypes.
GeeTestCaptchaSolver = GeetestV4Solver


def _compact_dom_info(info: dict[str, Any]) -> dict[str, Any]:
    keep = {
        "bgImage": info.get("bgImage"),
        "sliceImage": info.get("sliceImage"),
        "bgRect": info.get("bgRect"),
        "sliceRect": info.get("sliceRect"),
        "sliceBgRect": info.get("sliceBgRect"),
        "btnRect": info.get("btnRect"),
        "trackRect": info.get("trackRect"),
    }
    candidates = info.get("imageCandidates")
    if isinstance(candidates, list):
        keep["imageCandidates"] = candidates[:6]
    return {k: v for k, v in keep.items() if v not in (None, "", [], {})}


def _compact_state(state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {}
    return {
        "installed": state.get("installed"),
        "at": state.get("at"),
        "configs": state.get("configs", [])[-5:],
        "events": state.get("events", [])[-30:],
        "validates": state.get("validates", [])[-10:],
        "errors": state.get("errors", [])[-10:],
        "methodCalls": state.get("methodCalls", [])[-40:],
        "instances": state.get("instances", [])[-5:],
    }


def _compact_net(net: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact = []
    for item in net[-60:]:
        compact.append({k: v for k, v in item.items() if k != "body" and v not in (None, "", [], {})})
    return compact


def _compact_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact = []
    for event in events[-30:]:
        item = {
            key: event.get(key)
            for key in (
                "kind",
                "status",
                "host",
                "path",
                "captcha_id",
                "lot_number",
                "captcha_type",
                "risk_type",
                "result",
                "pass_token",
                "gen_time",
                "parse_error",
            )
            if event.get(key) not in (None, "", [], {})
        }
        compact.append(item)
    return compact
