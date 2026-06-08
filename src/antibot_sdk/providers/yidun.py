from __future__ import annotations

import asyncio
import itertools
import json
import math
import random
import re
import time
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageOps

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

YIDUN_POINT_OCR_CONFUSIONS: dict[str, set[str]] = {
    # RapidOCR is strong on clean Chinese crops, but these Yidun characters are
    # rotated, blended into natural photos, and sometimes partially occluded.
    # Keep the fallback map deliberately small: it is only used after exact
    # matches and still has to win the global one-to-one assignment.
    "全": {"金", "宝", "公", "叁", "参"},
    "来": {"米"},
    "扩": {"折", "拍", "式", "成", "区", "办", "专", "面", "护", "中"},
    "安": {"爱", "商", "中"},
    "类": {"美", "券", "拳", "泰", "茶", "新"},
    "元": {"无", "完", "先"},
    "体": {"保", "味"},
    "库": {"医"},
    "验": {"险", "健", "瑜", "喻", "输"},
    "特": {"持", "诗", "待", "鑫", "转", "本"},
}

_YIDUN_POINT_DDDD: Any | None = None
_YIDUN_POINT_RAPID: Any | None = None


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


def _clean_yidun_point_text(text: str | None) -> str:
    if not text:
        return ""
    # Prompt text is usually `"安" "验" "特"` or `请依次点击 "安" ...`.
    quoted = re.findall(r'["“”]\s*([\u3400-\u9fff])\s*["“”]', text)
    if quoted:
        return "".join(quoted)
    # Keep CJK only; it also normalizes API `front`.
    return "".join(re.findall(r"[\u3400-\u9fff]", text))


def _image_bytes_for_ocr(image: Image.Image, *, fmt: str = "JPEG") -> bytes:
    buf = BytesIO()
    if fmt.upper() == "JPEG":
        image.convert("RGB").save(buf, format="JPEG", quality=94)
    else:
        image.save(buf, format=fmt)
    return buf.getvalue()


def _point_ocr_engines() -> tuple[Any, Any]:
    global _YIDUN_POINT_DDDD, _YIDUN_POINT_RAPID
    if _YIDUN_POINT_DDDD is None:
        try:
            import ddddocr  # type: ignore
        except Exception as e:  # pragma: no cover - exercised by live env
            raise RuntimeError(
                "yidun picture-click needs optional OCR dependency ddddocr; "
                "install with `pip install ddddocr rapidocr-onnxruntime`"
            ) from e
        _YIDUN_POINT_DDDD = ddddocr.DdddOcr(det=True, show_ad=False)
    if _YIDUN_POINT_RAPID is None:
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore
        except Exception as e:  # pragma: no cover - exercised by live env
            raise RuntimeError(
                "yidun picture-click needs optional OCR dependency rapidocr-onnxruntime; "
                "install with `pip install ddddocr rapidocr-onnxruntime`"
            ) from e
        _YIDUN_POINT_RAPID = RapidOCR()
    return _YIDUN_POINT_DDDD, _YIDUN_POINT_RAPID


def _merge_point_box(
    boxes: list[dict[str, Any]],
    box: list[float],
    *,
    source: str,
    label: str | None = None,
    score: float | None = None,
) -> None:
    x1, y1, x2, y2 = box
    cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
    for item in boxes:
        bx1, by1, bx2, by2 = item["box"]
        bcx, bcy = (bx1 + bx2) / 2.0, (by1 + by2) / 2.0
        if abs(cx - bcx) < 12 and abs(cy - bcy) < 12:
            item["box"] = [min(bx1, x1), min(by1, y1), max(bx2, x2), max(by2, y2)]
            item.setdefault("sources", []).append(source)
            if label:
                item.setdefault("labels", []).append({"text": label, "score": float(score or 0), "source": source})
            return
    item = {"box": box, "sources": [source], "labels": []}
    if label:
        item["labels"].append({"text": label, "score": float(score or 0), "source": source})
    boxes.append(item)


def _detect_yidun_point_boxes(image: Image.Image) -> list[dict[str, Any]]:
    det, rapid = _point_ocr_engines()
    width, height = image.size
    boxes: list[dict[str, Any]] = []

    # DdddOCR's detector is very good at CAPTCHA object boxes, but its coordinate
    # scale can vary with generated PNG bytes. Feeding a 3x JPEG and normalizing
    # gives stable boxes in source-image coordinates.
    scaled = image.resize((width * 3, height * 3), Image.Resampling.LANCZOS)
    # Besides normal/color-enhanced passes, grayscale and inverse-grayscale are
    # important for dark glyphs blended into photo backgrounds. A hard sample
    # like `安验特` has a black `特` over boats/masts: the normal detector misses
    # it, but inverse/gray passes recover the box without doing a full sliding
    # OCR scan.
    gray_scaled = ImageOps.grayscale(scaled).convert("RGB")
    variants = (
        ("dddd:orig", scaled),
        ("dddd:contrast", ImageEnhance.Contrast(scaled).enhance(2.0)),
        (
            "dddd:sat",
            ImageEnhance.Contrast(ImageEnhance.Color(scaled).enhance(1.8)).enhance(1.7),
        ),
        ("dddd:inv", ImageOps.invert(scaled)),
        ("dddd:gray0", gray_scaled),
        ("dddd:invgray0", ImageOps.invert(gray_scaled)),
        ("dddd:gray", ImageEnhance.Contrast(gray_scaled).enhance(2.2)),
        ("dddd:invgray", ImageEnhance.Contrast(ImageOps.invert(gray_scaled)).enhance(2.0)),
        (
            "dddd:sharp",
            ImageEnhance.Sharpness(ImageEnhance.Contrast(scaled).enhance(2.0)).enhance(3.0),
        ),
    )
    for name, variant in variants:
        try:
            raw_boxes = det.detection(_image_bytes_for_ocr(variant))
        except Exception:
            raw_boxes = []
        for raw_box in raw_boxes or []:
            x1, y1, x2, y2 = [float(v) / 3.0 for v in raw_box]
            bw, bh = x2 - x1, y2 - y1
            if bw < 14 or bh < 14 or bw > 95 or bh > 90:
                continue
            if x1 < 2 and bw < 12:
                continue
            _merge_point_box(
                boxes,
                [max(0.0, x1), max(0.0, y1), min(float(width), x2), min(float(height), y2)],
                source=name,
            )

    # RapidOCR full-image passes add boxes/labels that DdddOCR occasionally
    # misses. These labels are also useful for quick exact matches.
    rapid_variants = (
        ("rapid:orig", image),
        ("rapid:contrast", ImageEnhance.Contrast(image).enhance(1.8)),
        (
            "rapid:sat",
            ImageEnhance.Contrast(ImageEnhance.Color(image).enhance(1.6)).enhance(1.6),
        ),
    )
    for source, variant in rapid_variants:
        try:
            result, _elapsed = rapid(np.array(variant))
        except Exception:
            result = None
        for item in result or []:
            if len(item) < 3:
                continue
            poly, text, conf = item[0], str(item[1] or ""), float(item[2] or 0)
            try:
                xs = [float(p[0]) for p in poly]
                ys = [float(p[1]) for p in poly]
            except Exception:
                continue
            x1, y1, x2, y2 = min(xs), min(ys), max(xs), max(ys)
            bw, bh = x2 - x1, y2 - y1
            if bw < 14 or bh < 14 or bw > 100 or bh > 95:
                continue
            _merge_point_box(
                boxes,
                [max(0.0, x1), max(0.0, y1), min(float(width), x2), min(float(height), y2)],
                source=source,
                label=text,
                score=conf,
            )

    return boxes


def _score_point_label_for_target(label: str, confidence: float, target_char: str) -> float:
    if not label:
        return 0.0
    if target_char in label:
        return max(0.0, confidence)
    confusions = YIDUN_POINT_OCR_CONFUSIONS.get(target_char, set())
    if any(ch in confusions for ch in label):
        # Exact OCR gets priority. Confusion scores are capped so they only fill
        # gaps when the exact character is not found. Do not floor the value:
        # very-low-confidence confusions should not steal an assignment from a
        # distractor box that happens to look vaguely similar.
        return min(0.62, max(0.0, confidence * 0.55))
    return 0.0


def _point_click_xy_for_box(image: Image.Image, box: list[float]) -> tuple[float, float]:
    """Return a stroke-biased click point for a detected glyph box."""

    width, height = image.size
    x1, y1, x2, y2 = [float(v) for v in box]
    x1i, y1i = max(0, int(math.floor(x1))), max(0, int(math.floor(y1)))
    x2i, y2i = min(width, int(math.ceil(x2))), min(height, int(math.ceil(y2)))
    if x2i - x1i < 4 or y2i - y1i < 4:
        return (x1 + x2) / 2.0, (y1 + y2) / 2.0
    crop = np.array(image.crop((x1i, y1i, x2i, y2i)).convert("RGB"))
    bgr = cv2.cvtColor(crop, cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    _h, sat, val = cv2.split(hsv)
    blur = cv2.GaussianBlur(gray, (0, 0), 3)
    diff = cv2.absdiff(gray, blur)
    mask = (
        ((sat > 65) & (diff > 5) & (val > 25))
        | ((gray < 110) & (diff > 5))
        | (diff > 32)
    )
    mask_u8 = (mask.astype(np.uint8)) * 255
    mask_u8 = cv2.medianBlur(mask_u8, 3)
    ys, xs = np.where(mask_u8 > 0)
    if len(xs) == 0:
        return (x1 + x2) / 2.0, (y1 + y2) / 2.0
    cx, cy = (x2i - x1i) / 2.0, (y2i - y1i) / 2.0
    dist = (xs.astype(np.float32) - cx) ** 2 + (ys.astype(np.float32) - cy) ** 2
    idx = int(np.argmin(dist))
    return float(x1i + xs[idx]), float(y1i + ys[idx])


def _recognize_yidun_point_box(
    image: Image.Image,
    box: list[float],
    target_chars: list[str],
    *,
    thorough: bool = False,
    preferred_chars: set[str] | None = None,
) -> tuple[dict[str, float], list[dict[str, Any]]]:
    _det, rapid = _point_ocr_engines()
    width, height = image.size
    x1, y1, x2, y2 = box
    bw, bh = max(1.0, x2 - x1), max(1.0, y2 - y1)
    # Tight boxes work best; add a second, larger crop for small boxes where the
    # detector may only cover the high-contrast strokes.
    pads = [0.14, 0.28] if bw < 34 or bh < 34 else [0.14]
    if thorough:
        pads = sorted({0.04, 0.14, *(pads or [])})
    # Most Yidun point glyphs are rotated around ±30 degrees. Keep the default
    # pass short; expand only when global assignment is missing/weak.
    angles = (-35, 0, 35)
    if thorough:
        angles = (0, -30, 30, 40, -40, -20, 20, -10, 10, -50, 50)
    scores: dict[str, float] = {}
    labels: list[dict[str, Any]] = []
    stop_chars = set(preferred_chars or target_chars)

    for pad in pads:
        xx1 = max(0, int(round(x1 - bw * pad)))
        yy1 = max(0, int(round(y1 - bh * pad)))
        xx2 = min(width, int(round(x2 + bw * pad)))
        yy2 = min(height, int(round(y2 + bh * pad)))
        if xx2 - xx1 < 8 or yy2 - yy1 < 8:
            continue
        base_crop = image.crop((xx1, yy1, xx2, yy2)).convert("RGB")
        contrast_crop = ImageEnhance.Contrast(ImageEnhance.Color(base_crop).enhance(1.7)).enhance(
            1.8
        )
        crop_variants: list[tuple[str, Image.Image]] = [("contrast", contrast_crop)]
        if thorough:
            crop_variants = [
                ("orig", base_crop),
                ("inv", ImageOps.invert(base_crop)),
                ("contrast", contrast_crop),
            ]
        for variant_name, crop in crop_variants:
            for angle in angles:
                rotated = crop.rotate(angle, expand=True, fillcolor=(255, 255, 255))
                scale = 4 if thorough else 3
                rotated = rotated.resize(
                    (max(1, rotated.width * scale), max(1, rotated.height * scale)),
                    Image.Resampling.LANCZOS,
                )
                try:
                    result, _elapsed = rapid(
                        np.array(rotated),
                        use_det=False,
                        use_cls=True,
                        use_rec=True,
                    )
                except Exception:
                    continue
                if not result:
                    continue
                text = str(result[0][0] or "")
                confidence = float(result[0][1] or 0)
                if not text:
                    continue
                labels.append(
                    {
                        "text": text,
                        "score": confidence,
                        "angle": angle,
                        "crop": [xx1, yy1, xx2, yy2],
                        "source": f"rapid:crop:{variant_name}",
                    }
                )
                for ch in set(target_chars):
                    score = _score_point_label_for_target(text, confidence, ch)
                    if score > scores.get(ch, 0.0):
                        scores[ch] = score
                exact_target = any(ch in text and confidence >= 0.30 for ch in stop_chars)
                stop_score = max((scores.get(ch, 0.0) for ch in stop_chars), default=0.0)
                if thorough and (stop_score >= 0.45 or exact_target):
                    labels.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
                    return scores, labels[:8]

    labels.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
    return scores, labels[:8]


def _assign_yidun_point_candidates(
    candidates: list[dict[str, Any]],
    target_chars: list[str],
    *,
    min_char_score: float,
) -> tuple[tuple[int, ...] | None, float]:
    best_score = -1.0
    best_perm: tuple[int, ...] | None = None
    if len(candidates) >= len(target_chars):
        for perm in itertools.permutations(range(len(candidates)), len(target_chars)):
            total = 0.0
            ok = True
            for ch, idx in zip(target_chars, perm):
                score = float((candidates[idx].get("scores") or {}).get(ch) or 0.0)
                if score < min_char_score:
                    ok = False
                    break
                total += score
            if ok and total > best_score:
                best_score = total
                best_perm = perm
    return best_perm, best_score


def _cjk_chars(text: str) -> set[str]:
    return set(re.findall(r"[\u3400-\u9fff]", text or ""))


def _point_candidate_needs_thorough(
    cand: dict[str, Any],
    *,
    missing_chars: set[str],
    target_chars: set[str],
) -> bool:
    """Return whether a candidate is worth expensive fallback OCR.

    When one target char is missing, blindly running expanded OCR on every box is
    slow. Most boxes can be skipped because they already have a strong label for
    another target/distractor, or are obvious non-CJK edge noise.
    """

    if not missing_chars:
        return True
    scores = cand.get("scores") or {}
    if any(float(scores.get(ch) or 0.0) >= 0.85 for ch in target_chars - missing_chars):
        return False
    labels = list(cand.get("labels") or [])
    if not labels:
        return True
    try:
        x1, y1, x2, y2 = [float(v) for v in cand.get("box") or []]
    except Exception:
        x1 = y1 = 0.0
        x2 = y2 = 99.0
    if (x1 <= 1.0 or y1 <= 1.0) and (x2 - x1 < 28 or y2 - y1 < 28):
        return False
    top = max(labels, key=lambda x: float(x.get("score") or 0.0))
    top_text = str(top.get("text") or "")
    top_score = float(top.get("score") or 0.0)
    chars = _cjk_chars(top_text)
    if not chars and top_score >= 0.45:
        return False
    if top_score >= 0.85:
        if not chars:
            return False
        if chars.isdisjoint(missing_chars):
            return False
    return True


def _write_yidun_point_debug_image(bg_bytes: bytes, detection: dict[str, Any], path: Path) -> None:
    """Draw candidate boxes and final click points for postmortem debugging."""

    image = Image.open(BytesIO(bg_bytes)).convert("RGB")
    draw = ImageDraw.Draw(image)
    for idx, cand in enumerate(detection.get("candidates") or []):
        try:
            x1, y1, x2, y2 = [float(v) for v in cand.get("box") or []]
        except Exception:
            continue
        scores = cand.get("scores") or {}
        score_text = ",".join(f"{k}:{float(v):.2f}" for k, v in scores.items()) or "?"
        draw.rectangle([x1, y1, x2, y2], outline=(255, 220, 0), width=2)
        draw.text((x1, max(0, y1 - 12)), f"{idx} {score_text}", fill=(255, 220, 0))
    for point in detection.get("points") or []:
        x, y = float(point.get("x") or 0), float(point.get("y") or 0)
        char = str(point.get("char") or "")
        draw.ellipse([x - 5, y - 5, x + 5, y + 5], outline=(255, 0, 0), width=3)
        draw.text((x + 6, y - 8), char, fill=(255, 0, 0))
    image.save(path)


def detect_yidun_point_targets(
    bg_bytes: bytes,
    target_text: str,
    *,
    min_char_score: float = 0.08,
) -> dict[str, Any]:
    """Detect NetEase Yidun picture-click target centers.

    The API exposes the target sequence (`front`) but not coordinates. The
    detector therefore combines:
    1) DdddOCR object detection for CAPTCHA glyph boxes;
    2) RapidOCR full-image and rotated-crop recognition;
    3) a conservative confusion map for heavily distorted glyphs;
    4) a global one-to-one assignment in the requested click order.
    """

    target = _clean_yidun_point_text(target_text)
    if not target:
        raise ValueError("empty yidun point target text")
    image = Image.open(BytesIO(bg_bytes)).convert("RGB")
    width, height = image.size
    boxes = _detect_yidun_point_boxes(image)

    candidates: list[dict[str, Any]] = []
    target_chars = list(target)
    for item in boxes:
        box = [float(x) for x in item["box"]]
        scores: dict[str, float] = {}
        labels = list(item.get("labels") or [])
        high_exact = False
        for label in labels:
            text = str(label.get("text") or "")
            confidence = float(label.get("score") or 0.0)
            for ch in set(target_chars):
                if ch in text and confidence >= 0.88:
                    high_exact = True
                score = _score_point_label_for_target(text, confidence, ch)
                if score > scores.get(ch, 0.0):
                    scores[ch] = score

        if not high_exact:
            crop_scores, crop_labels = _recognize_yidun_point_box(image, box, target_chars)
            for ch, score in crop_scores.items():
                if score > scores.get(ch, 0.0):
                    scores[ch] = score
            labels.extend(crop_labels)

        x1, y1, x2, y2 = box
        candidates.append(
            {
                "box": [round(x1, 2), round(y1, 2), round(x2, 2), round(y2, 2)],
                "center": {"x": round((x1 + x2) / 2.0, 2), "y": round((y1 + y2) / 2.0, 2)},
                "scores": {k: round(float(v), 4) for k, v in sorted(scores.items())},
                "labels": labels[:8],
                "sources": item.get("sources") or [],
            }
        )

    best_perm, best_score = _assign_yidun_point_candidates(
        candidates,
        target_chars,
        min_char_score=min_char_score,
    )

    # If the first pass is incomplete or only barely clears the threshold, run a
    # second, OCR-heavier pass over the existing detector boxes. This is the
    # difference between "works on easy colorful glyphs" and handling the harder
    # picture-click frames where one dark/rotated character is partially hidden
    # in the photo background.
    weakest_score = 0.0
    if best_perm is not None:
        weakest_score = min(
            float((candidates[idx].get("scores") or {}).get(ch) or 0.0)
            for ch, idx in zip(target_chars, best_perm)
        )
    thorough_indices: set[int] = set()
    preferred_by_idx: dict[int, set[str]] = {}
    if candidates and best_perm is None:
        missing_chars = {
            ch
            for ch in set(target_chars)
            if max(float((c.get("scores") or {}).get(ch) or 0.0) for c in candidates) < min_char_score
        }
        target_set = set(target_chars)
        thorough_indices = {
            idx
            for idx, cand in enumerate(candidates)
            if _point_candidate_needs_thorough(
                cand,
                missing_chars=missing_chars,
                target_chars=target_set,
            )
        }
        if not thorough_indices:
            thorough_indices = set(range(len(candidates)))
        for idx in thorough_indices:
            preferred_by_idx[idx] = set(missing_chars or target_chars)
    elif candidates and best_perm is not None and weakest_score < 0.18:
        for ch, idx in zip(target_chars, best_perm):
            score = float((candidates[idx].get("scores") or {}).get(ch) or 0.0)
            if score < 0.22:
                thorough_indices.add(idx)
                preferred_by_idx.setdefault(idx, set()).add(ch)

    if thorough_indices:
        for idx in sorted(thorough_indices):
            cand = candidates[idx]
            box = [float(x) for x in cand["box"]]
            crop_scores, crop_labels = _recognize_yidun_point_box(
                image,
                box,
                target_chars,
                thorough=True,
                preferred_chars=preferred_by_idx.get(idx),
            )
            scores = cand.setdefault("scores", {})
            for ch, score in crop_scores.items():
                if float(score) > float(scores.get(ch) or 0.0):
                    scores[ch] = round(float(score), 4)
            labels = list(cand.get("labels") or [])
            labels.extend(crop_labels)
            labels.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
            cand["labels"] = labels[:8]
        best_perm, best_score = _assign_yidun_point_candidates(
            candidates,
            target_chars,
            min_char_score=min_char_score,
        )

    points: list[dict[str, Any]] = []
    if best_perm is not None:
        for order, (ch, idx) in enumerate(zip(target_chars, best_perm), start=1):
            cand = candidates[idx]
            click_x, click_y = _point_click_xy_for_box(image, [float(v) for v in cand["box"]])
            points.append(
                {
                    "order": order,
                    "char": ch,
                    "x": round(click_x, 2),
                    "y": round(click_y, 2),
                    "center": cand["center"],
                    "score": float((cand.get("scores") or {}).get(ch) or 0.0),
                    "box": cand["box"],
                    "candidateIndex": idx,
                }
            )

    return {
        "ok": len(points) == len(target_chars),
        "target": target,
        "points": points,
        "score": round(best_score, 4) if best_perm is not None else 0.0,
        "candidates": candidates,
        "image_size": {"width": width, "height": height},
        "method": "ddddocr+rapidocr+assignment",
        "min_char_score": min_char_score,
    }


class YidunCaptchaSolver:
    """NetEase Yidun browser solver alpha: jigsaw + picture-click."""

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
        point_solve: bool = True,
        point_max_attempts: int = 6,
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
            "slideAttempts": [],
            "pointAttempts": [],
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

            raw["challengeKind"] = await self._wait_challenge_kind(page, raw)
            remaining_sec = int(overall_deadline - time.monotonic())
            if raw["challengeKind"] == "point" and point_solve:
                raw["pointAttempts"] = await self._solve_point_challenge(
                    page,
                    raw=raw,
                    output_root=output_root,
                    max_attempts=max(1, point_max_attempts),
                    total_timeout_sec=max(3, remaining_sec),
                )
            elif slide_solve:
                raw["slideAttempts"] = await self._solve_slide_challenge(
                    page,
                    output_root=output_root,
                    max_attempts=max(1, slide_max_attempts),
                    total_timeout_sec=max(3, remaining_sec),
                )

            state: dict[str, Any] | None = None
            success: dict[str, Any] | None = None
            while time.monotonic() < overall_deadline:
                state = await self._state(page)
                success = latest_yidun_success(raw, state)
                if success:
                    break
                if raw.get("slideAttempts") or raw.get("pointAttempts"):
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

    async def _challenge_kind(self, page: Any, raw: dict[str, Any] | None = None) -> str:
        dom = await page.evaluate(
            r"""() => {
              const visible = (el) => {
                if (!el) return false;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return r.width > 3 && r.height > 3 && cs.display !== 'none' && cs.visibility !== 'hidden';
              };
              const root = document.querySelector('.yidun');
              const cls = root ? String(root.className || '') : '';
              return {
                className: cls,
                sliderVisible: visible(document.querySelector('.yidun_slider')),
                bgVisible: visible(document.querySelector('.yidun_bg-img')),
                pointPrompt: (document.querySelector('.yidun_tips__point')
                  || document.querySelector('.yidun_tips__answer')
                  || document.querySelector('.yidun_control'))?.textContent || '',
                stateCaptchaType: (() => {
                  try {
                    const configs = window.__ANTIBOT_YIDUN?.snapshot?.().configs || [];
                    const cfg = configs.length ? configs[configs.length - 1].config || {} : {};
                    return cfg.captchaType || cfg.captcha_type || '';
                  } catch { return ''; }
                })(),
              };
            }"""
        )
        if dom.get("sliderVisible"):
            return "jigsaw"
        if str(dom.get("stateCaptchaType") or "").upper() == "POINT":
            return "point"
        cls = str(dom.get("className") or "")
        if "yidun--point" in cls:
            return "point"
        if raw:
            for item in reversed(raw.get("getResponses") or []):
                parsed = item.get("parsed") if isinstance(item, dict) else None
                data = parsed.get("data") if isinstance(parsed, dict) else None
                if isinstance(data, dict) and int(data.get("type") or 0) == 3:
                    return "point"
        if dom.get("bgVisible") and _clean_yidun_point_text(dom.get("pointPrompt")):
            return "point"
        return "unknown"

    async def _wait_challenge_kind(
        self,
        page: Any,
        raw: dict[str, Any] | None = None,
        *,
        timeout_ms: int = 9000,
    ) -> str:
        deadline = time.monotonic() + timeout_ms / 1000.0
        last = "unknown"
        while time.monotonic() < deadline:
            last = await self._challenge_kind(page, raw)
            if last != "unknown":
                return last
            await page.wait_for_timeout(300)
        return last

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
              const challengeVisible = () => visible(document.querySelector('.yidun_slider'))
                || visible(document.querySelector('.yidun_bg-img'));
              if (challengeVisible()) return ret;
              try {
                if (window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.popAll) {
                  ret.push({ selector: '__state__.popAll', calls: window.__ANTIBOT_YIDUN.popAll() });
                  await sleep(400);
                  if (challengeVisible()) return ret;
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
                    for (const type of ['mouseover', 'mouseenter', 'mousemove', 'mousedown', 'mouseup', 'click']) {
                      el.dispatchEvent(new MouseEvent(type, {
                        bubbles: true,
                        cancelable: true,
                        view: window,
                        clientX: r.left + r.width / 2,
                        clientY: r.top + r.height / 2,
                      }));
                      await sleep(70);
                    }
                    ret.push({ selector: sel, tag: el.tagName, id: el.id || '', className: String(el.className || ''), rect: { x: r.x, y: r.y, width: r.width, height: r.height } });
                    await sleep(300);
                    if (challengeVisible()) return ret;
                  } catch (e) { ret.push({ selector: sel, error: e.message }); }
                  if (ret.length >= 12) return ret;
                }
              }
              return ret;
            }""",
            selectors,
        )

    async def _solve_point_challenge(
        self,
        page: Any,
        *,
        raw: dict[str, Any],
        output_root: Path,
        max_attempts: int,
        total_timeout_sec: int,
    ) -> list[dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        deadline = time.monotonic() + total_timeout_sec
        for attempt_no in range(1, max_attempts + 1):
            if time.monotonic() >= deadline:
                break
            attempt: dict[str, Any] = {"attempt": attempt_no, "mode": "point"}
            try:
                info = await self._ensure_point_visible(page)
                attempt["dom"] = info
                bg_url = info.get("bgSrc") or ""
                target_text = (
                    _clean_yidun_point_text(info.get("targetText"))
                    or self._latest_point_front_from_get(raw)
                )
                attempt["bgUrl"] = bg_url
                attempt["target"] = target_text
                if not bg_url:
                    attempt["ok"] = False
                    attempt["error"] = "missing yidun point bg url"
                    attempts.append(attempt)
                    break
                if not target_text:
                    attempt["ok"] = False
                    attempt["error"] = "missing yidun point target text"
                    attempts.append(attempt)
                    if attempt_no < max_attempts:
                        await self._refresh_point(page)
                    continue

                bg_bytes = await self._fetch_bytes(page, bg_url)
                bg_path = output_root / f"yidun_point_bg_{attempt_no}.jpg"
                bg_path.write_bytes(bg_bytes)
                attempt["artifacts"] = {"bg": str(bg_path)}

                detection = detect_yidun_point_targets(bg_bytes, target_text)
                attempt["detection"] = detection
                debug_path = output_root / f"yidun_point_detect_{attempt_no}.png"
                try:
                    _write_yidun_point_debug_image(bg_bytes, detection, debug_path)
                    attempt["artifacts"]["debug"] = str(debug_path)
                except Exception as e:
                    attempt["debugImageError"] = str(e)
                if not detection.get("ok"):
                    attempt["ok"] = False
                    attempt["error"] = "point target detection incomplete"
                    attempts.append(attempt)
                    if attempt_no < max_attempts:
                        await self._refresh_point(page)
                    continue

                click_result = await self._click_yidun_points(page, detection)
                attempt["click"] = click_result
                await page.wait_for_timeout(2400)
                outcome = await self._point_outcome(page)
                attempt["outcome"] = outcome
                attempt["ok"] = bool(outcome.get("success"))
                attempts.append(attempt)
                if attempt["ok"]:
                    break
                if attempt_no < max_attempts:
                    await self._refresh_point(page)
            except Exception as e:
                attempt["ok"] = False
                attempt["error"] = str(e)
                attempt["errorType"] = type(e).__name__
                attempts.append(attempt)
                if attempt_no < max_attempts:
                    try:
                        await self._refresh_point(page)
                    except Exception:
                        pass
        return attempts

    def _latest_point_front_from_get(self, raw: dict[str, Any] | None) -> str:
        if not raw:
            return ""
        for item in reversed(raw.get("getResponses") or []):
            parsed = item.get("parsed") if isinstance(item, dict) else None
            data = parsed.get("data") if isinstance(parsed, dict) else None
            if isinstance(data, dict) and int(data.get("type") or 0) == 3:
                return _clean_yidun_point_text(str(data.get("front") or ""))
        return ""

    async def _ensure_point_visible(self, page: Any) -> dict[str, Any]:
        for _ in range(28):
            info = await self._point_dom_info(page)
            bg_rect = info.get("bgRect") or {}
            target = _clean_yidun_point_text(info.get("targetText"))
            root_class = str(info.get("rootClass") or "")
            loading = "yidun--loading" in root_class or "加载中" in str(info.get("targetText") or "")
            if (
                info.get("bgSrc")
                and float(bg_rect.get("width") or 0) > 20
                and float(bg_rect.get("height") or 0) > 20
                and target
                and not loading
            ):
                try:
                    await page.locator(".yidun_bg-img").first.scroll_into_view_if_needed(timeout=3000)
                except Exception:
                    pass
                return await self._point_dom_info(page)
            try:
                await page.evaluate(
                    r"""async () => {
                      const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                      try {
                        if (window.__ANTIBOT_YIDUN?.popAll) window.__ANTIBOT_YIDUN.popAll();
                      } catch {}
                      const el = document.querySelector('.yidun_control') || document.querySelector('.yidun');
                      if (el) {
                        try { el.scrollIntoView({ block: 'center' }); } catch {}
                        const r = el.getBoundingClientRect();
                        for (const type of ['mouseover', 'mouseenter', 'mousemove', 'mousedown', 'mouseup', 'click']) {
                          el.dispatchEvent(new MouseEvent(type, {
                            bubbles: true, cancelable: true, view: window,
                            clientX: r.left + r.width / 2, clientY: r.top + r.height / 2,
                          }));
                          await sleep(50);
                        }
                      }
                    }"""
                )
            except Exception:
                pass
            await page.wait_for_timeout(500)
        return await self._point_dom_info(page)

    async def _point_dom_info(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            r"""() => {
              const rect = (el) => {
                if (!el) return null;
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                return {
                  x: r.x, y: r.y, width: r.width, height: r.height,
                  display: cs.display, visibility: cs.visibility,
                };
              };
              const bg = document.querySelector('.yidun_bg-img');
              const panel = document.querySelector('.yidun_panel');
              const control = document.querySelector('.yidun_control');
              const root = document.querySelector('.yidun');
              const answer = document.querySelector('.yidun_tips__point')
                || document.querySelector('.yidun_tips__answer')
                || document.querySelector('.yidun_tips__content')
                || control;
              return {
                bgSrc: bg ? bg.src : '',
                bgRect: rect(bg),
                panelRect: rect(panel),
                controlRect: rect(control),
                rootClass: root ? String(root.className || '') : '',
                targetText: answer ? (answer.textContent || '') : '',
                controlText: control ? (control.textContent || '') : '',
              };
            }"""
        )

    async def _click_yidun_points(self, page: Any, detection: dict[str, Any]) -> dict[str, Any]:
        info = await self._point_dom_info(page)
        bg_rect = info.get("bgRect") or {}
        image_size = detection.get("image_size") or {}
        image_width = max(1.0, float(image_size.get("width") or 1))
        image_height = max(1.0, float(image_size.get("height") or 1))
        rect_x = float(bg_rect.get("x") or 0)
        rect_y = float(bg_rect.get("y") or 0)
        rect_w = float(bg_rect.get("width") or image_width)
        rect_h = float(bg_rect.get("height") or image_height)
        clicked: list[dict[str, Any]] = []
        # Let the challenge collect a small amount of pre-click motion.
        await page.mouse.move(
            rect_x + random.uniform(20, max(21, rect_w - 20)),
            rect_y + random.uniform(20, max(21, rect_h - 20)),
            steps=random.randint(8, 16),
        )
        await page.wait_for_timeout(random.randint(450, 900))
        last_x = rect_x + rect_w * random.uniform(0.25, 0.75)
        last_y = rect_y + rect_h * random.uniform(0.25, 0.75)
        for point in detection.get("points") or []:
            px = rect_x + float(point["x"]) * rect_w / image_width
            py = rect_y + float(point["y"]) * rect_h / image_height
            # Small human jitter, kept inside the target box center.
            px += random.uniform(-1.2, 1.2)
            py += random.uniform(-1.2, 1.2)
            steps = random.randint(14, 26)
            ctrl_x = (last_x + px) / 2 + random.uniform(-18, 18)
            ctrl_y = (last_y + py) / 2 + random.uniform(-12, 12)
            for i in range(1, steps + 1):
                t = i / steps
                # Quadratic Bezier with small tremor.
                bx = (1 - t) * (1 - t) * last_x + 2 * (1 - t) * t * ctrl_x + t * t * px
                by = (1 - t) * (1 - t) * last_y + 2 * (1 - t) * t * ctrl_y + t * t * py
                await page.mouse.move(
                    bx + random.uniform(-0.45, 0.45),
                    by + random.uniform(-0.45, 0.45),
                )
                await page.wait_for_timeout(random.randint(10, 28))
            await page.wait_for_timeout(random.randint(180, 420))
            await page.mouse.down()
            await page.wait_for_timeout(random.randint(65, 180))
            await page.mouse.up()
            last_x, last_y = px, py
            clicked.append(
                {
                    "char": point.get("char"),
                    "page": {"x": round(px, 2), "y": round(py, 2)},
                    "image": {"x": point.get("x"), "y": point.get("y")},
                    "score": point.get("score"),
                }
            )
            for _ in range(random.randint(1, 3)):
                await page.mouse.move(
                    px + random.uniform(-3, 3),
                    py + random.uniform(-3, 3),
                    steps=random.randint(1, 3),
                )
                await page.wait_for_timeout(random.randint(45, 140))
            await page.wait_for_timeout(random.randint(650, 1250))
        return {"ok": True, "clicked": clicked, "bgRect": bg_rect}

    async def _point_outcome(self, page: Any) -> dict[str, Any]:
        return await page.evaluate(
            r"""() => {
              const text = (document.body && document.body.innerText || '').replace(/\s+/g, ' ').trim();
              const root = document.querySelector('.yidun');
              const cls = root ? String(root.className || '') : '';
              const tips = document.querySelector('.yidun_tips__text')
                || document.querySelector('.yidun_control');
              const tip = tips ? tips.textContent : '';
              const fail = /失败|重试|error|fail/i.test(tip) || /yidun--error/.test(cls);
              const successText = /验证成功|验证通过|success/i.test(text) || /yidun--success/.test(cls);
              const validates = window.__ANTIBOT_YIDUN && window.__ANTIBOT_YIDUN.validates || [];
              const latest = validates.length ? validates[validates.length - 1].value : null;
              const payloadOk = JSON.stringify(latest || {}).indexOf('validate') >= 0;
              return { success: Boolean(successText || payloadOk), fail, tip, className: cls, latestValidate: latest || null };
            }"""
        )

    async def _refresh_point(self, page: Any) -> None:
        await page.wait_for_timeout(600)
        try:
            await page.evaluate(
                """() => {
                  const btn = document.querySelector('.yidun_refresh');
                  if (btn) { try { btn.click(); return 'click'; } catch {} }
                  try {
                    if (window.__ANTIBOT_YIDUN?.refreshAll) {
                      window.__ANTIBOT_YIDUN.refreshAll();
                      return 'instance';
                    }
                  } catch {}
                  return '';
                }"""
            )
        except Exception:
            pass
        await page.wait_for_timeout(1500)

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
                "challenge_kind": raw.get("challengeKind"),
                "configs": len(configs or []),
                "events": len(state.get("events") or []) if isinstance(state, dict) else 0,
                "validates": len(state.get("validates") or []) if isinstance(state, dict) else 0,
                "slide_attempts": len(raw.get("slideAttempts") or []),
                "slide_solved": any((a or {}).get("ok") for a in raw.get("slideAttempts") or []),
                "point_attempts": len(raw.get("pointAttempts") or []),
                "point_solved": any((a or {}).get("ok") for a in raw.get("pointAttempts") or []),
                "check_responses": len(raw.get("checkResponses") or []),
                "net_events": len(raw.get("net") or []),
                "trigger_clicks": len(raw.get("triggerClicks") or []),
                "proxy": redacted_proxy(proxy_server),
                "error": error,
            },
            raw=raw,
            errors=[] if ok else [str(error.get("message") or "yidun_not_solved")],
        )
