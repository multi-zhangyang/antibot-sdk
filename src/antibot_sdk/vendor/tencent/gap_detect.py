#!/usr/bin/env python3
"""
缺口检测:
  1. captcha-recognizer (主路径)
  2. OpenCV Sobel 只做兜底/共识校验，不再覆盖低置信但可信的 recognizer 输出

实测腾讯当前背景上 Sobel 容易被纹理边缘带偏；旧逻辑在
recognizer conf < 0.85 时直接切 Sobel，会把偶发低置信正确结果改错。
"""

import io, os, threading
import cv2, numpy as np
from typing import Optional
from PIL import Image

_SLIDER = None
_SLIDER_LOCK = threading.RLock()


def _get_slider():
    """captcha-recognizer ONNX session is expensive; keep one per process."""
    global _SLIDER
    if _SLIDER is None:
        with _SLIDER_LOCK:
            if _SLIDER is None:
                from captcha_recognizer.slider import Slider

                _SLIDER = Slider()
    return _SLIDER


def detect_gap_captcha_recognizer(bg_bytes: bytes) -> tuple[Optional[int], float]:
    # Serialize inference on the cached ONNX session; service concurrency is low and
    # this avoids model/session thread-safety surprises.
    with _SLIDER_LOCK:
        bbox, conf = _get_slider().identify(source=bg_bytes)
    if bbox and len(bbox) >= 2:
        return int(bbox[0]), float(conf)
    return None, 0.0


def detect_gap_sobel(bg_bytes: bytes) -> Optional[int]:
    """OpenCV Sobel 边缘检测找缺口左边界.
    适用于 bg 为纯色缺口、piece 有纹理的场景.
    """
    img = np.array(Image.open(io.BytesIO(bg_bytes)).convert("RGB"))
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    # blur to reduce noise
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    sobelx = cv2.Sobel(blurred, cv2.CV_64F, 1, 0, ksize=3)
    abs_sx = cv2.convertScaleAbs(sobelx)
    # threshold edges
    _, edges = cv2.threshold(abs_sx, 50, 255, cv2.THRESH_BINARY)
    # find vertical gaps where edge density drops (the hollow region)
    col_sum = edges.sum(axis=0)
    # smooth
    kernel = np.ones(15, np.float32) / 15
    smoothed = cv2.filter2D(col_sum.astype(np.float32), -1, kernel).flatten()
    # find valley in left half (gap is usually not at far right)
    half = len(smoothed) // 2
    # but we consider all, just weight center more
    candidates = []
    for x in range(80, len(smoothed) - 80):
        window = smoothed[max(0, x-20):min(len(smoothed), x+20)]
        if smoothed[x] < np.percentile(window, 15):
            candidates.append((x, smoothed[x]))
    if not candidates:
        return None
    # take the left-most strong valley
    candidates.sort(key=lambda t: (t[1], t[0]))
    return int(candidates[0][0])


def detect_gap(
    bg_bytes: bytes,
    conf_thresh: float = 0.85,
    min_recognizer_conf: float = 0.55,
    consensus_px: int = 40,
) -> tuple[int, float, str]:
    """返回 (gap_x, conf, method).

    method:
      - recognizer: captcha-recognizer 高置信主路径
      - recognizer_low_conf: recognizer 低于 conf_thresh 但仍达可用阈值，拒绝被 Sobel 覆盖
      - consensus: recognizer 与 Sobel 接近，取 recognizer
      - sobel: recognizer 不可用时的最后兜底
      - fallback: 仅保留 recognizer 极低置信输出，调用侧通常会按 conf 拦截
    """
    gap_x, conf = detect_gap_captcha_recognizer(bg_bytes)
    if gap_x is not None and conf >= conf_thresh:
        return gap_x, conf, "recognizer"

    # Sobel 在当前腾讯图上误报较多，只允许“共识”或显式兜底。
    sobel_x = detect_gap_sobel(bg_bytes)
    if gap_x is not None:
        if sobel_x is not None and abs(int(sobel_x) - int(gap_x)) <= consensus_px:
            return gap_x, max(conf, 0.65), "consensus"
        if conf >= min_recognizer_conf:
            return gap_x, conf, "recognizer_low_conf"
        if os.getenv("TCAPTCHA_ALLOW_SOBEL", "0") == "1" and sobel_x is not None:
            return int(sobel_x), 0.56, "sobel"
        return gap_x, conf, "fallback"

    if os.getenv("TCAPTCHA_ALLOW_SOBEL", "0") == "1" and sobel_x is not None:
        return int(sobel_x), 0.56, "sobel"
    raise RuntimeError("gap detection failed")
