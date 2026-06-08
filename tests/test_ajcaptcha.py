from __future__ import annotations

import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from typing import Any

import cv2
import numpy as np
from PIL import Image, ImageDraw

from antibot_sdk.providers.ajcaptcha import (
    AJCaptchaSolver,
    build_ajcaptcha_point_json,
    decrypt_ajcaptcha_text,
    detect_ajcaptcha_block_gap,
    encrypt_ajcaptcha_text,
)


def _png_bytes(arr: np.ndarray) -> bytes:
    bio = BytesIO()
    Image.fromarray(arr).save(bio, format="PNG")
    return bio.getvalue()


def _synthetic_aj_pair(gap_x: int = 142, mask_y: int = 45) -> tuple[bytes, bytes]:
    width, height, piece_width = 310, 155, 47
    rng = np.random.default_rng(20260608)
    xx = np.linspace(0, 1, width, dtype=np.float32)[None, :]
    yy = np.linspace(0, 1, height, dtype=np.float32)[:, None]
    bg = np.zeros((height, width, 3), dtype=np.uint8)
    bg[:, :, 0] = np.clip(70 + 95 * xx + 20 * yy, 0, 255).astype(np.uint8)
    bg[:, :, 1] = np.clip(120 + 50 * yy + 18 * np.sin(xx * 18), 0, 255).astype(np.uint8)
    bg[:, :, 2] = np.clip(150 + 45 * xx, 0, 255).astype(np.uint8)
    bg = np.clip(bg + rng.normal(0, 4, bg.shape), 0, 255).astype(np.uint8)

    alpha_img = Image.new("L", (piece_width, height), 0)
    draw = ImageDraw.Draw(alpha_img)
    draw.rounded_rectangle((4, mask_y, 38, mask_y + 42), radius=6, fill=255)
    draw.ellipse((26, mask_y + 12, 48, mask_y + 34), fill=255)
    draw.ellipse((-8, mask_y + 12, 12, mask_y + 34), fill=0)
    alpha = np.asarray(alpha_img)

    piece = np.zeros((height, piece_width, 4), dtype=np.uint8)
    ys, xs = np.where(alpha > 0)
    piece[ys, xs, :3] = bg[ys, gap_x + xs]
    piece[ys, xs, 3] = 255

    hole = bg.copy()
    blurred = cv2.GaussianBlur(bg, (5, 5), 0)
    edge = cv2.Canny(alpha, 50, 150)
    hole[ys, gap_x + xs] = blurred[ys, gap_x + xs]
    eys, exs = np.where(edge > 0)
    hole[eys, gap_x + exs] = 255

    # Add a different interference hole to make sure alpha-shape matching wins.
    false_alpha = np.zeros_like(alpha)
    cv2.circle(false_alpha, (20, 82), 20, 255, -1)
    fys, fxs = np.where(false_alpha > 0)
    false_x = 218
    hole[fys, false_x + fxs] = blurred[fys, false_x + fxs]
    false_edge = cv2.Canny(false_alpha, 50, 150)
    feys, fexs = np.where(false_edge > 0)
    hole[feys, false_x + fexs] = 255

    return _png_bytes(hole), _png_bytes(piece)


def test_ajcaptcha_aes_matches_cryptojs_shape() -> None:
    key = "1234567890abcdef"
    point_json = build_ajcaptcha_point_json(123.0, 5.0)

    assert point_json == '{"x":123,"y":5}'
    assert encrypt_ajcaptcha_text(point_json, key) == "lFLbRS8P8KwR180cLjg1iw=="
    assert (
        encrypt_ajcaptcha_text(f"token---{point_json}", key)
        == "w41VTU94ufi6MnsqPGOORtlevu4WUSIOPTsyUaCTQvI="
    )
    assert decrypt_ajcaptcha_text("lFLbRS8P8KwR180cLjg1iw==", key) == point_json


def test_detect_ajcaptcha_block_gap_synthetic_pair() -> None:
    original, jigsaw = _synthetic_aj_pair(gap_x=142)

    gap = detect_ajcaptcha_block_gap(original, jigsaw)

    assert abs(gap["distance_x"] - 142) <= 2
    assert gap["score"] > 0.3
    assert "alpha_edge" in gap["method"]


class _AJHandler(BaseHTTPRequestHandler):
    token = "tok-001"
    secret_key = "1234567890abcdef"
    gap_x = 142
    original_b64 = ""
    jigsaw_b64 = ""
    seen_check: dict[str, Any] = {}

    def log_message(self, fmt: str, *args: Any) -> None:  # keep pytest output clean
        return

    def _json_body(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def _send(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        body = self._json_body()
        if self.path == "/captcha/get":
            assert body.get("captchaType") == "blockPuzzle"
            self._send(
                {
                    "repCode": "0000",
                    "repData": {
                        "originalImageBase64": self.original_b64,
                        "jigsawImageBase64": self.jigsaw_b64,
                        "token": self.token,
                        "secretKey": self.secret_key,
                        "result": False,
                    },
                    "success": True,
                    "error": False,
                }
            )
            return
        if self.path == "/captcha/check":
            plain = decrypt_ajcaptcha_text(str(body.get("pointJson") or ""), self.secret_key)
            point = json.loads(plain)
            self.__class__.seen_check = {"plain": plain, "point": point, "body": body}
            ok = (
                body.get("token") == self.token
                and abs(int(point["x"]) - self.gap_x) <= 5
                and int(point["y"]) == 5
            )
            self._send(
                {
                    "repCode": "0000" if ok else "6111",
                    "repData": {"captchaType": "blockPuzzle", "token": self.token, "result": ok},
                    "success": ok,
                    "error": not ok,
                    "repMsg": None if ok else "验证失败",
                }
            )
            return
        self._send({"repCode": "404", "success": False, "error": True}, status=404)


def test_ajcaptcha_solver_protocol_flow_local_server() -> None:
    original, jigsaw = _synthetic_aj_pair(gap_x=_AJHandler.gap_x)
    _AJHandler.original_b64 = base64.b64encode(original).decode("ascii")
    _AJHandler.jigsaw_b64 = base64.b64encode(jigsaw).decode("ascii")
    _AJHandler.seen_check = {}

    server = ThreadingHTTPServer(("127.0.0.1", 0), _AJHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        ret = asyncio.run(AJCaptchaSolver().solve(base_url=base_url, timeout_sec=5, save_images=False))
    finally:
        server.shutdown()
        thread.join(2)
        server.server_close()

    assert ret.ok is True
    assert ret.provider == "ajcaptcha"
    assert ret.captcha_type == "slider_protocol"
    assert ret.capability == "protocol_solver"
    assert ret.randstr == _AJHandler.token
    assert ret.ticket
    assert decrypt_ajcaptcha_text(ret.ticket, _AJHandler.secret_key).startswith(
        f"{_AJHandler.token}---"
    )
    assert _AJHandler.seen_check["plain"] == ret.diagnostics["point_json"]
    assert abs(_AJHandler.seen_check["point"]["x"] - _AJHandler.gap_x) <= 5
