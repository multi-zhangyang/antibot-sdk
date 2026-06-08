from io import BytesIO

import numpy as np
from PIL import Image

from antibot_sdk.providers.geetest import detect_geetest_slide_gap


def _png_bytes(arr, mode):
    buf = BytesIO()
    Image.fromarray(arr, mode=mode).save(buf, format="PNG")
    return buf.getvalue()


def test_detect_geetest_slide_gap_with_transparent_padding():
    rng = np.random.default_rng(7)
    bg = rng.integers(0, 255, size=(180, 260, 3), dtype=np.uint8)
    target_x, target_y = 117, 63
    piece = np.zeros((80, 80, 4), dtype=np.uint8)
    mask_x0, mask_y0 = 13, 9
    mask_w, mask_h = 52, 58
    patch = bg[target_y + mask_y0 : target_y + mask_y0 + mask_h, target_x + mask_x0 : target_x + mask_x0 + mask_w]
    piece[mask_y0 : mask_y0 + mask_h, mask_x0 : mask_x0 + mask_w, :3] = patch
    piece[mask_y0 : mask_y0 + mask_h, mask_x0 : mask_x0 + mask_w, 3] = 255

    ret = detect_geetest_slide_gap(_png_bytes(bg, "RGB"), _png_bytes(piece, "RGBA"))

    assert ret["distance_x"] == target_x
    assert ret["distance_y"] == target_y
    assert ret["score"] > 0.99
