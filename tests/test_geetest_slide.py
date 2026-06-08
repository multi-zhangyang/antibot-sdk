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


def test_detect_geetest_slide_gap_uses_shadow_candidate_when_color_hits_edge():
    bg = np.full((170, 260, 3), 230, dtype=np.uint8)
    # A false exact color match at the left edge should not dominate when the
    # actual low-saturation hole is visible near the expected y band.
    target_x, target_y = 118, 70
    trim_x, trim_y = 12, 8
    yy, xx = np.ogrid[:44, :44]
    shape = np.ones((44, 44), dtype=bool)
    shape[(xx - 0) ** 2 + (yy - 22) ** 2 < 9**2] = False
    shape[(xx - 43) ** 2 + (yy - 22) ** 2 < 9**2] = False
    shape[(xx - 22) ** 2 + (yy - 0) ** 2 < 8**2] = False
    false_region = bg[78:122, 12:56]
    false_region[shape] = np.array([80, 160, 230], dtype=np.uint8)
    target_region = bg[target_y + trim_y : target_y + trim_y + 44, target_x + trim_x : target_x + trim_x + 44]
    target_region[shape] = 40
    piece = np.zeros((80, 80, 4), dtype=np.uint8)
    piece_region = piece[trim_y : trim_y + 44, trim_x : trim_x + 44]
    piece_region[shape, :3] = np.array([80, 160, 230], dtype=np.uint8)
    piece_region[shape, 3] = 255

    ret = detect_geetest_slide_gap(_png_bytes(bg, "RGB"), _png_bytes(piece, "RGBA"), expected_y=target_y)

    assert ret["method"].startswith("shadow")
    assert abs(ret["distance_x"] - target_x) <= 1
