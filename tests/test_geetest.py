from __future__ import annotations

import inspect
import io
from typing import Any

from PIL import Image, ImageDraw

import pytest

import antibot_sdk.providers.geetest as geetest
from antibot_sdk.providers.geetest import (
    geetest_query,
    geetest_v4_success_from_events,
    parse_geetest_jsonp,
    parse_geetest_v4_event,
)


def _jsonp(payload: str, callback: str = "geetest_1700000000000") -> str:
    return f"{callback}({payload});"


def _require_symbol(name: str) -> Any:
    if not hasattr(geetest, name):
        pytest.fail(f"antibot_sdk.providers.geetest is missing {name}")
    return getattr(geetest, name)


def test_parse_geetest_jsonp_accepts_json_and_wrapped_callbacks() -> None:
    assert parse_geetest_jsonp('{"status":"success","data":{"lot_number":"lot-a"}}') == {
        "status": "success",
        "data": {"lot_number": "lot-a"},
    }
    assert parse_geetest_jsonp(
        ' window.geetest_cb({"status":"success","data":{"captcha_type":"slide"}}); '.strip()
    )["data"]["captcha_type"] == "slide"


def test_geetest_query_flattens_last_value_and_decodes() -> None:
    query = geetest_query(
        "https://gcaptcha4.geetest.com/load?captcha_id=cid-1&risk_type=slide"
        "&challenge=a%2Bb&risk_type=ai&empty="
    )

    assert query == {
        "captcha_id": "cid-1",
        "risk_type": "ai",
        "challenge": "a+b",
    }


def test_parse_geetest_v4_event_load_jsonp_and_query_fields() -> None:
    url = (
        "https://gcaptcha4.geetest.com/load?callback=geetest_cb&captcha_id=cid-query"
        "&client_type=web&risk_type=slide&payload=payload-query"
    )
    text = _jsonp(
        "{"
        '"status":"success",'
        '"data":{'
        '"lot_number":"lot-load",'
        '"captcha_type":"slide",'
        '"risk_type":"slide",'
        '"process_token":"process-token",'
        '"payload":"payload-body"'
        "}"
        "}"
    )

    event = parse_geetest_v4_event(url, text)

    assert event is not None
    assert event["kind"] == "load"
    assert event["host"] == "gcaptcha4.geetest.com"
    assert event["path"] == "/load"
    assert event["captcha_id"] == "cid-query"
    assert event["lot_number"] == "lot-load"
    assert event["captcha_type"] == "slide"
    assert event["risk_type"] == "slide"
    assert event["process_token"] == "process-token"
    assert event["payload"] == "payload-body"
    assert event["query"]["client_type"] == "web"


def test_parse_geetest_v4_event_verify_jsonp_extracts_seccode() -> None:
    url = (
        "https://gcaptcha4.geetest.com/verify?callback=geetest_cb&captcha_id=cid-query"
        "&lot_number=lot-query&client_type=web&risk_type=slide&payload=payload-query"
    )
    text = _jsonp(
        "{"
        '"status":"success",'
        '"data":{'
        '"lot_number":"lot-body",'
        '"result":"success",'
        '"seccode":{'
        '"captcha_id":"cid-sec",'
        '"lot_number":"lot-sec",'
        '"pass_token":"pass-token",'
        '"gen_time":"1700000000",'
        '"captcha_output":"captcha-output"'
        "}"
        "}"
        "}"
    )

    event = parse_geetest_v4_event(url, text)

    assert event is not None
    assert event["kind"] == "verify"
    assert event["result"] == "success"
    assert event["captcha_id"] == "cid-sec"
    assert event["lot_number"] == "lot-sec"
    assert event["pass_token"] == "pass-token"
    assert event["gen_time"] == "1700000000"
    assert event["captcha_output"] == "captcha-output"
    assert event["query"]["payload"] == "payload-query"


def _success_event(pass_token: str, lot_number: str, *, result: str = "success") -> dict[str, Any]:
    return {
        "kind": "verify",
        "risk_type": "slide",
        "query": {"payload": f"payload-{lot_number}"},
        "data": {
            "result": result,
            "seccode": {
                "captcha_id": "cid-1",
                "lot_number": lot_number,
                "pass_token": pass_token,
                "gen_time": f"gen-{lot_number}",
                "captcha_output": f"output-{lot_number}",
            },
        },
        "seccode": {
            "captcha_id": "cid-1",
            "lot_number": lot_number,
            "pass_token": pass_token,
            "gen_time": f"gen-{lot_number}",
            "captcha_output": f"output-{lot_number}",
        },
    }


def test_geetest_v4_success_from_events_returns_latest_success() -> None:
    events = [
        {"kind": "load", "lot_number": "lot-load"},
        _success_event("pass-old", "lot-old"),
        _success_event("pass-fail", "lot-fail", result="fail"),
        _success_event("pass-new", "lot-new"),
    ]

    success = geetest_v4_success_from_events(events)

    assert success is not None
    assert success["captcha_id"] == "cid-1"
    assert success["lot_number"] == "lot-new"
    assert success["pass_token"] == "pass-new"
    assert success["gen_time"] == "gen-lot-new"
    assert success["captcha_output"] == "output-lot-new"
    assert success["result"] == "success"
    assert success["risk_type"] == "slide"
    assert success["payload"] == "payload-lot-new"


def test_latest_geetest_success_accepts_mixed_validates_and_picks_newest() -> None:
    latest_geetest_success = _require_symbol("latest_geetest_success")
    state = {
        "validates": [
            {"at": 1, "value": None},
            {"at": 2, "value": {"lot_number": "lot-incomplete", "pass_token": "token-only"}},
            {
                "at": 3,
                "source": "onSuccess",
                "value": {
                    "lot_number": "lot-first",
                    "captcha_output": "output-first",
                    "pass_token": "pass-first",
                    "gen_time": "gen-first",
                },
            },
            {"at": 4, "value": "noise"},
            {
                "at": 5,
                "source": "snapshot",
                "value": {
                    "lot_number": "lot-last",
                    "captcha_output": "output-last",
                    "pass_token": "pass-last",
                    "gen_time": "gen-last",
                },
            },
        ]
    }

    success = latest_geetest_success(state)

    assert success is not None
    assert success["pass_token"] == "pass-last"
    assert success["lot_number"] == "lot-last"
    assert success["captcha_output"] == "output-last"


def _png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _synthetic_slide_case(gap_x: int = 142, gap_y: int = 42) -> tuple[bytes, bytes, int, int]:
    """Build a deterministic GT-like background plus alpha-padded piece.

    The background contains a correct puzzle-shadow candidate and a stronger
    decoy shadow. The piece PNG has transparent padding around the real mask;
    detectors should crop/use alpha and return the true gap x, not the padding
    left edge or the decoy.
    """

    w, h = 320, 160
    bg = Image.new("RGBA", (w, h), (162, 184, 202, 255))
    draw = ImageDraw.Draw(bg)
    for y in range(h):
        shade = int(16 * y / h)
        draw.line((0, y, w, y), fill=(162 - shade, 184 - shade, 202 - shade, 255))
    for x in range(0, w, 16):
        color = (132 + (x % 48), 154 + (x % 35), 174 + (x % 27), 255)
        draw.rectangle((x, 0, x + 7, h), fill=color)

    mask = Image.new("L", (48, 48), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle((6, 7, 39, 41), radius=7, fill=255)
    md.ellipse((30, 18, 47, 35), fill=255)
    md.ellipse((13, -1, 30, 16), fill=0)

    # Decoy: dark enough to be a shadow candidate, but wrong shape/size.
    draw.rounded_rectangle((40, gap_y + 5, 82, gap_y + 36), radius=5, fill=(80, 88, 96, 255))
    # True candidate: shape matches the alpha mask and includes a small offset shadow.
    shadow = Image.new("RGBA", mask.size, (24, 28, 32, 0))
    shadow.putalpha(mask.point(lambda value: int(value * 0.47)))
    bg.alpha_composite(shadow, (gap_x + 3, gap_y + 2))
    hollow = Image.new("RGBA", mask.size, (42, 48, 54, 0))
    hollow.putalpha(mask.point(lambda value: int(value * 0.61)))
    bg.alpha_composite(hollow, (gap_x, gap_y))

    piece = Image.new("RGBA", (70, 58), (0, 0, 0, 0))
    piece_crop = bg.crop((gap_x, gap_y, gap_x + mask.width, gap_y + mask.height)).convert("RGBA")
    piece_crop.putalpha(mask)
    # Transparent left/top padding is intentional. The detector returns slider
    # element displacement, i.e. true visual gap minus transparent piece padding.
    piece.alpha_composite(piece_crop, (11, 5))

    return _png_bytes(bg), _png_bytes(piece), gap_x - 11, gap_y - 5


def _call_detect_geetest_slide_gap(bg_bytes: bytes, piece_bytes: bytes, expected_y: int) -> Any:
    detect = _require_symbol("detect_geetest_slide_gap")
    sig = inspect.signature(detect)
    required_positionals = [
        param
        for param in sig.parameters.values()
        if param.default is inspect.Signature.empty
        and param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD)
    ]
    if len(required_positionals) <= 1:
        return detect(bg_bytes)
    if "expected_y" in sig.parameters:
        return detect(bg_bytes, piece_bytes, expected_y=expected_y)
    return detect(bg_bytes, piece_bytes)


def _extract_gap_x(result: Any) -> int:
    if isinstance(result, int | float):
        return int(round(result))
    if isinstance(result, dict):
        for key in ("gap_x", "distance_x", "x", "left", "distance", "offset"):
            if key in result and result[key] is not None:
                return int(round(float(result[key])))
    if isinstance(result, (tuple, list)) and result:
        return _extract_gap_x(result[0])
    raise AssertionError(f"cannot extract gap x from result: {result!r}")


def test_detect_geetest_slide_gap_handles_alpha_padding_and_shadow_candidates() -> None:
    bg_bytes, piece_bytes, expected_x, expected_y = _synthetic_slide_case()

    result = _call_detect_geetest_slide_gap(bg_bytes, piece_bytes, expected_y)
    gap_x = _extract_gap_x(result)

    assert abs(gap_x - expected_x) <= 4
    if isinstance(result, dict):
        assert result.get("trim", {}).get("x0", 0) > 0
        assert any(str(item.get("name", "")).startswith("shadow_") for item in result.get("candidates", []))
