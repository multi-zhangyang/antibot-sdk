from pathlib import Path

from antibot_sdk.providers.yidun import (
    YIDUN_RUNTIME_DEBUG_JS,
    _clean_yidun_point_text,
    detect_yidun_point_targets,
    detect_yidun_slide_gap,
    latest_yidun_success,
)

FIXTURES = Path(__file__).parent / "fixtures" / "yidun"


def test_yidun_gap_detection_prefers_aligned_low_sat_shadow() -> None:
    result = detect_yidun_slide_gap(
        (FIXTURES / "bg_low_sat.jpg").read_bytes(),
        (FIXTURES / "front_low_sat.png").read_bytes(),
    )

    assert result["method"] in {"shadow_dark_low_sat", "color_template"}
    assert abs(result["distance_x"] - 137) <= 2
    assert abs(result["distance_y"]) <= 2


def test_yidun_gap_detection_dark_shadow() -> None:
    result = detect_yidun_slide_gap(
        (FIXTURES / "bg_dark.jpg").read_bytes(),
        (FIXTURES / "front_dark.png").read_bytes(),
    )

    assert result["method"] in {"shadow_dark", "shadow_dark_blur"}
    assert abs(result["distance_x"] - 192) <= 2
    assert abs(result["distance_y"]) <= 2


def test_yidun_gap_detection_color_fallback_when_shadow_y_is_misaligned() -> None:
    result = detect_yidun_slide_gap(
        (FIXTURES / "bg_color.jpg").read_bytes(),
        (FIXTURES / "front_color.png").read_bytes(),
    )

    assert result["method"] == "color_template"
    assert abs(result["distance_x"] - 165) <= 2
    assert abs(result["distance_y"]) <= 3


def test_latest_yidun_success_from_jsonp_parsed_check() -> None:
    raw = {
        "checkResponses": [
            {"parsed": {"data": {"result": False, "token": "old", "validate": ""}}},
            {
                "parsed": {
                    "data": {
                        "result": True,
                        "zoneId": "NANP",
                        "token": "tok",
                        "validate": "val",
                    }
                }
            },
        ]
    }

    assert latest_yidun_success(raw) == {
        "validate": "val",
        "token": "tok",
        "zoneId": "NANP",
        "result": True,
    }


def test_yidun_point_target_text_cleanup() -> None:
    assert _clean_yidun_point_text('请依次点击 "全" "来" "扩"') == "全来扩"
    assert _clean_yidun_point_text('"全" "来" "扩"') == "全来扩"


def test_yidun_runtime_debug_hooks_internal_methods() -> None:
    for marker in (
        "addPoint",
        "shouldVerifyCaptcha",
        "trackMoving",
        "VERIFY_CAPTCHA",
        "store:${name}",
    ):
        assert marker in YIDUN_RUNTIME_DEBUG_JS


def test_yidun_point_detector_fixture() -> None:
    result = detect_yidun_point_targets(
        (FIXTURES / "point_bg_quan_lai_kuo.jpg").read_bytes(),
        "全来扩",
    )

    assert result["ok"]
    assert [p["char"] for p in result["points"]] == ["全", "来", "扩"]
    assert abs(result["points"][0]["x"] - 167) <= 4
    assert abs(result["points"][1]["x"] - 254) <= 6
    assert abs(result["points"][2]["x"] - 95) <= 8


def test_yidun_point_detector_hard_dark_glyph_fixture() -> None:
    result = detect_yidun_point_targets(
        (FIXTURES / "point_bg_an_yan_te.jpg").read_bytes(),
        "安验特",
    )

    assert result["ok"]
    assert [p["char"] for p in result["points"]] == ["安", "验", "特"]
    assert result["points"][0]["score"] >= 0.5
    assert result["points"][1]["score"] >= 0.4
    # The black `特` is intentionally hard: it is blended into a dark marina area.
    assert result["points"][2]["score"] >= 0.1
