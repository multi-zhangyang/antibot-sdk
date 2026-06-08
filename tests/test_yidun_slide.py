from pathlib import Path

from antibot_sdk.providers.yidun import detect_yidun_slide_gap, latest_yidun_success

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
