from dataclasses import asdict

import antibot_sdk
from antibot_sdk import list_capabilities
from antibot_sdk.models import CaptchaResult


def test_capability_matrix_is_lean_slider_only() -> None:
    caps = list_capabilities()
    solvers = {item["provider"]: item for item in caps["solvers"]}

    assert set(solvers) == {"aliyun", "tencent"}
    assert solvers["tencent"]["captcha_type"] == "slider"
    assert solvers["aliyun"]["captcha_type"] == "slider"
    assert caps["flow_observers"] == []
    assert caps["unsupported"] == []


def test_captcha_result_schema_has_type_and_capability() -> None:
    ret = CaptchaResult(
        provider="tencent",
        ok=True,
        captcha_type="slider",
        capability="solver",
        ticket="ticket",
        randstr="randstr",
    )
    data = asdict(ret)

    assert data["provider"] == "tencent"
    assert data["captcha_type"] == "slider"
    assert data["capability"] == "solver"
    assert data["ticket"] == "ticket"
    assert data["randstr"] == "randstr"


def test_top_level_sdk_exports_only_core_slider_api() -> None:
    assert antibot_sdk.AntibotClient
    assert antibot_sdk.AliyunCaptchaSolver
    assert antibot_sdk.TencentCaptchaSolver
    assert antibot_sdk.list_capabilities
    assert antibot_sdk.parse_proxy
    assert set(list_capabilities()["solvers"][i]["provider"] for i in range(2)) == {"aliyun", "tencent"}
