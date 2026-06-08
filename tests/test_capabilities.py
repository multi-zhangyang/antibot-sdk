from dataclasses import asdict

from antibot_sdk import list_capabilities
from antibot_sdk.models import CaptchaResult


def test_capability_matrix_product_boundary() -> None:
    caps = list_capabilities()
    solvers = {item["provider"]: item for item in caps["solvers"]}
    observers = {item["provider"]: item for item in caps["flow_observers"]}
    unsupported = {item["captcha_type"] for item in caps["unsupported"]}

    assert set(solvers) == {"tencent", "aliyun", "geetest", "yidun"}
    assert solvers["tencent"]["captcha_type"] == "slider"
    assert solvers["yidun"]["captcha_type"] == "jigsaw"
    assert set(observers) == {"turnstile", "hcaptcha", "recaptcha"}
    assert all(item["captcha_type"] == "token_widget" for item in observers.values())
    assert {"text_click", "semantic_image_select", "complex_drag_sort"} <= unsupported


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
