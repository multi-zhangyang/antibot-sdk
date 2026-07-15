from dataclasses import asdict

import antibot_sdk
from antibot_sdk import list_capabilities
from antibot_sdk.models import BrowserResult, CaptchaResult


def test_capability_matrix_keeps_human_verification_boundary() -> None:
    caps = list_capabilities()
    solvers = {item["provider"]: item for item in caps["solvers"]}
    browser_flows = {item["provider"]: item for item in caps["browser_flows"]}

    assert set(solvers) == {"aliyun", "tencent", "geetest"}
    assert solvers["tencent"]["captcha_type"] == "slider"
    assert solvers["aliyun"]["captcha_type"] == "slider"
    assert solvers["geetest"]["captcha_type"] == "geetest_v4"
    assert set(browser_flows) == {"cloudflare"}
    assert browser_flows["cloudflare"]["category"] == "browser_flow"
    assert caps["flow_observers"] == caps["browser_flows"]
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


def test_browser_result_schema_for_cloudflare_flow() -> None:
    ret = BrowserResult(
        ok=True,
        state="clear",
        url="https://example.com",
        final_url="https://example.com/",
        cookies=[{"name": "cf_clearance", "value": "abc", "domain": ".example.com"}],
        cookie_header="cf_clearance=abc",
        cf_clearance="abc",
        turnstile_token="token-value-1234567890",
    )
    data = asdict(ret)

    assert data["ok"] is True
    assert data["state"] == "clear"
    assert data["final_url"] == "https://example.com/"
    assert data["cf_clearance"] == "abc"
    assert data["cookie_header"] == "cf_clearance=abc"
    assert data["turnstile_token"].startswith("token-")
    assert data["cookies"][0]["name"] == "cf_clearance"


def test_cloudflare_capability_documents_modes_and_session_output() -> None:
    caps = list_capabilities()
    browser_flows = {item["provider"]: item for item in caps["browser_flows"]}
    cf = browser_flows["cloudflare"]
    assert "cf_clearance" in cf["output"]
    assert set(cf["modes"]) >= {"auto", "turnstile", "managed", "scrape"}
    assert "不是" in cf["scope"] or "不是纯协议" in cf["scope"]


def test_top_level_sdk_exports_core_human_verification_api() -> None:
    assert antibot_sdk.AntibotClient
    assert antibot_sdk.BrowserAutomation
    assert antibot_sdk.AliyunCaptchaSolver
    assert antibot_sdk.TencentCaptchaSolver
    assert antibot_sdk.GeetestV4Solver
    assert antibot_sdk.RunnerConfig
    assert antibot_sdk.run_once
    assert antibot_sdk.list_capabilities
    assert antibot_sdk.parse_proxy
    caps = list_capabilities()
    assert {item["provider"] for item in caps["solvers"]} == {"aliyun", "tencent", "geetest"}
    assert {item["provider"] for item in caps["browser_flows"]} == {"cloudflare"}
