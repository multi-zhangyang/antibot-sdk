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
    assert solvers["aliyun"]["captcha_type"] == "aliyun_v3"
    assert set(solvers["aliyun"]["variants"]) == {
        "invisible",
        "one_click",
        "slider",
        "puzzle",
        "image_restore",
        "spatial_reasoning",
        "unknown_or_new_tasks",
    }
    assert "VerifyResult=true 和 VerifyCode=T001" in solvers["aliyun"]["scope"]
    assert solvers["aliyun"]["variants"]["puzzle"] == "live_verified_limited_matrix"
    assert solvers["aliyun"]["variants"]["invisible"] == "live_verified_limited_matrix"
    assert (
        solvers["aliyun"]["variants"]["image_restore"]
        == "live_verified_limited_matrix"
    )
    assert (
        solvers["aliyun"]["variants"]["slider"]
        == "live_verified_site_secondary_limited_matrix"
    )
    assert "site_secondary_pass" in solvers["aliyun"]["scope"]
    assert solvers["geetest"]["captcha_type"] == "geetest_v4"
    assert set(browser_flows) == {"cloudflare", "recaptcha", "hcaptcha", "arkose"}
    assert browser_flows["cloudflare"]["category"] == "browser_flow"
    assert browser_flows["recaptcha"]["category"] == "browser_flow"
    assert browser_flows["recaptcha"]["status"] == "active_limited_matrix"
    assert (
        browser_flows["recaptcha"]["variants"]["v2/dynamic_3x3/cars"]
        == "live_verified_limited_matrix"
    )
    assert "Google /userverify" in browser_flows["recaptcha"]["scope"]
    assert "checkcaptcha pass=true" in browser_flows["hcaptcha"]["scope"]
    assert "live_verified" in browser_flows["hcaptcha"]["variants"].values()
    assert (
        browser_flows["hcaptcha"]["variants"]["open_vocabulary/point"]
        == "live_verified_limited_matrix"
    )
    assert (
        browser_flows["hcaptcha"]["variants"]["open_vocabulary/drag_drop"]
        == "live_attempted_vendor_rejected"
    )
    assert browser_flows["arkose"]["status"] == "live_verified_limited_matrix"
    assert (
        browser_flows["arkose"]["variants"]["orbit_carousel"]
        == "live_verified_limited_matrix"
    )
    assert "/fc/ca/ pass=true" in browser_flows["arkose"]["scope"]
    assert caps["flow_observers"] == caps["browser_flows"]
    assert caps["harness"]["status"] == "active"
    assert "AntibotClient.solve_agent" in caps["harness"]["entrypoints"]
    assert caps["harness"]["contract"]["observation"] == "ChallengeObservation"
    assert "BrowserChallengeSession" in caps["harness"]["contract"]["session_adapters"]
    assert "TurnstileChallengeSession" in caps["harness"]["contract"]["session_adapters"]
    assert "affordance ids" in caps["harness"]["contract"]["action_validation"]
    assert "real verifier" in caps["harness"]["contract"]["unknown_scene_policy"]
    assert "dynamic scene replacements" in caps["harness"]["contract"]["replay_metrics"]
    assert "20 independent source runs" in caps["harness"]["contract"]["benchmark_gate"]
    assert {adapter["provider"] for adapter in caps["harness"]["adapters"]} == {
        "aliyun",
        "arkose",
        "cloudflare",
        "geetest",
        "hcaptcha",
        "recaptcha",
        "tencent",
    }
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


def test_capabilities_returns_an_isolated_deep_copy() -> None:
    first = list_capabilities()
    first["browser_flows"][0]["modes"]["auto"] = "mutated"

    second = list_capabilities()

    assert second["browser_flows"][0]["modes"]["auto"] != "mutated"


def test_top_level_sdk_exports_core_human_verification_api() -> None:
    assert antibot_sdk.AntibotClient
    assert antibot_sdk.BrowserAutomation
    assert antibot_sdk.AliyunCaptchaSolver
    assert antibot_sdk.TencentCaptchaSolver
    assert antibot_sdk.GeetestV4Solver
    assert antibot_sdk.CaptchaWidgetSolver
    assert antibot_sdk.RunnerConfig
    assert antibot_sdk.run_once
    assert antibot_sdk.list_capabilities
    assert antibot_sdk.parse_proxy
    assert antibot_sdk.OpenAICompatibleVisionBackend
    assert antibot_sdk.VisionTask
    assert antibot_sdk.CaptchaHarness
    assert antibot_sdk.TurnstileChallengeSession
    assert antibot_sdk.TencentChallengeSession
    assert antibot_sdk.TencentSliderChallengeSession
    assert antibot_sdk.HarnessBudget
    assert antibot_sdk.ChallengeObservation
    assert antibot_sdk.ChallengeAction
    assert antibot_sdk.ProviderAdapterRegistry
    assert antibot_sdk.VisionSolvePolicy
    caps = list_capabilities()
    assert {item["provider"] for item in caps["solvers"]} == {"aliyun", "tencent", "geetest"}
    assert {item["provider"] for item in caps["browser_flows"]} == {
        "cloudflare",
        "recaptcha",
        "hcaptcha",
        "arkose",
    }
