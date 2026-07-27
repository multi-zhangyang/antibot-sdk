from pathlib import Path

from antibot_sdk.policy import aliyun_policy_decision
from antibot_sdk.profiles import aliyun_profile_for_url, detect_provider_for_url, list_profiles
from antibot_sdk.providers.aliyun import (
    AliyunCaptchaSolver,
    is_recoverable_attempt_codes,
    node_is_compatible,
    node_version,
)


def test_aliyun_does_not_apply_host_specific_profiles() -> None:
    for url in (
        "https://first-host.example/sign-up",
        "https://second-host.example/login",
        "https://third-host.example/auth",
    ):
        assert aliyun_profile_for_url(url) is None


def test_provider_detection_is_lean() -> None:
    assert detect_provider_for_url("https://cloud.tencent.com/product/captcha") == "tencent"
    assert detect_provider_for_url("https://captcha.gtimg.com/TCaptcha.js") == "tencent"
    assert detect_provider_for_url("https://example.aliyun.com/captcha") == "aliyun"
    assert detect_provider_for_url("https://developers.cloudflare.com/cloudflare-challenges/") == "cloudflare"
    assert detect_provider_for_url("https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1") == "cloudflare"
    assert detect_provider_for_url("https://www.geetest.com/en/adaptive-captcha-demo") == "geetest"
    assert detect_provider_for_url("https://gcaptcha4.geetest.com/load?captcha_id=x") == "geetest"
    assert detect_provider_for_url("https://static.geetest.com/v4/gt4.js") == "geetest"
    assert detect_provider_for_url("https://www.google.com/recaptcha/api2/demo") == "recaptcha"
    assert detect_provider_for_url("https://accounts.hcaptcha.com/demo") == "hcaptcha"
    assert detect_provider_for_url("https://example.com") == "unknown"
    assert (
        detect_provider_for_url("https://example.com/?next=https://cloudflare.com/cdn-cgi")
        == "unknown"
    )


def test_list_profiles_only_slider_targets() -> None:
    profiles = list_profiles()
    assert set(profiles) == {
        "cloudflare",
        "aliyun",
        "tencent",
        "geetest",
        "recaptcha",
        "hcaptcha",
        "arkose",
    }
    assert "managed" in profiles["cloudflare"]
    assert profiles["aliyun"] == {}
    assert "cloud_product" in profiles["tencent"]
    assert "matrix_ai_detect" in profiles["tencent"]
    assert "v4_demo" in profiles["geetest"]
    assert "live_v2_demo" in profiles["recaptcha"]
    assert profiles["recaptcha"]["live_v2_demo"]["target_url"].startswith("https://")
    assert "official_demo" in profiles["hcaptcha"]
    assert profiles["hcaptcha"]["official_demo"]["success_text"] == "Verification Success!"
    assert "local_test_key" not in profiles["recaptcha"]
    assert "local_test_key" not in profiles["hcaptcha"]


def test_vendored_runtime_files_present() -> None:
    aliyun_vendor = AliyunCaptchaSolver.vendor_dir()
    assert (aliyun_vendor / "bridge.js").is_file()
    assert (aliyun_vendor / "src" / "runner.js").is_file()

    root = Path(__file__).resolve().parents[1] / "src" / "antibot_sdk" / "vendor" / "tencent"
    assert (root / "browser_pool.py").is_file()
    assert (root / "gap_detect.py").is_file()
    assert (root / "solve_optimized.py").is_file()
    assert not (root / "upstream").exists()


def test_aliyun_policy_engine_kept() -> None:
    assert is_recoverable_attempt_codes(["F001", "F001"])
    assert not is_recoverable_attempt_codes(["T001"])

    timeout_decision = aliyun_policy_decision(
        codes=["watchdog timeout: captcha.wait_ready", "NONE"],
        has_proxy=True,
    )
    assert timeout_decision.failure_class == "watchdog_or_timeout"
    assert timeout_decision.should_retry_session

    geometry_decision = aliyun_policy_decision(codes=["F015"])
    assert geometry_decision.failure_class == "geometry_or_delta"
    assert geometry_decision.recoverable
    assert geometry_decision.env_overrides["LISTENER_AUTO_DELTA"] == "1"


def test_node_version_check_matches_puppeteer_runtime_requirement(monkeypatch) -> None:
    class _Completed:
        stdout = "v22.12.1\n"

    monkeypatch.setattr("antibot_sdk.providers.aliyun.subprocess.run", lambda *a, **k: _Completed())

    assert node_version("node") == (22, 12, 1)
    assert node_is_compatible("node") is True


def test_aliyun_solver_fails_fast_when_node_is_missing() -> None:
    import asyncio

    result = asyncio.run(
        AliyunCaptchaSolver(node="/definitely/missing/node").solve(
            target_url="https://example.aliyun.com/captcha"
        )
    )

    assert result.ok is False
    assert "Node.js >=22.12.0" in result.errors[0]
