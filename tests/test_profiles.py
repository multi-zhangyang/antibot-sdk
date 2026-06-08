from antibot_sdk.profiles import aliyun_profile_for_url, detect_provider_for_url, list_profiles
from antibot_sdk.policy import aliyun_policy_decision
from antibot_sdk.providers.aliyun import AliyunCaptchaSolver, is_recoverable_attempt_codes


def test_qoder_profile_auto_detects_aliyun():
    url = "https://qoder.com/users/sign-up"
    profile = aliyun_profile_for_url(url)
    assert profile is not None
    assert profile.name == "qoder_signup"
    assert profile.profile["totalMs"] == 2000
    assert profile.profile["steps"] == 100
    assert detect_provider_for_url(url) == "aliyun"


def test_generic_provider_detection():
    assert detect_provider_for_url("https://cloud.tencent.com/product/captcha") == "tencent"
    assert detect_provider_for_url("https://example.com") == "browser"
    assert "qoder_signup" in list_profiles()["aliyun"]


def test_vendored_upstream_snapshots_present():
    aliyun_vendor = AliyunCaptchaSolver.vendor_dir()
    assert (aliyun_vendor / "bridge.js").is_file()
    assert (aliyun_vendor / "src" / "site_profiles.js").is_file()

    import antibot_sdk.vendor.tencent as vt

    root = vt.__path__[0]
    from pathlib import Path

    upstream = Path(root) / "upstream"
    assert (upstream / "README.md").is_file()
    assert (upstream / "replay" / "solve_optimized.py").is_file()
    assert (upstream / "hooks" / "xhr_verify_capture.js").is_file()


def test_aliyun_recoverable_attempt_codes():
    assert is_recoverable_attempt_codes(["F001", "F001"])
    assert is_recoverable_attempt_codes(["NONE", "candidate rejected: raw>240"])
    assert is_recoverable_attempt_codes(["captcha not ready after 120000ms", "NONE"])
    assert not is_recoverable_attempt_codes(["T001"])


def test_aliyun_policy_engine_classifies_watchdog_and_geometry():
    timeout_decision = aliyun_policy_decision(
        codes=["watchdog timeout: captcha.wait_ready", "NONE"],
        has_proxy=True,
    )
    assert timeout_decision.failure_class == "watchdog_or_timeout"
    assert timeout_decision.should_retry_session

    geometry_decision = aliyun_policy_decision(codes=["F015"])
    assert geometry_decision.failure_class == "geometry_or_delta"
    assert geometry_decision.recoverable
    assert not geometry_decision.should_retry_session
    assert geometry_decision.env_overrides["LISTENER_AUTO_DELTA"] == "1"
