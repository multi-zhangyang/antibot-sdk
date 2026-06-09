from pathlib import Path

from antibot_sdk.policy import aliyun_policy_decision
from antibot_sdk.profiles import aliyun_profile_for_url, detect_provider_for_url, list_profiles
from antibot_sdk.providers.aliyun import AliyunCaptchaSolver, is_recoverable_attempt_codes


def test_qoder_profile_auto_detects_aliyun() -> None:
    url = "https://qoder.com/users/sign-up"
    profile = aliyun_profile_for_url(url)
    assert profile is not None
    assert profile.name == "qoder_signup"
    assert profile.profile["totalMs"] == 2000
    assert detect_provider_for_url(url) == "aliyun"


def test_provider_detection_is_lean() -> None:
    assert detect_provider_for_url("https://cloud.tencent.com/product/captcha") == "tencent"
    assert detect_provider_for_url("https://captcha.gtimg.com/TCaptcha.js") == "tencent"
    assert detect_provider_for_url("https://example.aliyun.com/captcha") == "aliyun"
    assert detect_provider_for_url("https://developers.cloudflare.com/cloudflare-challenges/") == "cloudflare"
    assert detect_provider_for_url("https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1") == "cloudflare"
    assert detect_provider_for_url("https://example.com") == "unknown"


def test_list_profiles_only_slider_targets() -> None:
    profiles = list_profiles()
    assert set(profiles) == {"cloudflare", "aliyun", "tencent"}
    assert "managed" in profiles["cloudflare"]
    assert "qoder_signup" in profiles["aliyun"]
    assert "cloud_product" in profiles["tencent"]
    assert "matrix_ai_detect" in profiles["tencent"]


def test_vendored_runtime_files_present() -> None:
    aliyun_vendor = AliyunCaptchaSolver.vendor_dir()
    assert (aliyun_vendor / "bridge.js").is_file()
    assert (aliyun_vendor / "src" / "runner.js").is_file()
    assert (aliyun_vendor / "src" / "site_profiles.js").is_file()

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
