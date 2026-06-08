from antibot_sdk.profiles import aliyun_profile_for_url, detect_provider_for_url, list_profiles
from antibot_sdk.policy import aliyun_policy_decision
from antibot_sdk.providers.geetest import is_geetest_success_payload, latest_geetest_success
from antibot_sdk.providers.hcaptcha import is_hcaptcha_token, latest_hcaptcha_token
from antibot_sdk.providers.recaptcha import is_recaptcha_token, latest_recaptcha_token
from antibot_sdk.providers.turnstile import is_turnstile_token, latest_turnstile_token
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
    assert detect_provider_for_url("https://www.geetest.com/adaptive-captcha-demo") == "geetest"
    assert detect_provider_for_url("https://dun.163.com/trial/jigsaw") == "yidun"
    assert detect_provider_for_url("https://docs.hcaptcha.com/invisible/") == "hcaptcha"
    assert detect_provider_for_url("https://cloud.google.com/recaptcha/docs/overview") == "recaptcha"
    assert detect_provider_for_url("https://developers.cloudflare.com/turnstile/") == "turnstile"
    assert detect_provider_for_url("https://captcha.example/api/pow/challenge?siteKey=site-key") == "fcaptcha"
    assert detect_provider_for_url("https://auro.network/api/pow/setup") == "auro"
    assert detect_provider_for_url("https://captcha.example/challenge/simp") == "captxa"
    assert detect_provider_for_url("https://captcha.example/powcaptcha/challenge") == "powcaptcha"
    assert detect_provider_for_url("https://captcha.example/GetChallenges?difficultyLevel=5") == "powbot"
    assert detect_provider_for_url("https://captcha.example/chpiopow/challenge") == "chpiopow"
    assert detect_provider_for_url("https://captcha.example/impost/challenge") == "impost"
    assert detect_provider_for_url("https://captcha.example/kerberus/challenge?difficultyFactor=50") == "kerberus"
    assert detect_provider_for_url("https://captcha.example/paulpow/challenge?type=bcrypt_pow") == "paulpow"
    assert detect_provider_for_url("https://guns.lol/example") == "gunslol"
    assert detect_provider_for_url("https://captcha.example/page?_gs_sets=1&_2xa=1") == "gunslol"
    assert detect_provider_for_url("https://api.privatecaptcha.com/puzzle") == "privatecaptcha"
    assert detect_provider_for_url("https://captcha.example/api/v1/challenge") == "portcullis"
    assert detect_provider_for_url("https://example.com/api/captcha/challenge") == "yourcaptcha"
    assert detect_provider_for_url("https://captcha.example/silent-challenge") == "silentchallenge"
    assert detect_provider_for_url("https://example.com") == "browser"
    assert "qoder_signup" in list_profiles()["aliyun"]
    assert "generic_v4" in list_profiles()["geetest"]
    assert "generic_jigsaw" in list_profiles()["yidun"]
    assert "generic_widget" in list_profiles()["hcaptcha"]
    assert "generic_widget_enterprise" in list_profiles()["recaptcha"]
    assert "generic_widget" in list_profiles()["turnstile"]
    assert "buffer_reconstruction_pow" in list_profiles()["powcaptcha"]
    assert "scrypt_pow" in list_profiles()["powbot"]
    assert "signals_bound_pow" in list_profiles()["fcaptcha"]
    assert "encrypted_behavior_pow" in list_profiles()["auro"]
    assert "target_match_pow" in list_profiles()["chpiopow"]
    assert "argon2id_pow" in list_profiles()["impost"]
    assert "u128_score_pow" in list_profiles()["kerberus"]
    assert "bcrypt_pow" in list_profiles()["paulpow"]
    assert "seal_pow_blake3" in list_profiles()["gunslol"]
    assert "ja4_bound_pow" in list_profiles()["captxa"]
    assert "compute_pow" in list_profiles()["privatecaptcha"]
    assert "argon2_pow" in list_profiles()["portcullis"]
    assert "behavior_pow" in list_profiles()["yourcaptcha"]
    assert "passive_pow" in list_profiles()["silentchallenge"]


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


def test_geetest_success_payload_extraction():
    payload = {
        "lot_number": "lot",
        "captcha_output": "output",
        "pass_token": "token",
        "gen_time": "1710000000",
    }
    state = {"validates": [{"value": {"lot_number": ""}}, {"value": payload}]}
    assert is_geetest_success_payload(payload)
    assert latest_geetest_success(state) == payload
    assert not is_geetest_success_payload({"lot_number": "lot"})


def test_turnstile_token_extraction():
    token = "0." + "A" * 32 + "." + "b" * 32
    state = {
        "responses": [{"token": "short"}, {"token": token}],
        "inputs": [{"token": "ignored"}],
    }
    assert is_turnstile_token(token)
    assert latest_turnstile_token(state) == token
    assert not is_turnstile_token("short")


def test_hcaptcha_token_extraction():
    token = "P1_" + "A" * 40 + "." + "b" * 24 + ":response"
    state = {
        "responses": [{"token": ""}, {"token": token}],
        "inputs": [{"token": "ignored"}],
    }
    assert is_hcaptcha_token(token)
    assert latest_hcaptcha_token(state) == token
    assert not is_hcaptcha_token("short")


def test_recaptcha_token_extraction():
    token = "03AFcWeA" + "A" * 64 + "." + "b" * 24
    state = {
        "responses": [{"token": ""}, {"token": token}],
        "inputs": [{"token": "ignored"}],
    }
    assert is_recaptcha_token(token)
    assert latest_recaptcha_token(state) == token
    assert not is_recaptcha_token("short")
