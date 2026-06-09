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
    assert detect_provider_for_url("https://example.com/active_hashcash/session") == "activehashcash"
    assert detect_provider_for_url("https://auro.network/api/pow/setup") == "auro"
    assert detect_provider_for_url("https://example.com/albireo?albireo_challenge=x") == "albireo"
    assert detect_provider_for_url("https://gate.example/.powxy/static/main.js") == "powxy"
    assert detect_provider_for_url("https://gate.example/go-away/challenge/js-pow-sha256/script.mjs") == "goaway"
    assert detect_provider_for_url("https://gate.example/__guardianwaf/challenge/verify") == "guardianwaf"
    assert detect_provider_for_url("https://gate.example/shapow_internal/challenge-settings.js") == "shapow"
    assert detect_provider_for_url("https://d8c14d4960ca.edge.sdk.awswaf.com/abc/challenge.js") == "awswaf"
    assert detect_provider_for_url("https://wargon2.example/api/v1/challenge") == "wargon2"
    assert detect_provider_for_url("https://gate.example/balooproxy/challenge?publicSalt=abc") == "balooproxy"
    assert detect_provider_for_url("https://gate.example/.basedflare/bot-check") == "basedflare"
    assert detect_provider_for_url("https://gate.example/page?acw_sc__v2=1") == "acwscv2"
    assert detect_provider_for_url("https://gate.example/__pingoo/captcha/api/init") == "pingoo"
    assert detect_provider_for_url("https://target.example/149e9513-01fa-4fb0-aad4-566afd725d1b/p.js") == "kasada_kpsdk"
    assert detect_provider_for_url("https://target.example/kpsdk/ips.js") == "kasada_kpsdk"
    assert detect_provider_for_url("https://js.datadome.co/tags.js") == "datadome"
    assert detect_provider_for_url("https://api-js.datadome.co/js/") == "datadome"
    assert detect_provider_for_url("https://client.px-cloud.net/PXFIXTURE/main.min.js") == "perimeterx"
    assert detect_provider_for_url("https://collector.example/api/v2/collector") == "perimeterx"
    assert detect_provider_for_url("https://example.com/_vercel/botid/c.js?i=0&v=3") == "vercel_botid"
    assert detect_provider_for_url("https://captcha.example/crypto-puzzle/challenge") == "cryptopuzzle"
    assert detect_provider_for_url("https://captcha.example/challenge/simp") == "captxa"
    assert detect_provider_for_url("https://get.crovly.com/widget.js") == "crovly"
    assert detect_provider_for_url("https://captcha.example/powcaptcha/challenge") == "powcaptcha"
    assert detect_provider_for_url("https://js.powcaptcha.com/widget.js") == "getpowcaptcha"
    assert detect_provider_for_url("https://captcha.example/GetChallenges?difficultyLevel=5") == "powbot"
    assert detect_provider_for_url("https://captcha.example/powchallenge-server/challenge") == "powchallenge"
    assert detect_provider_for_url("https://captcha.powforge.dev/api/challenge") == "powforge"
    assert detect_provider_for_url("https://botcha.ai/v1/token?app_id=app_x") == "botcha"
    assert detect_provider_for_url("https://botcha.ai/api/speed-challenge") == "botcha"
    assert detect_provider_for_url("https://litebrowsers.github.io/donatello/") == "donatello"
    assert detect_provider_for_url("https://captcha.example/donatello/challenge?id=x") == "donatello"
    assert detect_provider_for_url("https://gate.example/matmulservicechallenge") == "btx"
    assert detect_provider_for_url("https://pow-reaction.pages.dev/demo/reactions/challenge") == "powreaction"
    assert detect_provider_for_url("https://hashguard.example/v1/pow/challenges") == "hashguard"
    assert detect_provider_for_url("https://api.trustcomponent.com/v2/verifications") == "trustcaptcha"
    assert detect_provider_for_url("https://example.test/__captcha/pow") == "stravcaptcha"
    assert detect_provider_for_url("https://captcha.example/justnocaptcha/challenge") == "justnocaptcha"
    assert detect_provider_for_url("https://provider.example/v1/prosopo/provider/client/captcha/pow") == "procaptcha"
    assert detect_provider_for_url("https://capybaracaptcha.example/api/challenge") == "capybara"
    assert detect_provider_for_url("https://captcha.example/eduvulcan/captcha-wrapper") == "vulcan"
    assert detect_provider_for_url("https://captcha.example/leptos-captcha/get_pow") == "spow"
    assert detect_provider_for_url("https://example.com/.tollbooth/verify") == "tollbooth"
    assert detect_provider_for_url("https://captcha.example/chpiopow/challenge") == "chpiopow"
    assert detect_provider_for_url("https://captcha.example/impost/challenge") == "impost"
    assert detect_provider_for_url("https://captcha.example/kerberus/challenge?difficultyFactor=50") == "kerberus"
    assert detect_provider_for_url("https://captcha.example/lapti/handshake/data") == "lapti"
    assert detect_provider_for_url("https://chat.example/api/v1/server?hashcash_bits=1") == "neoirc"
    assert detect_provider_for_url("https://captcha.example/hashptcha/get-task") == "hashptcha"
    assert detect_provider_for_url("https://gate.example/?pow_challenge=1&pow_sub_difficulty=8") == "phpantiddos"
    assert detect_provider_for_url("https://captcha.example/paulpow/challenge?type=bcrypt_pow") == "paulpow"
    assert detect_provider_for_url("https://guns.lol/example") == "gunslol"
    assert detect_provider_for_url("https://captcha.example/page?_gs_sets=1&_2xa=1") == "gunslol"
    assert detect_provider_for_url("https://api.h33.ai/v1/botshield/challenge") == "h33botshield"
    assert detect_provider_for_url("https://api.privatecaptcha.com/puzzle") == "privatecaptcha"
    assert detect_provider_for_url("https://captcha.example/api/v1/challenge") == "portcullis"
    assert detect_provider_for_url("https://api.swetrixcaptcha.com/v1/captcha/generate") == "swetrix"
    assert detect_provider_for_url("https://example.com/api/captcha/challenge") == "yourcaptcha"
    assert detect_provider_for_url("https://captcha.example/silent-challenge") == "silentchallenge"
    assert detect_provider_for_url("https://example.com") == "browser"
    assert "qoder_signup" in list_profiles()["aliyun"]
    assert "generic_v4" in list_profiles()["geetest"]
    assert "generic_jigsaw" in list_profiles()["yidun"]
    assert "generic_widget" in list_profiles()["hcaptcha"]
    assert "generic_widget_enterprise" in list_profiles()["recaptcha"]
    assert "generic_widget" in list_profiles()["turnstile"]
    assert "rails_hashcash_sha256" in list_profiles()["activehashcash"]
    assert "buffer_reconstruction_pow" in list_profiles()["powcaptcha"]
    assert "signals_bound_pow" in list_profiles()["getpowcaptcha"]
    assert "scrypt_pow" in list_profiles()["powbot"]
    assert "argon2id_memory_pow" in list_profiles()["powchallenge"]
    assert "signed_sha256_pow_token" in list_profiles()["powforge"]
    assert "ai_speed_challenge" in list_profiles()["botcha"]
    assert "canvas_fingerprint_challenge" in list_profiles()["donatello"]
    assert "matmul_service_pow" in list_profiles()["btx"]
    assert "signed_multi_round_pow" in list_profiles()["powreaction"]
    assert "jwt_proof_pow" in list_profiles()["hashguard"]
    assert "fingerprint_multi_pow" in list_profiles()["trustcaptcha"]
    assert "stateless_hmac_pow" in list_profiles()["stravcaptcha"]
    assert "multi_puzzle_fnv_pow" in list_profiles()["justnocaptcha"]
    assert "prosopo_pow" in list_profiles()["procaptcha"]
    assert "payload_bound_pow" in list_profiles()["capybara"]
    assert "chained_sha256_uint32_pow" in list_profiles()["vulcan"]
    assert "signed_hashcash_pow" in list_profiles()["spow"]
    assert "tollbooth_protocol" in list_profiles()["tollbooth"]
    assert "signals_bound_pow" in list_profiles()["fcaptcha"]
    assert "serverless_signed_pow" in list_profiles()["albireo"]
    assert "reverse_proxy_pow" in list_profiles()["powxy"]
    assert "goaway_js_pow_sha256" in list_profiles()["goaway"]
    assert "unsigned_js_pow_hmac_cookie" in list_profiles()["guardianwaf"]
    assert "nginx_ip_time_bound_pow" in list_profiles()["shapow"]
    assert "encrypted_behavior_pow" in list_profiles()["auro"]
    assert "encrypted_telemetry_scrypt_sha2_network_pow" in list_profiles()["awswaf"]
    assert "argon2id_prefix_pow_fingerprint" in list_profiles()["wargon2"]
    assert "balooproxy_js_suffix_sha256_cookie" in list_profiles()["balooproxy"]
    assert "haproxy_pow_cookie" in list_profiles()["basedflare"]
    assert "aliyun_acw_sc_v2_js_cookie" in list_profiles()["acwscv2"]
    assert "jwt_cookie_sha256_pow" in list_profiles()["pingoo"]
    assert "x_is_human_aes_gcm_fingerprint" in list_profiles()["vercel_botid"]
    assert "target_match_pow" in list_profiles()["chpiopow"]
    assert "argon2id_pow" in list_profiles()["impost"]
    assert "u128_score_pow" in list_profiles()["kerberus"]
    assert "sha3_token_pow" in list_profiles()["lapti"]
    assert "resource_body_bound_hashcash" in list_profiles()["neoirc"]
    assert "prefix_hash_cracking_task" in list_profiles()["hashptcha"]
    assert "stateless_hmac_multi_pow_cookie" in list_profiles()["phpantiddos"]
    assert "bcrypt_pow" in list_profiles()["paulpow"]
    assert "seal_pow_blake3" in list_profiles()["gunslol"]
    assert "botshield_pow" in list_profiles()["h33botshield"]
    assert "rsw_time_lock_puzzle" in list_profiles()["cryptopuzzle"]
    assert "ja4_bound_pow" in list_profiles()["captxa"]
    assert "fingerprint_behavior_pow" in list_profiles()["crovly"]
    assert "compute_pow" in list_profiles()["privatecaptcha"]
    assert "argon2_pow" in list_profiles()["portcullis"]
    assert "swetrix_pow" in list_profiles()["swetrix"]
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
