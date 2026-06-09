from dataclasses import asdict

from antibot_sdk import list_capabilities
from antibot_sdk.models import CaptchaResult


def test_capability_matrix_product_boundary() -> None:
    caps = list_capabilities()
    solvers = {item["provider"]: item for item in caps["solvers"]}
    observers = {item["provider"]: item for item in caps["flow_observers"]}
    unsupported = {item["captcha_type"] for item in caps["unsupported"]}

    assert set(solvers) == {
        "tencent",
        "aliyun",
        "ajcaptcha",
        "activehashcash",
        "altcha",
        "albireo",
        "powxy",
        "anubis",
        "auro",
        "fcaptcha",
        "friendlycaptcha",
        "getpowcaptcha",
        "gunslol",
        "h33botshield",
        "hashguard",
        "trustcaptcha",
        "stravcaptcha",
        "justnocaptcha",
        "capybara",
        "botcha",
        "donatello",
        "btx",
        "vulcan",
        "spow",
        "cap",
        "cryptopuzzle",
        "captxa",
        "crovly",
        "chpiopow",
        "impost",
        "kerberus",
        "lapti",
        "mcaptcha",
        "paulpow",
        "pcaptcha",
        "powcaptcha",
        "powbot",
        "powchallenge",
        "powforge",
        "powreaction",
        "procaptcha",
        "tollbooth",
        "privatecaptcha",
        "portcullis",
        "swetrix",
        "wicketkeeper",
        "yourcaptcha",
        "silentchallenge",
        "geetest",
        "yidun",
    }
    assert solvers["tencent"]["captcha_type"] == "slider"
    assert solvers["ajcaptcha"]["captcha_type"] == "slider_protocol"
    assert solvers["activehashcash"]["captcha_type"] == "rails_hashcash_sha256"
    assert solvers["altcha"]["captcha_type"] == "proof_of_work"
    assert solvers["albireo"]["captcha_type"] == "serverless_signed_pow"
    assert solvers["powxy"]["captcha_type"] == "reverse_proxy_pow"
    assert solvers["anubis"]["captcha_type"] == "proof_of_work"
    assert solvers["auro"]["captcha_type"] == "encrypted_behavior_pow"
    assert solvers["fcaptcha"]["captcha_type"] == "signals_bound_pow"
    assert solvers["friendlycaptcha"]["captcha_type"] == "proof_of_work"
    assert solvers["getpowcaptcha"]["captcha_type"] == "signals_bound_pow"
    assert solvers["gunslol"]["captcha_type"] == "seal_pow_blake3"
    assert solvers["h33botshield"]["captcha_type"] == "botshield_pow"
    assert solvers["hashguard"]["captcha_type"] == "jwt_proof_pow"
    assert solvers["trustcaptcha"]["captcha_type"] == "fingerprint_multi_pow"
    assert solvers["stravcaptcha"]["captcha_type"] == "stateless_hmac_pow"
    assert solvers["justnocaptcha"]["captcha_type"] == "multi_puzzle_fnv_pow"
    assert solvers["capybara"]["captcha_type"] == "payload_bound_pow"
    assert solvers["botcha"]["captcha_type"] == "ai_speed_challenge"
    assert solvers["donatello"]["captcha_type"] == "canvas_fingerprint_challenge"
    assert solvers["btx"]["captcha_type"] == "matmul_service_pow"
    assert solvers["vulcan"]["captcha_type"] == "chained_sha256_uint32_pow"
    assert solvers["spow"]["captcha_type"] == "signed_hashcash_pow"
    assert solvers["cap"]["captcha_type"] == "proof_of_work"
    assert solvers["cryptopuzzle"]["captcha_type"] == "rsw_time_lock_puzzle"
    assert solvers["captxa"]["captcha_type"] == "ja4_bound_pow"
    assert solvers["crovly"]["captcha_type"] == "fingerprint_behavior_pow"
    assert solvers["chpiopow"]["captcha_type"] == "target_match_pow"
    assert solvers["impost"]["captcha_type"] == "argon2id_pow"
    assert solvers["kerberus"]["captcha_type"] == "u128_score_pow"
    assert solvers["lapti"]["captcha_type"] == "sha3_token_pow"
    assert solvers["mcaptcha"]["captcha_type"] == "proof_of_work"
    assert solvers["paulpow"]["captcha_type"] == "bcrypt_pow"
    assert solvers["pcaptcha"]["captcha_type"] == "quadratic_residue_pow"
    assert solvers["powcaptcha"]["captcha_type"] == "buffer_reconstruction_pow"
    assert solvers["powbot"]["captcha_type"] == "scrypt_pow"
    assert solvers["powchallenge"]["captcha_type"] == "argon2id_memory_pow"
    assert solvers["powforge"]["captcha_type"] == "signed_sha256_pow_token"
    assert solvers["powreaction"]["captcha_type"] == "signed_multi_round_pow"
    assert solvers["procaptcha"]["captcha_type"] == "prosopo_pow"
    assert solvers["tollbooth"]["captcha_type"] == "tollbooth_protocol"
    assert solvers["privatecaptcha"]["captcha_type"] == "compute_pow"
    assert solvers["portcullis"]["captcha_type"] == "argon2_pow"
    assert solvers["swetrix"]["captcha_type"] == "swetrix_pow"
    assert solvers["wicketkeeper"]["captcha_type"] == "proof_of_work"
    assert solvers["yourcaptcha"]["captcha_type"] == "behavior_pow"
    assert solvers["silentchallenge"]["captcha_type"] == "passive_pow"
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
