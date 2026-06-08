from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AliyunSiteProfile:
    """Runtime profile used by the Aliyun Node bridge."""

    name: str
    url_patterns: tuple[str, ...] = ()
    site_profile: str | None = None
    headless: bool | str | None = None
    selectors: dict[str, str] = field(default_factory=dict)
    profile: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    verify_wait_ms: int | None = None
    captcha_wait_ms: int | None = None
    max_attempts: int | None = None
    session_retries: int | None = None
    session_retry_delay_sec: float | None = None
    session_retry_max_attempts: int | None = None
    proxy_max_attempts: int | None = None
    proxy_session_retries: int | None = None
    proxy_session_retry_max_attempts: int | None = None

    def matches(self, url: str | None) -> bool:
        if not url:
            return False
        u = url.lower()
        host = (urlparse(url).hostname or "").lower()
        return any(p in u or p in host for p in self.url_patterns)


ALIYUN_SITE_PROFILES: dict[str, AliyunSiteProfile] = {
    # 这是从 aliyun-captcha-repro/qoder_test.js 收敛出来的站点级 profile。
    # 关键点：Qoder 的滑块不是首屏出现，必须先走注册表单两段提交，之后
    # 才会加载完整的 #aliyunCaptcha-sliding-* DOM。
    "qoder_signup": AliyunSiteProfile(
        name="qoder_signup",
        url_patterns=("qoder.com/users/sign-up", "qoder.com"),
        site_profile="qoder_signup",
        headless=True,
        verify_wait_ms=12_000,
        captcha_wait_ms=120_000,
        max_attempts=5,
        session_retries=1,
        session_retry_delay_sec=3.0,
        session_retry_max_attempts=2,
        proxy_max_attempts=3,
        proxy_session_retries=2,
        proxy_session_retry_max_attempts=2,
        profile={
            "maxAttempts": 5,
            "totalMs": 2000,
            "steps": 100,
            "baseDelta": 8,
            "alignPuzzle": 1,
            "alignTolerancePx": 0.8,
            "alignIters": 6,
            "warmPoints": 0,
            "pressHoldMs": 220,
            "pressHoldJitterMs": 80,
            "postDownMs": 240,
            "releaseHoldMs": 340,
            "releaseHoldJitterMs": 120,
            "rawMin": 160,
            "rawMax": 240,
        },
        env={
            "LISTENER_AUTO_PROFILE": "0",
            "LISTENER_MAX_REFRESHES": "4",
            "LISTENER_MAX_VERIFY_REFRESHES": "0",
            "LISTENER_VERIFY_REFRESH_CODES": "F015",
            "LISTENER_AUTO_DELTA": "0",
            "LISTENER_ENFORCE_CANDIDATE_FILTER": "1",
            "LISTENER_SLOT_ONLY": "1",
            "LISTENER_RETRY_DELAY_MS": "700",
            "LISTENER_RETRY_JITTER_MS": "500",
        },
    ),
}


def aliyun_profile_for_url(
    target_url: str | None,
    requested: str | None = "auto",
) -> AliyunSiteProfile | None:
    """Resolve an Aliyun site profile by explicit name or URL."""

    if requested and requested != "auto":
        return ALIYUN_SITE_PROFILES.get(requested)
    for profile in ALIYUN_SITE_PROFILES.values():
        if profile.matches(target_url):
            return profile
    return None


def detect_provider_for_url(url: str | None) -> str:
    """Cheap URL-level router for the SDK auto mode."""

    if not url:
        return "browser"
    u = url.lower()
    host = (urlparse(url).hostname or "").lower()
    if aliyun_profile_for_url(url, "auto") or "aliyun" in u or "alibaba" in u:
        return "aliyun"
    if any(x in u or x in host for x in ("ajcaptcha", "anji-plus", "/captcha/get", "/captcha/check")):
        return "ajcaptcha"
    if any(x in u or x in host for x in ("altcha", "altcha.org")):
        return "altcha"
    if any(x in u or x in host for x in ("anubis", ".within.website/x/cmd/anubis", "techaro.lol-anubis")):
        return "anubis"
    if any(x in u or x in host for x in ("auro.network", "auro-captcha", "/api/pow/setup", "/api/pow/validate")):
        return "auro"
    if any(x in u or x in host for x in ("guns.lol", "_gs_sets", "_2xa", "seal_pow_blake3")):
        return "gunslol"
    if any(x in u or x in host for x in ("friendlycaptcha", "friendlycaptcha.com", "frc-captcha")):
        return "friendlycaptcha"
    if any(x in u or x in host for x in ("fcaptcha", "/api/pow/challenge")):
        return "fcaptcha"
    if any(x in u or x in host for x in ("trycap.dev", "cap.js", "cap-widget", "capjs")):
        return "cap"
    if any(x in u or x in host for x in ("crypto-puzzle", "cryptopuzzle", "time-lock-puzzle", "rsw96")):
        return "cryptopuzzle"
    if any(x in u or x in host for x in ("captxa", "/challenge/simp", "/solve/simp")):
        return "captxa"
    if any(x in u or x in host for x in ("crovly", "get.crovly.com", "api.crovly.com", "edge.crovly.com")):
        return "crovly"
    if any(
        x in u or x in host
        for x in ("chpio", "2104f639-ba1b-48f3-9443-889128163f5a", "/chpiopow/")
    ):
        return "chpiopow"
    if any(x in u or x in host for x in ("impost", "@impost", "impost-captcha")):
        return "impost"
    if any(x in u or x in host for x in ("kerberus", "/kerberus/", "difficultyfactor")):
        return "kerberus"
    if any(x in u or x in host for x in ("mcaptcha", "/api/v1/pow/config", "/api/v1/pow/verify")):
        return "mcaptcha"
    if any(x in u or x in host for x in ("pauldotsh", "bcrypt_pow", "bcrypt-captcha", "/paulpow/")):
        return "paulpow"
    if any(x in u or x in host for x in ("p-captcha", "pcaptcha", "quadraticresidueproblem")):
        return "pcaptcha"
    if any(x in u or x in host for x in ("pow_captcha", "powcaptcha", "taketest", "/powcaptcha/")):
        return "powcaptcha"
    if any(x in u or x in host for x in ("pow-bot-deterrent", "powbot", "/getchallenges?difficultylevel=")):
        return "powbot"
    if any(x in u or x in host for x in ("powchallenge", "powchallenge-server", "pow-captcha-server")):
        return "powchallenge"
    if any(x in u or x in host for x in ("pow-reaction", "powreaction", "/reactions/challenge")):
        return "powreaction"
    if any(
        x in u or x in host
        for x in ("prosopo", "procaptcha", "/v1/prosopo/provider/client/captcha/pow", "/v1/prosopo/provider/client/pow/solution")
    ):
        return "procaptcha"
    if any(x in u or x in host for x in ("tollbooth", "libcaptcha", "/.tollbooth/verify", "sha256-balloon")):
        return "tollbooth"
    if any(x in u or x in host for x in ("privatecaptcha", "private-captcha", "api.privatecaptcha.com", "/privatecaptcha/")):
        return "privatecaptcha"
    if any(x in u or x in host for x in ("portcullis", "pow-captcha", "/api/v1/challenge", "/api/v1/verify")):
        return "portcullis"
    if any(x in u or x in host for x in ("swetrixcaptcha", "swecaptcha", "/v1/captcha/generate", "/v1/captcha/verify")):
        return "swetrix"
    if any(x in u or x in host for x in ("wicketkeeper", "/v0/challenge", "/v0/siteverify")):
        return "wicketkeeper"
    if any(x in u or x in host for x in ("yourcaptcha", "/api/captcha/challenge", "/api/captcha/verify")):
        return "yourcaptcha"
    if any(x in u or x in host for x in ("silent-challenge", "silentchallenge", "libcaptcha")):
        return "silentchallenge"
    if any(x in u or x in host for x in ("geetest", "gcaptcha4", "gt4.geetest")):
        return "geetest"
    if any(x in u or x in host for x in ("yidun", "necaptcha", "dun.163.com", "c.dun.163.com")):
        return "yidun"
    if any(x in u or x in host for x in ("hcaptcha", "h-captcha", "js.hcaptcha.com")):
        return "hcaptcha"
    if any(x in u or x in host for x in ("recaptcha", "g-recaptcha", "grecaptcha", "recaptcha.net")):
        return "recaptcha"
    if any(x in u or x in host for x in ("turnstile", "challenges.cloudflare.com")):
        return "turnstile"
    if any(x in u or x in host for x in ("tencent", "gtimg", "turing.captcha", "tcaptcha")):
        return "tencent"
    if any(x in u or x in host for x in ("cloudflare", "turnstile", "cf-challenge")):
        return "cloudflare"
    return "browser"


def list_profiles() -> dict[str, Any]:
    return {
        "aliyun": {
            name: {
                "patterns": list(profile.url_patterns),
                "siteProfile": profile.site_profile,
                "maxAttempts": profile.max_attempts,
                "sessionRetries": profile.session_retries,
                "proxyMaxAttempts": profile.proxy_max_attempts,
                "proxySessionRetries": profile.proxy_session_retries,
            }
            for name, profile in ALIYUN_SITE_PROFILES.items()
        },
        "geetest": {
            "generic_v4": {
                "patterns": ["geetest", "gcaptcha4"],
                "mode": "browser-hook-slide-solver-alpha",
                "successFields": ["lot_number", "captcha_output", "pass_token", "gen_time"],
            }
        },
        "ajcaptcha": {
            "generic_block_puzzle": {
                "patterns": ["ajcaptcha", "anji-plus", "/captcha/get", "/captcha/check"],
                "mode": "http-protocol-solver",
                "successFields": ["captchaVerification", "token"],
                "endpoints": ["/captcha/get", "/captcha/check"],
            }
        },
        "altcha": {
            "generic_pow": {
                "patterns": ["altcha", "altcha.org"],
                "mode": "v1-hashcash-plus-v2-kdf-proof-of-work-protocol-solver",
                "successFields": ["altcha base64 payload", "Authorization: Altcha ...", "counter+derivedKey"],
            }
        },
        "anubis": {
            "generic_pow": {
                "patterns": ["anubis", ".within.website/x/cmd/anubis", "techaro.lol-anubis"],
                "mode": "anubis-sha256-pow-protocol-solver",
                "successFields": ["pass-challenge params", "Anubis auth cookie"],
                "endpoints": ["/make-challenge", "/pass-challenge"],
            }
        },
        "auro": {
            "encrypted_behavior_pow": {
                "patterns": ["auro.network", "auro-captcha", "/api/pow/setup", "/api/pow/validate"],
                "mode": "aes-gcm-mouse-telemetry-plus-sha256-pow-protocol-solver",
                "successFields": ["validate body", "Auro token/status"],
                "endpoints": ["/enckey", "/api/pow/setup", "/api/pow/validate"],
            }
        },
        "friendlycaptcha": {
            "classic_pow": {
                "patterns": ["friendlycaptcha", "friendlycaptcha.com", "frc-captcha"],
                "mode": "friendly-pow-protocol-solver",
                "successFields": ["frc-captcha-solution"],
                "endpoints": ["/api/v1/puzzle"],
            }
        },
        "fcaptcha": {
            "signals_bound_pow": {
                "patterns": ["fcaptcha", "/api/pow/challenge", "/api/verify"],
                "mode": "behavior-environment-signals-hash-bound-pow-solver",
                "successFields": ["token", "success"],
                "endpoints": ["/api/pow/challenge", "/api/verify", "/api/score"],
            }
        },
        "gunslol": {
            "seal_pow_blake3": {
                "patterns": ["guns.lol", "_gs_sets", "_2xa", "seal_pow_blake3"],
                "mode": "seal-template-sha256-plus-blake3-protocol-solver",
                "successFields": ["seal", "_oo"],
                "endpoints": ["page containing const _gs_sets", "verify endpoint accepting {seal,_oo}"],
            }
        },
        "cap": {
            "sha256_pow": {
                "patterns": ["trycap.dev", "cap.js", "cap-widget", "capjs"],
                "mode": "cap-sha256-pow-plus-rsw-time-lock-protocol-solver",
                "successFields": ["/redeem body", "Cap token", "RSW {y}"],
                "endpoints": ["/challenge", "/redeem"],
            }
        },
        "cryptopuzzle": {
            "rsw_time_lock_puzzle": {
                "patterns": ["crypto-puzzle", "cryptopuzzle", "time-lock-puzzle", "rsw96"],
                "mode": "rsw-time-lock-puzzle-protocol-solver",
                "successFields": ["decrypted message", "token"],
                "endpoints": ["/challenge", "/verify"],
            }
        },
        "captxa": {
            "ja4_bound_pow": {
                "patterns": ["captxa", "/challenge/simp", "/solve/simp"],
                "mode": "browser-metrics-plus-ja4-bound-sha256-pow-solver",
                "successFields": ["X-Captcha-Token", "valid=true"],
                "endpoints": ["/challenge/simp", "/solve/simp", "/api/validate"],
            }
        },
        "crovly": {
            "fingerprint_behavior_pow": {
                "patterns": ["crovly", "get.crovly.com/widget.js", "api.crovly.com/challenge"],
                "mode": "fingerprint-hash-plus-behavior-telemetry-sha256-bit-pow-solver",
                "successFields": ["passed=true", "token"],
                "endpoints": ["GET /challenge", "POST /verify"],
            }
        },
        "chpiopow": {
            "target_match_pow": {
                "patterns": ["chpio", "pow-captcha signedData", "2104f639-ba1b-48f3-9443-889128163f5a"],
                "mode": "signed-multi-challenge-target-match-pow-solver",
                "successFields": ["{challengesSigned, solutions}", "redeemed signedData/token"],
                "endpoints": ["challenge endpoint returning signedData", "redeem endpoint accepting solutions"],
            }
        },
        "impost": {
            "argon2id_pow": {
                "patterns": ["impost", "@impost/lib", "impost-captcha"],
                "mode": "zig-wasm-argon2id-pow-protocol-solver",
                "successFields": ["{challenge, nonce}", "validated message/token"],
                "endpoints": ["/challenge", "POST verify endpoint accepting {challenge, nonce}"],
            }
        },
        "kerberus": {
            "u128_score_pow": {
                "patterns": ["kerberus", "difficultyFactor", "serializedInput"],
                "mode": "multi-salt-u128-score-pow-protocol-solver",
                "successFields": ["Solution{id, nonces}", "validated token/status"],
                "endpoints": ["challenge endpoint returning {id,salts,difficultyFactor}", "validate endpoint"],
            }
        },
        "mcaptcha": {
            "sha256_pow": {
                "patterns": ["mcaptcha", "/api/v1/pow/config", "/api/v1/pow/verify"],
                "mode": "mcaptcha-sha256-pow-protocol-solver",
                "successFields": ["verify body", "mCaptcha token"],
                "endpoints": ["/api/v1/pow/config", "/api/v1/pow/verify", "/api/v1/pow/siteverify"],
            }
        },
        "paulpow": {
            "bcrypt_pow": {
                "patterns": ["PaulDotSH/pow-captcha", "bcrypt_pow", "bcrypt-captcha"],
                "mode": "bcrypt-exact-prefix-protocol-solver",
                "successFields": ["CaptchaServerInfo JSON", "nonce"],
                "endpoints": ["challenge endpoint returning client info", "verify endpoint accepting clientInfo+nonce"],
            }
        },
        "pcaptcha": {
            "quadratic_residue_pow": {
                "patterns": ["p-captcha", "pcaptcha", "QuadraticResidueProblem"],
                "mode": "quadratic-residue-protocol-solver",
                "successFields": ["answer", "{id, answer}"],
                "endpoints": ["/api/challenge", "/api/validate"],
            }
        },
        "powcaptcha": {
            "buffer_reconstruction_pow": {
                "patterns": ["pow_captcha", "powcaptcha", "takeTest"],
                "mode": "buffer-reconstruction-mixed-radix-protocol-solver",
                "successFields": ["answer base64", "answerHex"],
                "endpoints": ["challenge endpoint returning quiz bytes/json", "verify endpoint accepting answer"],
            }
        },
        "powbot": {
            "scrypt_pow": {
                "patterns": ["pow-bot-deterrent", "/GetChallenges?difficultyLevel=", "/Verify?challenge="],
                "mode": "scrypt-wasm-pow-protocol-solver",
                "successFields": ["nonce", "HTTP 200 OK"],
                "endpoints": ["/GetChallenges", "/Verify"],
            }
        },
        "powchallenge": {
            "argon2id_memory_pow": {
                "patterns": ["powchallenge", "powchallenge-server", "pow-captcha-server"],
                "mode": "argon2id-memory-hard-pow-protocol-solver",
                "successFields": ["{req_id, challenge, difficulty, nonce}", "validated message"],
                "endpoints": ["GET /challenge", "POST /verify"],
            }
        },
        "powreaction": {
            "signed_multi_round_pow": {
                "patterns": ["pow-reaction", "powreaction", "/reactions/challenge"],
                "mode": "jwt-signed-multi-round-sha256-pow-solver",
                "successFields": ["{challenge, solutions, reaction}", "success=true"],
                "endpoints": ["POST /reactions/challenge", "POST /reactions"],
            }
        },
        "procaptcha": {
            "prosopo_pow": {
                "patterns": ["prosopo", "procaptcha", "/v1/prosopo/provider/client/captcha/pow"],
                "mode": "prosopo-sha256-hex-prefix-pow-solver",
                "successFields": ["{challenge, difficulty, nonce}", "verified=true"],
                "endpoints": ["POST /v1/prosopo/provider/client/captcha/pow", "POST /v1/prosopo/provider/client/pow/solution"],
            }
        },
        "tollbooth": {
            "tollbooth_protocol": {
                "patterns": ["tollbooth", "libcaptcha", "/.tollbooth/verify", "sha256-balloon"],
                "mode": "sha256-balloon-and-navigator-attestation-protocol-solver",
                "successFields": ["nonce/token", "clearance token/cookie"],
                "endpoints": ["GET protected resource", "POST /.tollbooth/verify"],
            }
        },
        "privatecaptcha": {
            "compute_pow": {
                "patterns": ["privatecaptcha", "private-captcha", "api.privatecaptcha.com"],
                "mode": "blake2b-compute-puzzle-protocol-solver",
                "successFields": ["private-captcha-solution", "g-recaptcha-response compat"],
                "endpoints": ["/puzzle", "/verify", "/siteverify"],
            }
        },
        "portcullis": {
            "argon2_pow": {
                "patterns": ["portcullis", "pow-captcha", "/api/v1/challenge", "/api/v1/verify"],
                "mode": "argon2id-sha256-protocol-solver",
                "successFields": ["verify body", "captcha_token"],
                "endpoints": ["/api/v1/challenge", "/api/v1/verify", "/api/v1/siteverify"],
            }
        },
        "swetrix": {
            "swetrix_pow": {
                "patterns": ["swetrixcaptcha", "swecaptcha", "/v1/captcha/generate", "/v1/captcha/verify"],
                "mode": "sha256-challenge-colon-nonce-pow-protocol-solver",
                "successFields": ["token", "validate data"],
                "endpoints": ["/generate", "/verify", "/validate"],
            }
        },
        "wicketkeeper": {
            "jwt_pow": {
                "patterns": ["wicketkeeper", "/v0/challenge", "/v0/siteverify"],
                "mode": "wicketkeeper-jwt-pow-protocol-solver",
                "successFields": ["hidden input JSON", "success JWT"],
                "endpoints": ["/v0/challenge", "/v0/siteverify"],
            }
        },
        "yourcaptcha": {
            "behavior_pow": {
                "patterns": ["yourcaptcha", "/api/captcha/challenge", "/api/captcha/verify"],
                "mode": "synthetic-behavior-telemetry-plus-sha256-exact-pow-solver",
                "successFields": ["captcha payload", "verified result"],
                "endpoints": ["/api/captcha/challenge", "/api/captcha/verify"],
            }
        },
        "silentchallenge": {
            "passive_pow": {
                "patterns": ["silent-challenge", "silentchallenge", "/challenge/:challengeId/verify"],
                "mode": "synthetic-motion-navigator-attestation-plus-balloon-pow-solver",
                "successFields": ["cleared", "token"],
                "endpoints": ["/challenge", "/challenge/:challengeId/verify"],
            }
        },
        "yidun": {
            "generic_jigsaw": {
                "patterns": ["yidun", "necaptcha", "dun.163.com", "c.dun.163.com"],
                "mode": "browser-hook-slide-solver-alpha",
                "successFields": ["validate", "token", "zoneId"],
            }
        },
        "hcaptcha": {
            "generic_widget": {
                "patterns": ["hcaptcha", "h-captcha", "js.hcaptcha.com"],
                "mode": "browser-hook-observer",
                "successFields": ["h-captcha-response", "callback token"],
            }
        },
        "recaptcha": {
            "generic_widget_enterprise": {
                "patterns": ["recaptcha", "g-recaptcha", "grecaptcha", "recaptcha.net"],
                "mode": "browser-hook-observer",
                "successFields": ["g-recaptcha-response", "callback/execute token"],
            }
        },
        "turnstile": {
            "generic_widget": {
                "patterns": ["turnstile", "challenges.cloudflare.com"],
                "mode": "browser-hook-observer",
                "successFields": ["cf-turnstile-response", "callback token"],
            }
        },
    }
