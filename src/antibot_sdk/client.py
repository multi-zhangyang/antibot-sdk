from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.activehashcash import ActiveHashcashSolver
from .providers.ajcaptcha import AJCaptchaSolver
from .providers.altcha import AltchaSolver
from .providers.anubis import AnubisSolver
from .providers.auro import AuroSolver
from .providers.browser import BrowserAutomation
from .providers.btx import BtxSolver
from .providers.cap import CapSolver
from .providers.capybara import CapybaraSolver
from .providers.captxa import CaptxaSolver
from .providers.chpiopow import ChpioPowSolver
from .providers.crovly import CrovlySolver
from .providers.fcaptcha import FCaptchaSolver
from .providers.cryptopuzzle import CryptoPuzzleSolver
from .providers.friendlycaptcha import FriendlyCaptchaSolver
from .providers.geetest import GeeTestCaptchaSolver
from .providers.getpowcaptcha import GetPowCaptchaSolver
from .providers.gunslol import GunsLolSolver
from .providers.hashguard import HashGuardSolver
from .providers.hcaptcha import HCaptchaSolver
from .providers.justnocaptcha import JustNoCaptchaSolver
from .providers.impost import ImpostSolver
from .providers.kerberus import KerberusSolver
from .providers.lapti import LaptiSolver
from .providers.mcaptcha import MCaptchaSolver
from .providers.paulpow import PaulPowSolver
from .providers.pcaptcha import PCaptchaSolver
from .providers.powcaptcha import PowCaptchaSolver
from .providers.powbot import PowBotSolver
from .providers.powchallenge import PowChallengeSolver
from .providers.powforge import PowForgeSolver
from .providers.procaptcha import ProcaptchaSolver
from .providers.privatecaptcha import PrivateCaptchaSolver
from .providers.portcullis import PortcullisSolver
from .providers.powreaction import PowReactionSolver
from .providers.recaptcha import ReCaptchaSolver
from .providers.silentchallenge import SilentChallengeSolver
from .providers.spow import SpowSolver
from .providers.stravcaptcha import StravCaptchaSolver
from .providers.swetrix import SwetrixSolver
from .providers.tencent import TencentCaptchaSolver
from .providers.tollbooth import TollboothSolver
from .providers.trustcaptcha import TrustcaptchaSolver
from .providers.turnstile import TurnstileSolver
from .providers.vulcan import VulcanSolver
from .providers.yourcaptcha import YourCaptchaSolver
from .providers.yidun import YidunCaptchaSolver
from .providers.wicketkeeper import WicketkeeperSolver


class AntibotClient:
    """Unified SDK facade."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.browser = BrowserAutomation()
        self.activehashcash = ActiveHashcashSolver()
        self.btx = BtxSolver()
        self.cap = CapSolver()
        self.capybara = CapybaraSolver()
        self.captxa = CaptxaSolver()
        self.chpiopow = ChpioPowSolver()
        self.crovly = CrovlySolver()
        self.ajcaptcha = AJCaptchaSolver()
        self.altcha = AltchaSolver()
        self.anubis = AnubisSolver()
        self.auro = AuroSolver()
        self.fcaptcha = FCaptchaSolver()
        self.cryptopuzzle = CryptoPuzzleSolver()
        self.friendlycaptcha = FriendlyCaptchaSolver()
        self.getpowcaptcha = GetPowCaptchaSolver()
        self.gunslol = GunsLolSolver()
        self.mcaptcha = MCaptchaSolver()
        self.paulpow = PaulPowSolver()
        self.pcaptcha = PCaptchaSolver()
        self.powcaptcha = PowCaptchaSolver()
        self.powbot = PowBotSolver()
        self.powchallenge = PowChallengeSolver()
        self.powforge = PowForgeSolver()
        self.powreaction = PowReactionSolver()
        self.procaptcha = ProcaptchaSolver()
        self.privatecaptcha = PrivateCaptchaSolver()
        self.portcullis = PortcullisSolver()
        self.swetrix = SwetrixSolver()
        self.wicketkeeper = WicketkeeperSolver()
        self.yourcaptcha = YourCaptchaSolver()
        self.silentchallenge = SilentChallengeSolver()
        self.spow = SpowSolver()
        self.stravcaptcha = StravCaptchaSolver()
        self.tencent = TencentCaptchaSolver()
        self.tollbooth = TollboothSolver()
        self.trustcaptcha = TrustcaptchaSolver()
        self.vulcan = VulcanSolver()
        self.aliyun = AliyunCaptchaSolver()
        self.geetest = GeeTestCaptchaSolver()
        self.turnstile = TurnstileSolver()
        self.hcaptcha = HCaptchaSolver()
        self.hashguard = HashGuardSolver()
        self.justnocaptcha = JustNoCaptchaSolver()
        self.impost = ImpostSolver()
        self.kerberus = KerberusSolver()
        self.lapti = LaptiSolver()
        self.recaptcha = ReCaptchaSolver()
        self.yidun = YidunCaptchaSolver()

    async def __aenter__(self) -> "AntibotClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def open(self, url: str, **kwargs: Any) -> BrowserResult:
        kwargs.setdefault("browser_binary", self.browser_binary)
        return await self.browser.open(url, **kwargs)

    async def solve_tencent(self, **kwargs: Any) -> CaptchaResult:
        return await self.tencent.solve(**kwargs)

    async def solve_activehashcash(self, **kwargs: Any) -> CaptchaResult:
        return await self.activehashcash.solve(**kwargs)

    async def solve_btx(self, **kwargs: Any) -> CaptchaResult:
        return await self.btx.solve(**kwargs)

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        return await self.aliyun.solve(**kwargs)

    async def solve_ajcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.ajcaptcha.solve(**kwargs)

    async def solve_cap(self, **kwargs: Any) -> CaptchaResult:
        return await self.cap.solve(**kwargs)

    async def solve_capybara(self, **kwargs: Any) -> CaptchaResult:
        return await self.capybara.solve(**kwargs)

    async def solve_captxa(self, **kwargs: Any) -> CaptchaResult:
        return await self.captxa.solve(**kwargs)

    async def solve_chpiopow(self, **kwargs: Any) -> CaptchaResult:
        return await self.chpiopow.solve(**kwargs)

    async def solve_crovly(self, **kwargs: Any) -> CaptchaResult:
        return await self.crovly.solve(**kwargs)

    async def solve_altcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.altcha.solve(**kwargs)

    async def solve_anubis(self, **kwargs: Any) -> CaptchaResult:
        return await self.anubis.solve(**kwargs)

    async def solve_auro(self, **kwargs: Any) -> CaptchaResult:
        return await self.auro.solve(**kwargs)

    async def solve_cryptopuzzle(self, **kwargs: Any) -> CaptchaResult:
        return await self.cryptopuzzle.solve(**kwargs)

    async def solve_friendlycaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.friendlycaptcha.solve(**kwargs)

    async def solve_getpowcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.getpowcaptcha.solve(**kwargs)

    async def solve_fcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.fcaptcha.solve(**kwargs)

    async def solve_mcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.mcaptcha.solve(**kwargs)

    async def solve_paulpow(self, **kwargs: Any) -> CaptchaResult:
        return await self.paulpow.solve(**kwargs)

    async def solve_pcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.pcaptcha.solve(**kwargs)

    async def solve_powcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.powcaptcha.solve(**kwargs)

    async def solve_powbot(self, **kwargs: Any) -> CaptchaResult:
        return await self.powbot.solve(**kwargs)

    async def solve_powchallenge(self, **kwargs: Any) -> CaptchaResult:
        return await self.powchallenge.solve(**kwargs)

    async def solve_powforge(self, **kwargs: Any) -> CaptchaResult:
        return await self.powforge.solve(**kwargs)

    async def solve_powreaction(self, **kwargs: Any) -> CaptchaResult:
        return await self.powreaction.solve(**kwargs)

    async def solve_procaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.procaptcha.solve(**kwargs)

    async def solve_privatecaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.privatecaptcha.solve(**kwargs)

    async def solve_portcullis(self, **kwargs: Any) -> CaptchaResult:
        return await self.portcullis.solve(**kwargs)

    async def solve_swetrix(self, **kwargs: Any) -> CaptchaResult:
        return await self.swetrix.solve(**kwargs)

    async def solve_wicketkeeper(self, **kwargs: Any) -> CaptchaResult:
        return await self.wicketkeeper.solve(**kwargs)

    async def solve_geetest(self, **kwargs: Any) -> CaptchaResult:
        return await self.geetest.solve(**kwargs)

    async def solve_tollbooth(self, **kwargs: Any) -> CaptchaResult:
        return await self.tollbooth.solve(**kwargs)

    async def solve_trustcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.trustcaptcha.solve(**kwargs)

    async def solve_vulcan(self, **kwargs: Any) -> CaptchaResult:
        return await self.vulcan.solve(**kwargs)

    async def solve_turnstile(self, **kwargs: Any) -> CaptchaResult:
        return await self.turnstile.solve(**kwargs)

    async def solve_hcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.hcaptcha.solve(**kwargs)

    async def solve_gunslol(self, **kwargs: Any) -> CaptchaResult:
        return await self.gunslol.solve(**kwargs)

    async def solve_hashguard(self, **kwargs: Any) -> CaptchaResult:
        return await self.hashguard.solve(**kwargs)

    async def solve_impost(self, **kwargs: Any) -> CaptchaResult:
        return await self.impost.solve(**kwargs)

    async def solve_justnocaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.justnocaptcha.solve(**kwargs)

    async def solve_kerberus(self, **kwargs: Any) -> CaptchaResult:
        return await self.kerberus.solve(**kwargs)

    async def solve_lapti(self, **kwargs: Any) -> CaptchaResult:
        return await self.lapti.solve(**kwargs)

    async def solve_recaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.recaptcha.solve(**kwargs)

    async def solve_yidun(self, **kwargs: Any) -> CaptchaResult:
        return await self.yidun.solve(**kwargs)

    async def solve_yourcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.yourcaptcha.solve(**kwargs)

    async def solve_silentchallenge(self, **kwargs: Any) -> CaptchaResult:
        return await self.silentchallenge.solve(**kwargs)

    async def solve_stravcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.stravcaptcha.solve(**kwargs)

    async def solve_spow(self, **kwargs: Any) -> CaptchaResult:
        return await self.spow.solve(**kwargs)

    async def solve_auto(self, target_url: str, **kwargs: Any) -> BrowserResult | CaptchaResult:
        provider = kwargs.pop("provider", None) or detect_provider_for_url(target_url)
        if provider == "activehashcash":
            ah_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "resource",
                    "challenge_json",
                    "challenge_file",
                    "challenge_html",
                    "challenge_url",
                    "submit_url",
                    "submit",
                    "submit_format",
                    "bits",
                    "stamp_date",
                    "rand",
                    "response_field",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            ah_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_activehashcash(**ah_kwargs)
        if provider == "btx":
            btx_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "submit_url",
                    "submit",
                    "submit_method",
                    "submit_json",
                    "response_field",
                    "nonce_start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            btx_kwargs.setdefault("challenge_url", target_url)
            if btx_kwargs.get("submit") and not btx_kwargs.get("submit_url"):
                btx_kwargs["submit_url"] = target_url
            return await self.solve_btx(**btx_kwargs)
        if provider == "ajcaptcha":
            aj_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "get_path",
                    "check_path",
                    "verify_path",
                    "captcha_type",
                    "client_uid",
                    "canonical_width",
                    "point_y",
                    "timeout_sec",
                    "max_attempts",
                    "proxy_server",
                    "output_dir",
                    "save_images",
                    "min_score",
                    "use_returned_point",
                    "verify_after_check",
                    "headers",
                }
                and v is not None
            }
            aj_kwargs.setdefault("base_url", target_url)
            return await self.solve_ajcaptcha(**aj_kwargs)
        if provider == "altcha":
            altcha_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_url",
                    "challenge_json",
                    "challenge_file",
                    "www_authenticate",
                    "default_maxnumber",
                    "max_number",
                    "start",
                    "workers",
                    "timeout_sec",
                    "v2_strategy",
                    "counter_mode",
                    "hmac_algorithm",
                    "hmac_signature_secret",
                    "hmac_key_signature_secret",
                    "proxy_server",
                    "output_dir",
                    "include_took",
                    "mode",
                    "headers",
                }
                and v is not None
            }
            altcha_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_altcha(**altcha_kwargs)
        if provider == "anubis":
            anubis_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "page_url",
                    "base_url",
                    "pass_url",
                    "redir",
                    "difficulty",
                    "algorithm",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "submit",
                    "ensure_test_cookie",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            anubis_kwargs.setdefault("page_url", target_url)
            return await self.solve_anubis(**anubis_kwargs)
        if provider == "auro":
            auro_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "enckey_url",
                    "setup_url",
                    "validate_url",
                    "key_b64",
                    "prefix",
                    "difficulty",
                    "challenge_json",
                    "challenge_file",
                    "mouse_json",
                    "mouse_file",
                    "mouse_points",
                    "mouse_seed",
                    "iv_b64",
                    "client_guid",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not auro_kwargs.get("base_url") and not auro_kwargs.get("enckey_url"):
                auro_kwargs["base_url"] = target_url
            return await self.solve_auro(**auro_kwargs)
        if provider == "friendlycaptcha":
            frc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "puzzle",
                    "puzzle_file",
                    "puzzle_url",
                    "sitekey",
                    "max_attempts_per_solution",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "frc_client",
                }
                and v is not None
            }
            frc_kwargs.setdefault("puzzle_url", target_url)
            return await self.solve_friendlycaptcha(**frc_kwargs)
        if provider == "getpowcaptcha":
            gpc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "app_id",
                    "backend_url",
                    "create_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "secret",
                    "verify",
                    "context_json",
                    "context_file",
                    "signals_json",
                    "signals_file",
                    "fingerprint_json",
                    "fingerprint_file",
                    "gzip_create",
                    "start",
                    "max_attempts_per_problem",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not gpc_kwargs.get("backend_url") and not gpc_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/challenges/create"):
                    gpc_kwargs["create_url"] = target_url
                    gpc_kwargs["backend_url"] = target_url[: target_lower.rindex("/challenges/create")]
                elif target_lower.rstrip("/").endswith("/challenges/verify"):
                    gpc_kwargs["verify_url"] = target_url
                    gpc_kwargs["backend_url"] = target_url[: target_lower.rindex("/challenges/verify")]
                else:
                    gpc_kwargs["backend_url"] = target_url
            return await self.solve_getpowcaptcha(**gpc_kwargs)
        if provider == "gunslol":
            gl_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "page_url",
                    "verify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not gl_kwargs.get("challenge_url") and not gl_kwargs.get("page_url"):
                gl_kwargs["page_url"] = target_url
            return await self.solve_gunslol(**gl_kwargs)
        if provider == "hashguard":
            hg_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "route_prefix",
                    "context",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "introspect_url",
                    "submit",
                    "introspect",
                    "consume",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "min_solve_ms",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not hg_kwargs.get("base_url") and not hg_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/pow/challenges"):
                    hg_kwargs["challenge_url"] = target_url
                    marker = "/pow/challenges"
                    root = target_url[: target_lower.rindex(marker)]
                    parts = root.rstrip("/").rsplit("/", 1)
                    if parts and parts[-1] in {"v1", "v2"}:
                        hg_kwargs.setdefault("route_prefix", parts[-1])
                        hg_kwargs["base_url"] = parts[0]
                    else:
                        hg_kwargs["base_url"] = root
                elif target_lower.rstrip("/").endswith("/pow/verifications"):
                    hg_kwargs["verify_url"] = target_url
                    marker = "/pow/verifications"
                    root = target_url[: target_lower.rindex(marker)]
                    parts = root.rstrip("/").rsplit("/", 1)
                    if parts and parts[-1] in {"v1", "v2"}:
                        hg_kwargs.setdefault("route_prefix", parts[-1])
                        hg_kwargs["base_url"] = parts[0]
                    else:
                        hg_kwargs["base_url"] = root
                else:
                    hg_kwargs["base_url"] = target_url
            return await self.solve_hashguard(**hg_kwargs)
        if provider == "trustcaptcha":
            tc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "site_key",
                    "api_url",
                    "target_url",
                    "create_url",
                    "submit_url",
                    "challenge_json",
                    "challenge_file",
                    "create_body_json",
                    "create_body_file",
                    "submit",
                    "max_rounds",
                    "start",
                    "max_attempts_per_task",
                    "workers",
                    "timeout_sec",
                    "min_solve_ms",
                    "minimal_data_mode",
                    "bypass_token",
                    "framework",
                    "language",
                    "theme",
                    "user_agent",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            tc_kwargs.setdefault("target_url", target_url)
            if not tc_kwargs.get("api_url") and not tc_kwargs.get("create_url"):
                if target_lower.rstrip("/").endswith("/v2/verifications"):
                    tc_kwargs["create_url"] = target_url
                    tc_kwargs["api_url"] = target_url[: target_lower.rindex("/v2/verifications")]
                elif "/v2/verifications/" in target_lower and target_lower.rstrip("/").endswith("/challenges"):
                    tc_kwargs["submit_url"] = target_url
                    tc_kwargs["api_url"] = target_url[: target_lower.index("/v2/verifications/")]
                else:
                    tc_kwargs["api_url"] = target_url
            return await self.solve_trustcaptcha(**tc_kwargs)
        if provider == "stravcaptcha":
            sc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "token",
                    "challenge_json",
                    "challenge_file",
                    "challenge_html",
                    "challenge_url",
                    "submit_url",
                    "submit",
                    "secret",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "token_field",
                    "response_field",
                    "honeypot_field",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            sc_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_stravcaptcha(**sc_kwargs)
        if provider == "spow":
            spow_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_html",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "submit_format",
                    "secret",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "response_field",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            spow_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_spow(**spow_kwargs)
        if provider == "justnocaptcha":
            jnc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_html",
                    "challenge_url",
                    "submit_url",
                    "submit",
                    "challenge_salt",
                    "start",
                    "max_attempts_per_puzzle",
                    "workers",
                    "timeout_sec",
                    "challenge_field",
                    "response_field",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            jnc_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_justnocaptcha(**jnc_kwargs)
        if provider == "lapti":
            lapti_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "data",
                    "token",
                    "challenge_json",
                    "challenge_file",
                    "base_url",
                    "handshake_url",
                    "action_url",
                    "submit",
                    "secret",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            if not lapti_kwargs.get("base_url") and not lapti_kwargs.get("handshake_url"):
                if "/handshake/" in target_url:
                    lapti_kwargs["handshake_url"] = target_url
                elif "/action/" in target_url:
                    lapti_kwargs["action_url"] = target_url
                    lapti_kwargs["base_url"] = target_url.split("/action/", 1)[0]
                else:
                    lapti_kwargs["base_url"] = target_url
            return await self.solve_lapti(**lapti_kwargs)
        if provider == "capybara":
            capy_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "payload_token",
                    "submit",
                    "difficulty",
                    "duration_sec",
                    "secret",
                    "instance_id",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            if not capy_kwargs.get("base_url") and not capy_kwargs.get("challenge_url"):
                if target_url.rstrip("/").endswith("/api/challenge"):
                    capy_kwargs["challenge_url"] = target_url
                elif target_url.rstrip("/").endswith("/api/verify"):
                    capy_kwargs["verify_url"] = target_url
                    capy_kwargs["base_url"] = target_url.rsplit("/api/verify", 1)[0]
                else:
                    capy_kwargs["base_url"] = target_url
            return await self.solve_capybara(**capy_kwargs)
        if provider == "vulcan":
            vulcan_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_html",
                    "challenge_url",
                    "start",
                    "max_attempts_per_round",
                    "workers",
                    "timeout_sec",
                    "response_field",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            vulcan_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_vulcan(**vulcan_kwargs)
        if provider == "cap":
            cap_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "token",
                    "c",
                    "s",
                    "d",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "api_endpoint",
                    "redeem_url",
                    "redeem",
                    "instr_json",
                    "instr_file",
                    "secret",
                    "start",
                    "max_attempts_per_challenge",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            cap_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_cap(**cap_kwargs)
        if provider == "cryptopuzzle":
            cpz_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "puzzle",
                    "puzzle_file",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "expected_message",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not cpz_kwargs.get("base_url") and not cpz_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/verify"):
                    cpz_kwargs["verify_url"] = target_url
                    cpz_kwargs["base_url"] = target_url[: target_lower.rindex("/verify")]
                elif target_lower.rstrip("/").endswith("/challenge"):
                    cpz_kwargs["challenge_url"] = target_url
                    cpz_kwargs["base_url"] = target_url[: target_lower.rindex("/challenge")]
                else:
                    cpz_kwargs["challenge_url"] = target_url
            return await self.solve_cryptopuzzle(**cpz_kwargs)
        if provider == "captxa":
            captxa_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "solve_url",
                    "submit",
                    "metrics_json",
                    "metrics_file",
                    "start",
                    "max_attempts",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                    "timezone_id",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not captxa_kwargs.get("base_url") and not captxa_kwargs.get("challenge_url"):
                if "/challenge/simp" in target_lower:
                    captxa_kwargs["challenge_url"] = target_url
                elif "/solve/simp" in target_lower:
                    captxa_kwargs["solve_url"] = target_url
                    captxa_kwargs["base_url"] = target_url[: target_lower.index("/solve/simp")]
                else:
                    captxa_kwargs["base_url"] = target_url
            return await self.solve_captxa(**captxa_kwargs)
        if provider == "crovly":
            crovly_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "site_key",
                    "api_url",
                    "edge_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "fingerprint_hash",
                    "fingerprint_json",
                    "fingerprint_file",
                    "profile_json",
                    "profile_file",
                    "environment_json",
                    "environment_file",
                    "behavior_json",
                    "behavior_file",
                    "hold_json",
                    "hold_file",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "min_submit_ms",
                    "min_solve_ms",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not crovly_kwargs.get("api_url") and not crovly_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/challenge"):
                    crovly_kwargs["challenge_url"] = target_url
                    crovly_kwargs["api_url"] = target_url[: target_lower.rindex("/challenge")]
                elif target_lower.rstrip("/").endswith("/verify"):
                    crovly_kwargs["verify_url"] = target_url
                    crovly_kwargs["api_url"] = target_url[: target_lower.rindex("/verify")]
                else:
                    crovly_kwargs["api_url"] = target_url
            return await self.solve_crovly(**crovly_kwargs)
        if provider == "chpiopow":
            cp_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "redeem_url",
                    "submit",
                    "secret",
                    "start",
                    "max_attempts_per_challenge",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            cp_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_chpiopow(**cp_kwargs)
        if provider == "impost":
            impost_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            impost_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_impost(**impost_kwargs)
        if provider == "kerberus":
            kerb_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "serialized_input",
                    "input_file",
                    "validate_url",
                    "submit",
                    "start",
                    "max_attempts_per_salt",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            kerb_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_kerberus(**kerb_kwargs)
        if provider == "mcaptcha":
            mc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "config_json",
                    "config_file",
                    "config_url",
                    "base_url",
                    "sitekey",
                    "key",
                    "verify_url",
                    "submit",
                    "siteverify_url",
                    "siteverify",
                    "secret",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not mc_kwargs.get("config_url") and not mc_kwargs.get("base_url"):
                if target_url.rstrip("/").endswith("/config"):
                    mc_kwargs["config_url"] = target_url
                else:
                    mc_kwargs["base_url"] = target_url
            return await self.solve_mcaptcha(**mc_kwargs)
        if provider == "paulpow":
            pp_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            pp_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_paulpow(**pp_kwargs)
        if provider == "pcaptcha":
            pc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "challenge_id",
                    "validate_url",
                    "validate",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            pc_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_pcaptcha(**pc_kwargs)
        if provider == "powcaptcha":
            pow_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "quiz",
                    "quiz_b64",
                    "quiz_hex",
                    "quiz_file",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "challenge_id",
                    "verify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            pow_kwargs.setdefault("challenge_url", target_url)
            return await self.solve_powcaptcha(**pow_kwargs)
        if provider == "powbot":
            powbot_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenges_url",
                    "verify_url",
                    "api_token",
                    "difficulty_level",
                    "batch_index",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not powbot_kwargs.get("base_url") and not powbot_kwargs.get("challenges_url"):
                target_lower = target_url.lower()
                if "/getchallenges" in target_lower:
                    powbot_kwargs["challenges_url"] = target_url
                elif "/verify" in target_lower:
                    powbot_kwargs["verify_url"] = target_url
                    cut = target_lower.index("/verify")
                    powbot_kwargs["base_url"] = target_url[:cut]
                else:
                    powbot_kwargs["base_url"] = target_url
            return await self.solve_powbot(**powbot_kwargs)
        if provider == "powchallenge":
            pc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "nonce_seed",
                    "nonce_length",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not pc_kwargs.get("base_url") and not pc_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/challenge"):
                    pc_kwargs["challenge_url"] = target_url
                    pc_kwargs["base_url"] = target_url[: target_lower.rindex("/challenge")]
                elif target_lower.rstrip("/").endswith("/verify"):
                    pc_kwargs["verify_url"] = target_url
                    pc_kwargs["base_url"] = target_url[: target_lower.rindex("/verify")]
                else:
                    pc_kwargs["base_url"] = target_url
            return await self.solve_powchallenge(**pc_kwargs)
        if provider == "powforge":
            pf_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_url",
                    "verify_url",
                    "token_verify_url",
                    "challenge_json",
                    "challenge_file",
                    "salt",
                    "difficulty",
                    "response_field",
                    "submit",
                    "token_verify",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not pf_kwargs.get("base_url") and not pf_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/api/challenge"):
                    pf_kwargs["challenge_url"] = target_url
                    pf_kwargs["base_url"] = target_url[: target_lower.rindex("/api/challenge")]
                elif target_lower.rstrip("/").endswith("/api/verify"):
                    pf_kwargs["verify_url"] = target_url
                    pf_kwargs["base_url"] = target_url[: target_lower.rindex("/api/verify")]
                else:
                    pf_kwargs["base_url"] = target_url
            return await self.solve_powforge(**pf_kwargs)
        if provider == "powreaction":
            pr_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "submit_url",
                    "reaction",
                    "submit",
                    "secret",
                    "max_attempts_per_round",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not pr_kwargs.get("base_url") and not pr_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/challenge"):
                    pr_kwargs["challenge_url"] = target_url
                    pr_kwargs["base_url"] = target_url[: target_lower.rindex("/challenge")]
                else:
                    pr_kwargs["base_url"] = target_url
            return await self.solve_powreaction(**pr_kwargs)
        if provider == "procaptcha":
            proc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "provider_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "submit_url",
                    "site_key",
                    "user",
                    "dapp",
                    "session_id",
                    "submit",
                    "user_timestamp_signature",
                    "verified_timeout",
                    "provider_challenge_signature",
                    "behavioral_data",
                    "salt",
                    "simd_readings",
                    "client_meta_json",
                    "client_meta_file",
                    "include_timestamp",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not proc_kwargs.get("provider_url") and not proc_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/captcha/pow"):
                    proc_kwargs["challenge_url"] = target_url
                    proc_kwargs["provider_url"] = target_url[: target_lower.rindex("/v1/prosopo/provider/client/captcha/pow")]
                elif target_lower.rstrip("/").endswith("/pow/solution"):
                    proc_kwargs["submit_url"] = target_url
                    proc_kwargs["provider_url"] = target_url[: target_lower.rindex("/v1/prosopo/provider/client/pow/solution")]
                else:
                    proc_kwargs["provider_url"] = target_url
            return await self.solve_procaptcha(**proc_kwargs)
        if provider == "tollbooth":
            tb_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "navigator_strategy",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not tb_kwargs.get("base_url") and not tb_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/.tollbooth/verify"):
                    tb_kwargs["verify_url"] = target_url
                    tb_kwargs["base_url"] = target_url[: target_lower.rindex("/.tollbooth/verify")]
                else:
                    tb_kwargs["challenge_url"] = target_url
            return await self.solve_tollbooth(**tb_kwargs)
        if provider == "privatecaptcha":
            pc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "puzzle",
                    "puzzle_file",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "puzzle_url",
                    "sitekey",
                    "verify_url",
                    "siteverify_url",
                    "submit",
                    "api_key",
                    "secret",
                    "start",
                    "max_attempts_per_solution",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            pc_kwargs.setdefault("puzzle_url", target_url)
            return await self.solve_privatecaptcha(**pc_kwargs)
        if provider == "portcullis":
            pc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "base_url",
                    "sitekey",
                    "sig",
                    "verify_url",
                    "siteverify_url",
                    "submit",
                    "secret_key",
                    "client_ip",
                    "user_agent",
                    "start",
                    "max_iters",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not pc_kwargs.get("challenge_url") and not pc_kwargs.get("base_url"):
                if target_url.rstrip("/").endswith("/challenge"):
                    pc_kwargs["challenge_url"] = target_url
                else:
                    pc_kwargs["base_url"] = target_url
            return await self.solve_portcullis(**pc_kwargs)
        if provider == "swetrix":
            sx_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "pid",
                    "api_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "validate_url",
                    "submit",
                    "secret",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                    "user_agent",
                }
                and v is not None
            }
            target_lower = target_url.lower()
            if not sx_kwargs.get("api_url") and not sx_kwargs.get("challenge_url"):
                if target_lower.rstrip("/").endswith("/generate"):
                    sx_kwargs["challenge_url"] = target_url
                    sx_kwargs["api_url"] = target_url[: target_lower.rindex("/generate")]
                elif target_lower.rstrip("/").endswith("/verify"):
                    sx_kwargs["verify_url"] = target_url
                    sx_kwargs["api_url"] = target_url[: target_lower.rindex("/verify")]
                elif target_lower.rstrip("/").endswith("/validate"):
                    sx_kwargs["validate_url"] = target_url
                    sx_kwargs["api_url"] = target_url[: target_lower.rindex("/validate")]
                else:
                    sx_kwargs["api_url"] = target_url
            return await self.solve_swetrix(**sx_kwargs)
        if provider == "wicketkeeper":
            wk_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "base_url",
                    "difficulty",
                    "token",
                    "siteverify_url",
                    "submit",
                    "start",
                    "max_attempts",
                    "workers",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not wk_kwargs.get("challenge_url") and not wk_kwargs.get("base_url"):
                if target_url.rstrip("/").endswith("/challenge"):
                    wk_kwargs["challenge_url"] = target_url
                else:
                    wk_kwargs["base_url"] = target_url
            return await self.solve_wicketkeeper(**wk_kwargs)
        if provider == "yourcaptcha":
            yc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "signals_json",
                    "signals_file",
                    "start",
                    "max_attempts",
                    "timeout_sec",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not yc_kwargs.get("challenge_url"):
                if "/api/captcha/verify" in target_url:
                    yc_kwargs.setdefault("verify_url", target_url)
                    yc_kwargs["challenge_url"] = target_url.replace("/api/captcha/verify", "/api/captcha/challenge")
                else:
                    yc_kwargs["challenge_url"] = target_url
            return await self.solve_yourcaptcha(**yc_kwargs)
        if provider == "silentchallenge":
            sc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "submit",
                    "motion_json",
                    "motion_file",
                    "signals_json",
                    "signals_file",
                    "start",
                    "max_attempts",
                    "timeout_sec",
                    "min_submit_ms",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not sc_kwargs.get("base_url") and not sc_kwargs.get("challenge_url"):
                if target_url.rstrip("/").endswith("/challenge"):
                    sc_kwargs["challenge_url"] = target_url
                elif "/challenge/" in target_url and target_url.rstrip("/").endswith("/verify"):
                    sc_kwargs["verify_url"] = target_url
                else:
                    sc_kwargs["base_url"] = target_url
            return await self.solve_silentchallenge(**sc_kwargs)
        if provider == "fcaptcha":
            fc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "base_url",
                    "challenge_json",
                    "challenge_file",
                    "challenge_url",
                    "verify_url",
                    "site_key",
                    "submit",
                    "score_endpoint",
                    "signals_json",
                    "signals_file",
                    "start",
                    "max_attempts",
                    "timeout_sec",
                    "min_submit_ms",
                    "proxy_server",
                    "output_dir",
                    "headers",
                }
                and v is not None
            }
            if not fc_kwargs.get("base_url") and not fc_kwargs.get("challenge_url"):
                if "/api/pow/challenge" in target_url:
                    fc_kwargs["challenge_url"] = target_url
                elif "/api/verify" in target_url or "/api/score" in target_url:
                    fc_kwargs["verify_url"] = target_url
                    marker = "/api/score" if "/api/score" in target_url else "/api/verify"
                    fc_kwargs["base_url"] = target_url.split(marker, 1)[0]
                    if marker == "/api/score":
                        fc_kwargs["score_endpoint"] = True
                else:
                    fc_kwargs["base_url"] = target_url
            return await self.solve_fcaptcha(**fc_kwargs)
        if provider == "aliyun":
            return await self.solve_aliyun(target_url=target_url, **kwargs)
        if provider == "recaptcha":
            rc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_recaptcha(target_url=target_url, **rc_kwargs)
        if provider == "hcaptcha":
            hc_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_hcaptcha(target_url=target_url, **hc_kwargs)
        if provider == "turnstile":
            ts_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_turnstile(target_url=target_url, **ts_kwargs)
        if provider == "geetest":
            gt_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_geetest(target_url=target_url, **gt_kwargs)
        if provider == "yidun":
            yd_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "headless",
                    "proxy_server",
                    "timeout_sec",
                    "trigger_selectors",
                    "auto_trigger",
                    "slide_solve",
                    "slide_max_attempts",
                    "output_dir",
                    "browser_binary",
                    "user_agent",
                    "locale",
                    "timezone_id",
                }
                and v is not None
            }
            return await self.solve_yidun(target_url=target_url, **yd_kwargs)
        if provider == "tencent":
            ten_kwargs = {
                k: v
                for k, v in kwargs.items()
                if k
                in {
                    "profile",
                    "appid",
                    "headless",
                    "proxy_server",
                    "pool_size",
                    "browser_max_uses",
                    "locale",
                    "timezone_id",
                    "user_agent",
                    "timeout_sec",
                    "verbose",
                }
                and v is not None
            }
            if ten_kwargs.get("headless") == "new":
                ten_kwargs["headless"] = True
            return await self.solve_tencent(target_url=target_url, **ten_kwargs)
        browser_kwargs = dict(kwargs)
        if "proxy_server" in browser_kwargs and "proxy" not in browser_kwargs:
            browser_kwargs["proxy"] = browser_kwargs.pop("proxy_server")
        if browser_kwargs.get("headless") is None:
            browser_kwargs.pop("headless", None)
        for k in (
            "site_profile",
            "out",
            "output_dir",
            "timeout_sec",
            "chrome_path",
            "max_attempts",
            "captcha_wait_ms",
            "verify_wait_ms",
            "trigger_selectors",
            "auto_trigger",
            "locale",
            "timezone_id",
        ):
            browser_kwargs.pop(k, None)
        return await self.open(target_url, **browser_kwargs)
