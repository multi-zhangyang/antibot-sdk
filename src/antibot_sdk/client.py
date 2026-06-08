from __future__ import annotations

from typing import Any

from .models import BrowserResult, CaptchaResult
from .profiles import detect_provider_for_url
from .providers.aliyun import AliyunCaptchaSolver
from .providers.ajcaptcha import AJCaptchaSolver
from .providers.altcha import AltchaSolver
from .providers.anubis import AnubisSolver
from .providers.auro import AuroSolver
from .providers.browser import BrowserAutomation
from .providers.cap import CapSolver
from .providers.captxa import CaptxaSolver
from .providers.chpiopow import ChpioPowSolver
from .providers.fcaptcha import FCaptchaSolver
from .providers.friendlycaptcha import FriendlyCaptchaSolver
from .providers.geetest import GeeTestCaptchaSolver
from .providers.gunslol import GunsLolSolver
from .providers.hcaptcha import HCaptchaSolver
from .providers.impost import ImpostSolver
from .providers.kerberus import KerberusSolver
from .providers.mcaptcha import MCaptchaSolver
from .providers.paulpow import PaulPowSolver
from .providers.pcaptcha import PCaptchaSolver
from .providers.powcaptcha import PowCaptchaSolver
from .providers.powbot import PowBotSolver
from .providers.privatecaptcha import PrivateCaptchaSolver
from .providers.portcullis import PortcullisSolver
from .providers.recaptcha import ReCaptchaSolver
from .providers.silentchallenge import SilentChallengeSolver
from .providers.tencent import TencentCaptchaSolver
from .providers.turnstile import TurnstileSolver
from .providers.yourcaptcha import YourCaptchaSolver
from .providers.yidun import YidunCaptchaSolver
from .providers.wicketkeeper import WicketkeeperSolver


class AntibotClient:
    """Unified SDK facade."""

    def __init__(self, *, profile: str = "windows-chrome", browser_binary: str | None = None):
        self.profile = profile
        self.browser_binary = browser_binary
        self.browser = BrowserAutomation()
        self.cap = CapSolver()
        self.captxa = CaptxaSolver()
        self.chpiopow = ChpioPowSolver()
        self.ajcaptcha = AJCaptchaSolver()
        self.altcha = AltchaSolver()
        self.anubis = AnubisSolver()
        self.auro = AuroSolver()
        self.fcaptcha = FCaptchaSolver()
        self.friendlycaptcha = FriendlyCaptchaSolver()
        self.gunslol = GunsLolSolver()
        self.mcaptcha = MCaptchaSolver()
        self.paulpow = PaulPowSolver()
        self.pcaptcha = PCaptchaSolver()
        self.powcaptcha = PowCaptchaSolver()
        self.powbot = PowBotSolver()
        self.privatecaptcha = PrivateCaptchaSolver()
        self.portcullis = PortcullisSolver()
        self.wicketkeeper = WicketkeeperSolver()
        self.yourcaptcha = YourCaptchaSolver()
        self.silentchallenge = SilentChallengeSolver()
        self.tencent = TencentCaptchaSolver()
        self.aliyun = AliyunCaptchaSolver()
        self.geetest = GeeTestCaptchaSolver()
        self.turnstile = TurnstileSolver()
        self.hcaptcha = HCaptchaSolver()
        self.impost = ImpostSolver()
        self.kerberus = KerberusSolver()
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

    async def solve_aliyun(self, **kwargs: Any) -> CaptchaResult:
        return await self.aliyun.solve(**kwargs)

    async def solve_ajcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.ajcaptcha.solve(**kwargs)

    async def solve_cap(self, **kwargs: Any) -> CaptchaResult:
        return await self.cap.solve(**kwargs)

    async def solve_captxa(self, **kwargs: Any) -> CaptchaResult:
        return await self.captxa.solve(**kwargs)

    async def solve_chpiopow(self, **kwargs: Any) -> CaptchaResult:
        return await self.chpiopow.solve(**kwargs)

    async def solve_altcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.altcha.solve(**kwargs)

    async def solve_anubis(self, **kwargs: Any) -> CaptchaResult:
        return await self.anubis.solve(**kwargs)

    async def solve_auro(self, **kwargs: Any) -> CaptchaResult:
        return await self.auro.solve(**kwargs)

    async def solve_friendlycaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.friendlycaptcha.solve(**kwargs)

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

    async def solve_privatecaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.privatecaptcha.solve(**kwargs)

    async def solve_portcullis(self, **kwargs: Any) -> CaptchaResult:
        return await self.portcullis.solve(**kwargs)

    async def solve_wicketkeeper(self, **kwargs: Any) -> CaptchaResult:
        return await self.wicketkeeper.solve(**kwargs)

    async def solve_geetest(self, **kwargs: Any) -> CaptchaResult:
        return await self.geetest.solve(**kwargs)

    async def solve_turnstile(self, **kwargs: Any) -> CaptchaResult:
        return await self.turnstile.solve(**kwargs)

    async def solve_hcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.hcaptcha.solve(**kwargs)

    async def solve_gunslol(self, **kwargs: Any) -> CaptchaResult:
        return await self.gunslol.solve(**kwargs)

    async def solve_impost(self, **kwargs: Any) -> CaptchaResult:
        return await self.impost.solve(**kwargs)

    async def solve_kerberus(self, **kwargs: Any) -> CaptchaResult:
        return await self.kerberus.solve(**kwargs)

    async def solve_recaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.recaptcha.solve(**kwargs)

    async def solve_yidun(self, **kwargs: Any) -> CaptchaResult:
        return await self.yidun.solve(**kwargs)

    async def solve_yourcaptcha(self, **kwargs: Any) -> CaptchaResult:
        return await self.yourcaptcha.solve(**kwargs)

    async def solve_silentchallenge(self, **kwargs: Any) -> CaptchaResult:
        return await self.silentchallenge.solve(**kwargs)

    async def solve_auto(self, target_url: str, **kwargs: Any) -> BrowserResult | CaptchaResult:
        provider = kwargs.pop("provider", None) or detect_provider_for_url(target_url)
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
