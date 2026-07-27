from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import CaptchaResult
from ..policy import aliyun_policy_decision
from ..profiles import aliyun_profile_for_url
from ..proxy import (
    normalize_proxy_url,
    proxy_free_environment,
    redacted_proxy,
    resolve_runtime_proxy,
)

VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "aliyun"
BRIDGE = VENDOR_DIR / "bridge.js"
MINIMUM_NODE_VERSION = (22, 12, 0)
ALIYUN_CAPTCHA_TYPES = (
    "auto",
    "invisible",
    "one_click",
    "slider",
    "puzzle",
    "image_restore",
)
ALIYUN_PASS_VERIFY_CODES = frozenset({"T001"})
ALIYUN_NON_PRODUCTION_VERIFY_CODES = frozenset({"T005", "T006"})

_CAPTCHA_TYPE_ALIASES = {
    "": "auto",
    "auto": "auto",
    "detect": "auto",
    "automatic": "auto",
    "invisible": "invisible",
    "traceless": "invisible",
    "seamless": "invisible",
    "one_click": "one_click",
    "oneclick": "one_click",
    "checkbox": "one_click",
    "click": "one_click",
    "slider": "slider",
    "slide": "slider",
    "puzzle": "puzzle",
    "jigsaw": "puzzle",
    "slider_puzzle": "puzzle",
    "image_restore": "image_restore",
    "image_restoration": "image_restore",
    "restoration": "image_restore",
    "restore": "image_restore",
    "unknown": "unknown",
}


def normalize_aliyun_captcha_type(value: str | None, *, allow_unknown: bool = False) -> str:
    key = (value or "auto").strip().lower().replace("-", "_").replace(" ", "_")
    normalized = _CAPTCHA_TYPE_ALIASES.get(key)
    if normalized is not None and (allow_unknown or normalized != "unknown"):
        return normalized
    if allow_unknown:
        return "unknown"
    expected = ", ".join(ALIYUN_CAPTCHA_TYPES)
    raise ValueError(f"unsupported Aliyun captcha type: {value!r}; expected one of {expected}")


def aliyun_verify_passed(value: dict[str, Any] | None) -> bool:
    payload = value or {}
    nested = payload.get("Result")
    if isinstance(nested, dict):
        payload = nested
    code = str(payload.get("VerifyCode") or "").strip().upper()
    return payload.get("VerifyResult") is True and code in ALIYUN_PASS_VERIFY_CODES


def _aliyun_vendor_verification(raw: dict[str, Any]) -> dict[str, Any]:
    verify = raw.get("verifyResponse")
    verify = verify if isinstance(verify, dict) else {}
    nested = verify.get("Result")
    if isinstance(nested, dict):
        verify = nested

    network = raw.get("verifyNetwork")
    network = network if isinstance(network, dict) else {}
    envelope: dict[str, Any] = {}
    text = network.get("text")
    if isinstance(text, str) and text:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                envelope = parsed
        except json.JSONDecodeError:
            pass

    envelope_result = envelope.get("Result")
    if isinstance(envelope_result, dict):
        verify = envelope_result
    code = str(verify.get("VerifyCode") or "").strip().upper()
    endpoint_host = None
    try:
        endpoint_host = urlsplit(str(network.get("url") or "")).hostname
    except ValueError:
        pass
    classification = {
        "T001": "production_pass",
        "T005": "test_mode",
        "T006": "whitelist_mode",
    }.get(code, "failure_or_unknown")

    return {
        "observed": bool(network or verify),
        "endpoint_host": endpoint_host,
        "http_status": network.get("status"),
        "response_code": envelope.get("Code"),
        "response_success": envelope.get("Success"),
        "verify_result": verify.get("VerifyResult"),
        "verify_code": code or None,
        "classification": classification,
        "production_pass": aliyun_verify_passed(verify),
    }


def is_recoverable_attempt_codes(codes: list[str]) -> bool:
    return aliyun_policy_decision(codes=codes).should_retry_session


def discover_chrome() -> str | None:
    for root in (Path.home() / ".cache" / "ms-playwright", Path("/ms-playwright")):
        if root.exists():
            for path in sorted(root.glob("chromium-*/chrome-linux*/chrome"), reverse=True):
                if path.is_file():
                    return str(path)
    for name in ("google-chrome-stable", "google-chrome", "chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def node_version(node: str | None = None) -> tuple[int, int, int] | None:
    executable = node or shutil.which("node")
    if not executable:
        return None
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        parts = proc.stdout.strip().lstrip("v").split(".")
        if len(parts) >= 3:
            return int(parts[0]), int(parts[1]), int(parts[2].split("-", 1)[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def node_is_compatible(node: str | None = None) -> bool:
    version = node_version(node)
    return version is not None and version >= MINIMUM_NODE_VERSION


class AliyunCaptchaSolver:
    """Aliyun CAPTCHA V3 multi-challenge adapter using the bundled Node runner."""

    def __init__(self, node: str | None = None):
        self.node = node or shutil.which("node") or "node"

    @staticmethod
    def vendor_dir() -> Path:
        return VENDOR_DIR

    @staticmethod
    def js_deps_installed() -> bool:
        return (VENDOR_DIR / "node_modules" / "puppeteer-core").exists()

    @staticmethod
    def install_js_deps() -> None:
        version = node_version()
        if version is None:
            raise RuntimeError("Node.js is required to install Aliyun JavaScript dependencies")
        if version < MINIMUM_NODE_VERSION:
            actual = ".".join(str(part) for part in version)
            required = ".".join(str(part) for part in MINIMUM_NODE_VERSION)
            raise RuntimeError(f"Node.js >={required} is required; found {actual}")
        npm = shutil.which("npm")
        if not npm:
            raise RuntimeError("npm is required to install Aliyun JavaScript dependencies")
        subprocess.run([npm, "install"], cwd=str(VENDOR_DIR), check=True)

    async def solve(
        self,
        *,
        target_url: str,
        captcha_type: str = "auto",
        chrome_path: str | None = None,
        headless: bool | str | None = None,
        output_dir: str | None = None,
        out: str | None = None,
        proxy_server: str | None = None,
        use_env_proxy: bool | None = None,
        user_agent: str | None = None,
        selectors: dict[str, str] | None = None,
        site_profile: str | None = "auto",
        profile: dict[str, Any] | None = None,
        env: dict[str, str] | None = None,
        pre_captcha_fills: dict[str, str] | None = None,
        pre_captcha_presses: list[str] | None = None,
        pre_captcha_clicks: list[str] | None = None,
        site_verification_control: bool = False,
        site_verification_accepted_pattern: str | None = None,
        site_verification_rejected_pattern: str | None = None,
        verify_wait_ms: int | None = None,
        captcha_wait_ms: int | None = None,
        max_attempts: int | None = None,
        timeout_sec: int = 180,
        cleanup_profile: bool = True,
        vision_base_url: str | None = None,
        vision_api_key: str | None = None,
        vision_api_key_env: str = "ANTIBOT_VISION_API_KEY",
        vision_model: str | None = None,
        vision_timeout_sec: float = 180,
        vision_min_confidence: float = 0.35,
        vision_retries: int = 2,
        vision_extra_body: dict[str, Any] | None = None,
        image_restore_answer: dict[str, Any] | None = None,
        restore_distance_px: float | None = None,
        extra_options: dict[str, Any] | None = None,
        session_retries: int | None = None,
        session_retry_delay_sec: float | None = None,
        session_retry_max_attempts: int | None = None,
        _session_retry_depth: int = 0,
    ) -> CaptchaResult:
        import asyncio

        requested_captcha_type = normalize_aliyun_captcha_type(captcha_type)
        fallback_captcha_type = (
            requested_captcha_type if requested_captcha_type != "auto" else "unknown"
        )
        detected_node = node_version(self.node)
        if not node_is_compatible(self.node):
            actual = (
                ".".join(str(part) for part in detected_node)
                if detected_node
                else "not found"
            )
            return CaptchaResult(
                provider="aliyun",
                ok=False,
                captcha_type=fallback_captcha_type,
                capability="solver",
                diagnostics={
                    "target_url": target_url,
                    "node_version": actual,
                    "minimum_node_version": "22.12.0",
                },
                errors=[f"Node.js >=22.12.0 is required; found {actual}"],
            )
        if not self.js_deps_installed():
            return CaptchaResult(
                provider="aliyun",
                ok=False,
                captcha_type=fallback_captcha_type,
                capability="solver",
                diagnostics={"target_url": target_url, "js_deps_installed": False},
                errors=["Aliyun JavaScript dependencies are missing; run `antibot install-js-deps`"],
            )

        output_root = output_dir or tempfile.mkdtemp(prefix="antibot-aliyun-run-")
        final_out = out or str(Path(output_root) / "aliyun_captcha_run.json")
        user_data_dir = tempfile.mkdtemp(prefix="antibot-aliyun-profile-")
        resolved_proxy = resolve_runtime_proxy(proxy_server, use_env=use_env_proxy)
        proxy_server = resolved_proxy.url if resolved_proxy else None

        user_max_attempts = max_attempts is not None
        user_session_retries = session_retries is not None
        user_session_retry_max_attempts = session_retry_max_attempts is not None
        resolved_site = aliyun_profile_for_url(target_url, site_profile)
        merged_profile: dict[str, Any] = {}
        merged_selectors: dict[str, str] = {}
        merged_env: dict[str, str] = {}
        if resolved_site:
            merged_profile.update(resolved_site.profile)
            merged_selectors.update(resolved_site.selectors)
            merged_env.update(resolved_site.env)
            if resolved_site.verify_wait_ms and verify_wait_ms is None:
                verify_wait_ms = resolved_site.verify_wait_ms
            if resolved_site.captcha_wait_ms and captcha_wait_ms is None:
                captcha_wait_ms = resolved_site.captcha_wait_ms
            if resolved_site.max_attempts and max_attempts is None:
                max_attempts = resolved_site.max_attempts
            if resolved_site.session_retries is not None and session_retries is None:
                session_retries = resolved_site.session_retries
            if resolved_site.session_retry_delay_sec is not None and session_retry_delay_sec is None:
                session_retry_delay_sec = resolved_site.session_retry_delay_sec
            if resolved_site.session_retry_max_attempts is not None and session_retry_max_attempts is None:
                session_retry_max_attempts = resolved_site.session_retry_max_attempts
            if proxy_server:
                if (
                    resolved_site.proxy_max_attempts is not None
                    and not user_max_attempts
                ):
                    max_attempts = resolved_site.proxy_max_attempts
                if (
                    resolved_site.proxy_session_retries is not None
                    and not user_session_retries
                ):
                    session_retries = resolved_site.proxy_session_retries
                if (
                    resolved_site.proxy_session_retry_max_attempts is not None
                    and not user_session_retry_max_attempts
                ):
                    session_retry_max_attempts = resolved_site.proxy_session_retry_max_attempts
            if headless is None:
                headless = resolved_site.headless
        if selectors:
            merged_selectors.update(selectors)
        if profile:
            merged_profile.update(profile)
        if env:
            merged_env.update({k: str(v) for k, v in env.items()})
        if captcha_wait_ms:
            merged_env["CAPTCHA_WAIT_MS"] = str(captcha_wait_ms)

        options: dict[str, Any] = {
            "targetUrl": target_url,
            "captchaType": requested_captcha_type,
            "outputDir": output_root,
            "out": final_out,
            "browserArgs": [f"--user-data-dir={user_data_dir}"],
        }
        if headless is not None:
            options["headless"] = headless
        if resolved_site and resolved_site.site_profile:
            options["siteProfile"] = resolved_site.site_profile
        chrome_path = chrome_path or discover_chrome()
        if chrome_path:
            options["chromePath"] = chrome_path
        if proxy_server:
            options["proxyServer"] = normalize_proxy_url(proxy_server)
        if user_agent:
            options["userAgent"] = user_agent
        if merged_selectors:
            options["selectors"] = merged_selectors
        if merged_profile:
            options["profile"] = merged_profile
        if merged_env:
            options["env"] = merged_env
        if pre_captcha_fills:
            options["preCaptchaFills"] = [
                {"selector": str(selector), "value": str(value)}
                for selector, value in pre_captcha_fills.items()
            ]
        if pre_captcha_presses:
            options["preCaptchaPresses"] = [str(key) for key in pre_captcha_presses]
        if pre_captcha_clicks:
            options["preCaptchaClicks"] = [str(locator) for locator in pre_captcha_clicks]
        if site_verification_control:
            options["siteVerificationControl"] = True
        if site_verification_accepted_pattern:
            options["siteVerificationAcceptedPattern"] = (
                site_verification_accepted_pattern
            )
        if site_verification_rejected_pattern:
            options["siteVerificationRejectedPattern"] = (
                site_verification_rejected_pattern
            )
        if verify_wait_ms:
            options["verifyWaitMs"] = verify_wait_ms
        if max_attempts:
            options["maxAttempts"] = max_attempts
        resolved_vision_base_url = vision_base_url or os.environ.get("ANTIBOT_VISION_BASE_URL")
        resolved_vision_model = vision_model or os.environ.get("ANTIBOT_VISION_MODEL")
        resolved_vision_key = vision_api_key or os.environ.get(vision_api_key_env)
        reserved_vision_fields = {"model", "messages", "stream", "max_tokens"}
        vision_conflicts = sorted(reserved_vision_fields.intersection(vision_extra_body or {}))
        if vision_conflicts:
            raise ValueError(
                "vision_extra_body cannot override reserved request fields: "
                + ", ".join(vision_conflicts)
            )
        vision_requested = any(
            (vision_base_url, vision_model, vision_api_key, vision_extra_body)
        ) or (
            requested_captcha_type == "image_restore"
            and image_restore_answer is None
            and restore_distance_px is None
        )
        vision_complete = all(
            (resolved_vision_base_url, resolved_vision_model, resolved_vision_key)
        )
        if vision_requested or vision_complete:
            missing = [
                name
                for name, value in (
                    ("vision_base_url", resolved_vision_base_url),
                    ("vision_model", resolved_vision_model),
                    (f"vision_api_key/{vision_api_key_env}", resolved_vision_key),
                )
                if not value
            ]
            if missing:
                return CaptchaResult(
                    provider="aliyun",
                    ok=False,
                    captcha_type=fallback_captcha_type,
                    capability="solver",
                    diagnostics={
                        "target_url": target_url,
                        "requested_captcha_type": requested_captcha_type,
                    },
                    errors=[
                        "incomplete vision backend configuration: missing " + ", ".join(missing)
                    ],
                )
            options["vision"] = {
                "baseUrl": resolved_vision_base_url,
                "model": resolved_vision_model,
                "apiKeyEnv": vision_api_key_env,
                "timeoutMs": max(1_000, int(vision_timeout_sec * 1_000)),
                "minConfidence": max(0.0, min(1.0, float(vision_min_confidence))),
                "retries": max(1, min(5, int(vision_retries))),
            }
            if vision_extra_body:
                options["vision"]["extraBody"] = dict(vision_extra_body)
        if image_restore_answer:
            options["imageRestoreAnswer"] = dict(image_restore_answer)
        if restore_distance_px is not None:
            options["restoreDistancePx"] = float(restore_distance_px)
        if extra_options:
            if extra_options.get("browserArgs"):
                options["browserArgs"] = [*options.get("browserArgs", []), *extra_options["browserArgs"]]
                extra_options = {k: v for k, v in extra_options.items() if k != "browserArgs"}
            options.update(extra_options)

        def load_out_json() -> dict[str, Any]:
            for candidate in (options.get("out"), final_out, Path(output_root) / "aliyun_captcha_run.json"):
                try:
                    p = Path(str(candidate))
                    if p.is_file():
                        return json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
            return {}

        def build_result(
            raw: dict[str, Any] | None,
            *,
            ok: bool | None = None,
            errors: list[str] | None = None,
            stderr: str = "",
            timed_out: bool = False,
        ) -> CaptchaResult:
            raw = raw or {}
            verify = raw.get("verifyResponse") or {}
            verify_ok = aliyun_verify_passed(verify)
            is_ok = verify_ok if ok is None else ok
            artifacts = {
                "out": str(raw.get("out") or final_out),
                "outputDir": str(raw.get("outputDir") or output_root),
            }
            for name in (
                "aliyun_bg_selected.png",
                "aliyun_puzzle_selected.png",
                "aliyun_restore_selected.png",
                "aliyun_restore_background.png",
                "aliyun_restore_fragment.png",
            ):
                p = Path(artifacts["outputDir"]) / name
                if p.exists():
                    artifacts[name] = str(p)
            raw_error = raw.get("error") or {}
            raw_msg = raw_error.get("message") if isinstance(raw_error, dict) else raw_error
            site_evidence = raw.get("siteVerificationEvidence")
            site_secondary_pass = bool(
                isinstance(site_evidence, dict)
                and site_evidence.get("site_secondary_pass") is True
            )
            err_list = errors or []
            if not is_ok and not err_list:
                err_list = [
                    "vendor_verification_not_observed"
                    if site_secondary_pass
                    else str(raw.get("verifyFailureCode") or raw_msg or "solve_failed")
                ]
            diagnostics = {
                "site_profile": resolved_site.name if resolved_site else None,
                "requested_captcha_type": requested_captcha_type,
                "detected_captcha_type": raw.get("captchaType"),
                "attempt": raw.get("attempt"),
                "maxAttempts": raw.get("maxAttempts") or max_attempts,
                "candidate": raw.get("candidate"),
                "trajectory": raw.get("trajectory"),
                "vision": raw.get("vision"),
                "chromePath": chrome_path,
                "headless": headless if headless is not None else "runner-default",
                "timed_out": timed_out,
                "proxy": redacted_proxy(proxy_server),
                "vendor_verification": _aliyun_vendor_verification(raw),
                "site_verification": raw.get("siteVerificationNetwork"),
                "site_verification_control": raw.get(
                    "siteVerificationControlNetwork"
                ),
                "site_verification_evidence": raw.get(
                    "siteVerificationEvidence"
                ),
            }
            attempts = raw.get("attempts") or []
            codes = [
                str(a.get("verifyFailureCode") or a.get("verifyCode") or a.get("error") or "")
                for a in attempts
                if isinstance(a, dict)
            ]
            policy = aliyun_policy_decision(raw, errors=err_list, has_proxy=bool(proxy_server))
            if proxy_server is None and codes.count("F001") >= 2:
                diagnostics["failure_class"] = "likely_ip_or_session_reputation"
                diagnostics["hint"] = (
                    "Aliyun F001 repeated without a proxy; use proxy_server or a "
                    "cooldown, then retry the same challenge configuration."
                )
            if attempts:
                diagnostics["attempt_codes"] = codes
                diagnostics["f001_count"] = codes.count("F001")
            diagnostics["policy"] = policy.to_dict()
            if site_secondary_pass and not is_ok:
                diagnostics["failure_class"] = (
                    "site_secondary_verified_vendor_result_not_observable"
                )
            if not is_ok:
                diagnostics.setdefault("failure_class", policy.failure_class)
            if raw.get("watchdog"):
                diagnostics["watchdog"] = raw.get("watchdog")
            if raw.get("watchdogEvents"):
                diagnostics["watchdog_events"] = raw.get("watchdogEvents")[-5:]
            if stderr:
                diagnostics["stderr_tail"] = stderr[-2000:]
            return CaptchaResult(
                provider="aliyun",
                ok=is_ok,
                captcha_type=normalize_aliyun_captcha_type(
                    raw.get("captchaType") or fallback_captcha_type,
                    allow_unknown=True,
                ),
                capability="solver",
                verify_code=verify.get("VerifyCode") or raw.get("verifyFailureCode"),
                elapsed_ms=raw.get("elapsedMs"),
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if is_ok else err_list,
            )

        async def maybe_session_retry(result: CaptchaResult) -> CaptchaResult:
            retry_budget = max(0, int(session_retries or 0))
            site_evidence = result.diagnostics.get("site_verification_evidence")
            if (
                result.ok
                or (
                    isinstance(site_evidence, dict)
                    and site_evidence.get("site_secondary_pass") is True
                )
                or _session_retry_depth >= retry_budget
            ):
                return result
            attempts = result.raw.get("attempts") if isinstance(result.raw, dict) else []
            codes = [
                str(a.get("verifyFailureCode") or a.get("verifyCode") or a.get("error") or "")
                for a in (attempts or [])
                if isinstance(a, dict)
            ]
            policy = aliyun_policy_decision(
                result.raw if isinstance(result.raw, dict) else {},
                errors=result.errors,
                has_proxy=bool(proxy_server),
            )
            legacy_reputation = result.diagnostics.get("failure_class") == "likely_ip_or_session_reputation"
            if not (policy.should_retry_session or legacy_reputation):
                return result
            delay = float(session_retry_delay_sec if session_retry_delay_sec is not None else 3.0)
            if delay > 0:
                await asyncio.sleep(delay)
            retry_no = _session_retry_depth + 1
            retry_output_dir = None
            if output_dir:
                retry_output_dir = str(Path(output_dir) / f"session_retry_{retry_no}")
            retry_max_attempts = session_retry_max_attempts
            if retry_max_attempts is None:
                retry_max_attempts = min(int(max_attempts or 5), 2)
            retried = await self.solve(
                target_url=target_url,
                captcha_type=requested_captcha_type,
                chrome_path=chrome_path,
                headless=headless,
                output_dir=retry_output_dir,
                out=None,
                proxy_server=proxy_server,
                user_agent=user_agent,
                selectors=selectors,
                site_profile=site_profile,
                profile=profile,
                env=env,
                pre_captcha_fills=pre_captcha_fills,
                pre_captcha_presses=pre_captcha_presses,
                pre_captcha_clicks=pre_captcha_clicks,
                site_verification_control=site_verification_control,
                site_verification_accepted_pattern=(
                    site_verification_accepted_pattern
                ),
                site_verification_rejected_pattern=(
                    site_verification_rejected_pattern
                ),
                verify_wait_ms=verify_wait_ms,
                captcha_wait_ms=captcha_wait_ms,
                max_attempts=retry_max_attempts,
                timeout_sec=timeout_sec,
                cleanup_profile=cleanup_profile,
                vision_base_url=vision_base_url,
                vision_api_key=vision_api_key,
                vision_api_key_env=vision_api_key_env,
                vision_model=vision_model,
                vision_timeout_sec=vision_timeout_sec,
                vision_min_confidence=vision_min_confidence,
                vision_retries=vision_retries,
                vision_extra_body=vision_extra_body,
                image_restore_answer=image_restore_answer,
                restore_distance_px=restore_distance_px,
                extra_options=extra_options,
                session_retries=session_retries,
                session_retry_delay_sec=session_retry_delay_sec,
                session_retry_max_attempts=session_retry_max_attempts,
                _session_retry_depth=retry_no,
            )
            retried.diagnostics["session_retry"] = {
                "used": retry_no,
                "delay_sec": delay,
                "retry_max_attempts": retry_max_attempts,
                "previous_errors": result.errors,
                "previous_attempt_codes": codes or policy.codes,
                "policy": policy.to_dict(),
                "previous_out": result.artifacts.get("out"),
            }
            return retried

        async def terminate_process_group(proc: asyncio.subprocess.Process) -> None:
            if proc.returncode is not None:
                return
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    return
                except Exception:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        return
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                    return
                except asyncio.TimeoutError:
                    continue

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fp:
            json.dump(options, fp, ensure_ascii=False)
            options_path = fp.name
        stdout = b""
        stderr = b""
        proc = None
        process_env = {
            **proxy_free_environment(),
            "NODE_PATH": str(VENDOR_DIR / "node_modules"),
        }
        if vision_api_key:
            process_env[vision_api_key_env] = vision_api_key
        try:
            proc = await asyncio.create_subprocess_exec(
                self.node,
                str(BRIDGE),
                options_path,
                cwd=str(VENDOR_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=process_env,
                start_new_session=True,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            except asyncio.TimeoutError:
                await terminate_process_group(proc)
                err = f"aliyun solver timeout after {timeout_sec}s"
                raw = load_out_json()
                recovered = build_result(raw, timed_out=True)
                if recovered.ok:
                    recovered.diagnostics["process_timeout_recovered"] = True
                    recovered.diagnostics["timeout_note"] = err
                    return recovered
                failed = build_result(raw, ok=False, errors=[err], timed_out=True)
                return await maybe_session_retry(failed)
            except asyncio.CancelledError:
                await terminate_process_group(proc)
                raise
        except asyncio.CancelledError:
            if proc is not None:
                await terminate_process_group(proc)
            raise
        except Exception as e:
            err = f"aliyun solver process failed: {e}"
            raw = load_out_json()
            return build_result(raw, ok=False, errors=[err], stderr=str(e))
        finally:
            try:
                os.unlink(options_path)
            except OSError:
                pass
            if cleanup_profile:
                shutil.rmtree(user_data_dir, ignore_errors=True)

        if proc is None:
            return build_result(load_out_json(), ok=False, errors=["aliyun solver process did not start"])
        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[-4000:]
            raw = load_out_json() or {"stderr": err}
            return build_result(raw, ok=False, errors=[err or "node bridge failed"], stderr=err)
        try:
            raw = json.loads(stdout.decode() or "{}")
        except json.JSONDecodeError as e:
            err = stderr.decode(errors="replace")[-4000:]
            raw = load_out_json()
            if raw:
                return await maybe_session_retry(build_result(raw, stderr=err))
            return build_result(raw, ok=False, errors=[f"invalid bridge json: {e}", err], stderr=err)
        return await maybe_session_retry(build_result(raw))
