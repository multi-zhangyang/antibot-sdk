from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ._version import __version__
from .capabilities import list_capabilities
from .client import AntibotClient
from .profiles import detect_provider_for_url, list_profiles
from .providers.aliyun import ALIYUN_CAPTCHA_TYPES, AliyunCaptchaSolver
from .providers.geetest import DEFAULT_GEETEST_DEMO_URL
from .runtime import runtime_diagnostics
from .stress import run_stress

HCAPTCHA_ENGINE_REQUIREMENTS = (
    "ftfy>=6.1",
    "httpx[http2]>=0.24,<1",
    "importlib-metadata>=6",
    "loguru>=0.7",
    "msgpack>=1.1,<2",
    "onnxruntime>=1.16",
    "pydantic>=2.5,<3",
    "pyyaml>=6",
    "regex>=2023.0",
    "scikit-image>=0.21",
    "scikit-learn>=1.3,<2",
    "tenacity>=8,<9",
    "tqdm>=4.66",
)


def _install_hcaptcha_engine() -> None:
    base = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    subprocess.run([*base, *HCAPTCHA_ENGINE_REQUIREMENTS], check=True)
    subprocess.run(
        [*base, "--no-deps", "hcaptcha-challenger==0.10.1.post2"],
        check=True,
    )


def _json_arg(value: str | None) -> Any:
    if value is None:
        return None
    text = Path(value[1:]).read_text(encoding="utf-8") if value.startswith("@") else value
    return json.loads(text)


def _kv(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit("expected KEY=VALUE")
        key, value = item.split("=", 1)
        out[key] = value
    return out


def _headless_any(value: str | None) -> bool | str | None:
    if value in (None, "", "auto"):
        return None
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    return value


def _headless_bool(value: str | None, *, default: bool = True) -> bool:
    parsed = _headless_any(value)
    if parsed is None:
        return default
    if isinstance(parsed, bool):
        return parsed
    return str(parsed).lower() not in {"0", "false", "no", "headed"}


def _compact_raw(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return raw
    verify = raw.get("verifyResponse")
    compact_verify = None
    if isinstance(verify, dict):
        nested = verify.get("Result")
        if isinstance(nested, dict):
            verify = nested
        compact_verify = {
            key: verify.get(key)
            for key in ("VerifyResult", "VerifyCode")
            if verify.get(key) is not None
        }
    keep = {
        "ok": raw.get("ok"),
        "ticket": raw.get("ticket"),
        "randstr": raw.get("randstr"),
        "verifyResponse": compact_verify,
        "verifyFailureCode": raw.get("verifyFailureCode"),
        "siteVerificationNetwork": raw.get("siteVerificationNetwork"),
        "siteVerificationControlNetwork": raw.get("siteVerificationControlNetwork"),
        "siteVerificationEvidence": raw.get("siteVerificationEvidence"),
        "attempt": raw.get("attempt"),
        "maxAttempts": raw.get("maxAttempts"),
        "attempts": raw.get("attempts"),
        "candidate": raw.get("candidate"),
        "error": raw.get("error"),
        "state": raw.get("state"),
        "target_url": raw.get("target_url"),
        "final_url": raw.get("final_url"),
        "title": raw.get("title"),
        "solution": raw.get("solution"),
        "events": raw.get("events"),
        "cf_clearance": raw.get("cf_clearance"),
        "cookie_header": raw.get("cookie_header"),
        "turnstile_token": raw.get("turnstile_token"),
        "cookies": raw.get("cookies"),
    }
    return {key: value for key, value in keep.items() if value not in (None, "", [], {})}


def emit(obj: Any, *, include_raw: bool = False) -> None:
    data = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
    if isinstance(data, dict) and not include_raw and "raw" in data:
        data["raw"] = _compact_raw(data.get("raw"))
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _add_common_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--proxy")
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--raw", action="store_true")


def _add_tencent_args(parser: argparse.ArgumentParser) -> None:
    _add_common_target_args(parser)
    parser.add_argument("--profile", default="cloud_product")
    parser.add_argument("--appid")
    parser.add_argument("--headless", default="true", choices=["auto", "true", "false", "1", "0", "yes", "no"])
    parser.add_argument("--pool-size", type=int, default=1)
    parser.add_argument("--browser-max-uses", type=int, default=1)
    parser.add_argument("--locale")
    parser.add_argument("--timezone-id")
    parser.add_argument("--user-agent")
    parser.add_argument("--browser-binary")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--output-json",
        help="persist this run's complete result; use a unique path for each benchmark run",
    )


def _add_aliyun_args(parser: argparse.ArgumentParser) -> None:
    _add_common_target_args(parser)
    parser.add_argument("--captcha-type", default="auto", choices=ALIYUN_CAPTCHA_TYPES)
    parser.add_argument("--chrome-path")
    parser.add_argument("--headless", default="auto", choices=["auto", "true", "false", "1", "0", "yes", "no", "new"])
    parser.add_argument("--output-dir")
    parser.add_argument("--out")
    parser.add_argument("--user-agent")
    parser.add_argument("--selector", action="append", default=[])
    parser.add_argument("--site-profile", default="auto")
    parser.add_argument("--profile-json")
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument(
        "--pre-captcha-fill",
        action="append",
        default=[],
        metavar="CSS=VALUE",
        help="fill a visible form field after navigation; values are runtime-only",
    )
    parser.add_argument(
        "--pre-captcha-press",
        action="append",
        default=[],
        metavar="KEY",
        help="press a key after runtime form fills",
    )
    parser.add_argument(
        "--pre-captcha-click",
        action="append",
        default=[],
        metavar="CSS|text:LABEL",
        help="click a visible CSS target or exact text after navigation",
    )
    parser.add_argument("--site-verification-control", action="store_true")
    parser.add_argument("--site-verification-accepted-pattern")
    parser.add_argument("--site-verification-rejected-pattern")
    parser.add_argument("--verify-wait-ms", type=int)
    parser.add_argument("--captcha-wait-ms", type=int)
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--session-retries", type=int)
    parser.add_argument("--session-retry-delay-sec", type=float)
    parser.add_argument("--session-retry-max-attempts", type=int)
    parser.add_argument("--vision-base-url")
    parser.add_argument("--vision-model")
    parser.add_argument("--vision-api-key-env", default="ANTIBOT_VISION_API_KEY")
    parser.add_argument("--vision-timeout", type=float, default=180)
    parser.add_argument("--vision-min-confidence", type=float, default=0.35)
    parser.add_argument("--vision-retries", type=int, default=2)
    parser.add_argument(
        "--vision-extra-json",
        help="OpenAI-compatible request fields as JSON or @path; never put API keys here",
    )
    parser.add_argument("--restore-distance-px", type=float)
    parser.add_argument("--keep-profile", action="store_true")


def _aliyun_kwargs(args: argparse.Namespace, *, target_url: str | None = None) -> dict[str, Any]:
    return {
        "target_url": target_url or args.target_url,
        "captcha_type": getattr(args, "captcha_type", "auto"),
        "chrome_path": getattr(args, "chrome_path", None),
        "headless": _headless_any(getattr(args, "headless", None)),
        "output_dir": getattr(args, "output_dir", None),
        "out": getattr(args, "out", None),
        "proxy_server": getattr(args, "proxy", None),
        "user_agent": getattr(args, "user_agent", None),
        "selectors": _kv(getattr(args, "selector", [])),
        "site_profile": getattr(args, "site_profile", None)
        or getattr(args, "profile", None)
        or "auto",
        "profile": _json_arg(getattr(args, "profile_json", None)),
        "env": _kv(getattr(args, "env", [])),
        "pre_captcha_fills": _kv(getattr(args, "pre_captcha_fill", [])),
        "pre_captcha_presses": list(getattr(args, "pre_captcha_press", [])),
        "pre_captcha_clicks": list(getattr(args, "pre_captcha_click", [])),
        "site_verification_control": bool(
            getattr(args, "site_verification_control", False)
        ),
        "site_verification_accepted_pattern": getattr(
            args, "site_verification_accepted_pattern", None
        ),
        "site_verification_rejected_pattern": getattr(
            args, "site_verification_rejected_pattern", None
        ),
        "verify_wait_ms": getattr(args, "verify_wait_ms", None),
        "captcha_wait_ms": getattr(args, "captcha_wait_ms", None),
        "max_attempts": getattr(args, "max_attempts", None),
        "timeout_sec": getattr(args, "timeout", None) or 180,
        "cleanup_profile": not bool(getattr(args, "keep_profile", False)),
        "session_retries": getattr(args, "session_retries", None),
        "session_retry_delay_sec": getattr(args, "session_retry_delay_sec", None),
        "session_retry_max_attempts": getattr(args, "session_retry_max_attempts", None),
        "vision_base_url": getattr(args, "vision_base_url", None),
        "vision_api_key_env": getattr(
            args, "vision_api_key_env", "ANTIBOT_VISION_API_KEY"
        ),
        "vision_model": getattr(args, "vision_model", None),
        "vision_timeout_sec": getattr(args, "vision_timeout", 180),
        "vision_min_confidence": getattr(args, "vision_min_confidence", 0.35),
        "vision_retries": getattr(args, "vision_retries", 2),
        "vision_extra_body": _json_arg(getattr(args, "vision_extra_json", None)),
        "restore_distance_px": getattr(args, "restore_distance_px", None),
    }


def _add_cloudflare_args(parser: argparse.ArgumentParser, *, positional_url: bool = False) -> None:
    if positional_url:
        parser.add_argument("url")
    else:
        parser.add_argument("--target-url", required=True)
    parser.add_argument("--mode", default="auto", choices=["auto", "turnstile", "managed", "scrape"])
    parser.add_argument("--headless", default="auto", choices=["auto", "true", "false", "1", "0", "yes", "no"])
    parser.add_argument("--browser-binary")
    parser.add_argument("--proxy")
    parser.add_argument("--profile-dir")
    parser.add_argument("--accept-languages", default="en-US,en")
    parser.add_argument("--user-agent")
    parser.add_argument("--platform")
    parser.add_argument("--viewport", default="1920,1080")
    parser.add_argument("--startup-timeout", type=int, default=45)
    parser.add_argument("--navigation-timeout", type=int, default=90)
    parser.add_argument("--max-wait", type=int, default=90)
    parser.add_argument("--captcha-wait", type=float, default=8.0)
    parser.add_argument("--selector", action="append", default=[])
    parser.add_argument("--click", action="append", default=[])
    parser.add_argument("--wait-after-click", type=float, default=3.0)
    parser.add_argument("--screenshot")
    parser.add_argument("--html-output")
    parser.add_argument("--output-json")
    parser.add_argument("--block-resources", action="store_true")
    parser.add_argument("--block-stylesheets", action="store_true")
    parser.add_argument("--no-fingerprint-patch", action="store_true")
    parser.add_argument("--no-human-probe", action="store_true")
    parser.add_argument("--raw", action="store_true")


def _add_geetest_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-url", default=DEFAULT_GEETEST_DEMO_URL)
    parser.add_argument("--headless", default="true", choices=["auto", "true", "false", "1", "0", "yes", "no"])
    parser.add_argument("--browser-binary")
    parser.add_argument("--proxy")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--wait-after-load-ms", type=int, default=2500)
    parser.add_argument("--click-selector", "--trigger", dest="click_selector", action="append", default=[])
    parser.add_argument("--variant", default="auto", choices=["auto", "ai", "slide", "icon", "gobang", "winlinze", "match", "iconcrush", "observe"])
    parser.add_argument("--slide-attempts", type=int, default=3)
    parser.add_argument("--winlinze-attempts", "--match-attempts", dest="winlinze_attempts", type=int, default=2)
    parser.add_argument("--no-slide-solve", action="store_true")
    parser.add_argument("--no-auto-trigger", action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--save-html", action="store_true")
    parser.add_argument("--screenshot")
    parser.add_argument("--output-json")
    parser.add_argument("--raw-events", action="store_true")
    parser.add_argument("--user-agent")
    parser.add_argument("--locale", default="zh-CN")
    parser.add_argument("--timezone-id", default="Asia/Shanghai")
    parser.add_argument("--raw", action="store_true")


def _add_widget_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--headless", default="true", choices=["true", "false", "1", "0", "yes", "no"])
    parser.add_argument("--browser-binary")
    parser.add_argument("--proxy")
    parser.add_argument("--proxy-bypass", default="127.0.0.1,localhost")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--wait-after-load-ms", type=int, default=1500)
    parser.add_argument("--trigger", dest="click_selector", action="append", default=[])
    parser.add_argument("--no-auto-click", action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--screenshot")
    parser.add_argument("--html-output")
    parser.add_argument("--output-json")
    parser.add_argument("--user-agent")
    parser.add_argument("--locale")
    parser.add_argument("--timezone-id")
    parser.add_argument("--submit-selector")
    parser.add_argument("--success-selector", action="append", default=[])
    parser.add_argument("--success-text")
    parser.add_argument("--verification-wait-ms", type=int, default=3000)
    parser.add_argument("--vision-base-url")
    parser.add_argument("--vision-model")
    parser.add_argument("--vision-api-key-env", default="ANTIBOT_VISION_API_KEY")
    parser.add_argument("--vision-timeout", type=float, default=180)
    parser.add_argument("--vision-min-confidence", type=float, default=0.35)
    parser.add_argument("--vision-retries", type=int, default=2)
    parser.add_argument("--recaptcha-max-attempts", type=int, default=6)
    parser.add_argument("--recaptcha-max-rounds", type=int, default=8)
    parser.add_argument("--hcaptcha-max-attempts", type=int, default=6)
    parser.add_argument(
        "--vision-extra-json",
        help="OpenAI-compatible request fields as JSON or @path; never put API keys here",
    )
    parser.add_argument("--raw", action="store_true")


def _cloudflare_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "mode": args.mode,
        "headless": str(args.headless),
        "browser_binary": args.browser_binary,
        "proxy": args.proxy,
        "profile_dir": args.profile_dir,
        "accept_languages": args.accept_languages,
        "user_agent": args.user_agent,
        "platform": args.platform,
        "viewport": args.viewport,
        "startup_timeout": args.startup_timeout,
        "navigation_timeout": args.navigation_timeout,
        "max_wait": args.max_wait,
        "captcha_wait": args.captcha_wait,
        "screenshot": args.screenshot,
        "html_output": args.html_output,
        "output_json": args.output_json,
        "selectors": _kv(args.selector),
        "clicks": args.click,
        "wait_after_click": args.wait_after_click,
        "block_resources": args.block_resources,
        "block_stylesheets": args.block_stylesheets,
        "inject_fingerprint_patch": not args.no_fingerprint_patch,
        "human_probe": not args.no_human_probe,
    }


def _geetest_kwargs(
    args: argparse.Namespace,
    *,
    target_url: str | None = None,
    browser_binary: str | None = None,
) -> dict[str, Any]:
    return {
        "target_url": target_url or getattr(args, "target_url", None) or DEFAULT_GEETEST_DEMO_URL,
        "headless": _headless_bool(getattr(args, "headless", None)),
        "browser_binary": browser_binary or getattr(args, "browser_binary", None),
        "proxy_server": getattr(args, "proxy", None),
        "timeout_sec": getattr(args, "timeout", None) or 60,
        "wait_after_load_ms": getattr(args, "wait_after_load_ms", 2500),
        "click_selectors": getattr(args, "click_selector", None) or None,
        "variant": getattr(args, "variant", "auto"),
        "auto_trigger": not bool(getattr(args, "no_auto_trigger", False)),
        "slide_max_attempts": getattr(args, "slide_attempts", 3),
        "winlinze_max_attempts": getattr(args, "winlinze_attempts", 2),
        "slide_solve": not bool(getattr(args, "no_slide_solve", False)),
        "output_dir": getattr(args, "output_dir", None),
        "save_html": bool(getattr(args, "save_html", False)),
        "screenshot": getattr(args, "screenshot", None),
        "output_json": getattr(args, "output_json", None),
        "raw_events": bool(getattr(args, "raw_events", False)),
        "user_agent": getattr(args, "user_agent", None),
        "locale": getattr(args, "locale", "zh-CN"),
        "timezone_id": getattr(args, "timezone_id", "Asia/Shanghai"),
    }


def _widget_kwargs(
    args: argparse.Namespace,
    *,
    target_url: str | None = None,
    browser_binary: str | None = None,
) -> dict[str, Any]:
    return {
        "target_url": target_url or args.target_url,
        "headless": _headless_bool(getattr(args, "headless", None)),
        "browser_binary": browser_binary or getattr(args, "browser_binary", None),
        "proxy_server": getattr(args, "proxy", None),
        "proxy_bypass": getattr(args, "proxy_bypass", "127.0.0.1,localhost"),
        "timeout_sec": getattr(args, "timeout", None) or 90,
        "wait_after_load_ms": getattr(args, "wait_after_load_ms", 1500),
        "click_selectors": getattr(args, "click_selector", None) or None,
        "auto_click": not bool(getattr(args, "no_auto_click", False)),
        "output_dir": getattr(args, "output_dir", None),
        "screenshot": getattr(args, "screenshot", None),
        "html_output": getattr(args, "html_output", None),
        "output_json": getattr(args, "output_json", None),
        "user_agent": getattr(args, "user_agent", None),
        "locale": getattr(args, "locale", None),
        "timezone_id": getattr(args, "timezone_id", None),
        "submit_selector": getattr(args, "submit_selector", None),
        "success_selectors": getattr(args, "success_selector", None) or None,
        "success_text": getattr(args, "success_text", None),
        "verification_wait_ms": getattr(args, "verification_wait_ms", 3000),
        "vision_base_url": getattr(args, "vision_base_url", None),
        "vision_model": getattr(args, "vision_model", None),
        "vision_api_key_env": getattr(
            args, "vision_api_key_env", "ANTIBOT_VISION_API_KEY"
        ),
        "vision_timeout_sec": getattr(args, "vision_timeout", 180),
        "vision_min_confidence": getattr(args, "vision_min_confidence", 0.35),
        "vision_retries": getattr(args, "vision_retries", 2),
        "recaptcha_max_attempts": getattr(args, "recaptcha_max_attempts", 6),
        "recaptcha_max_rounds": getattr(args, "recaptcha_max_rounds", 8),
        "hcaptcha_max_attempts": getattr(args, "hcaptcha_max_attempts", 6),
        "vision_extra_body": _json_arg(getattr(args, "vision_extra_json", None)),
    }


def _arkose_kwargs(
    args: argparse.Namespace,
    *,
    target_url: str | None = None,
    browser_binary: str | None = None,
) -> dict[str, Any]:
    """Build Arkose runner options without passing reCAPTCHA-only settings."""

    return {
        "target_url": target_url or args.target_url,
        "headless": _headless_bool(getattr(args, "headless", None)),
        "browser_binary": browser_binary or getattr(args, "browser_binary", None),
        "browser_args": getattr(args, "browser_arg", None) or None,
        "proxy_server": getattr(args, "proxy", None),
        "proxy_bypass": getattr(args, "proxy_bypass", "127.0.0.1,localhost"),
        "timeout_sec": getattr(args, "timeout", None) or 120,
        "wait_after_load_ms": getattr(args, "wait_after_load_ms", 1800),
        "click_selectors": getattr(args, "click_selector", None) or None,
        "auto_click": not bool(getattr(args, "no_auto_click", False)),
        "output_dir": getattr(args, "output_dir", None),
        "screenshot": getattr(args, "screenshot", None),
        "html_output": getattr(args, "html_output", None),
        "output_json": getattr(args, "output_json", None),
        "user_agent": getattr(args, "user_agent", None),
        "locale": getattr(args, "locale", None),
        "timezone_id": getattr(args, "timezone_id", None),
        "submit_selector": getattr(args, "submit_selector", None),
        "success_selectors": getattr(args, "success_selector", None) or None,
        "success_text": getattr(args, "success_text", None),
        "verification_wait_ms": getattr(args, "verification_wait_ms", 4000),
        "vision_base_url": getattr(args, "vision_base_url", None),
        "vision_model": getattr(args, "vision_model", None),
        "vision_api_key_env": getattr(args, "vision_api_key_env", "ANTIBOT_VISION_API_KEY"),
        "vision_timeout_sec": getattr(args, "vision_timeout", 180),
        "vision_min_confidence": getattr(args, "vision_min_confidence", 0.35),
        "vision_retries": getattr(args, "vision_retries", 2),
        "max_rounds": getattr(args, "arkose_max_rounds", 12),
        "vision_extra_body": _json_arg(getattr(args, "vision_extra_json", None)),
    }


async def amain(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="antibot")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("profiles")
    sub.add_parser("capabilities")
    sub.add_parser("diagnose")
    sub.add_parser("install-js-deps")
    sub.add_parser("install-hcaptcha-engine")

    replay = sub.add_parser("replay-eval")
    replay.add_argument("inputs", nargs="+")

    harness = sub.add_parser("harness")
    harness.add_argument("--target-url", required=True)
    harness.add_argument(
        "--provider",
        default="auto",
        choices=[
            "auto",
            "aliyun",
            "cloudflare",
            "geetest",
            "hcaptcha",
            "recaptcha",
            "arkose",
            "tencent",
        ],
    )
    harness.add_argument("--planner", choices=["heuristic", "pydantic-ai"], default="heuristic")
    harness.add_argument("--agent-base-url")
    harness.add_argument("--agent-model")
    harness.add_argument("--agent-api-key-env", default="ANTIBOT_AGENT_API_KEY")
    harness.add_argument("--agent-timeout", type=float, default=30.0)
    harness.add_argument("--timeout", type=float, default=300.0)
    harness.add_argument("--max-steps", type=int, default=6)
    harness.add_argument("--max-provider-actions", type=int, default=2)
    harness.add_argument("--options-json")
    harness.add_argument("--proxy")
    harness.add_argument("--browser-binary")
    harness.add_argument("--raw", action="store_true")

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--max-concurrency", type=int, default=2)
    serve.add_argument("--default-timeout", type=float, default=180.0)
    serve.add_argument("--browser-binary")
    serve.add_argument("--proxy")
    serve.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
    )
    serve.add_argument("--no-access-log", action="store_true")

    run = sub.add_parser("run")
    _add_cloudflare_args(run, positional_url=True)

    auto = sub.add_parser("auto")
    auto.add_argument("url", nargs="?")
    auto.add_argument("--target-url")
    auto.add_argument(
        "--provider",
        default="auto",
        choices=[
            "auto",
            "aliyun",
            "tencent",
            "cloudflare",
            "geetest",
            "recaptcha",
            "hcaptcha",
            "arkose",
        ],
    )
    auto.add_argument("--proxy")
    auto.add_argument("--timeout", type=int)
    auto.add_argument("--raw", action="store_true")
    auto.add_argument("--profile", default=None, help="Tencent profile or Aliyun site profile")
    auto.add_argument("--appid")
    auto.add_argument("--headless", default="auto")
    auto.add_argument("--chrome-path")
    auto.add_argument("--browser-binary")
    auto.add_argument("--browser-arg", action="append", default=[])
    auto.add_argument("--wait-after-load-ms", type=int, default=2500)
    auto.add_argument("--click-selector", "--trigger", dest="click_selector", action="append", default=[])
    auto.add_argument("--variant", default="auto")
    auto.add_argument("--slide-attempts", type=int, default=3)
    auto.add_argument("--winlinze-attempts", "--match-attempts", dest="winlinze_attempts", type=int, default=2)
    auto.add_argument("--no-slide-solve", action="store_true")
    auto.add_argument("--no-auto-trigger", action="store_true")
    auto.add_argument("--output-dir")
    auto.add_argument("--save-html", action="store_true")
    auto.add_argument("--screenshot")
    auto.add_argument("--html-output")
    auto.add_argument("--output-json")
    auto.add_argument("--raw-events", action="store_true")
    auto.add_argument("--user-agent")
    auto.add_argument("--locale", default="zh-CN")
    auto.add_argument("--timezone-id", default="Asia/Shanghai")
    auto.add_argument("--proxy-bypass", default="127.0.0.1,localhost")
    auto.add_argument("--no-auto-click", action="store_true")
    auto.add_argument("--recaptcha-max-attempts", type=int, default=6)
    auto.add_argument("--recaptcha-max-rounds", type=int, default=8)
    auto.add_argument("--hcaptcha-max-attempts", type=int, default=6)
    auto.add_argument("--arkose-max-rounds", type=int, default=12)
    auto.add_argument("--captcha-type", default="auto", choices=ALIYUN_CAPTCHA_TYPES)
    auto.add_argument("--vision-base-url")
    auto.add_argument("--vision-model")
    auto.add_argument("--vision-api-key-env", default="ANTIBOT_VISION_API_KEY")
    auto.add_argument("--vision-timeout", type=float, default=180)
    auto.add_argument("--vision-min-confidence", type=float, default=0.35)
    auto.add_argument("--vision-retries", type=int, default=2)
    auto.add_argument("--vision-extra-json")
    auto.add_argument("--restore-distance-px", type=float)

    solve = sub.add_parser("solve")
    solve_sub = solve.add_subparsers(dest="provider", required=True)
    _add_tencent_args(solve_sub.add_parser("tencent"))
    _add_aliyun_args(solve_sub.add_parser("aliyun"))
    _add_cloudflare_args(solve_sub.add_parser("cloudflare"))
    _add_geetest_args(solve_sub.add_parser("geetest"))
    _add_widget_args(solve_sub.add_parser("recaptcha"))
    _add_widget_args(solve_sub.add_parser("hcaptcha"))
    arkose = solve_sub.add_parser("arkose")
    _add_widget_args(arkose)
    arkose.add_argument("--browser-arg", action="append", default=[])
    arkose.add_argument("--arkose-max-rounds", type=int, default=12)

    stress = sub.add_parser("stress")
    stress_sub = stress.add_subparsers(dest="provider", required=True)
    st = stress_sub.add_parser("tencent")
    _add_tencent_args(st)
    st.add_argument("--runs", type=int, default=5)
    st.add_argument("--concurrency", type=int, default=1)
    st.add_argument("--full", action="store_true")

    sa = stress_sub.add_parser("aliyun")
    _add_aliyun_args(sa)
    sa.add_argument("--runs", type=int, default=3)
    sa.add_argument("--concurrency", type=int, default=1)
    sa.add_argument("--output-json")
    sa.add_argument("--full", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "profiles":
        emit(list_profiles(), include_raw=True)
        return 0
    if args.cmd == "capabilities":
        emit(list_capabilities(), include_raw=True)
        return 0
    if args.cmd == "install-js-deps":
        try:
            AliyunCaptchaSolver.install_js_deps()
        except (OSError, RuntimeError) as exc:
            emit({"ok": False, "error": str(exc)}, include_raw=True)
            return 2
        return 0
    if args.cmd == "install-hcaptcha-engine":
        try:
            _install_hcaptcha_engine()
        except (OSError, subprocess.CalledProcessError) as exc:
            emit({"ok": False, "error": str(exc)}, include_raw=True)
            return 2
        emit(
            {
                "ok": True,
                "engine": "hcaptcha-challenger",
                "version": "0.10.1.post2",
            },
            include_raw=True,
        )
        return 0
    if args.cmd == "diagnose":
        emit(runtime_diagnostics(), include_raw=True)
        return 0
    if args.cmd == "replay-eval":
        from .harness import evaluate_replays

        try:
            report = evaluate_replays(args.inputs)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, include_raw=True)
            return 2
        emit(report.to_dict(), include_raw=True)
        return 0
    if args.cmd == "serve":
        try:
            import uvicorn
        except ImportError as exc:
            parser.error(
                "serve requires optional dependencies: "
                "install with `pip install -e '.[service]'` or `uv sync --extra service`"
            )
            raise AssertionError("unreachable") from exc
        from .service import ServiceSettings, create_app

        app = create_app(
            ServiceSettings(
                max_concurrency=args.max_concurrency,
                default_timeout_sec=args.default_timeout,
                browser_binary=args.browser_binary,
                default_proxy=args.proxy,
            )
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=args.host,
                port=args.port,
                log_level=args.log_level,
                access_log=not args.no_access_log,
            )
        )
        await server.serve()
        return 0 if server.started else 1

    async with AntibotClient(
        browser_binary=getattr(args, "browser_binary", None)
        or getattr(args, "chrome_path", None)
    ) as client:
        if args.cmd == "harness":
            from .harness import HarnessBudget, PydanticAIPlanner

            options = _json_arg(args.options_json) or {}
            if not isinstance(options, dict):
                parser.error("--options-json must decode to a JSON object")
            if args.proxy and "proxy" not in options and "proxy_server" not in options:
                options["proxy"] = args.proxy
            planner = None
            if args.planner == "pydantic-ai":
                api_key = os.environ.get(args.agent_api_key_env, "")
                if not args.agent_base_url or not args.agent_model or not api_key:
                    emit(
                        {
                            "ok": False,
                            "error": (
                                "pydantic-ai planner requires --agent-base-url, "
                                "--agent-model and the configured API key environment variable"
                            ),
                        },
                        include_raw=True,
                    )
                    return 2
                planner = PydanticAIPlanner(
                    base_url=args.agent_base_url,
                    api_key=api_key,
                    model=args.agent_model,
                    timeout_sec=args.agent_timeout,
                )
            ret = await client.solve_agent(
                args.target_url,
                provider=args.provider,
                planner=planner,
                budget=HarnessBudget(
                    timeout_sec=args.timeout,
                    max_steps=args.max_steps,
                    max_provider_actions=args.max_provider_actions,
                ),
                **options,
            )
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "run":
            ret = await client.open(args.url, **_cloudflare_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "auto":
            target_url = args.target_url or args.url
            if args.provider == "geetest" and not target_url:
                target_url = DEFAULT_GEETEST_DEMO_URL
            if not target_url:
                parser.error("auto requires url or --target-url")
            provider = detect_provider_for_url(target_url) if args.provider == "auto" else args.provider
            if provider == "aliyun":
                ret = await client.solve_aliyun(**_aliyun_kwargs(args, target_url=target_url))
            elif provider == "tencent":
                ret = await client.solve_tencent(
                    target_url=target_url,
                    profile=args.profile or "cloud_product",
                    appid=args.appid,
                    headless=_headless_bool(args.headless),
                    proxy_server=args.proxy,
                    browser_binary=args.browser_binary,
                    timeout_sec=args.timeout,
                    output_json=getattr(args, "output_json", None),
                )
            elif provider == "cloudflare":
                # auto headless on VPS without DISPLAY is safer than forcing headed.
                headless_value = str(args.headless)
                ret = await client.solve_cloudflare(
                    target_url=target_url,
                    mode="auto",
                    headless=headless_value,
                    browser_binary=args.browser_binary or args.chrome_path,
                    proxy=args.proxy,
                    max_wait=args.timeout or 90,
                    screenshot=getattr(args, "screenshot", None),
                    output_json=getattr(args, "output_json", None),
                )
            elif provider == "geetest":
                ret = await client.solve_geetest(
                    **_geetest_kwargs(
                        args,
                        target_url=target_url,
                        browser_binary=args.browser_binary or args.chrome_path,
                    )
                )
            elif provider in {"recaptcha", "hcaptcha"}:
                method = getattr(client, f"solve_{provider}")
                ret = await method(
                    **_widget_kwargs(
                        args,
                        target_url=target_url,
                        browser_binary=args.browser_binary or args.chrome_path,
                    )
                )
            elif provider == "arkose":
                ret = await client.solve_arkose(
                    **_arkose_kwargs(
                        args,
                        target_url=target_url,
                        browser_binary=args.browser_binary or args.chrome_path,
                    )
                )
            else:
                ret = await client.solve_auto(target_url, provider=provider)
            emit(ret, include_raw=args.raw or getattr(args, "raw_events", False))
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "cloudflare":
            ret = await client.solve_cloudflare(args.target_url, **_cloudflare_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "geetest":
            ret = await client.solve_geetest(**_geetest_kwargs(args))
            emit(ret, include_raw=args.raw or args.raw_events)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider in {"recaptcha", "hcaptcha"}:
            method = getattr(client, f"solve_{args.provider}")
            ret = await method(**_widget_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "arkose":
            ret = await client.solve_arkose(**_arkose_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "tencent":
            ret = await client.solve_tencent(
                target_url=args.target_url,
                profile=args.profile,
                appid=args.appid,
                headless=_headless_bool(args.headless),
                proxy_server=args.proxy,
                pool_size=args.pool_size,
                browser_max_uses=args.browser_max_uses,
                locale=args.locale,
                timezone_id=args.timezone_id,
                user_agent=args.user_agent,
                browser_binary=args.browser_binary,
                timeout_sec=args.timeout,
                verbose=args.verbose,
                output_json=args.output_json,
            )
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "aliyun":
            ret = await client.solve_aliyun(**_aliyun_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "stress" and args.provider == "tencent":
            headless = _headless_bool(args.headless)
            pool = None
            try:
                pool, prof = client.tencent.create_pool(
                    target_url=args.target_url,
                    profile=args.profile,
                    headless=headless,
                    proxy_server=args.proxy,
                    pool_size=args.pool_size,
                    browser_max_uses=args.browser_max_uses,
                    locale=args.locale,
                    timezone_id=args.timezone_id,
                    user_agent=args.user_agent,
                    browser_binary=args.browser_binary,
                )
                await pool.start()
                payload = await run_stress(
                    name="tencent",
                    runs=args.runs,
                    concurrency=args.concurrency,
                    per_run_timeout=args.timeout,
                    output_json=args.output_json,
                    run_once=lambda _i: client.tencent.solve_with_pool(
                        pool,
                        target_url=args.target_url,
                        profile=args.profile,
                        appid=args.appid,
                        prof=prof,
                        headless=headless,
                        pool_size=args.pool_size,
                        browser_max_uses=args.browser_max_uses,
                        proxy_server=args.proxy,
                        timeout_sec=args.timeout,
                        verbose=args.verbose,
                    ),
                )
            finally:
                if pool is not None:
                    await pool.stop()
            emit(payload if args.full else {"summary": payload["summary"]}, include_raw=True)
            return 0 if payload["summary"]["fail"] == 0 else 2

        if args.cmd == "stress" and args.provider == "aliyun":
            payload = await run_stress(
                name="aliyun",
                runs=args.runs,
                concurrency=args.concurrency,
                per_run_timeout=args.timeout,
                output_json=args.output_json,
                run_once=lambda _i: client.solve_aliyun(
                    **{**_aliyun_kwargs(args), "out": None}
                ),
            )
            emit(payload if args.full else {"summary": payload["summary"]}, include_raw=True)
            return 0 if payload["summary"]["fail"] == 0 else 2

    return 1


def main() -> None:
    try:
        code = asyncio.run(amain())
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
