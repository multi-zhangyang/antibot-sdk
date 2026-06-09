from __future__ import annotations

import argparse
import asyncio
import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .capabilities import list_capabilities
from .client import AntibotClient
from .profiles import detect_provider_for_url, list_profiles
from .providers.aliyun import AliyunCaptchaSolver, discover_chrome
from .providers.browser import BrowserAutomation
from .stress import run_stress


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
    keep = {
        "ok": raw.get("ok"),
        "ticket": raw.get("ticket"),
        "randstr": raw.get("randstr"),
        "verifyResponse": raw.get("verifyResponse"),
        "verifyFailureCode": raw.get("verifyFailureCode"),
        "attempt": raw.get("attempt"),
        "maxAttempts": raw.get("maxAttempts"),
        "attempts": raw.get("attempts"),
        "candidate": raw.get("candidate"),
        "error": raw.get("error"),
        "state": raw.get("state"),
        "final_url": raw.get("final_url"),
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
    parser.add_argument("--verbose", action="store_true")


def _add_aliyun_args(parser: argparse.ArgumentParser) -> None:
    _add_common_target_args(parser)
    parser.add_argument("--chrome-path")
    parser.add_argument("--headless", default="auto", choices=["auto", "true", "false", "1", "0", "yes", "no", "new"])
    parser.add_argument("--output-dir")
    parser.add_argument("--out")
    parser.add_argument("--user-agent")
    parser.add_argument("--selector", action="append", default=[])
    parser.add_argument("--site-profile", default="auto")
    parser.add_argument("--profile-json")
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("--verify-wait-ms", type=int)
    parser.add_argument("--captcha-wait-ms", type=int)
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--session-retries", type=int)
    parser.add_argument("--session-retry-delay-sec", type=float)
    parser.add_argument("--session-retry-max-attempts", type=int)
    parser.add_argument("--keep-profile", action="store_true")


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


async def amain(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="antibot")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("profiles")
    sub.add_parser("capabilities")
    sub.add_parser("diagnose")
    sub.add_parser("install-js-deps")

    run = sub.add_parser("run")
    _add_cloudflare_args(run, positional_url=True)

    auto = sub.add_parser("auto")
    auto.add_argument("url")
    auto.add_argument("--provider", default="auto", choices=["auto", "aliyun", "tencent", "cloudflare"])
    auto.add_argument("--proxy")
    auto.add_argument("--timeout", type=int)
    auto.add_argument("--raw", action="store_true")
    auto.add_argument("--profile", default=None, help="Tencent profile or Aliyun site profile")
    auto.add_argument("--appid")
    auto.add_argument("--headless", default="auto")
    auto.add_argument("--chrome-path")

    solve = sub.add_parser("solve")
    solve_sub = solve.add_subparsers(dest="provider", required=True)
    _add_tencent_args(solve_sub.add_parser("tencent"))
    _add_aliyun_args(solve_sub.add_parser("aliyun"))
    _add_cloudflare_args(solve_sub.add_parser("cloudflare"))

    stress = sub.add_parser("stress")
    stress_sub = stress.add_subparsers(dest="provider", required=True)
    st = stress_sub.add_parser("tencent")
    _add_tencent_args(st)
    st.add_argument("--runs", type=int, default=5)
    st.add_argument("--concurrency", type=int, default=1)
    st.add_argument("--output-json")
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
        AliyunCaptchaSolver.install_js_deps()
        return 0
    if args.cmd == "diagnose":
        emit(
            {
                "node": shutil.which("node"),
                "npm": shutil.which("npm"),
                "chrome": discover_chrome(),
                "playwright_python": True,
                "aliyun_js_deps_installed": AliyunCaptchaSolver.js_deps_installed(),
                "cloudflare": BrowserAutomation.diagnose(),
            },
            include_raw=True,
        )
        return 0

    async with AntibotClient(browser_binary=getattr(args, "chrome_path", None)) as client:
        if args.cmd == "run":
            ret = await client.open(args.url, **_cloudflare_kwargs(args))
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "auto":
            provider = detect_provider_for_url(args.url) if args.provider == "auto" else args.provider
            if provider == "aliyun":
                ret = await client.solve_aliyun(
                    target_url=args.url,
                    chrome_path=args.chrome_path,
                    headless=_headless_any(args.headless),
                    proxy_server=args.proxy,
                    timeout_sec=args.timeout or 180,
                    site_profile=args.profile or "auto",
                )
            elif provider == "tencent":
                ret = await client.solve_tencent(
                    target_url=args.url,
                    profile=args.profile or "cloud_product",
                    appid=args.appid,
                    headless=_headless_bool(args.headless),
                    proxy_server=args.proxy,
                    timeout_sec=args.timeout,
                )
            elif provider == "cloudflare":
                ret = await client.solve_cloudflare(
                    target_url=args.url,
                    mode="auto",
                    headless=str(args.headless),
                    browser_binary=args.chrome_path,
                    proxy=args.proxy,
                    max_wait=args.timeout or 90,
                )
            else:
                ret = await client.solve_auto(args.url, provider=provider)
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "cloudflare":
            ret = await client.solve_cloudflare(args.target_url, **_cloudflare_kwargs(args))
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
                timeout_sec=args.timeout,
                verbose=args.verbose,
            )
            emit(ret, include_raw=args.raw)
            return 0 if ret.ok else 2

        if args.cmd == "solve" and args.provider == "aliyun":
            ret = await client.solve_aliyun(
                target_url=args.target_url,
                chrome_path=args.chrome_path,
                headless=_headless_any(args.headless),
                output_dir=args.output_dir,
                out=args.out,
                proxy_server=args.proxy,
                user_agent=args.user_agent,
                selectors=_kv(args.selector),
                site_profile=args.site_profile,
                profile=_json_arg(args.profile_json),
                env=_kv(args.env),
                verify_wait_ms=args.verify_wait_ms,
                captcha_wait_ms=args.captcha_wait_ms,
                max_attempts=args.max_attempts,
                timeout_sec=args.timeout or 180,
                cleanup_profile=not args.keep_profile,
                session_retries=args.session_retries,
                session_retry_delay_sec=args.session_retry_delay_sec,
                session_retry_max_attempts=args.session_retry_max_attempts,
            )
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
                    target_url=args.target_url,
                    chrome_path=args.chrome_path,
                    headless=_headless_any(args.headless),
                    output_dir=args.output_dir,
                    proxy_server=args.proxy,
                    user_agent=args.user_agent,
                    selectors=_kv(args.selector),
                    site_profile=args.site_profile,
                    profile=_json_arg(args.profile_json),
                    env=_kv(args.env),
                    verify_wait_ms=args.verify_wait_ms,
                    captcha_wait_ms=args.captcha_wait_ms,
                    max_attempts=args.max_attempts,
                    timeout_sec=args.timeout or 180,
                    cleanup_profile=not args.keep_profile,
                    session_retries=args.session_retries,
                    session_retry_delay_sec=args.session_retry_delay_sec,
                    session_retry_max_attempts=args.session_retry_max_attempts,
                ),
            )
            emit(payload if args.full else {"summary": payload["summary"]}, include_raw=True)
            return 0 if payload["summary"]["fail"] == 0 else 2

    return 1


def main() -> None:
    raise SystemExit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
