from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from .client import AntibotClient
from .profiles import list_profiles
from .providers.aliyun import AliyunCaptchaSolver
from .providers.browser import BrowserAutomation
from .stress import run_stress


def _selector(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit("--selector must be key=selector")
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _kv(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit("expected KEY=VALUE")
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _headless(value: str):
    if value in ("", "auto", None):
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    return value


def _compact_raw(raw):
    if not isinstance(raw, dict) or not raw:
        return raw
    keep = {
        "ok": raw.get("ok"),
        "verifyResponse": raw.get("verifyResponse"),
        "verifyFailureCode": raw.get("verifyFailureCode"),
        "attempt": raw.get("attempt"),
        "maxAttempts": raw.get("maxAttempts"),
        "attempts": raw.get("attempts"),
        "candidate": raw.get("candidate"),
        "finalSolve": raw.get("finalSolve"),
        "retryHint": raw.get("retryHint"),
    }
    return {k: v for k, v in keep.items() if v not in (None, "", [], {})}


def emit(obj, *, include_raw: bool = False) -> None:
    data = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
    if isinstance(data, dict) and not include_raw and "raw" in data:
        data["raw"] = _compact_raw(data.get("raw"))
    print(json.dumps(data, ensure_ascii=False, indent=2))


def emit_stress(payload: dict, *, full: bool = False) -> None:
    emit(payload if full else {"summary": payload.get("summary", {})})


async def amain(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="antibot")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("diagnose")
    d.add_argument("--browser-binary")

    profs = sub.add_parser("profiles")

    run = sub.add_parser("run")
    run.add_argument("url")
    run.add_argument("--mode", default="auto", choices=["auto", "turnstile", "managed", "scrape"])
    run.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    run.add_argument("--selector", action="append", default=[])
    run.add_argument("--click", action="append", default=[])
    run.add_argument("--screenshot")
    run.add_argument("--html-output")
    run.add_argument("--output-json")
    run.add_argument("--proxy")
    run.add_argument("--max-wait", type=int, default=90)
    run.add_argument("--browser-binary")
    run.add_argument("--user-agent")
    run.add_argument("--platform")
    run.add_argument("--raw", action="store_true")

    inst = sub.add_parser("install-js-deps")

    auto = sub.add_parser("auto")
    auto.add_argument("url")
    auto.add_argument("--provider", choices=["auto", "aliyun", "tencent", "cloudflare", "browser"], default="auto")
    auto.add_argument("--headless", default="auto", choices=["auto", "new", "true", "false"])
    auto.add_argument("--headed", action="store_true")
    auto.add_argument("--site-profile", default="auto")
    auto.add_argument("--profile")
    auto.add_argument("--appid")
    auto.add_argument("--output-dir")
    auto.add_argument("--out")
    auto.add_argument("--proxy")
    auto.add_argument("--timeout", type=int, default=180)
    auto.add_argument("--selector", action="append", default=[])
    auto.add_argument("--raw", action="store_true")

    solve = sub.add_parser("solve")
    solve_sub = solve.add_subparsers(dest="provider", required=True)
    ten = solve_sub.add_parser("tencent")
    ten.add_argument("--url", dest="target_url")
    ten.add_argument("--profile", default="cloud_product")
    ten.add_argument("--appid")
    ten.add_argument("--headless", action="store_true", default=False)
    ten.add_argument("--headed", action="store_true", default=False)
    ten.add_argument("--proxy")
    ten.add_argument("--timeout", type=int)
    ten.add_argument("--verbose", action="store_true")
    ten.add_argument("--raw", action="store_true")

    ali = solve_sub.add_parser("aliyun")
    ali.add_argument("--url", dest="target_url", required=True)
    ali.add_argument("--chrome-path")
    ali.add_argument("--headless", default="auto", choices=["auto", "new", "true", "false"])
    ali.add_argument("--headed", action="store_true")
    ali.add_argument("--site-profile", default="auto")
    ali.add_argument("--output-dir")
    ali.add_argument("--out")
    ali.add_argument("--proxy")
    ali.add_argument("--selector", action="append", default=[])
    ali.add_argument("--env", action="append", default=[])
    ali.add_argument("--max-attempts", type=int)
    ali.add_argument("--captcha-wait-ms", type=int)
    ali.add_argument("--verify-wait-ms", type=int)
    ali.add_argument("--timeout", type=int, default=180)
    ali.add_argument("--session-retries", type=int)
    ali.add_argument("--session-retry-delay", type=float)
    ali.add_argument("--session-retry-max-attempts", type=int)
    ali.add_argument("--raw", action="store_true")

    stress = sub.add_parser("stress")
    stress_sub = stress.add_subparsers(dest="provider", required=True)

    sb = stress_sub.add_parser("browser")
    sb.add_argument("url")
    sb.add_argument("--runs", type=int, default=5)
    sb.add_argument("--concurrency", type=int, default=2)
    sb.add_argument("--timeout", type=int, default=30)
    sb.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    sb.add_argument("--selector", action="append", default=[])
    sb.add_argument("--max-wait", type=int, default=8)
    sb.add_argument("--output-json")
    sb.add_argument("--full", action="store_true")

    st = stress_sub.add_parser("tencent")
    st.add_argument("--url", dest="target_url")
    st.add_argument("--profile", default="cloud_product")
    st.add_argument("--appid")
    st.add_argument("--runs", type=int, default=5)
    st.add_argument("--concurrency", type=int, default=1)
    st.add_argument("--timeout", type=int, default=120)
    st.add_argument("--headed", action="store_true")
    st.add_argument("--proxy")
    st.add_argument("--pool-size", type=int)
    st.add_argument("--browser-max-uses", type=int, default=1)
    st.add_argument("--isolated", action="store_true", help="disable shared BrowserPool; start/stop a pool per run")
    st.add_argument("--output-json")
    st.add_argument("--full", action="store_true")

    sa = stress_sub.add_parser("aliyun")
    sa.add_argument("--url", dest="target_url", required=True)
    sa.add_argument("--site-profile", default="auto")
    sa.add_argument("--runs", type=int, default=3)
    sa.add_argument("--concurrency", type=int, default=1)
    sa.add_argument("--timeout", type=int, default=220)
    sa.add_argument("--max-attempts", type=int)
    sa.add_argument("--headless", default="auto", choices=["auto", "new", "true", "false"])
    sa.add_argument("--headed", action="store_true")
    sa.add_argument("--proxy")
    sa.add_argument("--env", action="append", default=[])
    sa.add_argument("--session-retries", type=int)
    sa.add_argument("--session-retry-delay", type=float)
    sa.add_argument("--session-retry-max-attempts", type=int)
    sa.add_argument("--output-dir")
    sa.add_argument("--output-json")
    sa.add_argument("--full", action="store_true")

    args = p.parse_args(argv)
    if args.cmd == "diagnose":
        emit(BrowserAutomation.diagnose(args.browser_binary))
        return 0
    if args.cmd == "profiles":
        emit(list_profiles())
        return 0
    if args.cmd == "install-js-deps":
        AliyunCaptchaSolver.install_js_deps()
        return 0
    client = AntibotClient(browser_binary=getattr(args, "browser_binary", None))
    if args.cmd == "run":
        ret = await client.open(
            args.url,
            mode=args.mode,
            headless=args.headless,
            selectors=_selector(args.selector),
            clicks=args.click,
            screenshot=args.screenshot,
            html_output=args.html_output,
            output_json=args.output_json,
            proxy=args.proxy,
            max_wait=args.max_wait,
            user_agent=args.user_agent,
            platform=args.platform,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "auto":
        provider = None if args.provider == "auto" else args.provider
        headless = False if args.headed else _headless(args.headless)
        common = {
            "proxy_server": args.proxy,
            "headless": headless,
        }
        if provider in (None, "aliyun"):
            common.update({
                "site_profile": args.site_profile,
                "output_dir": args.output_dir,
                "out": args.out,
                "timeout_sec": args.timeout,
                "selectors": _selector(args.selector),
            })
        if provider == "tencent":
            common.update({"profile": args.profile, "appid": args.appid})
        ret = await client.solve_auto(args.url, provider=provider, **common)
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "tencent":
        ret = await client.solve_tencent(
            target_url=args.target_url,
            profile=args.profile,
            appid=args.appid,
            headless=not args.headed if not args.headless else True,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            verbose=args.verbose,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "aliyun":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_aliyun(
            target_url=args.target_url,
            chrome_path=args.chrome_path,
            headless=headless,
            site_profile=args.site_profile,
            output_dir=args.output_dir,
            out=args.out,
            proxy_server=args.proxy,
            selectors=_selector(args.selector),
            env=_kv(args.env),
            max_attempts=args.max_attempts,
            captcha_wait_ms=args.captcha_wait_ms,
            verify_wait_ms=args.verify_wait_ms,
            timeout_sec=args.timeout,
            session_retries=args.session_retries,
            session_retry_delay_sec=args.session_retry_delay,
            session_retry_max_attempts=args.session_retry_max_attempts,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "stress" and args.provider == "browser":
        ret = await run_stress(
            name="browser",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout,
            output_json=args.output_json,
            run_once=lambda i: client.open(
                args.url,
                headless=args.headless,
                selectors=_selector(args.selector),
                max_wait=args.max_wait,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "tencent":
        if args.isolated:
            ret = await run_stress(
                name="tencent",
                runs=args.runs,
                concurrency=args.concurrency,
                per_run_timeout=args.timeout + 30,
                output_json=args.output_json,
                run_once=lambda i: client.solve_tencent(
                    target_url=args.target_url,
                    profile=args.profile,
                    appid=args.appid,
                    headless=not args.headed,
                    proxy_server=args.proxy,
                    pool_size=args.pool_size or 1,
                    browser_max_uses=args.browser_max_uses,
                    timeout_sec=args.timeout,
                ),
            )
        else:
            pool_size = args.pool_size or args.concurrency
            pool, prof = client.tencent.create_pool(
                target_url=args.target_url,
                profile=args.profile,
                headless=not args.headed,
                proxy_server=args.proxy,
                pool_size=pool_size,
                browser_max_uses=args.browser_max_uses,
            )
            await pool.start()
            try:
                ret = await run_stress(
                    name="tencent",
                    runs=args.runs,
                    concurrency=args.concurrency,
                    per_run_timeout=args.timeout + 20,
                    output_json=args.output_json,
                    run_once=lambda i: client.tencent.solve_with_pool(
                        pool,
                        target_url=args.target_url,
                        profile=args.profile,
                        appid=args.appid,
                        prof=prof,
                        headless=not args.headed,
                        pool_size=pool_size,
                        browser_max_uses=args.browser_max_uses,
                        proxy_server=args.proxy,
                        timeout_sec=args.timeout,
                    ),
                )
            finally:
                await pool.stop()
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "aliyun":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        retry_budget = args.session_retries if args.session_retries is not None else 1
        ret = await run_stress(
            name="aliyun",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout * (1 + max(0, retry_budget)) + 90,
            output_json=args.output_json,
            run_once=lambda i: client.solve_aliyun(
                target_url=args.target_url,
                site_profile=args.site_profile,
                headless=headless,
                proxy_server=args.proxy,
                env=_kv(args.env),
                max_attempts=args.max_attempts,
                session_retries=args.session_retries,
                session_retry_delay_sec=args.session_retry_delay,
                session_retry_max_attempts=args.session_retry_max_attempts,
                output_dir=str(root / f"run_{i}") if root else None,
                timeout_sec=args.timeout,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    return 1


def main() -> None:
    raise SystemExit(asyncio.run(amain()))
