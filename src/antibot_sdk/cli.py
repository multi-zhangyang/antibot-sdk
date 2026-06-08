from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from .capabilities import list_capabilities
from .client import AntibotClient
from .profiles import list_profiles
from .providers.aliyun import AliyunCaptchaSolver
from .providers.browser import BrowserAutomation
from .stress import run_stress
from .verification import SubmitFlow, verify_submit_flow


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


def _load_token(path: str | None) -> str | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return (
            data.get("token")
            or data.get("ticket")
            or data.get("randstr")
            or (data.get("raw") or {}).get("token")
            or ((data.get("success") or {}).get("pass_token") if isinstance(data.get("success"), dict) else None)
        )
    return None


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
        "watchdog": raw.get("watchdog"),
        "watchdogEvents": raw.get("watchdogEvents"),
        "success": raw.get("success"),
        "token": raw.get("token"),
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

    sub.add_parser("profiles")
    sub.add_parser("capabilities")

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

    sub.add_parser("install-js-deps")

    auto = sub.add_parser("auto")
    auto.add_argument("url")
    auto.add_argument(
        "--provider",
        choices=[
            "auto",
            "ajcaptcha",
            "altcha",
            "aliyun",
            "tencent",
            "friendlycaptcha",
            "cap",
            "geetest",
            "yidun",
            "hcaptcha",
            "recaptcha",
            "turnstile",
            "cloudflare",
            "browser",
        ],
        default="auto",
    )
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

    aj = solve_sub.add_parser("ajcaptcha")
    aj.add_argument("--base-url", required=True, help="AJ-Captcha API prefix, e.g. http://host")
    aj.add_argument("--get-path", default="/captcha/get")
    aj.add_argument("--check-path", default="/captcha/check")
    aj.add_argument("--verify-path")
    aj.add_argument("--captcha-type", default="blockPuzzle")
    aj.add_argument("--client-uid")
    aj.add_argument("--canonical-width", type=int, default=310)
    aj.add_argument("--point-y", type=int, default=5)
    aj.add_argument("--timeout", type=int, default=20)
    aj.add_argument("--max-attempts", type=int, default=2)
    aj.add_argument("--proxy")
    aj.add_argument("--output-dir")
    aj.add_argument("--no-save-images", action="store_true")
    aj.add_argument("--min-score", type=float, default=0.15)
    aj.add_argument("--no-returned-point", action="store_true")
    aj.add_argument("--verify-after-check", action="store_true")
    aj.add_argument("--raw", action="store_true")

    alt = solve_sub.add_parser("altcha")
    alt_source = alt.add_mutually_exclusive_group(required=True)
    alt_source.add_argument("--challenge-url")
    alt_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    alt_source.add_argument("--challenge-file")
    alt_source.add_argument("--www-authenticate", help="M2M WWW-Authenticate: Altcha ... challenge")
    alt.add_argument("--default-maxnumber", type=int, default=1_000_000)
    alt.add_argument("--max-number", type=int)
    alt.add_argument("--start", type=int, default=0)
    alt.add_argument("--workers", type=int, default=1)
    alt.add_argument("--timeout", type=int, default=30)
    alt.add_argument("--proxy")
    alt.add_argument("--output-dir")
    alt.add_argument("--include-took", action="store_true")
    alt.add_argument("--mode", choices=["form", "m2m"], default="form")
    alt.add_argument("--raw", action="store_true")

    frc = solve_sub.add_parser("friendlycaptcha")
    frc_source = frc.add_mutually_exclusive_group(required=True)
    frc_source.add_argument("--puzzle", help="inline '<signature>.<puzzle_b64>', or @/path")
    frc_source.add_argument("--puzzle-file")
    frc_source.add_argument("--puzzle-url")
    frc.add_argument("--sitekey")
    frc.add_argument("--max-attempts-per-solution", type=int, default=10_000_000)
    frc.add_argument("--workers", type=int, default=1)
    frc.add_argument("--timeout", type=int, default=60)
    frc.add_argument("--proxy")
    frc.add_argument("--output-dir")
    frc.add_argument("--frc-client", default="js-0.9.19")
    frc.add_argument("--raw", action="store_true")

    cap = solve_sub.add_parser("cap")
    cap_source = cap.add_mutually_exclusive_group(required=True)
    cap_source.add_argument("--token", help="Cap seeded challenge token")
    cap_source.add_argument("--challenge-json", help="inline JSON object/list, or @/path/to/challenge.json")
    cap_source.add_argument("--challenge-file")
    cap_source.add_argument("--challenge-url")
    cap_source.add_argument("--api-endpoint", help="Cap API endpoint prefix; infers /challenge and /redeem")
    cap.add_argument("--c", type=int, default=50, help="seeded challenge count")
    cap.add_argument("--s", type=int, default=32, help="seeded salt size")
    cap.add_argument("--d", type=int, default=4, help="seeded difficulty hex-prefix length")
    cap.add_argument("--start", type=int, default=0)
    cap.add_argument("--max-attempts-per-challenge", type=int, default=10_000_000)
    cap.add_argument("--workers", type=int, default=1)
    cap.add_argument("--timeout", type=int, default=60)
    cap.add_argument("--proxy")
    cap.add_argument("--output-dir")
    cap.add_argument("--redeem-url")
    cap.add_argument("--redeem", action="store_true", help="POST solved body to /redeem and return final Cap token")
    cap.add_argument("--raw", action="store_true")

    gt = solve_sub.add_parser("geetest")
    gt.add_argument("--url", dest="target_url", required=True)
    gt.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    gt.add_argument("--headed", action="store_true")
    gt.add_argument("--proxy")
    gt.add_argument("--timeout", type=int, default=90)
    gt.add_argument("--output-dir")
    gt.add_argument("--trigger", action="append", default=[])
    gt.add_argument("--no-auto-trigger", action="store_true")
    gt.add_argument("--no-slide-solve", action="store_true")
    gt.add_argument("--slide-attempts", type=int, default=3)
    gt.add_argument("--browser-binary")
    gt.add_argument("--user-agent")
    gt.add_argument("--locale", default="zh-CN")
    gt.add_argument("--timezone", default="Asia/Shanghai")
    gt.add_argument("--raw", action="store_true")

    yd = solve_sub.add_parser("yidun")
    yd.add_argument("--url", dest="target_url", required=True)
    yd.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    yd.add_argument("--headed", action="store_true")
    yd.add_argument("--proxy")
    yd.add_argument("--timeout", type=int, default=90)
    yd.add_argument("--output-dir")
    yd.add_argument("--trigger", action="append", default=[])
    yd.add_argument("--no-auto-trigger", action="store_true")
    yd.add_argument("--no-slide-solve", action="store_true")
    yd.add_argument("--slide-attempts", type=int, default=3)
    yd.add_argument("--browser-binary")
    yd.add_argument("--user-agent")
    yd.add_argument("--locale", default="zh-CN")
    yd.add_argument("--timezone", default="Asia/Shanghai")
    yd.add_argument("--raw", action="store_true")

    ts = solve_sub.add_parser("turnstile")
    ts.add_argument("--url", dest="target_url", required=True)
    ts.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    ts.add_argument("--headed", action="store_true")
    ts.add_argument("--proxy")
    ts.add_argument("--timeout", type=int, default=90)
    ts.add_argument("--output-dir")
    ts.add_argument("--trigger", action="append", default=[])
    ts.add_argument("--no-auto-trigger", action="store_true")
    ts.add_argument("--browser-binary")
    ts.add_argument("--user-agent")
    ts.add_argument("--locale", default="en-US")
    ts.add_argument("--timezone", default="America/New_York")
    ts.add_argument("--raw", action="store_true")

    hc = solve_sub.add_parser("hcaptcha")
    hc.add_argument("--url", dest="target_url", required=True)
    hc.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    hc.add_argument("--headed", action="store_true")
    hc.add_argument("--proxy")
    hc.add_argument("--timeout", type=int, default=90)
    hc.add_argument("--output-dir")
    hc.add_argument("--trigger", action="append", default=[])
    hc.add_argument("--no-auto-trigger", action="store_true")
    hc.add_argument("--browser-binary")
    hc.add_argument("--user-agent")
    hc.add_argument("--locale", default="en-US")
    hc.add_argument("--timezone", default="America/New_York")
    hc.add_argument("--raw", action="store_true")

    rc = solve_sub.add_parser("recaptcha")
    rc.add_argument("--url", dest="target_url", required=True)
    rc.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    rc.add_argument("--headed", action="store_true")
    rc.add_argument("--proxy")
    rc.add_argument("--timeout", type=int, default=90)
    rc.add_argument("--output-dir")
    rc.add_argument("--trigger", action="append", default=[])
    rc.add_argument("--no-auto-trigger", action="store_true")
    rc.add_argument("--browser-binary")
    rc.add_argument("--user-agent")
    rc.add_argument("--locale", default="en-US")
    rc.add_argument("--timezone", default="America/New_York")
    rc.add_argument("--raw", action="store_true")

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

    saj = stress_sub.add_parser("ajcaptcha")
    saj.add_argument("--base-url", required=True)
    saj.add_argument("--get-path", default="/captcha/get")
    saj.add_argument("--check-path", default="/captcha/check")
    saj.add_argument("--captcha-type", default="blockPuzzle")
    saj.add_argument("--runs", type=int, default=10)
    saj.add_argument("--concurrency", type=int, default=2)
    saj.add_argument("--timeout", type=int, default=20)
    saj.add_argument("--max-attempts", type=int, default=2)
    saj.add_argument("--proxy")
    saj.add_argument("--output-dir")
    saj.add_argument("--min-score", type=float, default=0.15)
    saj.add_argument("--output-json")
    saj.add_argument("--full", action="store_true")

    salt = stress_sub.add_parser("altcha")
    salt.add_argument("--challenge-url", required=True)
    salt.add_argument("--runs", type=int, default=10)
    salt.add_argument("--concurrency", type=int, default=2)
    salt.add_argument("--timeout", type=int, default=30)
    salt.add_argument("--max-number", type=int)
    salt.add_argument("--workers", type=int, default=1)
    salt.add_argument("--proxy")
    salt.add_argument("--output-dir")
    salt.add_argument("--output-json")
    salt.add_argument("--full", action="store_true")

    sfrc = stress_sub.add_parser("friendlycaptcha")
    sfrc.add_argument("--puzzle-url", required=True)
    sfrc.add_argument("--sitekey")
    sfrc.add_argument("--runs", type=int, default=10)
    sfrc.add_argument("--concurrency", type=int, default=2)
    sfrc.add_argument("--timeout", type=int, default=60)
    sfrc.add_argument("--max-attempts-per-solution", type=int, default=10_000_000)
    sfrc.add_argument("--workers", type=int, default=1)
    sfrc.add_argument("--proxy")
    sfrc.add_argument("--output-dir")
    sfrc.add_argument("--output-json")
    sfrc.add_argument("--full", action="store_true")

    scap = stress_sub.add_parser("cap")
    scap_source = scap.add_mutually_exclusive_group(required=True)
    scap_source.add_argument("--challenge-url")
    scap_source.add_argument("--api-endpoint", help="Cap API endpoint prefix; infers /challenge and /redeem")
    scap.add_argument("--runs", type=int, default=10)
    scap.add_argument("--concurrency", type=int, default=2)
    scap.add_argument("--timeout", type=int, default=60)
    scap.add_argument("--max-attempts-per-challenge", type=int, default=10_000_000)
    scap.add_argument("--workers", type=int, default=1)
    scap.add_argument("--proxy")
    scap.add_argument("--redeem-url")
    scap.add_argument("--redeem", action="store_true")
    scap.add_argument("--output-dir")
    scap.add_argument("--output-json")
    scap.add_argument("--full", action="store_true")

    sg = stress_sub.add_parser("geetest")
    sg.add_argument("--url", dest="target_url", required=True)
    sg.add_argument("--runs", type=int, default=3)
    sg.add_argument("--concurrency", type=int, default=1)
    sg.add_argument("--timeout", type=int, default=90)
    sg.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    sg.add_argument("--headed", action="store_true")
    sg.add_argument("--proxy")
    sg.add_argument("--trigger", action="append", default=[])
    sg.add_argument("--no-auto-trigger", action="store_true")
    sg.add_argument("--no-slide-solve", action="store_true")
    sg.add_argument("--slide-attempts", type=int, default=3)
    sg.add_argument("--output-dir")
    sg.add_argument("--output-json")
    sg.add_argument("--full", action="store_true")

    sy = stress_sub.add_parser("yidun")
    sy.add_argument("--url", dest="target_url", required=True)
    sy.add_argument("--runs", type=int, default=3)
    sy.add_argument("--concurrency", type=int, default=1)
    sy.add_argument("--timeout", type=int, default=90)
    sy.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    sy.add_argument("--headed", action="store_true")
    sy.add_argument("--proxy")
    sy.add_argument("--trigger", action="append", default=[])
    sy.add_argument("--no-auto-trigger", action="store_true")
    sy.add_argument("--no-slide-solve", action="store_true")
    sy.add_argument("--slide-attempts", type=int, default=3)
    sy.add_argument("--output-dir")
    sy.add_argument("--output-json")
    sy.add_argument("--full", action="store_true")

    sts = stress_sub.add_parser("turnstile")
    sts.add_argument("--url", dest="target_url", required=True)
    sts.add_argument("--runs", type=int, default=3)
    sts.add_argument("--concurrency", type=int, default=1)
    sts.add_argument("--timeout", type=int, default=90)
    sts.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    sts.add_argument("--headed", action="store_true")
    sts.add_argument("--proxy")
    sts.add_argument("--trigger", action="append", default=[])
    sts.add_argument("--no-auto-trigger", action="store_true")
    sts.add_argument("--output-dir")
    sts.add_argument("--output-json")
    sts.add_argument("--full", action="store_true")

    shc = stress_sub.add_parser("hcaptcha")
    shc.add_argument("--url", dest="target_url", required=True)
    shc.add_argument("--runs", type=int, default=3)
    shc.add_argument("--concurrency", type=int, default=1)
    shc.add_argument("--timeout", type=int, default=90)
    shc.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    shc.add_argument("--headed", action="store_true")
    shc.add_argument("--proxy")
    shc.add_argument("--trigger", action="append", default=[])
    shc.add_argument("--no-auto-trigger", action="store_true")
    shc.add_argument("--output-dir")
    shc.add_argument("--output-json")
    shc.add_argument("--full", action="store_true")

    src = stress_sub.add_parser("recaptcha")
    src.add_argument("--url", dest="target_url", required=True)
    src.add_argument("--runs", type=int, default=3)
    src.add_argument("--concurrency", type=int, default=1)
    src.add_argument("--timeout", type=int, default=90)
    src.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
    src.add_argument("--headed", action="store_true")
    src.add_argument("--proxy")
    src.add_argument("--trigger", action="append", default=[])
    src.add_argument("--no-auto-trigger", action="store_true")
    src.add_argument("--output-dir")
    src.add_argument("--output-json")
    src.add_argument("--full", action="store_true")

    verify = sub.add_parser("verify")
    verify_sub = verify.add_subparsers(dest="provider", required=True)
    for provider_name in ("recaptcha", "hcaptcha", "turnstile"):
        vf = verify_sub.add_parser(provider_name)
        vf.add_argument("--url", required=True)
        vf.add_argument("--token")
        vf.add_argument("--captcha-json", help="read token from a previous solve artifact/result JSON")
        vf.add_argument("--token-field")
        vf.add_argument("--token-selector")
        vf.add_argument("--submit", dest="submit_selector")
        vf.add_argument("--success", dest="success_selector")
        vf.add_argument("--failure", dest="failure_selector")
        vf.add_argument("--expected-url-contains")
        vf.add_argument("--prefill", action="append", default=[], help="CSS_SELECTOR=VALUE before submit")
        vf.add_argument("--click", action="append", default=[], help="CSS selector to click before token injection")
        vf.add_argument("--wait-after-submit-ms", type=int, default=2000)
        vf.add_argument("--timeout", type=int, default=60)
        vf.add_argument("--output-dir")
        vf.add_argument("--headless", default="auto", choices=["auto", "true", "false"])
        vf.add_argument("--headed", action="store_true")
        vf.add_argument("--proxy")
        vf.add_argument("--browser-binary")
        vf.add_argument("--user-agent")
        vf.add_argument("--locale", default="en-US")
        vf.add_argument("--timezone", default="America/New_York")
        vf.add_argument("--raw", action="store_true")

    args = p.parse_args(argv)
    if args.cmd == "diagnose":
        emit(BrowserAutomation.diagnose(args.browser_binary))
        return 0
    if args.cmd == "profiles":
        emit(list_profiles())
        return 0
    if args.cmd == "capabilities":
        emit(list_capabilities())
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
        if provider in (None, "aliyun", "geetest", "yidun", "hcaptcha", "recaptcha", "turnstile", "cap"):
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
    if args.cmd == "verify":
        headless = False if args.headed else _headless(args.headless)
        token = args.token or _load_token(args.captcha_json)
        ret = await verify_submit_flow(
            SubmitFlow(
                provider=args.provider,
                url=args.url,
                token=token,
                token_field=args.token_field,
                token_value_selector=args.token_selector,
                submit_selector=args.submit_selector,
                success_selector=args.success_selector,
                failure_selector=args.failure_selector,
                expected_url_contains=args.expected_url_contains,
                prefill=_kv(args.prefill),
                clicks=args.click,
                wait_after_submit_ms=args.wait_after_submit_ms,
                timeout_sec=args.timeout,
                output_dir=args.output_dir,
                headless=headless,
                proxy_server=args.proxy,
                browser_binary=args.browser_binary,
                user_agent=args.user_agent,
                locale=args.locale,
                timezone_id=args.timezone,
            )
        )
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
    if args.cmd == "solve" and args.provider == "ajcaptcha":
        ret = await client.solve_ajcaptcha(
            base_url=args.base_url,
            get_path=args.get_path,
            check_path=args.check_path,
            verify_path=args.verify_path,
            captcha_type=args.captcha_type,
            client_uid=args.client_uid,
            canonical_width=args.canonical_width,
            point_y=args.point_y,
            timeout_sec=args.timeout,
            max_attempts=args.max_attempts,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            save_images=not args.no_save_images,
            min_score=args.min_score,
            use_returned_point=not args.no_returned_point,
            verify_after_check=args.verify_after_check,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "altcha":
        ret = await client.solve_altcha(
            challenge_url=args.challenge_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            www_authenticate=args.www_authenticate,
            default_maxnumber=args.default_maxnumber,
            max_number=args.max_number,
            start=args.start,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            include_took=args.include_took,
            mode=args.mode,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "friendlycaptcha":
        ret = await client.solve_friendlycaptcha(
            puzzle=args.puzzle,
            puzzle_file=args.puzzle_file,
            puzzle_url=args.puzzle_url,
            sitekey=args.sitekey,
            max_attempts_per_solution=args.max_attempts_per_solution,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            frc_client=args.frc_client,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "cap":
        ret = await client.solve_cap(
            token=args.token,
            c=args.c,
            s=args.s,
            d=args.d,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            api_endpoint=args.api_endpoint,
            redeem_url=args.redeem_url,
            redeem=args.redeem,
            start=args.start,
            max_attempts_per_challenge=args.max_attempts_per_challenge,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "geetest":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_geetest(
            target_url=args.target_url,
            headless=headless,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            output_dir=args.output_dir,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                slide_solve=not args.no_slide_solve,
                slide_max_attempts=args.slide_attempts,
                browser_binary=args.browser_binary,
                user_agent=args.user_agent,
                locale=args.locale,
            timezone_id=args.timezone,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "yidun":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_yidun(
            target_url=args.target_url,
            headless=headless,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            output_dir=args.output_dir,
            trigger_selectors=args.trigger or None,
            auto_trigger=not args.no_auto_trigger,
            slide_solve=not args.no_slide_solve,
            slide_max_attempts=args.slide_attempts,
            browser_binary=args.browser_binary,
            user_agent=args.user_agent,
            locale=args.locale,
            timezone_id=args.timezone,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "turnstile":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_turnstile(
            target_url=args.target_url,
            headless=headless,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            output_dir=args.output_dir,
            trigger_selectors=args.trigger or None,
            auto_trigger=not args.no_auto_trigger,
            browser_binary=args.browser_binary,
            user_agent=args.user_agent,
            locale=args.locale,
            timezone_id=args.timezone,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "hcaptcha":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_hcaptcha(
            target_url=args.target_url,
            headless=headless,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            output_dir=args.output_dir,
            trigger_selectors=args.trigger or None,
            auto_trigger=not args.no_auto_trigger,
            browser_binary=args.browser_binary,
            user_agent=args.user_agent,
            locale=args.locale,
            timezone_id=args.timezone,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "recaptcha":
        headless = False if args.headed else _headless(args.headless)
        ret = await client.solve_recaptcha(
            target_url=args.target_url,
            headless=headless,
            proxy_server=args.proxy,
            timeout_sec=args.timeout,
            output_dir=args.output_dir,
            trigger_selectors=args.trigger or None,
            auto_trigger=not args.no_auto_trigger,
            browser_binary=args.browser_binary,
            user_agent=args.user_agent,
            locale=args.locale,
            timezone_id=args.timezone,
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
    if args.cmd == "stress" and args.provider == "ajcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="ajcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_ajcaptcha(
                base_url=args.base_url,
                get_path=args.get_path,
                check_path=args.check_path,
                captcha_type=args.captcha_type,
                timeout_sec=args.timeout,
                max_attempts=args.max_attempts,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                min_score=args.min_score,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "altcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="altcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_altcha(
                challenge_url=args.challenge_url,
                max_number=args.max_number,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "friendlycaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="friendlycaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_friendlycaptcha(
                puzzle_url=args.puzzle_url,
                sitekey=args.sitekey,
                max_attempts_per_solution=args.max_attempts_per_solution,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "cap":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="cap",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_cap(
                challenge_url=args.challenge_url,
                api_endpoint=args.api_endpoint,
                redeem_url=args.redeem_url,
                redeem=args.redeem,
                max_attempts_per_challenge=args.max_attempts_per_challenge,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "geetest":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        ret = await run_stress(
            name="geetest",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 20,
            output_json=args.output_json,
            run_once=lambda i: client.solve_geetest(
                target_url=args.target_url,
                headless=headless,
                proxy_server=args.proxy,
                timeout_sec=args.timeout,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                slide_solve=not args.no_slide_solve,
                slide_max_attempts=args.slide_attempts,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "yidun":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        ret = await run_stress(
            name="yidun",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 20,
            output_json=args.output_json,
            run_once=lambda i: client.solve_yidun(
                target_url=args.target_url,
                headless=headless,
                proxy_server=args.proxy,
                timeout_sec=args.timeout,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                slide_solve=not args.no_slide_solve,
                slide_max_attempts=args.slide_attempts,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "turnstile":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        ret = await run_stress(
            name="turnstile",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 20,
            output_json=args.output_json,
            run_once=lambda i: client.solve_turnstile(
                target_url=args.target_url,
                headless=headless,
                proxy_server=args.proxy,
                timeout_sec=args.timeout,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "hcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        ret = await run_stress(
            name="hcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 20,
            output_json=args.output_json,
            run_once=lambda i: client.solve_hcaptcha(
                target_url=args.target_url,
                headless=headless,
                proxy_server=args.proxy,
                timeout_sec=args.timeout,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "recaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        headless = False if args.headed else _headless(args.headless)
        ret = await run_stress(
            name="recaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 20,
            output_json=args.output_json,
            run_once=lambda i: client.solve_recaptcha(
                target_url=args.target_url,
                headless=headless,
                proxy_server=args.proxy,
                timeout_sec=args.timeout,
                trigger_selectors=args.trigger or None,
                auto_trigger=not args.no_auto_trigger,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    return 1


def main() -> None:
    raise SystemExit(asyncio.run(amain()))
