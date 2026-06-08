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
            "anubis",
            "aliyun",
            "tencent",
            "friendlycaptcha",
            "cap",
            "mcaptcha",
            "pcaptcha",
            "powcaptcha",
            "privatecaptcha",
            "portcullis",
            "wicketkeeper",
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

    anu = solve_sub.add_parser("anubis")
    anu_source = anu.add_mutually_exclusive_group(required=True)
    anu_source.add_argument("--challenge", help="inline Anubis randomData, JSON object, or challenge HTML")
    anu_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    anu_source.add_argument("--challenge-file")
    anu_source.add_argument("--challenge-url", help="Anubis make-challenge JSON endpoint")
    anu_source.add_argument("--page-url", help="Anubis challenge page with anubis_challenge JSONScript")
    anu_source.add_argument("--base-url", help="target base URL; infers Anubis API endpoints")
    anu.add_argument("--pass-url")
    anu.add_argument("--redir", default="/")
    anu.add_argument("--difficulty", type=int)
    anu.add_argument("--algorithm", default="fast")
    anu.add_argument("--start", type=int, default=0)
    anu.add_argument("--max-attempts", type=int, default=50_000_000)
    anu.add_argument("--workers", type=int, default=1)
    anu.add_argument("--timeout", type=int, default=30)
    anu.add_argument("--submit", action="store_true", help="GET pass-challenge and return auth cookie when available")
    anu.add_argument("--no-ensure-test-cookie", action="store_true")
    anu.add_argument("--proxy")
    anu.add_argument("--output-dir")
    anu.add_argument("--raw", action="store_true")

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

    mc = solve_sub.add_parser("mcaptcha")
    mc_source = mc.add_mutually_exclusive_group(required=True)
    mc_source.add_argument("--config-json", help="inline JSON object, or @/path/to/config.json")
    mc_source.add_argument("--config-file")
    mc_source.add_argument("--config-url", help="mCaptcha /api/v1/pow/config endpoint")
    mc_source.add_argument("--base-url", help="mCaptcha instance root; infers /api/v1/pow/{config,verify}")
    mc.add_argument("--sitekey", "--key", dest="sitekey", help="mCaptcha sitekey/key")
    mc.add_argument("--verify-url", help="mCaptcha /api/v1/pow/verify endpoint")
    mc.add_argument("--no-submit", action="store_true", help="only return the solved verify body")
    mc.add_argument("--siteverify-url", help="mCaptcha /api/v1/pow/siteverify endpoint")
    mc.add_argument("--siteverify", action="store_true", help="POST token+secret to siteverify")
    mc.add_argument("--secret")
    mc.add_argument("--start", type=int, default=1)
    mc.add_argument("--max-attempts", type=int, default=50_000_000)
    mc.add_argument("--workers", type=int, default=1)
    mc.add_argument("--timeout", type=int, default=60)
    mc.add_argument("--proxy")
    mc.add_argument("--output-dir")
    mc.add_argument("--raw", action="store_true")

    pc = solve_sub.add_parser("pcaptcha")
    pc_source = pc.add_mutually_exclusive_group(required=True)
    pc_source.add_argument("--challenge", help="inline P-Captcha raw challenge")
    pc_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    pc_source.add_argument("--challenge-file")
    pc_source.add_argument("--challenge-url")
    pc.add_argument("--id", dest="challenge_id", help="challenge id when the endpoint does not include it")
    pc.add_argument("--validate-url")
    pc.add_argument("--validate", action="store_true", help="POST {id, answer} to --validate-url")
    pc.add_argument("--timeout", type=int, default=30)
    pc.add_argument("--proxy")
    pc.add_argument("--output-dir")
    pc.add_argument("--raw", action="store_true")

    powc = solve_sub.add_parser("powcaptcha")
    powc_source = powc.add_mutually_exclusive_group(required=True)
    powc_source.add_argument("--quiz", help="inline raw/base64/hex quiz")
    powc_source.add_argument("--quiz-b64")
    powc_source.add_argument("--quiz-hex")
    powc_source.add_argument("--quiz-file")
    powc_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    powc_source.add_argument("--challenge-file")
    powc_source.add_argument("--challenge-url")
    powc.add_argument("--id", dest="challenge_id", help="challenge id when the endpoint does not include it")
    powc.add_argument("--verify-url", help="POST solved answer to verification endpoint")
    powc.add_argument("--submit", action="store_true", help="POST solution.submit_body to --verify-url")
    powc.add_argument("--start", type=int, default=0)
    powc.add_argument("--max-attempts", type=int, default=50_000_000)
    powc.add_argument("--workers", type=int, default=1)
    powc.add_argument("--timeout", type=int, default=60)
    powc.add_argument("--proxy")
    powc.add_argument("--output-dir")
    powc.add_argument("--raw", action="store_true")

    priv = solve_sub.add_parser("privatecaptcha")
    priv_source = priv.add_mutually_exclusive_group(required=True)
    priv_source.add_argument("--puzzle", help="inline '<puzzle_b64>.<signature_b64>'")
    priv_source.add_argument("--puzzle-file")
    priv_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    priv_source.add_argument("--challenge-file")
    priv_source.add_argument("--challenge-url")
    priv_source.add_argument("--puzzle-url", help="PrivateCaptcha /puzzle endpoint")
    priv.add_argument("--sitekey", help="sitekey used when fetching /puzzle")
    priv.add_argument("--verify-url", help="PrivateCaptcha /verify endpoint; POST raw widget payload")
    priv.add_argument("--siteverify-url", help="reCAPTCHA-compatible /siteverify endpoint; POST form response/secret")
    priv.add_argument("--submit", action="store_true")
    priv.add_argument("--api-key", help="X-API-Key for /verify")
    priv.add_argument("--secret", help="secret for /siteverify")
    priv.add_argument("--start", type=int, default=0)
    priv.add_argument("--max-attempts-per-solution", type=int, default=50_000_000)
    priv.add_argument("--workers", type=int, default=1)
    priv.add_argument("--timeout", type=int, default=60)
    priv.add_argument("--proxy")
    priv.add_argument("--output-dir")
    priv.add_argument("--raw", action="store_true")

    port = solve_sub.add_parser("portcullis")
    port_source = port.add_mutually_exclusive_group(required=True)
    port_source.add_argument("--challenge", help="inline challenge JSON or full challenge response")
    port_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    port_source.add_argument("--challenge-file")
    port_source.add_argument("--challenge-url", help="Portcullis /api/v1/challenge endpoint")
    port_source.add_argument("--base-url", help="Portcullis instance root; infers /api/v1/{challenge,verify}")
    port.add_argument("--sitekey", help="site_key used when fetching challenge")
    port.add_argument("--sig", help="challenge signature when --challenge only contains challenge object")
    port.add_argument("--verify-url", help="Portcullis /api/v1/verify endpoint")
    port.add_argument("--siteverify-url", help="Portcullis /api/v1/siteverify endpoint")
    port.add_argument("--submit", action="store_true", help="POST solved body to --verify-url/base-url")
    port.add_argument("--secret-key", help="siteverify secret_key")
    port.add_argument("--client-ip")
    port.add_argument("--user-agent")
    port.add_argument("--start", type=int, default=0)
    port.add_argument("--max-iters", type=int, default=10_000_000)
    port.add_argument("--workers", type=int, default=1)
    port.add_argument("--timeout", type=int, default=60)
    port.add_argument("--proxy")
    port.add_argument("--output-dir")
    port.add_argument("--raw", action="store_true")

    wk = solve_sub.add_parser("wicketkeeper")
    wk_source = wk.add_mutually_exclusive_group(required=True)
    wk_source.add_argument("--challenge", help="inline challenge/cid")
    wk_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    wk_source.add_argument("--challenge-file")
    wk_source.add_argument("--challenge-url", help="Wicketkeeper /v0/challenge endpoint")
    wk_source.add_argument("--base-url", help="Wicketkeeper instance root; infers /v0/{challenge,siteverify}")
    wk.add_argument("--difficulty", type=int)
    wk.add_argument("--token", help="challenge JWT when using --challenge")
    wk.add_argument("--siteverify-url", help="Wicketkeeper /v0/siteverify endpoint")
    wk.add_argument("--no-submit", action="store_true", help="only return the solved hidden-input JSON")
    wk.add_argument("--start", type=int, default=0)
    wk.add_argument("--max-attempts", type=int, default=50_000_000)
    wk.add_argument("--workers", type=int, default=1)
    wk.add_argument("--timeout", type=int, default=60)
    wk.add_argument("--proxy")
    wk.add_argument("--output-dir")
    wk.add_argument("--raw", action="store_true")

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

    sanu = stress_sub.add_parser("anubis")
    sanu_source = sanu.add_mutually_exclusive_group(required=True)
    sanu_source.add_argument("--challenge-url")
    sanu_source.add_argument("--page-url")
    sanu_source.add_argument("--base-url")
    sanu.add_argument("--pass-url")
    sanu.add_argument("--redir", default="/")
    sanu.add_argument("--difficulty", type=int)
    sanu.add_argument("--algorithm", default="fast")
    sanu.add_argument("--runs", type=int, default=10)
    sanu.add_argument("--concurrency", type=int, default=2)
    sanu.add_argument("--timeout", type=int, default=30)
    sanu.add_argument("--max-attempts", type=int, default=50_000_000)
    sanu.add_argument("--workers", type=int, default=1)
    sanu.add_argument("--submit", action="store_true")
    sanu.add_argument("--proxy")
    sanu.add_argument("--output-dir")
    sanu.add_argument("--output-json")
    sanu.add_argument("--full", action="store_true")

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

    smc = stress_sub.add_parser("mcaptcha")
    smc_source = smc.add_mutually_exclusive_group(required=True)
    smc_source.add_argument("--config-url")
    smc_source.add_argument("--base-url")
    smc_source.add_argument("--config-json")
    smc_source.add_argument("--config-file")
    smc.add_argument("--sitekey", "--key", dest="sitekey")
    smc.add_argument("--verify-url")
    smc.add_argument("--no-submit", action="store_true")
    smc.add_argument("--runs", type=int, default=10)
    smc.add_argument("--concurrency", type=int, default=2)
    smc.add_argument("--timeout", type=int, default=60)
    smc.add_argument("--max-attempts", type=int, default=50_000_000)
    smc.add_argument("--workers", type=int, default=1)
    smc.add_argument("--proxy")
    smc.add_argument("--output-dir")
    smc.add_argument("--output-json")
    smc.add_argument("--full", action="store_true")

    spc = stress_sub.add_parser("pcaptcha")
    spc.add_argument("--challenge-url", required=True)
    spc.add_argument("--validate-url")
    spc.add_argument("--validate", action="store_true")
    spc.add_argument("--runs", type=int, default=10)
    spc.add_argument("--concurrency", type=int, default=2)
    spc.add_argument("--timeout", type=int, default=30)
    spc.add_argument("--proxy")
    spc.add_argument("--output-dir")
    spc.add_argument("--output-json")
    spc.add_argument("--full", action="store_true")

    spow = stress_sub.add_parser("powcaptcha")
    spow_source = spow.add_mutually_exclusive_group(required=True)
    spow_source.add_argument("--challenge-url")
    spow_source.add_argument("--challenge-json")
    spow_source.add_argument("--challenge-file")
    spow_source.add_argument("--quiz-b64")
    spow_source.add_argument("--quiz-hex")
    spow_source.add_argument("--quiz-file")
    spow.add_argument("--id", dest="challenge_id")
    spow.add_argument("--verify-url")
    spow.add_argument("--submit", action="store_true")
    spow.add_argument("--runs", type=int, default=10)
    spow.add_argument("--concurrency", type=int, default=2)
    spow.add_argument("--timeout", type=int, default=60)
    spow.add_argument("--max-attempts", type=int, default=50_000_000)
    spow.add_argument("--workers", type=int, default=1)
    spow.add_argument("--proxy")
    spow.add_argument("--output-dir")
    spow.add_argument("--output-json")
    spow.add_argument("--full", action="store_true")

    spriv = stress_sub.add_parser("privatecaptcha")
    spriv_source = spriv.add_mutually_exclusive_group(required=True)
    spriv_source.add_argument("--puzzle")
    spriv_source.add_argument("--puzzle-file")
    spriv_source.add_argument("--challenge-json")
    spriv_source.add_argument("--challenge-file")
    spriv_source.add_argument("--challenge-url")
    spriv_source.add_argument("--puzzle-url")
    spriv.add_argument("--sitekey")
    spriv.add_argument("--verify-url")
    spriv.add_argument("--siteverify-url")
    spriv.add_argument("--submit", action="store_true")
    spriv.add_argument("--api-key")
    spriv.add_argument("--secret")
    spriv.add_argument("--runs", type=int, default=10)
    spriv.add_argument("--concurrency", type=int, default=2)
    spriv.add_argument("--timeout", type=int, default=60)
    spriv.add_argument("--max-attempts-per-solution", type=int, default=50_000_000)
    spriv.add_argument("--workers", type=int, default=1)
    spriv.add_argument("--proxy")
    spriv.add_argument("--output-dir")
    spriv.add_argument("--output-json")
    spriv.add_argument("--full", action="store_true")

    sport = stress_sub.add_parser("portcullis")
    sport_source = sport.add_mutually_exclusive_group(required=True)
    sport_source.add_argument("--challenge")
    sport_source.add_argument("--challenge-json")
    sport_source.add_argument("--challenge-file")
    sport_source.add_argument("--challenge-url")
    sport_source.add_argument("--base-url")
    sport.add_argument("--sitekey")
    sport.add_argument("--sig")
    sport.add_argument("--verify-url")
    sport.add_argument("--siteverify-url")
    sport.add_argument("--submit", action="store_true")
    sport.add_argument("--secret-key")
    sport.add_argument("--client-ip")
    sport.add_argument("--user-agent")
    sport.add_argument("--runs", type=int, default=10)
    sport.add_argument("--concurrency", type=int, default=2)
    sport.add_argument("--timeout", type=int, default=60)
    sport.add_argument("--max-iters", type=int, default=10_000_000)
    sport.add_argument("--workers", type=int, default=1)
    sport.add_argument("--proxy")
    sport.add_argument("--output-dir")
    sport.add_argument("--output-json")
    sport.add_argument("--full", action="store_true")

    swk = stress_sub.add_parser("wicketkeeper")
    swk_source = swk.add_mutually_exclusive_group(required=True)
    swk_source.add_argument("--challenge-url")
    swk_source.add_argument("--base-url")
    swk_source.add_argument("--challenge-json")
    swk_source.add_argument("--challenge-file")
    swk.add_argument("--siteverify-url")
    swk.add_argument("--no-submit", action="store_true")
    swk.add_argument("--runs", type=int, default=10)
    swk.add_argument("--concurrency", type=int, default=2)
    swk.add_argument("--timeout", type=int, default=60)
    swk.add_argument("--max-attempts", type=int, default=50_000_000)
    swk.add_argument("--workers", type=int, default=1)
    swk.add_argument("--proxy")
    swk.add_argument("--output-dir")
    swk.add_argument("--output-json")
    swk.add_argument("--full", action="store_true")

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
        if provider in (
            None,
            "aliyun",
            "geetest",
            "yidun",
            "hcaptcha",
            "recaptcha",
            "turnstile",
            "cap",
            "mcaptcha",
            "pcaptcha",
            "powcaptcha",
            "privatecaptcha",
            "portcullis",
            "wicketkeeper",
            "anubis",
        ):
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
    if args.cmd == "solve" and args.provider == "anubis":
        ret = await client.solve_anubis(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            page_url=args.page_url,
            base_url=args.base_url,
            pass_url=args.pass_url,
            redir=args.redir,
            difficulty=args.difficulty,
            algorithm=args.algorithm,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            submit=args.submit,
            ensure_test_cookie=not args.no_ensure_test_cookie,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
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
    if args.cmd == "solve" and args.provider == "mcaptcha":
        ret = await client.solve_mcaptcha(
            config_json=args.config_json,
            config_file=args.config_file,
            config_url=args.config_url,
            base_url=args.base_url,
            sitekey=args.sitekey,
            verify_url=args.verify_url,
            submit=not args.no_submit,
            siteverify_url=args.siteverify_url,
            siteverify=args.siteverify,
            secret=args.secret,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "pcaptcha":
        ret = await client.solve_pcaptcha(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            challenge_id=args.challenge_id,
            validate_url=args.validate_url,
            validate=args.validate,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "powcaptcha":
        ret = await client.solve_powcaptcha(
            quiz=args.quiz,
            quiz_b64=args.quiz_b64,
            quiz_hex=args.quiz_hex,
            quiz_file=args.quiz_file,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            challenge_id=args.challenge_id,
            verify_url=args.verify_url,
            submit=args.submit,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "privatecaptcha":
        ret = await client.solve_privatecaptcha(
            puzzle=args.puzzle,
            puzzle_file=args.puzzle_file,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            puzzle_url=args.puzzle_url,
            sitekey=args.sitekey,
            verify_url=args.verify_url,
            siteverify_url=args.siteverify_url,
            submit=args.submit,
            api_key=args.api_key,
            secret=args.secret,
            start=args.start,
            max_attempts_per_solution=args.max_attempts_per_solution,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "portcullis":
        ret = await client.solve_portcullis(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            base_url=args.base_url,
            sitekey=args.sitekey,
            sig=args.sig,
            verify_url=args.verify_url,
            siteverify_url=args.siteverify_url,
            submit=args.submit,
            secret_key=args.secret_key,
            client_ip=args.client_ip,
            user_agent=args.user_agent,
            start=args.start,
            max_iters=args.max_iters,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "wicketkeeper":
        ret = await client.solve_wicketkeeper(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            base_url=args.base_url,
            difficulty=args.difficulty,
            token=args.token,
            siteverify_url=args.siteverify_url,
            submit=not args.no_submit,
            start=args.start,
            max_attempts=args.max_attempts,
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
    if args.cmd == "stress" and args.provider == "anubis":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="anubis",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_anubis(
                challenge_url=args.challenge_url,
                page_url=args.page_url,
                base_url=args.base_url,
                pass_url=args.pass_url,
                redir=args.redir,
                difficulty=args.difficulty,
                algorithm=args.algorithm,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                submit=args.submit,
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
    if args.cmd == "stress" and args.provider == "mcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="mcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_mcaptcha(
                config_json=args.config_json,
                config_file=args.config_file,
                config_url=args.config_url,
                base_url=args.base_url,
                sitekey=args.sitekey,
                verify_url=args.verify_url,
                submit=not args.no_submit,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "pcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="pcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_pcaptcha(
                challenge_url=args.challenge_url,
                validate_url=args.validate_url,
                validate=args.validate,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "powcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="powcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_powcaptcha(
                quiz_b64=args.quiz_b64,
                quiz_hex=args.quiz_hex,
                quiz_file=args.quiz_file,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                challenge_id=args.challenge_id,
                verify_url=args.verify_url,
                submit=args.submit,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "privatecaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="privatecaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_privatecaptcha(
                puzzle=args.puzzle,
                puzzle_file=args.puzzle_file,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                puzzle_url=args.puzzle_url,
                sitekey=args.sitekey,
                verify_url=args.verify_url,
                siteverify_url=args.siteverify_url,
                submit=args.submit,
                api_key=args.api_key,
                secret=args.secret,
                max_attempts_per_solution=args.max_attempts_per_solution,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "portcullis":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="portcullis",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_portcullis(
                challenge=args.challenge,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                base_url=args.base_url,
                sitekey=args.sitekey,
                sig=args.sig,
                verify_url=args.verify_url,
                siteverify_url=args.siteverify_url,
                submit=args.submit,
                secret_key=args.secret_key,
                client_ip=args.client_ip,
                user_agent=args.user_agent,
                max_iters=args.max_iters,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "wicketkeeper":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="wicketkeeper",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_wicketkeeper(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                base_url=args.base_url,
                siteverify_url=args.siteverify_url,
                submit=not args.no_submit,
                max_attempts=args.max_attempts,
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
