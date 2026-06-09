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
            "activehashcash",
            "botcha",
            "btx",
            "altcha",
            "anubis",
            "auro",
            "aliyun",
            "tencent",
            "friendlycaptcha",
            "getpowcaptcha",
            "fcaptcha",
            "gunslol",
            "h33botshield",
            "hashguard",
            "trustcaptcha",
            "stravcaptcha",
            "justnocaptcha",
            "capybara",
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

    ah = solve_sub.add_parser("activehashcash")
    ah_source = ah.add_mutually_exclusive_group(required=True)
    ah_source.add_argument("--resource", help="ActiveHashcash resource, usually request.host")
    ah_source.add_argument("--challenge-json", help="inline {resource,bits,date,rand} JSON, or @/path")
    ah_source.add_argument("--challenge-file")
    ah_source.add_argument("--challenge-html", help="HTML form containing input[data-hashcash]")
    ah_source.add_argument("--challenge-url", help="GET endpoint returning ActiveHashcash HTML/JSON")
    ah.add_argument("--submit-url")
    ah.add_argument("--submit", action="store_true")
    ah.add_argument("--submit-format", choices=["form", "json"], default="form")
    ah.add_argument("--bits", type=int)
    ah.add_argument("--date", dest="stamp_date")
    ah.add_argument("--rand")
    ah.add_argument("--response-field", default="hashcash")
    ah.add_argument("--start", type=int, default=0)
    ah.add_argument("--max-attempts", type=int, default=100_000_000)
    ah.add_argument("--workers", type=int, default=1)
    ah.add_argument("--timeout", type=int, default=60)
    ah.add_argument("--proxy")
    ah.add_argument("--output-dir")
    ah.add_argument("--user-agent")
    ah.add_argument("--raw", action="store_true")

    btx = solve_sub.add_parser("btx")
    btx_source = btx.add_mutually_exclusive_group(required=True)
    btx_source.add_argument("--challenge-json", help="inline BTX challenge JSON, or @/path")
    btx_source.add_argument("--challenge-file")
    btx_source.add_argument("--challenge-url", help="endpoint returning X-BTX-Challenge or challenge JSON")
    btx.add_argument("--submit-url", help="retry target; sends X-BTX-* proof headers")
    btx.add_argument("--submit", action="store_true")
    btx.add_argument("--submit-method", default="POST", choices=["GET", "POST", "PUT", "PATCH"])
    btx.add_argument("--submit-json", help="optional JSON body for retry request, or @/path")
    btx.add_argument("--response-field", default="btx_proof")
    btx.add_argument("--nonce-start")
    btx.add_argument("--max-attempts", type=int, default=1_000_000)
    btx.add_argument("--workers", type=int, default=1)
    btx.add_argument("--timeout", type=int, default=60)
    btx.add_argument("--proxy")
    btx.add_argument("--output-dir")
    btx.add_argument("--user-agent")
    btx.add_argument("--raw", action="store_true")

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
    alt.add_argument("--v2-strategy", choices=["auto", "verify-compatible", "prefix"], default="auto")
    alt.add_argument("--counter-mode", choices=["uint32", "string"], default="uint32")
    alt.add_argument("--hmac-algorithm", default="SHA-256", choices=["SHA-256", "SHA-384", "SHA-512"])
    alt.add_argument("--hmac-signature-secret")
    alt.add_argument("--hmac-key-signature-secret")
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

    auro = solve_sub.add_parser("auro")
    auro_source = auro.add_mutually_exclusive_group(required=False)
    auro_source.add_argument("--challenge-json", help="inline {'prefix','difficulty'}, or @/path")
    auro_source.add_argument("--challenge-file")
    auro_source.add_argument("--prefix", help="inline PoW prefix; requires --difficulty")
    auro.add_argument("--difficulty", type=int)
    auro.add_argument("--base-url", default="https://auro.network")
    auro.add_argument("--enckey-url")
    auro.add_argument("--setup-url")
    auro.add_argument("--validate-url")
    auro.add_argument("--key-b64", help="inline AES-GCM key for local fixtures; otherwise fetch /enckey")
    auro.add_argument("--mouse-json", help="inline mouse point list, or @/path")
    auro.add_argument("--mouse-file")
    auro.add_argument("--mouse-points", type=int, default=50)
    auro.add_argument("--mouse-seed")
    auro.add_argument("--iv-b64")
    auro.add_argument("--client-guid")
    auro.add_argument("--no-submit", action="store_true", help="skip /api/pow/validate after solving")
    auro.add_argument("--start", type=int, default=0)
    auro.add_argument("--max-attempts", type=int, default=50_000_000)
    auro.add_argument("--workers", type=int, default=1)
    auro.add_argument("--timeout", type=int, default=60)
    auro.add_argument("--proxy")
    auro.add_argument("--output-dir")
    auro.add_argument("--raw", action="store_true")

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

    gpc = solve_sub.add_parser("getpowcaptcha")
    gpc_source = gpc.add_mutually_exclusive_group(required=True)
    gpc_source.add_argument("--app-id", help="powCAPTCHA APP ID; POSTs /challenges/create")
    gpc_source.add_argument("--challenge-json", help="inline challenge JSON, or @/path")
    gpc_source.add_argument("--challenge-file")
    gpc_source.add_argument("--challenge-url", help="GET endpoint returning powCAPTCHA challenge JSON")
    gpc.add_argument("--backend-url", default="https://api.powcaptcha.com")
    gpc.add_argument("--create-url")
    gpc.add_argument("--verify-url")
    gpc.add_argument("--secret", help="private key for optional /challenges/verify")
    gpc.add_argument("--verify", action="store_true", help="POST solution+secret to /challenges/verify")
    gpc.add_argument("--context-json", help="inline context JSON, or @/path")
    gpc.add_argument("--context-file")
    gpc.add_argument("--signals-json", help="inline signals JSON, or @/path; default synthesizes low-risk signals")
    gpc.add_argument("--signals-file")
    gpc.add_argument("--fingerprint-json", help="inline fingerprint JSON/base64, or @/path")
    gpc.add_argument("--fingerprint-file")
    gpc.add_argument("--no-gzip-create", action="store_true")
    gpc.add_argument("--start", type=int, default=0)
    gpc.add_argument("--max-attempts-per-problem", type=int, default=10_000_000)
    gpc.add_argument("--workers", type=int, default=1)
    gpc.add_argument("--timeout", type=int, default=60)
    gpc.add_argument("--proxy")
    gpc.add_argument("--output-dir")
    gpc.add_argument("--raw", action="store_true")

    h33 = solve_sub.add_parser("h33botshield")
    h33_source = h33.add_mutually_exclusive_group(required=False)
    h33_source.add_argument("--base-url", default="https://api.h33.ai", help="H33 API origin; infers /v1/botshield/*")
    h33_source.add_argument("--challenge-json", help="inline challenge JSON, or @/path")
    h33_source.add_argument("--challenge-file")
    h33_source.add_argument("--challenge-url", help="POST endpoint returning BotShield challenge JSON")
    h33.add_argument("--solve-url")
    h33.add_argument("--challenge-body-json", help="inline POST body JSON, or @/path; default {}")
    h33.add_argument("--challenge-body-file")
    h33.add_argument("--submit", action="store_true", help="POST solution to /v1/botshield/solve and return h33_bot_token")
    h33.add_argument("--start", type=int, default=0)
    h33.add_argument("--max-attempts", type=int, default=25_000_000)
    h33.add_argument("--workers", type=int, default=1)
    h33.add_argument("--timeout", type=int, default=60)
    h33.add_argument("--proxy")
    h33.add_argument("--output-dir")
    h33.add_argument("--raw", action="store_true")

    botcha = solve_sub.add_parser("botcha")
    botcha.add_argument("--mode", choices=["auto", "speed", "token", "standard"], default="speed")
    botcha.add_argument("--base-url", default="https://botcha.ai")
    botcha.add_argument("--app-id", help="BOTCHA app_id for /v1/token flow")
    botcha.add_argument("--audience")
    botcha.add_argument("--challenge-json", help="inline challenge JSON, or @/path")
    botcha.add_argument("--challenge-file")
    botcha.add_argument("--challenge-url")
    botcha.add_argument("--verify-url")
    botcha.add_argument("--submit", action="store_true", help="POST solved body to verify/token endpoint")
    botcha.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"], help="legacy /api/challenge difficulty")
    botcha.add_argument("--rtt-adjust", action="store_true", help="append ts=now for RTT-aware timeout endpoints")
    botcha.add_argument("--timeout", type=int, default=10)
    botcha.add_argument("--proxy")
    botcha.add_argument("--output-dir")
    botcha.add_argument("--raw", action="store_true")

    fc = solve_sub.add_parser("fcaptcha")
    fc_source = fc.add_mutually_exclusive_group(required=True)
    fc_source.add_argument("--base-url", help="FCaptcha server origin; infers /api/pow/challenge and /api/verify")
    fc_source.add_argument("--challenge-json", help="inline challenge JSON, or @/path")
    fc_source.add_argument("--challenge-file")
    fc_source.add_argument("--challenge-url", help="FCaptcha /api/pow/challenge endpoint")
    fc.add_argument("--verify-url", help="FCaptcha /api/verify or /api/score endpoint")
    fc.add_argument("--site-key", default="default")
    fc.add_argument("--submit", action="store_true", help="POST solved body to verify endpoint")
    fc.add_argument("--score-endpoint", action="store_true", help="derive /api/score instead of /api/verify when --base-url is used")
    fc.add_argument("--signals-json", help="inline signals JSON, or @/path; default synthesizes low-risk signals")
    fc.add_argument("--signals-file")
    fc.add_argument("--start", type=int, default=0)
    fc.add_argument("--max-attempts", type=int)
    fc.add_argument("--timeout", type=int, default=60)
    fc.add_argument("--min-submit-ms", type=int, default=1600)
    fc.add_argument("--proxy")
    fc.add_argument("--output-dir")
    fc.add_argument("--raw", action="store_true")

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
    cap.add_argument("--instr-json", help="Cap instrumentation payload/meta JSON, or @/path")
    cap.add_argument("--instr-file", help="Cap instrumentation payload/meta JSON file")
    cap.add_argument("--secret", help="self-hosted Cap secret for decrypting encrypted instrumentation metadata")
    cap.add_argument("--raw", action="store_true")

    cpz = solve_sub.add_parser("cryptopuzzle")
    cpz_source = cpz.add_mutually_exclusive_group(required=True)
    cpz_source.add_argument("--base-url", help="API root; infers /challenge and /verify")
    cpz_source.add_argument("--puzzle", help="inline archive base64/hex")
    cpz_source.add_argument("--puzzle-file")
    cpz_source.add_argument("--challenge-json", help="inline JSON with puzzleB64/archive/challenge, or @/path")
    cpz_source.add_argument("--challenge-file")
    cpz_source.add_argument("--challenge-url", help="GET endpoint returning puzzle archive/base64/JSON")
    cpz.add_argument("--verify-url", help="POST endpoint accepting {solution,message}")
    cpz.add_argument("--submit", action="store_true")
    cpz.add_argument("--expected-message")
    cpz.add_argument("--timeout", type=int, default=60)
    cpz.add_argument("--proxy")
    cpz.add_argument("--output-dir")
    cpz.add_argument("--user-agent")
    cpz.add_argument("--raw", action="store_true")

    cx = solve_sub.add_parser("captxa")
    cx_source = cx.add_mutually_exclusive_group(required=True)
    cx_source.add_argument("--base-url", help="Captxa API root; infers /challenge/simp and /solve/simp")
    cx_source.add_argument("--challenge-json", help="inline simple challenge JSON, or @/path")
    cx_source.add_argument("--challenge-file")
    cx_source.add_argument("--challenge-url", help="Captxa /challenge/simp endpoint")
    cx.add_argument("--solve-url", help="Captxa /solve/simp endpoint")
    cx.add_argument("--submit", action="store_true", help="POST solved body to /solve/simp")
    cx.add_argument("--metrics-json", help="inline browser metrics JSON, or @/path")
    cx.add_argument("--metrics-file")
    cx.add_argument("--start", type=int, default=0)
    cx.add_argument("--max-attempts", type=int)
    cx.add_argument("--timeout", type=int, default=60)
    cx.add_argument("--proxy")
    cx.add_argument("--output-dir")
    cx.add_argument("--user-agent")
    cx.add_argument("--timezone", default="America/New_York")
    cx.add_argument("--raw", action="store_true")

    crv = solve_sub.add_parser("crovly")
    crv_source = crv.add_mutually_exclusive_group(required=True)
    crv_source.add_argument("--api-url", default="https://api.crovly.com", help="Crovly API root; infers /challenge and /verify")
    crv_source.add_argument("--challenge-json", help="inline {nonce,difficulty} JSON, or @/path")
    crv_source.add_argument("--challenge-file")
    crv_source.add_argument("--challenge-url", help="Crovly /challenge endpoint")
    crv.add_argument("--edge-url", default="https://edge.crovly.com")
    crv.add_argument("--verify-url", help="Crovly /verify endpoint")
    crv.add_argument("--site-key")
    crv.add_argument("--submit", action="store_true")
    crv.add_argument("--fingerprint-hash")
    crv.add_argument("--fingerprint-json", help="inline fingerprintHash/profile JSON, or @/path")
    crv.add_argument("--fingerprint-file")
    crv.add_argument("--profile-json", help="inline synthetic browser profile JSON, or @/path")
    crv.add_argument("--profile-file")
    crv.add_argument("--environment-json", help="inline environment signals JSON, or @/path")
    crv.add_argument("--environment-file")
    crv.add_argument("--behavior-json", help="inline behavior stats JSON, or @/path")
    crv.add_argument("--behavior-file")
    crv.add_argument("--hold-json", help="inline hold-challenge stats JSON, or @/path")
    crv.add_argument("--hold-file")
    crv.add_argument("--start", type=int, default=0)
    crv.add_argument("--max-attempts", type=int, default=2**32)
    crv.add_argument("--workers", type=int, default=1)
    crv.add_argument("--timeout", type=int, default=60)
    crv.add_argument("--min-submit-ms", type=int, default=0)
    crv.add_argument("--min-solve-ms", type=int, default=0)
    crv.add_argument("--proxy")
    crv.add_argument("--output-dir")
    crv.add_argument("--user-agent")
    crv.add_argument("--raw", action="store_true")

    chpio = solve_sub.add_parser("chpiopow")
    chpio_source = chpio.add_mutually_exclusive_group(required=True)
    chpio_source.add_argument("--challenge", help="inline signed/raw challenge JSON")
    chpio_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    chpio_source.add_argument("--challenge-file")
    chpio_source.add_argument("--challenge-url", help="endpoint returning signed/raw chpio pow-captcha challenge")
    chpio.add_argument("--redeem-url", help="endpoint accepting {challengesSigned, solutions}")
    chpio.add_argument("--submit", action="store_true", help="POST solved body to --redeem-url")
    chpio.add_argument("--secret", help="optional server secret for signed-data cross-check / local fixtures")
    chpio.add_argument("--start", type=int, default=0)
    chpio.add_argument("--max-attempts-per-challenge", type=int, default=50_000_000)
    chpio.add_argument("--workers", type=int, default=1)
    chpio.add_argument("--timeout", type=int, default=60)
    chpio.add_argument("--proxy")
    chpio.add_argument("--output-dir")
    chpio.add_argument("--raw", action="store_true")

    imp = solve_sub.add_parser("impost")
    imp_source = imp.add_mutually_exclusive_group(required=True)
    imp_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    imp_source.add_argument("--challenge-file")
    imp_source.add_argument("--challenge-url")
    imp.add_argument("--verify-url", help="endpoint accepting {challenge, nonce}")
    imp.add_argument("--submit", action="store_true", help="POST solution to --verify-url")
    imp.add_argument("--start", type=int, default=0)
    imp.add_argument("--max-attempts", type=int, default=1_000_000)
    imp.add_argument("--workers", type=int, default=1)
    imp.add_argument("--timeout", type=int, default=60)
    imp.add_argument("--proxy")
    imp.add_argument("--output-dir")
    imp.add_argument("--raw", action="store_true")

    kerb = solve_sub.add_parser("kerberus")
    kerb_source = kerb.add_mutually_exclusive_group(required=True)
    kerb_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    kerb_source.add_argument("--challenge-file")
    kerb_source.add_argument("--challenge-url")
    kerb.add_argument("--serialized-input", help="Kerberus serializedInput")
    kerb.add_argument("--input-file", help="read serializedInput from file")
    kerb.add_argument("--validate-url")
    kerb.add_argument("--submit", action="store_true", help="POST solution to --validate-url")
    kerb.add_argument("--start", type=int, default=0)
    kerb.add_argument("--max-attempts-per-salt", type=int, default=50_000_000)
    kerb.add_argument("--workers", type=int, default=1)
    kerb.add_argument("--timeout", type=int, default=60)
    kerb.add_argument("--proxy")
    kerb.add_argument("--output-dir")
    kerb.add_argument("--raw", action="store_true")

    lapti = solve_sub.add_parser("lapti")
    lapti_source = lapti.add_mutually_exclusive_group(required=True)
    lapti_source.add_argument("--base-url", help="Lapti API root; infers /handshake/{data} and /action/{data}/{nonce}")
    lapti_source.add_argument("--handshake-url", help="explicit GET /handshake/{data} URL")
    lapti_source.add_argument("--token", help="inline SHA3-512 token returned by handshake")
    lapti_source.add_argument("--challenge-json", help="inline {token,complexity,data} JSON, or @/path")
    lapti_source.add_argument("--challenge-file")
    lapti.add_argument("--data", help="initial client data used by /handshake/{data}")
    lapti.add_argument("--action-url", help="explicit protected action URL, usually /action/{data}/{nonce}")
    lapti.add_argument("--submit", action="store_true")
    lapti.add_argument("--secret", help="optional server SECRET for local token verification")
    lapti.add_argument("--start", type=int, default=1)
    lapti.add_argument("--max-attempts", type=int, default=100_000_000)
    lapti.add_argument("--workers", type=int, default=1)
    lapti.add_argument("--timeout", type=int, default=60)
    lapti.add_argument("--proxy")
    lapti.add_argument("--output-dir")
    lapti.add_argument("--user-agent")
    lapti.add_argument("--raw", action="store_true")

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

    pp = solve_sub.add_parser("paulpow")
    pp_source = pp.add_mutually_exclusive_group(required=True)
    pp_source.add_argument("--challenge-json", help="inline JSON object, or @/path/to/challenge.json")
    pp_source.add_argument("--challenge-file")
    pp_source.add_argument("--challenge-url")
    pp.add_argument("--verify-url", help="endpoint accepting {clientInfo, nonce}")
    pp.add_argument("--submit", action="store_true", help="POST solution to --verify-url")
    pp.add_argument("--start", type=int, default=0)
    pp.add_argument("--max-attempts", type=int)
    pp.add_argument("--workers", type=int, default=1)
    pp.add_argument("--timeout", type=int, default=60)
    pp.add_argument("--proxy")
    pp.add_argument("--output-dir")
    pp.add_argument("--raw", action="store_true")

    gl = solve_sub.add_parser("gunslol")
    gl_source = gl.add_mutually_exclusive_group(required=True)
    gl_source.add_argument("--challenge-json", help="inline JSON object with o09/_n/_org_ts/_2xa, or @/path")
    gl_source.add_argument("--challenge-file")
    gl_source.add_argument("--challenge-url", help="endpoint returning JSON or HTML containing const _gs_sets")
    gl_source.add_argument("--page-url", help="page HTML containing const _gs_sets")
    gl.add_argument("--verify-url", help="endpoint accepting {seal, _oo}")
    gl.add_argument("--submit", action="store_true", help="POST solution to --verify-url")
    gl.add_argument("--start", type=int, default=0)
    gl.add_argument("--max-attempts", type=int)
    gl.add_argument("--workers", type=int, default=1)
    gl.add_argument("--timeout", type=int, default=60)
    gl.add_argument("--proxy")
    gl.add_argument("--output-dir")
    gl.add_argument("--raw", action="store_true")

    hg = solve_sub.add_parser("hashguard")
    hg_source = hg.add_mutually_exclusive_group(required=True)
    hg_source.add_argument("--base-url", help="HashGuard server root; infers /v1/pow/challenges and /v1/pow/verifications")
    hg_source.add_argument("--challenge-json", help="inline {challengeId,seed,target} JSON, or @/path")
    hg_source.add_argument("--challenge-file")
    hg_source.add_argument("--challenge-url", help="POST endpoint returning HashGuard challenge")
    hg.add_argument("--route-prefix", default="v1")
    hg.add_argument("--context")
    hg.add_argument("--verify-url")
    hg.add_argument("--introspect-url")
    hg.add_argument("--submit", action="store_true")
    hg.add_argument("--introspect", action="store_true")
    hg.add_argument("--no-consume", dest="consume", action="store_false", default=True)
    hg.add_argument("--start", type=int, default=0)
    hg.add_argument("--max-attempts", type=int, default=200_000_000)
    hg.add_argument("--workers", type=int, default=1)
    hg.add_argument("--timeout", type=int, default=60)
    hg.add_argument("--min-solve-ms", type=int, default=0)
    hg.add_argument("--proxy")
    hg.add_argument("--output-dir")
    hg.add_argument("--user-agent")
    hg.add_argument("--raw", action="store_true")

    tc = solve_sub.add_parser("trustcaptcha")
    tc_source = tc.add_mutually_exclusive_group(required=True)
    tc_source.add_argument("--site-key", help="TrustCaptcha site key; POSTs /v2/verifications")
    tc_source.add_argument("--challenge-json", help="inline {verificationId,difficulty,tasks} JSON, or @/path")
    tc_source.add_argument("--challenge-file")
    tc.add_argument("--api-url", default="https://api.trustcomponent.com")
    tc.add_argument("--target-url", default="https://example.com/")
    tc.add_argument("--create-url", help="explicit POST /v2/verifications endpoint")
    tc.add_argument("--submit-url", help="explicit POST /v2/verifications/{id}/challenges endpoint")
    tc.add_argument("--create-body-json", help="override create body JSON, or @/path")
    tc.add_argument("--create-body-file")
    tc.add_argument("--submit", dest="submit", action="store_true", default=None)
    tc.add_argument("--no-submit", dest="submit", action="store_false")
    tc.add_argument("--max-rounds", type=int, default=3)
    tc.add_argument("--start", type=int, default=0)
    tc.add_argument("--max-attempts-per-task", type=int, default=20_000_000)
    tc.add_argument("--workers", type=int, default=1)
    tc.add_argument("--timeout", type=int, default=60)
    tc.add_argument("--min-solve-ms", type=int, default=1200)
    tc.add_argument("--minimal-data-mode", action="store_true")
    tc.add_argument("--bypass-token")
    tc.add_argument("--framework", default="other")
    tc.add_argument("--language", default="en-US")
    tc.add_argument("--theme", default="light")
    tc.add_argument("--proxy")
    tc.add_argument("--output-dir")
    tc.add_argument("--user-agent")
    tc.add_argument("--raw", action="store_true")

    sc = solve_sub.add_parser("stravcaptcha")
    sc_source = sc.add_mutually_exclusive_group(required=True)
    sc_source.add_argument("--token", help="@strav/captcha signed token")
    sc_source.add_argument("--challenge-json", help="inline {token,props} JSON, or @/path")
    sc_source.add_argument("--challenge-file")
    sc_source.add_argument("--challenge-html", help="view helper HTML containing _captcha input")
    sc_source.add_argument("--challenge-url", help="GET /__captcha/pow endpoint")
    sc.add_argument("--submit-url")
    sc.add_argument("--submit", action="store_true")
    sc.add_argument("--secret", help="optional server secret for local token signature verification")
    sc.add_argument("--start", type=int, default=0)
    sc.add_argument("--max-attempts", type=int, default=100_000_000)
    sc.add_argument("--workers", type=int, default=1)
    sc.add_argument("--timeout", type=int, default=60)
    sc.add_argument("--token-field", default="_captcha")
    sc.add_argument("--response-field", default="_captcha_answer")
    sc.add_argument("--honeypot-field", default="website")
    sc.add_argument("--proxy")
    sc.add_argument("--output-dir")
    sc.add_argument("--user-agent")
    sc.add_argument("--raw", action="store_true")

    jnc = solve_sub.add_parser("justnocaptcha")
    jnc_source = jnc.add_mutually_exclusive_group(required=True)
    jnc_source.add_argument("--challenge", help="inline JustNoCaptcha challenge string")
    jnc_source.add_argument("--challenge-json", help="inline {challenge,challengeSalt} JSON, or @/path")
    jnc_source.add_argument("--challenge-file")
    jnc_source.add_argument("--challenge-html", help="HTML containing hidden challenge input")
    jnc_source.add_argument("--challenge-url", help="GET endpoint returning challenge string/JSON/HTML")
    jnc.add_argument("--submit-url")
    jnc.add_argument("--submit", action="store_true")
    jnc.add_argument("--challenge-salt", help="optional server salt to verify challenge hash for fixtures")
    jnc.add_argument("--start", type=int)
    jnc.add_argument("--max-attempts-per-puzzle", type=int)
    jnc.add_argument("--workers", type=int, default=1)
    jnc.add_argument("--timeout", type=int, default=60)
    jnc.add_argument("--challenge-field", default="challenge")
    jnc.add_argument("--response-field", default="solution")
    jnc.add_argument("--proxy")
    jnc.add_argument("--output-dir")
    jnc.add_argument("--user-agent")
    jnc.add_argument("--raw", action="store_true")

    capy = solve_sub.add_parser("capybara")
    capy_source = capy.add_mutually_exclusive_group(required=True)
    capy_source.add_argument("--base-url", help="Capybara Worker origin; infers /api/challenge and /api/verify")
    capy_source.add_argument("--challenge-json", help="inline challenge response JSON, payload_token, or @/path")
    capy_source.add_argument("--challenge-file")
    capy_source.add_argument("--challenge-url", help="POST /api/challenge endpoint")
    capy_source.add_argument("--payload-token", help="payload_token containing id/nonce/exp/difficulty/signature")
    capy.add_argument("--verify-url", help="POST /api/verify endpoint")
    capy.add_argument("--submit", action="store_true")
    capy.add_argument("--difficulty", type=int, default=3)
    capy.add_argument("--duration-sec", type=int, default=30)
    capy.add_argument("--secret", help="optional TOKEN_SECRET for local payload_token signature verification")
    capy.add_argument("--instance-id", default="guest")
    capy.add_argument("--start", type=int, default=0)
    capy.add_argument("--max-attempts", type=int, default=100_000_000)
    capy.add_argument("--workers", type=int, default=1)
    capy.add_argument("--timeout", type=int, default=60)
    capy.add_argument("--proxy")
    capy.add_argument("--output-dir")
    capy.add_argument("--user-agent")
    capy.add_argument("--raw", action="store_true")

    vul = solve_sub.add_parser("vulcan")
    vul_source = vul.add_mutually_exclusive_group(required=True)
    vul_source.add_argument("--challenge-json", help="inline {challenge,difficulty,rounds} JSON, or @/path")
    vul_source.add_argument("--challenge-file")
    vul_source.add_argument("--challenge-html", help="HTML containing div.captcha-wrapper")
    vul_source.add_argument("--challenge-url", help="GET endpoint returning Vulcan JSON or HTML")
    vul.add_argument("--start", type=int, default=1)
    vul.add_argument("--max-attempts-per-round", type=int, default=1_000_000_000)
    vul.add_argument("--workers", type=int, default=1)
    vul.add_argument("--timeout", type=int, default=60)
    vul.add_argument("--response-field", default="captcha-response")
    vul.add_argument("--proxy")
    vul.add_argument("--output-dir")
    vul.add_argument("--user-agent")
    vul.add_argument("--raw", action="store_true")

    spw = solve_sub.add_parser("spow")
    spw_source = spw.add_mutually_exclusive_group(required=True)
    spw_source.add_argument("--challenge", help="inline spow challenge string")
    spw_source.add_argument("--challenge-json", help="inline {pow/challenge} JSON, or @/path")
    spw_source.add_argument("--challenge-file")
    spw_source.add_argument("--challenge-html", help="HTML containing a spow challenge string")
    spw_source.add_argument("--challenge-url", help="GET endpoint returning spow challenge text/JSON/HTML")
    spw.add_argument("--verify-url", help="endpoint accepting the solved pow field")
    spw.add_argument("--submit", action="store_true")
    spw.add_argument("--submit-format", choices=["json", "form"], default="json")
    spw.add_argument("--secret", help="optional server secret for local challenge signature verification")
    spw.add_argument("--start", type=int, default=0)
    spw.add_argument("--max-attempts", type=int, default=100_000_000)
    spw.add_argument("--workers", type=int, default=1)
    spw.add_argument("--timeout", type=int, default=60)
    spw.add_argument("--response-field", default="pow")
    spw.add_argument("--proxy")
    spw.add_argument("--output-dir")
    spw.add_argument("--user-agent")
    spw.add_argument("--raw", action="store_true")

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

    powbot = solve_sub.add_parser("powbot")
    powbot_source = powbot.add_mutually_exclusive_group(required=True)
    powbot_source.add_argument("--base-url", help="PoW Bot Deterrent API root; infers /GetChallenges and /Verify")
    powbot_source.add_argument("--challenge", help="inline base64 challenge")
    powbot_source.add_argument("--challenge-json", help="inline challenge JSON/base64/list, or @/path")
    powbot_source.add_argument("--challenge-file")
    powbot_source.add_argument("--challenges-url", help="PoW Bot Deterrent /GetChallenges endpoint")
    powbot.add_argument("--verify-url", help="PoW Bot Deterrent /Verify endpoint")
    powbot.add_argument("--api-token", help="Bearer token for /GetChallenges and /Verify")
    powbot.add_argument("--difficulty-level", type=int, default=5)
    powbot.add_argument("--batch-index", type=int, default=0)
    powbot.add_argument("--submit", action="store_true", help="POST solution to /Verify")
    powbot.add_argument("--start", type=int, default=0)
    powbot.add_argument("--max-attempts", type=int)
    powbot.add_argument("--workers", type=int, default=1)
    powbot.add_argument("--timeout", type=int, default=60)
    powbot.add_argument("--proxy")
    powbot.add_argument("--output-dir")
    powbot.add_argument("--raw", action="store_true")

    powch = solve_sub.add_parser("powchallenge")
    powch_source = powch.add_mutually_exclusive_group(required=True)
    powch_source.add_argument("--base-url", help="powchallenge-server root; infers /challenge and /verify")
    powch_source.add_argument("--challenge-json", help="inline {req_id,challenge,difficulty} JSON, or @/path")
    powch_source.add_argument("--challenge-file")
    powch_source.add_argument("--challenge-url", help="GET endpoint returning {req_id,challenge,difficulty}")
    powch.add_argument("--verify-url", help="POST endpoint accepting {req_id,challenge,timestamp,difficulty,nonce}")
    powch.add_argument("--submit", action="store_true")
    powch.add_argument("--start", type=int, default=0)
    powch.add_argument("--max-attempts", type=int, default=100_000)
    powch.add_argument("--workers", type=int, default=1)
    powch.add_argument("--timeout", type=int, default=60)
    powch.add_argument("--nonce-seed", help="optional base64/hex seed to increment like browser miners")
    powch.add_argument("--nonce-length", type=int, default=32)
    powch.add_argument("--proxy")
    powch.add_argument("--output-dir")
    powch.add_argument("--user-agent")
    powch.add_argument("--raw", action="store_true")

    powr = solve_sub.add_parser("powreaction")
    powr_source = powr.add_mutually_exclusive_group(required=True)
    powr_source.add_argument("--base-url", help="reactions endpoint root; infers /challenge")
    powr_source.add_argument("--challenge", help="inline signed JWT challenge")
    powr_source.add_argument("--challenge-json", help="inline {challenge} JSON or raw payload fixture, or @/path")
    powr_source.add_argument("--challenge-file")
    powr_source.add_argument("--challenge-url", help="POST endpoint returning {challenge}")
    powr.add_argument("--submit-url", help="POST endpoint accepting {challenge, solutions, reaction}")
    powr.add_argument("--reaction", help="reaction/emoji when fetching challenge_url")
    powr.add_argument("--submit", action="store_true")
    powr.add_argument("--secret", help="optional HS256 secret to cross-check signed challenge")
    powr.add_argument("--max-attempts-per-round", type=int, default=50_000_000)
    powr.add_argument("--workers", type=int, default=1)
    powr.add_argument("--timeout", type=int, default=60)
    powr.add_argument("--proxy")
    powr.add_argument("--output-dir")
    powr.add_argument("--user-agent")
    powr.add_argument("--raw", action="store_true")

    proc = solve_sub.add_parser("procaptcha")
    proc_source = proc.add_mutually_exclusive_group(required=True)
    proc_source.add_argument("--provider-url", help="Prosopo provider root; infers /v1/prosopo/provider/client/captcha/pow and /pow/solution")
    proc_source.add_argument("--challenge-json", help="inline {challenge,difficulty,timestamp,signature} JSON, or @/path")
    proc_source.add_argument("--challenge-file")
    proc_source.add_argument("--challenge-url", help="POST endpoint returning Procaptcha PoW challenge")
    proc.add_argument("--submit-url", help="POST endpoint accepting Procaptcha PoW solution body")
    proc.add_argument("--site-key", help="Prosopo-Site-Key header; defaults to --dapp")
    proc.add_argument("--user", help="Prosopo user account")
    proc.add_argument("--dapp", help="Prosopo dapp/site account")
    proc.add_argument("--session-id")
    proc.add_argument("--submit", action="store_true")
    proc.add_argument("--user-timestamp-signature", help="signature over challenge timestamp from the user signer")
    proc.add_argument("--verified-timeout", type=int, default=120_000)
    proc.add_argument("--provider-challenge-signature", help="override signature.provider.challenge")
    proc.add_argument("--behavioral-data")
    proc.add_argument("--salt")
    proc.add_argument("--simd-readings")
    proc.add_argument("--client-meta-json", help="inline clientMetaData JSON, or @/path")
    proc.add_argument("--client-meta-file")
    proc.add_argument("--include-timestamp", action="store_true", help="include raw timestamp in submit body for legacy fixtures")
    proc.add_argument("--start", type=int, default=0)
    proc.add_argument("--max-attempts", type=int, default=100_000_000)
    proc.add_argument("--workers", type=int, default=1)
    proc.add_argument("--timeout", type=int, default=60)
    proc.add_argument("--proxy")
    proc.add_argument("--output-dir")
    proc.add_argument("--user-agent")
    proc.add_argument("--raw", action="store_true")

    tb = solve_sub.add_parser("tollbooth")
    tb_source = tb.add_mutually_exclusive_group(required=True)
    tb_source.add_argument("--base-url", help="protected resource URL; alias for --challenge-url")
    tb_source.add_argument("--challenge-json", help="inline JSON/HTML challenge, or @/path")
    tb_source.add_argument("--challenge-file")
    tb_source.add_argument("--challenge-url", help="protected resource returning Tollbooth HTML/JSON challenge")
    tb.add_argument("--verify-url", help="Tollbooth verify endpoint, usually /.tollbooth/verify")
    tb.add_argument("--submit", action="store_true")
    tb.add_argument("--navigator-strategy", choices=["empty", "minimal"], default="empty")
    tb.add_argument("--start", type=int, default=0)
    tb.add_argument("--max-attempts", type=int, default=1_000_000)
    tb.add_argument("--workers", type=int, default=1)
    tb.add_argument("--timeout", type=int, default=60)
    tb.add_argument("--proxy")
    tb.add_argument("--output-dir")
    tb.add_argument("--user-agent")
    tb.add_argument("--raw", action="store_true")

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

    pf = solve_sub.add_parser("powforge")
    pf_source = pf.add_mutually_exclusive_group(required=False)
    pf_source.add_argument("--base-url", default=None, help="PowForge server root; infers /api/{challenge,verify,token/verify}")
    pf_source.add_argument("--challenge-url", help="PowForge /api/challenge endpoint")
    pf_source.add_argument("--challenge-json", help="inline challenge JSON, or @/path")
    pf_source.add_argument("--challenge-file")
    pf_source.add_argument("--salt", help="inline salt/challenge prefix")
    pf.add_argument("--verify-url", help="PowForge /api/verify endpoint")
    pf.add_argument("--token-verify-url", help="PowForge /api/token/verify endpoint")
    pf.add_argument("--difficulty", type=int)
    pf.add_argument("--response-field", default="pf_token")
    pf.add_argument("--no-submit", action="store_true", help="only solve locally; do not POST /api/verify")
    pf.add_argument("--token-verify", action="store_true", help="POST returned token to /api/token/verify")
    pf.add_argument("--start", type=int, default=1)
    pf.add_argument("--max-attempts", type=int, default=100_000_000)
    pf.add_argument("--workers", type=int, default=1)
    pf.add_argument("--timeout", type=int, default=60)
    pf.add_argument("--proxy")
    pf.add_argument("--output-dir")
    pf.add_argument("--user-agent")
    pf.add_argument("--raw", action="store_true")

    swe = solve_sub.add_parser("swetrix")
    swe.add_argument("--pid", "--project-id", dest="pid", help="Swetrix CAPTCHA project id; POST /generate")
    swe.add_argument("--api-url", default="https://api.swetrixcaptcha.com/v1/captcha")
    swe.add_argument("--challenge-json", help="inline /generate response JSON, or @/path")
    swe.add_argument("--challenge-file")
    swe.add_argument("--challenge-url", help="Swetrix /generate endpoint")
    swe.add_argument("--verify-url", help="Swetrix /verify endpoint")
    swe.add_argument("--validate-url", help="Swetrix /validate endpoint")
    swe.add_argument("--submit", action="store_true", help="POST solved body to /verify")
    swe.add_argument("--secret", help="optional project secret; validates token after /verify")
    swe.add_argument("--start", type=int, default=0)
    swe.add_argument("--max-attempts", type=int, default=100_000_000)
    swe.add_argument("--workers", type=int, default=1)
    swe.add_argument("--timeout", type=int, default=60)
    swe.add_argument("--proxy")
    swe.add_argument("--output-dir")
    swe.add_argument("--user-agent")
    swe.add_argument("--raw", action="store_true")

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

    yc = solve_sub.add_parser("yourcaptcha")
    yc_source = yc.add_mutually_exclusive_group(required=True)
    yc_source.add_argument("--challenge-json", help="inline JSON challenge, or @/path")
    yc_source.add_argument("--challenge-file")
    yc_source.add_argument("--challenge-url", help="yourcaptcha challenge endpoint")
    yc.add_argument("--verify-url", help="yourcaptcha verify endpoint")
    yc.add_argument("--submit", action="store_true", help="POST solved payload to --verify-url")
    yc.add_argument("--signals-json", help="inline signals JSON, or @/path; default synthesizes low-risk signals")
    yc.add_argument("--signals-file")
    yc.add_argument("--start", type=int, default=0)
    yc.add_argument("--max-attempts", type=int)
    yc.add_argument("--timeout", type=int, default=60)
    yc.add_argument("--proxy")
    yc.add_argument("--output-dir")
    yc.add_argument("--raw", action="store_true")

    sc = solve_sub.add_parser("silentchallenge")
    sc_source = sc.add_mutually_exclusive_group(required=True)
    sc_source.add_argument("--base-url", help="silent-challenge base URL")
    sc_source.add_argument("--challenge-json", help="inline JSON challenge, or @/path")
    sc_source.add_argument("--challenge-file")
    sc_source.add_argument("--challenge-url", help="POST /challenge endpoint")
    sc.add_argument("--verify-url", help="verify endpoint; supports {challengeId}")
    sc.add_argument("--submit", action="store_true", help="POST solved payload to verify endpoint")
    sc.add_argument("--motion-json", help="inline motion JSON, or @/path; default synthesizes human-like motion")
    sc.add_argument("--motion-file")
    sc.add_argument("--signals-json", help="inline navigator signals JSON, or @/path; default synthesizes low-risk signals")
    sc.add_argument("--signals-file")
    sc.add_argument("--start", type=int, default=0)
    sc.add_argument("--max-attempts", type=int)
    sc.add_argument("--timeout", type=int, default=60)
    sc.add_argument("--min-submit-ms", type=int, default=60)
    sc.add_argument("--proxy")
    sc.add_argument("--output-dir")
    sc.add_argument("--raw", action="store_true")

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

    sah = stress_sub.add_parser("activehashcash")
    sah_source = sah.add_mutually_exclusive_group(required=True)
    sah_source.add_argument("--resource")
    sah_source.add_argument("--challenge-json")
    sah_source.add_argument("--challenge-file")
    sah_source.add_argument("--challenge-html")
    sah_source.add_argument("--challenge-url")
    sah.add_argument("--submit-url")
    sah.add_argument("--submit", action="store_true")
    sah.add_argument("--submit-format", choices=["form", "json"], default="form")
    sah.add_argument("--bits", type=int)
    sah.add_argument("--date", dest="stamp_date")
    sah.add_argument("--rand")
    sah.add_argument("--response-field", default="hashcash")
    sah.add_argument("--runs", type=int, default=10)
    sah.add_argument("--concurrency", type=int, default=2)
    sah.add_argument("--timeout", type=int, default=60)
    sah.add_argument("--start", type=int, default=0)
    sah.add_argument("--max-attempts", type=int, default=100_000_000)
    sah.add_argument("--workers", type=int, default=1)
    sah.add_argument("--proxy")
    sah.add_argument("--output-dir")
    sah.add_argument("--output-json")
    sah.add_argument("--user-agent")
    sah.add_argument("--full", action="store_true")

    sbtx = stress_sub.add_parser("btx")
    sbtx_source = sbtx.add_mutually_exclusive_group(required=True)
    sbtx_source.add_argument("--challenge-json")
    sbtx_source.add_argument("--challenge-file")
    sbtx_source.add_argument("--challenge-url")
    sbtx.add_argument("--submit-url")
    sbtx.add_argument("--submit", action="store_true")
    sbtx.add_argument("--submit-method", default="POST", choices=["GET", "POST", "PUT", "PATCH"])
    sbtx.add_argument("--submit-json")
    sbtx.add_argument("--response-field", default="btx_proof")
    sbtx.add_argument("--nonce-start")
    sbtx.add_argument("--runs", type=int, default=10)
    sbtx.add_argument("--concurrency", type=int, default=2)
    sbtx.add_argument("--timeout", type=int, default=60)
    sbtx.add_argument("--max-attempts", type=int, default=1_000_000)
    sbtx.add_argument("--workers", type=int, default=1)
    sbtx.add_argument("--proxy")
    sbtx.add_argument("--output-dir")
    sbtx.add_argument("--output-json")
    sbtx.add_argument("--user-agent")
    sbtx.add_argument("--full", action="store_true")

    salt = stress_sub.add_parser("altcha")
    salt.add_argument("--challenge-url", required=True)
    salt.add_argument("--runs", type=int, default=10)
    salt.add_argument("--concurrency", type=int, default=2)
    salt.add_argument("--timeout", type=int, default=30)
    salt.add_argument("--max-number", type=int)
    salt.add_argument("--workers", type=int, default=1)
    salt.add_argument("--v2-strategy", choices=["auto", "verify-compatible", "prefix"], default="auto")
    salt.add_argument("--counter-mode", choices=["uint32", "string"], default="uint32")
    salt.add_argument("--hmac-algorithm", default="SHA-256", choices=["SHA-256", "SHA-384", "SHA-512"])
    salt.add_argument("--hmac-signature-secret")
    salt.add_argument("--hmac-key-signature-secret")
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

    sauro = stress_sub.add_parser("auro")
    sauro_source = sauro.add_mutually_exclusive_group(required=False)
    sauro_source.add_argument("--challenge-json")
    sauro_source.add_argument("--challenge-file")
    sauro_source.add_argument("--prefix")
    sauro.add_argument("--difficulty", type=int)
    sauro.add_argument("--base-url", default="https://auro.network")
    sauro.add_argument("--enckey-url")
    sauro.add_argument("--setup-url")
    sauro.add_argument("--validate-url")
    sauro.add_argument("--key-b64")
    sauro.add_argument("--mouse-json")
    sauro.add_argument("--mouse-file")
    sauro.add_argument("--mouse-points", type=int, default=50)
    sauro.add_argument("--mouse-seed")
    sauro.add_argument("--iv-b64")
    sauro.add_argument("--client-guid")
    sauro.add_argument("--no-submit", action="store_true")
    sauro.add_argument("--runs", type=int, default=10)
    sauro.add_argument("--concurrency", type=int, default=2)
    sauro.add_argument("--timeout", type=int, default=60)
    sauro.add_argument("--max-attempts", type=int, default=50_000_000)
    sauro.add_argument("--workers", type=int, default=1)
    sauro.add_argument("--proxy")
    sauro.add_argument("--output-dir")
    sauro.add_argument("--output-json")
    sauro.add_argument("--full", action="store_true")

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

    sgpc = stress_sub.add_parser("getpowcaptcha")
    sgpc_source = sgpc.add_mutually_exclusive_group(required=True)
    sgpc_source.add_argument("--app-id")
    sgpc_source.add_argument("--challenge-json")
    sgpc_source.add_argument("--challenge-file")
    sgpc_source.add_argument("--challenge-url")
    sgpc.add_argument("--backend-url", default="https://api.powcaptcha.com")
    sgpc.add_argument("--create-url")
    sgpc.add_argument("--verify-url")
    sgpc.add_argument("--secret")
    sgpc.add_argument("--verify", action="store_true")
    sgpc.add_argument("--context-json")
    sgpc.add_argument("--context-file")
    sgpc.add_argument("--signals-json")
    sgpc.add_argument("--signals-file")
    sgpc.add_argument("--fingerprint-json")
    sgpc.add_argument("--fingerprint-file")
    sgpc.add_argument("--no-gzip-create", action="store_true")
    sgpc.add_argument("--runs", type=int, default=10)
    sgpc.add_argument("--concurrency", type=int, default=2)
    sgpc.add_argument("--timeout", type=int, default=60)
    sgpc.add_argument("--max-attempts-per-problem", type=int, default=10_000_000)
    sgpc.add_argument("--workers", type=int, default=1)
    sgpc.add_argument("--proxy")
    sgpc.add_argument("--output-dir")
    sgpc.add_argument("--output-json")
    sgpc.add_argument("--full", action="store_true")

    sh33 = stress_sub.add_parser("h33botshield")
    sh33_source = sh33.add_mutually_exclusive_group(required=False)
    sh33_source.add_argument("--base-url", default="https://api.h33.ai")
    sh33_source.add_argument("--challenge-json")
    sh33_source.add_argument("--challenge-file")
    sh33_source.add_argument("--challenge-url")
    sh33.add_argument("--solve-url")
    sh33.add_argument("--challenge-body-json")
    sh33.add_argument("--challenge-body-file")
    sh33.add_argument("--submit", action="store_true")
    sh33.add_argument("--runs", type=int, default=10)
    sh33.add_argument("--concurrency", type=int, default=2)
    sh33.add_argument("--timeout", type=int, default=60)
    sh33.add_argument("--start", type=int, default=0)
    sh33.add_argument("--max-attempts", type=int, default=25_000_000)
    sh33.add_argument("--workers", type=int, default=1)
    sh33.add_argument("--proxy")
    sh33.add_argument("--output-dir")
    sh33.add_argument("--output-json")
    sh33.add_argument("--full", action="store_true")

    sbotcha = stress_sub.add_parser("botcha")
    sbotcha.add_argument("--mode", choices=["auto", "speed", "token", "standard"], default="speed")
    sbotcha.add_argument("--base-url", default="https://botcha.ai")
    sbotcha.add_argument("--app-id")
    sbotcha.add_argument("--audience")
    sbotcha.add_argument("--challenge-json")
    sbotcha.add_argument("--challenge-file")
    sbotcha.add_argument("--challenge-url")
    sbotcha.add_argument("--verify-url")
    sbotcha.add_argument("--submit", action="store_true")
    sbotcha.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    sbotcha.add_argument("--rtt-adjust", action="store_true")
    sbotcha.add_argument("--runs", type=int, default=10)
    sbotcha.add_argument("--concurrency", type=int, default=2)
    sbotcha.add_argument("--timeout", type=int, default=10)
    sbotcha.add_argument("--proxy")
    sbotcha.add_argument("--output-dir")
    sbotcha.add_argument("--output-json")
    sbotcha.add_argument("--full", action="store_true")

    sfc = stress_sub.add_parser("fcaptcha")
    sfc_source = sfc.add_mutually_exclusive_group(required=True)
    sfc_source.add_argument("--base-url")
    sfc_source.add_argument("--challenge-json")
    sfc_source.add_argument("--challenge-file")
    sfc_source.add_argument("--challenge-url")
    sfc.add_argument("--verify-url")
    sfc.add_argument("--site-key", default="default")
    sfc.add_argument("--submit", action="store_true")
    sfc.add_argument("--score-endpoint", action="store_true")
    sfc.add_argument("--signals-json")
    sfc.add_argument("--signals-file")
    sfc.add_argument("--runs", type=int, default=10)
    sfc.add_argument("--concurrency", type=int, default=2)
    sfc.add_argument("--timeout", type=int, default=60)
    sfc.add_argument("--min-submit-ms", type=int, default=1600)
    sfc.add_argument("--start", type=int, default=0)
    sfc.add_argument("--max-attempts", type=int)
    sfc.add_argument("--proxy")
    sfc.add_argument("--output-dir")
    sfc.add_argument("--output-json")
    sfc.add_argument("--full", action="store_true")

    scap = stress_sub.add_parser("cap")
    scap_source = scap.add_mutually_exclusive_group(required=True)
    scap_source.add_argument("--challenge-json")
    scap_source.add_argument("--challenge-file")
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
    scap.add_argument("--instr-json")
    scap.add_argument("--instr-file")
    scap.add_argument("--secret")
    scap.add_argument("--output-dir")
    scap.add_argument("--output-json")
    scap.add_argument("--full", action="store_true")

    scpz = stress_sub.add_parser("cryptopuzzle")
    scpz_source = scpz.add_mutually_exclusive_group(required=True)
    scpz_source.add_argument("--base-url")
    scpz_source.add_argument("--puzzle")
    scpz_source.add_argument("--puzzle-file")
    scpz_source.add_argument("--challenge-json")
    scpz_source.add_argument("--challenge-file")
    scpz_source.add_argument("--challenge-url")
    scpz.add_argument("--verify-url")
    scpz.add_argument("--submit", action="store_true")
    scpz.add_argument("--expected-message")
    scpz.add_argument("--runs", type=int, default=10)
    scpz.add_argument("--concurrency", type=int, default=2)
    scpz.add_argument("--timeout", type=int, default=60)
    scpz.add_argument("--proxy")
    scpz.add_argument("--output-dir")
    scpz.add_argument("--output-json")
    scpz.add_argument("--user-agent")
    scpz.add_argument("--full", action="store_true")

    scx = stress_sub.add_parser("captxa")
    scx_source = scx.add_mutually_exclusive_group(required=True)
    scx_source.add_argument("--base-url")
    scx_source.add_argument("--challenge-json")
    scx_source.add_argument("--challenge-file")
    scx_source.add_argument("--challenge-url")
    scx.add_argument("--solve-url")
    scx.add_argument("--submit", action="store_true")
    scx.add_argument("--metrics-json")
    scx.add_argument("--metrics-file")
    scx.add_argument("--runs", type=int, default=10)
    scx.add_argument("--concurrency", type=int, default=2)
    scx.add_argument("--timeout", type=int, default=60)
    scx.add_argument("--start", type=int, default=0)
    scx.add_argument("--max-attempts", type=int)
    scx.add_argument("--proxy")
    scx.add_argument("--output-dir")
    scx.add_argument("--user-agent")
    scx.add_argument("--timezone", default="America/New_York")
    scx.add_argument("--output-json")
    scx.add_argument("--full", action="store_true")

    scrv = stress_sub.add_parser("crovly")
    scrv_source = scrv.add_mutually_exclusive_group(required=True)
    scrv_source.add_argument("--api-url")
    scrv_source.add_argument("--challenge-json")
    scrv_source.add_argument("--challenge-file")
    scrv_source.add_argument("--challenge-url")
    scrv.add_argument("--edge-url", default="https://edge.crovly.com")
    scrv.add_argument("--verify-url")
    scrv.add_argument("--site-key")
    scrv.add_argument("--submit", action="store_true")
    scrv.add_argument("--fingerprint-hash")
    scrv.add_argument("--fingerprint-json")
    scrv.add_argument("--fingerprint-file")
    scrv.add_argument("--profile-json")
    scrv.add_argument("--profile-file")
    scrv.add_argument("--environment-json")
    scrv.add_argument("--environment-file")
    scrv.add_argument("--behavior-json")
    scrv.add_argument("--behavior-file")
    scrv.add_argument("--hold-json")
    scrv.add_argument("--hold-file")
    scrv.add_argument("--runs", type=int, default=10)
    scrv.add_argument("--concurrency", type=int, default=2)
    scrv.add_argument("--timeout", type=int, default=60)
    scrv.add_argument("--start", type=int, default=0)
    scrv.add_argument("--max-attempts", type=int, default=2**32)
    scrv.add_argument("--workers", type=int, default=1)
    scrv.add_argument("--min-submit-ms", type=int, default=0)
    scrv.add_argument("--min-solve-ms", type=int, default=0)
    scrv.add_argument("--proxy")
    scrv.add_argument("--output-dir")
    scrv.add_argument("--output-json")
    scrv.add_argument("--user-agent")
    scrv.add_argument("--full", action="store_true")

    schpio = stress_sub.add_parser("chpiopow")
    schpio_source = schpio.add_mutually_exclusive_group(required=True)
    schpio_source.add_argument("--challenge-json")
    schpio_source.add_argument("--challenge-file")
    schpio_source.add_argument("--challenge-url")
    schpio.add_argument("--redeem-url")
    schpio.add_argument("--submit", action="store_true")
    schpio.add_argument("--secret")
    schpio.add_argument("--runs", type=int, default=10)
    schpio.add_argument("--concurrency", type=int, default=2)
    schpio.add_argument("--timeout", type=int, default=60)
    schpio.add_argument("--max-attempts-per-challenge", type=int, default=50_000_000)
    schpio.add_argument("--workers", type=int, default=1)
    schpio.add_argument("--proxy")
    schpio.add_argument("--output-dir")
    schpio.add_argument("--output-json")
    schpio.add_argument("--full", action="store_true")

    simp = stress_sub.add_parser("impost")
    simp_source = simp.add_mutually_exclusive_group(required=True)
    simp_source.add_argument("--challenge-json")
    simp_source.add_argument("--challenge-file")
    simp_source.add_argument("--challenge-url")
    simp.add_argument("--verify-url")
    simp.add_argument("--submit", action="store_true")
    simp.add_argument("--runs", type=int, default=10)
    simp.add_argument("--concurrency", type=int, default=2)
    simp.add_argument("--timeout", type=int, default=60)
    simp.add_argument("--max-attempts", type=int, default=1_000_000)
    simp.add_argument("--workers", type=int, default=1)
    simp.add_argument("--proxy")
    simp.add_argument("--output-dir")
    simp.add_argument("--output-json")
    simp.add_argument("--full", action="store_true")

    skerb = stress_sub.add_parser("kerberus")
    skerb_source = skerb.add_mutually_exclusive_group(required=True)
    skerb_source.add_argument("--challenge-json")
    skerb_source.add_argument("--challenge-file")
    skerb_source.add_argument("--challenge-url")
    skerb.add_argument("--serialized-input")
    skerb.add_argument("--input-file")
    skerb.add_argument("--validate-url")
    skerb.add_argument("--submit", action="store_true")
    skerb.add_argument("--runs", type=int, default=10)
    skerb.add_argument("--concurrency", type=int, default=2)
    skerb.add_argument("--timeout", type=int, default=60)
    skerb.add_argument("--max-attempts-per-salt", type=int, default=50_000_000)
    skerb.add_argument("--workers", type=int, default=1)
    skerb.add_argument("--proxy")
    skerb.add_argument("--output-dir")
    skerb.add_argument("--output-json")
    skerb.add_argument("--full", action="store_true")

    slapti = stress_sub.add_parser("lapti")
    slapti_source = slapti.add_mutually_exclusive_group(required=True)
    slapti_source.add_argument("--base-url")
    slapti_source.add_argument("--handshake-url")
    slapti_source.add_argument("--token")
    slapti_source.add_argument("--challenge-json")
    slapti_source.add_argument("--challenge-file")
    slapti.add_argument("--data")
    slapti.add_argument("--action-url")
    slapti.add_argument("--submit", action="store_true")
    slapti.add_argument("--secret")
    slapti.add_argument("--runs", type=int, default=10)
    slapti.add_argument("--concurrency", type=int, default=2)
    slapti.add_argument("--timeout", type=int, default=60)
    slapti.add_argument("--start", type=int, default=1)
    slapti.add_argument("--max-attempts", type=int, default=100_000_000)
    slapti.add_argument("--workers", type=int, default=1)
    slapti.add_argument("--proxy")
    slapti.add_argument("--output-dir")
    slapti.add_argument("--output-json")
    slapti.add_argument("--user-agent")
    slapti.add_argument("--full", action="store_true")

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

    spp = stress_sub.add_parser("paulpow")
    spp_source = spp.add_mutually_exclusive_group(required=True)
    spp_source.add_argument("--challenge-json")
    spp_source.add_argument("--challenge-file")
    spp_source.add_argument("--challenge-url")
    spp.add_argument("--verify-url")
    spp.add_argument("--submit", action="store_true")
    spp.add_argument("--runs", type=int, default=10)
    spp.add_argument("--concurrency", type=int, default=2)
    spp.add_argument("--timeout", type=int, default=60)
    spp.add_argument("--max-attempts", type=int)
    spp.add_argument("--workers", type=int, default=1)
    spp.add_argument("--proxy")
    spp.add_argument("--output-dir")
    spp.add_argument("--output-json")
    spp.add_argument("--full", action="store_true")

    sgl = stress_sub.add_parser("gunslol")
    sgl_source = sgl.add_mutually_exclusive_group(required=True)
    sgl_source.add_argument("--challenge-json")
    sgl_source.add_argument("--challenge-file")
    sgl_source.add_argument("--challenge-url")
    sgl_source.add_argument("--page-url")
    sgl.add_argument("--verify-url")
    sgl.add_argument("--submit", action="store_true")
    sgl.add_argument("--runs", type=int, default=10)
    sgl.add_argument("--concurrency", type=int, default=2)
    sgl.add_argument("--timeout", type=int, default=60)
    sgl.add_argument("--start", type=int, default=0)
    sgl.add_argument("--max-attempts", type=int)
    sgl.add_argument("--workers", type=int, default=1)
    sgl.add_argument("--proxy")
    sgl.add_argument("--output-dir")
    sgl.add_argument("--output-json")
    sgl.add_argument("--full", action="store_true")

    shg = stress_sub.add_parser("hashguard")
    shg_source = shg.add_mutually_exclusive_group(required=True)
    shg_source.add_argument("--base-url")
    shg_source.add_argument("--challenge-json")
    shg_source.add_argument("--challenge-file")
    shg_source.add_argument("--challenge-url")
    shg.add_argument("--route-prefix", default="v1")
    shg.add_argument("--context")
    shg.add_argument("--verify-url")
    shg.add_argument("--introspect-url")
    shg.add_argument("--submit", action="store_true")
    shg.add_argument("--introspect", action="store_true")
    shg.add_argument("--no-consume", dest="consume", action="store_false", default=True)
    shg.add_argument("--runs", type=int, default=10)
    shg.add_argument("--concurrency", type=int, default=2)
    shg.add_argument("--timeout", type=int, default=60)
    shg.add_argument("--start", type=int, default=0)
    shg.add_argument("--max-attempts", type=int, default=200_000_000)
    shg.add_argument("--workers", type=int, default=1)
    shg.add_argument("--min-solve-ms", type=int, default=0)
    shg.add_argument("--proxy")
    shg.add_argument("--output-dir")
    shg.add_argument("--output-json")
    shg.add_argument("--user-agent")
    shg.add_argument("--full", action="store_true")

    stc = stress_sub.add_parser("trustcaptcha")
    stc_source = stc.add_mutually_exclusive_group(required=True)
    stc_source.add_argument("--site-key")
    stc_source.add_argument("--challenge-json")
    stc_source.add_argument("--challenge-file")
    stc.add_argument("--api-url", default="https://api.trustcomponent.com")
    stc.add_argument("--target-url", default="https://example.com/")
    stc.add_argument("--create-url")
    stc.add_argument("--submit-url")
    stc.add_argument("--create-body-json")
    stc.add_argument("--create-body-file")
    stc.add_argument("--submit", dest="submit", action="store_true", default=None)
    stc.add_argument("--no-submit", dest="submit", action="store_false")
    stc.add_argument("--runs", type=int, default=10)
    stc.add_argument("--concurrency", type=int, default=2)
    stc.add_argument("--timeout", type=int, default=60)
    stc.add_argument("--max-rounds", type=int, default=3)
    stc.add_argument("--start", type=int, default=0)
    stc.add_argument("--max-attempts-per-task", type=int, default=20_000_000)
    stc.add_argument("--workers", type=int, default=1)
    stc.add_argument("--min-solve-ms", type=int, default=1200)
    stc.add_argument("--minimal-data-mode", action="store_true")
    stc.add_argument("--bypass-token")
    stc.add_argument("--framework", default="other")
    stc.add_argument("--language", default="en-US")
    stc.add_argument("--theme", default="light")
    stc.add_argument("--proxy")
    stc.add_argument("--output-dir")
    stc.add_argument("--output-json")
    stc.add_argument("--user-agent")
    stc.add_argument("--full", action="store_true")

    sscap = stress_sub.add_parser("stravcaptcha")
    sscap_source = sscap.add_mutually_exclusive_group(required=True)
    sscap_source.add_argument("--token")
    sscap_source.add_argument("--challenge-json")
    sscap_source.add_argument("--challenge-file")
    sscap_source.add_argument("--challenge-html")
    sscap_source.add_argument("--challenge-url")
    sscap.add_argument("--submit-url")
    sscap.add_argument("--submit", action="store_true")
    sscap.add_argument("--secret")
    sscap.add_argument("--runs", type=int, default=10)
    sscap.add_argument("--concurrency", type=int, default=2)
    sscap.add_argument("--timeout", type=int, default=60)
    sscap.add_argument("--start", type=int, default=0)
    sscap.add_argument("--max-attempts", type=int, default=100_000_000)
    sscap.add_argument("--workers", type=int, default=1)
    sscap.add_argument("--token-field", default="_captcha")
    sscap.add_argument("--response-field", default="_captcha_answer")
    sscap.add_argument("--honeypot-field", default="website")
    sscap.add_argument("--proxy")
    sscap.add_argument("--output-dir")
    sscap.add_argument("--output-json")
    sscap.add_argument("--user-agent")
    sscap.add_argument("--full", action="store_true")

    sjnc = stress_sub.add_parser("justnocaptcha")
    sjnc_source = sjnc.add_mutually_exclusive_group(required=True)
    sjnc_source.add_argument("--challenge")
    sjnc_source.add_argument("--challenge-json")
    sjnc_source.add_argument("--challenge-file")
    sjnc_source.add_argument("--challenge-html")
    sjnc_source.add_argument("--challenge-url")
    sjnc.add_argument("--submit-url")
    sjnc.add_argument("--submit", action="store_true")
    sjnc.add_argument("--challenge-salt")
    sjnc.add_argument("--runs", type=int, default=10)
    sjnc.add_argument("--concurrency", type=int, default=2)
    sjnc.add_argument("--timeout", type=int, default=60)
    sjnc.add_argument("--start", type=int)
    sjnc.add_argument("--max-attempts-per-puzzle", type=int)
    sjnc.add_argument("--workers", type=int, default=1)
    sjnc.add_argument("--challenge-field", default="challenge")
    sjnc.add_argument("--response-field", default="solution")
    sjnc.add_argument("--proxy")
    sjnc.add_argument("--output-dir")
    sjnc.add_argument("--output-json")
    sjnc.add_argument("--user-agent")
    sjnc.add_argument("--full", action="store_true")

    scapy = stress_sub.add_parser("capybara")
    scapy_source = scapy.add_mutually_exclusive_group(required=True)
    scapy_source.add_argument("--base-url")
    scapy_source.add_argument("--challenge-json")
    scapy_source.add_argument("--challenge-file")
    scapy_source.add_argument("--challenge-url")
    scapy_source.add_argument("--payload-token")
    scapy.add_argument("--verify-url")
    scapy.add_argument("--submit", action="store_true")
    scapy.add_argument("--difficulty", type=int, default=3)
    scapy.add_argument("--duration-sec", type=int, default=30)
    scapy.add_argument("--secret")
    scapy.add_argument("--instance-id", default="guest")
    scapy.add_argument("--runs", type=int, default=10)
    scapy.add_argument("--concurrency", type=int, default=2)
    scapy.add_argument("--timeout", type=int, default=60)
    scapy.add_argument("--start", type=int, default=0)
    scapy.add_argument("--max-attempts", type=int, default=100_000_000)
    scapy.add_argument("--workers", type=int, default=1)
    scapy.add_argument("--proxy")
    scapy.add_argument("--output-dir")
    scapy.add_argument("--output-json")
    scapy.add_argument("--user-agent")
    scapy.add_argument("--full", action="store_true")

    svul = stress_sub.add_parser("vulcan")
    svul_source = svul.add_mutually_exclusive_group(required=True)
    svul_source.add_argument("--challenge-json")
    svul_source.add_argument("--challenge-file")
    svul_source.add_argument("--challenge-html")
    svul_source.add_argument("--challenge-url")
    svul.add_argument("--runs", type=int, default=10)
    svul.add_argument("--concurrency", type=int, default=2)
    svul.add_argument("--timeout", type=int, default=60)
    svul.add_argument("--start", type=int, default=1)
    svul.add_argument("--max-attempts-per-round", type=int, default=1_000_000_000)
    svul.add_argument("--workers", type=int, default=1)
    svul.add_argument("--response-field", default="captcha-response")
    svul.add_argument("--proxy")
    svul.add_argument("--output-dir")
    svul.add_argument("--output-json")
    svul.add_argument("--user-agent")
    svul.add_argument("--full", action="store_true")

    sspw = stress_sub.add_parser("spow")
    sspw_source = sspw.add_mutually_exclusive_group(required=True)
    sspw_source.add_argument("--challenge")
    sspw_source.add_argument("--challenge-json")
    sspw_source.add_argument("--challenge-file")
    sspw_source.add_argument("--challenge-html")
    sspw_source.add_argument("--challenge-url")
    sspw.add_argument("--verify-url")
    sspw.add_argument("--submit", action="store_true")
    sspw.add_argument("--submit-format", choices=["json", "form"], default="json")
    sspw.add_argument("--secret")
    sspw.add_argument("--runs", type=int, default=10)
    sspw.add_argument("--concurrency", type=int, default=2)
    sspw.add_argument("--timeout", type=int, default=60)
    sspw.add_argument("--start", type=int, default=0)
    sspw.add_argument("--max-attempts", type=int, default=100_000_000)
    sspw.add_argument("--workers", type=int, default=1)
    sspw.add_argument("--response-field", default="pow")
    sspw.add_argument("--proxy")
    sspw.add_argument("--output-dir")
    sspw.add_argument("--output-json")
    sspw.add_argument("--user-agent")
    sspw.add_argument("--full", action="store_true")

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

    spowbot = stress_sub.add_parser("powbot")
    spowbot_source = spowbot.add_mutually_exclusive_group(required=True)
    spowbot_source.add_argument("--base-url")
    spowbot_source.add_argument("--challenge")
    spowbot_source.add_argument("--challenge-json")
    spowbot_source.add_argument("--challenge-file")
    spowbot_source.add_argument("--challenges-url")
    spowbot.add_argument("--verify-url")
    spowbot.add_argument("--api-token")
    spowbot.add_argument("--difficulty-level", type=int, default=5)
    spowbot.add_argument("--batch-index", type=int, default=0)
    spowbot.add_argument("--submit", action="store_true")
    spowbot.add_argument("--runs", type=int, default=10)
    spowbot.add_argument("--concurrency", type=int, default=2)
    spowbot.add_argument("--timeout", type=int, default=60)
    spowbot.add_argument("--start", type=int, default=0)
    spowbot.add_argument("--max-attempts", type=int)
    spowbot.add_argument("--workers", type=int, default=1)
    spowbot.add_argument("--proxy")
    spowbot.add_argument("--output-dir")
    spowbot.add_argument("--output-json")
    spowbot.add_argument("--full", action="store_true")

    spowch = stress_sub.add_parser("powchallenge")
    spowch_source = spowch.add_mutually_exclusive_group(required=True)
    spowch_source.add_argument("--base-url")
    spowch_source.add_argument("--challenge-json")
    spowch_source.add_argument("--challenge-file")
    spowch_source.add_argument("--challenge-url")
    spowch.add_argument("--verify-url")
    spowch.add_argument("--submit", action="store_true")
    spowch.add_argument("--runs", type=int, default=10)
    spowch.add_argument("--concurrency", type=int, default=2)
    spowch.add_argument("--timeout", type=int, default=60)
    spowch.add_argument("--start", type=int, default=0)
    spowch.add_argument("--max-attempts", type=int, default=100_000)
    spowch.add_argument("--workers", type=int, default=1)
    spowch.add_argument("--nonce-seed")
    spowch.add_argument("--nonce-length", type=int, default=32)
    spowch.add_argument("--proxy")
    spowch.add_argument("--output-dir")
    spowch.add_argument("--output-json")
    spowch.add_argument("--user-agent")
    spowch.add_argument("--full", action="store_true")

    spowr = stress_sub.add_parser("powreaction")
    spowr_source = spowr.add_mutually_exclusive_group(required=True)
    spowr_source.add_argument("--base-url")
    spowr_source.add_argument("--challenge")
    spowr_source.add_argument("--challenge-json")
    spowr_source.add_argument("--challenge-file")
    spowr_source.add_argument("--challenge-url")
    spowr.add_argument("--submit-url")
    spowr.add_argument("--reaction")
    spowr.add_argument("--submit", action="store_true")
    spowr.add_argument("--secret")
    spowr.add_argument("--runs", type=int, default=10)
    spowr.add_argument("--concurrency", type=int, default=2)
    spowr.add_argument("--timeout", type=int, default=60)
    spowr.add_argument("--max-attempts-per-round", type=int, default=50_000_000)
    spowr.add_argument("--workers", type=int, default=1)
    spowr.add_argument("--proxy")
    spowr.add_argument("--output-dir")
    spowr.add_argument("--output-json")
    spowr.add_argument("--user-agent")
    spowr.add_argument("--full", action="store_true")

    sproc = stress_sub.add_parser("procaptcha")
    sproc_source = sproc.add_mutually_exclusive_group(required=True)
    sproc_source.add_argument("--provider-url")
    sproc_source.add_argument("--challenge-json")
    sproc_source.add_argument("--challenge-file")
    sproc_source.add_argument("--challenge-url")
    sproc.add_argument("--submit-url")
    sproc.add_argument("--site-key")
    sproc.add_argument("--user")
    sproc.add_argument("--dapp")
    sproc.add_argument("--session-id")
    sproc.add_argument("--submit", action="store_true")
    sproc.add_argument("--user-timestamp-signature")
    sproc.add_argument("--verified-timeout", type=int, default=120_000)
    sproc.add_argument("--provider-challenge-signature")
    sproc.add_argument("--behavioral-data")
    sproc.add_argument("--salt")
    sproc.add_argument("--simd-readings")
    sproc.add_argument("--client-meta-json")
    sproc.add_argument("--client-meta-file")
    sproc.add_argument("--include-timestamp", action="store_true")
    sproc.add_argument("--runs", type=int, default=10)
    sproc.add_argument("--concurrency", type=int, default=2)
    sproc.add_argument("--timeout", type=int, default=60)
    sproc.add_argument("--start", type=int, default=0)
    sproc.add_argument("--max-attempts", type=int, default=100_000_000)
    sproc.add_argument("--workers", type=int, default=1)
    sproc.add_argument("--proxy")
    sproc.add_argument("--output-dir")
    sproc.add_argument("--output-json")
    sproc.add_argument("--user-agent")
    sproc.add_argument("--full", action="store_true")

    stb = stress_sub.add_parser("tollbooth")
    stb_source = stb.add_mutually_exclusive_group(required=True)
    stb_source.add_argument("--base-url")
    stb_source.add_argument("--challenge-json")
    stb_source.add_argument("--challenge-file")
    stb_source.add_argument("--challenge-url")
    stb.add_argument("--verify-url")
    stb.add_argument("--submit", action="store_true")
    stb.add_argument("--navigator-strategy", choices=["empty", "minimal"], default="empty")
    stb.add_argument("--runs", type=int, default=10)
    stb.add_argument("--concurrency", type=int, default=2)
    stb.add_argument("--timeout", type=int, default=60)
    stb.add_argument("--start", type=int, default=0)
    stb.add_argument("--max-attempts", type=int, default=1_000_000)
    stb.add_argument("--workers", type=int, default=1)
    stb.add_argument("--proxy")
    stb.add_argument("--output-dir")
    stb.add_argument("--output-json")
    stb.add_argument("--user-agent")
    stb.add_argument("--full", action="store_true")

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

    spf = stress_sub.add_parser("powforge")
    spf_source = spf.add_mutually_exclusive_group(required=False)
    spf_source.add_argument("--base-url", default=None)
    spf_source.add_argument("--challenge-url")
    spf_source.add_argument("--challenge-json")
    spf_source.add_argument("--challenge-file")
    spf_source.add_argument("--salt")
    spf.add_argument("--verify-url")
    spf.add_argument("--token-verify-url")
    spf.add_argument("--difficulty", type=int)
    spf.add_argument("--response-field", default="pf_token")
    spf.add_argument("--no-submit", action="store_true")
    spf.add_argument("--token-verify", action="store_true")
    spf.add_argument("--runs", type=int, default=10)
    spf.add_argument("--concurrency", type=int, default=2)
    spf.add_argument("--timeout", type=int, default=60)
    spf.add_argument("--start", type=int, default=1)
    spf.add_argument("--max-attempts", type=int, default=100_000_000)
    spf.add_argument("--workers", type=int, default=1)
    spf.add_argument("--proxy")
    spf.add_argument("--output-dir")
    spf.add_argument("--output-json")
    spf.add_argument("--user-agent")
    spf.add_argument("--full", action="store_true")

    sswe = stress_sub.add_parser("swetrix")
    sswe.add_argument("--pid", "--project-id", dest="pid")
    sswe.add_argument("--api-url", default="https://api.swetrixcaptcha.com/v1/captcha")
    sswe.add_argument("--challenge-json")
    sswe.add_argument("--challenge-file")
    sswe.add_argument("--challenge-url")
    sswe.add_argument("--verify-url")
    sswe.add_argument("--validate-url")
    sswe.add_argument("--submit", action="store_true")
    sswe.add_argument("--secret")
    sswe.add_argument("--runs", type=int, default=10)
    sswe.add_argument("--concurrency", type=int, default=2)
    sswe.add_argument("--timeout", type=int, default=60)
    sswe.add_argument("--max-attempts", type=int, default=100_000_000)
    sswe.add_argument("--workers", type=int, default=1)
    sswe.add_argument("--proxy")
    sswe.add_argument("--output-dir")
    sswe.add_argument("--output-json")
    sswe.add_argument("--user-agent")
    sswe.add_argument("--full", action="store_true")

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

    syc = stress_sub.add_parser("yourcaptcha")
    syc_source = syc.add_mutually_exclusive_group(required=True)
    syc_source.add_argument("--challenge-json")
    syc_source.add_argument("--challenge-file")
    syc_source.add_argument("--challenge-url")
    syc.add_argument("--verify-url")
    syc.add_argument("--submit", action="store_true")
    syc.add_argument("--signals-json")
    syc.add_argument("--signals-file")
    syc.add_argument("--runs", type=int, default=10)
    syc.add_argument("--concurrency", type=int, default=2)
    syc.add_argument("--timeout", type=int, default=60)
    syc.add_argument("--start", type=int, default=0)
    syc.add_argument("--max-attempts", type=int)
    syc.add_argument("--proxy")
    syc.add_argument("--output-dir")
    syc.add_argument("--output-json")
    syc.add_argument("--full", action="store_true")

    ssc = stress_sub.add_parser("silentchallenge")
    ssc_source = ssc.add_mutually_exclusive_group(required=True)
    ssc_source.add_argument("--base-url")
    ssc_source.add_argument("--challenge-json")
    ssc_source.add_argument("--challenge-file")
    ssc_source.add_argument("--challenge-url")
    ssc.add_argument("--verify-url")
    ssc.add_argument("--submit", action="store_true")
    ssc.add_argument("--motion-json")
    ssc.add_argument("--motion-file")
    ssc.add_argument("--signals-json")
    ssc.add_argument("--signals-file")
    ssc.add_argument("--runs", type=int, default=10)
    ssc.add_argument("--concurrency", type=int, default=2)
    ssc.add_argument("--timeout", type=int, default=60)
    ssc.add_argument("--min-submit-ms", type=int, default=60)
    ssc.add_argument("--start", type=int, default=0)
    ssc.add_argument("--max-attempts", type=int)
    ssc.add_argument("--proxy")
    ssc.add_argument("--output-dir")
    ssc.add_argument("--output-json")
    ssc.add_argument("--full", action="store_true")

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
            "activehashcash",
            "btx",
            "cap",
            "cryptopuzzle",
            "captxa",
            "crovly",
            "fcaptcha",
            "chpiopow",
            "auro",
            "gunslol",
            "hashguard",
            "trustcaptcha",
            "stravcaptcha",
            "justnocaptcha",
            "capybara",
            "vulcan",
            "spow",
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
    if args.cmd == "solve" and args.provider == "activehashcash":
        ret = await client.solve_activehashcash(
            resource=args.resource,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_html=args.challenge_html,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            submit=args.submit,
            submit_format=args.submit_format,
            bits=args.bits,
            stamp_date=args.stamp_date,
            rand=args.rand,
            response_field=args.response_field,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "btx":
        ret = await client.solve_btx(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            submit=args.submit,
            submit_method=args.submit_method,
            submit_json=args.submit_json,
            response_field=args.response_field,
            nonce_start=args.nonce_start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
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
            v2_strategy=args.v2_strategy,
            counter_mode=args.counter_mode,
            hmac_algorithm=args.hmac_algorithm,
            hmac_signature_secret=args.hmac_signature_secret,
            hmac_key_signature_secret=args.hmac_key_signature_secret,
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
    if args.cmd == "solve" and args.provider == "auro":
        ret = await client.solve_auro(
            base_url=args.base_url,
            enckey_url=args.enckey_url,
            setup_url=args.setup_url,
            validate_url=args.validate_url,
            key_b64=args.key_b64,
            prefix=args.prefix,
            difficulty=args.difficulty,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            mouse_json=args.mouse_json,
            mouse_file=args.mouse_file,
            mouse_points=args.mouse_points,
            mouse_seed=args.mouse_seed,
            iv_b64=args.iv_b64,
            client_guid=args.client_guid,
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
    if args.cmd == "solve" and args.provider == "impost":
        ret = await client.solve_impost(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
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
    if args.cmd == "solve" and args.provider == "kerberus":
        ret = await client.solve_kerberus(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            serialized_input=args.serialized_input,
            input_file=args.input_file,
            validate_url=args.validate_url,
            submit=args.submit,
            start=args.start,
            max_attempts_per_salt=args.max_attempts_per_salt,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "lapti":
        ret = await client.solve_lapti(
            data=args.data,
            token=args.token,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            base_url=args.base_url,
            handshake_url=args.handshake_url,
            action_url=args.action_url,
            submit=args.submit,
            secret=args.secret,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
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
    if args.cmd == "solve" and args.provider == "getpowcaptcha":
        ret = await client.solve_getpowcaptcha(
            app_id=args.app_id,
            backend_url=args.backend_url,
            create_url=args.create_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            secret=args.secret,
            verify=args.verify,
            context_json=args.context_json,
            context_file=args.context_file,
            signals_json=args.signals_json,
            signals_file=args.signals_file,
            fingerprint_json=args.fingerprint_json,
            fingerprint_file=args.fingerprint_file,
            gzip_create=not args.no_gzip_create,
            start=args.start,
            max_attempts_per_problem=args.max_attempts_per_problem,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "h33botshield":
        ret = await client.solve_h33botshield(
            base_url=args.base_url,
            challenge_url=args.challenge_url,
            solve_url=args.solve_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_body_json=args.challenge_body_json,
            challenge_body_file=args.challenge_body_file,
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
    if args.cmd == "solve" and args.provider == "botcha":
        ret = await client.solve_botcha(
            mode=args.mode,
            base_url=args.base_url,
            app_id=args.app_id,
            audience=args.audience,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            difficulty=args.difficulty,
            rtt_adjust=args.rtt_adjust,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "fcaptcha":
        ret = await client.solve_fcaptcha(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            site_key=args.site_key,
            submit=args.submit,
            score_endpoint=args.score_endpoint,
            signals_json=args.signals_json,
            signals_file=args.signals_file,
            start=args.start,
            max_attempts=args.max_attempts,
            timeout_sec=args.timeout,
            min_submit_ms=args.min_submit_ms,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
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
            instr_json=args.instr_json,
            instr_file=args.instr_file,
            secret=args.secret,
            start=args.start,
            max_attempts_per_challenge=args.max_attempts_per_challenge,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "cryptopuzzle":
        ret = await client.solve_cryptopuzzle(
            base_url=args.base_url,
            puzzle=args.puzzle,
            puzzle_file=args.puzzle_file,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            expected_message=args.expected_message,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "captxa":
        ret = await client.solve_captxa(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            solve_url=args.solve_url,
            submit=args.submit,
            metrics_json=args.metrics_json,
            metrics_file=args.metrics_file,
            start=args.start,
            max_attempts=args.max_attempts,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
            timezone_id=args.timezone,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "crovly":
        ret = await client.solve_crovly(
            site_key=args.site_key,
            api_url=args.api_url,
            edge_url=args.edge_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            fingerprint_hash=args.fingerprint_hash,
            fingerprint_json=args.fingerprint_json,
            fingerprint_file=args.fingerprint_file,
            profile_json=args.profile_json,
            profile_file=args.profile_file,
            environment_json=args.environment_json,
            environment_file=args.environment_file,
            behavior_json=args.behavior_json,
            behavior_file=args.behavior_file,
            hold_json=args.hold_json,
            hold_file=args.hold_file,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            min_submit_ms=args.min_submit_ms,
            min_solve_ms=args.min_solve_ms,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "chpiopow":
        ret = await client.solve_chpiopow(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            redeem_url=args.redeem_url,
            submit=args.submit,
            secret=args.secret,
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
    if args.cmd == "solve" and args.provider == "paulpow":
        ret = await client.solve_paulpow(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
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
    if args.cmd == "solve" and args.provider == "gunslol":
        ret = await client.solve_gunslol(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            page_url=args.page_url,
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
    if args.cmd == "solve" and args.provider == "hashguard":
        ret = await client.solve_hashguard(
            base_url=args.base_url,
            route_prefix=args.route_prefix,
            context=args.context,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            introspect_url=args.introspect_url,
            submit=args.submit,
            introspect=args.introspect,
            consume=args.consume,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            min_solve_ms=args.min_solve_ms,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "trustcaptcha":
        ret = await client.solve_trustcaptcha(
            site_key=args.site_key,
            api_url=args.api_url,
            target_url=args.target_url,
            create_url=args.create_url,
            submit_url=args.submit_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            create_body_json=args.create_body_json,
            create_body_file=args.create_body_file,
            submit=args.submit,
            max_rounds=args.max_rounds,
            start=args.start,
            max_attempts_per_task=args.max_attempts_per_task,
            workers=args.workers,
            timeout_sec=args.timeout,
            min_solve_ms=args.min_solve_ms,
            minimal_data_mode=args.minimal_data_mode,
            bypass_token=args.bypass_token,
            framework=args.framework,
            language=args.language,
            theme=args.theme,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "stravcaptcha":
        ret = await client.solve_stravcaptcha(
            token=args.token,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_html=args.challenge_html,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            submit=args.submit,
            secret=args.secret,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            token_field=args.token_field,
            response_field=args.response_field,
            honeypot_field=args.honeypot_field,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "justnocaptcha":
        ret = await client.solve_justnocaptcha(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_html=args.challenge_html,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            submit=args.submit,
            challenge_salt=args.challenge_salt,
            start=args.start,
            max_attempts_per_puzzle=args.max_attempts_per_puzzle,
            workers=args.workers,
            timeout_sec=args.timeout,
            challenge_field=args.challenge_field,
            response_field=args.response_field,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "capybara":
        ret = await client.solve_capybara(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            payload_token=args.payload_token,
            submit=args.submit,
            difficulty=args.difficulty,
            duration_sec=args.duration_sec,
            secret=args.secret,
            instance_id=args.instance_id,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "vulcan":
        ret = await client.solve_vulcan(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_html=args.challenge_html,
            challenge_url=args.challenge_url,
            start=args.start,
            max_attempts_per_round=args.max_attempts_per_round,
            workers=args.workers,
            timeout_sec=args.timeout,
            response_field=args.response_field,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "spow":
        ret = await client.solve_spow(
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_html=args.challenge_html,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            submit_format=args.submit_format,
            secret=args.secret,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            response_field=args.response_field,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
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
    if args.cmd == "solve" and args.provider == "powbot":
        ret = await client.solve_powbot(
            base_url=args.base_url,
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenges_url=args.challenges_url,
            verify_url=args.verify_url,
            api_token=args.api_token,
            difficulty_level=args.difficulty_level,
            batch_index=args.batch_index,
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
    if args.cmd == "solve" and args.provider == "powchallenge":
        ret = await client.solve_powchallenge(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            nonce_seed=args.nonce_seed,
            nonce_length=args.nonce_length,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "powreaction":
        ret = await client.solve_powreaction(
            base_url=args.base_url,
            challenge=args.challenge,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            reaction=args.reaction,
            submit=args.submit,
            secret=args.secret,
            max_attempts_per_round=args.max_attempts_per_round,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "procaptcha":
        ret = await client.solve_procaptcha(
            provider_url=args.provider_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            submit_url=args.submit_url,
            site_key=args.site_key,
            user=args.user,
            dapp=args.dapp,
            session_id=args.session_id,
            submit=args.submit,
            user_timestamp_signature=args.user_timestamp_signature,
            verified_timeout=args.verified_timeout,
            provider_challenge_signature=args.provider_challenge_signature,
            behavioral_data=args.behavioral_data,
            salt=args.salt,
            simd_readings=args.simd_readings,
            client_meta_json=args.client_meta_json,
            client_meta_file=args.client_meta_file,
            include_timestamp=args.include_timestamp,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "tollbooth":
        ret = await client.solve_tollbooth(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            navigator_strategy=args.navigator_strategy,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
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
    if args.cmd == "solve" and args.provider == "powforge":
        ret = await client.solve_powforge(
            base_url=args.base_url,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            token_verify_url=args.token_verify_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            salt=args.salt,
            difficulty=args.difficulty,
            response_field=args.response_field,
            submit=not args.no_submit,
            token_verify=args.token_verify,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "swetrix":
        ret = await client.solve_swetrix(
            pid=args.pid,
            api_url=args.api_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            validate_url=args.validate_url,
            submit=args.submit,
            secret=args.secret,
            start=args.start,
            max_attempts=args.max_attempts,
            workers=args.workers,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
            user_agent=args.user_agent,
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
    if args.cmd == "solve" and args.provider == "yourcaptcha":
        ret = await client.solve_yourcaptcha(
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            signals_json=args.signals_json,
            signals_file=args.signals_file,
            start=args.start,
            max_attempts=args.max_attempts,
            timeout_sec=args.timeout,
            proxy_server=args.proxy,
            output_dir=args.output_dir,
        )
        emit(ret, include_raw=args.raw)
        return 0 if ret.ok else 2
    if args.cmd == "solve" and args.provider == "silentchallenge":
        ret = await client.solve_silentchallenge(
            base_url=args.base_url,
            challenge_json=args.challenge_json,
            challenge_file=args.challenge_file,
            challenge_url=args.challenge_url,
            verify_url=args.verify_url,
            submit=args.submit,
            motion_json=args.motion_json,
            motion_file=args.motion_file,
            signals_json=args.signals_json,
            signals_file=args.signals_file,
            start=args.start,
            max_attempts=args.max_attempts,
            timeout_sec=args.timeout,
            min_submit_ms=args.min_submit_ms,
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
    if args.cmd == "stress" and args.provider == "activehashcash":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="activehashcash",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_activehashcash(
                resource=args.resource,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_html=args.challenge_html,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                submit=args.submit,
                submit_format=args.submit_format,
                bits=args.bits,
                stamp_date=args.stamp_date,
                rand=args.rand,
                response_field=args.response_field,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "btx":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="btx",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_btx(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                submit=args.submit,
                submit_method=args.submit_method,
                submit_json=args.submit_json,
                response_field=args.response_field,
                nonce_start=args.nonce_start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
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
                v2_strategy=args.v2_strategy,
                counter_mode=args.counter_mode,
                hmac_algorithm=args.hmac_algorithm,
                hmac_signature_secret=args.hmac_signature_secret,
                hmac_key_signature_secret=args.hmac_key_signature_secret,
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
    if args.cmd == "stress" and args.provider == "auro":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="auro",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_auro(
                base_url=args.base_url,
                enckey_url=args.enckey_url,
                setup_url=args.setup_url,
                validate_url=args.validate_url,
                key_b64=args.key_b64,
                prefix=args.prefix,
                difficulty=args.difficulty,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                mouse_json=args.mouse_json,
                mouse_file=args.mouse_file,
                mouse_points=args.mouse_points,
                mouse_seed=args.mouse_seed,
                iv_b64=args.iv_b64,
                client_guid=args.client_guid,
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
    if args.cmd == "stress" and args.provider == "impost":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="impost",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_impost(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
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
    if args.cmd == "stress" and args.provider == "kerberus":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="kerberus",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_kerberus(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                serialized_input=args.serialized_input,
                input_file=args.input_file,
                validate_url=args.validate_url,
                submit=args.submit,
                max_attempts_per_salt=args.max_attempts_per_salt,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "lapti":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="lapti",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_lapti(
                data=args.data,
                token=args.token,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                base_url=args.base_url,
                handshake_url=args.handshake_url,
                action_url=args.action_url,
                submit=args.submit,
                secret=args.secret,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
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
    if args.cmd == "stress" and args.provider == "getpowcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="getpowcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_getpowcaptcha(
                app_id=args.app_id,
                backend_url=args.backend_url,
                create_url=args.create_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                secret=args.secret,
                verify=args.verify,
                context_json=args.context_json,
                context_file=args.context_file,
                signals_json=args.signals_json,
                signals_file=args.signals_file,
                fingerprint_json=args.fingerprint_json,
                fingerprint_file=args.fingerprint_file,
                gzip_create=not args.no_gzip_create,
                max_attempts_per_problem=args.max_attempts_per_problem,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "h33botshield":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="h33botshield",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_h33botshield(
                base_url=args.base_url,
                challenge_url=args.challenge_url,
                solve_url=args.solve_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_body_json=args.challenge_body_json,
                challenge_body_file=args.challenge_body_file,
                submit=args.submit,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "botcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="botcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_botcha(
                mode=args.mode,
                base_url=args.base_url,
                app_id=args.app_id,
                audience=args.audience,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                difficulty=args.difficulty,
                rtt_adjust=args.rtt_adjust,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "fcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="fcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + max(3, int(args.min_submit_ms / 1000) + 2),
            output_json=args.output_json,
            run_once=lambda i: client.solve_fcaptcha(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                site_key=args.site_key,
                submit=args.submit,
                score_endpoint=args.score_endpoint,
                signals_json=args.signals_json,
                signals_file=args.signals_file,
                start=args.start,
                max_attempts=args.max_attempts,
                timeout_sec=args.timeout,
                min_submit_ms=args.min_submit_ms,
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
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                api_endpoint=args.api_endpoint,
                redeem_url=args.redeem_url,
                redeem=args.redeem,
                instr_json=args.instr_json,
                instr_file=args.instr_file,
                secret=args.secret,
                max_attempts_per_challenge=args.max_attempts_per_challenge,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "cryptopuzzle":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="cryptopuzzle",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_cryptopuzzle(
                base_url=args.base_url,
                puzzle=args.puzzle,
                puzzle_file=args.puzzle_file,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                expected_message=args.expected_message,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "captxa":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="captxa",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_captxa(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                solve_url=args.solve_url,
                submit=args.submit,
                metrics_json=args.metrics_json,
                metrics_file=args.metrics_file,
                start=args.start,
                max_attempts=args.max_attempts,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
                timezone_id=args.timezone,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "crovly":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="crovly",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_crovly(
                site_key=args.site_key,
                api_url=args.api_url,
                edge_url=args.edge_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                fingerprint_hash=args.fingerprint_hash,
                fingerprint_json=args.fingerprint_json,
                fingerprint_file=args.fingerprint_file,
                profile_json=args.profile_json,
                profile_file=args.profile_file,
                environment_json=args.environment_json,
                environment_file=args.environment_file,
                behavior_json=args.behavior_json,
                behavior_file=args.behavior_file,
                hold_json=args.hold_json,
                hold_file=args.hold_file,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                min_submit_ms=args.min_submit_ms,
                min_solve_ms=args.min_solve_ms,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "chpiopow":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="chpiopow",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_chpiopow(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                redeem_url=args.redeem_url,
                submit=args.submit,
                secret=args.secret,
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
    if args.cmd == "stress" and args.provider == "paulpow":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="paulpow",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_paulpow(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
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
    if args.cmd == "stress" and args.provider == "gunslol":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="gunslol",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_gunslol(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                page_url=args.page_url,
                verify_url=args.verify_url,
                submit=args.submit,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "hashguard":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="hashguard",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_hashguard(
                base_url=args.base_url,
                route_prefix=args.route_prefix,
                context=args.context,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                introspect_url=args.introspect_url,
                submit=args.submit,
                introspect=args.introspect,
                consume=args.consume,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                min_solve_ms=args.min_solve_ms,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "trustcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="trustcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_trustcaptcha(
                site_key=args.site_key,
                api_url=args.api_url,
                target_url=args.target_url,
                create_url=args.create_url,
                submit_url=args.submit_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                create_body_json=args.create_body_json,
                create_body_file=args.create_body_file,
                submit=args.submit,
                max_rounds=args.max_rounds,
                start=args.start,
                max_attempts_per_task=args.max_attempts_per_task,
                workers=args.workers,
                timeout_sec=args.timeout,
                min_solve_ms=args.min_solve_ms,
                minimal_data_mode=args.minimal_data_mode,
                bypass_token=args.bypass_token,
                framework=args.framework,
                language=args.language,
                theme=args.theme,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "stravcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="stravcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_stravcaptcha(
                token=args.token,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_html=args.challenge_html,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                submit=args.submit,
                secret=args.secret,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                token_field=args.token_field,
                response_field=args.response_field,
                honeypot_field=args.honeypot_field,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "justnocaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="justnocaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_justnocaptcha(
                challenge=args.challenge,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_html=args.challenge_html,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                submit=args.submit,
                challenge_salt=args.challenge_salt,
                start=args.start,
                max_attempts_per_puzzle=args.max_attempts_per_puzzle,
                workers=args.workers,
                timeout_sec=args.timeout,
                challenge_field=args.challenge_field,
                response_field=args.response_field,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "capybara":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="capybara",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_capybara(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                payload_token=args.payload_token,
                submit=args.submit,
                difficulty=args.difficulty,
                duration_sec=args.duration_sec,
                secret=args.secret,
                instance_id=args.instance_id,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "vulcan":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="vulcan",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_vulcan(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_html=args.challenge_html,
                challenge_url=args.challenge_url,
                start=args.start,
                max_attempts_per_round=args.max_attempts_per_round,
                workers=args.workers,
                timeout_sec=args.timeout,
                response_field=args.response_field,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "spow":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="spow",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_spow(
                challenge=args.challenge,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_html=args.challenge_html,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                submit_format=args.submit_format,
                secret=args.secret,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                response_field=args.response_field,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
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
    if args.cmd == "stress" and args.provider == "powbot":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="powbot",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_powbot(
                base_url=args.base_url,
                challenge=args.challenge,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenges_url=args.challenges_url,
                verify_url=args.verify_url,
                api_token=args.api_token,
                difficulty_level=args.difficulty_level,
                batch_index=args.batch_index,
                submit=args.submit,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "powchallenge":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="powchallenge",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_powchallenge(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                nonce_seed=args.nonce_seed,
                nonce_length=args.nonce_length,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "powreaction":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="powreaction",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_powreaction(
                base_url=args.base_url,
                challenge=args.challenge,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                reaction=args.reaction,
                submit=args.submit,
                secret=args.secret,
                max_attempts_per_round=args.max_attempts_per_round,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "procaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="procaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_procaptcha(
                provider_url=args.provider_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                submit_url=args.submit_url,
                site_key=args.site_key,
                user=args.user,
                dapp=args.dapp,
                session_id=args.session_id,
                submit=args.submit,
                user_timestamp_signature=args.user_timestamp_signature,
                verified_timeout=args.verified_timeout,
                provider_challenge_signature=args.provider_challenge_signature,
                behavioral_data=args.behavioral_data,
                salt=args.salt,
                simd_readings=args.simd_readings,
                client_meta_json=args.client_meta_json,
                client_meta_file=args.client_meta_file,
                include_timestamp=args.include_timestamp,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "tollbooth":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="tollbooth",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_tollbooth(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                navigator_strategy=args.navigator_strategy,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
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
    if args.cmd == "stress" and args.provider == "powforge":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="powforge",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_powforge(
                base_url=args.base_url,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                token_verify_url=args.token_verify_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                salt=args.salt,
                difficulty=args.difficulty,
                response_field=args.response_field,
                submit=not args.no_submit,
                token_verify=args.token_verify,
                start=args.start,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "swetrix":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="swetrix",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_swetrix(
                pid=args.pid,
                api_url=args.api_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                validate_url=args.validate_url,
                submit=args.submit,
                secret=args.secret,
                max_attempts=args.max_attempts,
                workers=args.workers,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
                user_agent=args.user_agent,
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
    if args.cmd == "stress" and args.provider == "yourcaptcha":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="yourcaptcha",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_yourcaptcha(
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                signals_json=args.signals_json,
                signals_file=args.signals_file,
                start=args.start,
                max_attempts=args.max_attempts,
                timeout_sec=args.timeout,
                proxy_server=args.proxy,
                output_dir=str(root / f"run_{i}") if root else None,
            ),
        )
        emit_stress(ret, full=args.full)
        return 0 if ret["summary"]["fail"] == 0 else 2
    if args.cmd == "stress" and args.provider == "silentchallenge":
        root = Path(args.output_dir) if args.output_dir else None
        ret = await run_stress(
            name="silentchallenge",
            runs=args.runs,
            concurrency=args.concurrency,
            per_run_timeout=args.timeout + 5,
            output_json=args.output_json,
            run_once=lambda i: client.solve_silentchallenge(
                base_url=args.base_url,
                challenge_json=args.challenge_json,
                challenge_file=args.challenge_file,
                challenge_url=args.challenge_url,
                verify_url=args.verify_url,
                submit=args.submit,
                motion_json=args.motion_json,
                motion_file=args.motion_file,
                signals_json=args.signals_json,
                signals_file=args.signals_file,
                start=args.start,
                max_attempts=args.max_attempts,
                timeout_sec=args.timeout,
                min_submit_ms=args.min_submit_ms,
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
