#!/usr/bin/env python3
"""Matrix Zhuque AI Detect captcha acceptance helper.

This project solves the TencentCaptcha layer.  Matrix additionally checks the
captcha ticket on its own WebSocket and only proceeds when evil_level == "0".
The authoritative full detect runner lives in the sibling tencent-ai-detect
project; this helper either summarizes existing evidence or invokes that runner
so captcha research keeps a site-specific record here as well.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CTF = ROOT.parent
SIBLING_RUNNER = CTF / "tencent-ai-detect" / "replay" / "browser_guest_detect.py"
DEFAULT_SOURCE = CTF / "tencent-ai-detect" / "notes" / "browser-guest-native-socks2-stablefp.json"
DEFAULT_OUT = ROOT / "notes" / "matrix_ai_detect_e2e_summary.json"
SENSITIVE_KEYS = {
    "fp",
    "proxy",
    "captcha_uips",
    "uip",
    "ip",
    "cos",
    "cosurl",
    "ticket",
    "randstr",
    "sess",
    "tdc",
    "feedback_token",
    "access_token",
    "cookie",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _redact_string(s: str) -> str:
    s = re.sub(r"t03tserver[-A-Za-z0-9_\\*]+", "<redacted-ticket>", s)
    s = re.sub(r"(?i)(https?|socks5)://[^\\s/@:]+:[^\\s/@]+@[^\\s'\"),]+", r"\\1://<user>:<pass>@<host>:<port>", s)
    s = re.sub(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "<redacted-ip>", s)
    s = re.sub(r"\\b[a-f0-9]{32}\\b", "<redacted-hex32>", s, flags=re.I)
    return s


def _safe_payload_summary(obj: Any) -> Any:
    """Keep only shape and harmless status fields for raw request/response bodies."""
    if obj in (None, "", []):
        return obj
    parsed = obj
    if isinstance(obj, str):
        try:
            parsed = json.loads(obj)
        except Exception:
            return {"present": True, "type": "str", "redacted": True}
    if isinstance(parsed, dict):
        keep = {k: parsed.get(k) for k in ("code", "status", "msg", "message", "ret", "errorCode") if k in parsed}
        keep["present"] = True
        keep["keys"] = sorted(str(k) for k in parsed.keys())
        return _redact(keep)
    if isinstance(parsed, list):
        return {"present": True, "type": "list", "length": len(parsed), "redacted": True}
    return {"present": True, "type": type(parsed).__name__, "redacted": True}


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in SENSITIVE_KEYS or any(marker in lk for marker in ("token", "ticket", "cookie")):
                out[k] = "<redacted>" if v not in (None, "", []) else v
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


def summarize(d: dict[str, Any], source: str, include_sensitive: bool = False) -> dict[str, Any]:
    final = d.get("final_ws") or {}
    if not final:
        for ev in reversed(d.get("ws_hook", [])):
            data = ev.get("data")
            if ev.get("dir") == "RECV" and isinstance(data, dict) and data.get("status") == "success" and data.get("confidence") is not None:
                final = data
                break
    upload = None
    for h in d.get("http", []):
        if str(h.get("url", "")).endswith("/user/detect"):
            upload = h.get("body")
    out = {
        "source": source,
        "ok": bool(final and final.get("confidence") is not None),
        "profile": "matrix_ai_detect",
        "target_url": "https://matrix.tencent.com/ai-detect/ai_gen_txt",
        "appid": "2089775896",
        "fp_present": bool(d.get("fp")),
        "proxy_present": bool(d.get("proxy")),
        "captcha_uip_count": len(d.get("captcha_uips") or []),
        "initial_ws": d.get("initial_ws") if include_sensitive else _redact(d.get("initial_ws")),
        "upload": upload if include_sensitive else _safe_payload_summary(upload),
        "captcha_decision": d.get("captcha_decision") if include_sensitive else _redact(d.get("captcha_decision")),
        "final": {
            "status": final.get("status"),
            "confidence": final.get("confidence"),
            "labels_ratio": final.get("labels_ratio"),
            "content_type": final.get("content_type"),
            "availableUses": final.get("availableUses"),
        } if final else None,
        "terminal": d.get("terminal") if include_sensitive else _redact(d.get("terminal")),
        "error": d.get("error") if include_sensitive else _redact(d.get("error")),
    }
    if include_sensitive:
        out["fp"] = d.get("fp")
        out["proxy"] = d.get("proxy")
        out["captcha_uips"] = d.get("captcha_uips")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SOURCE), help="existing tencent-ai-detect evidence JSON")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--run", action="store_true", help="invoke sibling tencent-ai-detect runner; consumes one Matrix detect quota on success")
    ap.add_argument("--include-sensitive", action="store_true", help="include fp/proxy/uip values in local-only output")
    ap.add_argument("--proxy-server", default="http://127.0.0.1:18092")
    ap.add_argument("--timeout", type=int, default=100)
    args = ap.parse_args()

    source = Path(args.source)
    if args.run:
        if not SIBLING_RUNNER.exists():
            raise SystemExit(f"missing sibling runner: {SIBLING_RUNNER}")
        source = ROOT / "notes" / "matrix_ai_detect_e2e_live.json"
        cmd = [
            sys.executable,
            str(SIBLING_RUNNER),
            "--proxy-server", args.proxy_server,
            "--timeout", str(args.timeout),
            "--out", str(source),
        ]
        subprocess.check_call(cmd)

    d = _load(source)
    summary = summarize(d, str(source), include_sensitive=args.include_sensitive)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
