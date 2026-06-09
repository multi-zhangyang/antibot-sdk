from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

PROVIDER = "hcaptcha_hsw"
CAPABILITY = "hcaptcha_hsw_vm_primitive"
CAPTCHA_TYPE = "hcaptcha_hsw_n_experimental"
DEFAULT_TIMEOUT = 10
VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "hcaptcha_hsw"
HSW_VM_RUNNER = VENDOR_DIR / "hsw_vm_runner.mjs"


def run_hcaptcha_hsw_vm(
    script: str,
    *,
    req: dict[str, Any] | str | None = None,
    function_name: str | None = None,
    args: list[Any] | None = None,
    script_url: str | None = None,
    page_url: str = "https://example.test/",
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    source = _load_text_arg(script)
    if not source.strip():
        raise ValueError("hCaptcha HSW VM requires non-empty script")
    node_bin = node or shutil.which("node")
    if not node_bin:
        raise RuntimeError("node executable is required for hCaptcha HSW VM mode")
    if not HSW_VM_RUNNER.is_file():
        raise RuntimeError(f"hCaptcha HSW VM helper is missing: {HSW_VM_RUNNER}")
    payload = {
        "script": source,
        "req": _coerce_req(req),
        "function_name": function_name or "",
        "args": args or [],
        "script_url": script_url,
        "page_url": page_url or "https://example.test/",
        "profile": profile or {},
        "vm_timeout_ms": max(1000, int(timeout_sec * 1000)),
    }
    try:
        proc = subprocess.run(
            [node_bin, str(HSW_VM_RUNNER)],
            input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_sec) + 2),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hCaptcha HSW VM helper timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "hCaptcha HSW VM helper failed").strip()
        raise RuntimeError(message)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("hCaptcha HSW VM helper returned non-JSON output") from exc
    if not isinstance(data, dict):
        raise RuntimeError("hCaptcha HSW VM helper returned invalid payload")
    return data


def extract_hcaptcha_hsw_urls(html_or_js: str, base_url: str = "") -> list[str]:
    text = html_or_js or ""
    hits: list[str] = []
    for match in re.finditer(r"""<script\b[^>]*\bsrc=["'](?P<src>[^"']+)["']""", text, re.I):
        hits.append(match.group("src"))
    for match in re.finditer(r"""["'](?P<url>(?:https?:)?//[^"']+|/[^"']+)["']""", text):
        hits.append(match.group("url"))
    out: list[str] = []
    seen: set[str] = set()
    for raw in hits:
        lowered = raw.lower()
        if not any(marker in lowered for marker in ("hcaptcha", "hsw", "checksiteconfig", "getcaptcha", "newassets")):
            continue
        url = raw
        if url.startswith("//"):
            base_scheme = urlsplit(base_url).scheme or "https"
            url = f"{base_scheme}:{url}"
        elif base_url:
            url = urljoin(base_url, url)
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def build_hcaptcha_req(
    *,
    sitekey: str | None = None,
    host: str | None = None,
    rqdata: str | None = None,
    motion_data: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    req: dict[str, Any] = dict(extra or {})
    if sitekey:
        req.setdefault("sitekey", sitekey)
    if host:
        req.setdefault("host", host)
    if rqdata:
        req.setdefault("rqdata", rqdata)
    if motion_data is not None:
        req.setdefault("motionData", motion_data)
    return req


def parse_hcaptcha_hsw_result(vm_result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(vm_result, dict):
        return {"n": None, "raw": None}
    value = vm_result.get("value")
    value_string = vm_result.get("valueString")
    if isinstance(value, str):
        return {"n": value, "raw": value, "type": "string"}
    if isinstance(value, dict):
        n = value.get("n") or value.get("proof") or value.get("answer") or value.get("token")
        return {"n": str(n) if n is not None else None, "raw": value, "type": "object"}
    return {"n": str(value_string) if value_string not in (None, "null") else None, "raw": value_string, "type": vm_result.get("valueType")}


class HCaptchaHswSolver:
    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        script_js: str | None = None,
        script_file: str | None = None,
        script_url: str | None = None,
        allow_network: bool = False,
        req: dict[str, Any] | str | None = None,
        req_json: str | dict[str, Any] | None = None,
        req_file: str | None = None,
        sitekey: str | None = None,
        host: str | None = None,
        rqdata: str | None = None,
        motion_json: str | dict[str, Any] | None = None,
        function_name: str | None = None,
        args_json: str | list[Any] | None = None,
        profile: dict[str, Any] | None = None,
        profile_json: str | dict[str, Any] | None = None,
        profile_file: str | None = None,
        page_url: str = "https://example.test/",
        node: str | None = None,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        headers: dict[str, str] | None = None,
        output_dir: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "mode": "browserless_vm_primitive",
            "script_url": script_url,
            "page_url": page_url,
            "allow_network": allow_network,
            "function_name": function_name,
            "timeout_sec": timeout_sec,
            "proxy": redacted_proxy(proxy_server),
        }
        errors: list[str] = []

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            raw["ok"] = ok
            raw["elapsedMs"] = elapsed_ms
            _write_artifact(output_dir, raw)
            return CaptchaResult(
                provider=PROVIDER,
                ok=ok,
                captcha_type=CAPTCHA_TYPE,
                capability=CAPABILITY,
                ticket=ticket,
                verify_code=verify_code,
                elapsed_ms=elapsed_ms,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            script = self._load_script(script_js=script_js, script_file=script_file, script_url=script_url, allow_network=allow_network, timeout_sec=timeout_sec, proxy_server=proxy_server, headers=headers, raw=raw)
            req_obj = _load_req(req, req_json, req_file)
            if req_obj is None:
                req_obj = build_hcaptcha_req(sitekey=sitekey, host=host, rqdata=rqdata, motion_data=_load_json_any(motion_json))
            elif isinstance(req_obj, dict):
                req_obj = build_hcaptcha_req(sitekey=sitekey, host=host, rqdata=rqdata, motion_data=_load_json_any(motion_json), extra=req_obj)
            profile_obj = _load_json_obj(profile, profile_json, profile_file, "profile") or {}
            args = _load_args(args_json)
            vm_result = run_hcaptcha_hsw_vm(
                script,
                req=req_obj,
                function_name=function_name,
                args=args,
                script_url=script_url,
                page_url=page_url,
                profile=profile_obj,
                node=node,
                timeout_sec=timeout_sec,
            )
            raw["vm"] = vm_result
            parsed = parse_hcaptcha_hsw_result(vm_result)
            raw["hsw"] = parsed
            vm_diag = vm_result.get("diagnostics") if isinstance(vm_result.get("diagnostics"), dict) else {}
            diagnostics.update(
                {
                    "resolved_function": vm_result.get("functionName"),
                    "value_type": vm_result.get("valueType"),
                    "n_present": bool(parsed.get("n")),
                    "request_count": vm_diag.get("requestCount", 0),
                    "module_export_keys": vm_diag.get("moduleExportKeys") or [],
                    "window_keys": vm_diag.get("windowKeys") or [],
                    "req_keys": sorted(req_obj) if isinstance(req_obj, dict) else [],
                }
            )
            if parsed.get("n"):
                return finish(ok=True, ticket=str(parsed["n"]), verify_code="n")
            if parsed.get("raw") is not None:
                ticket = json.dumps({"hsw": parsed["raw"]}, ensure_ascii=False, separators=(",", ":"))
                return finish(ok=True, ticket=ticket, verify_code="payload")
            errors.append("hCaptcha HSW VM did not return n/payload")
            return finish(ok=False, verify_code="no_hsw_result")
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_script(self, *, script_js: str | None, script_file: str | None, script_url: str | None, allow_network: bool, timeout_sec: int, proxy_server: str | None, headers: dict[str, str] | None, raw: dict[str, Any]) -> str:
        if script_js is not None:
            return _load_text_arg(script_js)
        if script_file:
            return Path(script_file).read_text(encoding="utf-8")
        if not script_url:
            raise ValueError("hCaptcha HSW solve requires script_js, script_file, or script_url")
        if not allow_network:
            raise ValueError("script_url fetch is disabled by default; pass allow_network=True for mocks")
        resp = requests.get(script_url, headers=headers or {}, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
        raw["scriptResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("content-type"), "bodyPrefix": resp.text[:120]}
        resp.raise_for_status()
        return resp.text


def _coerce_req(value: dict[str, Any] | str | None) -> Any:
    if value is None:
        return {}
    if isinstance(value, str):
        text = _load_text_arg(value).strip()
        if text.startswith("{") or text.startswith("["):
            return json.loads(text)
        return text
    return value


def _load_req(req: dict[str, Any] | str | None, req_json: str | dict[str, Any] | None, req_file: str | None) -> Any:
    if req is not None:
        return _coerce_req(req)
    if req_json is not None:
        return _load_json_arg(req_json)
    if req_file:
        return json.loads(Path(req_file).read_text(encoding="utf-8"))
    return None


def _load_args(args_json: str | list[Any] | None) -> list[Any]:
    if args_json is None:
        return []
    data = _load_json_arg(args_json) if isinstance(args_json, str) else args_json
    if not isinstance(data, list):
        raise ValueError("hCaptcha HSW args_json must be a JSON list")
    return data


def _load_json_any(value: str | dict[str, Any] | list[Any] | None) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    return _load_json_arg(value)


def _load_text_arg(value: str) -> str:
    text = str(value)
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8")
    return text


def _load_json_arg(value: str | dict[str, Any] | list[Any]) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = value.strip()
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8").strip()
    return json.loads(text)


def _load_json_obj(direct: dict[str, Any] | None, inline_or_at: str | dict[str, Any] | None, file_path: str | None, name: str) -> dict[str, Any] | None:
    data: Any = None
    if direct is not None:
        data = dict(direct)
    if inline_or_at is not None:
        data = _load_json_arg(inline_or_at)
    if file_path:
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError(f"hCaptcha HSW {name} must be a JSON object")
    return data


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    if not proxy_server:
        return None
    parsed = parse_proxy(proxy_server)
    return {"http": parsed.url, "https": parsed.url}


def _write_artifact(output_dir: str | None, raw: dict[str, Any]) -> None:
    if not output_dir:
        return
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "hcaptcha_hsw_run.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = [
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "DEFAULT_TIMEOUT",
    "HSW_VM_RUNNER",
    "PROVIDER",
    "HCaptchaHswSolver",
    "build_hcaptcha_req",
    "extract_hcaptcha_hsw_urls",
    "parse_hcaptcha_hsw_result",
    "run_hcaptcha_hsw_vm",
]
