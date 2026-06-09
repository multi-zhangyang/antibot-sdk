from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

PROVIDER = "perimeterx"
CAPABILITY = "perimeterx_px_vm_primitive"
CAPTCHA_TYPE = "perimeterx_px_sensor_experimental"
DEFAULT_TIMEOUT = 10
DEFAULT_SETTLE_MS = 100
VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "perimeterx"
PX_VM_RUNNER = VENDOR_DIR / "px_vm_runner.mjs"
PX_COOKIE_NAMES = ("_px", "_px2", "_px3", "_pxde", "_pxvid", "pxcts")


@dataclass(frozen=True, slots=True)
class PerimeterXCookie:
    name: str
    value: str
    source: str = "unknown"
    attributes: dict[str, str] | None = None


def run_perimeterx_px_vm(
    script: str,
    *,
    script_url: str | None = None,
    page_url: str = "https://example.test/",
    collector_url: str | None = None,
    cookie: str | None = None,
    config: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
    settle_ms: int = DEFAULT_SETTLE_MS,
) -> dict[str, Any]:
    source = _load_text_arg(script)
    if not source.strip():
        raise ValueError("PerimeterX PX VM requires non-empty script")
    node_bin = node or shutil.which("node")
    if not node_bin:
        raise RuntimeError("node executable is required for PerimeterX PX VM mode")
    if not PX_VM_RUNNER.is_file():
        raise RuntimeError(f"PerimeterX PX VM helper is missing: {PX_VM_RUNNER}")
    payload = {
        "script": source,
        "script_url": script_url,
        "page_url": page_url or "https://example.test/",
        "collector_url": collector_url or "",
        "cookie": cookie or "",
        "config": config or {},
        "profile": profile or {},
        "settle_ms": max(0, int(settle_ms)),
        "vm_timeout_ms": max(1000, int(timeout_sec * 1000)),
    }
    try:
        proc = subprocess.run(
            [node_bin, str(PX_VM_RUNNER)],
            input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_sec) + 2),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"PerimeterX PX VM helper timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "PerimeterX PX VM helper failed").strip()
        raise RuntimeError(message)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PerimeterX PX VM helper returned non-JSON output") from exc
    if not isinstance(data, dict):
        raise RuntimeError("PerimeterX PX VM helper returned invalid payload")
    return data


def extract_px_requests(vm_result: dict[str, Any], *, collector_hint: str | None = None) -> list[dict[str, Any]]:
    if not isinstance(vm_result, dict):
        return []
    hint_host = (urlsplit(collector_hint or "").hostname or "").lower()
    out: list[dict[str, Any]] = []
    for item in vm_result.get("requests") or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        lowered = url.lower()
        host = (urlsplit(url).hostname or "").lower()
        body = str(item.get("body") or "")
        body_lower = body.lower()
        headers = {str(k).lower(): str(v).lower() for k, v in (item.get("headers") or {}).items()}
        if (
            "perimeterx" in lowered
            or "px-cloud" in host
            or (hint_host and host == hint_host)
            or "/api/v" in lowered
            or "/collector" in lowered
            or "/init" in lowered
            or "pxvid" in body_lower
            or "_px" in body_lower
            or "px3" in body_lower
            or any(k.startswith("x-px") for k in headers)
        ):
            out.append(item)
    return out


def parse_px_cookies(value: str | dict[str, Any] | None, *, source: str = "unknown") -> list[PerimeterXCookie]:
    if not value:
        return []
    if isinstance(value, dict):
        return [
            PerimeterXCookie(str(k), str(v), source=source, attributes={})
            for k, v in value.items()
            if str(k) in PX_COOKIE_NAMES or str(k).startswith("_px")
        ]
    text = str(value).strip()
    if not text:
        return []
    cookie = SimpleCookie()
    try:
        cookie.load(text)
    except Exception:
        cookie = SimpleCookie()
    out: list[PerimeterXCookie] = []
    for name in PX_COOKIE_NAMES:
        morsel = cookie.get(name)
        if morsel is not None:
            attrs = {k: str(v) for k, v in morsel.items() if v}
            out.append(PerimeterXCookie(name, morsel.value, source=source, attributes=attrs))
    if out:
        return out
    m = re.fullmatch(r"(?P<name>_px\w*)=(?P<value>[^;]+).*", text)
    if m:
        return [PerimeterXCookie(m.group("name"), m.group("value"), source=source, attributes={})]
    return []


def parse_px_response(body: str | dict[str, Any] | None = None, *, headers: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookies: list[PerimeterXCookie] = []
    for key in ("set-cookie", "x-set-cookie"):
        cookies.extend(parse_px_cookies(headers.get(key), source=key))
    data: Any = body
    raw_text = ""
    if isinstance(body, str):
        raw_text = body
        stripped = body.strip()
        if stripped:
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                data = stripped
    challenge_url = None
    status = None
    if isinstance(data, dict):
        status = data.get("status") or data.get("pxStatus") or data.get("result")
        for key in ("cookie", "pxCookie", "_px3", "_px2", "_pxvid"):
            if data.get(key):
                raw_cookie = f"{key}={data[key]}" if key.startswith("_") else str(data[key])
                cookies.extend(parse_px_cookies(raw_cookie, source=f"body.{key}"))
        challenge_url = data.get("url") or data.get("redirectUrl") or data.get("blockUrl") or data.get("captchaUrl")
    unique: dict[str, PerimeterXCookie] = {c.name: c for c in cookies}
    return {
        "cookies": {name: c.value for name, c in unique.items()},
        "cookie_sources": {name: c.source for name, c in unique.items()},
        "challenge_url": challenge_url,
        "blocked": bool(challenge_url or "captcha" in raw_text.lower() or "block" in raw_text.lower()),
        "status": status,
        "raw": data if isinstance(data, dict) else None,
        "body_prefix": raw_text[:240] if raw_text else None,
    }


def extract_perimeterx_sdk_urls(html_or_js: str, base_url: str = "") -> list[str]:
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
        if not any(marker in lowered for marker in ("perimeterx", "px-cloud", "px.js", "/px/", "_px", "collector")):
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


class PerimeterXSolver:
    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        script_js: str | None = None,
        script_file: str | None = None,
        script_url: str | None = None,
        allow_network: bool = False,
        page_url: str = "https://example.test/",
        collector_url: str | None = None,
        cookie: str | None = None,
        config: dict[str, Any] | None = None,
        config_json: str | dict[str, Any] | None = None,
        config_file: str | None = None,
        profile: dict[str, Any] | None = None,
        profile_json: str | dict[str, Any] | None = None,
        profile_file: str | None = None,
        submit: bool = False,
        submit_url: str | None = None,
        success_contains: str | None = None,
        node: str | None = None,
        timeout_sec: int = DEFAULT_TIMEOUT,
        settle_ms: int = DEFAULT_SETTLE_MS,
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
            "collector_url": collector_url,
            "allow_network": allow_network,
            "submit": submit,
            "submit_url": submit_url,
            "timeout_sec": timeout_sec,
            "settle_ms": settle_ms,
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
            script = self._load_script(
                script_js=script_js,
                script_file=script_file,
                script_url=script_url,
                allow_network=allow_network,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            config_obj = _load_json_obj(config, config_json, config_file, "config") or {}
            profile_obj = _load_json_obj(profile, profile_json, profile_file, "profile") or {}
            vm_result = run_perimeterx_px_vm(
                script,
                script_url=script_url,
                page_url=page_url,
                collector_url=collector_url,
                cookie=cookie,
                config=config_obj,
                profile=profile_obj,
                node=node,
                timeout_sec=timeout_sec,
                settle_ms=settle_ms,
            )
            raw["vm"] = vm_result
            px_requests = extract_px_requests(vm_result, collector_hint=collector_url)
            vm_cookies = parse_px_cookies(vm_result.get("cookies") if isinstance(vm_result, dict) else None, source="vm")
            diagnostics.update(
                {
                    "request_count": len(vm_result.get("requests") or []),
                    "px_request_count": len(px_requests),
                    "event_count": len(vm_result.get("events") or []),
                    "vm_error_count": len(vm_result.get("errors") or []),
                    "cookie_names": sorted({c.name for c in vm_cookies}),
                    "request_kinds": sorted({str(item.get("kind")) for item in px_requests if isinstance(item, dict)}),
                }
            )
            raw["pxRequests"] = px_requests
            if vm_cookies:
                raw["pxCookies"] = {c.name: c.value for c in vm_cookies}

            if submit:
                if not px_requests:
                    errors.append("PerimeterX submit requested but VM captured no PX request")
                    return finish(ok=False, ticket=_ticket_from_cookies(vm_cookies), verify_code="missing_request")
                submit_info = _submit_captured_request(
                    px_requests[-1],
                    submit_url=submit_url,
                    success_contains=success_contains,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                    headers=headers,
                )
                raw["submitRequest"] = submit_info["request"]
                raw["submitResponse"] = submit_info["response"]
                response_info = submit_info["parsed"]
                diagnostics.update(
                    {
                        "submitted": True,
                        "submit_status": submit_info["response"]["status"],
                        "submit_ok": submit_info["ok"],
                        "submit_reason": submit_info["reason"],
                        "response_cookie_names": sorted((response_info.get("cookies") or {}).keys()),
                        "challenge_url_present": bool(response_info.get("challenge_url")),
                    }
                )
                if response_info.get("cookies"):
                    ticket = json.dumps({"cookies": response_info["cookies"]}, ensure_ascii=False, separators=(",", ":"))
                    return finish(ok=submit_info["ok"], ticket=ticket, verify_code="submitted_cookie")
                if submit_info["ok"]:
                    ticket = json.dumps({"response": response_info}, ensure_ascii=False, separators=(",", ":"))
                    return finish(ok=True, ticket=ticket, verify_code="submitted")
                errors.append(f"PerimeterX submit failed: {submit_info['reason']}")
                return finish(ok=False, ticket=_ticket_from_cookies(vm_cookies), verify_code="submit_failed")

            cookie_ticket = _ticket_from_cookies(vm_cookies)
            if cookie_ticket:
                return finish(ok=True, ticket=cookie_ticket, verify_code="cookie")
            if px_requests:
                ticket = json.dumps({"requests": [_compact_request(px_requests[-1])]}, ensure_ascii=False, separators=(",", ":"))
                return finish(ok=True, ticket=ticket, verify_code="signals")
            errors.append("PerimeterX PX VM did not capture PX request or PX cookie")
            return finish(ok=False, verify_code="no_px_artifacts")
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
            raise ValueError("PerimeterX solve requires script_js, script_file, or script_url")
        if not allow_network:
            raise ValueError("script_url fetch is disabled by default; pass allow_network=True for mocks")
        resp = requests.get(script_url, headers=headers or {}, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
        raw["scriptResponse"] = {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("content-type"), "bodyPrefix": resp.text[:120]}
        resp.raise_for_status()
        return resp.text


def _submit_captured_request(captured: dict[str, Any], *, submit_url: str | None, success_contains: str | None, timeout_sec: int, proxy_server: str | None, headers: dict[str, str] | None) -> dict[str, Any]:
    url = submit_url or str(captured.get("url") or "")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("PerimeterX submit_url must be an absolute http(s) URL")
    method = str(captured.get("method") or "POST").upper()
    req_headers = {str(k): str(v) for k, v in (captured.get("headers") or {}).items()}
    req_headers.update({str(k): str(v) for k, v in (headers or {}).items()})
    req_headers.setdefault("Accept", "application/json, text/plain, */*")
    body = captured.get("body")
    kwargs: dict[str, Any] = {"headers": req_headers, "timeout": timeout_sec, "proxies": _requests_proxies(proxy_server)}
    if body is not None and method not in {"GET", "HEAD"}:
        kwargs["data"] = str(body).encode("utf-8")
    resp = requests.request(method, url, **kwargs)
    text = resp.text or ""
    parsed_response = parse_px_response(text, headers=dict(resp.headers))
    contains_ok = True if success_contains is None else success_contains in text
    status_ok = 200 <= resp.status_code < 400
    ok = bool(status_ok and contains_ok and not (parsed_response.get("blocked") and not parsed_response.get("cookies")))
    if not status_ok:
        reason = f"http_{resp.status_code}"
    elif success_contains is not None and not contains_ok:
        reason = "missing_success_contains"
    elif parsed_response.get("blocked") and not parsed_response.get("cookies"):
        reason = "challenge_returned"
    else:
        reason = "accepted"
    return {
        "ok": ok,
        "reason": reason,
        "request": {"url": url, "method": method, "bodyKind": "text" if body is not None else "none", "bodyKeys": sorted(parse_qs(str(body or ""), keep_blank_values=True))[:30]},
        "response": {"status": resp.status_code, "url": resp.url, "contentType": resp.headers.get("content-type"), "headers": {k: v for k, v in dict(resp.headers).items() if k.lower() in {"set-cookie", "x-set-cookie", "content-type"}}, "bodyPrefix": text[:240]},
        "parsed": parsed_response,
    }


def _ticket_from_cookies(cookies: list[PerimeterXCookie]) -> str | None:
    if not cookies:
        return None
    return json.dumps({"cookies": {c.name: c.value for c in cookies}}, ensure_ascii=False, separators=(",", ":"))


def _compact_request(item: dict[str, Any]) -> dict[str, Any]:
    body = str(item.get("body") or "")
    return {"kind": item.get("kind"), "url": item.get("url"), "method": item.get("method"), "headers": item.get("headers") or {}, "bodyKeys": sorted(parse_qs(body, keep_blank_values=True))[:30], "bodyPrefix": body[:240] if body else None}


def _load_text_arg(value: str) -> str:
    text = str(value)
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8")
    return text


def _load_json_arg(value: str | dict[str, Any]) -> Any:
    if isinstance(value, dict):
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
        raise ValueError(f"PerimeterX {name} must be a JSON object")
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
    (out / "perimeterx_run.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = [
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "DEFAULT_SETTLE_MS",
    "DEFAULT_TIMEOUT",
    "PROVIDER",
    "PX_COOKIE_NAMES",
    "PX_VM_RUNNER",
    "PerimeterXCookie",
    "PerimeterXSolver",
    "extract_perimeterx_sdk_urls",
    "extract_px_requests",
    "parse_px_cookies",
    "parse_px_response",
    "run_perimeterx_px_vm",
]
