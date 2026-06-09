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

PROVIDER = "datadome"
CAPABILITY = "datadome_js_tag_vm_primitive"
CAPTCHA_TYPE = "datadome_js_tag_signals_experimental"
DEFAULT_TIMEOUT = 10
DEFAULT_SETTLE_MS = 100
VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "datadome"
TAG_VM_RUNNER = VENDOR_DIR / "tag_vm_runner.mjs"


@dataclass(frozen=True, slots=True)
class DataDomeCookie:
    value: str
    source: str = "unknown"
    attributes: dict[str, str] | None = None


def run_datadome_tag_vm(
    script: str,
    *,
    script_url: str | None = None,
    page_url: str = "https://example.test/",
    endpoint_url: str | None = None,
    cookie: str | None = None,
    config: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
    settle_ms: int = DEFAULT_SETTLE_MS,
) -> dict[str, Any]:
    """Execute a DataDome JavaScript tag in the bundled browserless Node VM shim."""

    source = _load_text_arg(script)
    if not source.strip():
        raise ValueError("DataDome tag VM requires non-empty script")
    node_bin = node or shutil.which("node")
    if not node_bin:
        raise RuntimeError("node executable is required for DataDome tag VM mode")
    if not TAG_VM_RUNNER.is_file():
        raise RuntimeError(f"DataDome tag VM helper is missing: {TAG_VM_RUNNER}")
    payload = {
        "script": source,
        "script_url": script_url,
        "page_url": page_url or "https://example.test/",
        "endpoint_url": endpoint_url or "",
        "cookie": cookie or "",
        "config": config or {},
        "profile": profile or {},
        "settle_ms": max(0, int(settle_ms)),
        "vm_timeout_ms": max(1000, int(timeout_sec * 1000)),
    }
    try:
        proc = subprocess.run(
            [node_bin, str(TAG_VM_RUNNER)],
            input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_sec) + 2),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"DataDome tag VM helper timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "DataDome tag VM helper failed").strip()
        raise RuntimeError(message)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("DataDome tag VM helper returned non-JSON output") from exc
    if not isinstance(data, dict):
        raise RuntimeError("DataDome tag VM helper returned invalid payload")
    return data


def extract_datadome_requests(vm_result: dict[str, Any], *, endpoint_hint: str | None = None) -> list[dict[str, Any]]:
    """Return likely DataDome JS Tag signal requests from VM captures."""

    if not isinstance(vm_result, dict):
        return []
    hint_host = (urlsplit(endpoint_hint or "").hostname or "").lower()
    out: list[dict[str, Any]] = []
    for item in vm_result.get("requests") or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        lowered = url.lower()
        host = (urlsplit(url).hostname or "").lower()
        body = str(item.get("body") or "")
        if (
            "datadome" in lowered
            or "api-js" in host
            or (hint_host and host == hint_host)
            or "/js/" in lowered
            or "jsdata=" in body.lower()
            or "ddjs" in body.lower()
        ):
            out.append(item)
    return out


def parse_datadome_cookie(value: str | dict[str, Any] | None, *, source: str = "unknown") -> DataDomeCookie | None:
    """Parse a DataDome cookie value, Cookie header, Set-Cookie header, or VM cookie map."""

    if not value:
        return None
    if isinstance(value, dict):
        raw = value.get("datadome")
        return DataDomeCookie(str(raw), source=source, attributes={}) if raw else None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("datadome=") or "; datadome=" in text or " datadome=" in text:
        cookie = SimpleCookie()
        try:
            cookie.load(text)
        except Exception:
            cookie = SimpleCookie()
        morsel = cookie.get("datadome")
        if morsel is not None:
            attrs = {k: str(v) for k, v in morsel.items() if v}
            return DataDomeCookie(morsel.value, source=source, attributes=attrs)
    if re.fullmatch(r"[A-Za-z0-9._~+/=-]{16,}", text):
        return DataDomeCookie(text, source=source, attributes={})
    return None


def parse_datadome_response(
    body: str | dict[str, Any] | None = None,
    *,
    headers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse DataDome cookie/challenge hints from JS endpoint responses."""

    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie = parse_datadome_cookie(headers.get("set-cookie"), source="set-cookie") or parse_datadome_cookie(
        headers.get("x-set-cookie"), source="x-set-cookie"
    )
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
    body_cookie = None
    challenge_url = None
    if isinstance(data, dict):
        for key in ("cookie", "datadome", "dd_cookie", "ddCookie"):
            if data.get(key):
                body_cookie = parse_datadome_cookie(str(data[key]), source=f"body.{key}")
                break
        challenge_url = data.get("url") or data.get("captchaUrl") or data.get("captcha_url")
        if not challenge_url and isinstance(data.get("captcha"), dict):
            challenge_url = data["captcha"].get("url")
    if body_cookie and not cookie:
        cookie = body_cookie
    return {
        "cookie": cookie.value if cookie else None,
        "cookie_source": cookie.source if cookie else None,
        "cookie_attributes": cookie.attributes if cookie else None,
        "challenge_url": challenge_url,
        "blocked": bool(challenge_url or "captcha" in raw_text.lower()),
        "raw": data if isinstance(data, dict) else None,
        "body_prefix": raw_text[:240] if raw_text else None,
    }


def extract_datadome_sdk_urls(html_or_js: str, base_url: str = "") -> list[str]:
    """Extract likely DataDome JavaScript tag URLs from HTML/script text."""

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
        if not any(marker in lowered for marker in ("datadome", "tags.js", "/js/", "api-js")):
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


class DataDomeSolver:
    """Browserless DataDome JavaScript Tag primitive.

    It executes a caller-supplied or explicitly fetched tag in a Node VM, captures the generated
    JS-signal requests and optional ``datadome`` cookie writes, and can replay one captured request
    to a caller-provided mock/controlled endpoint for protocol verification.
    """

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
        endpoint_url: str | None = None,
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
            "endpoint_url": endpoint_url,
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
            vm_result = run_datadome_tag_vm(
                script,
                script_url=script_url,
                page_url=page_url,
                endpoint_url=endpoint_url,
                cookie=cookie,
                config=config_obj,
                profile=profile_obj,
                node=node,
                timeout_sec=timeout_sec,
                settle_ms=settle_ms,
            )
            raw["vm"] = vm_result
            dd_requests = extract_datadome_requests(vm_result, endpoint_hint=endpoint_url)
            vm_cookie = parse_datadome_cookie(vm_result.get("cookies") if isinstance(vm_result, dict) else None, source="vm")
            diagnostics.update(
                {
                    "request_count": len(vm_result.get("requests") or []),
                    "datadome_request_count": len(dd_requests),
                    "event_count": len(vm_result.get("events") or []),
                    "vm_error_count": len(vm_result.get("errors") or []),
                    "cookie_present": bool(vm_cookie),
                    "request_kinds": sorted({str(item.get("kind")) for item in dd_requests if isinstance(item, dict)}),
                }
            )
            raw["datadomeRequests"] = dd_requests
            if vm_cookie:
                raw["datadomeCookie"] = {"value": vm_cookie.value, "source": vm_cookie.source}

            submit_info = None
            response_info = None
            if submit:
                if not dd_requests:
                    errors.append("DataDome submit requested but VM captured no DataDome JS request")
                    return finish(ok=False, ticket=vm_cookie.value if vm_cookie else None, verify_code="missing_request")
                submit_info = _submit_captured_request(
                    dd_requests[-1],
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
                        "response_cookie_present": bool(response_info.get("cookie")),
                        "challenge_url_present": bool(response_info.get("challenge_url")),
                    }
                )
                if response_info.get("cookie"):
                    return finish(ok=submit_info["ok"], ticket=str(response_info["cookie"]), verify_code="submitted_cookie")
                if submit_info["ok"]:
                    ticket = json.dumps({"response": response_info}, ensure_ascii=False, separators=(",", ":"))
                    return finish(ok=True, ticket=ticket, verify_code="submitted")
                errors.append(f"DataDome submit failed: {submit_info['reason']}")
                return finish(ok=False, ticket=vm_cookie.value if vm_cookie else None, verify_code="submit_failed")

            if vm_cookie:
                return finish(ok=True, ticket=vm_cookie.value, verify_code="cookie")
            if dd_requests:
                ticket = json.dumps({"requests": [_compact_request(dd_requests[-1])]}, ensure_ascii=False, separators=(",", ":"))
                return finish(ok=True, ticket=ticket, verify_code="signals")
            errors.append("DataDome tag VM did not capture JS signal request or datadome cookie")
            return finish(ok=False, verify_code="no_datadome_artifacts")
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_script(
        self,
        *,
        script_js: str | None,
        script_file: str | None,
        script_url: str | None,
        allow_network: bool,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> str:
        if script_js is not None:
            return _load_text_arg(script_js)
        if script_file:
            return Path(script_file).read_text(encoding="utf-8")
        if not script_url:
            raise ValueError("DataDome solve requires script_js, script_file, or script_url")
        if not allow_network:
            raise ValueError("script_url fetch is disabled by default; pass allow_network=True for mocks")
        resp = requests.get(script_url, headers=headers or {}, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
        raw["scriptResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "bodyPrefix": resp.text[:120],
        }
        resp.raise_for_status()
        return resp.text


def _submit_captured_request(
    captured: dict[str, Any],
    *,
    submit_url: str | None,
    success_contains: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str] | None,
) -> dict[str, Any]:
    url = submit_url or str(captured.get("url") or "")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("DataDome submit_url must be an absolute http(s) URL")
    method = str(captured.get("method") or "POST").upper()
    req_headers = {str(k): str(v) for k, v in (captured.get("headers") or {}).items()}
    req_headers.update({str(k): str(v) for k, v in (headers or {}).items()})
    req_headers.setdefault("Accept", "application/json, text/plain, */*")
    body = captured.get("body")
    kwargs: dict[str, Any] = {
        "headers": req_headers,
        "timeout": timeout_sec,
        "proxies": _requests_proxies(proxy_server),
    }
    if body is not None and method not in {"GET", "HEAD"}:
        kwargs["data"] = str(body).encode("utf-8")
    resp = requests.request(method, url, **kwargs)
    text = resp.text or ""
    parsed_response = parse_datadome_response(text, headers=dict(resp.headers))
    contains_ok = True if success_contains is None else success_contains in text
    status_ok = 200 <= resp.status_code < 400
    ok = bool(status_ok and contains_ok and not (parsed_response.get("blocked") and not parsed_response.get("cookie")))
    if not status_ok:
        reason = f"http_{resp.status_code}"
    elif success_contains is not None and not contains_ok:
        reason = "missing_success_contains"
    elif parsed_response.get("blocked") and not parsed_response.get("cookie"):
        reason = "challenge_returned"
    else:
        reason = "accepted"
    return {
        "ok": ok,
        "reason": reason,
        "request": {
            "url": url,
            "method": method,
            "bodyKind": "text" if body is not None else "none",
            "bodyKeys": sorted(parse_qs(str(body or ""), keep_blank_values=True))[:30],
        },
        "response": {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "headers": {k: v for k, v in dict(resp.headers).items() if k.lower() in {"set-cookie", "x-set-cookie", "content-type"}},
            "bodyPrefix": text[:240],
        },
        "parsed": parsed_response,
    }


def _compact_request(item: dict[str, Any]) -> dict[str, Any]:
    body = str(item.get("body") or "")
    return {
        "kind": item.get("kind"),
        "url": item.get("url"),
        "method": item.get("method"),
        "headers": item.get("headers") or {},
        "bodyKeys": sorted(parse_qs(body, keep_blank_values=True))[:30],
        "bodyPrefix": body[:240] if body else None,
    }


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


def _load_json_obj(
    direct: dict[str, Any] | None,
    inline_or_at: str | dict[str, Any] | None,
    file_path: str | None,
    name: str,
) -> dict[str, Any] | None:
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
        raise ValueError(f"DataDome {name} must be a JSON object")
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
    (out / "datadome_run.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = [
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "DEFAULT_SETTLE_MS",
    "DEFAULT_TIMEOUT",
    "PROVIDER",
    "TAG_VM_RUNNER",
    "DataDomeCookie",
    "DataDomeSolver",
    "extract_datadome_requests",
    "extract_datadome_sdk_urls",
    "parse_datadome_cookie",
    "parse_datadome_response",
    "run_datadome_tag_vm",
]
