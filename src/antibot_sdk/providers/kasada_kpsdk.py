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

PROVIDER = "kasada_kpsdk"
CAPABILITY = "kasada_kpsdk_vm_primitive"
CAPTCHA_TYPE = "kasada_kpsdk_headers_experimental"
DEFAULT_TIMEOUT = 10
DEFAULT_SETTLE_MS = 50
VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "kasada_kpsdk"
KPSDK_VM_RUNNER = VENDOR_DIR / "kpsdk_vm_runner.mjs"

_KPSDK_HEADER_PREFIX = "x-kpsdk-"
_DONE_PREFIX = "KPSDK:DONE"


def run_kasada_kpsdk_vm(
    script: str,
    *,
    script_url: str | None = None,
    page_url: str = "https://example.test/",
    request_url: str | None = None,
    request_method: str = "GET",
    request_transport: str = "fetch",
    request_headers: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    node: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT,
    settle_ms: int = DEFAULT_SETTLE_MS,
) -> dict[str, Any]:
    """Execute a local Kasada KPSDK script inside the bundled browserless Node VM shim."""

    source = _load_text_arg(script)
    if not source.strip():
        raise ValueError("Kasada KPSDK VM requires non-empty script")
    node_bin = node or shutil.which("node")
    if not node_bin:
        raise RuntimeError("node executable is required for Kasada KPSDK VM mode")
    if not KPSDK_VM_RUNNER.is_file():
        raise RuntimeError(f"Kasada KPSDK VM helper is missing: {KPSDK_VM_RUNNER}")
    transport = (request_transport or "fetch").lower()
    if transport not in {"fetch", "xhr"}:
        raise ValueError("Kasada KPSDK request_transport must be 'fetch' or 'xhr'")

    payload = {
        "script": source,
        "script_url": script_url,
        "page_url": page_url or "https://example.test/",
        "request_url": request_url or "",
        "request_method": (request_method or "GET").upper(),
        "request_transport": transport,
        "request_headers": {str(k): str(v) for k, v in (request_headers or {}).items()},
        "config": config or None,
        "profile": profile or {},
        "settle_ms": max(0, int(settle_ms)),
        "vm_timeout_ms": max(1000, int(timeout_sec * 1000)),
    }
    try:
        proc = subprocess.run(
            [node_bin, str(KPSDK_VM_RUNNER)],
            input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_sec) + 2),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Kasada KPSDK VM helper timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "Kasada KPSDK VM helper failed").strip()
        raise RuntimeError(message)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Kasada KPSDK VM helper returned non-JSON output") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Kasada KPSDK VM helper returned invalid payload")
    return data


def extract_kpsdk_headers(vm_result: dict[str, Any]) -> dict[str, str]:
    """Return normalized ``x-kpsdk-*`` headers from the protected request capture."""

    if not isinstance(vm_result, dict):
        return {}
    candidates: list[Any] = []
    request = vm_result.get("request")
    if isinstance(request, dict):
        last = request.get("last")
        if isinstance(last, dict):
            candidates.append(last.get("headers"))
        for item in reversed(request.get("fetches") or []):
            if isinstance(item, dict):
                candidates.append(item.get("headers"))
    for key in ("fetches", "xhrs"):
        for item in reversed(vm_result.get(key) or []):
            if isinstance(item, dict):
                candidates.append(item.get("headers"))

    for candidate in candidates:
        headers = _normalize_headers(candidate)
        kpsdk = {k: v for k, v in headers.items() if k.startswith(_KPSDK_HEADER_PREFIX)}
        if kpsdk:
            return dict(sorted(kpsdk.items()))
    return {}


def parse_kpsdk_done_messages(messages: list[Any] | None) -> list[dict[str, Any]]:
    """Parse ``KPSDK:DONE:*`` postMessage captures into compact summaries."""

    out: list[dict[str, Any]] = []
    for index, item in enumerate(messages or []):
        if isinstance(item, dict):
            data = item.get("data")
            origin = item.get("origin")
            at = item.get("at")
        else:
            data = item
            origin = None
            at = None
        if not isinstance(data, str) or not data.startswith(_DONE_PREFIX):
            continue
        ct = ""
        if data == _DONE_PREFIX:
            ct = ""
        elif data.startswith(_DONE_PREFIX + ":"):
            ct = data[len(_DONE_PREFIX) + 1 :]
        out.append({"index": index, "raw": data, "ct": ct, "origin": origin, "at": at})
    return out


def extract_kasada_sdk_urls(html_or_js: str, base_url: str = "") -> list[str]:
    """Extract likely Kasada/KPSDK SDK URLs from HTML or script text."""

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
        if not any(marker in lowered for marker in ("kasada", "kpsdk", "/p.js", "/ips.js", "x-kpsdk")):
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


class KasadaKpsdkSolver:
    """Browserless Kasada KPSDK primitive.

    The provider executes a caller-supplied or explicitly fetched KPSDK script in a minimal Node VM
    browser shim, triggers an optional protected request, and returns captured ``x-kpsdk-*`` headers
    or ``KPSDK:DONE`` messages. It intentionally does not start Chrome/Playwright.
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
        request_url: str | None = None,
        request_method: str = "GET",
        request_transport: str = "fetch",
        request_headers: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        config: dict[str, Any] | None = None,
        config_json: str | dict[str, Any] | None = None,
        config_file: str | None = None,
        profile: dict[str, Any] | None = None,
        profile_json: str | dict[str, Any] | None = None,
        profile_file: str | None = None,
        node: str | None = None,
        timeout_sec: int = DEFAULT_TIMEOUT,
        settle_ms: int = DEFAULT_SETTLE_MS,
        proxy_server: str | None = None,
        output_dir: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "mode": "browserless_vm_primitive",
            "script_url": script_url,
            "page_url": page_url,
            "request_url": request_url,
            "request_method": (request_method or "GET").upper(),
            "request_transport": request_transport,
            "allow_network": allow_network,
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
            merged_request_headers = _merge_headers(headers, request_headers)
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
            config_obj = _load_json_obj(config, config_json, config_file, "config")
            profile_obj = _load_json_obj(profile, profile_json, profile_file, "profile") or {}
            vm_result = run_kasada_kpsdk_vm(
                script,
                script_url=script_url,
                page_url=page_url,
                request_url=request_url,
                request_method=request_method,
                request_transport=request_transport,
                request_headers=merged_request_headers,
                config=config_obj,
                profile=profile_obj,
                node=node,
                timeout_sec=timeout_sec,
                settle_ms=settle_ms,
            )
            raw["vm"] = vm_result
            vm_diag = vm_result.get("diagnostics") if isinstance(vm_result.get("diagnostics"), dict) else {}
            kpsdk_headers = extract_kpsdk_headers(vm_result)
            done_messages = parse_kpsdk_done_messages(vm_result.get("messages") if isinstance(vm_result, dict) else [])
            diagnostics.update(
                {
                    "kpsdk_present": bool(vm_diag.get("kpsdkPresent")),
                    "kpsdk_ready": bool(vm_diag.get("kpsdkReady")),
                    "message_count": int(vm_diag.get("messageCount") or len(vm_result.get("messages") or [])),
                    "fetch_count": int(vm_diag.get("fetchCount") or len(vm_result.get("fetches") or [])),
                    "xhr_count": len(vm_result.get("xhrs") or []),
                    "header_keys": sorted(kpsdk_headers),
                    "done_count": len(done_messages),
                    "kpsdk_keys": vm_diag.get("kpsdkKeys") or [],
                }
            )
            raw["headers"] = kpsdk_headers
            raw["doneMessages"] = done_messages
            if kpsdk_headers:
                ticket = json.dumps(
                    {"headers": kpsdk_headers, "done": done_messages[-1] if done_messages else None},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                return finish(ok=True, ticket=ticket, verify_code="headers")
            if done_messages:
                ticket = json.dumps({"done": done_messages}, ensure_ascii=False, separators=(",", ":"))
                return finish(ok=True, ticket=ticket, verify_code="done")
            errors.append("Kasada KPSDK VM did not capture x-kpsdk headers or KPSDK:DONE messages")
            return finish(ok=False, ticket=None, verify_code="no_kpsdk_artifacts")
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
            raise ValueError("Kasada KPSDK solve requires script_js, script_file, or script_url")
        if not allow_network:
            raise ValueError("script_url fetch is disabled by default; pass allow_network=True for mocks")
        resp = requests.get(
            script_url,
            headers=headers or {},
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["scriptResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "bodyPrefix": resp.text[:120],
        }
        resp.raise_for_status()
        return resp.text


def _normalize_headers(value: Any) -> dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(k).lower(): str(v) for k, v in value.items()}
    if isinstance(value, list):
        out: dict[str, str] = {}
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out[str(item[0]).lower()] = str(item[1])
        return out
    return {}


def _merge_headers(*items: dict[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if item:
            out.update({str(k): str(v) for k, v in item.items()})
    return out


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
        raise ValueError(f"Kasada KPSDK {name} must be a JSON object")
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
    (out / "kasada_kpsdk_run.json").write_text(
        json.dumps(raw, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


__all__ = [
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "DEFAULT_SETTLE_MS",
    "DEFAULT_TIMEOUT",
    "KPSDK_VM_RUNNER",
    "PROVIDER",
    "KasadaKpsdkSolver",
    "extract_kasada_sdk_urls",
    "extract_kpsdk_headers",
    "parse_kpsdk_done_messages",
    "run_kasada_kpsdk_vm",
]
