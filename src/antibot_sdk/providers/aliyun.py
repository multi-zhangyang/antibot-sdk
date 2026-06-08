from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..models import CaptchaResult
from ..profiles import aliyun_profile_for_url
from ..proxy import normalize_proxy_url, redacted_proxy

VENDOR_DIR = Path(__file__).resolve().parents[1] / "vendor" / "aliyun"
BRIDGE = VENDOR_DIR / "bridge.js"


def is_recoverable_attempt_codes(codes: list[str]) -> bool:
    transient = [
        c for c in codes
        if c in {"", "NONE"}
        or "captcha not ready" in c
        or "Navigation timeout" in c
        or "timeout" in c.lower()
        or "gap not found" in c
        or "candidate rejected" in c
    ]
    repeated_f001 = codes.count("F001") >= 2
    return len(codes) >= 2 and (repeated_f001 or len(transient) >= 2)


def discover_chrome() -> str | None:
    for root in (Path.home() / ".cache" / "ms-playwright", Path("/ms-playwright")):
        if root.exists():
            for path in sorted(root.glob("chromium-*/chrome-linux*/chrome"), reverse=True):
                if path.is_file():
                    return str(path)
    for name in ("google-chrome-stable", "google-chrome", "chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


class AliyunCaptchaSolver:
    """Aliyun CAPTCHA V3 slider adapter using the bundled Node runner."""

    def __init__(self, node: str | None = None):
        self.node = node or shutil.which("node") or "node"

    @staticmethod
    def vendor_dir() -> Path:
        return VENDOR_DIR

    @staticmethod
    def js_deps_installed() -> bool:
        return (VENDOR_DIR / "node_modules" / "puppeteer-core").exists()

    @staticmethod
    def install_js_deps() -> None:
        subprocess.run(["npm", "install"], cwd=str(VENDOR_DIR), check=True)

    async def solve(
        self,
        *,
        target_url: str,
        chrome_path: str | None = None,
        headless: bool | str | None = None,
        output_dir: str | None = None,
        out: str | None = None,
        proxy_server: str | None = None,
        user_agent: str | None = None,
        selectors: dict[str, str] | None = None,
        site_profile: str | None = "auto",
        profile: dict[str, Any] | None = None,
        env: dict[str, str] | None = None,
        verify_wait_ms: int | None = None,
        captcha_wait_ms: int | None = None,
        max_attempts: int | None = None,
        timeout_sec: int = 180,
        cleanup_profile: bool = True,
        extra_options: dict[str, Any] | None = None,
        session_retries: int | None = None,
        session_retry_delay_sec: float | None = None,
        session_retry_max_attempts: int | None = None,
        _session_retry_depth: int = 0,
    ) -> CaptchaResult:
        import asyncio

        output_root = output_dir or tempfile.mkdtemp(prefix="antibot-aliyun-run-")
        final_out = out or str(Path(output_root) / "aliyun_captcha_run.json")
        user_data_dir = tempfile.mkdtemp(prefix="antibot-aliyun-profile-")

        user_max_attempts = max_attempts is not None
        user_session_retries = session_retries is not None
        user_session_retry_max_attempts = session_retry_max_attempts is not None
        resolved_site = aliyun_profile_for_url(target_url, site_profile)
        merged_profile: dict[str, Any] = {}
        merged_selectors: dict[str, str] = {}
        merged_env: dict[str, str] = {}
        if resolved_site:
            merged_profile.update(resolved_site.profile)
            merged_selectors.update(resolved_site.selectors)
            merged_env.update(resolved_site.env)
            if resolved_site.verify_wait_ms and verify_wait_ms is None:
                verify_wait_ms = resolved_site.verify_wait_ms
            if resolved_site.captcha_wait_ms and captcha_wait_ms is None:
                captcha_wait_ms = resolved_site.captcha_wait_ms
            if resolved_site.max_attempts and max_attempts is None:
                max_attempts = resolved_site.max_attempts
            if resolved_site.session_retries is not None and session_retries is None:
                session_retries = resolved_site.session_retries
            if resolved_site.session_retry_delay_sec is not None and session_retry_delay_sec is None:
                session_retry_delay_sec = resolved_site.session_retry_delay_sec
            if resolved_site.session_retry_max_attempts is not None and session_retry_max_attempts is None:
                session_retry_max_attempts = resolved_site.session_retry_max_attempts
            if proxy_server:
                if (
                    resolved_site.proxy_max_attempts is not None
                    and not user_max_attempts
                ):
                    max_attempts = resolved_site.proxy_max_attempts
                if (
                    resolved_site.proxy_session_retries is not None
                    and not user_session_retries
                ):
                    session_retries = resolved_site.proxy_session_retries
                if (
                    resolved_site.proxy_session_retry_max_attempts is not None
                    and not user_session_retry_max_attempts
                ):
                    session_retry_max_attempts = resolved_site.proxy_session_retry_max_attempts
            if headless is None:
                headless = resolved_site.headless
        if selectors:
            merged_selectors.update(selectors)
        if profile:
            merged_profile.update(profile)
        if env:
            merged_env.update({k: str(v) for k, v in env.items()})
        if captcha_wait_ms:
            merged_env["CAPTCHA_WAIT_MS"] = str(captcha_wait_ms)

        options: dict[str, Any] = {
            "targetUrl": target_url,
            "outputDir": output_root,
            "out": final_out,
            "browserArgs": [f"--user-data-dir={user_data_dir}"],
        }
        if headless is not None:
            options["headless"] = headless
        if resolved_site and resolved_site.site_profile:
            options["siteProfile"] = resolved_site.site_profile
        chrome_path = chrome_path or discover_chrome()
        if chrome_path:
            options["chromePath"] = chrome_path
        if proxy_server:
            options["proxyServer"] = normalize_proxy_url(proxy_server)
        if user_agent:
            options["userAgent"] = user_agent
        if merged_selectors:
            options["selectors"] = merged_selectors
        if merged_profile:
            options["profile"] = merged_profile
        if merged_env:
            options["env"] = merged_env
        if verify_wait_ms:
            options["verifyWaitMs"] = verify_wait_ms
        if max_attempts:
            options["maxAttempts"] = max_attempts
        if extra_options:
            if extra_options.get("browserArgs"):
                options["browserArgs"] = [*options.get("browserArgs", []), *extra_options["browserArgs"]]
                extra_options = {k: v for k, v in extra_options.items() if k != "browserArgs"}
            options.update(extra_options)

        def load_out_json() -> dict[str, Any]:
            for candidate in (options.get("out"), final_out, Path(output_root) / "aliyun_captcha_run.json"):
                try:
                    p = Path(str(candidate))
                    if p.is_file():
                        return json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
            return {}

        def build_result(
            raw: dict[str, Any] | None,
            *,
            ok: bool | None = None,
            errors: list[str] | None = None,
            stderr: str = "",
            timed_out: bool = False,
        ) -> CaptchaResult:
            raw = raw or {}
            verify = raw.get("verifyResponse") or {}
            verify_ok = verify.get("VerifyResult") is True or verify.get("VerifyCode") == "T001"
            is_ok = bool(raw.get("ok") or verify_ok) if ok is None else ok
            artifacts = {
                "out": str(raw.get("out") or final_out),
                "outputDir": str(raw.get("outputDir") or output_root),
            }
            for name in ("aliyun_bg_selected.png", "aliyun_puzzle_selected.png"):
                p = Path(artifacts["outputDir"]) / name
                if p.exists():
                    artifacts[name] = str(p)
            raw_error = raw.get("error") or {}
            raw_msg = raw_error.get("message") if isinstance(raw_error, dict) else raw_error
            err_list = errors or []
            if not is_ok and not err_list:
                err_list = [str(raw.get("verifyFailureCode") or raw_msg or "solve_failed")]
            diagnostics = {
                "site_profile": resolved_site.name if resolved_site else None,
                "attempt": raw.get("attempt"),
                "maxAttempts": raw.get("maxAttempts") or max_attempts,
                "candidate": raw.get("candidate"),
                "trajectory": raw.get("trajectory"),
                "chromePath": chrome_path,
                "headless": headless if headless is not None else "runner-default",
                "timed_out": timed_out,
                "proxy": redacted_proxy(proxy_server),
            }
            attempts = raw.get("attempts") or []
            codes = [
                str(a.get("verifyFailureCode") or a.get("verifyCode") or a.get("error") or "")
                for a in attempts
                if isinstance(a, dict)
            ]
            if proxy_server is None and codes.count("F001") >= 2:
                diagnostics["failure_class"] = "likely_ip_or_session_reputation"
                diagnostics["hint"] = "Qoder/Aliyun F001 repeated without proxy; use proxy_server or cooldown, then retry same profile."
            if attempts:
                diagnostics["attempt_codes"] = codes
                diagnostics["f001_count"] = codes.count("F001")
            if stderr:
                diagnostics["stderr_tail"] = stderr[-2000:]
            return CaptchaResult(
                provider="aliyun",
                ok=is_ok,
                verify_code=verify.get("VerifyCode") or raw.get("verifyFailureCode"),
                elapsed_ms=raw.get("elapsedMs"),
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if is_ok else err_list,
            )

        async def maybe_session_retry(result: CaptchaResult) -> CaptchaResult:
            retry_budget = max(0, int(session_retries or 0))
            if result.ok or _session_retry_depth >= retry_budget:
                return result
            attempts = result.raw.get("attempts") if isinstance(result.raw, dict) else []
            codes = [
                str(a.get("verifyFailureCode") or a.get("verifyCode") or a.get("error") or "")
                for a in (attempts or [])
                if isinstance(a, dict)
            ]
            repeated_f001 = codes.count("F001") >= 2 or result.diagnostics.get("failure_class") == "likely_ip_or_session_reputation"
            mixed_recoverable = repeated_f001 or is_recoverable_attempt_codes(codes)
            if not mixed_recoverable:
                return result
            delay = float(session_retry_delay_sec if session_retry_delay_sec is not None else 3.0)
            if delay > 0:
                await asyncio.sleep(delay)
            retry_no = _session_retry_depth + 1
            retry_output_dir = None
            if output_dir:
                retry_output_dir = str(Path(output_dir) / f"session_retry_{retry_no}")
            retry_max_attempts = session_retry_max_attempts
            if retry_max_attempts is None:
                retry_max_attempts = min(int(max_attempts or 5), 2)
            retried = await self.solve(
                target_url=target_url,
                chrome_path=chrome_path,
                headless=headless,
                output_dir=retry_output_dir,
                out=None,
                proxy_server=proxy_server,
                user_agent=user_agent,
                selectors=selectors,
                site_profile=site_profile,
                profile=profile,
                env=env,
                verify_wait_ms=verify_wait_ms,
                captcha_wait_ms=captcha_wait_ms,
                max_attempts=retry_max_attempts,
                timeout_sec=timeout_sec,
                cleanup_profile=cleanup_profile,
                extra_options=extra_options,
                session_retries=session_retries,
                session_retry_delay_sec=session_retry_delay_sec,
                session_retry_max_attempts=session_retry_max_attempts,
                _session_retry_depth=retry_no,
            )
            retried.diagnostics["session_retry"] = {
                "used": retry_no,
                "delay_sec": delay,
                "retry_max_attempts": retry_max_attempts,
                "previous_errors": result.errors,
                "previous_attempt_codes": codes,
                "previous_out": result.artifacts.get("out"),
            }
            return retried

        async def terminate_process_group(proc: asyncio.subprocess.Process) -> None:
            if proc.returncode is not None:
                return
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    return
                except Exception:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        return
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                    return
                except asyncio.TimeoutError:
                    continue

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fp:
            json.dump(options, fp, ensure_ascii=False)
            options_path = fp.name
        stdout = b""
        stderr = b""
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.node,
                str(BRIDGE),
                options_path,
                cwd=str(VENDOR_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "NODE_PATH": str(VENDOR_DIR / "node_modules")},
                start_new_session=True,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            except asyncio.TimeoutError:
                await terminate_process_group(proc)
                err = f"aliyun solver timeout after {timeout_sec}s"
                raw = load_out_json()
                recovered = build_result(raw, timed_out=True)
                if recovered.ok:
                    recovered.diagnostics["process_timeout_recovered"] = True
                    recovered.diagnostics["timeout_note"] = err
                    return recovered
                failed = build_result(raw, ok=False, errors=[err], timed_out=True)
                return await maybe_session_retry(failed)
            except asyncio.CancelledError:
                await terminate_process_group(proc)
                raise
        except asyncio.CancelledError:
            if proc is not None:
                await terminate_process_group(proc)
            raise
        except Exception as e:
            err = f"aliyun solver process failed: {e}"
            raw = load_out_json()
            return build_result(raw, ok=False, errors=[err], stderr=str(e))
        finally:
            try:
                os.unlink(options_path)
            except OSError:
                pass
            if cleanup_profile:
                shutil.rmtree(user_data_dir, ignore_errors=True)

        if proc is None:
            return build_result(load_out_json(), ok=False, errors=["aliyun solver process did not start"])
        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[-4000:]
            raw = load_out_json() or {"stderr": err}
            return build_result(raw, ok=False, errors=[err or "node bridge failed"], stderr=err)
        try:
            raw = json.loads(stdout.decode() or "{}")
        except json.JSONDecodeError as e:
            err = stderr.decode(errors="replace")[-4000:]
            raw = load_out_json()
            if raw:
                return await maybe_session_retry(build_result(raw, stderr=err))
            return build_result(raw, ok=False, errors=[f"invalid bridge json: {e}", err], stderr=err)
        return await maybe_session_retry(build_result(raw))
