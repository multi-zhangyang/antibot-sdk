from __future__ import annotations

import asyncio
import os
import shutil
import signal
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

SUPPORTED_PROXY_SCHEMES = frozenset({"http", "https", "socks4", "socks5"})
PROXY_ENVIRONMENT_KEYS = (
    "ANTIBOT_PROXY",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    scheme: str
    host: str
    port: int | None = None
    username: str | None = None
    password: str | None = None

    @property
    def has_auth(self) -> bool:
        return bool(self.username or self.password)

    @property
    def server(self) -> str:
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{self.host}{port}"

    @property
    def url(self) -> str:
        if not self.has_auth:
            return self.server
        user = quote(self.username or "", safe="")
        pwd = quote(self.password or "", safe="")
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{user}:{pwd}@{self.host}{port}"

    @property
    def redacted_url(self) -> str:
        if not self.has_auth:
            return self.server
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://***:***@{self.host}{port}"

    def playwright(self) -> dict[str, str]:
        """Playwright launch/context proxy dict (supports username/password)."""
        cfg = {"server": self.server}
        if self.username:
            cfg["username"] = self.username
        if self.password:
            cfg["password"] = self.password
        return cfg

    def chromium_server(self) -> str:
        """Value suitable for Chrome ``--proxy-server``.

        Chromium does **not** accept embedded credentials in ``--proxy-server``.
        Authenticated proxies must be bridged to a local anonymized proxy first.
        """
        return self.server


def _proxy_config(
    scheme: str,
    host: str,
    port: int | None,
    username: str | None = None,
    password: str | None = None,
) -> ProxyConfig:
    normalized_scheme = scheme.lower()
    if normalized_scheme not in SUPPORTED_PROXY_SCHEMES:
        supported = ", ".join(sorted(SUPPORTED_PROXY_SCHEMES))
        raise ValueError(f"unsupported proxy scheme {scheme!r}; expected one of: {supported}")
    if not host or any(char.isspace() for char in host):
        raise ValueError("proxy host must be non-empty and contain no whitespace")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"invalid proxy port: {port!r}")
    return ProxyConfig(normalized_scheme, host, port, username, password)


def parse_proxy(value: str | None, *, default_scheme: str = "http") -> ProxyConfig | None:
    """Parse SDK proxy input.

    Supported forms:
      - host:port
      - host:port:user:pass
      - http://host:port
      - http://user:pass@host:port
      - socks5://user:pass@host:port

    The host:port:user:pass form is common for proxy pools.  Password may
    contain additional ':' characters; they are preserved.
    """

    raw = (value or "").strip()
    if not raw:
        return None

    if "://" in raw:
        p = urlparse(raw)
        if not p.hostname:
            raise ValueError(f"invalid proxy: {value!r}")
        return _proxy_config(
            p.scheme or default_scheme,
            p.hostname,
            p.port,
            unquote(p.username) if p.username else None,
            unquote(p.password) if p.password else None,
        )

    parts = raw.split(":")
    if len(parts) >= 4:
        host, port_s, username = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        try:
            port = int(port_s)
        except ValueError as e:
            raise ValueError(f"invalid proxy port: {port_s!r}") from e
        return _proxy_config(default_scheme, host, port, username, password)

    if len(parts) == 2:
        host, port_s = parts
        try:
            port = int(port_s)
        except ValueError as e:
            raise ValueError(f"invalid proxy port: {port_s!r}") from e
        return _proxy_config(default_scheme, host, port)

    raise ValueError(f"unsupported proxy format: {value!r}")


def normalize_proxy_url(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.url if cfg else None


def normalize_proxy_server(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.server if cfg else None


def chromium_proxy_server(value: str | None, *, default_scheme: str = "http") -> str | None:
    """Return a Chromium-safe ``--proxy-server`` value (no credentials)."""
    return normalize_proxy_server(value, default_scheme=default_scheme)


def redacted_proxy(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.redacted_url if cfg else None


def env_proxy_candidates() -> dict[str, str | None]:
    """Surface common proxy-related environment variables (redacted values)."""
    keys = (
        "ANTIBOT_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    )
    out: dict[str, str | None] = {}
    for key in keys:
        raw = os.environ.get(key)
        if raw is None:
            out[key] = None
            continue
        if key.lower() in {"no_proxy"}:
            out[key] = raw
            continue
        try:
            out[key] = redacted_proxy(raw) or raw
        except Exception:
            out[key] = "***"
    return out


def proxy_free_environment() -> dict[str, str]:
    """Return a child-process environment without implicit proxy variables."""

    return {
        key: value
        for key, value in os.environ.items()
        if key not in PROXY_ENVIRONMENT_KEYS
    }


def resolve_runtime_proxy(
    explicit: str | None = None,
    *,
    use_env: bool | None = None,
) -> ProxyConfig | None:
    """Resolve proxy from explicit value or optional env fallback.

    Env fallback order when ``use_env`` is true (or ``ANTIBOT_USE_ENV_PROXY=1``):
    ``ANTIBOT_PROXY`` → ``HTTPS_PROXY`` → ``HTTP_PROXY`` → ``ALL_PROXY``.
    """
    if explicit:
        return parse_proxy(explicit)
    enabled = use_env
    if enabled is None:
        enabled = os.environ.get("ANTIBOT_USE_ENV_PROXY", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if not enabled:
        return None
    for key in ("ANTIBOT_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        value = os.environ.get(key)
        if value:
            return parse_proxy(value)
    return None


def _default_proxy_chain_dir() -> Path:
    return Path(__file__).resolve().parent / "vendor" / "aliyun"


class LocalAnonymizedProxy:
    """Bridge an authenticated upstream proxy to a local no-auth HTTP proxy.

    Chromium's ``--proxy-server`` cannot embed username/password. Aliyun's Node
    runner already uses ``proxy-chain`` for this; Cloudflare/Pydoll reuses the
    same vendored dependency so VPS authenticated proxies keep working.
    """

    def __init__(
        self,
        upstream: str | ProxyConfig,
        *,
        node: str | None = None,
        module_dir: Path | None = None,
    ):
        cfg = upstream if isinstance(upstream, ProxyConfig) else parse_proxy(str(upstream))
        if cfg is None:
            raise ValueError("upstream proxy is required")
        self.upstream = cfg
        self.node = node or shutil.which("node") or "node"
        self.module_dir = Path(module_dir or _default_proxy_chain_dir())
        self.local_url: str | None = None
        self._proc: asyncio.subprocess.Process | None = None

    @property
    def available(self) -> bool:
        return (self.module_dir / "node_modules" / "proxy-chain").exists()

    async def start(self, *, timeout: float = 15.0) -> str:
        if self.local_url:
            return self.local_url
        if not self.upstream.has_auth:
            self.local_url = self.upstream.server
            return self.local_url
        if not self.available:
            raise RuntimeError(
                "proxy-chain is not installed; run `antibot install-js-deps` "
                f"(expected under {self.module_dir / 'node_modules' / 'proxy-chain'})"
            )

        # proxy-chain@3 is ESM-only; use dynamic import instead of require().
        script = r"""
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const moduleDir = process.argv[1];
const upstream = process.argv[2];
const entry = pathToFileURL(path.join(moduleDir, 'node_modules', 'proxy-chain', 'dist', 'index.js')).href;
const ProxyChain = await import(entry);
const local = await ProxyChain.anonymizeProxy(upstream);
process.stdout.write(local + '\n');
const shutdown = async () => {
  try { await ProxyChain.closeAnonymizedProxy(local, true); } catch (_) {}
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.stdin.resume();
""".strip()
        self._proc = await asyncio.create_subprocess_exec(
            self.node,
            "--input-type=module",
            "-e",
            script,
            str(self.module_dir),
            self.upstream.url,
            cwd=str(self.module_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            env={
                **proxy_free_environment(),
                "NODE_PATH": str(self.module_dir / "node_modules"),
            },
            start_new_session=True,
        )
        assert self._proc.stdout is not None
        try:
            line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            await self.close()
            raise RuntimeError("timed out starting local anonymized proxy") from exc
        local = line.decode("utf-8", errors="replace").strip()
        if not local.startswith("http://") and not local.startswith("https://"):
            stderr = b""
            if self._proc.stderr is not None:
                try:
                    stderr = await asyncio.wait_for(self._proc.stderr.read(), timeout=1.0)
                except Exception:
                    stderr = b""
            await self.close()
            raise RuntimeError(
                "failed to start local anonymized proxy: "
                f"{local or '(empty)'} {stderr.decode('utf-8', errors='replace')[-500:]}"
            )
        self.local_url = local
        return local

    async def close(self) -> None:
        proc = self._proc
        self._proc = None
        local = self.local_url
        self.local_url = None
        if proc is None:
            return
        if proc.returncode is not None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except Exception:
            pass
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
                await asyncio.wait_for(proc.wait(), timeout=3)
                return
            except asyncio.TimeoutError:
                continue
        _ = local  # retained for readability / future explicit closeAnonymizedProxy hooks

    async def __aenter__(self) -> "LocalAnonymizedProxy":
        await self.start()
        return self

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        await self.close()


async def prepare_chromium_proxy(
    value: str | None,
    *,
    node: str | None = None,
    module_dir: Path | None = None,
) -> tuple[str | None, LocalAnonymizedProxy | None, dict]:
    """Prepare a Chromium-safe proxy server URL.

    Returns ``(proxy_server, bridge_or_none, diagnostics)``.
    """
    cfg = parse_proxy(value)
    diagnostics: dict = {
        "requested": redacted_proxy(value),
        "has_auth": bool(cfg and cfg.has_auth),
        "scheme": cfg.scheme if cfg else None,
    }
    if cfg is None:
        return None, None, diagnostics
    if not cfg.has_auth:
        diagnostics["mode"] = "direct"
        diagnostics["server"] = cfg.server
        return cfg.server, None, diagnostics

    bridge = LocalAnonymizedProxy(cfg, node=node, module_dir=module_dir)
    local = await bridge.start()
    diagnostics["mode"] = "anonymized_local_bridge"
    diagnostics["server"] = local
    diagnostics["upstream"] = cfg.redacted_url
    return local, bridge, diagnostics
