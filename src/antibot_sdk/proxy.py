from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote, urlparse


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
        cfg = {"server": self.server}
        if self.username:
            cfg["username"] = self.username
        if self.password:
            cfg["password"] = self.password
        return cfg


def parse_proxy(value: str | None, *, default_scheme: str = "http") -> ProxyConfig | None:
    """Parse SDK proxy input.

    Supported forms:
      - host:port
      - host:port:user:pass
      - http://host:port
      - http://user:pass@host:port

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
        return ProxyConfig(
            scheme=(p.scheme or default_scheme).lower(),
            host=p.hostname,
            port=p.port,
            username=unquote(p.username) if p.username else None,
            password=unquote(p.password) if p.password else None,
        )

    parts = raw.split(":")
    if len(parts) >= 4:
        host, port_s, username = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        try:
            port = int(port_s)
        except ValueError as e:
            raise ValueError(f"invalid proxy port: {port_s!r}") from e
        return ProxyConfig(default_scheme, host, port, username, password)

    if len(parts) == 2:
        host, port_s = parts
        try:
            port = int(port_s)
        except ValueError as e:
            raise ValueError(f"invalid proxy port: {port_s!r}") from e
        return ProxyConfig(default_scheme, host, port)

    raise ValueError(f"unsupported proxy format: {value!r}")


def normalize_proxy_url(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.url if cfg else None


def normalize_proxy_server(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.server if cfg else None


def redacted_proxy(value: str | None, *, default_scheme: str = "http") -> str | None:
    cfg = parse_proxy(value, default_scheme=default_scheme)
    return cfg.redacted_url if cfg else None

