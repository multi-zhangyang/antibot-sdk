from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


@dataclass(slots=True)
class BrowserResult:
    ok: bool
    state: str
    url: str
    final_url: str = ""
    title: str = ""
    selectors: dict[str, Any] = field(default_factory=dict)
    # Session material recovered after a browser challenge flow.
    cookies: list[dict[str, Any]] = field(default_factory=list)
    cookie_header: str = ""
    cf_clearance: str | None = None
    turnstile_token: str | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CaptchaResult:
    provider: str
    ok: bool
    captcha_type: str | None = None
    capability: str | None = None
    ticket: str | None = None
    randstr: str | None = None
    verify_code: str | None = None
    elapsed_ms: int | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SolveRequest:
    """Provider-neutral request accepted by :meth:`AntibotClient.solve_batch`."""

    target_url: str
    provider: str = "auto"
    options: dict[str, Any] = field(default_factory=dict)
    timeout_sec: float | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target_url, str) or not self.target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("provider must be a non-empty string")
        self.provider = self.provider.lower()
        if not isinstance(self.options, Mapping):
            raise TypeError("options must be a mapping")
        self.options = dict(self.options)
        if self.timeout_sec is not None and self.timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")

    @classmethod
    def from_value(cls, value: SolveRequest | Mapping[str, Any]) -> SolveRequest:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("batch requests must be SolveRequest instances or mappings")
        data = dict(value)
        if "url" in data and "target_url" not in data:
            data["target_url"] = data.pop("url")
        return cls(**data)


@dataclass(slots=True)
class BatchItemResult:
    index: int
    request_id: str
    provider: str
    ok: bool
    elapsed_ms: int
    result: BrowserResult | CaptchaResult | None = None
    error_type: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BatchResult:
    ok: bool
    total: int
    succeeded: int
    failed: int
    elapsed_ms: int
    concurrency: int
    items: list[BatchItemResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
