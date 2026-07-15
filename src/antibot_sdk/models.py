from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
