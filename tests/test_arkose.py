from __future__ import annotations

import asyncio
from io import BytesIO

from PIL import Image

from antibot_sdk.harness.contracts import ChallengeAction
from antibot_sdk.harness.adapters import default_adapter_registry
from antibot_sdk.harness.replay import evaluate_result
from antibot_sdk.models import CaptchaResult
from antibot_sdk.providers.arkose import (
    ArkoseChallengeSession,
    _arkose_payload_from_text,
    _arkose_pass_from_payload,
    _redact_event_url,
    _surface_is_loading,
    detect_arkose_provider,
    normalize_arkose_provider,
)


def _png(color: tuple[int, int, int]) -> bytes:
    image = Image.new("RGB", (160, 90), color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class _Element:
    def __init__(self, *, area: float = 1000, text: str = "", screenshots: list[bytes] | None = None):
        self.area = area
        self.text = text
        self.screenshots = list(screenshots or [_png((30, 40, 50))])
        self.clicks = 0

    async def count(self) -> int:
        return 1

    async def is_visible(self, **_kwargs) -> bool:
        return True

    async def bounding_box(self):
        return {"x": 0, "y": 0, "width": 160, "height": 90}

    async def screenshot(self, **_kwargs) -> bytes:
        value = self.screenshots[min(self.clicks, len(self.screenshots) - 1)]
        self.clicks += 1
        return value

    async def inner_text(self, **_kwargs) -> str:
        return self.text

    async def get_attribute(self, _name: str) -> str | None:
        return None

    async def click(self, **_kwargs) -> None:
        self.clicks += 1

    def locator(self, _selector: str):
        return _Locator([])


class _Locator:
    def __init__(self, items: list[_Element]):
        self.items = items

    async def count(self) -> int:
        return len(self.items)

    def nth(self, index: int):
        return self.items[index]

    @property
    def first(self):
        return self.items[0] if self.items else _Element()

    async def inner_text(self, **kwargs) -> str:
        return await self.first.inner_text(**kwargs) if self.items else ""


class _ArkoseFrame:
    def __init__(self, url: str, *, marker: bool, direct_surface: bool = False, screenshots=None, parent=None):
        self.url = url
        self.parent_frame = parent
        self.marker = marker
        self.direct_surface = direct_surface
        self.surface = _Element(screenshots=screenshots)

    def locator(self, selector: str):
        if selector == "canvas":
            return _Locator([self.surface])
        if selector == "body":
            return _Locator([_Element(text="Select the visible object")])
        return _Locator([])

    async def evaluate(self, script: str):
        if "iframe[src*='arkose']" in script:
            return self.marker
        if "[data-e2e='game-core-frame']" in script:
            return self.direct_surface
        return {}


class _ArkosePage:
    def __init__(self, frames):
        self.frames = frames
        self.main_frame = frames[0]

    async def evaluate(self, script: str):
        return await self.main_frame.evaluate(script)

    async def wait_for_timeout(self, _milliseconds: int) -> None:
        return None


class _ButtonFrame:
    def __init__(self, buttons: list[_Element]):
        self.buttons = buttons

    def locator(self, selector: str):
        if selector == "button, [role='button']":
            return _Locator(self.buttons)
        return _Locator([])


class _FailingSurface:
    async def screenshot(self, **_kwargs) -> bytes:
        raise RuntimeError("surface detached")


class _ReacquireSession(ArkoseChallengeSession):
    def __init__(self, ready_surface: _Element):
        super().__init__(_Page(), verification_wait_ms=0)
        self.ready_surface = ready_surface

    async def _find_surface(self):
        return object(), self.ready_surface, "canvas"


class _Page:
    async def wait_for_timeout(self, _milliseconds: int) -> None:
        return None


class _TokenSession(ArkoseChallengeSession):
    def __init__(self, tokens: list[str], *args, **kwargs):
        super().__init__(_Page(), *args, **kwargs)
        self.tokens = tokens

    async def read_tokens(self) -> list[str]:
        return list(self.tokens)


def test_arkose_alias_and_url_detection() -> None:
    assert normalize_arkose_provider("funcaptcha") == "arkose"
    assert normalize_arkose_provider("Arkose Labs") == "arkose"
    assert detect_arkose_provider("https://client-api.arkoselabs.com/fc/ca/") == "arkose"
    assert detect_arkose_provider("https://example.test/funcaptcha/widget") == "arkose"
    assert detect_arkose_provider("https://example.test/form") is None


def test_arkose_response_parser_requires_explicit_vendor_semantics() -> None:
    assert _arkose_pass_from_payload({"response": "answered"}) is True
    assert _arkose_pass_from_payload({"pass": False}) is False
    assert _arkose_pass_from_payload({"http_status": 200}) is None
    assert _arkose_pass_from_payload(_arkose_payload_from_text("response=answered")) is True
    assert _arkose_pass_from_payload(_arkose_payload_from_text('"failed"')) is False


def test_arkose_surface_prefers_nested_vendor_frame_over_business_canvas() -> None:
    main = _ArkoseFrame("https://example.test/checkout", marker=True)
    challenge = _ArkoseFrame(
        "https://client-api.arkoselabs.com/fc/gfct/",
        marker=True,
        parent=main,
    )
    session = ArkoseChallengeSession(_ArkosePage([main, challenge]), verification_wait_ms=0)

    found = asyncio.run(session._find_surface())

    assert found is not None
    frame, surface, selector = found
    assert frame is challenge
    assert surface is challenge.surface
    assert selector == "canvas"


def test_arkose_loading_shell_is_not_a_visual_task() -> None:
    loading = _Element(text="Verifying browser...")
    ready = _Element(text="Protecting your account Start Puzzle Audio")

    assert asyncio.run(_surface_is_loading(loading)) is True
    assert asyncio.run(_surface_is_loading(ready)) is False


def test_arkose_vendor_error_uses_reload_control_without_vision() -> None:
    button = _Element(text="Reload Challenge")
    frame = _ButtonFrame([button])
    session = ArkoseChallengeSession(_Page(), verification_wait_ms=0)
    controls = [{"index": 0, "label": "Reload Challenge", "box": None}]

    advanced = asyncio.run(
        session._advance_reload_control(
            frame,
            controls,
            "Something went wrong. Please reload the challenge to try again.",
        )
    )

    assert advanced is True
    assert button.clicks == 1
    assert session.diagnostics["arkose_navigation_actions"] == [
        {"kind": "reload_challenge", "control_index": 0}
    ]


def test_arkose_surface_capture_reacquires_replaced_locator() -> None:
    ready = _Element(screenshots=[_png((45, 55, 65))])
    session = _ReacquireSession(ready)
    session._navigation_attempts = 1

    screenshot, _frame, surface = asyncio.run(
        session._capture_surface(object(), _FailingSurface())
    )

    assert screenshot == _png((45, 55, 65))
    assert surface is ready
    assert session.diagnostics["arkose_surface_reacquired"] == 1


def test_arkose_replacement_marks_dynamic_and_rejects_old_observation_action() -> None:
    main = _ArkoseFrame("https://example.test/checkout", marker=True)
    challenge = _ArkoseFrame(
        "https://client-api.arkoselabs.com/fc/gfct/",
        marker=True,
        screenshots=[_png((20, 30, 40)), _png((80, 90, 100))],
        parent=main,
    )
    session = ArkoseChallengeSession(_ArkosePage([main, challenge]), verification_wait_ms=0)

    async def run() -> tuple[bool, bool, str]:
        first = await session.observe()
        second = await session.observe()
        assert first is not None and second is not None
        action = ChallengeAction(
            observation_id=first.observation_id,
            kind="point",
            payload={"points": [{"x": 40, "y": 30}]},
        )
        try:
            await session.execute(action)
        except Exception as exc:
            error = str(exc)
        else:
            error = ""
        return first.dynamic, second.dynamic, error

    first_dynamic, second_dynamic, error = asyncio.run(run())
    assert first_dynamic is False
    assert second_dynamic is True
    assert "current challenge surface" in error
    assert session.diagnostics["arkose_scene_replacements"] == 1


def test_arkose_event_url_drops_query_token_and_fragment() -> None:
    value = _redact_event_url(
        "https://client-api.arkoselabs.com/fc/ca/?session_token=secret#callback-token"
    )
    assert value == "https://client-api.arkoselabs.com/fc/ca/"
    assert "secret" not in value


def test_arkose_initialization_token_is_not_success_without_fc_ca_pass() -> None:
    async def run():
        session = _TokenSession(
            ["initialization-token-value-that-is-not-a-final-answer"],
            network_events=[
                {
                    "url": "https://client-api.arkoselabs.com/fc/gt2/public_key/",
                    "status": 200,
                }
            ],
            verification_wait_ms=0,
        )
        return await session.verify()

    verification = asyncio.run(run())
    assert verification.accepted is False
    assert verification.token_length > 20
    assert verification.vendor_pass is None
    assert "arkose_vendor_pass_not_observed" in verification.gaps


def test_arkose_fc_ca_failure_rejects_nonempty_token() -> None:
    async def run():
        session = _TokenSession(
            ["final-callback-token-value-that-is-long-enough"],
            network_events=[
                {
                    "url": "https://client-api.arkoselabs.com/fc/ca/",
                    "status": 200,
                    "pass": False,
                }
            ],
            verification_wait_ms=0,
        )
        return await session.verify()

    verification = asyncio.run(run())
    assert verification.accepted is False
    assert verification.vendor_pass is False
    assert "arkose_vendor_pass_not_observed" in verification.gaps


def test_arkose_requires_token_and_fc_ca_pass() -> None:
    async def run():
        session = _TokenSession(
            ["final-callback-token-value-that-is-long-enough"],
            network_events=[
                {
                    "url": "https://client-api.arkoselabs.com/fc/ca/",
                    "status": 200,
                    "pass": True,
                }
            ],
            verification_wait_ms=0,
        )
        return await session.verify()

    verification = asyncio.run(run())
    assert verification.accepted is True
    assert verification.vendor_pass is True
    assert verification.verifier_events == ("/fc/ca/",)


def test_arkose_adapter_rejects_token_without_vendor_response() -> None:
    result = CaptchaResult(
        provider="arkose",
        ok=True,
        ticket="final-callback-token-value-that-is-long-enough",
        diagnostics={},
    )
    verification = default_adapter_registry().verify_result(result, "funcaptcha")
    assert verification.accepted is False
    assert "arkose_fc_ca_pass_true_not_observed" in verification.gaps


def test_arkose_adapter_accepts_only_redacted_pass_record() -> None:
    result = CaptchaResult(
        provider="arkose",
        ok=True,
        ticket="final-callback-token-value-that-is-long-enough",
        diagnostics={
            "arkose_verification_responses": [
                {
                    "url": "https://client-api.arkoselabs.com/fc/ca/",
                    "status": 200,
                    "pass": True,
                    "token_persisted": False,
                }
            ]
        },
        raw={
            "events": [
                {
                    "kind": "arkose_response",
                    "url": "https://client-api.arkoselabs.com/fc/ca/",
                    "status": 200,
                }
            ]
        },
    )
    verification = default_adapter_registry().verify_result(result, "arkose")
    assert verification.accepted is True
    assert verification.token_length == len(result.ticket or "")


def test_arkose_replay_requires_vendor_pass_and_token_length() -> None:
    run = evaluate_result(
        {
            "provider": "arkose",
            "ok": True,
            "ticket": "final-callback-token-value-that-is-long-enough",
            "elapsed_ms": 1200,
            "diagnostics": {
                "token_len": 46,
                "arkose_verification_responses": [
                    {
                        "url": "https://client-api.arkoselabs.com/fc/ca/",
                        "status": 200,
                        "pass": True,
                        "token_persisted": False,
                    }
                ],
            },
            "raw": {"events": [], "token_len": 46},
        }
    )
    assert run.provider == "arkose"
    assert run.evidence_accepted is True
    assert run.vendor_passes == 1
    assert run.vendor_failures == 0
    assert run.token_length == 46
