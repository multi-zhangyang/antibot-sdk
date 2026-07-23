import asyncio
from io import BytesIO

from PIL import Image
import pytest

from antibot_sdk.harness import (
    BrowserChallengeSession,
    ChallengeAction,
    ChallengeAgentLoop,
    StaticActionPlanningBackend,
    VendorVerification,
    VisionChallengePolicy,
)
from antibot_sdk.vision import StaticVisionBackend


def _png() -> bytes:
    output = BytesIO()
    Image.new("RGB", (400, 300), (230, 230, 230)).save(output, format="PNG")
    return output.getvalue()


class _Control:
    def __init__(self, data, page) -> None:
        self.data = data
        self.page = page
        self.calls = []

    async def evaluate(self, _script, index):
        assert index == self.data["index"]
        return dict(self.data)

    async def click(self, *, timeout: int, delay: int):
        self.calls.append(("click", timeout, delay))
        if "verify" in self.data["text"].casefold():
            self.page.submitted = True

    async def fill(self, value: str):
        self.calls.append(("fill", value))
        self.page.value = value

    async def press(self, key: str):
        self.calls.append(("press", key))


class _Controls:
    def __init__(self, controls) -> None:
        self.controls = controls

    async def count(self):
        return len(self.controls)

    def nth(self, index):
        return self.controls[index]


class _Prompt:
    first = None

    def __init__(self):
        self.first = self

    async def count(self):
        return 1

    async def inner_text(self, *, timeout: int):
        assert timeout == 300
        return "Enter the answer and verify"


class _Surface:
    def __init__(self, page) -> None:
        self.page = page
        self.prompt = _Prompt()
        self.controls = _Controls(
            [
                _Control(
                    {
                        "index": 0,
                        "tag": "input",
                        "type": "text",
                        "role": "",
                        "aria": "Answer",
                        "title": "",
                        "placeholder": "",
                        "name": "answer",
                        "text": "",
                        "disabled": False,
                        "draggable": False,
                        "bounds": {"x": 30, "y": 50, "width": 120, "height": 32},
                    },
                    page,
                ),
                _Control(
                    {
                        "index": 1,
                        "tag": "button",
                        "type": "",
                        "role": "",
                        "aria": "",
                        "title": "",
                        "placeholder": "",
                        "name": "",
                        "text": "Verify",
                        "disabled": False,
                        "draggable": False,
                        "bounds": {"x": 200, "y": 220, "width": 100, "height": 36},
                    },
                    page,
                ),
            ]
        )

    async def screenshot(self, **kwargs):
        assert kwargs == {"type": "png", "animations": "disabled"}
        return _png()

    async def bounding_box(self):
        return {"x": 10.0, "y": 20.0, "width": 400.0, "height": 300.0}

    def locator(self, selector: str):
        if selector.startswith("button"):
            return self.controls
        return self.prompt

    async def click(self, *, position):
        self.page.clicks.append(position)


class _Page:
    def __init__(self):
        self.submitted = False
        self.value = ""
        self.clicks = []
        self.waits = []
        self.mouse = _Mouse()

    async def wait_for_timeout(self, milliseconds: int):
        self.waits.append(milliseconds)


class _Mouse:
    def __init__(self):
        self.calls = []

    async def move(self, x: float, y: float, *, steps: int | None = None):
        self.calls.append(("move", x, y, steps))

    async def down(self):
        self.calls.append(("down",))

    async def up(self):
        self.calls.append(("up",))


class _FailingControl(_Control):
    async def click(self, *, timeout: int, delay: int):
        del timeout, delay
        raise RuntimeError("dom node was replaced during click")


class _BrokenControl(_Control):
    async def evaluate(self, _script, _index):
        raise RuntimeError("detached dom node")


class _VisibilitySurface(_Surface):
    async def is_visible(self, *, timeout: int):
        del timeout
        return self.page.surface_visible


def _control_data(
    index: int,
    *,
    tag: str = "button",
    text: str = "Continue",
    bounds: dict[str, float] | None = None,
    disabled: bool = False,
    visible: bool = True,
) -> dict:
    return {
        "index": index,
        "tag": tag,
        "type": "text" if tag == "input" else "",
        "role": "",
        "aria": "",
        "title": "",
        "placeholder": "",
        "name": "",
        "text": text,
        "disabled": disabled,
        "draggable": False,
        "visible": visible,
        "bounds": bounds or {"x": 20, "y": 30, "width": 100, "height": 36},
    }


def test_browser_session_exposes_dom_affordances_and_executes_generic_actions() -> None:
    page = _Page()
    surface = _Surface(page)
    diagnostics = {}

    async def verifier():
        return VendorVerification(
            provider="new-vendor",
            accepted=page.submitted,
            token_length=48 if page.submitted else 0,
            gaps=() if page.submitted else ("vendor_not_verified",),
        )

    session = BrowserChallengeSession(
        page,
        provider="new-vendor",
        surface=surface,
        verifier=verifier,
        diagnostics=diagnostics,
    )
    action_backend = StaticActionPlanningBackend(
        [
            {
                "action": "type",
                "payload": {"affordance_id": "control-0", "text": "7"},
                "confidence": 0.95,
            },
            {
                "action": "submit",
                "payload": {},
                "confidence": 0.96,
            },
        ]
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=action_backend,
            ),
            max_steps=4,
        ).run()
    )

    assert result.accepted is True
    assert page.value == "7"
    assert diagnostics["browser_scene_observations"][0]["affordance_count"] == 2
    assert [item["kind"] for item in result.diagnostics["challenge_actions"]] == [
        "type",
        "submit",
    ]
    assert all(item["executed"] for item in result.diagnostics["challenge_actions"])


def test_browser_session_refuses_to_claim_success_without_verifier() -> None:
    page = _Page()
    session = BrowserChallengeSession(
        page,
        provider="unverified-vendor",
        surface=_Surface(page),
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=StaticActionPlanningBackend(
                    [
                        {
                            "action": "click",
                            "payload": {"affordance_id": "control-1"},
                            "confidence": 0.9,
                        }
                    ]
                ),
            ),
            max_steps=2,
        ).run()
    )

    assert result.accepted is False
    assert "browser_session_verifier_not_configured" in result.errors


def test_browser_session_filters_hidden_broken_and_outside_controls_and_clips_bounds() -> None:
    page = _Page()
    surface = _Surface(page)
    surface.controls = _Controls(
        [
            _Control(
                _control_data(
                    0,
                    text="Next",
                    bounds={"x": 0, "y": 10, "width": 30, "height": 30},
                ),
                page,
            ),
            _Control(
                _control_data(1, text="Hidden", visible=False),
                page,
            ),
            _Control(
                _control_data(2, text="Outside", bounds={"x": 999, "y": 999, "width": 20, "height": 20}),
                page,
            ),
            _BrokenControl(_control_data(3, text="Broken"), page),
            _Control(
                _control_data(4, text="Verify", disabled=True),
                page,
            ),
        ]
    )
    session = BrowserChallengeSession(page, provider="fixture", surface=surface)

    observation = asyncio.run(session.observe())

    assert observation is not None
    assert [item.label for item in observation.affordances] == ["Next", "Verify"]
    assert observation.affordances[0].x == 0
    assert observation.affordances[0].y == 0
    assert observation.affordances[0].width == 20
    assert observation.affordances[0].height == 20
    assert "submit" not in observation.allowed_actions
    assert observation.affordances[1].enabled is False


def test_browser_session_marks_dynamic_replacement_and_rejects_stale_affordance() -> None:
    page = _Page()
    surface = _Surface(page)
    session = BrowserChallengeSession(page, provider="fixture", surface=surface)

    first = asyncio.run(session.observe())
    assert first is not None
    asyncio.run(
        session.execute(
            ChallengeAction(
                observation_id=first.observation_id,
                kind="click",
                payload={"affordance_id": "control-1"},
            )
        )
    )
    surface.controls = _Controls(
        [
            _Control(
                _control_data(
                    0,
                    tag="input",
                    text="Answer changed",
                    bounds={"x": 30, "y": 50, "width": 120, "height": 32},
                ),
                page,
            ),
            _Control(_control_data(1, text="Verify changed"), page),
        ]
    )
    second = asyncio.run(session.observe())

    assert second is not None
    assert second.observation_id != first.observation_id
    assert second.dynamic is True
    assert session.diagnostics["browser_scene_replacements"] == 1
    with pytest.raises(ValueError, match="does not target current observation"):
        asyncio.run(
            session.execute(
                ChallengeAction(
                    observation_id=first.observation_id,
                    kind="click",
                    payload={"affordance_id": "control-1"},
                )
            )
        )


def test_browser_session_does_not_mark_action_executed_when_dom_execution_fails() -> None:
    page = _Page()
    surface = _Surface(page)
    surface.controls = _Controls([_FailingControl(_control_data(0), page)])
    session = BrowserChallengeSession(page, provider="fixture", surface=surface)

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=StaticActionPlanningBackend(
                    [
                        {
                            "action": "click",
                            "payload": {"affordance_id": "control-0"},
                            "confidence": 0.9,
                        }
                    ]
                ),
            ),
            max_steps=2,
        ).run()
    )

    assert result.accepted is False
    assert result.diagnostics["challenge_actions"][0]["valid"] is True
    assert result.diagnostics["challenge_actions"][0]["executed"] is False
    assert "RuntimeError: dom node was replaced during click" in result.errors
    assert "browser_scene_actions" not in result.diagnostics["session"]


def test_browser_session_stops_after_verifier_accepts_even_if_surface_remains() -> None:
    page = _Page()
    page.surface_visible = True
    surface = _Surface(page)

    async def verifier():
        return VendorVerification(
            provider="fixture",
            accepted=bool(page.value),
            token_length=64 if page.value else 0,
            gaps=() if page.value else ("vendor_not_verified",),
        )

    session = BrowserChallengeSession(
        page,
        provider="fixture",
        surface=surface,
        verifier=verifier,
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                action_backend=StaticActionPlanningBackend(
                    [
                        {
                            "action": "type",
                            "payload": {"affordance_id": "control-0", "text": "ok"},
                            "confidence": 0.9,
                        }
                    ]
                ),
            ),
            max_steps=3,
        ).run()
    )

    assert result.accepted is True
    assert len(result.diagnostics["challenge_observations"]) == 1


def test_browser_session_rejects_ambiguous_verification_sources() -> None:
    page = _Page()

    async def verifier():
        return VendorVerification(provider="fixture", accepted=True, token_length=32)

    with pytest.raises(ValueError, match="mutually exclusive"):
        BrowserChallengeSession(
            page,
            provider="fixture",
            surface=_Surface(page),
            verifier=verifier,
            token_reader=lambda: ["a" * 32],
        )
    with pytest.raises(ValueError, match="require a token reader"):
        BrowserChallengeSession(
            page,
            provider="fixture",
            surface=_Surface(page),
            vendor_pass_reader=lambda: True,
        )


def test_browser_session_executes_canvas_point_drag_and_targeted_keyboard_actions() -> None:
    page = _Page()
    surface = _Surface(page)
    canvas = _Control(
        _control_data(
            0,
            tag="canvas",
            text="Puzzle canvas",
            bounds={"x": 10, "y": 20, "width": 400, "height": 300},
        ),
        page,
    )
    surface.controls = _Controls([canvas])
    session = BrowserChallengeSession(page, provider="fixture", surface=surface)

    point_observation = asyncio.run(session.observe())
    assert point_observation is not None
    asyncio.run(
        session.execute(
            ChallengeAction(
                observation_id=point_observation.observation_id,
                kind="point",
                payload={"points": [{"x": 40, "y": 50}]},
            )
        )
    )
    drag_observation = asyncio.run(session.observe())
    assert drag_observation is not None
    asyncio.run(
        session.execute(
            ChallengeAction(
                observation_id=drag_observation.observation_id,
                kind="drag",
                payload={
                    "paths": [
                        {
                            "start": {"x": 20, "y": 30},
                            "end": {"x": 120, "y": 130},
                        }
                    ]
                },
            )
        )
    )
    textbox = _Control(_control_data(0, tag="input", text="Answer"), page)
    surface.controls = _Controls([textbox])
    press_observation = asyncio.run(session.observe())
    assert press_observation is not None
    asyncio.run(
        session.execute(
            ChallengeAction(
                observation_id=press_observation.observation_id,
                kind="press",
                payload={"affordance_id": "control-0", "key": "Enter"},
            )
        )
    )

    assert page.clicks == [{"x": 40, "y": 50}]
    assert page.mouse.calls == [
        ("move", 30.0, 50.0, None),
        ("down",),
        ("move", 130.0, 150.0, 20),
        ("up",),
    ]
    assert textbox.calls == [("press", "Enter")]
    assert [item["kind"] for item in session.diagnostics["browser_scene_actions"]] == [
        "point",
        "drag",
        "press",
    ]
