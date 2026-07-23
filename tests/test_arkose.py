from __future__ import annotations

import asyncio
import json
from io import BytesIO

from PIL import Image, ImageDraw

from antibot_sdk.harness.contracts import ChallengeAction, ChallengeObservation
from antibot_sdk.harness.adapters import default_adapter_registry
from antibot_sdk.harness.replay import evaluate_result
from antibot_sdk.models import CaptchaResult
from antibot_sdk.providers.arkose import (
    _ArkoseCarousel,
    _ArkoseOrbitVisionBackend,
    _ArkoseState,
    ArkoseChallengeSession,
    _arkose_payload_from_text,
    _arkose_pass_from_payload,
    _carousel_position,
    _carousel_vision_images,
    _carousel_vision_prompt,
    _classify_surface,
    _parse_carousel_position,
    _redact_event_url,
    _orbit_ring_centers,
    _orbit_symbol_images,
    _surface_is_loading,
    _vision_image_for_surface,
    _vision_images_for_surface,
    _vision_prompt_for_surface,
    detect_arkose_provider,
    normalize_arkose_provider,
)
from antibot_sdk.vision import VisionAnswer, VisionImage, VisionTask


def _png(color: tuple[int, int, int]) -> bytes:
    image = Image.new("RGB", (160, 90), color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _orbit_png(*, x_offset: int = 0) -> bytes:
    image = Image.new("RGB", (800, 800), (18, 18, 18))
    draw = ImageDraw.Draw(image)
    rings = (
        ((220, 100), (225, 30, 45)),
        ((500, 190), (20, 210, 45)),
        ((300, 320), (230, 220, 10)),
        ((570, 430), (205, 20, 210)),
        ((350, 560), (10, 205, 210)),
    )
    for (x, y), color in rings:
        x += x_offset
        draw.ellipse((x - 80, y - 80, x + 80, y + 80), outline=color, width=18)
        draw.rectangle((x - 15, y - 25, x + 15, y + 25), fill="white")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class _Element:
    def __init__(
        self, *, area: float = 1000, text: str = "", screenshots: list[bytes] | None = None
    ):
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
    def __init__(
        self, url: str, *, marker: bool, direct_surface: bool = False, screenshots=None, parent=None
    ):
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


class _CarouselButton(_Element):
    def __init__(self, frame: _CarouselFrame, kind: str):
        super().__init__(text=kind)
        self.frame = frame
        self.kind = kind

    async def click(self, **_kwargs) -> None:
        self.clicks += 1
        if self.kind == "next":
            self.frame.index = (self.frame.index + 1) % self.frame.count
            self.frame.next_clicks += 1
        elif self.kind == "submit":
            self.frame.submissions += 1


class _CarouselFrame:
    def __init__(self, *, index: int = 0, count: int = 5, fail_screenshot_at: int | None = None):
        self.index = index
        self.count = count
        self.fail_screenshot_at = fail_screenshot_at
        self.next_clicks = 0
        self.submissions = 0
        self.buttons = [
            _CarouselButton(self, "previous"),
            _CarouselButton(self, "next"),
            _CarouselButton(self, "reload"),
            _CarouselButton(self, "submit"),
        ]

    async def evaluate(self, _script: str):
        return {"index": self.index, "count": self.count}

    def locator(self, selector: str):
        if selector == "button, [role='button']":
            return _Locator(self.buttons)
        if selector == ".key-frame-image":
            return _Locator([_Element(screenshots=[_png((90, 80, 70))])])
        if selector == ".answer-frame img[aria-label], .answer-frame img":
            return _Locator([_CarouselAnswer(self)])
        return _Locator([])


class _CarouselAnswer(_Element):
    def __init__(self, frame: _CarouselFrame):
        super().__init__()
        self.frame = frame

    async def screenshot(self, **_kwargs) -> bytes:
        if self.frame.fail_screenshot_at == self.frame.index:
            self.frame.fail_screenshot_at = None
            raise RuntimeError("candidate image detached")
        return _png((self.frame.index, self.frame.index, self.frame.index))


class _FailingSurface:
    async def screenshot(self, **_kwargs) -> bytes:
        raise RuntimeError("surface detached")


class _ShellWithCanvas(_Element):
    def locator(self, selector: str):
        if selector == "button, [role='button']":
            return _Locator([_Element(text="Close")])
        if selector.startswith("canvas,"):
            return _Locator([self])
        return _Locator([])


class _ShellWithIframe(_Element):
    def locator(self, selector: str):
        if selector == "iframe":
            return _Locator([self])
        return _Locator([])


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


class _OrbitStageBackend:
    model = "test-model"

    def __init__(self) -> None:
        self.tasks: list[VisionTask] = []

    async def solve(self, task: VisionTask) -> VisionAnswer:
        self.tasks.append(task)
        if task.metadata.get("stage") == "orbit_mapping":
            return VisionAnswer(
                kind="multiple_choice",
                choices=("Ring 4",),
                confidence=0.91,
                diagnostics={"stage": "mapping"},
            )
        return VisionAnswer(
            kind="multiple_choice",
            choices=("State 2",),
            confidence=0.84,
            diagnostics={"stage": "matching"},
        )


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
    assert _arkose_pass_from_payload({"response": "not answered", "solved": None}) is None


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


def test_arkose_close_shell_with_canvas_is_still_loading() -> None:
    shell = _ShellWithCanvas(text="")

    assert asyncio.run(_surface_is_loading(shell)) is True


def test_arkose_parent_container_with_iframe_is_loading() -> None:
    shell = _ShellWithIframe(text="")

    assert asyncio.run(_surface_is_loading(shell)) is True


def test_arkose_carousel_is_multiple_choice_not_point_coordinates() -> None:
    kind, choices = _classify_surface(
        "Match the icons on the left with the icons on the top faces of the dice (1 of 1)",
        [
            {"index": 0, "label": "Navigate to previous image", "box": None},
            {"index": 1, "label": "Navigate to next image", "box": None},
            {"index": 2, "label": "Submit", "box": None},
        ],
        0,
    )

    assert kind == "multiple_choice"
    assert choices == ("Navigate to next image", "Submit")


def test_arkose_orbit_prompt_explains_next_vs_submit_semantics() -> None:
    prompt = _vision_prompt_for_surface(
        "Use the arrows to move the icon into the indicated orbit. (1 of 3)",
        "multiple_choice",
        ("Navigate to next image", "Submit"),
    )

    assert "left panel gives one large target orbit number" in prompt
    assert "Choose Submit only when" in prompt


def test_arkose_small_choice_surface_is_upscaled_for_vision() -> None:
    screenshot, size = _vision_image_for_surface(
        _png((30, 40, 50)),
        "multiple_choice",
        ("Navigate to next image", "Submit"),
    )

    assert size == (480, 270)
    assert Image.open(BytesIO(screenshot)).size == size


def test_arkose_orbit_surface_adds_target_and_game_crops() -> None:
    images, size = _vision_images_for_surface(
        _png((30, 40, 50)),
        "Move the icon into the indicated orbit",
        "multiple_choice",
        ("Navigate to next image", "Submit"),
    )

    assert size == (480, 270)
    assert [image.label for image in images] == [
        "arkose-challenge.png",
        "target-panel.png",
        "orbit-panel.png",
    ]


def test_arkose_carousel_position_is_read_from_dom_state() -> None:
    frame = _CarouselFrame(index=3, count=5)

    assert _parse_carousel_position({"index": 3, "count": 5}) == (3, 5)
    assert _parse_carousel_position("Image 4 of 5.") == (3, 5)
    assert asyncio.run(_carousel_position(frame)) == (3, 5)


def test_arkose_carousel_vision_batch_has_one_labeled_image_per_state() -> None:
    images = _carousel_vision_images(
        _png((10, 20, 30)),
        tuple(_png((index, index, index)) for index in range(5)),
    )

    assert [image.label for image in images] == [
        "target-panel.png",
        "state-1.png",
        "state-2.png",
        "state-3.png",
        "state-4.png",
        "state-5.png",
    ]
    assert all(Image.open(BytesIO(image.data)).size == (640, 360) for image in images)
    assert "State 1 through State 5" in _carousel_vision_prompt("Move into orbit", 5)


def test_arkose_orbit_ring_detector_returns_five_vertical_ranks() -> None:
    rings = _orbit_ring_centers(_orbit_png())

    assert [ring.color for ring in rings] == ["red", "green", "yellow", "purple", "cyan"]
    assert [ring.y for ring in rings] == sorted(ring.y for ring in rings)
    assert all(ring.score >= 0.8 for ring in rings)


def test_arkose_orbit_symbol_crop_redetects_each_carousel_frame() -> None:
    images, _ = _orbit_symbol_images(
        VisionImage(_png((40, 40, 40)), label="target-panel.png"),
        (
            VisionImage(_orbit_png(), label="state-1.png"),
            VisionImage(_orbit_png(x_offset=70), label="state-2.png"),
        ),
        0,
    )

    for candidate in images[1:]:
        with Image.open(BytesIO(candidate.data)) as image:
            center = image.convert("RGB").getpixel((image.width // 2, image.height // 2))
        assert min(center) >= 240


def test_arkose_orbit_backend_maps_rank_then_matches_local_symbols() -> None:
    raw = _OrbitStageBackend()
    backend = _ArkoseOrbitVisionBackend(raw)
    choices = tuple(f"State {index}" for index in range(1, 6))
    task = VisionTask(
        kind="multiple_choice",
        prompt="Move the icon into the indicated orbit",
        images=(
            VisionImage(_png((40, 40, 40)), label="target-panel.png"),
            *(VisionImage(_orbit_png(), label=f"state-{index}.png") for index in range(1, 6)),
        ),
        min_answers=1,
        max_answers=1,
        choices=choices,
        metadata={"provider": "arkose", "arkose_orbit_carousel": True},
    )

    answer = asyncio.run(backend.solve(task))

    assert answer.choices == ("State 2",)
    assert answer.confidence == 0.84
    assert [item.metadata["stage"] for item in raw.tasks] == [
        "orbit_mapping",
        "orbit_symbol_matching",
    ]
    assert [image.label for image in raw.tasks[0].images] == [
        "target-number-only.png",
        "orbit-number-list-only.png",
    ]
    assert [image.label for image in raw.tasks[1].images] == [
        "target-rotation-contact-sheet.png",
        "state-candidate-contact-sheet.png",
    ]
    stages = answer.diagnostics["arkose_orbit_stages"]
    assert stages["ring_rank"] == 4
    assert len(stages["rings"]) == 5


def test_arkose_carousel_choice_navigates_to_exact_state_then_submits() -> None:
    frame = _CarouselFrame(index=0, count=5)
    choices = tuple(f"State {index}" for index in range(1, 6))
    observation = ChallengeObservation(
        observation_id="carousel-observation",
        provider="arkose",
        kind="multiple_choice",
        modality="image",
        min_answers=1,
        max_answers=1,
        choices=choices,
    )
    session = ArkoseChallengeSession(_Page(), verification_wait_ms=0)
    session._current = _ArkoseState(
        observation=observation,
        task=VisionTask(
            kind="multiple_choice",
            prompt="Choose one state",
            images=(VisionImage(_png((1, 2, 3))),),
            min_answers=1,
            max_answers=1,
            choices=choices,
        ),
        frame=frame,
        surface=_Element(),
        screenshot=_png((1, 2, 3)),
        signature="signature",
        controls=[],
        candidate_selector=None,
        carousel=_ArkoseCarousel(
            count=5,
            current_index=0,
            next_control_index=1,
            submit_control_index=3,
        ),
    )

    asyncio.run(
        session.execute(
            ChallengeAction(
                observation_id=observation.observation_id,
                kind="choice",
                payload={"choice": "State 4"},
                confidence=0.9,
            )
        )
    )

    assert frame.index == 3
    assert frame.buttons[1].clicks == 3
    assert frame.buttons[3].clicks == 1
    assert frame.submissions == 1
    assert session.submitted is True


def test_arkose_failed_carousel_capture_restores_starting_index() -> None:
    frame = _CarouselFrame(index=2, count=5, fail_screenshot_at=4)
    session = ArkoseChallengeSession(_Page(), verification_wait_ms=0)
    controls = [
        {"index": 1, "label": "Navigate to next image", "box": None},
        {"index": 3, "label": "Submit", "box": None},
    ]

    captured = asyncio.run(session._capture_orbit_carousel(frame, "Move into orbit", controls))

    assert captured is None
    assert frame.index == 2
    assert frame.next_clicks == 5
    assert session.diagnostics["arkose_carousel_restores"] == [
        {"starting_index": 2, "state_count": 5, "restored": True}
    ]


def test_arkose_replay_persists_every_model_image(tmp_path) -> None:
    session = ArkoseChallengeSession(_Page(), output_dir=str(tmp_path), verification_wait_ms=0)
    session._sequence = 3
    choices = ("State 1", "State 2")
    observation = ChallengeObservation(
        observation_id="replay-observation",
        provider="arkose",
        kind="multiple_choice",
        modality="image",
        min_answers=1,
        max_answers=1,
        choices=choices,
        metadata={"image_sha256": "a" * 64},
    )
    images = (
        VisionImage(_png((1, 2, 3)), label="target-panel.png"),
        VisionImage(_png((4, 5, 6)), label="state-1.png"),
    )
    state = _ArkoseState(
        observation=observation,
        task=VisionTask(
            kind="multiple_choice",
            prompt="Choose one state",
            images=images,
            min_answers=1,
            max_answers=1,
            choices=choices,
        ),
        frame=object(),
        surface=_Element(),
        screenshot=_png((7, 8, 9)),
        signature="b" * 64,
        controls=[],
        candidate_selector=None,
        carousel=None,
    )

    session._save_replay(state)

    replay_root = tmp_path / "vision-replay"
    manifest_path = next(replay_root.glob("arkose-03-*.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = manifest["vision_task"]["images"]
    assert [record["label"] for record in records] == ["target-panel.png", "state-1.png"]
    assert all(
        (replay_root / record["path"]).read_bytes() == images[index].data
        for index, record in enumerate(records)
    )


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


def test_arkose_intro_next_control_is_navigation() -> None:
    button = _Element(text="Next")
    frame = _ButtonFrame([button])
    session = ArkoseChallengeSession(_Page(), verification_wait_ms=0)
    controls = [{"index": 0, "label": "Next", "box": None}]

    advanced = asyncio.run(
        session._advance_start_control(frame, controls, "Protecting your account")
    )

    assert advanced is True
    assert button.clicks == 1
    assert session.diagnostics["arkose_navigation_actions"] == [
        {"kind": "start_puzzle", "control_index": 0}
    ]


def test_arkose_explicit_failure_uses_restart_control() -> None:
    button = _Element(text="Restart")
    frame = _ButtonFrame([button])
    session = ArkoseChallengeSession(_Page(), verification_wait_ms=0)

    advanced = asyncio.run(
        session._advance_failure_control(
            frame,
            [{"index": 0, "label": "Restart", "box": None}],
            "That was not quite right.",
        )
    )

    assert advanced is True
    assert button.clicks == 1
    assert session.diagnostics["arkose_navigation_actions"] == [
        {"kind": "restart_after_failure", "control_index": 0}
    ]


def test_arkose_surface_capture_reacquires_replaced_locator() -> None:
    ready = _Element(screenshots=[_png((45, 55, 65))])
    session = _ReacquireSession(ready)
    session._navigation_attempts = 1

    screenshot, _frame, surface = asyncio.run(session._capture_surface(object(), _FailingSurface()))

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


def test_arkose_fc_ca_pass_accepts_same_session_field_token() -> None:
    async def run():
        token = "same-session-token-that-remains-valid-after-vendor-pass"
        session = _TokenSession(
            [token],
            network_events=[
                {
                    "url": "https://client-api.arkoselabs.com/fc/ca/",
                    "status": 200,
                    "pass": True,
                }
            ],
            verification_wait_ms=0,
        )
        session._initial_tokens.add(token)
        return session, await session.verify()

    session, verification = asyncio.run(run())
    assert verification.accepted is True
    assert verification.vendor_pass is True
    assert verification.token_length > 20
    assert session.diagnostics["arkose_final_token_matches_initial"] is True
    assert session.diagnostics["arkose_session_verification"]["token_source"] == (
        "field_after_vendor_pass"
    )


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
