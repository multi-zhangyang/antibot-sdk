import asyncio
import hashlib
import random
from io import BytesIO
from types import SimpleNamespace

import pytest
from PIL import Image

from antibot_sdk.harness import ChallengeAgentLoop, VisionChallengePolicy
from antibot_sdk.providers.widgets import (
    CaptchaWidgetSolver,
    RecaptchaChallengeSession,
    _TaskCanvasTimeout,
    _hcaptcha_prompt_label,
    _hcaptcha_question_observation,
    _hcaptcha_verified_token,
    _solve_recaptcha_grid,
    _score_task_image_alignment,
    _sha256,
    _select_widget_token,
    _wait_for_task_canvas,
    _visual_observation,
    detect_widget_provider,
    normalize_widget_provider,
)
from antibot_sdk.vision import VisionAnswer
from antibot_sdk.vision import StaticVisionBackend, VisionSolvePolicy


def _noise_png(*, seed: int, size: tuple[int, int] = (32, 24)) -> bytes:
    pixels = random.Random(seed).randbytes(size[0] * size[1] * 3)
    image = Image.frombytes("RGB", size, pixels)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _canvas_png(task: bytes, *, offset: tuple[int, int]) -> bytes:
    canvas = Image.new("RGB", (80, 60), (238, 238, 238))
    with Image.open(BytesIO(task)) as image:
        canvas.paste(image.convert("RGB"), offset)
    output = BytesIO()
    canvas.save(output, format="PNG")
    return output.getvalue()


class _CanvasSequence:
    def __init__(self, screenshots: list[bytes]):
        self.screenshots = screenshots
        self.index = 0
        self.bounding_box_calls = 0

    async def wait_for(self, *, state: str) -> None:
        assert state == "visible"

    async def screenshot(self, *, type: str) -> bytes:
        assert type == "png"
        screenshot = self.screenshots[min(self.index, len(self.screenshots) - 1)]
        self.index += 1
        return screenshot

    async def bounding_box(self, *, timeout: int) -> dict[str, float]:
        assert timeout == 1500
        self.bounding_box_calls += 1
        return {"x": 5.0, "y": 7.0, "width": 80.0, "height": 60.0}


def test_sha256_is_python_310_compatible(tmp_path) -> None:
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"antibot" * 200_000)

    assert _sha256(fixture) == hashlib.sha256(fixture.read_bytes()).hexdigest()


def test_widget_provider_normalization_and_url_detection() -> None:
    assert normalize_widget_provider("Google_reCAPTCHA") == "recaptcha"
    assert normalize_widget_provider("recaptcha_v2") == "recaptcha"
    assert normalize_widget_provider("h-captcha") == "hcaptcha"
    assert detect_widget_provider("https://www.google.com/recaptcha/api2/demo") == "recaptcha"
    assert detect_widget_provider("https://js.hcaptcha.com/1/api.js") == "hcaptcha"
    assert detect_widget_provider("https://example.test/?next=https://hcaptcha.com") is None


def test_hcaptcha_question_is_normalized_without_vendor_state_mutation() -> None:
    question = SimpleNamespace(
        requester_question={"en": "Select every matching image"},
        request_type="image_label_binary",
        request_config={},
        tasklist=[object() for _ in range(9)],
        requester_restricted_answer_set=["default"],
    )

    observation = _hcaptcha_question_observation(question, sequence=1)

    assert observation.kind == "binary"
    assert observation.candidate_count == 9
    assert observation.min_answers == 0
    assert observation.max_answers == 9
    assert observation.metadata["source"] == "vendor_question"


def test_rendered_visual_observation_hashes_exact_image_and_sequence() -> None:
    screenshot = _noise_png(seed=27)
    first = _visual_observation(
        provider="hcaptcha",
        prompt="select buses",
        kind="binary",
        screenshot=screenshot,
        sequence=1,
        width=32,
        height=24,
        candidate_count=9,
    )
    second = _visual_observation(
        provider="hcaptcha",
        prompt="select buses",
        kind="binary",
        screenshot=screenshot,
        sequence=2,
        width=32,
        height=24,
        candidate_count=9,
    )

    assert first.observation_id != second.observation_id
    assert first.grid_rows == first.grid_columns == 3
    assert first.metadata["image_sha256"] == hashlib.sha256(screenshot).hexdigest()


def test_widget_solver_rejects_invalid_input_without_starting_browser() -> None:
    invalid_url = asyncio.run(CaptchaWidgetSolver().solve(target_url="", provider="recaptcha"))
    invalid_provider = asyncio.run(
        CaptchaWidgetSolver().solve(target_url="https://example.test", provider="unsupported")
    )

    assert invalid_url.ok is False
    assert invalid_url.errors == ["target_url must be a non-empty string"]
    assert invalid_provider.ok is False
    assert invalid_provider.errors == [
        "unsupported_widget_provider: expected recaptcha or hcaptcha"
    ]


def test_hcaptcha_prompt_label_routes_tree_climbing_animals_to_specialized_model() -> None:
    assert (
        _hcaptcha_prompt_label("Select all animals that are able to climb straight up trees")
        == "tree_climbing_animals"
    )
    assert _hcaptcha_prompt_label("Please click the largest animal") is None


def test_task_image_alignment_returns_exact_canvas_offset() -> None:
    task = _noise_png(seed=7)
    alignment = _score_task_image_alignment(
        _canvas_png(task, offset=(17, 23)),
        task,
    )

    assert (alignment.x, alignment.y) == (17, 23)
    assert alignment.score > 0.999
    assert (alignment.canvas_width, alignment.canvas_height) == (80, 60)


def test_wait_for_task_canvas_ignores_previous_task_until_expected_image_appears() -> None:
    previous_task = _noise_png(seed=1)
    expected_task = _noise_png(seed=2)
    canvas = _CanvasSequence(
        [
            _canvas_png(previous_task, offset=(10, 12)),
            _canvas_png(expected_task, offset=(21, 19)),
        ]
    )

    async def no_delay(_seconds: float) -> None:
        return None

    match = asyncio.run(
        _wait_for_task_canvas(
            canvas,
            expected_task,
            timeout_sec=1,
            poll_interval_sec=0.01,
            sleep=no_delay,
        )
    )

    assert match.attempt_scores[0] < 0.70
    assert match.attempt_scores[1] > 0.999
    assert (match.alignment.x, match.alignment.y) == (21, 19)
    assert canvas.bounding_box_calls == 1


def test_wait_for_task_canvas_times_out_without_low_score_fallback() -> None:
    expected_task = _noise_png(seed=3)
    canvas = _CanvasSequence([_canvas_png(_noise_png(seed=4), offset=(8, 9))])

    with pytest.raises(_TaskCanvasTimeout) as raised:
        asyncio.run(
            _wait_for_task_canvas(
                canvas,
                expected_task,
                min_score=0.70,
                timeout_sec=0,
            )
        )

    assert max(raised.value.attempt_scores) < 0.70
    assert raised.value.last_screenshot == canvas.screenshots[0]
    assert canvas.bounding_box_calls == 0


def test_hcaptcha_verified_token_wins_after_backcall_status() -> None:
    challenge = type(
        "Challenge",
        (),
        {"is_pass": True, "generated_pass_UUID": "P1_" + "x" * 80},
    )()
    failed = type(
        "Challenge",
        (),
        {"is_pass": False, "generated_pass_UUID": "P1_" + "y" * 80},
    )()

    assert _hcaptcha_verified_token(failed) is None
    verified = _hcaptcha_verified_token(challenge)
    assert verified is not None
    assert _select_widget_token("hcaptcha", [], [verified]) == verified
    assert _select_widget_token("hcaptcha", ["dom-token"], [verified]) == verified


class _RecaptchaTarget:
    async def wait_for(self, *, state: str, timeout: int) -> None:
        assert state == "visible"
        assert timeout == 5000

    async def screenshot(self, **_kwargs) -> bytes:
        output = BytesIO()
        Image.new("RGB", (300, 300), (200, 200, 200)).save(output, format="PNG")
        return output.getvalue()


class _RecaptchaTiles:
    async def count(self) -> int:
        return 9


class _RecaptchaFrame:
    def locator(self, selector: str):
        if selector == "#rc-imageselect-target":
            return _RecaptchaTarget()
        if selector == "#rc-imageselect-target .rc-imageselect-tile":
            return _RecaptchaTiles()
        raise AssertionError(f"unexpected selector: {selector}")


class _SessionRecaptchaTarget:
    def __init__(self, page) -> None:
        self.page = page

    async def wait_for(self, *, state: str, timeout: int) -> None:
        assert state == "visible"
        assert timeout == 5000

    async def screenshot(self, **_kwargs) -> bytes:
        return self.page.screenshots[self.page.image_index]


class _SessionRecaptchaTile:
    def __init__(self, page, index: int) -> None:
        self.page = page
        self.index = index

    async def click(self, *, timeout: int, delay: int) -> None:
        assert timeout == 1500
        assert delay == 100
        self.page.clicked.append(self.index)


class _SessionRecaptchaTiles:
    def __init__(self, page) -> None:
        self.page = page

    async def count(self) -> int:
        return 9

    def nth(self, index: int) -> _SessionRecaptchaTile:
        return _SessionRecaptchaTile(self.page, index)


class _SessionRecaptchaFrame:
    def __init__(self, page) -> None:
        self.page = page

    def locator(self, selector: str):
        if selector == "#rc-imageselect-target":
            return _SessionRecaptchaTarget(self.page)
        if selector == "#rc-imageselect-target .rc-imageselect-tile":
            return _SessionRecaptchaTiles(self.page)
        raise AssertionError(f"unexpected selector: {selector}")


class _SessionRecaptchaPage:
    def __init__(self) -> None:
        self.challenge_visible = True
        self.submitted = False
        self.image_index = 0
        self.screenshots = [_noise_png(seed=80), _noise_png(seed=81)]
        self.clicked = []
        self.waits = []
        self.frame = _SessionRecaptchaFrame(self)

    async def wait_for_timeout(self, milliseconds: int) -> None:
        self.waits.append(milliseconds)


class _RecaptchaBackend:
    def __init__(self, *, confidence: float) -> None:
        self.confidence = confidence

    async def solve(self, _task) -> VisionAnswer:
        return VisionAnswer(kind="binary", selected=(), confidence=self.confidence)


class _RecaptchaSequenceBackend:
    def __init__(self, confidences: list[float]) -> None:
        self.confidences = iter(confidences)

    async def solve(self, _task) -> VisionAnswer:
        return VisionAnswer(kind="binary", selected=(), confidence=next(self.confidences))


def test_recaptcha_low_confidence_empty_answer_refreshes_instead_of_verifying(
    monkeypatch,
) -> None:
    frame = _RecaptchaFrame()
    refresh_calls = []

    async def challenge_frame(_page):
        return frame

    async def ready(*_args, **_kwargs):
        return "ready-signature"

    async def prompt(_frame):
        return "Select all images with buses. Click verify once there are none left."

    async def signature(_frame):
        return "before-refresh"

    async def refresh(*_args, **kwargs):
        refresh_calls.append(kwargs)
        return "after-refresh"

    async def must_not_verify(*_args, **_kwargs):
        raise AssertionError("an uncertain empty answer must not click Verify")

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_tile_image_signature", signature)
    monkeypatch.setattr("antibot_sdk.providers.widgets._refresh_recaptcha_challenge", refresh)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", must_not_verify)
    diagnostics = {}

    status = asyncio.run(
        _solve_recaptcha_grid(
            object(),
            _RecaptchaBackend(confidence=0),
            diagnostics=diagnostics,
            output_dir=None,
            min_confidence=0.35,
            retries=1,
            max_rounds=8,
        )
    )

    assert status == "refreshed"
    assert diagnostics["recaptcha_uncertain_refreshes"] == 1
    assert diagnostics["challenge_observations"][0]["kind"] == "binary"
    assert diagnostics["challenge_observations"][0]["grid_rows"] == 3
    assert diagnostics["challenge_actions"] == [
        {
            "observation_id": diagnostics["challenge_observations"][0]["observation_id"],
            "kind": "reload",
            "payload": {},
            "confidence": None,
            "uncertain": True,
            "valid": True,
            "errors": [],
            "executed": True,
        }
    ]
    assert diagnostics["recaptcha_rounds"] == [
        {
            "round": 1,
            "prompt": "Select all images with buses. Click verify once there are none left.",
            "candidate_count": 9,
            "selected_count": 0,
            "dynamic": True,
            "uncertain": True,
            "proposed_selected_count": 0,
            "action": "refresh",
            "refresh_observed": True,
        }
    ]
    assert refresh_calls[0]["previous_signature"] == "before-refresh"


def test_recaptcha_high_confidence_empty_answer_can_verify(monkeypatch) -> None:
    frame = _RecaptchaFrame()
    action_calls = []

    async def challenge_frame(_page):
        return frame

    async def ready(*_args, **_kwargs):
        return "ready-signature"

    async def prompt(_frame):
        return "Select all images with cars. Click verify once there are none left."

    async def action(*_args, **kwargs):
        action_calls.append(kwargs)
        return "verify"

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", action)
    diagnostics = {}

    status = asyncio.run(
        _solve_recaptcha_grid(
            object(),
            _RecaptchaBackend(confidence=0.9),
            diagnostics=diagnostics,
            output_dir=None,
            min_confidence=0.35,
            retries=1,
            max_rounds=8,
        )
    )

    assert status == "submitted"
    assert action_calls == [{"expect_verify": True}]
    assert diagnostics["recaptcha_rounds"][0]["action"] == "verify"
    assert diagnostics["challenge_actions"][0]["kind"] == "submit"
    assert diagnostics["challenge_actions"][0]["valid"] is True


def test_recaptcha_retry_can_recover_high_confidence_answer_without_reload(monkeypatch) -> None:
    frame = _RecaptchaFrame()
    action_calls = []

    async def challenge_frame(_page):
        return frame

    async def ready(*_args, **_kwargs):
        return "ready-signature"

    async def prompt(_frame):
        return "Select all images with cars. Click verify once there are none left."

    async def action(*_args, **kwargs):
        action_calls.append(kwargs)
        return "verify"

    async def must_not_refresh(*_args, **_kwargs):
        raise AssertionError("a later confident retry should not reload")

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", action)
    monkeypatch.setattr("antibot_sdk.providers.widgets._refresh_recaptcha_challenge", must_not_refresh)
    diagnostics = {}

    status = asyncio.run(
        _solve_recaptcha_grid(
            object(),
            _RecaptchaSequenceBackend([0.0, 0.9]),
            diagnostics=diagnostics,
            output_dir=None,
            min_confidence=0.35,
            retries=2,
            max_rounds=8,
        )
    )

    assert status == "submitted"
    assert action_calls == [{"expect_verify": True}]
    assert "recaptcha_uncertain_refreshes" not in diagnostics


def test_recaptcha_session_static_grid_requires_submit_and_vendor_token(monkeypatch) -> None:
    page = _SessionRecaptchaPage()
    frame = page.frame
    diagnostics = {}
    token = "recaptcha-token-" + "x" * 40

    async def challenge_frame(_page):
        return frame if page.challenge_visible else None

    async def ready(_page, _frame, **kwargs):
        assert kwargs["require_unselected"] in {True, False}
        return f"signature-{page.image_index}"

    async def prompt(_frame):
        return "Select all images with buses"

    async def action(_page, _frame, *, expect_verify):
        assert expect_verify is False
        page.submitted = True
        page.challenge_visible = False
        return "verify"

    async def collect(_page, _provider):
        return [token] if page.submitted else []

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", action)
    monkeypatch.setattr("antibot_sdk.providers.widgets._collect_tokens", collect)

    session = RecaptchaChallengeSession(
        page,
        diagnostics=diagnostics,
        verification_wait_ms=0,
    )
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([{"selected": [2], "confidence": 0.9}])
            ),
            max_steps=6,
        ).run()
    )

    assert result.accepted is True
    assert result.verification.token_length == len(token)
    assert page.clicked == [2]
    assert [item["kind"] for item in result.diagnostics["challenge_actions"]] == [
        "select",
        "submit",
    ]
    assert all(item["executed"] for item in result.diagnostics["challenge_actions"])
    assert [item["phase"] for item in diagnostics["recaptcha_session_observations"]] == [
        "presented",
        "answering",
    ]
    assert len(diagnostics["challenge_engine"]["vision_tasks"]) == 1


def test_recaptcha_session_dynamic_grid_reobserves_replaced_tiles(monkeypatch) -> None:
    page = _SessionRecaptchaPage()
    frame = page.frame
    diagnostics = {}
    token = "dynamic-token-" + "y" * 40

    async def challenge_frame(_page):
        return frame if page.challenge_visible else None

    async def ready(_page, _frame, **kwargs):
        if kwargs.get("previous_signature") is not None:
            page.image_index = 1
        return f"signature-{page.image_index}"

    async def prompt(_frame):
        return "Select all images with buses. Click verify once there are none left."

    async def action(_page, _frame, *, expect_verify):
        assert expect_verify is True
        page.submitted = True
        page.challenge_visible = False
        return "verify"

    async def collect(_page, _provider):
        return [token] if page.submitted else []

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", action)
    monkeypatch.setattr("antibot_sdk.providers.widgets._collect_tokens", collect)

    session = RecaptchaChallengeSession(page, diagnostics=diagnostics, verification_wait_ms=0)
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend(
                    [
                        {"selected": [1], "confidence": 0.9},
                        {"selected": [], "confidence": 0.9},
                    ]
                )
            ),
            max_steps=8,
        ).run()
    )

    assert result.accepted is True
    assert page.clicked == [1]
    assert len({item["observation_id"] for item in diagnostics["recaptcha_session_observations"]}) == 2
    assert diagnostics["recaptcha_session_observations"][1]["phase"] == "presented"
    assert diagnostics["recaptcha_session_observations"][1]["round"] == 2
    assert diagnostics["recaptcha_session_observations"][0]["replacement_observed"] is True


def test_recaptcha_session_low_confidence_reloads_before_answering(monkeypatch) -> None:
    page = _SessionRecaptchaPage()
    frame = page.frame
    diagnostics = {}
    token = "reload-token-" + "z" * 40
    backend = StaticVisionBackend(
        [
            {"selected": [], "confidence": 0.0},
            {"selected": [], "confidence": 0.9},
        ]
    )

    async def challenge_frame(_page):
        return frame if page.challenge_visible else None

    async def ready(_page, _frame, **kwargs):
        return f"signature-{page.image_index}"

    async def prompt(_frame):
        return "Select all images with cars"

    async def refresh(_page, _frame, **kwargs):
        page.image_index = 1
        return "signature-1"

    async def action(_page, _frame, *, expect_verify):
        page.submitted = True
        page.challenge_visible = False
        return "verify"

    async def collect(_page, _provider):
        return [token] if page.submitted else []

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._wait_for_recaptcha_grid_ready", ready)
    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_prompt", prompt)
    monkeypatch.setattr("antibot_sdk.providers.widgets._refresh_recaptcha_challenge", refresh)
    monkeypatch.setattr("antibot_sdk.providers.widgets._click_recaptcha_action", action)
    monkeypatch.setattr("antibot_sdk.providers.widgets._collect_tokens", collect)

    session = RecaptchaChallengeSession(page, diagnostics=diagnostics, verification_wait_ms=0)
    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                backend,
                solve_policy=VisionSolvePolicy(
                    min_confidence=0.35,
                    retries=1,
                    require_confidence=True,
                    allow_uncertain=True,
                ),
            ),
            max_steps=10,
        ).run()
    )

    assert result.accepted is True
    assert [item["kind"] for item in result.diagnostics["challenge_actions"]] == [
        "reload",
        "submit",
    ]
    assert result.diagnostics["challenge_actions"][0]["uncertain"] is True
    assert diagnostics["recaptcha_uncertain_refreshes"] == 1


def test_recaptcha_session_verification_rejects_missing_token(monkeypatch) -> None:
    page = _SessionRecaptchaPage()

    async def collect(_page, _provider):
        return []

    monkeypatch.setattr("antibot_sdk.providers.widgets._collect_tokens", collect)
    verification = asyncio.run(
        RecaptchaChallengeSession(page, verification_wait_ms=0).verify()
    )

    assert verification.accepted is False
    assert verification.token_length == 0
    assert verification.gaps == ("recaptcha_vendor_token_not_captured",)


def test_recaptcha_session_stops_observing_when_token_precedes_frame_disappearance(
    monkeypatch,
) -> None:
    page = _SessionRecaptchaPage()
    page.submitted = True
    diagnostics = {}

    async def challenge_frame(_page):
        # Google can report the bframe for a short time after userverify.
        return page.frame

    async def collect(_page, _provider):
        return ["post-submit-token-" + "a" * 40]

    monkeypatch.setattr("antibot_sdk.providers.widgets._recaptcha_challenge_frame", challenge_frame)
    monkeypatch.setattr("antibot_sdk.providers.widgets._collect_tokens", collect)

    observation = asyncio.run(RecaptchaChallengeSession(page, diagnostics=diagnostics).observe())

    assert observation is None
    assert diagnostics == {}
