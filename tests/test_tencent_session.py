import asyncio
import json
from io import BytesIO

from PIL import Image

from antibot_sdk.harness import ChallengeAction, ChallengeAgentLoop, VisionChallengePolicy
from antibot_sdk.providers.tencent import TencentCaptchaSolver
from antibot_sdk.providers.tencent_session import TencentChallengeSession, TencentWordOCRBackend
from antibot_sdk.vendor.tencent.solve_optimized import CaptchaFrame, RuntimeGeometry
from antibot_sdk.vision import StaticVisionBackend


def _png(color: tuple[int, int, int]) -> bytes:
    image = Image.new("RGB", (300, 120), color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class _Frame:
    async def evaluate(self, *_args, **_kwargs):
        return None


class _Page:
    viewport_size = {"width": 400, "height": 240}


def _target() -> CaptchaFrame:
    return CaptchaFrame(frame=_Frame())


def _geometry() -> RuntimeGeometry:
    return RuntimeGeometry(
        rate=1.0,
        init_x=50.0,
        start_x=40.0,
        start_y=80.0,
        end_x=210.0,
        end_y=80.0,
        raw_width=300,
        css_width=300.0,
    )


def test_tencent_slider_session_runs_shared_loop_and_requires_vendor_ticket() -> None:
    drag_calls = []

    async def drag(_page, geometry):
        drag_calls.append(geometry)

    async def verify(_frame, _state):
        return {
            "errorCode": "0",
            "ticket": "tencent-ticket-" + "x" * 48,
            "randstr": "rand-" + "x" * 12,
        }

    session = TencentChallengeSession(
        _Page(),
        frame_reader=lambda: asyncio.sleep(0, result=_target()),
        kind_reader=lambda _frame: asyncio.sleep(0, result="slider"),
        background_reader=lambda _frame: asyncio.sleep(0, result=_png((30, 40, 50))),
        gap_detector=lambda _image: (180, 0.94, "fixture-detector"),
        geometry_reader=lambda *_args: asyncio.sleep(0, result=_geometry()),
        drag_executor=drag,
        frame_resolver=lambda: asyncio.sleep(0, result=_target()),
        verify_reader=verify,
        verify_state={"res": None},
        verification_wait_ms=100,
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                strategies=session.strategy_registry(),
            ),
            max_steps=3,
        ).run()
    )

    assert result.accepted is True
    assert result.verification.vendor_pass is True
    assert result.verification.token_length == len(session.ticket or "")
    assert result.verification.verifier_events == ("cap_union_new_verify",)
    assert len(drag_calls) == 1
    assert result.diagnostics["harness"]["evidence"]["accepted"] is True


def test_tencent_slider_session_reobserves_dynamic_replacement_after_reject() -> None:
    backgrounds = [_png((30, 40, 50)), _png((80, 90, 100))]
    responses = [
        {"errorCode": "50", "ticket": "", "randstr": ""},
        {"errorCode": "0", "ticket": "ticket-" + "x" * 40, "randstr": "rand"},
    ]
    drag_calls = []

    async def drag(_page, geometry):
        drag_calls.append(geometry.end_x)

    async def verify(_frame, _state):
        return responses.pop(0)

    async def background(_frame):
        return backgrounds.pop(0)

    session = TencentChallengeSession(
        _Page(),
        frame_reader=lambda: asyncio.sleep(0, result=_target()),
        kind_reader=lambda _frame: asyncio.sleep(0, result="slider"),
        background_reader=background,
        gap_detector=lambda _image: (180, 0.91, "fixture-detector"),
        geometry_reader=lambda *_args: asyncio.sleep(0, result=_geometry()),
        drag_executor=drag,
        frame_resolver=lambda: asyncio.sleep(0, result=_target()),
        verify_reader=verify,
        verify_state={"res": None},
        max_attempts=2,
        verification_wait_ms=100,
    )

    result = asyncio.run(
        ChallengeAgentLoop(
            session,
            VisionChallengePolicy(
                StaticVisionBackend([]),
                strategies=session.strategy_registry(),
            ),
            max_steps=5,
        ).run()
    )

    assert result.accepted is True
    assert len(drag_calls) == 2
    observations = result.diagnostics["challenge_observations"]
    assert len(observations) == 2
    assert observations[1]["dynamic"] is True
    responses_trace = result.diagnostics["session"]["tencent_verification_responses"]
    assert responses_trace[0]["accepted"] is False
    assert responses_trace[1]["accepted"] is True


def test_tencent_word_click_uses_normalized_point_action_and_real_verify() -> None:
    points = []

    async def execute_points(_target, _background, value):
        points.extend(value)

    async def verify(_frame, _state):
        return {"errorCode": "0", "ticket": "ticket-" + "x" * 40, "randstr": "rand"}

    session = TencentChallengeSession(
        _Page(),
        frame_reader=lambda: asyncio.sleep(0, result=_target()),
        kind_reader=lambda _frame: asyncio.sleep(0, result="word_click"),
        background_reader=lambda _frame: asyncio.sleep(0, result=_png((10, 20, 30))),
        instruction_reader=lambda _frame: asyncio.sleep(0, result="请依次点击：猫 狗"),
        point_executor=execute_points,
        frame_resolver=lambda: asyncio.sleep(0, result=_target()),
        verify_reader=verify,
        verify_state={"res": None},
        verification_wait_ms=100,
    )

    async def run() -> None:
        observation = await session.observe()
        assert observation is not None
        assert observation.kind == "point"
        action = ChallengeAction(
            observation_id=observation.observation_id,
            kind="point",
            payload={"points": [{"x": 50, "y": 30}, {"x": 180, "y": 70}]},
        )
        await session.execute(action)
        await session.verify()

    asyncio.run(run())

    assert points == [(50.0, 30.0), (180.0, 70.0)]
    assert session.ticket is not None
    assert session.diagnostics["tencent_session_verification"]["accepted"] is True


def test_tencent_slider_rejects_low_gap_confidence_before_action() -> None:
    session = TencentChallengeSession(
        _Page(),
        frame_reader=lambda: asyncio.sleep(0, result=_target()),
        kind_reader=lambda _frame: asyncio.sleep(0, result="slider"),
        background_reader=lambda _frame: asyncio.sleep(0, result=_png((1, 2, 3))),
        gap_detector=lambda _image: (180, 0.2, "weak"),
        verify_state={"res": None},
    )

    try:
        asyncio.run(session.observe())
    except RuntimeError as exc:
        assert "confidence below policy" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("low-confidence Tencent gap must fail explicitly")


def test_tencent_word_ocr_backend_returns_ordered_normalized_points() -> None:
    calls = []

    def locator(image, targets):
        calls.append((image, targets))
        return [(12, 20), (80, 45)]

    backend = TencentWordOCRBackend(locator)
    task = type(
        "Task",
        (),
        {
            "kind": "point",
            "prompt": "请依次点击：猫 狗",
            "images": (type("Image", (), {"data": b"png"})(),),
        },
    )()
    answer = asyncio.run(backend.solve(task))

    assert calls == [(b"png", ["猫", "狗"])]
    assert [(point.x, point.y) for point in answer.points] == [(12.0, 20.0), (80.0, 45.0)]
    assert answer.diagnostics["backend"] == "tencent_word_siamese"


def test_tencent_result_requires_captured_success_response_and_flattens_session_trace() -> None:
    solver = TencentCaptchaSolver()
    profile = type("Profile", (), {"name": "cloud_product", "appid": "199999861"})()
    trace = {
        "challenge_observations": [{"kind": "slider", "observation_id": "obs-1"}],
        "challenge_actions": [{"kind": "drag", "executed": True, "valid": True}],
        "harness": {"evidence": {"accepted": True, "vendor_pass": True}},
        "session": {
            "tencent_verification_responses": [
                {"error_code": "0", "accepted": True, "ticket_len": 48}
            ],
            "tencent_session_verification": {"accepted": True, "error_code": "0"},
        },
    }
    raw = {
        "ok": True,
        "error_code": "0",
        "ticket": "ticket-" + "x" * 40,
        "randstr": "rand",
        "session_diagnostics": trace,
    }

    result = solver._result_from_raw(raw, prof=profile, target_url="https://example.test")
    unverified = solver._result_from_raw(
        {"ok": True, "ticket": "ticket-without-response"},
        prof=profile,
        target_url="https://example.test",
    )

    assert result.ok is True
    assert result.diagnostics["challenge_observations"][0]["observation_id"] == "obs-1"
    assert result.diagnostics["challenge_actions"][0]["executed"] is True
    assert result.diagnostics["tencent_verification_responses"][0]["accepted"] is True
    assert result.diagnostics["tencent_session_verification"]["accepted"] is True
    assert result.captcha_type == "slider"
    assert unverified.ok is False
    assert unverified.errors == ["solve_failed"]


def test_tencent_solve_with_pool_persists_complete_trace(monkeypatch, tmp_path) -> None:
    import antibot_sdk.providers.tencent as provider_module

    async def solve_one(*_args, **_kwargs):
        return {
            "ok": True,
            "error_code": "0",
            "ticket": "ticket-" + "x" * 40,
            "randstr": "rand",
            "session_diagnostics": {
                "challenge_observations": [
                    {
                        "observation_id": "online-1",
                        "provider": "tencent",
                        "kind": "slider",
                        "modality": "image",
                        "prompt": "Align the puzzle piece with the missing slot",
                    }
                ],
                "challenge_actions": [
                    {
                        "observation_id": "online-1",
                        "kind": "drag",
                        "payload": {
                            "paths": [
                                {
                                    "start": {"x": 10, "y": 20},
                                    "end": {"x": 100, "y": 20},
                                }
                            ]
                        },
                        "valid": True,
                        "executed": True,
                    }
                ],
                "harness": {"evidence": {"accepted": True, "vendor_pass": True}},
                "tencent_verification_responses": [
                    {"error_code": "0", "accepted": True, "ticket_len": 47}
                ],
            },
        }

    monkeypatch.setattr(provider_module, "solve_one", solve_one)
    pool = type("Pool", (), {"size": 1, "max_uses": 1, "pool_id": "test-pool"})()
    profile = type("Profile", (), {"name": "cloud_product", "appid": "199999861"})()
    destination = tmp_path / "run-001" / "result.json"

    result = asyncio.run(
        TencentCaptchaSolver().solve_with_pool(
            pool,
            prof=profile,
            target_url="https://example.test",
            output_json=str(destination),
        )
    )
    payload = json.loads(destination.read_text(encoding="utf-8"))

    assert result.ok is True
    assert payload["ok"] is True
    assert payload["diagnostics"]["challenge_actions"][0]["executed"] is True
    assert payload["diagnostics"]["harness"]["evidence"]["accepted"] is True
    assert payload["artifacts"]["output_json"] == str(destination.resolve())
