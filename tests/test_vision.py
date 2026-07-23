import asyncio
import json as json_module
from types import SimpleNamespace

import pytest

from antibot_sdk.vision import (
    OpenAICompatibleVisionBackend,
    StaticVisionBackend,
    VisionBackendError,
    VisionImage,
    VisionTask,
    coordinate_grid_overlay,
    validate_vision_answer,
)


def image(label: str = "fixture.png") -> VisionImage:
    return VisionImage(b"png", label=label)


def test_binary_answer_accepts_indexes_and_grid_coordinates() -> None:
    task = VisionTask(
        kind="binary",
        prompt="select bicycles",
        images=tuple(image(str(index)) for index in range(9)),
        min_answers=1,
        max_answers=3,
    )

    indexes = validate_vision_answer(task, {"selected": [1, 7, 1], "confidence": 0.9})
    grid = validate_vision_answer(
        task,
        {"coordinates": [{"box_2d": [0, 1]}, {"box_2d": [2, 1]}]},
    )

    assert indexes.selected == (1, 7)
    assert grid.selected == (1, 7)


def test_binary_candidate_count_is_independent_of_prompt_images() -> None:
    task = VisionTask(
        kind="binary",
        prompt="select buses",
        images=(image("full-challenge.png"),),
        candidate_count=9,
    )

    answer = validate_vision_answer(task, {"selected": [2, 8]})

    assert answer.selected == (2, 8)


def test_visual_spatial_answers_are_normalized() -> None:
    point_task = VisionTask(
        kind="point",
        prompt="click each target",
        images=(image(),),
        min_answers=1,
        max_answers=2,
    )
    box_task = VisionTask(
        kind="bounding_box",
        prompt="box the target",
        images=(image(),),
        min_answers=1,
    )
    drag_task = VisionTask(
        kind="drag_drop",
        prompt="match the shapes",
        images=(image(),),
        min_answers=1,
    )

    point = validate_vision_answer(point_task, {"points": [{"x": 12, "y": 34}]})
    box = validate_vision_answer(
        box_task,
        {
            "bounding_boxes": {
                "top_left_x": 1,
                "top_left_y": 2,
                "bottom_right_x": 30,
                "bottom_right_y": 40,
            }
        },
    )
    drag = validate_vision_answer(
        drag_task,
        {"paths": [{"start_point": {"x": 5, "y": 6}, "end_point": {"x": 50, "y": 60}}]},
    )

    assert (point.points[0].x, point.points[0].y) == (12, 34)
    assert (box.boxes[0].x1, box.boxes[0].y2) == (1, 40)
    assert (drag.paths[0].start.x, drag.paths[0].end.y) == (5, 60)


def test_multiple_choice_accepts_gateway_singular_choice_alias() -> None:
    task = VisionTask(
        kind="multiple_choice",
        prompt="choose one",
        images=(image(),),
        choices=("State 1", "State 2"),
        min_answers=1,
        max_answers=1,
    )

    answer = validate_vision_answer(task, {"choice": "State 2", "confidence": 0.8})

    assert answer.choices == ("State 2",)


@pytest.mark.parametrize(
    ("task", "payload", "message"),
    [
        (
            VisionTask("binary", "select", (image(),), min_answers=1),
            {"selected": []},
            "requires a selection",
        ),
        (
            VisionTask("binary", "select", (image(),)),
            {"selected": [1]},
            "outside",
        ),
        (
            VisionTask("point", "click", (image(),)),
            {"points": [{"x": -1, "y": 2}]},
            "non-negative",
        ),
        (
            VisionTask("drag_drop", "drag", (image(),)),
            {"paths": [{"start": {"x": 1, "y": 2}}]},
            "end must be an object",
        ),
    ],
)
def test_invalid_answers_fail_closed(task, payload, message) -> None:
    with pytest.raises(VisionBackendError, match=message):
        validate_vision_answer(task, payload)


def test_static_backend_records_normalized_tasks() -> None:
    task = VisionTask("point", "click", (image(),), min_answers=1)
    backend = StaticVisionBackend([{"points": [{"x": 3, "y": 4}]}])

    answer = asyncio.run(backend.solve(task))

    assert backend.calls == [task]
    assert answer.points[0].x == 3
    assert answer.diagnostics == {"backend": "static"}


def test_openai_compatible_backend_uses_standard_vision_message(monkeypatch) -> None:
    captured = {}

    def fake_post(url, *, headers, json, timeout, stream):
        captured.update(url=url, headers=headers, body=json, timeout=timeout)
        events = [
            "data: "
            + json_module.dumps(
                {
                    "model": "vision-model",
                    "choices": [{"delta": {"content": "```json\\n"}}],
                }
            ),
            "data: "
            + json_module.dumps(
                {
                    "choices": [
                        {
                            "delta": {
                                "content": '{"selected":[0],"confidence":0.75}\\n```',
                                "reasoning_content": "private reasoning",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 4},
                }
            ),
            "data: [DONE]",
        ]
        return SimpleNamespace(
            status_code=200,
            iter_lines=lambda decode_unicode=True: iter(events),
        )

    monkeypatch.setattr("antibot_sdk.vision.requests.post", fake_post)
    backend = OpenAICompatibleVisionBackend(
        base_url="https://vision.example/v1",
        api_key="secret",
        model="vision-model",
    )
    task = VisionTask("binary", "select", (image(),), min_answers=1)

    answer = asyncio.run(backend.solve(task))

    assert answer.selected == (0,)
    assert answer.diagnostics["finish_reason"] == "stop"
    assert answer.diagnostics["reasoning_chars"] == len("private reasoning")
    assert captured["url"] == "https://vision.example/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer secret"
    assert captured["body"]["model"] == "vision-model"
    assert captured["body"]["stream"] is True
    assert "max_tokens" not in captured["body"]
    assert captured["body"]["messages"][0]["content"][0]["text"].startswith(
        "You are a visual challenge solver"
    )
    content = captured["body"]["messages"][0]["content"]
    image_part = next(item for item in content if item["type"] == "image_url")
    assert image_part["image_url"]["url"].startswith("data:image/png;base64,")
    assert image_part["image_url"]["detail"] == "high"
    assert "secret" not in json_module.dumps(answer.diagnostics)


def test_openai_compatible_backend_rejects_unparseable_response(monkeypatch) -> None:
    events = [
        "data: "
        + json_module.dumps(
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "delta": {"reasoning_content": "still thinking"},
                    }
                ]
            }
        ),
        "data: [DONE]",
    ]
    monkeypatch.setattr(
        "antibot_sdk.vision.requests.post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            iter_lines=lambda decode_unicode=True: iter(events),
        ),
    )
    backend = OpenAICompatibleVisionBackend(
        base_url="https://vision.example",
        api_key="secret",
        model="vision-model",
    )

    with pytest.raises(VisionBackendError, match="truncated"):
        asyncio.run(backend.solve(VisionTask("point", "click", (image(),))))


def test_openai_compatible_backend_rejects_reserved_streaming_overrides() -> None:
    with pytest.raises(ValueError, match="reserved request fields: max_tokens"):
        OpenAICompatibleVisionBackend(
            base_url="https://vision.example",
            api_key="secret",
            model="vision-model",
            extra_body={"max_tokens": 1_000},
        )

    with pytest.raises(ValueError, match="reserved request fields: stream"):
        OpenAICompatibleVisionBackend(
            base_url="https://vision.example",
            api_key="secret",
            model="vision-model",
            extra_body={"stream": False},
        )


def test_coordinate_grid_overlay_preserves_dimensions() -> None:
    from io import BytesIO

    from PIL import Image

    source = BytesIO()
    Image.new("RGB", (123, 87), "navy").save(source, format="PNG")

    overlay = coordinate_grid_overlay(source.getvalue(), spacing=25)

    with Image.open(BytesIO(overlay.data)) as result:
        assert result.size == (123, 87)
    assert overlay.label == "coordinate-grid.png"
