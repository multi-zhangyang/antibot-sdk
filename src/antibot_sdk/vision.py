"""Provider-neutral visual reasoning primitives.

The captcha providers should only describe a visual task and validate the
returned answer.  They must not know whether the model is Gemini, an
OpenAI-compatible gateway, vLLM, or a local inference server.  This module
contains the small wire adapter shared by those providers.
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, Sequence, runtime_checkable

import requests
from PIL import Image, ImageDraw

VisionTaskKind = Literal[
    "binary",
    "point",
    "bounding_box",
    "multiple_choice",
    "drag_drop",
    "interactive",
]


class VisionBackendError(RuntimeError):
    """A model request or answer validation failed."""


class _VisionResponseTruncated(VisionBackendError):
    def __init__(self, metadata: dict[str, Any]):
        self.metadata = metadata
        super().__init__(
            "vision response was truncated before a final answer "
            f"(completion_tokens={metadata.get('usage', {}).get('completion_tokens')})"
        )


@dataclass(frozen=True)
class VisionImage:
    """An image supplied to a vision backend without requiring a temp file."""

    data: bytes
    mime_type: str = "image/png"
    label: str | None = None

    @classmethod
    def from_path(cls, path: str | Path, *, mime_type: str = "image/png") -> "VisionImage":
        return cls(data=Path(path).read_bytes(), mime_type=mime_type, label=Path(path).name)


@dataclass(frozen=True)
class VisionTask:
    """A normalized visual challenge presented to a backend."""

    kind: VisionTaskKind
    prompt: str
    images: tuple[VisionImage, ...]
    width: int | None = None
    height: int | None = None
    min_answers: int | None = None
    max_answers: int | None = None
    candidate_count: int | None = None
    choices: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VisionPoint:
    x: float
    y: float


@dataclass(frozen=True)
class VisionBox:
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class VisionPath:
    start: VisionPoint
    end: VisionPoint


@dataclass(frozen=True)
class VisionAnswer:
    """Validated answer shared by all visual challenge executors."""

    kind: VisionTaskKind
    selected: tuple[int, ...] = ()
    points: tuple[VisionPoint, ...] = ()
    boxes: tuple[VisionBox, ...] = ()
    paths: tuple[VisionPath, ...] = ()
    choices: tuple[str, ...] = ()
    confidence: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VisionSolvePolicy:
    """Shared retry/confidence policy for every visual provider adapter."""

    min_confidence: float = 0.35
    retries: int = 2
    require_confidence: bool = False
    allow_uncertain: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.min_confidence <= 1:
            raise ValueError("vision min_confidence must be between 0 and 1")
        if self.retries < 1:
            raise ValueError("vision retries must be at least 1")


@dataclass(frozen=True, slots=True)
class VisionSolveOutcome:
    """A model answer plus whether it was retained only for a safe fallback."""

    answer: VisionAnswer
    uncertain: bool = False
    errors: tuple[str, ...] = ()


@runtime_checkable
class VisionBackend(Protocol):
    async def solve(self, task: VisionTask) -> VisionAnswer:
        """Reason over a normalized visual task."""


def _finite_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VisionBackendError(f"{field_name} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise VisionBackendError(f"{field_name} must be finite")
    return number


def _positive_count(task: VisionTask, count: int) -> None:
    if count == 0 and (task.min_answers or 0) > 0:
        raise VisionBackendError("model returned no answers but the task requires a selection")
    if task.min_answers is not None and count < task.min_answers:
        raise VisionBackendError(f"model returned {count} answers, minimum is {task.min_answers}")
    if task.max_answers is not None and count > task.max_answers:
        raise VisionBackendError(f"model returned {count} answers, maximum is {task.max_answers}")


def _parse_point(value: Any, prefix: str) -> VisionPoint:
    if not isinstance(value, dict):
        raise VisionBackendError(f"{prefix} must be an object")
    x = _finite_number(value.get("x"), f"{prefix}.x")
    y = _finite_number(value.get("y"), f"{prefix}.y")
    if x < 0 or y < 0:
        raise VisionBackendError(f"{prefix} coordinates must be non-negative")
    return VisionPoint(x=x, y=y)


def _parse_box(value: Any, prefix: str) -> VisionBox:
    if not isinstance(value, dict):
        raise VisionBackendError(f"{prefix} must be an object")
    aliases = (
        ("x1", "top_left_x", "left"),
        ("y1", "top_left_y", "top"),
        ("x2", "bottom_right_x", "right"),
        ("y2", "bottom_right_y", "bottom"),
    )
    values = []
    for names, coordinate in zip(aliases, ("x1", "y1", "x2", "y2"), strict=True):
        raw = next((value.get(name) for name in names if name in value), None)
        values.append(_finite_number(raw, f"{prefix}.{coordinate}"))
    x1, y1, x2, y2 = values
    if min(x1, y1, x2, y2) < 0 or x2 <= x1 or y2 <= y1:
        raise VisionBackendError(f"{prefix} must be a non-empty box")
    return VisionBox(x1=x1, y1=y1, x2=x2, y2=y2)


def _extract_coordinate_points(value: Any) -> list[VisionPoint]:
    """Accept the two common VLM coordinate forms used by upstream tools."""

    if not isinstance(value, list):
        return []
    points: list[VisionPoint] = []
    for item in value:
        if isinstance(item, dict) and "box_2d" in item:
            pair = item["box_2d"]
            if not isinstance(pair, list) or len(pair) != 2:
                raise VisionBackendError("box_2d must contain two coordinates")
            points.append(
                VisionPoint(
                    x=_finite_number(pair[1], "box_2d.x"),
                    y=_finite_number(pair[0], "box_2d.y"),
                )
            )
        else:
            points.append(_parse_point(item, "points[]"))
    return points


def validate_vision_answer(task: VisionTask, payload: Any, *, diagnostics: dict[str, Any] | None = None) -> VisionAnswer:
    """Parse and strictly validate a model JSON object.

    A malformed or ambiguous answer is a hard failure.  Returning a guessed
    click is worse than asking the provider for another challenge because it
    poisons the vendor-side risk score and makes success impossible to prove.
    """

    if not isinstance(payload, dict):
        raise VisionBackendError("model response must be a JSON object")
    confidence = payload.get("confidence")
    if confidence is not None:
        confidence = _finite_number(confidence, "confidence")
        if not 0 <= confidence <= 1:
            raise VisionBackendError("confidence must be between 0 and 1")

    if task.kind == "binary":
        values = payload.get("selected", payload.get("indexes", payload.get("indices")))
        if not isinstance(values, list):
            coordinates = payload.get("coordinates")
            values = []
            if isinstance(coordinates, list):
                for item in coordinates:
                    pair = item.get("box_2d") if isinstance(item, dict) else None
                    if not isinstance(pair, list) or len(pair) != 2:
                        raise VisionBackendError("binary coordinates must contain box_2d pairs")
                    row = int(_finite_number(pair[0], "coordinates[].box_2d[0]"))
                    col = int(_finite_number(pair[1], "coordinates[].box_2d[1]"))
                    values.append(row * 3 + col)
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in values):
            raise VisionBackendError("selected indexes must be integers")
        selected = tuple(dict.fromkeys(values))
        candidate_count = task.candidate_count or len(task.images)
        if any(item < 0 or item >= candidate_count for item in selected):
            raise VisionBackendError("selected index is outside the supplied image list")
        _positive_count(task, len(selected))
        return VisionAnswer(
            task.kind,
            selected=selected,
            confidence=confidence,
            raw=payload,
            diagnostics=diagnostics or {},
        )

    if task.kind == "point":
        values = payload.get("points", payload.get("coordinates"))
        if values is None:
            raise VisionBackendError("point response is missing points")
        points = tuple(_extract_coordinate_points(values))
        _positive_count(task, len(points))
        return VisionAnswer(
            task.kind,
            points=points,
            confidence=confidence,
            raw=payload,
            diagnostics=diagnostics or {},
        )

    if task.kind == "bounding_box":
        values = payload.get("boxes", payload.get("bounding_boxes"))
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            raise VisionBackendError("bounding_box response is missing boxes")
        boxes = tuple(_parse_box(item, "boxes[]") for item in values)
        _positive_count(task, len(boxes))
        return VisionAnswer(
            task.kind,
            boxes=boxes,
            confidence=confidence,
            raw=payload,
            diagnostics=diagnostics or {},
        )

    if task.kind == "drag_drop":
        values = payload.get("paths")
        if not isinstance(values, list):
            raise VisionBackendError("drag_drop response is missing paths")
        paths: list[VisionPath] = []
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                raise VisionBackendError(f"paths[{index}] must be an object")
            start = item.get("start", item.get("start_point"))
            end = item.get("end", item.get("end_point"))
            paths.append(VisionPath(_parse_point(start, f"paths[{index}].start"), _parse_point(end, f"paths[{index}].end")))
        _positive_count(task, len(paths))
        return VisionAnswer(
            task.kind,
            paths=tuple(paths),
            confidence=confidence,
            raw=payload,
            diagnostics=diagnostics or {},
        )

    if task.kind == "multiple_choice":
        values = payload.get("choices", payload.get("selected"))
        if not isinstance(values, list) or not values:
            raise VisionBackendError("multiple_choice response is missing choices")
        choices = tuple(str(value) for value in values)
        if task.choices:
            allowed = {choice.casefold() for choice in task.choices}
            if any(choice.casefold() not in allowed for choice in choices):
                raise VisionBackendError("model returned a choice outside the supplied options")
        _positive_count(task, len(choices))
        return VisionAnswer(
            task.kind,
            choices=choices,
            confidence=confidence,
            raw=payload,
            diagnostics=diagnostics or {},
        )

    raise VisionBackendError(f"unsupported vision task kind: {task.kind}")


def validate_vision_geometry(answer: VisionAnswer, *, width: int, height: int) -> None:
    """Reject coordinates outside the exact screenshot supplied to the model."""

    points = list(answer.points)
    points.extend(point for path in answer.paths for point in (path.start, path.end))
    if any(
        point.x < 0 or point.x >= width or point.y < 0 or point.y >= height
        for point in points
    ):
        raise VisionBackendError(
            f"vision answer contains a point outside {width}x{height} image bounds"
        )
    if any(
        box.x1 < 0
        or box.x2 > width
        or box.y1 < 0
        or box.y2 > height
        or box.x2 <= box.x1
        or box.y2 <= box.y1
        for box in answer.boxes
    ):
        raise VisionBackendError(
            f"vision answer contains a box outside {width}x{height} image bounds"
        )


async def solve_vision_task(
    backend: VisionBackend,
    task: VisionTask,
    *,
    policy: VisionSolvePolicy | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> VisionSolveOutcome:
    """Run one normalized visual task with provider-independent retry rules.

    A backend outage or malformed response is a hard failure. When
    ``allow_uncertain`` is enabled, the last syntactically valid low-confidence
    answer is returned as ``uncertain=True`` so the provider can choose a
    vendor-safe fallback such as reload instead of clicking it blindly.
    """

    effective = policy or VisionSolvePolicy()
    errors: list[str] = []
    last_answer: VisionAnswer | None = None
    for attempt in range(1, effective.retries + 1):
        try:
            candidate = await backend.solve(task)
            last_answer = candidate
            confidence_error = (
                candidate.confidence is None and effective.require_confidence
            ) or (
                candidate.confidence is not None
                and candidate.confidence < effective.min_confidence
            )
            if confidence_error:
                confidence = (
                    "missing"
                    if candidate.confidence is None
                    else f"{candidate.confidence:.3f}"
                )
                raise VisionBackendError(
                    f"vision confidence {confidence} is below "
                    f"{effective.min_confidence:.3f}"
                )
            if task.width and task.height:
                validate_vision_geometry(candidate, width=task.width, height=task.height)
            if diagnostics is not None and errors:
                diagnostics.setdefault("vision_inference_retries", []).append(
                    {"kind": task.kind, "attempt": attempt, "prior_errors": list(errors)}
                )
            return VisionSolveOutcome(answer=candidate, errors=tuple(errors))
        except VisionBackendError as exc:
            message = f"attempt {attempt}: {type(exc).__name__}: {exc}"
            errors.append(message)
            if diagnostics is not None:
                diagnostics.setdefault("vision_inference_errors", []).append(
                    {"attempt": attempt, "kind": task.kind, "error": message}
                )
    if last_answer is not None and effective.allow_uncertain:
        return VisionSolveOutcome(answer=last_answer, uncertain=True, errors=tuple(errors))
    raise VisionBackendError(errors[-1] if errors else "vision backend returned no answer")


def vision_instruction(task: VisionTask) -> str:
    """Build a model-neutral prompt with an explicit, machine-checkable schema."""

    dimensions = (
        f"The main image coordinate space is {task.width}x{task.height} pixels. "
        if task.width and task.height
        else "Use the supplied image pixel coordinates. "
    )
    image_hint = "Images are indexed in the order supplied, starting at zero. "
    if task.kind == "binary":
        schema = '{"selected":[0,3],"confidence":0.0}'
        if task.candidate_count:
            image_hint = (
                f"The main image contains {task.candidate_count} selectable cells. "
                "Index them in row-major order starting at zero; headers and example images are not cells. "
                "Select every cell containing any visible part of the requested object, including "
                "small parts crossing a grid boundary. Do not select cells containing only shadows, "
                "road, or nearby background. Inspect each boundary before answering. "
            )
        if task.metadata.get("grid_tiles"):
            image_hint = (
                f"The request supplies {task.candidate_count or len(task.images)} separate grid-cell images "
                "in row-major order, starting at zero. Decide YES or NO for each cell independently. "
                "Return every cell where the requested object is clearly visible; do not infer an object "
                "from ordinary road surface, lane markings, shadows, or nearby background. "
            )
    elif task.kind == "point":
        schema = '{"points":[{"x":123,"y":45}],"confidence":0.0}'
    elif task.kind == "bounding_box":
        schema = '{"boxes":[{"x1":10,"y1":20,"x2":100,"y2":120}],"confidence":0.0}'
    elif task.kind == "drag_drop":
        schema = '{"paths":[{"start":{"x":10,"y":20},"end":{"x":100,"y":120}}],"confidence":0.0}'
    else:
        schema = '{"choices":["option"],"confidence":0.0}'
    choice_hint = f" Allowed choices: {list(task.choices)!r}." if task.choices else ""
    return (
        "You are a visual challenge solver. Analyze every supplied image and the task instruction. "
        "Do not narrate or repeat the task; inspect it directly and finish as soon as the visual "
        "answer is known. Return ONLY one compact JSON object, with no Markdown and no explanation. "
        f"Task kind: {task.kind}. Instruction: {task.prompt!r}. {dimensions}{image_hint}"
        f"{choice_hint} The JSON schema is {schema}. "
        "Do not invent coordinates outside the image. If the answer is not visually certain, "
        "return an empty answer and confidence 0 instead of guessing."
    )


def coordinate_grid_overlay(image: bytes, *, spacing: int = 50) -> VisionImage:
    """Overlay readable pixel coordinates without changing the image dimensions."""

    from io import BytesIO

    with Image.open(BytesIO(image)) as source:
        canvas = source.convert("RGB")
    draw = ImageDraw.Draw(canvas, "RGBA")
    width, height = canvas.size
    spacing = max(20, int(spacing))
    for x in range(0, width, spacing):
        draw.line((x, 0, x, height), fill=(255, 255, 255, 150), width=1)
        draw.rectangle((x + 1, 1, x + 35, 13), fill=(0, 0, 0, 180))
        draw.text((x + 3, 1), str(x), fill=(255, 255, 255, 255))
    for y in range(0, height, spacing):
        draw.line((0, y, width, y), fill=(255, 255, 255, 150), width=1)
        draw.rectangle((1, y + 1, 36, y + 13), fill=(0, 0, 0, 180))
        draw.text((3, y + 1), str(y), fill=(255, 255, 255, 255))
    output = BytesIO()
    canvas.save(output, format="PNG")
    return VisionImage(output.getvalue(), mime_type="image/png", label="coordinate-grid.png")


def _content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return ""


def _extract_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    candidates = [text]
    candidates.extend(re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE))
    for candidate in candidates:
        try:
            value = json.loads(candidate.strip())
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            for index, char in enumerate(candidate):
                if char != "{":
                    continue
                try:
                    value, _ = decoder.raw_decode(candidate[index:])
                except json.JSONDecodeError:
                    continue
                break
            else:
                continue
        if isinstance(value, dict):
            return value
    return None


class OpenAICompatibleVisionBackend:
    """Vision backend for OpenAI-compatible chat completion gateways.

    The endpoint, key and model are runtime configuration.  No provider name,
    URL, or credential is embedded in the SDK.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_sec: float = 180,
        temperature: float = 0,
        extra_body: dict[str, Any] | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("vision base_url must not be empty")
        if not api_key.strip():
            raise ValueError("vision api_key must not be empty")
        if not model.strip():
            raise ValueError("vision model must not be empty")
        normalized = base_url.rstrip("/")
        self.endpoint = normalized if normalized.endswith("/chat/completions") else f"{normalized}/v1/chat/completions" if not normalized.endswith("/v1") else f"{normalized}/chat/completions"
        self.api_key = api_key
        self.model = model
        self.timeout_sec = max(1.0, float(timeout_sec))
        self.temperature = float(temperature)
        self.extra_body = dict(extra_body or {})
        reserved = {"model", "messages", "stream", "max_tokens"}
        conflicts = sorted(reserved.intersection(self.extra_body))
        if conflicts:
            raise ValueError(
                "vision extra_body cannot override reserved request fields: "
                + ", ".join(conflicts)
            )

    def _request(
        self,
        task: VisionTask,
        instruction: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        content: list[dict[str, Any]] = [
            {"type": "text", "text": instruction or vision_instruction(task)}
        ]
        for index, image in enumerate(task.images):
            if image.label:
                content.append({"type": "text", "text": f"Image {index}: {image.label}"})
            encoded = base64.b64encode(image.data).decode("ascii")
            content.append(
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{image.mime_type};base64,{encoded}",
                        "detail": "high",
                    },
                }
            )
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": content}],
            "temperature": self.temperature,
            "stream": True,
        }
        body.update(self.extra_body)
        response = requests.post(
            self.endpoint,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=self.timeout_sec,
            stream=True,
        )
        if response.status_code >= 400:
            try:
                error_payload = response.json()
            except ValueError:
                error_payload = {}
            message = error_payload.get("error", {}).get("message", "request rejected") if isinstance(error_payload, dict) else "request rejected"
            raise VisionBackendError(f"vision gateway HTTP {response.status_code}: {message}")
        payload = self._read_stream(response)
        if not isinstance(payload, dict):
            raise VisionBackendError("vision gateway response must be an object")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise VisionBackendError("vision gateway response has no choices")
        message = choices[0].get("message") or {}
        text = _content_text(message.get("content"))
        reasoning = _content_text(message.get("reasoning_content"))
        metadata = {
            "backend": "openai_compatible",
            "model": payload.get("model", self.model),
            "finish_reason": choices[0].get("finish_reason"),
            "content_chars": len(text),
            "reasoning_chars": len(reasoning),
            "usage": payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
        }
        if choices[0].get("finish_reason") == "length":
            raise _VisionResponseTruncated(metadata)
        parsed = _extract_json(text)
        if parsed is None and text == "":
            # Some reasoning models place the final JSON in reasoning_content.
            parsed = _extract_json(reasoning)
        if parsed is None:
            finish = choices[0].get("finish_reason")
            raise VisionBackendError(
                f"vision gateway returned no parseable JSON (finish_reason={finish!r}, "
                f"content_chars={len(text)}, reasoning_chars={len(reasoning)})"
            )
        return parsed, metadata

    @staticmethod
    def _read_json(response: Any) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise VisionBackendError("vision gateway returned non-JSON HTTP response") from exc
        if not isinstance(payload, dict):
            raise VisionBackendError("vision gateway response must be an object")
        return payload

    @staticmethod
    def _read_stream(response: Any) -> dict[str, Any]:
        """Collect an OpenAI-compatible SSE chat stream into one response object."""

        # A few test doubles and older gateways ignore ``stream=true`` and
        # return a normal JSON object. The request is still made in streaming
        # mode; this compatibility branch only keeps their response usable.
        iterator = getattr(response, "iter_lines", None)
        if not callable(iterator):
            return OpenAICompatibleVisionBackend._read_json(response)
        content: list[str] = []
        reasoning: list[str] = []
        model: str | None = None
        finish_reason: Any = None
        usage: dict[str, Any] = {}
        saw_event = False
        for raw_line in iterator(decode_unicode=True):
            if isinstance(raw_line, bytes):
                raw_line = raw_line.decode("utf-8", errors="replace")
            line = str(raw_line).strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            saw_event = True
            if isinstance(event.get("model"), str):
                model = event["model"]
            if isinstance(event.get("usage"), dict):
                usage = event["usage"]
            choices = event.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                continue
            choice = choices[0]
            if choice.get("finish_reason") is not None:
                finish_reason = choice.get("finish_reason")
            delta = choice.get("delta") or choice.get("message") or {}
            if isinstance(delta, dict):
                text = _content_text(delta.get("content"))
                if text:
                    content.append(text)
                private = _content_text(
                    delta.get("reasoning_content", delta.get("reasoning"))
                )
                if private:
                    reasoning.append(private)
        if not saw_event:
            raise VisionBackendError("vision gateway returned an empty SSE stream")
        return {
            "model": model,
            "choices": [
                {
                    "finish_reason": finish_reason,
                    "message": {
                        "content": "".join(content),
                        "reasoning_content": "".join(reasoning),
                    },
                }
            ],
            "usage": usage,
        }

    async def complete_json(
        self,
        task: VisionTask,
        *,
        instruction: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return one parsed JSON object for a caller-defined multimodal schema."""

        return await asyncio.to_thread(
            self._request,
            task,
            instruction,
        )

    async def solve(self, task: VisionTask) -> VisionAnswer:
        parsed, metadata = await self.complete_json(
            task,
            instruction=vision_instruction(task),
        )
        return validate_vision_answer(task, parsed, diagnostics=metadata)


class StaticVisionBackend:
    """Deterministic backend used by replay tests and custom integrations."""

    def __init__(self, answers: Sequence[dict[str, Any]]) -> None:
        self._answers = list(answers)
        self.calls: list[VisionTask] = []

    async def solve(self, task: VisionTask) -> VisionAnswer:
        self.calls.append(task)
        if not self._answers:
            raise VisionBackendError("static vision backend has no answer left")
        return validate_vision_answer(task, self._answers.pop(0), diagnostics={"backend": "static"})


__all__ = [
    "OpenAICompatibleVisionBackend",
    "StaticVisionBackend",
    "VisionAnswer",
    "VisionBackend",
    "VisionBackendError",
    "VisionBox",
    "VisionImage",
    "VisionPath",
    "VisionPoint",
    "VisionSolveOutcome",
    "VisionSolvePolicy",
    "VisionTask",
    "coordinate_grid_overlay",
    "solve_vision_task",
    "validate_vision_answer",
    "validate_vision_geometry",
    "vision_instruction",
]
