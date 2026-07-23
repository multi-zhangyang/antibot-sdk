from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from io import BytesIO
from pathlib import Path
from types import MethodType
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlparse

from PIL import Image

from ..models import CaptchaResult
from ..persistence import persist_result
from ..proxy import proxy_free_environment, redacted_proxy, resolve_runtime_proxy
from ..harness.contracts import (
    ChallengeAction,
    ChallengeCandidate,
    ChallengeObservation,
    VendorVerification,
)
from ..harness.execution import ActionValidation, ChallengeExecutor, action_from_vision
from ..vision import (
    OpenAICompatibleVisionBackend,
    VisionAnswer,
    VisionBackend,
    VisionBackendError,
    VisionImage,
    VisionSolvePolicy,
    VisionTask,
    coordinate_grid_overlay,
    solve_vision_task,
)

WidgetProvider = Literal["recaptcha", "hcaptcha"]

WIDGET_PROVIDER_ALIASES = {
    "recaptcha": "recaptcha",
    "re-captcha": "recaptcha",
    "google": "recaptcha",
    "google-recaptcha": "recaptcha",
    "recaptcha_v2": "recaptcha",
    "recaptcha-v2": "recaptcha",
    "hcaptcha": "hcaptcha",
    "h-captcha": "hcaptcha",
    "hcaptcha_v1": "hcaptcha",
    "hcaptcha-v1": "hcaptcha",
}

WIDGET_HOST_MARKERS = {
    "recaptcha": ("google.com/recaptcha", "gstatic.com/recaptcha", "recaptcha.net/recaptcha"),
    "hcaptcha": ("hcaptcha.com", "hcaptcha.net"),
}

HCAPTCHA_OBJECTS_URL = (
    "https://raw.githubusercontent.com/QIN2DIM/hcaptcha-challenger/"
    "1e4611f9567255afdac87a5748424d5d6dcbc06a/src/objects.yaml"
)
HCAPTCHA_MODEL_RELEASE_URL = (
    "https://api.github.com/repos/QIN2DIM/hcaptcha-challenger/releases/tags/model"
)
HCAPTCHA_IMAGENET_MODEL_URL = (
    "https://github.com/onnx/models/raw/main/validated/vision/classification/"
    "mobilenet/model/mobilenetv2-12.onnx"
)
HCAPTCHA_IMAGENET_LABELS_URL = (
    "https://raw.githubusercontent.com/onnx/models/main/validated/vision/"
    "classification/synset.txt"
)
HCAPTCHA_IMAGENET_MODEL_SHA256 = (
    "c0c3f76d93fa3fd6580652a45618618a220fced18babf65774ed169de0432ad5"
)
HCAPTCHA_IMAGENET_LABELS_SHA256 = (
    "acf75ef0abe89694b19056e0796401068b459c457baa30335f240c7692857355"
)

HCAPTCHA_PROMPT_LABEL_RULES = (
    ({"animal", "climb", "tree"}, "tree_climbing_animals"),
)

HCAPTCHA_TREE_CLIMBER_CLASSES = (
    "fox squirrel",
    "orangutan",
    "gorilla",
    "chimpanzee",
    "gibbon",
    "guenon",
    "patas",
    "baboon",
    "macaque",
    "langur",
    "colobus",
    "proboscis monkey",
    "marmoset",
    "capuchin",
    "howler monkey",
    "titi",
    "spider monkey",
    "squirrel monkey",
)

HCAPTCHA_NON_CLIMBER_CLASSES = (
    "tench",
    "goldfish",
    "great white shark",
    "tiger shark",
    "hammerhead",
    "electric ray",
    "stingray",
    "dolphin",
    "whale",
    "sea lion",
    "dugong",
    "otter",
    "weasel",
    "polecat",
    "black-footed ferret",
    "barracouta",
    "sturgeon",
)

TOKEN_SELECTORS = {
    "recaptcha": (
        "textarea[name='g-recaptcha-response']",
        "textarea[name='g-recaptcha-response-100000']",
        "input[name='g-recaptcha-response']",
    ),
    "hcaptcha": (
        "textarea[name='h-captcha-response']",
        "input[name='h-captcha-response']",
    ),
}

CHECKBOX_SELECTORS = {
    "recaptcha": (
        "#recaptcha-anchor",
        "[role='checkbox']",
        ".recaptcha-checkbox-border",
    ),
    "hcaptcha": (
        "#checkbox",
        "[role='checkbox']",
        ".check",
    ),
}

WIDGET_HOOK_JS = r"""
(() => {
  if (globalThis.__ANTIBOT_WIDGET_HOOK__) return;
  const state = { tokens: [], events: [], startedAt: Date.now() };
  const record = (provider, token, event) => {
    const value = typeof token === 'string' ? token.trim() : '';
    if (value.length > 20 && !state.tokens.includes(value)) state.tokens.push(value);
    state.events.push({ provider, event, tokenLength: value.length, at: Date.now() });
    if (state.events.length > 100) state.events.shift();
  };
  const readFields = () => {
    for (const selector of [
      "textarea[name='g-recaptcha-response']",
      "textarea[name='h-captcha-response']",
      "input[name='g-recaptcha-response']",
      "input[name='h-captcha-response']",
    ]) {
      for (const element of document.querySelectorAll(selector)) {
        if (element.value) record(selector.includes('h-captcha') ? 'hcaptcha' : 'recaptcha', element.value, 'field');
      }
    }
  };
  const wrap = (name) => {
    const api = globalThis[name];
    if (!api || api.__antibotWrapped) return;
    try {
      if (typeof api.render === 'function') {
        const originalRender = api.render;
        api.render = function(container, parameters) {
          const config = { ...(parameters || {}) };
          const callback = config.callback;
          config.callback = function(token) {
            record(name === 'hcaptcha' ? 'hcaptcha' : 'recaptcha', token, 'callback');
            if (typeof callback === 'function') callback.apply(this, arguments);
          };
          return originalRender.call(this, container, config);
        };
      }
      if (typeof api.execute === 'function') {
        const originalExecute = api.execute;
        api.execute = function() {
          const value = originalExecute.apply(this, arguments);
          if (value && typeof value.then === 'function') {
            value.then((token) => record(name === 'hcaptcha' ? 'hcaptcha' : 'recaptcha', token, 'execute'));
          }
          return value;
        };
      }
      Object.defineProperty(api, '__antibotWrapped', { value: true, configurable: true });
    } catch (_) {}
  };
  globalThis.__ANTIBOT_WIDGET_HOOK__ = state;
  setInterval(() => {
    readFields();
    wrap('grecaptcha');
    wrap('hcaptcha');
  }, 250);
})();
""".strip()


def normalize_widget_provider(value: str | None) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    return WIDGET_PROVIDER_ALIASES.get(normalized, normalized)


def detect_widget_provider(url: str | None) -> str | None:
    parsed = urlparse(str(url or ""))
    surface = f"{parsed.hostname or ''}{parsed.path or ''}".lower()
    for provider, markers in WIDGET_HOST_MARKERS.items():
        if any(marker in surface for marker in markers):
            return provider
    return None


def _headless(value: bool | str | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "true").lower() not in {"0", "false", "no", "headed"}


def _hcaptcha_prompt_label(prompt: str | None) -> str | None:
    words = {
        token.strip(".,!?;:()[]{}\"'")
        for token in str(prompt or "").lower().split()
        if token.strip(".,!?;:()[]{}\"'")
    }
    normalized_words = {word[:-1] if word.endswith("s") else word for word in words}
    for required, label in HCAPTCHA_PROMPT_LABEL_RULES:
        if required <= normalized_words:
            return label
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _TreeClimbingAnimalClassifier:
    """Detect tree-climbing animals in hCaptcha's current composite-image task."""

    def __init__(self, cache_root: Path, download: Any):
        self.model_path = cache_root / "mobilenetv2-12.onnx"
        self.labels_path = cache_root / "imagenet-synset.txt"
        self._download = download
        self._session: Any = None
        self._labels: list[str] = []
        self._positive_ids: list[int] = []
        self._negative_ids: list[int] = []

    def _ensure_file(
        self,
        path: Path,
        *,
        url: str,
        size: int,
        sha256: str,
    ) -> None:
        if not path.is_file() or path.stat().st_size != size or _sha256(path) != sha256:
            self._download(url, path, expected_size=size)
        if _sha256(path) != sha256:
            raise RuntimeError(f"checksum mismatch for hCaptcha vision asset: {path.name}")

    def ensure_ready(self) -> None:
        if self._session is not None:
            return
        self._ensure_file(
            self.model_path,
            url=HCAPTCHA_IMAGENET_MODEL_URL,
            size=13_964_571,
            sha256=HCAPTCHA_IMAGENET_MODEL_SHA256,
        )
        self._ensure_file(
            self.labels_path,
            url=HCAPTCHA_IMAGENET_LABELS_URL,
            size=31_675,
            sha256=HCAPTCHA_IMAGENET_LABELS_SHA256,
        )

        import onnxruntime

        self._labels = [
            line.strip().split(" ", 1)[1]
            for line in self.labels_path.read_text(encoding="utf-8").splitlines()
            if " " in line
        ]
        self._positive_ids = [
            index
            for index, label in enumerate(self._labels)
            if any(term in label.lower() for term in HCAPTCHA_TREE_CLIMBER_CLASSES)
        ]
        self._negative_ids = [
            index
            for index, label in enumerate(self._labels)
            if any(term in label.lower() for term in HCAPTCHA_NON_CLIMBER_CLASSES)
        ]
        self._session = onnxruntime.InferenceSession(
            str(self.model_path),
            providers=["CPUExecutionProvider"],
        )

    def detect(self, screenshot: bytes, *, max_points: int = 5) -> list[dict[str, Any]]:
        import cv2
        import numpy as np
        from PIL import Image

        self.ensure_ready()
        encoded = np.frombuffer(screenshot, dtype=np.uint8)
        bgr = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
        if bgr is None:
            raise RuntimeError("unable to decode hCaptcha challenge screenshot")

        height, width = bgr.shape[:2]
        scale = min(width / 500, height / 470)
        left = max(0, int(round(width * 10 / 500)))
        right = min(width, int(round(width * 490 / 500)))
        top = max(0, int(round(height * 135 / 470)))
        bottom = min(height, int(round(height * 455 / 470)))
        roi = bgr[top:bottom, left:right]
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
        edge_energy = cv2.magnitude(
            cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3),
            cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3),
        )
        edge_energy = cv2.GaussianBlur(
            edge_energy,
            (0, 0),
            max(2, 16 * scale),
        )

        candidate_map = edge_energy.copy()
        candidate_radius = max(24, int(round(55 * scale)))
        candidates: list[tuple[int, int, float]] = []
        for _ in range(12):
            _, energy, _, (x, y) = cv2.minMaxLoc(candidate_map)
            candidates.append((x + left, y + top, float(energy)))
            cv2.circle(candidate_map, (x, y), candidate_radius, 0, -1)

        image = Image.open(BytesIO(screenshot)).convert("RGB")
        crop_sizes = [
            max(32, int(round(value * scale)))
            for value in (48, 56, 64, 72, 80, 88, 96)
        ]
        tensors: list[Any] = []
        owners: list[int] = []
        mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
        std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
        for candidate_index, (x, y, _) in enumerate(candidates):
            for crop_size in crop_sizes:
                half = crop_size // 2
                crop = image.crop((x - half, y - half, x + half, y + half)).resize(
                    (224, 224),
                    Image.Resampling.BILINEAR,
                )
                tensor = np.asarray(crop, dtype=np.float32) / 255
                tensors.append(((tensor - mean) / std).transpose(2, 0, 1))
                owners.append(candidate_index)

        output_name = self._session.get_outputs()[0].name
        input_name = self._session.get_inputs()[0].name
        logits = self._session.run(
            [output_name],
            {input_name: np.stack(tensors).astype(np.float32)},
        )[0]
        margins: list[list[float]] = [[] for _ in candidates]
        labels: list[list[str]] = [[] for _ in candidates]
        for owner, scores in zip(owners, logits, strict=True):
            positive_id = max(self._positive_ids, key=lambda index: scores[index])
            positive_score = float(scores[positive_id])
            negative_score = max(float(scores[index]) for index in self._negative_ids)
            margins[owner].append(positive_score - negative_score)
            labels[owner].append(self._labels[positive_id])

        ranked = []
        for candidate, candidate_margins, candidate_labels in zip(
            candidates, margins, labels, strict=True
        ):
            best_index = max(range(len(candidate_margins)), key=candidate_margins.__getitem__)
            x, y, energy = candidate
            color_patch = np.asarray(
                image.crop(
                    (
                        x - max(24, int(round(35 * scale))),
                        y - max(24, int(round(35 * scale))),
                        x + max(24, int(round(35 * scale))),
                        y + max(24, int(round(35 * scale))),
                    )
                ),
                dtype=np.float32,
            )
            blue_excess = float(
                color_patch[:, :, 2].mean()
                - (color_patch[:, :, 0].mean() + color_patch[:, :, 1].mean()) / 2
            )
            ranked.append(
                {
                    "x": x,
                    "y": y,
                    "margin": candidate_margins[best_index],
                    "label": candidate_labels[best_index],
                    "edge_energy": energy,
                    "blue_excess": blue_excess,
                }
            )

        selected: list[dict[str, Any]] = []
        point_radius = max(30, int(round(65 * scale)))
        for candidate in sorted(ranked, key=lambda item: item["margin"], reverse=True):
            if candidate["margin"] < 2.4:
                break
            if (
                candidate["blue_excess"] > 15
                and "squirrel" not in candidate["label"].lower()
                and candidate["margin"] < 8
            ):
                continue
            if all(
                (candidate["x"] - current["x"]) ** 2
                + (candidate["y"] - current["y"]) ** 2
                > point_radius**2
                for current in selected
            ):
                selected.append(candidate)
            if len(selected) >= max(1, max_points):
                break
        return selected


def _resolve_vision_backend(
    backend: VisionBackend | None,
    *,
    base_url: str | None,
    api_key: str | None,
    api_key_env: str | None,
    model: str | None,
    timeout_sec: float,
    extra_body: dict[str, Any] | None,
) -> VisionBackend | None:
    if backend is not None:
        return backend
    resolved_base_url = base_url or os.environ.get("ANTIBOT_VISION_BASE_URL")
    resolved_model = model or os.environ.get("ANTIBOT_VISION_MODEL")
    resolved_key = api_key
    if not resolved_key and api_key_env:
        resolved_key = os.environ.get(api_key_env)
    if not any((resolved_base_url, resolved_model, resolved_key)):
        return None
    missing = [
        name
        for name, value in (
            ("vision_base_url", resolved_base_url),
            ("vision_model", resolved_model),
            (f"vision_api_key/{api_key_env or 'configured env'}", resolved_key),
        )
        if not value
    ]
    if missing:
        raise ValueError("incomplete vision backend configuration: missing " + ", ".join(missing))
    return OpenAICompatibleVisionBackend(
        base_url=str(resolved_base_url),
        api_key=str(resolved_key),
        model=str(resolved_model),
        timeout_sec=timeout_sec,
        extra_body=extra_body,
    )


def _vision_answer_summary(answer: VisionAnswer) -> dict[str, Any]:
    return {
        "kind": answer.kind,
        "selected": list(answer.selected),
        "points": [{"x": round(point.x, 2), "y": round(point.y, 2)} for point in answer.points],
        "boxes": [
            {
                "x1": round(box.x1, 2),
                "y1": round(box.y1, 2),
                "x2": round(box.x2, 2),
                "y2": round(box.y2, 2),
            }
            for box in answer.boxes
        ],
        "paths": [
            {
                "start": {"x": round(path.start.x, 2), "y": round(path.start.y, 2)},
                "end": {"x": round(path.end.x, 2), "y": round(path.end.y, 2)},
            }
            for path in answer.paths
        ],
        "choices": list(answer.choices),
        "confidence": answer.confidence,
        "backend": answer.diagnostics,
    }


def _grid_observation(
    *,
    provider: str,
    prompt: str,
    candidate_count: int,
    dynamic: bool,
    screenshot: bytes,
    sequence: int,
    phase: str = "presented",
    metadata: dict[str, Any] | None = None,
) -> ChallengeObservation:
    side = math.isqrt(candidate_count)
    rows = side if side * side == candidate_count else None
    columns = rows
    digest = hashlib.sha256(screenshot).hexdigest()
    candidates = tuple(
        ChallengeCandidate(
            index=index,
            row=(index // columns if columns else None),
            column=(index % columns if columns else None),
        )
        for index in range(candidate_count)
    )
    observation_id = hashlib.sha256(
        f"{provider}|{sequence}|{prompt}|{digest}".encode("utf-8")
    ).hexdigest()[:24]
    return ChallengeObservation(
        observation_id=observation_id,
        provider=provider,
        kind="binary",
        modality="image",
        prompt=prompt[:500],
        candidate_count=candidate_count,
        candidates=candidates,
        grid_rows=rows,
        grid_columns=columns,
        dynamic=dynamic,
        min_answers=0,
        max_answers=candidate_count,
        phase=phase,  # type: ignore[arg-type]
        metadata={"image_sha256": digest, **(metadata or {})},
    )


def _visual_observation(
    *,
    provider: str,
    prompt: str,
    kind: str,
    screenshot: bytes,
    sequence: int,
    width: int | None = None,
    height: int | None = None,
    candidate_count: int | None = None,
    dynamic: bool = False,
    min_answers: int | None = None,
    max_answers: int | None = None,
    choices: tuple[str, ...] = (),
    metadata: dict[str, Any] | None = None,
) -> ChallengeObservation:
    """Build an observation for the exact rendered image used by a solver.

    Vendor responses describe the logical challenge, while the browser can
    replace the rendered image after every click.  Hashing the screenshot into
    the observation id prevents an action from being replayed against a stale
    canvas or tile set.
    """

    digest = hashlib.sha256(screenshot).hexdigest()
    rows: int | None = None
    columns: int | None = None
    candidates: tuple[ChallengeCandidate, ...] = ()
    if candidate_count is not None and candidate_count >= 0:
        side = math.isqrt(candidate_count)
        if side > 0 and side * side == candidate_count:
            rows = columns = side
            candidates = tuple(
                ChallengeCandidate(index=index, row=index // side, column=index % side)
                for index in range(candidate_count)
            )
        else:
            candidates = tuple(
                ChallengeCandidate(index=index) for index in range(candidate_count)
            )
    observation_id = hashlib.sha256(
        f"{provider}|{kind}|{sequence}|{prompt}|{digest}".encode("utf-8")
    ).hexdigest()[:24]
    return ChallengeObservation(
        observation_id=observation_id,
        provider=provider,
        kind=kind,  # type: ignore[arg-type]
        modality="image",
        prompt=prompt[:500],
        candidate_count=candidate_count,
        candidates=candidates,
        grid_rows=rows,
        grid_columns=columns,
        width=width,
        height=height,
        dynamic=dynamic,
        min_answers=min_answers,
        max_answers=max_answers,
        choices=choices,
        phase="presented",
        metadata={"image_sha256": digest, **(metadata or {})},
    )


def _hcaptcha_question_observation(
    question: Any,
    *,
    sequence: int,
) -> ChallengeObservation:
    """Normalize one hCaptcha getcaptcha response without touching agent state."""

    prompt = str(question.requester_question.get("en", ""))
    request_type = str(question.request_type)
    config = question.request_config
    shape_type = config.get("shape_type")
    kind = {
        "image_label_binary": "binary",
        "image_label_multiple_choice": "multiple_choice",
        "image_drag_drop": "drag_drop",
    }.get(request_type)
    if request_type == "image_label_area_select":
        kind = {
            "point": "point",
            "bounding_box": "bounding_box",
        }.get(str(shape_type), "unknown")
    if kind is None:
        kind = "unknown"

    candidate_count = len(question.tasklist) if kind == "binary" else None
    minimum = config.get("min_shapes_per_image", config.get("min_points"))
    maximum = config.get("max_shapes_per_image", config.get("max_points"))
    minimum = minimum if isinstance(minimum, int) and minimum >= 0 else None
    maximum = maximum if isinstance(maximum, int) and maximum >= 0 else None
    if kind == "binary":
        minimum = 0 if minimum is None else minimum
        maximum = candidate_count if maximum is None else maximum
    elif kind == "multiple_choice":
        minimum = maximum = 1
    if minimum is not None and maximum is not None and minimum > maximum:
        minimum = maximum = None

    restricted = tuple(
        str(item).strip()
        for item in question.requester_restricted_answer_set
        if str(item).strip() and str(item).strip().casefold() != "default"
    )
    observation_id = hashlib.sha256(
        f"hcaptcha|{sequence}|{request_type}|{shape_type}|{prompt}".encode("utf-8")
    ).hexdigest()[:24]
    return ChallengeObservation(
        observation_id=observation_id,
        provider="hcaptcha",
        kind=kind,  # type: ignore[arg-type]
        modality="image",
        prompt=prompt[:500],
        candidate_count=candidate_count,
        min_answers=minimum,
        max_answers=maximum,
        choices=restricted if kind == "multiple_choice" else (),
        phase="presented",
        metadata={
            "request_type": request_type,
            "shape_type": shape_type,
            "task_count": len(question.tasklist),
            "source": "vendor_question",
        },
    )


def _record_challenge_observation(
    diagnostics: dict[str, Any], observation: ChallengeObservation
) -> None:
    ChallengeExecutor(diagnostics).observe(observation)


def _validate_challenge_action(
    diagnostics: dict[str, Any],
    observation: ChallengeObservation,
    action: ChallengeAction,
) -> ActionValidation:
    return ChallengeExecutor(diagnostics).validate(observation, action)


def _mark_challenge_action_executed(
    diagnostics: dict[str, Any], validation: ActionValidation
) -> None:
    ChallengeExecutor(diagnostics).mark_executed(validation)


@dataclass(frozen=True)
class _CanvasAlignmentScore:
    x: int
    y: int
    score: float
    canvas_width: int
    canvas_height: int


@dataclass(frozen=True)
class _TaskCanvasMatch:
    screenshot: bytes
    box: dict[str, float] | None
    alignment: _CanvasAlignmentScore
    attempt_scores: tuple[float, ...]


class _TaskCanvasTimeout(VisionBackendError):
    def __init__(
        self,
        *,
        threshold: float,
        attempt_scores: list[float],
        last_screenshot: bytes | None,
        last_alignment: _CanvasAlignmentScore | None,
    ) -> None:
        best_score = max(attempt_scores, default=0.0)
        super().__init__(
            "expected task image did not appear on the hCaptcha canvas: "
            f"best alignment {best_score:.3f}, required {threshold:.3f}"
        )
        self.threshold = threshold
        self.attempt_scores = tuple(attempt_scores)
        self.last_screenshot = last_screenshot
        self.last_alignment = last_alignment


def _score_task_image_alignment(
    canvas_image: bytes,
    task_image: bytes,
) -> _CanvasAlignmentScore:
    """Locate an exact challenge image inside the larger rendered hCaptcha canvas."""

    import cv2
    import numpy as np

    canvas_array = cv2.imdecode(
        np.frombuffer(canvas_image, dtype=np.uint8), cv2.IMREAD_GRAYSCALE
    )
    task_array = cv2.imdecode(
        np.frombuffer(task_image, dtype=np.uint8), cv2.IMREAD_GRAYSCALE
    )
    if canvas_array is None or task_array is None:
        raise VisionBackendError("unable to decode task image for canvas alignment")
    task_height, task_width = task_array.shape[:2]
    canvas_height, canvas_width = canvas_array.shape[:2]
    if task_width > canvas_width or task_height > canvas_height:
        raise VisionBackendError("task image is larger than the rendered canvas")
    scores = cv2.matchTemplate(canvas_array, task_array, cv2.TM_CCOEFF_NORMED)
    _, score, _, location = cv2.minMaxLoc(scores)
    return _CanvasAlignmentScore(
        x=location[0],
        y=location[1],
        score=float(score),
        canvas_width=canvas_width,
        canvas_height=canvas_height,
    )


async def _wait_for_task_canvas(
    canvas: Any,
    task_image: bytes,
    *,
    min_score: float = 0.70,
    timeout_sec: float = 12.0,
    poll_interval_sec: float = 0.20,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> _TaskCanvasMatch:
    """Wait until the canvas renders the exact raw image for the task being answered."""

    await canvas.wait_for(state="visible")
    deadline = time.monotonic() + max(0.0, timeout_sec)
    attempt_scores: list[float] = []
    last_screenshot: bytes | None = None
    last_alignment: _CanvasAlignmentScore | None = None
    while True:
        last_screenshot = await canvas.screenshot(type="png")
        last_alignment = _score_task_image_alignment(last_screenshot, task_image)
        attempt_scores.append(last_alignment.score)
        if last_alignment.score >= min_score:
            box = await canvas.bounding_box(timeout=1500)
            return _TaskCanvasMatch(
                screenshot=last_screenshot,
                box=box,
                alignment=last_alignment,
                attempt_scores=tuple(attempt_scores),
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _TaskCanvasTimeout(
                threshold=min_score,
                attempt_scores=attempt_scores,
                last_screenshot=last_screenshot,
                last_alignment=last_alignment,
            )
        await sleep(min(max(0.01, poll_interval_sec), remaining))


def _install_hcaptcha_vision_solver(
    agent: Any,
    backend: VisionBackend,
    *,
    diagnostics: dict[str, Any],
    trace_diagnostics: dict[str, Any] | None = None,
    min_confidence: float,
    retries: int,
) -> None:
    """Replace prompt-specific model routing with normalized open-vocabulary tasks."""

    from PIL import Image

    task_serial = 0
    observation_serial = 0
    trace = trace_diagnostics if trace_diagnostics is not None else diagnostics

    def task_limits(instance: Any) -> tuple[int | None, int | None]:
        config = instance.qr.request_config
        minimum = config.get("min_shapes_per_image", config.get("min_points"))
        maximum = config.get("max_shapes_per_image", config.get("max_points"))
        return (
            minimum if isinstance(minimum, int) else None,
            maximum if isinstance(maximum, int) else None,
        )

    def observe(
        instance: Any,
        task: VisionTask,
        screenshot: bytes,
        *,
        candidate_count: int | None = None,
        choices: tuple[str, ...] = (),
        task_index: int | None = None,
        dynamic: bool = False,
    ) -> ChallengeObservation:
        nonlocal observation_serial
        observation_serial += 1
        observation = _visual_observation(
            provider="hcaptcha",
            prompt=instance.prompt,
            kind=task.kind,
            screenshot=screenshot,
            sequence=observation_serial,
            width=task.width,
            height=task.height,
            candidate_count=(
                candidate_count
                if candidate_count is not None
                else task.candidate_count
            ),
            dynamic=dynamic,
            min_answers=task.min_answers,
            max_answers=task.max_answers,
            choices=choices or task.choices,
            metadata={
                "request_type": str(instance.qr.request_type),
                "shape_type": instance.qr.request_config.get("shape_type"),
                "task_index": task_index,
                "source": "rendered_challenge",
            },
        )
        _record_challenge_observation(trace, observation)
        return observation

    def require_valid_action(
        observation: ChallengeObservation,
        action: ChallengeAction,
    ) -> ActionValidation:
        validation = _validate_challenge_action(trace, observation, action)
        if validation.valid:
            return validation
        raise VisionBackendError(
            "challenge action failed observation validation: "
            + ", ".join(validation.errors)
        )

    def save_replay(instance: Any, screenshot: bytes, task: VisionTask, answer: VisionAnswer) -> None:
        nonlocal task_serial
        task_serial += 1
        replay_root = Path(instance.tmp_dir) / "vision-replay"
        replay_root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(screenshot).hexdigest()[:16]
        stem = f"{task_serial:04d}-{task.kind}-{digest}"
        (replay_root / f"{stem}.png").write_bytes(screenshot)
        record = {
            "schema_version": 1,
            "kind": task.kind,
            "prompt": task.prompt,
            "width": task.width,
            "height": task.height,
            "min_answers": task.min_answers,
            "max_answers": task.max_answers,
            "candidate_count": task.candidate_count,
            "choices": list(task.choices),
            "image_sha256": hashlib.sha256(screenshot).hexdigest(),
            "answer": _vision_answer_summary(answer),
        }
        (replay_root / f"{stem}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    async def infer(instance: Any, task: VisionTask, screenshot: bytes) -> VisionAnswer:
        outcome = await solve_vision_task(
            backend,
            task,
            policy=VisionSolvePolicy(
                min_confidence=min_confidence,
                retries=max(1, retries),
            ),
            diagnostics=diagnostics,
        )
        answer = outcome.answer
        summary = _vision_answer_summary(answer)
        summary.update(
            {
                "request_type": instance.qr.request_type,
                "shape_type": instance.qr.request_config.get("shape_type"),
                "prompt": instance.prompt[:300],
            }
        )
        diagnostics.setdefault("vision_tasks", []).append(summary)
        save_replay(instance, screenshot, task, answer)
        return answer

    async def challenge_view_screenshot(frame_challenge: Any) -> tuple[Any, bytes, int, int]:
        view = frame_challenge.locator("//div[@class='challenge-view']")
        await view.wait_for(state="visible")
        await agent.page.wait_for_timeout(500)
        screenshot = await view.screenshot(type="png")
        with Image.open(BytesIO(screenshot)) as image:
            width, height = image.size
        return view, screenshot, width, height

    async def submit(
        frame_challenge: Any,
        observation: ChallengeObservation,
    ) -> None:
        validation = require_valid_action(
            observation,
            ChallengeAction(observation_id=observation.observation_id, kind="submit"),
        )
        button = frame_challenge.locator("//div[@class='button-submit button']")
        if not await button.count():
            raise VisionBackendError("hCaptcha challenge has no submit button")
        await button.click(delay=150)
        _mark_challenge_action_executed(trace, validation)

    def as_png(path: Path) -> tuple[bytes, int, int]:
        output = BytesIO()
        with Image.open(path) as source:
            width, height = source.size
            source.convert("RGB").save(output, format="PNG")
        return output.getvalue(), width, height

    def spatial_task_paths(instance: Any) -> list[Path]:
        paths = [Path(path) for path in instance.img_paths]
        if len(paths) < len(instance.qr.tasklist):
            raise VisionBackendError(
                f"downloaded {len(paths)} task images for {len(instance.qr.tasklist)} tasks"
            )
        return paths[: len(instance.qr.tasklist)]

    async def spatial_answer(
        instance: Any,
        path: Path,
        *,
        kind: str,
        minimum: int | None,
        maximum: int | None,
    ) -> tuple[bytes, int, int, VisionAnswer]:
        screenshot, width, height = await asyncio.to_thread(as_png, path)
        task = VisionTask(
            kind=kind,
            prompt=instance.prompt,
            images=(
                VisionImage(screenshot, label="challenge-image.png"),
                coordinate_grid_overlay(screenshot),
            ),
            width=width,
            height=height,
            min_answers=minimum,
            max_answers=maximum,
            metadata={"provider": "hcaptcha"},
        )
        answer = await infer(instance, task, screenshot)
        return screenshot, width, height, answer

    async def aligned_canvas(
        instance: Any,
        frame_challenge: Any,
        task_screenshot: bytes,
        *,
        task_index: int,
        previous_canvas_sha256: str | None,
    ) -> tuple[Any, _TaskCanvasMatch, str]:
        canvas = frame_challenge.locator("//div[@class='challenge-view']//canvas")
        expected_sha256 = hashlib.sha256(task_screenshot).hexdigest()
        try:
            match = await _wait_for_task_canvas(canvas, task_screenshot)
        except _TaskCanvasTimeout as exc:
            record: dict[str, Any] = {
                "task_index": task_index,
                "status": "timeout",
                "expected_image_sha256": expected_sha256,
                "required_score": exc.threshold,
                "attempt_scores": [round(score, 4) for score in exc.attempt_scores],
                "best_score": round(max(exc.attempt_scores, default=0.0), 4),
            }
            if exc.last_alignment is not None:
                record.update(
                    {
                        "last_x": exc.last_alignment.x,
                        "last_y": exc.last_alignment.y,
                    }
                )
            if exc.last_screenshot:
                replay_root = Path(instance.tmp_dir) / "vision-replay"
                replay_root.mkdir(parents=True, exist_ok=True)
                artifact = replay_root / (
                    f"alignment-timeout-{task_index + 1:04d}-{expected_sha256[:16]}.png"
                )
                artifact.write_bytes(exc.last_screenshot)
                record["rendered_canvas"] = str(artifact)
            diagnostics.setdefault("vision_canvas_alignment", []).append(record)
            raise

        rendered_sha256 = hashlib.sha256(match.screenshot).hexdigest()
        alignment = match.alignment
        diagnostics.setdefault("vision_canvas_alignment", []).append(
            {
                "task_index": task_index,
                "status": "matched",
                "expected_image_sha256": expected_sha256,
                "rendered_canvas_sha256": rendered_sha256,
                "changed_from_previous": (
                    previous_canvas_sha256 is None
                    or rendered_sha256 != previous_canvas_sha256
                ),
                "x": alignment.x,
                "y": alignment.y,
                "score": round(alignment.score, 4),
                "attempt_scores": [round(score, 4) for score in match.attempt_scores],
            }
        )
        return canvas, match, rendered_sha256

    async def point_challenge(instance: Any, frame_challenge: Any) -> None:
        minimum, maximum = task_limits(instance)
        previous_canvas_sha256: str | None = None
        for task_index, path in enumerate(spatial_task_paths(instance)):
            task_screenshot, width, height, answer = await spatial_answer(
                instance,
                path,
                kind="point",
                minimum=minimum,
                maximum=maximum,
            )
            task = VisionTask(
                kind="point",
                prompt=instance.prompt,
                images=(),
                width=width,
                height=height,
                min_answers=minimum,
                max_answers=maximum,
                metadata={"provider": "hcaptcha"},
            )
            observation = observe(
                instance,
                task,
                task_screenshot,
                task_index=task_index,
            )
            validation = require_valid_action(
                observation,
                action_from_vision(observation, answer),
            )
            canvas, match, previous_canvas_sha256 = await aligned_canvas(
                instance,
                frame_challenge,
                task_screenshot,
                task_index=task_index,
                previous_canvas_sha256=previous_canvas_sha256,
            )
            alignment = match.alignment
            canvas_box = match.box
            scale_x = (
                float(canvas_box["width"]) / alignment.canvas_width if canvas_box else 1
            )
            scale_y = (
                float(canvas_box["height"]) / alignment.canvas_height if canvas_box else 1
            )
            for point in answer.points:
                if canvas_box:
                    await instance.page.mouse.click(
                        canvas_box["x"] + (alignment.x + point.x) * scale_x,
                        canvas_box["y"] + (alignment.y + point.y) * scale_y,
                        delay=120,
                    )
                else:
                    await canvas.click(
                        delay=120,
                        position={
                            "x": (alignment.x + point.x) * scale_x,
                            "y": (alignment.y + point.y) * scale_y,
                        },
                    )
            _mark_challenge_action_executed(trace, validation)
            await submit(frame_challenge, observation)

    async def bounding_box_challenge(instance: Any, frame_challenge: Any) -> None:
        minimum, maximum = task_limits(instance)
        previous_canvas_sha256: str | None = None
        for task_index, path in enumerate(spatial_task_paths(instance)):
            task_screenshot, width, height, answer = await spatial_answer(
                instance,
                path,
                kind="bounding_box",
                minimum=minimum,
                maximum=maximum,
            )
            task = VisionTask(
                kind="bounding_box",
                prompt=instance.prompt,
                images=(),
                width=width,
                height=height,
                min_answers=minimum,
                max_answers=maximum,
                metadata={"provider": "hcaptcha"},
            )
            observation = observe(
                instance,
                task,
                task_screenshot,
                task_index=task_index,
            )
            validation = require_valid_action(
                observation,
                action_from_vision(observation, answer),
            )
            canvas, match, previous_canvas_sha256 = await aligned_canvas(
                instance,
                frame_challenge,
                task_screenshot,
                task_index=task_index,
                previous_canvas_sha256=previous_canvas_sha256,
            )
            alignment = match.alignment
            canvas_box = match.box
            scale_x = (
                float(canvas_box["width"]) / alignment.canvas_width if canvas_box else 1
            )
            scale_y = (
                float(canvas_box["height"]) / alignment.canvas_height if canvas_box else 1
            )
            for bounds in answer.boxes:
                if canvas_box:
                    await instance.page.mouse.click(
                        canvas_box["x"] + (alignment.x + bounds.x1) * scale_x,
                        canvas_box["y"] + (alignment.y + bounds.y1) * scale_y,
                        delay=120,
                    )
                    await instance.page.mouse.click(
                        canvas_box["x"] + (alignment.x + bounds.x2) * scale_x,
                        canvas_box["y"] + (alignment.y + bounds.y2) * scale_y,
                        delay=120,
                    )
                else:
                    await canvas.click(
                        delay=120,
                        position={
                            "x": (alignment.x + bounds.x1) * scale_x,
                            "y": (alignment.y + bounds.y1) * scale_y,
                        },
                    )
                    await canvas.click(
                        delay=120,
                        position={
                            "x": (alignment.x + bounds.x2) * scale_x,
                            "y": (alignment.y + bounds.y2) * scale_y,
                        },
                    )
            _mark_challenge_action_executed(trace, validation)
            await submit(frame_challenge, observation)

    async def binary_challenge(instance: Any, frame_challenge: Any, _model: Any = None) -> None:
        rounds = max(1, (len(instance.qr.tasklist) + 8) // 9)
        for _ in range(rounds):
            _view, screenshot, width, height = await challenge_view_screenshot(frame_challenge)
            samples = frame_challenge.locator("//div[@class='task-image']")
            count = await samples.count()
            if count < 1:
                raise VisionBackendError("hCaptcha binary challenge has no candidate images")
            task = VisionTask(
                kind="binary",
                prompt=instance.prompt,
                images=(VisionImage(screenshot, label="full-challenge.png"),),
                width=width,
                height=height,
                min_answers=0,
                max_answers=count,
                candidate_count=count,
                metadata={"provider": "hcaptcha"},
            )
            answer = await infer(instance, task, screenshot)
            observation = observe(
                instance,
                task,
                screenshot,
                candidate_count=count,
                dynamic=rounds > 1,
            )
            validation = require_valid_action(
                observation,
                action_from_vision(observation, answer),
            )
            for index in answer.selected:
                await samples.nth(index).click(delay=120)
            _mark_challenge_action_executed(trace, validation)
            await submit(frame_challenge, observation)

    async def multiple_choice_challenge(instance: Any, frame_challenge: Any) -> None:
        for _ in range(len(instance.qr.tasklist)):
            _view, screenshot, width, height = await challenge_view_screenshot(frame_challenge)
            options = frame_challenge.locator("//div[@class='challenge-answer']")
            count = await options.count()
            labels = tuple(
                (await options.nth(index).text_content() or "").strip()
                for index in range(count)
            )
            task = VisionTask(
                kind="multiple_choice",
                prompt=instance.prompt,
                images=(VisionImage(screenshot, label="full-challenge.png"),),
                width=width,
                height=height,
                min_answers=1,
                max_answers=1,
                choices=labels,
                metadata={"provider": "hcaptcha"},
            )
            answer = await infer(instance, task, screenshot)
            observation = observe(
                instance,
                task,
                screenshot,
                choices=labels,
            )
            selected = answer.choices[0].casefold()
            index = next(
                index for index, label in enumerate(labels) if label.casefold() == selected
            )
            validation = require_valid_action(
                observation,
                action_from_vision(observation, answer),
            )
            await options.nth(index).click(delay=120)
            _mark_challenge_action_executed(trace, validation)
            await submit(frame_challenge, observation)

    async def drag_drop_challenge(instance: Any, frame_challenge: Any) -> None:
        minimum, maximum = task_limits(instance)
        for _ in range(len(instance.qr.tasklist)):
            view, screenshot, width, height = await challenge_view_screenshot(frame_challenge)
            box = await view.bounding_box(timeout=1500)
            if not box:
                raise VisionBackendError("hCaptcha challenge view has no clickable geometry")
            task = VisionTask(
                kind="drag_drop",
                prompt=instance.prompt,
                images=(
                    VisionImage(screenshot, label="full-challenge.png"),
                    coordinate_grid_overlay(screenshot),
                ),
                width=width,
                height=height,
                min_answers=minimum or 1,
                max_answers=maximum,
                metadata={"provider": "hcaptcha"},
            )
            answer = await infer(instance, task, screenshot)
            observation = observe(instance, task, screenshot)
            validation = require_valid_action(
                observation,
                action_from_vision(observation, answer),
            )
            origin_x = float(box["x"])
            origin_y = float(box["y"])
            scale_x = float(box["width"]) / width
            scale_y = float(box["height"]) / height
            for path in answer.paths:
                await instance.page.mouse.move(
                    origin_x + path.start.x * scale_x,
                    origin_y + path.start.y * scale_y,
                )
                await instance.page.mouse.down()
                await instance.page.mouse.move(
                    origin_x + path.end.x * scale_x,
                    origin_y + path.end.y * scale_y,
                    steps=20,
                )
                await instance.page.mouse.up()
            _mark_challenge_action_executed(trace, validation)
            await submit(frame_challenge, observation)

    async def execute(instance: Any, **kwargs: Any) -> Any:
        frame_challenge = instance._switch_to_challenge_frame(
            instance.page, kwargs.get("window", "login")
        )
        try:
            if not await instance._reset_state() or not instance.qr:
                return instance.status.CHALLENGE_BACKCALL
        except asyncio.QueueEmpty:
            return instance.status.CHALLENGE_BACKCALL
        if not instance.qr.requester_question.keys():
            instance._recover_state()
            return instance.status.CHALLENGE_SUCCESS

        instance._parse_label()
        request_type = str(instance.qr.request_type)
        shape_type = instance.qr.request_config.get("shape_type")
        if request_type == "image_label_area_select":
            await instance._download_images()
        if request_type == "image_label_binary":
            await binary_challenge(instance, frame_challenge)
        elif request_type == "image_label_area_select" and shape_type == "point":
            await point_challenge(instance, frame_challenge)
        elif request_type == "image_label_area_select" and shape_type == "bounding_box":
            await bounding_box_challenge(instance, frame_challenge)
        elif request_type == "image_label_multiple_choice":
            await multiple_choice_challenge(instance, frame_challenge)
        elif request_type == "image_drag_drop":
            await drag_drop_challenge(instance, frame_challenge)
        else:
            diagnostics.setdefault("unsupported_vision_tasks", []).append(
                {"request_type": request_type, "shape_type": shape_type}
            )
            return instance.status.CHALLENGE_BACKCALL

        instance.modelhub.unplug()
        try:
            return await instance._is_success()
        except asyncio.QueueEmpty:
            return instance.status.CHALLENGE_BACKCALL

    agent.execute = MethodType(execute, agent)
    diagnostics["vision_solver"] = {
        "enabled": True,
        "strategy": "open_vocabulary_multimodal",
        "supported_tasks": [
            "image_label_binary",
            "image_label_area_select:point",
            "image_label_area_select:bounding_box",
            "image_label_multiple_choice",
            "image_drag_drop",
        ],
        "minimum_confidence": min_confidence,
        "inference_attempts": max(1, retries),
    }


def _discover_browser(explicit: str | None = None) -> str | None:
    candidates: list[str] = []
    for value in (
        explicit,
        shutil.which("google-chrome-stable"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ):
        if value:
            candidates.append(value)
    for root in (Path.home() / ".cache" / "ms-playwright", Path("/ms-playwright")):
        if root.exists():
            candidates.extend(str(path) for path in root.glob("chromium-*/chrome-linux*/chrome"))
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and path.stat().st_mode & 0o111:
            return str(path)
    return None


async def _read_frame_tokens(frame: Any, provider: str) -> list[str]:
    tokens: list[str] = []
    for selector in TOKEN_SELECTORS[provider]:
        try:
            count = await frame.locator(selector).count()
            for index in range(count):
                value = await frame.locator(selector).nth(index).input_value(timeout=300)
                if isinstance(value, str) and len(value.strip()) > 20:
                    tokens.append(value.strip())
        except Exception:
            continue
    return tokens


async def _collect_tokens(page: Any, provider: str) -> list[str]:
    tokens: list[str] = []
    for frame in page.frames:
        tokens.extend(await _read_frame_tokens(frame, provider))
    try:
        state = await page.evaluate(
            """() => ({
              tokens: globalThis.__ANTIBOT_WIDGET_HOOK__?.tokens || [],
              events: globalThis.__ANTIBOT_WIDGET_HOOK__?.events || []
            })"""
        )
        if isinstance(state, dict):
            tokens.extend(value for value in state.get("tokens", []) if isinstance(value, str))
    except Exception:
        pass
    return list(dict.fromkeys(token.strip() for token in tokens if token and len(token.strip()) > 20))


def _hcaptcha_verified_token(challenge: Any) -> str | None:
    token = str(getattr(challenge, "generated_pass_UUID", "") or "").strip()
    if bool(getattr(challenge, "is_pass", False)) and len(token) > 20:
        return token
    return None


def _select_widget_token(
    provider: str,
    dom_tokens: list[str],
    hcaptcha_verified_tokens: list[str],
) -> str | None:
    if provider == "hcaptcha" and hcaptcha_verified_tokens:
        return hcaptcha_verified_tokens[-1]
    return dom_tokens[0] if dom_tokens else None


async def _detect_widget_provider(page: Any) -> str | None:
    """Infer a widget from frames and DOM markers without relying on URL query text."""

    for candidate in ("recaptcha", "hcaptcha"):
        if any(_frame_kind(frame.url, candidate) for frame in page.frames):
            return candidate
    try:
        markers = await page.evaluate(
            """() => {
              const values = [
                ...Array.from(document.querySelectorAll('iframe[src],script[src]')).map((el) => el.src),
                ...Array.from(document.querySelectorAll('[class], [id], [data-sitekey]')).map((el) =>
                  `${el.id || ''} ${el.className || ''} ${el.getAttribute('data-sitekey') || ''}`),
              ].join(' ').toLowerCase();
              return { recaptcha: /recaptcha|g-recaptcha/.test(values), hcaptcha: /hcaptcha|h-captcha/.test(values) };
            }"""
        )
    except Exception:
        return None
    if isinstance(markers, dict):
        if markers.get("recaptcha"):
            return "recaptcha"
        if markers.get("hcaptcha"):
            return "hcaptcha"
    return None


def _frame_kind(url: str, provider: str) -> str | None:
    normalized = (url or "").lower()
    if provider == "recaptcha":
        if "api2/anchor" in normalized or "recaptcha/api2" in normalized:
            return "recaptcha_v2"
        if "recaptcha" in normalized:
            return "recaptcha"
    elif provider == "hcaptcha" and "hcaptcha" in normalized:
        return "hcaptcha"
    return None


async def _click_checkbox(page: Any, provider: str) -> bool:
    clicked = False
    for frame in page.frames:
        if _frame_kind(frame.url, provider) is None:
            continue
        for selector in CHECKBOX_SELECTORS[provider]:
            try:
                locator = frame.locator(selector).first
                if await locator.count() and await locator.is_visible(timeout=250):
                    await locator.click(timeout=1500)
                    clicked = True
                    break
            except Exception:
                continue
        if clicked:
            break
    return clicked


async def _recaptcha_challenge_frame(page: Any) -> Any | None:
    """Return the visible reCAPTCHA image challenge frame, if one exists."""

    for frame in page.frames:
        if "recaptcha/api2/bframe" not in str(frame.url):
            continue
        try:
            target = frame.locator("#rc-imageselect-target")
            if await target.count() and await target.is_visible(timeout=100):
                return frame
        except Exception:
            continue
    return None


async def _recaptcha_prompt(frame: Any) -> str:
    for selector in (".rc-imageselect-desc-wrapper", ".rc-imageselect-desc-no-canonical"):
        try:
            locator = frame.locator(selector).first
            if await locator.count():
                value = (await locator.inner_text(timeout=500) or "").strip()
                if value:
                    return " ".join(value.split())[:500]
        except Exception:
            continue
    return "Select all matching images"


async def _recaptcha_tile_image_signature(frame: Any) -> str:
    """Hash image sources/classes without retaining Google payload URLs in diagnostics."""

    values = await frame.locator("#rc-imageselect-target .rc-imageselect-tile img").evaluate_all(
        """els => els.map((el) => ({
          src: el.getAttribute('src') || '',
          className: el.className || '',
          style: el.getAttribute('style') || '',
        }))"""
    )
    encoded = json.dumps(values, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


async def _wait_for_recaptcha_grid_ready(
    page: Any,
    frame: Any,
    *,
    require_unselected: bool,
    previous_signature: str | None = None,
    timeout_sec: float = 8.0,
) -> str:
    """Wait for decoded tile images and, after clicks, completed replacements."""

    deadline = time.monotonic() + max(0.25, timeout_sec)
    stable_signature: str | None = None
    stable_polls = 0
    while True:
        state = await frame.locator("#rc-imageselect-target").evaluate(
            """target => {
              const tiles = Array.from(target.querySelectorAll('.rc-imageselect-tile'));
              const images = Array.from(target.querySelectorAll('img'));
              return {
                tileCount: tiles.length,
                selectedCount: target.querySelectorAll('.rc-imageselect-tileselected').length,
                imagesReady: images.length > 0 && images.every((img) => img.complete && img.naturalWidth > 0),
                imagesVisible: images.length > 0 && images.every((img) => Number(getComputedStyle(img).opacity) >= 0.95),
              };
            }"""
        )
        signature = await _recaptcha_tile_image_signature(frame)
        ready = bool(
            isinstance(state, dict)
            and state.get("tileCount")
            and state.get("imagesReady")
            and state.get("imagesVisible")
            and (not require_unselected or state.get("selectedCount") == 0)
            and (previous_signature is None or signature != previous_signature)
        )
        if ready and signature == stable_signature:
            stable_polls += 1
        elif ready:
            stable_signature = signature
            stable_polls = 1
        else:
            stable_signature = None
            stable_polls = 0
        if stable_polls >= 2:
            return signature
        if time.monotonic() >= deadline:
            raise VisionBackendError("reCAPTCHA grid did not finish loading or replacing tiles")
        await page.wait_for_timeout(200)


async def _screenshot_recaptcha_target(page: Any, target: Any) -> bytes:
    """Capture a grid without spending Playwright's full default timeout on animations."""

    try:
        return await target.screenshot(
            type="png",
            animations="disabled",
            timeout=5000,
        )
    except Exception:
        # Dynamic replacement grids can keep the element's stability box in
        # motion even after every image is decoded. A page-level clipped
        # screenshot does not require Locator's scroll/stability action.
        try:
            box = await target.bounding_box(timeout=1500)
            if not box:
                raise VisionBackendError("reCAPTCHA grid has no visible bounding box")
            return await page.screenshot(
                type="png",
                clip=box,
                animations="disabled",
                caret="hide",
                timeout=5000,
            )
        except Exception as fallback_error:
            raise VisionBackendError(
                "reCAPTCHA grid screenshot failed after clipped-page fallback"
            ) from fallback_error


def _recaptcha_vision_images(screenshot: bytes, candidate_count: int) -> tuple[VisionImage, ...]:
    """Split a rendered grid into enlarged row-major cells for visual inference."""

    side = math.isqrt(candidate_count)
    if side * side != candidate_count or side < 2:
        return (VisionImage(screenshot, label="recaptcha-grid.png"),)
    with Image.open(BytesIO(screenshot)) as source:
        image = source.convert("RGB")
        width, height = image.size
        cell_width = width / side
        cell_height = height / side
        cells: list[VisionImage] = []
        for index in range(candidate_count):
            row, column = divmod(index, side)
            left = int(round(column * cell_width))
            top = int(round(row * cell_height))
            right = int(round((column + 1) * cell_width))
            bottom = int(round((row + 1) * cell_height))
            crop = image.crop((left, top, right, bottom))
            crop = crop.resize((crop.width * 2, crop.height * 2), Image.Resampling.LANCZOS)
            output = BytesIO()
            crop.save(output, format="PNG")
            cells.append(VisionImage(output.getvalue(), label=f"grid-cell-{index}.png"))
    return tuple(cells)


async def _click_recaptcha_action(
    page: Any,
    frame: Any,
    *,
    expect_verify: bool,
) -> str:
    button = frame.locator("#recaptcha-verify-button").first
    if not await button.count():
        raise VisionBackendError("reCAPTCHA action button is missing")
    deadline = time.monotonic() + 3
    label = ""
    while True:
        label = " ".join((await button.inner_text(timeout=500) or "").split()).upper()
        if not expect_verify or label not in {"", "SKIP"}:
            break
        if time.monotonic() >= deadline:
            raise VisionBackendError("reCAPTCHA action button remained SKIP after selection")
        await page.wait_for_timeout(150)
    await button.click(timeout=3000, delay=100)
    return label.casefold() or "unknown"


async def _refresh_recaptcha_challenge(
    page: Any,
    frame: Any,
    *,
    previous_signature: str,
    timeout_sec: float,
) -> str:
    """Request a new Google challenge and prove that its image grid changed."""

    button = frame.locator("#recaptcha-reload-button").first
    if not await button.count():
        raise VisionBackendError("reCAPTCHA reload button is missing")
    await button.click(timeout=3000, delay=100)
    return await _wait_for_recaptcha_grid_ready(
        page,
        frame,
        require_unselected=True,
        previous_signature=previous_signature,
        timeout_sec=timeout_sec,
    )


@dataclass(slots=True)
class _RecaptchaGridState:
    observation: ChallengeObservation
    task: VisionTask
    frame: Any
    signature: str
    screenshot: bytes
    round_record: dict[str, Any]


class RecaptchaChallengeSession:
    """Provider adapter for one live reCAPTCHA image-grid episode.

    The adapter owns Google-specific frame discovery, stable-grid waits, tile
    clicks, reloads, and token collection. It deliberately does not choose
    tiles or infer success from a button click; those responsibilities belong
    to :class:`ChallengeAgentLoop` and :meth:`verify`, respectively.
    """

    def __init__(
        self,
        page: Any,
        *,
        diagnostics: dict[str, Any] | None = None,
        output_dir: str | None = None,
        max_rounds: int = 8,
        refresh_wait_ms: int = 8000,
        verification_wait_ms: int = 3000,
        network_events: list[dict[str, Any]] | None = None,
    ) -> None:
        if max_rounds < 1:
            raise ValueError("reCAPTCHA session max_rounds must be positive")
        if refresh_wait_ms < 1:
            raise ValueError("reCAPTCHA session refresh_wait_ms must be positive")
        if verification_wait_ms < 0:
            raise ValueError("reCAPTCHA session verification_wait_ms must be non-negative")
        self.page = page
        self.diagnostics = diagnostics if diagnostics is not None else {}
        self.output_root = (
            Path(output_dir).expanduser().resolve() / "vision-replay"
            if output_dir
            else None
        )
        self.max_rounds = max_rounds
        self.refresh_timeout_sec = refresh_wait_ms / 1000
        self.verification_wait_sec = verification_wait_ms / 1000
        self.network_events = network_events if network_events is not None else []
        self._sequence = 0
        self._rounds = 0
        self._dynamic = False
        self._pending_submit = False
        self._submitted = False
        self._current: _RecaptchaGridState | None = None

    @property
    def submitted(self) -> bool:
        return self._submitted

    async def observe(self) -> ChallengeObservation | None:
        # Google can leave the bframe visible for a short period after
        # userverify. A token is stronger evidence than that transient DOM;
        # stop the action loop before it proposes another reload or click.
        if await _collect_tokens(self.page, "recaptcha"):
            self._current = None
            return None
        frame = await _recaptcha_challenge_frame(self.page)
        if frame is None:
            self._current = None
            return None
        if not self._pending_submit and self._rounds >= self.max_rounds:
            self.diagnostics["recaptcha_max_rounds_exhausted"] = True
            raise VisionBackendError("reCAPTCHA session exhausted its challenge-round budget")

        target = frame.locator("#rc-imageselect-target")
        await target.wait_for(state="visible", timeout=5000)
        signature = await _wait_for_recaptcha_grid_ready(
            self.page,
            frame,
            require_unselected=not self._pending_submit,
        )
        prompt = await _recaptcha_prompt(frame)
        self._dynamic = self._dynamic or "once there are none left" in prompt.casefold()
        tiles = frame.locator("#rc-imageselect-target .rc-imageselect-tile")
        candidate_count = await tiles.count()
        if candidate_count < 1:
            raise VisionBackendError("reCAPTCHA image challenge has no candidate tiles")
        screenshot = await _screenshot_recaptcha_target(self.page, target)
        from PIL import Image

        with Image.open(BytesIO(screenshot)) as image:
            width, height = image.size

        phase = "answering" if self._pending_submit else "presented"
        if phase == "presented":
            self._rounds += 1
        self._sequence += 1
        observation = _grid_observation(
            provider="recaptcha",
            prompt=prompt,
            candidate_count=candidate_count,
            dynamic=self._dynamic,
            screenshot=screenshot,
            sequence=self._sequence,
            phase=phase,
            metadata={"round": self._rounds, "source": "rendered_grid"},
        )
        task = VisionTask(
            kind="binary",
            prompt=prompt,
            images=_recaptcha_vision_images(screenshot, candidate_count),
            width=width,
            height=height,
            min_answers=0,
            max_answers=candidate_count,
            candidate_count=candidate_count,
            metadata={
                "provider": "recaptcha",
                "round": self._rounds,
                "grid_tiles": True,
            },
        )
        round_record = {
            "round": self._rounds,
            "observation_id": observation.observation_id,
            "prompt": prompt,
            "candidate_count": candidate_count,
            "dynamic": self._dynamic,
            "phase": phase,
        }
        if phase == "presented":
            engine = self.diagnostics.setdefault("challenge_engine", {})
            tasks = engine.setdefault("vision_tasks", [])
            if isinstance(tasks, list):
                tasks.append(
                    {
                        "kind": "binary",
                        "prompt": prompt,
                        "round": self._rounds,
                        "observation_id": observation.observation_id,
                        "candidate_count": candidate_count,
                    }
                )
        self.diagnostics.setdefault("recaptcha_session_observations", []).append(
            round_record
        )
        state = _RecaptchaGridState(
            observation=observation,
            task=task,
            frame=frame,
            signature=signature,
            screenshot=screenshot,
            round_record=round_record,
        )
        self._current = state
        self._save_replay(state)
        return observation

    async def vision_task(self, observation: ChallengeObservation) -> VisionTask | None:
        state = self._current
        if state is None or state.observation.observation_id != observation.observation_id:
            return None
        if observation.phase != "presented":
            return None
        return state.task

    def translate_vision_answer(
        self,
        observation: ChallengeObservation,
        answer: VisionAnswer,
    ) -> ChallengeAction:
        """Map a confident empty grid answer directly to Google's action button."""

        action = action_from_vision(observation, answer)
        if answer.kind == "binary" and not answer.selected:
            return ChallengeAction(
                observation_id=observation.observation_id,
                kind="submit",
                confidence=answer.confidence,
                rationale="reCAPTCHA grid contains no remaining matching tiles",
            )
        return action

    async def execute(self, action: ChallengeAction) -> None:
        state = self._current
        if state is None or state.observation.observation_id != action.observation_id:
            raise VisionBackendError("reCAPTCHA action does not target the current grid")
        frame = await _recaptcha_challenge_frame(self.page)
        if frame is None:
            raise VisionBackendError("reCAPTCHA challenge disappeared before action execution")

        if action.kind == "select":
            selected = list(action.payload.get("selected", []))
            state.round_record.update(
                {
                    "action": "select",
                    "selected_count": len(selected),
                    "confidence": action.confidence,
                }
            )
            if selected:
                tiles = frame.locator("#rc-imageselect-target .rc-imageselect-tile")
                if await tiles.count() != state.observation.candidate_count:
                    raise VisionBackendError(
                        "reCAPTCHA tile count changed before selection execution"
                    )
                for index in selected:
                    await tiles.nth(index).click(timeout=1500, delay=100)
                    await self.page.wait_for_timeout(120)
            if state.observation.dynamic and selected:
                try:
                    await _wait_for_recaptcha_grid_ready(
                        self.page,
                        frame,
                        require_unselected=True,
                        previous_signature=state.signature,
                        timeout_sec=max(0.25, self.refresh_timeout_sec),
                    )
                    state.round_record["replacement_observed"] = True
                except VisionBackendError:
                    state.round_record["replacement_observed"] = False
                    raise
                self._pending_submit = False
            else:
                self._pending_submit = True
            self._current = None
            return

        if action.kind == "reload":
            state.round_record.update(
                {
                    "action": "reload",
                    "uncertain": action.uncertain,
                }
            )
            try:
                await _refresh_recaptcha_challenge(
                    self.page,
                    frame,
                    previous_signature=state.signature,
                    timeout_sec=max(0.25, self.refresh_timeout_sec),
                )
                state.round_record["replacement_observed"] = True
            except VisionBackendError:
                state.round_record["replacement_observed"] = False
                raise
            self.diagnostics["recaptcha_uncertain_refreshes"] = (
                int(self.diagnostics.get("recaptcha_uncertain_refreshes", 0)) + 1
            )
            self._pending_submit = False
            self._current = None
            return

        if action.kind == "submit":
            label = await _click_recaptcha_action(
                self.page,
                frame,
                expect_verify=state.observation.dynamic,
            )
            state.round_record.update({"action": "submit", "button_label": label})
            self._submitted = True
            self._pending_submit = False
            self._current = None
            await self.page.wait_for_timeout(250)
            return

        if action.kind == "noop":
            state.round_record["action"] = "noop"
            self._current = None
            return
        raise VisionBackendError(f"unsupported reCAPTCHA session action: {action.kind}")

    async def verify(self) -> VendorVerification:
        deadline = time.monotonic() + self.verification_wait_sec
        tokens: list[str] = []
        while True:
            tokens = await _collect_tokens(self.page, "recaptcha")
            if tokens or time.monotonic() >= deadline:
                break
            await self.page.wait_for_timeout(200)

        token_length = max((len(token) for token in tokens), default=0)
        site = self.diagnostics.get("site_verification")
        site_verified = site.get("ok") if isinstance(site, dict) else None
        event_urls = tuple(
            str(item.get("url"))
            for item in self.network_events
            if isinstance(item, dict) and item.get("url")
        )
        verifier_events = tuple(
            marker
            for marker in ("/recaptcha/api2/userverify",)
            if any(marker in url for url in event_urls)
        )
        accepted = token_length > 0 and site_verified is not False
        gaps: list[str] = []
        if token_length == 0:
            gaps.append("recaptcha_vendor_token_not_captured")
        if site_verified is False:
            gaps.append("site_verification_not_observed")
        self.diagnostics["recaptcha_session_verification"] = {
            "accepted": accepted,
            "submitted": self._submitted,
            "token_length": token_length,
            "site_verified": site_verified,
            "verifier_events": list(verifier_events),
            "gaps": gaps,
        }
        return VendorVerification(
            provider="recaptcha",
            accepted=accepted,
            token_length=token_length,
            site_verified=site_verified,
            verifier_events=verifier_events,
            gaps=tuple(gaps),
        )

    def _save_replay(self, state: _RecaptchaGridState) -> None:
        if self.output_root is None:
            return
        self.output_root.mkdir(parents=True, exist_ok=True)
        digest = state.observation.metadata["image_sha256"]
        stem = f"recaptcha-session-{self._sequence:02d}-{digest[:16]}"
        (self.output_root / f"{stem}.png").write_bytes(state.screenshot)
        (self.output_root / f"{stem}.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "observation": state.observation.to_dict(),
                    "vision_task": {
                        "kind": state.task.kind,
                        "prompt": state.task.prompt,
                        "width": state.task.width,
                        "height": state.task.height,
                        "candidate_count": state.task.candidate_count,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )


async def _solve_recaptcha_session(
    page: Any,
    backend: VisionBackend,
    *,
    diagnostics: dict[str, Any],
    network_events: list[dict[str, Any]],
    output_dir: str | None,
    min_confidence: float,
    retries: int,
    max_rounds: int,
    timeout_sec: float,
    refresh_wait_ms: int = 8000,
) -> str:
    """Run the provider-neutral loop and retain its trace in provider output."""

    from ..harness.agent import ChallengeAgentLoop, VisionChallengePolicy

    session = RecaptchaChallengeSession(
        page,
        diagnostics=diagnostics,
        output_dir=output_dir,
        max_rounds=max(1, max_rounds),
        refresh_wait_ms=refresh_wait_ms,
        verification_wait_ms=min(3000, max(0, int(timeout_sec * 1000))),
        network_events=network_events,
    )
    result = await ChallengeAgentLoop(
        session,
        VisionChallengePolicy(
            backend,
            solve_policy=VisionSolvePolicy(
                min_confidence=min_confidence,
                retries=max(1, retries),
                require_confidence=True,
                allow_uncertain=True,
            ),
        ),
        max_steps=max(4, max_rounds * 2 + 2),
        timeout_sec=max(0.1, timeout_sec),
    ).run()

    for key, value in result.diagnostics.items():
        # This adapter passes the outer diagnostics mapping directly to the
        # session, so the generic session snapshot would only duplicate the
        # complete provider trace under diagnostics.session.
        if key == "session":
            continue
        if isinstance(value, list):
            diagnostics.setdefault(key, []).extend(value)
        elif key not in diagnostics:
            diagnostics[key] = value
    diagnostics.setdefault("recaptcha_agent_runs", []).append(
        {
            "status": result.status,
            "accepted": result.accepted,
            "steps": result.steps,
            "elapsed_ms": result.elapsed_ms,
            "errors": list(result.errors),
            "verification": result.verification.to_dict(),
        }
    )
    if result.accepted:
        return "verified"
    if result.status == "unsupported":
        return "unsupported"
    if diagnostics.get("recaptcha_max_rounds_exhausted"):
        return "max_rounds_exhausted"
    if result.status == "timeout":
        return "timeout"
    if session.submitted:
        return "submitted"
    return "failed"


async def _solve_recaptcha_grid(
    page: Any,
    backend: VisionBackend,
    *,
    diagnostics: dict[str, Any],
    output_dir: str | None,
    min_confidence: float,
    retries: int,
    max_rounds: int,
    refresh_wait_ms: int = 8000,
) -> str:
    """Solve one Google image challenge without treating a click as verification."""

    frame = await _recaptcha_challenge_frame(page)
    if frame is None:
        return "no_challenge"
    dynamic = False
    engine = diagnostics.setdefault("challenge_engine", {})
    engine.setdefault("engine", "recaptcha-open-vocabulary-vision")
    engine.setdefault("vision_tasks", [])
    replay_root = Path(output_dir).expanduser().resolve() / "vision-replay" if output_dir else None

    for round_index in range(1, max(1, max_rounds) + 1):
        frame = await _recaptcha_challenge_frame(page)
        if frame is None:
            return "no_challenge"
        target = frame.locator("#rc-imageselect-target")
        await target.wait_for(state="visible", timeout=5000)
        await _wait_for_recaptcha_grid_ready(
            page,
            frame,
            require_unselected=True,
        )
        prompt = await _recaptcha_prompt(frame)
        dynamic = dynamic or "once there are none left" in prompt.casefold()
        tiles = frame.locator("#rc-imageselect-target .rc-imageselect-tile")
        candidate_count = await tiles.count()
        if candidate_count < 1:
            return "unsupported"
        screenshot = await _screenshot_recaptcha_target(page, target)
        from PIL import Image

        with Image.open(BytesIO(screenshot)) as image:
            width, height = image.size
        task = VisionTask(
            kind="binary",
            prompt=prompt,
            images=(VisionImage(screenshot, label="recaptcha-grid.png"),),
            width=width,
            height=height,
            min_answers=0,
            max_answers=candidate_count,
            candidate_count=candidate_count,
            metadata={"provider": "recaptcha", "round": round_index},
        )
        observation = _grid_observation(
            provider="recaptcha",
            prompt=prompt,
            candidate_count=candidate_count,
            dynamic=dynamic,
            screenshot=screenshot,
            sequence=round_index,
            metadata={"round": round_index},
        )
        _record_challenge_observation(diagnostics, observation)
        outcome = await solve_vision_task(
            backend,
            task,
            policy=VisionSolvePolicy(
                min_confidence=min_confidence,
                retries=max(1, retries),
                require_confidence=True,
                allow_uncertain=True,
            ),
            diagnostics=diagnostics,
        )
        answer = outcome.answer
        inference_uncertain = outcome.uncertain

        summary = _vision_answer_summary(answer)
        summary.update(
            {
                "request_type": "recaptcha_image_grid",
                "prompt": prompt,
                "round": round_index,
                "candidate_count": candidate_count,
            }
        )
        engine["vision_tasks"].append(summary)
        if replay_root is not None:
            replay_root.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(screenshot).hexdigest()
            stem = f"recaptcha-{round_index:02d}-{digest[:16]}"
            (replay_root / f"{stem}.png").write_bytes(screenshot)
            (replay_root / f"{stem}.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "binary",
                        "prompt": prompt,
                        "width": width,
                        "height": height,
                        "candidate_count": candidate_count,
                        "answer": summary,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

        select_action = action_from_vision(observation, answer)
        selected = list(select_action.payload["selected"])
        round_record = {
            "round": round_index,
            "prompt": prompt,
            "candidate_count": candidate_count,
            "selected_count": len(selected) if not inference_uncertain else 0,
            "dynamic": dynamic,
        }
        diagnostics.setdefault("recaptcha_rounds", []).append(round_record)
        if inference_uncertain:
            reload_validation = _validate_challenge_action(
                diagnostics,
                observation,
                ChallengeAction(
                    observation_id=observation.observation_id,
                    kind="reload",
                    uncertain=True,
                    rationale="vision answer below confidence threshold",
                ),
            )
            round_record.update(
                {
                    "uncertain": True,
                    "proposed_selected_count": len(selected),
                    "action": "refresh",
                }
            )
            before_signature = await _recaptcha_tile_image_signature(frame)
            try:
                await _refresh_recaptcha_challenge(
                    page,
                    frame,
                    previous_signature=before_signature,
                    timeout_sec=max(0.25, refresh_wait_ms / 1000),
                )
                _mark_challenge_action_executed(diagnostics, reload_validation)
                round_record["refresh_observed"] = True
                diagnostics["recaptcha_uncertain_refreshes"] = (
                    int(diagnostics.get("recaptcha_uncertain_refreshes", 0)) + 1
                )
                return "refreshed"
            except VisionBackendError as exc:
                round_record["refresh_observed"] = False
                diagnostics.setdefault("recaptcha_refresh_errors", []).append(
                    f"{type(exc).__name__}: {exc}"
                )
                return "refresh_timeout"
        if not selected:
            submit_validation = _validate_challenge_action(
                diagnostics,
                observation,
                ChallengeAction(
                    observation_id=observation.observation_id,
                    kind="submit",
                ),
            )
            if not submit_validation.valid:
                return "unsupported"
            round_record["action"] = await _click_recaptcha_action(
                page,
                frame,
                expect_verify=dynamic,
            )
            _mark_challenge_action_executed(diagnostics, submit_validation)
            return "submitted" if dynamic else "skipped"

        before_signature = await _recaptcha_tile_image_signature(frame)
        select_validation = _validate_challenge_action(
            diagnostics, observation, select_action
        )
        if not select_validation.valid:
            return "unsupported"
        for index in selected:
            await tiles.nth(index).click(timeout=1500, delay=100)
            await page.wait_for_timeout(120)
        _mark_challenge_action_executed(diagnostics, select_validation)
        if not dynamic:
            submit_validation = _validate_challenge_action(
                diagnostics,
                observation,
                ChallengeAction(observation_id=observation.observation_id, kind="submit"),
            )
            if not submit_validation.valid:
                return "unsupported"
            round_record["action"] = await _click_recaptcha_action(
                page,
                frame,
                expect_verify=True,
            )
            _mark_challenge_action_executed(diagnostics, submit_validation)
            return "submitted"

        try:
            await _wait_for_recaptcha_grid_ready(
                page,
                frame,
                require_unselected=True,
                previous_signature=before_signature,
                timeout_sec=max(0.25, refresh_wait_ms / 1000),
            )
            round_record["refresh_observed"] = True
        except VisionBackendError:
            round_record["refresh_observed"] = False
            return "refresh_timeout"
    diagnostics["recaptcha_max_rounds_exhausted"] = True
    return "max_rounds_exhausted"


def _frame_diagnostics(page: Any, provider: str | None) -> dict[str, Any]:
    urls = [frame.url for frame in page.frames if frame.url]
    providers = (provider,) if provider else tuple(WIDGET_HOST_MARKERS)
    kinds = [
        kind
        for url in urls
        for provider_name in providers
        if (kind := _frame_kind(url, provider_name))
    ]
    return {
        "frame_count": len(urls),
        "widget_frames": len(kinds),
        "frame_kinds": sorted(set(kinds)),
        "challenge_visible": any("bframe" in url or "challenge" in url for url in urls),
    }


def _prepare_hcaptcha_agent(
    page: Any,
    *,
    proxy: Any = None,
    cache_dir: str | None = None,
    tmp_dir: str | None = None,
    trace_diagnostics: dict[str, Any] | None = None,
    vision_backend: VisionBackend | None = None,
    vision_min_confidence: float = 0.35,
    vision_retries: int = 2,
) -> tuple[Any, Any, Any, dict[str, Any]]:
    """Load the last local-ONNX hcaptcha-challenger engine without CLIP models."""

    import requests
    from hcaptcha_challenger.agents.playwright.control import AgentT
    from hcaptcha_challenger.onnx.modelhub import ModelHub, ReleaseAsset

    cache_root = Path(cache_dir or Path.home() / ".cache" / "antibot" / "hcaptcha").resolve()
    assets_dir = cache_root / "_assets"
    memory_dir = cache_root / "_memory"
    for path in (cache_root, assets_dir, memory_dir):
        path.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.trust_env = False
    if proxy is not None:
        session.proxies.update({"http": proxy.url, "https": proxy.url})

    def download(url: str, destination: Path, *, expected_size: int | None = None) -> None:
        temporary = destination.with_suffix(destination.suffix + ".part")
        with session.get(url, timeout=(15, 180), stream=True) as response:
            response.raise_for_status()
            with temporary.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        output.write(chunk)
        if expected_size is not None and temporary.stat().st_size != expected_size:
            raise RuntimeError(
                f"incomplete hCaptcha model download: expected {expected_size} bytes, "
                f"received {temporary.stat().st_size}"
            )
        temporary.replace(destination)

    objects_path = cache_root / "objects.yaml"
    if not objects_path.is_file():
        download(HCAPTCHA_OBJECTS_URL, objects_path)
    release_path = cache_root / "model-release.json"
    if not release_path.is_file():
        download(HCAPTCHA_MODEL_RELEASE_URL, release_path)
    release = json.loads(release_path.read_text(encoding="utf-8"))

    modelhub = ModelHub.from_github_repo(lang="en")
    modelhub.models_dir = cache_root
    modelhub.assets_dir = assets_dir
    modelhub.objects_path = objects_path
    modelhub.assets._assets_dir = assets_dir
    modelhub.assets._memory_dir = memory_dir
    modelhub.assets._name2asset = {
        item["name"]: ReleaseAsset(
            id=item["id"],
            node_id=item["node_id"],
            name=item["name"],
            size=item["size"],
            browser_download_url=item["browser_download_url"],
        )
        for item in release.get("assets", [])
    }
    modelhub.parse_objects()

    def pull_model(instance: Any, focus_name: str) -> None:
        asset = instance.assets.get_focus_asset(focus_name)
        if asset is None:
            return
        model_path = instance.models_dir / focus_name
        if not model_path.is_file() or model_path.stat().st_size != asset.size:
            download(asset.browser_download_url, model_path, expected_size=asset.size)
            instance.assets.archive_memory(focus_name, asset.node_id)

    modelhub.pull_model = MethodType(pull_model, modelhub)
    temporary_workspace = None
    if tmp_dir:
        agent_tmp = Path(tmp_dir).resolve()
    else:
        temporary_workspace = tempfile.TemporaryDirectory(prefix="antibot-hcaptcha-")
        agent_tmp = Path(temporary_workspace.name)
    agent = AgentT.from_page(
        page,
        tmp_dir=agent_tmp,
        modelhub=modelhub,
        self_supervised=False,
    )
    tree_classifier = _TreeClimbingAnimalClassifier(cache_root, download)
    tree_detections: list[dict[str, Any]] = []
    trace = trace_diagnostics
    original_default_challenge = agent._keypoint_default_challenge

    async def solve_default_challenge(instance: Any, frame_challenge: Any) -> None:
        if _hcaptcha_prompt_label(instance.prompt) != "tree_climbing_animals":
            await original_default_challenge(frame_challenge)
            return

        max_points = instance.qr.request_config.get("max_shapes_per_image", 5)
        if not isinstance(max_points, int):
            max_points = 5
        for task_index in range(len(instance.qr.tasklist)):
            canvas = frame_challenge.locator("//div[@class='challenge-view']//canvas")
            await canvas.wait_for(state="visible")
            await page.wait_for_timeout(500)
            screenshot = await canvas.screenshot(type="png")
            detections = await asyncio.to_thread(
                tree_classifier.detect,
                screenshot,
                max_points=max_points,
            )
            if not detections:
                raise RuntimeError("tree-climbing animal classifier found no targets")

            from PIL import Image

            screenshot_size = Image.open(BytesIO(screenshot)).size
            observation = _visual_observation(
                provider="hcaptcha",
                prompt=instance.prompt,
                kind="point",
                screenshot=screenshot,
                sequence=(
                    len(trace.get("challenge_observations", [])) + 1
                    if trace is not None
                    else task_index + 1
                ),
                width=screenshot_size[0],
                height=screenshot_size[1],
                min_answers=1,
                max_answers=max_points,
                metadata={
                    "request_type": str(instance.qr.request_type),
                    "shape_type": instance.qr.request_config.get("shape_type"),
                    "source": "local_onnx_classifier",
                    "task_index": task_index,
                },
            )
            action = ChallengeAction(
                observation_id=observation.observation_id,
                kind="point",
                payload={
                    "points": [
                        {"x": item["x"], "y": item["y"]} for item in detections
                    ]
                },
            )
            if trace is not None:
                _record_challenge_observation(trace, observation)
                validation = _validate_challenge_action(trace, observation, action)
                if not validation.valid:
                    raise VisionBackendError(
                        "tree classifier action failed observation validation: "
                        + ", ".join(validation.errors)
                    )
            box = await canvas.bounding_box()
            scale_x = float(box["width"]) / screenshot_size[0] if box else 1
            scale_y = float(box["height"]) / screenshot_size[1] if box else 1
            task_diagnostics = {
                "task_index": task_index,
                "detections": [
                    {
                        "x": item["x"],
                        "y": item["y"],
                        "label": item["label"],
                        "margin": round(item["margin"], 3),
                    }
                    for item in detections
                ],
            }
            tree_detections.append(task_diagnostics)
            for detection in detections:
                await canvas.click(
                    delay=160,
                    position={
                        "x": detection["x"] * scale_x,
                        "y": detection["y"] * scale_y,
                    },
                )
            if trace is not None:
                _mark_challenge_action_executed(trace, validation)
            submit = frame_challenge.locator("//div[@class='button-submit button']")
            if await submit.count():
                if trace is not None:
                    submit_action = ChallengeAction(
                        observation_id=observation.observation_id,
                        kind="submit",
                    )
                    submit_validation = _validate_challenge_action(
                        trace, observation, submit_action
                    )
                    if not submit_validation.valid:
                        raise VisionBackendError(
                            "tree classifier submit failed observation validation: "
                            + ", ".join(submit_validation.errors)
                        )
                await submit.click(delay=200)
                if trace is not None:
                    _mark_challenge_action_executed(trace, submit_validation)
            if task_index == 0:
                await page.wait_for_timeout(1000)

    agent._keypoint_default_challenge = MethodType(solve_default_challenge, agent)
    try:
        engine_version = version("hcaptcha-challenger")
    except PackageNotFoundError:
        engine_version = "unknown"
    engine_diagnostics = {
        "engine": "hcaptcha-challenger-local-onnx",
        "engine_version": engine_version,
        "model_cache": str(cache_root),
        "model_count": len(modelhub.assets._name2asset),
        "tree_climber_classifier": "mobilenetv2-imagenet",
        "tree_climber_detections": tree_detections,
    }
    if vision_backend is not None:
        _install_hcaptcha_vision_solver(
            agent,
            vision_backend,
            diagnostics=engine_diagnostics,
            trace_diagnostics=trace_diagnostics,
            min_confidence=vision_min_confidence,
            retries=vision_retries,
        )
        engine_diagnostics["engine"] = "hcaptcha-open-vocabulary-vision"
        engine_diagnostics["fallback_engine"] = "hcaptcha-challenger-local-onnx"
    return agent, session, temporary_workspace, engine_diagnostics


def _install_hcaptcha_response_listener(
    page: Any,
    agent: Any,
    *,
    diagnostics: dict[str, Any],
    raw: dict[str, Any],
) -> tuple[set[asyncio.Task[Any]], Any, list[str]]:
    """Feed only completed hCaptcha JSON API responses into the legacy agent queues."""

    from hcaptcha_challenger.components.middleware import ChallengeResp, QuestionResp
    import msgpack

    try:
        page.remove_listener("response", agent.handler)
    except Exception:
        pass

    tasks: set[asyncio.Task[Any]] = set()
    verified_tokens: list[str] = []

    async def consume_response(response: Any) -> None:
        url = str(getattr(response, "url", ""))
        if url.endswith("/hsw.js"):
            try:
                hsw_source = await response.text()
                await page.evaluate(hsw_source)
                diagnostics["hcaptcha_hsw_ready"] = bool(
                    await page.evaluate("() => typeof hsw === 'function'")
                )
            except Exception as exc:
                diagnostics["hcaptcha_hsw_ready"] = False
                diagnostics.setdefault("hcaptcha_response_errors", []).append(
                    f"hsw bootstrap failed: {type(exc).__name__}: {exc}"
                )
            return

        is_question = url.startswith("https://api.hcaptcha.com/getcaptcha/")
        is_answer = url.startswith("https://api.hcaptcha.com/checkcaptcha/")
        if not is_question and not is_answer:
            return

        request = getattr(response, "request", None)
        method = str(getattr(request, "method", "")).upper()
        if method != "POST":
            return

        try:
            headers = getattr(response, "headers", {}) or {}
            content_type = str(headers.get("content-type", "")).lower()
            if "json" in content_type:
                body = await response.body()
                data = json.loads(body.decode("utf-8"))
            elif is_question and "application/octet-stream" in content_type:
                body = await response.body()
                decoded = await page.evaluate(
                    """async (values) => {
                      if (typeof hsw !== 'function') throw new Error('hsw is not initialized');
                      return Array.from(await hsw(0, new Uint8Array(values)));
                    }""",
                    list(body),
                )
                data = msgpack.unpackb(bytes(decoded), raw=False)
                diagnostics["hcaptcha_payload_encoding"] = "hsw-msgpack"
            else:
                return
            if not isinstance(data, dict):
                raise TypeError("hCaptcha API response is not a JSON object")

            if is_question:
                question = QuestionResp(**data)
                agent.qr_queue.put_nowait(question)
                original_answer_labels = list(question.requester_restricted_answer_set)
                prompt = question.requester_question.get("en", "")
                model_label_hint = None
                if original_answer_labels == ["default"]:
                    model_label_hint = _hcaptcha_prompt_label(prompt)
                shape_type = question.request_config.get("shape_type")
                request_type = str(question.request_type)
                try:
                    observation = _hcaptcha_question_observation(
                        question,
                        sequence=(
                            len(diagnostics.get("challenge_observations", [])) + 1
                        ),
                    )
                    _record_challenge_observation(diagnostics, observation)
                except Exception as exc:
                    diagnostics.setdefault("challenge_observation_errors", []).append(
                        f"{type(exc).__name__}: {exc}"
                    )
                diagnostics.setdefault("hcaptcha_challenges", []).append(
                    {
                        "request_type": request_type,
                        "shape_type": shape_type,
                        "prompt": prompt[:300],
                        "task_count": len(question.tasklist),
                        "restricted_answer_labels": original_answer_labels[:20],
                        "model_label_hint": model_label_hint,
                    }
                )
                if data.get("pass"):
                    agent.cr_queue.put_nowait(ChallengeResp(**data))
            else:
                challenge = ChallengeResp(**data)
                if verified_token := _hcaptcha_verified_token(challenge):
                    verified_tokens.append(verified_token)
                agent.cr_queue.put_nowait(challenge)
                diagnostics.setdefault("hcaptcha_verification_responses", []).append(
                    {
                        "pass": challenge.is_pass,
                        "error": challenge.error or None,
                        "token_len": len(challenge.generated_pass_UUID or ""),
                    }
                )
        except Exception as exc:
            event = {
                "kind": "hcaptcha_response_error",
                "url": url[:500],
                "error": f"{type(exc).__name__}: {exc}",
            }
            raw.setdefault("events", []).append(event)
            diagnostics.setdefault("hcaptcha_response_errors", []).append(event["error"])

    def schedule_response(response: Any) -> None:
        task = asyncio.create_task(consume_response(response))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    page.on("response", schedule_response)
    return tasks, schedule_response, verified_tokens


class CaptchaWidgetSolver:
    """Browser-flow adapter for Google reCAPTCHA and hCaptcha widgets.

    The provider captures callback/hidden-field tokens and handles hCaptcha image
    challenges when the optional local ONNX engine is installed. Unsupported challenge
    types remain explicit failures unless a vendor-generated token is captured.
    """

    async def solve(
        self,
        *,
        target_url: str,
        provider: str = "auto",
        headless: bool | str | None = True,
        browser_binary: str | None = None,
        proxy_server: str | None = None,
        use_env_proxy: bool | None = None,
        timeout_sec: int = 90,
        wait_after_load_ms: int = 1500,
        click_selectors: list[str] | None = None,
        auto_click: bool = True,
        screenshot: str | None = None,
        html_output: str | None = None,
        output_json: str | None = None,
        output_dir: str | None = None,
        user_agent: str | None = None,
        locale: str | None = None,
        timezone_id: str | None = None,
        proxy_bypass: str | None = "127.0.0.1,localhost",
        solve_challenge: bool = True,
        recaptcha_max_attempts: int = 6,
        recaptcha_max_rounds: int = 8,
        hcaptcha_max_attempts: int = 6,
        hcaptcha_model_cache: str | None = None,
        vision_backend: VisionBackend | None = None,
        vision_base_url: str | None = None,
        vision_api_key: str | None = None,
        vision_api_key_env: str | None = "ANTIBOT_VISION_API_KEY",
        vision_model: str | None = None,
        vision_timeout_sec: float = 180,
        vision_min_confidence: float = 0.35,
        vision_retries: int = 2,
        vision_extra_body: dict[str, Any] | None = None,
        submit_selector: str | None = None,
        success_selectors: list[str] | None = None,
        success_text: str | None = None,
        verification_wait_ms: int = 3000,
    ) -> CaptchaResult:
        if not isinstance(target_url, str) or not target_url.strip():
            return CaptchaResult(
                provider=normalize_widget_provider(provider) or "unknown",
                ok=False,
                captcha_type=None,
                capability="browser_flow",
                errors=["target_url must be a non-empty string"],
            )
        started = time.monotonic()
        requested = normalize_widget_provider(provider)
        selected = detect_widget_provider(target_url) if requested == "auto" else requested
        diagnostics: dict[str, Any] = {
            "target_url": target_url,
            "requested_provider": requested,
            "provider": selected,
            "proxy": redacted_proxy(proxy_server),
        }
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        raw: dict[str, Any] = {"provider": selected, "events": []}
        token: str | None = None
        page: Any = None
        context: Any = None
        browser: Any = None
        playwright: Any = None
        hcaptcha_agent: Any = None
        hcaptcha_session: Any = None
        hcaptcha_workspace: Any = None
        hcaptcha_response_tasks: set[asyncio.Task[Any]] = set()
        hcaptcha_response_listener: Any = None
        hcaptcha_verified_tokens: list[str] = []
        hcaptcha_engine_error: str | None = None
        recaptcha_engine_error: str | None = None
        site_verified: bool | None = None
        resolved_vision_backend: VisionBackend | None = None

        if requested != "auto" and selected not in WIDGET_HOST_MARKERS:
            return CaptchaResult(
                provider=selected or "unknown",
                ok=False,
                captcha_type=None,
                capability="browser_flow",
                diagnostics=diagnostics,
                errors=["unsupported_widget_provider: expected recaptcha or hcaptcha"],
            )
        try:
            from playwright.async_api import async_playwright

            resolved_proxy = resolve_runtime_proxy(proxy_server, use_env=use_env_proxy)
            if resolved_proxy:
                diagnostics["proxy"] = resolved_proxy.redacted_url
            playwright = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {
                "headless": _headless(headless),
                "env": proxy_free_environment(),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                ],
            }
            executable = _discover_browser(browser_binary)
            if executable:
                launch_kwargs["executable_path"] = executable
            if resolved_proxy:
                proxy_kwargs = resolved_proxy.playwright()
                if proxy_bypass:
                    proxy_kwargs["bypass"] = proxy_bypass
                launch_kwargs["proxy"] = proxy_kwargs
            browser = await playwright.chromium.launch(**launch_kwargs)
            diagnostics["browser_binary"] = executable
            diagnostics["timeout_sec"] = max(1, int(timeout_sec))
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if user_agent:
                context_kwargs["user_agent"] = user_agent
            if locale:
                context_kwargs["locale"] = locale
            if timezone_id:
                context_kwargs["timezone_id"] = timezone_id
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.add_init_script(WIDGET_HOOK_JS)

            if selected == "recaptcha" and solve_challenge:
                try:
                    resolved_vision_backend = _resolve_vision_backend(
                        vision_backend,
                        base_url=vision_base_url,
                        api_key=vision_api_key,
                        api_key_env=vision_api_key_env,
                        model=vision_model,
                        timeout_sec=vision_timeout_sec,
                        extra_body=vision_extra_body,
                    )
                    diagnostics["vision_backend_configured"] = bool(
                        resolved_vision_backend
                    )
                    if resolved_vision_backend is not None:
                        diagnostics["challenge_engine"] = {
                            "engine": "recaptcha-open-vocabulary-vision",
                            "supported_tasks": ["image_grid", "dynamic_image_grid"],
                            "minimum_confidence": vision_min_confidence,
                            "inference_attempts": max(1, vision_retries),
                            "vision_tasks": [],
                        }
                except Exception as exc:
                    recaptcha_engine_error = f"{type(exc).__name__}: {exc}"
                    diagnostics["challenge_engine"] = {
                        "engine": "recaptcha-open-vocabulary-vision",
                        "ready": False,
                        "error": recaptcha_engine_error,
                    }

            if selected == "hcaptcha" and solve_challenge:
                try:
                    resolved_vision_backend = _resolve_vision_backend(
                        vision_backend,
                        base_url=vision_base_url,
                        api_key=vision_api_key,
                        api_key_env=vision_api_key_env,
                        model=vision_model,
                        timeout_sec=vision_timeout_sec,
                        extra_body=vision_extra_body,
                    )
                    diagnostics["vision_backend_configured"] = bool(resolved_vision_backend)
                    (
                        hcaptcha_agent,
                        hcaptcha_session,
                        hcaptcha_workspace,
                        engine_diagnostics,
                    ) = (
                        _prepare_hcaptcha_agent(
                            page,
                            proxy=resolved_proxy,
                            cache_dir=hcaptcha_model_cache,
                            tmp_dir=output_dir,
                            trace_diagnostics=diagnostics,
                            vision_backend=resolved_vision_backend,
                            vision_min_confidence=vision_min_confidence,
                            vision_retries=vision_retries,
                        )
                    )
                    diagnostics["challenge_engine"] = engine_diagnostics
                    (
                        hcaptcha_response_tasks,
                        hcaptcha_response_listener,
                        hcaptcha_verified_tokens,
                    ) = _install_hcaptcha_response_listener(
                        page,
                        hcaptcha_agent,
                        diagnostics=diagnostics,
                        raw=raw,
                    )
                except Exception as exc:
                    hcaptcha_engine_error = f"{type(exc).__name__}: {exc}"
                    diagnostics["challenge_engine"] = {
                        "engine": "hcaptcha-challenger-local-onnx",
                        "ready": False,
                        "error": hcaptcha_engine_error,
                    }

            def capture_response(response: Any) -> None:
                url = str(getattr(response, "url", ""))
                providers = (selected,) if selected else tuple(WIDGET_HOST_MARKERS)
                if any(
                    marker in url.lower()
                    for provider_name in providers
                    for marker in WIDGET_HOST_MARKERS[provider_name]
                ):
                    raw["events"].append(
                        {"kind": "response", "url": url[:500], "status": getattr(response, "status", None)}
                    )
                    if len(raw["events"]) > 200:
                        del raw["events"][:-200]

            page.on("response", capture_response)
            deadline = time.monotonic() + max(1, int(timeout_sec))
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            await page.goto(target_url, wait_until="domcontentloaded", timeout=remaining_ms)
            remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
            if remaining_ms:
                await page.wait_for_timeout(min(max(0, wait_after_load_ms), remaining_ms))
            if auto_click:
                for selector in click_selectors or []:
                    try:
                        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                        await page.locator(selector).first.click(timeout=min(1200, remaining_ms))
                    except Exception:
                        continue

            if selected is None:
                selected = await _detect_widget_provider(page)
                diagnostics["provider"] = selected
                raw["provider"] = selected
            if selected is None:
                errors.append("widget_provider_not_detected")
            checkbox_clicked = False
            hcaptcha_attempts = 0
            recaptcha_attempts = 0
            while time.monotonic() < deadline:
                if selected is None:
                    break
                tokens = await _collect_tokens(page, selected)
                token = _select_widget_token(selected, tokens, hcaptcha_verified_tokens)
                if token:
                    break
                if auto_click and not checkbox_clicked:
                    checkbox_clicked = await _click_checkbox(page, selected)
                    if checkbox_clicked:
                        diagnostics["checkbox_clicked"] = True
                if (
                    selected == "hcaptcha"
                    and hcaptcha_agent is not None
                    and hcaptcha_attempts < max(1, hcaptcha_max_attempts)
                    and _frame_diagnostics(page, selected)["challenge_visible"]
                ):
                    hcaptcha_attempts += 1
                    try:
                        remaining = max(0.1, deadline - time.monotonic())
                        status = await asyncio.wait_for(
                            hcaptcha_agent.execute(),
                            timeout=remaining,
                        )
                        status_value = getattr(status, "value", str(status))
                        diagnostics.setdefault("hcaptcha_statuses", []).append(status_value)
                        token = _select_widget_token(
                            selected,
                            [],
                            hcaptcha_verified_tokens,
                        )
                        if token:
                            break
                        if status_value == "backcall":
                            break
                        if hcaptcha_attempts >= max(1, hcaptcha_max_attempts):
                            diagnostics["hcaptcha_attempts_exhausted"] = True
                            break
                    except Exception as exc:
                        diagnostics.setdefault("hcaptcha_engine_errors", []).append(
                            f"{type(exc).__name__}: {exc}"
                        )
                        break
                recaptcha_frame = (
                    await _recaptcha_challenge_frame(page)
                    if selected == "recaptcha" and solve_challenge
                    else None
                )
                if recaptcha_frame is not None:
                    if recaptcha_engine_error or resolved_vision_backend is None:
                        break
                    if recaptcha_attempts >= max(1, recaptcha_max_attempts):
                        diagnostics["recaptcha_attempts_exhausted"] = True
                        break
                    recaptcha_attempts += 1
                    try:
                        remaining = max(0.1, deadline - time.monotonic())
                        status_value = await asyncio.wait_for(
                            _solve_recaptcha_session(
                                page,
                                resolved_vision_backend,
                                diagnostics=diagnostics,
                                network_events=raw["events"],
                                output_dir=output_dir,
                                min_confidence=vision_min_confidence,
                                retries=vision_retries,
                                max_rounds=recaptcha_max_rounds,
                                timeout_sec=remaining,
                            ),
                            timeout=remaining,
                        )
                        diagnostics.setdefault("recaptcha_statuses", []).append(
                            status_value
                        )
                        if status_value in {
                            "unsupported",
                            "vision_failed",
                            "refresh_timeout",
                            "max_rounds_exhausted",
                            "timeout",
                            "failed",
                        }:
                            break
                        remaining_ms = max(
                            0, int((deadline - time.monotonic()) * 1000)
                        )
                        if remaining_ms:
                            await page.wait_for_timeout(min(1000, remaining_ms))
                    except Exception as exc:
                        diagnostics.setdefault("recaptcha_engine_errors", []).append(
                            f"{type(exc).__name__}: {exc}"
                        )
                        break
                await asyncio.sleep(min(0.25, max(0.01, deadline - time.monotonic())))

            if token and (submit_selector or success_selectors or success_text):
                verification: dict[str, Any] = {
                    "submit_selector": submit_selector,
                    "submit_clicked": False,
                    "matched_selectors": [],
                    "matched_text": False,
                }
                if submit_selector:
                    try:
                        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                        await page.locator(submit_selector).first.click(
                            timeout=min(3000, remaining_ms)
                        )
                        verification["submit_clicked"] = True
                    except Exception as exc:
                        verification["submit_error"] = f"{type(exc).__name__}: {exc}"
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                if remaining_ms:
                    await page.wait_for_timeout(
                        min(max(0, verification_wait_ms), remaining_ms)
                    )

                for selector in success_selectors or []:
                    try:
                        locator = page.locator(selector).first
                        if await locator.count() and await locator.is_visible(timeout=300):
                            verification["matched_selectors"].append(selector)
                            text_content = (await locator.text_content(timeout=300) or "").strip()
                            if text_content:
                                verification.setdefault("selector_text", {})[selector] = text_content[:500]
                    except Exception:
                        continue
                if success_text:
                    try:
                        body_text = await page.locator("body").inner_text(timeout=1000)
                        verification["matched_text"] = success_text in body_text
                    except Exception:
                        pass
                has_success_assertion = bool(success_selectors or success_text)
                if has_success_assertion:
                    submit_ok = not submit_selector or verification["submit_clicked"]
                    selectors_ok = not success_selectors or bool(
                        verification["matched_selectors"]
                    )
                    text_ok = not success_text or verification["matched_text"]
                    site_verified = bool(submit_ok and selectors_ok and text_ok)
                    verification["ok"] = site_verified
                    if not site_verified:
                        errors.append("site_verification_not_observed")
                diagnostics["site_verification"] = verification

            diagnostics.update(_frame_diagnostics(page, selected))
            diagnostics["checkbox_clicked"] = checkbox_clicked
            if selected == "hcaptcha":
                diagnostics["hcaptcha_attempts"] = hcaptcha_attempts
            elif selected == "recaptcha":
                diagnostics["recaptcha_attempts"] = recaptcha_attempts
            if selected and not token:
                if diagnostics.get("challenge_visible"):
                    if selected == "recaptcha" and recaptcha_engine_error:
                        errors.append(
                            "recaptcha_challenge_engine_unavailable: "
                            + recaptcha_engine_error
                        )
                    elif selected == "recaptcha" and resolved_vision_backend is None:
                        errors.append("recaptcha_challenge_engine_unavailable")
                    elif selected == "recaptcha" and diagnostics.get(
                        "recaptcha_engine_errors"
                    ):
                        errors.append("recaptcha_challenge_engine_failed")
                    elif hcaptcha_engine_error:
                        errors.append(f"hcaptcha_challenge_engine_unavailable: {hcaptcha_engine_error}")
                    elif diagnostics.get("hcaptcha_engine_errors"):
                        errors.append("hcaptcha_challenge_engine_failed")
                    else:
                        errors.append("captcha_challenge_not_solved")
                else:
                    errors.append("captcha_token_not_found_before_timeout")
            final_url = page.url
            diagnostics["final_url"] = final_url
            diagnostics["title"] = await page.title()
            diagnostics["token_len"] = len(token or "")

            output_root = Path(output_dir).expanduser().resolve() if output_dir else None
            if output_root:
                output_root.mkdir(parents=True, exist_ok=True)

            def artifact_path(value: str) -> Path:
                path = Path(value).expanduser()
                if output_root and not path.is_absolute():
                    path = output_root / path
                return path.resolve()

            if screenshot:
                screenshot_path = artifact_path(screenshot)
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(screenshot_path), full_page=True)
                artifacts["screenshot"] = str(screenshot_path)
            if html_output:
                html_path = artifact_path(html_output)
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_path.write_text(await page.content(), encoding="utf-8")
                artifacts["html"] = str(html_path)
        except Exception as exc:
            errors.append(f"widget browser flow failed: {type(exc).__name__}: {exc}")
        finally:
            if page is not None and hcaptcha_response_listener is not None:
                try:
                    page.remove_listener("response", hcaptcha_response_listener)
                except Exception:
                    pass
            if hcaptcha_response_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tuple(hcaptcha_response_tasks), return_exceptions=True),
                        timeout=2,
                    )
                except Exception:
                    pass
            if hcaptcha_session is not None:
                try:
                    hcaptcha_session.close()
                except Exception:
                    pass
            for resource in (context, browser):
                if resource is not None:
                    try:
                        await resource.close()
                    except Exception:
                        pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except Exception:
                    pass
            if hcaptcha_workspace is not None:
                try:
                    hcaptcha_workspace.cleanup()
                except Exception:
                    pass

        captcha_type = selected
        if selected == "recaptcha":
            captcha_type = "recaptcha_v2" if "recaptcha_v2" in diagnostics.get("frame_kinds", []) else "recaptcha"
        raw["event_count"] = len(raw["events"])
        raw["token_len"] = len(token or "")
        result = CaptchaResult(
            provider=selected or "unknown",
            ok=bool(token) and site_verified is not False,
            captcha_type=captcha_type,
            capability="browser_flow",
            ticket=token,
            verify_code="token_captured" if token else None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            artifacts=artifacts,
            diagnostics=diagnostics,
            raw=raw,
            errors=errors,
        )
        if output_dir:
            output_path = Path(output_dir).expanduser().resolve()
            output_path.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_path)
        json_target = output_json
        if json_target is None and output_dir:
            json_target = str(Path(output_dir).expanduser().resolve() / "result.json")
        if json_target:
            json_path = Path(json_target).expanduser()
            if output_dir and not json_path.is_absolute():
                json_path = Path(output_dir).expanduser() / json_path
            json_path = json_path.resolve()
            json_path.parent.mkdir(parents=True, exist_ok=True)
            artifacts["output_json"] = str(json_path)
            # Keep browser results durable even when the process is stopped
            # during a long vision request. ``persist_result`` writes via a
            # same-directory temporary file and atomic replace.
            persist_result(result, json_path)
        return result


__all__ = [
    "CaptchaWidgetSolver",
    "RecaptchaChallengeSession",
    "CHECKBOX_SELECTORS",
    "TOKEN_SELECTORS",
    "WIDGET_HOOK_JS",
    "detect_widget_provider",
    "normalize_widget_provider",
]
