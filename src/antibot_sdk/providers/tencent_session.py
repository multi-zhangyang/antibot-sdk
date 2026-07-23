"""Tencent Captcha adapter for the provider-neutral challenge Harness.

The existing Tencent runner owns page bootstrap and browser pooling.  This
module extracts the live challenge episode into the shared session contract:
rendered observations, normalized actions, and a hard vendor verification
gate based on ``cap_union_new_verify``.  It supports both slider puzzles and
the word-click variant without teaching the Harness core Tencent selectors.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from PIL import Image

from ..harness.agent import ChallengeStrategyRegistry
from ..harness.contracts import ChallengeAction, ChallengeObservation, VendorVerification
from ..vision import VisionAnswer, VisionImage, VisionPoint, VisionTask
from ..vendor.tencent.solve_optimized import (
    BG_SELECTOR,
    RELOAD_SELECTOR,
    VERIFY_PATH,
    CaptchaFrame,
    RuntimeGeometry,
    _bg_url,
    _challenge_kind,
    _drag,
    _fetch_bg_bytes,
    _inject_xhr_hook,
    _install_verify_capture,
    _parse_word_click_targets,
    _read_verify,
    _resolve_captcha_frame,
    _runtime_geometry,
    _wait_frame,
    _word_click_instruction,
    detect_gap,
)

FrameReader = Callable[[], Awaitable[CaptchaFrame]]
KindReader = Callable[[Any], Awaitable[str]]
BackgroundReader = Callable[[Any], Awaitable[bytes]]
GapDetector = Callable[[bytes], tuple[int, float, str]]
GeometryReader = Callable[[CaptchaFrame, bytes, int], Awaitable[RuntimeGeometry]]
DragExecutor = Callable[[Any, RuntimeGeometry], Awaitable[None]]
VerifyReader = Callable[[Any, dict[str, Any]], Awaitable[dict[str, Any] | None]]
PointExecutor = Callable[[CaptchaFrame, bytes, tuple[tuple[float, float], ...]], Awaitable[None]]
ReloadExecutor = Callable[[CaptchaFrame], Awaitable[bool]]
FrameResolver = Callable[[], Awaitable[CaptchaFrame | None]]
InstructionReader = Callable[[Any], Awaitable[str]]


class TencentWordOCRBackend:
    """Adapt the proven Tencent Siamese OCR locator to the shared vision API."""

    def __init__(self, locator: Callable[[bytes, list[str]], Any] | None = None) -> None:
        self._locator = locator

    async def solve(self, task: VisionTask) -> VisionAnswer:
        if task.kind != "point" or not task.images:
            raise RuntimeError("Tencent word OCR backend requires one point image")
        targets = _parse_word_click_targets(task.prompt)
        if not targets:
            raise RuntimeError("Tencent word OCR prompt has no ordered targets")
        locator = self._locator
        if locator is None:
            from crack_tcaptcha.solvers.word_ocr import locate_chars_by_siamese

            locator = locate_chars_by_siamese
        points = await asyncio.to_thread(locator, task.images[0].data, targets)
        normalized = tuple(
            VisionPoint(float(point[0]), float(point[1]))
            for point in points
            if isinstance(point, (tuple, list)) and len(point) == 2
        )
        if len(normalized) != len(targets):
            raise RuntimeError(
                "Tencent word OCR returned an incomplete target set: "
                f"{len(normalized)} != {len(targets)}"
            )
        return VisionAnswer(
            kind="point",
            points=normalized,
            confidence=None,
            raw={"targets": targets, "points": [[p.x, p.y] for p in normalized]},
            diagnostics={
                "backend": "tencent_word_siamese",
                "target_count": len(targets),
                "confidence_source": "not_exposed_by_locator",
            },
        )


@dataclass(slots=True)
class _TencentScene:
    observation: ChallengeObservation
    task: VisionTask
    target: CaptchaFrame
    background: bytes
    image_width: int
    image_height: int
    fingerprint: str
    geometry: RuntimeGeometry | None = None


class TencentChallengeSession:
    """One live Tencent slider or word-click challenge episode.

    Page bootstrap remains outside this class because different Tencent sites
    expose different trigger buttons and appids.  Once the widget is visible,
    the session discovers the active main-frame/iframe template and drives the
    normalized loop.  ``accepted`` is only possible after Tencent returns
    ``errorCode=0`` together with a non-empty ticket.
    """

    def __init__(
        self,
        page: Any,
        *,
        diagnostics: dict[str, Any] | None = None,
        min_gap_confidence: float = 0.55,
        max_attempts: int = 3,
        verification_wait_ms: int = 5200,
        frame_reader: FrameReader | None = None,
        kind_reader: KindReader | None = None,
        background_reader: BackgroundReader | None = None,
        gap_detector: GapDetector | None = None,
        geometry_reader: GeometryReader | None = None,
        drag_executor: DragExecutor | None = None,
        verify_reader: VerifyReader | None = None,
        point_executor: PointExecutor | None = None,
        reload_executor: ReloadExecutor | None = None,
        frame_resolver: FrameResolver | None = None,
        instruction_reader: InstructionReader | None = None,
        verify_state: dict[str, Any] | None = None,
    ) -> None:
        if (
            isinstance(min_gap_confidence, bool)
            or not isinstance(min_gap_confidence, (int, float))
            or not math.isfinite(float(min_gap_confidence))
            or not 0 <= float(min_gap_confidence) <= 1
        ):
            raise ValueError("Tencent min_gap_confidence must be between 0 and 1")
        if max_attempts < 1:
            raise ValueError("Tencent max_attempts must be positive")
        if verification_wait_ms < 0:
            raise ValueError("Tencent verification_wait_ms must be non-negative")
        self.page = page
        self.provider = "tencent"
        self.diagnostics = diagnostics if diagnostics is not None else {}
        self.min_gap_confidence = float(min_gap_confidence)
        self.max_attempts = max_attempts
        self.verification_wait_sec = verification_wait_ms / 1000
        self._frame_reader = frame_reader or self._default_frame_reader
        self._kind_reader = kind_reader or _challenge_kind
        self._background_reader = background_reader or self._default_background_reader
        self._gap_detector = gap_detector or detect_gap
        self._geometry_reader = geometry_reader or _runtime_geometry
        self._drag_executor = drag_executor or _drag
        self._verify_reader = verify_reader or _read_verify
        self._point_executor = point_executor or self._execute_points
        self._reload_executor = reload_executor or self._reload
        self._frame_resolver = frame_resolver or (lambda: _resolve_captcha_frame(page))
        self._instruction_reader = instruction_reader or (
            lambda frame: _word_click_instruction(page, frame)
        )
        if verify_state is not None:
            self._verify_state = verify_state
        else:
            try:
                self._verify_state = _install_verify_capture(page)
            except Exception:
                # Unit fixtures and alternate browser wrappers may expose a
                # response stream through their own injected verify_reader.
                self._verify_state = {"res": None}
        self._sequence = 0
        self._attempts = 0
        self._pending_verification = False
        self._current: _TencentScene | None = None
        self._verification_response: dict[str, Any] | None = None
        self._last_fingerprint: str | None = None
        self._last_target: CaptchaFrame | None = None
        self.ticket: str | None = None
        self.randstr: str | None = None

    def strategy_registry(self) -> ChallengeStrategyRegistry:
        """Return the provider strategy needed for normalized slider actions."""

        strategies = ChallengeStrategyRegistry()
        strategies.register("slider", _tencent_slider_strategy)
        return strategies

    async def _default_frame_reader(self) -> CaptchaFrame:
        return await _wait_frame(self.page)

    async def _default_background_reader(self, frame: Any) -> bytes:
        url = await _bg_url(frame)
        return await _fetch_bg_bytes(frame, url)

    async def observe(self) -> ChallengeObservation | None:
        if self._pending_verification:
            await self._collect_verification()
            if self._vendor_passed() or self._attempts >= self.max_attempts:
                self._current = None
                return None

        target = await self._frame_reader()
        try:
            await _inject_xhr_hook(target.frame)
        except Exception as exc:
            self.diagnostics.setdefault("tencent_session_hook_errors", []).append(
                f"{type(exc).__name__}: {exc}"
            )
        kind = await self._kind_reader(target.frame)
        background = await self._background_reader(target.frame)
        with Image.open(BytesIO(background)) as image:
            image_width, image_height = image.size
        fingerprint = hashlib.sha256(background).hexdigest()
        dynamic = self._last_fingerprint not in {None, fingerprint}
        self._last_fingerprint = fingerprint
        self._sequence += 1
        metadata: dict[str, Any] = {
            "source": "rendered_tencent_widget",
            "image_sha256": fingerprint,
            "attempt": self._attempts + 1,
            "verify_path": VERIFY_PATH,
        }

        if kind == "slider":
            gap_x, confidence, method = self._gap_detector(background)
            if confidence < self.min_gap_confidence:
                raise RuntimeError(
                    "Tencent slider gap confidence below policy: "
                    f"{confidence:.4f} < {self.min_gap_confidence:.4f}"
                )
            geometry = await self._geometry_reader(target, background, gap_x)
            width, height = await self._slider_coordinate_bounds(geometry)
            metadata.update(
                {
                    "detector": method,
                    "detector_confidence": confidence,
                    "raw_image_width": geometry.raw_width,
                    "css_image_width": geometry.css_width,
                }
            )
            observation = self._observation(
                kind="slider",
                prompt="Align the puzzle piece with the missing slot",
                width=width,
                height=height,
                dynamic=dynamic,
                metadata=metadata,
                allowed_actions=("drag", "reload", "noop", "fail"),
            )
        elif kind == "word_click":
            instruction = await self._instruction_reader(target.frame)
            targets = _parse_word_click_targets(instruction)
            if not targets:
                raise RuntimeError("Tencent word-click instruction has no ordered targets")
            metadata["target_count"] = len(targets)
            observation = self._observation(
                kind="point",
                prompt=instruction,
                width=image_width,
                height=image_height,
                dynamic=dynamic,
                metadata=metadata,
                allowed_actions=("point", "reload", "noop", "fail"),
                min_answers=len(targets),
                max_answers=len(targets),
            )
            geometry = None
        else:
            raise RuntimeError(f"unsupported Tencent challenge kind: {kind}")

        task = VisionTask(
            kind="point" if kind == "word_click" else "drag_drop",
            prompt=observation.prompt,
            images=(VisionImage(background, label="tencent-challenge.png"),),
            width=image_width,
            height=image_height,
            min_answers=observation.min_answers,
            max_answers=observation.max_answers,
            metadata={"provider": "tencent", "observation_id": observation.observation_id},
        )
        self._current = _TencentScene(
            observation=observation,
            task=task,
            target=target,
            background=background,
            image_width=image_width,
            image_height=image_height,
            fingerprint=fingerprint,
            geometry=geometry,
        )
        self._last_target = target
        self.diagnostics.setdefault("tencent_session_observations", []).append(
            observation.to_dict()
        )
        return observation

    def _observation(
        self,
        *,
        kind: str,
        prompt: str,
        width: int,
        height: int,
        dynamic: bool,
        metadata: dict[str, Any],
        allowed_actions: tuple[str, ...],
        min_answers: int | None = None,
        max_answers: int | None = None,
    ) -> ChallengeObservation:
        observation_id = hashlib.sha256(
            f"tencent|{kind}|{metadata['image_sha256']}|{self._sequence}".encode()
        ).hexdigest()[:24]
        return ChallengeObservation(
            observation_id=observation_id,
            provider="tencent",
            kind=kind,  # type: ignore[arg-type]
            modality="image",
            prompt=prompt,
            width=width,
            height=height,
            dynamic=dynamic,
            min_answers=min_answers,
            max_answers=max_answers,
            allowed_actions=allowed_actions,  # type: ignore[arg-type]
            metadata=metadata,
        )

    async def _slider_coordinate_bounds(
        self, geometry: RuntimeGeometry
    ) -> tuple[int, int]:
        viewport = getattr(self.page, "viewport_size", None) or {}
        width = int(viewport.get("width") or 0) if isinstance(viewport, dict) else 0
        height = int(viewport.get("height") or 0) if isinstance(viewport, dict) else 0
        width = max(width, math.ceil(max(geometry.start_x, geometry.end_x) + 2))
        height = max(height, math.ceil(max(geometry.start_y, geometry.end_y) + 2))
        return max(1, width), max(1, height)

    async def vision_task(self, observation: ChallengeObservation) -> VisionTask | None:
        state = self._current
        if state is None or state.observation.observation_id != observation.observation_id:
            return None
        return state.task if observation.kind == "point" else None

    def slider_action(self, observation: ChallengeObservation) -> ChallengeAction:
        state = self._current
        if (
            state is None
            or state.observation.observation_id != observation.observation_id
            or state.geometry is None
        ):
            raise ValueError("Tencent slider observation is stale or has no geometry")
        geometry = state.geometry
        confidence = observation.metadata.get("detector_confidence")
        return ChallengeAction(
            observation_id=observation.observation_id,
            kind="drag",
            payload={
                "paths": [
                    {
                        "start": {"x": geometry.start_x, "y": geometry.start_y},
                        "end": {"x": geometry.end_x, "y": geometry.end_y},
                    }
                ]
            },
            confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
            rationale="Tencent runtime geometry mapped the detected gap to rendered coordinates",
        )

    async def execute(self, action: ChallengeAction) -> None:
        state = self._current
        if state is None or state.observation.observation_id != action.observation_id:
            raise ValueError("Tencent action does not target the current observation")
        errors = action.validate(state.observation)
        if errors:
            raise ValueError("invalid Tencent action: " + ", ".join(errors))

        if action.kind == "drag":
            if state.geometry is None:
                raise ValueError("Tencent drag action has no runtime geometry")
            self._validate_slider_path(action, state.geometry)
            await self._drag_executor(self.page, state.geometry)
            self._attempts += 1
            self._pending_verification = True
        elif action.kind == "point":
            points = tuple(
                (float(item["x"]), float(item["y"]))
                for item in action.payload.get("points", [])
            )
            await self._point_executor(state.target, state.background, points)
            self._attempts += 1
            self._pending_verification = True
        elif action.kind == "reload":
            if not await self._reload_executor(state.target):
                raise RuntimeError("Tencent reload control was not available")
        elif action.kind == "noop":
            self.diagnostics["tencent_session_noop"] = True
        else:
            raise ValueError(f"unsupported Tencent session action: {action.kind}")
        self._current = None

    @staticmethod
    def _validate_slider_path(action: ChallengeAction, geometry: RuntimeGeometry) -> None:
        path = action.payload["paths"][0]
        for name, expected_x, expected_y in (
            ("start", geometry.start_x, geometry.start_y),
            ("end", geometry.end_x, geometry.end_y),
        ):
            point = path[name]
            if (
                abs(float(point["x"]) - expected_x) > 2
                or abs(float(point["y"]) - expected_y) > 2
            ):
                raise ValueError("Tencent drag path does not match current runtime geometry")

    async def _collect_verification(self) -> dict[str, Any] | None:
        if self._verification_response is not None and self._vendor_passed():
            return self._verification_response
        target = await self._frame_resolver()
        frame = target.frame if target is not None else None
        if frame is None and self._current is not None:
            frame = self._current.target.frame
        if frame is None and self._last_target is not None:
            frame = self._last_target.frame
        if frame is None:
            frame = getattr(self.page, "main_frame", None)
        if frame is None:
            return None
        try:
            response = await asyncio.wait_for(
                self._verify_reader(frame, self._verify_state),
                timeout=max(0.01, self.verification_wait_sec),
            )
        except asyncio.TimeoutError:
            response = None
        self._pending_verification = False
        if not isinstance(response, dict):
            return None
        self._verification_response = response
        code = _verify_code(response)
        ticket = response.get("ticket")
        randstr = response.get("randstr")
        self.ticket = ticket if isinstance(ticket, str) and ticket else None
        self.randstr = randstr if isinstance(randstr, str) and randstr else None
        accepted = code == "0" and self.ticket is not None
        self.diagnostics.setdefault("tencent_verification_responses", []).append(
            {
                "error_code": code,
                "accepted": accepted,
                "ticket_len": len(self.ticket or ""),
                "randstr_len": len(self.randstr or ""),
            }
        )
        return response

    def _vendor_passed(self) -> bool:
        return (
            self._verification_response is not None
            and _verify_code(self._verification_response) == "0"
            and bool(self.ticket)
        )

    async def verify(self) -> VendorVerification:
        if self._pending_verification:
            await self._collect_verification()
        response = self._verification_response
        code = _verify_code(response) if response else ""
        token_length = len(self.ticket or "")
        vendor_pass = self._vendor_passed() if response is not None else None
        gaps: list[str] = []
        if response is None:
            gaps.append("tencent_verify_response_not_captured")
        elif code != "0":
            gaps.append(f"tencent_verify_code:{code or 'missing'}")
        if token_length == 0:
            gaps.append("tencent_vendor_ticket_not_captured")
        if response is not None and vendor_pass is not True:
            gaps.append("tencent_vendor_pass_not_observed")
        accepted = vendor_pass is True and token_length > 0 and not gaps
        self.diagnostics["tencent_session_verification"] = {
            "accepted": accepted,
            "attempts": self._attempts,
            "error_code": code or None,
            "ticket_len": token_length,
            "randstr_len": len(self.randstr or ""),
            "gaps": gaps,
        }
        return VendorVerification(
            provider="tencent",
            accepted=accepted,
            token_length=token_length,
            vendor_pass=vendor_pass,
            vendor_failures=int(response is not None and vendor_pass is False),
            verifier_events=(VERIFY_PATH,) if response is not None else (),
            gaps=tuple(gaps),
        )

    async def _execute_points(
        self,
        target: CaptchaFrame,
        background: bytes,
        points: tuple[tuple[float, float], ...],
    ) -> None:
        with Image.open(BytesIO(background)) as image:
            raw_width, raw_height = image.size
        locator = target.frame.locator(BG_SELECTOR).first
        box = await locator.bounding_box()
        if not box or box.get("width", 0) <= 0 or box.get("height", 0) <= 0:
            raise RuntimeError("Tencent word-click background geometry is unavailable")
        scale_x = float(box["width"]) / raw_width
        scale_y = float(box["height"]) / raw_height
        for x, y in points:
            page_x = float(box["x"]) + x * scale_x + random.uniform(-0.8, 0.8)
            page_y = float(box["y"]) + y * scale_y + random.uniform(-0.8, 0.8)
            await self.page.mouse.move(page_x, page_y)
            await self.page.mouse.down()
            await asyncio.sleep(random.uniform(0.03, 0.08))
            await self.page.mouse.up()
            await asyncio.sleep(random.uniform(0.2, 0.45))
        for selector in (
            "#tcStatus .tc-status--right",
            ".tc-status--right",
            "text=确定",
            "#verifyBtn",
            ".tc-action--confirm",
        ):
            try:
                confirm = target.frame.locator(selector).first
                if await confirm.count():
                    await confirm.click(timeout=1500, force=True)
                    return
            except Exception:
                continue
        raise RuntimeError("Tencent word-click confirm control is unavailable")

    async def _reload(self, target: CaptchaFrame) -> bool:
        try:
            return bool(
                await target.frame.evaluate(
                    """(selector)=>{
                      const element = document.querySelector(selector);
                      if (!element) return false;
                      element.click();
                      return true;
                    }""",
                    RELOAD_SELECTOR,
                )
            )
        except Exception:
            return False


async def _tencent_slider_strategy(
    session: Any,
    observation: ChallengeObservation,
    _diagnostics: dict[str, Any],
) -> ChallengeAction:
    if not isinstance(session, TencentChallengeSession):
        return ChallengeAction(
            observation_id=observation.observation_id,
            kind="fail",
            rationale="Tencent slider strategy received an incompatible session",
        )
    return session.slider_action(observation)


def _verify_code(response: dict[str, Any]) -> str:
    value = response.get("errorCode", response.get("error_code", ""))
    return str(value) if value is not None else ""


class TencentSliderChallengeSession(TencentChallengeSession):
    """Named compatibility entry point for Tencent's dominant slider flow."""

__all__ = [
    "TencentChallengeSession",
    "TencentSliderChallengeSession",
    "TencentWordOCRBackend",
]
