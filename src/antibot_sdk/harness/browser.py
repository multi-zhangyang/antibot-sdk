"""Generic Playwright-backed challenge scene session.

This adapter intentionally contains no vendor selectors. A caller supplies the
challenge surface and evidence reader; the adapter turns rendered controls into
observation-scoped affordances and executes only validated standard actions.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Awaitable, Callable

from PIL import Image

from ..vision import VisionImage, VisionTask
from .contracts import (
    ChallengeAction,
    ChallengeAffordance,
    ChallengeObservation,
    VendorVerification,
)
from .token import TokenChallengeSession, TokenReader, VendorPassReader

VerificationReader = Callable[[], Awaitable[VendorVerification] | VendorVerification]


@dataclass(slots=True)
class _BrowserSceneState:
    observation: ChallengeObservation
    task: VisionTask
    surface: Any
    root_box: dict[str, float] | None
    controls: dict[str, Any]
    submit_ids: tuple[str, ...]
    reload_ids: tuple[str, ...]


class BrowserChallengeSession:
    """Observe and execute a generic interactive browser challenge."""

    def __init__(
        self,
        page: Any,
        *,
        provider: str,
        surface_selector: str = "body",
        surface: Any | None = None,
        prompt_selectors: tuple[str, ...] = (
            "[data-captcha-prompt]",
            "[aria-live]",
            ".challenge-prompt",
            ".prompt",
        ),
        token_selectors: tuple[str, ...] = (),
        token_reader: TokenReader | None = None,
        vendor_pass_reader: VendorPassReader | None = None,
        verifier: VerificationReader | None = None,
        verifier_event_markers: tuple[str, ...] = (),
        network_events: list[dict[str, Any]] | None = None,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        if not provider.strip():
            raise ValueError("browser session provider must not be empty")
        if not surface_selector.strip() and surface is None:
            raise ValueError("browser session surface_selector must not be empty")
        has_token_source = bool(token_selectors) or token_reader is not None
        if verifier is not None and has_token_source:
            raise ValueError(
                "browser session verifier and token reader are mutually exclusive"
            )
        if (vendor_pass_reader is not None or verifier_event_markers) and not has_token_source:
            raise ValueError(
                "vendor pass or verifier markers require a token reader or token selectors"
            )
        self.page = page
        self.provider = provider.strip().casefold()
        self.surface_selector = surface_selector
        self.surface = surface
        self.prompt_selectors = tuple(prompt_selectors)
        self.diagnostics = diagnostics if diagnostics is not None else {}
        self.verifier = verifier
        self.network_events = network_events if network_events is not None else []
        self._sequence = 0
        self._actions_executed = 0
        self._current: _BrowserSceneState | None = None
        self._last_verification: VendorVerification | None = None
        self._last_scene_fingerprint: str | None = None
        self._token_session = (
            TokenChallengeSession(
                page,
                provider=self.provider,
                token_selectors=token_selectors,
                token_reader=token_reader,
                vendor_pass_reader=vendor_pass_reader,
                verifier_event_markers=verifier_event_markers,
                network_events=self.network_events,
                diagnostics=self.diagnostics,
                verification_wait_ms=0,
            )
            if has_token_source
            else None
        )

    async def _surface_locator(self) -> Any | None:
        if self.surface is not None:
            visible = getattr(self.surface, "is_visible", None)
            if callable(visible):
                try:
                    if not await visible(timeout=250):
                        return None
                except Exception:
                    return None
            return self.surface
        locator = self.page.locator(self.surface_selector).first
        try:
            if not await locator.count() or not await locator.is_visible(timeout=250):
                return None
        except Exception:
            return None
        return locator

    async def _prompt(self, surface: Any) -> str:
        for selector in self.prompt_selectors:
            try:
                locator = surface.locator(selector).first
                if await locator.count():
                    text = " ".join((await locator.inner_text(timeout=300) or "").split())
                    if text:
                        return text[:500]
            except Exception:
                continue
        return "Complete the visible challenge"

    async def observe(self) -> ChallengeObservation | None:
        if self._actions_executed:
            verification = await self._read_verification()
            if verification is not None and verification.accepted:
                self._last_verification = verification
                self._current = None
                return None
        surface = await self._surface_locator()
        if surface is None:
            self._current = None
            return None
        screenshot = await surface.screenshot(type="png", animations="disabled")
        with Image.open(BytesIO(screenshot)) as image:
            width, height = image.size
        root_box = await _maybe_bounding_box(surface)
        controls, submit_ids, reload_ids = await self._controls(
            surface,
            root_box,
            width,
            height,
        )
        prompt = await self._prompt(surface)
        signature = hashlib.sha256(
            json.dumps(
                [
                    {
                        "id": item.affordance_id,
                        "role": item.role,
                        "label": item.label,
                        "enabled": item.enabled,
                        "actions": item.actions,
                        "bounds": (item.x, item.y, item.width, item.height),
                        "candidate_index": item.candidate_index,
                    }
                    for item in controls["affordances"]
                ],
                ensure_ascii=True,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        self._sequence += 1
        image_hash = hashlib.sha256(screenshot).hexdigest()
        scene_fingerprint = hashlib.sha256(
            f"{prompt}|{image_hash}|{signature}".encode("utf-8")
        ).hexdigest()
        scene_changed = (
            self._last_scene_fingerprint is not None
            and self._last_scene_fingerprint != scene_fingerprint
        )
        if scene_changed:
            self.diagnostics["browser_scene_replacements"] = (
                int(self.diagnostics.get("browser_scene_replacements") or 0) + 1
            )
        self._last_scene_fingerprint = scene_fingerprint
        observation_id = hashlib.sha256(
            f"{self.provider}|{self._sequence}|{prompt}|{image_hash}|{signature}".encode(
                "utf-8"
            )
        ).hexdigest()[:24]
        allowed = set(("wait", "noop", "fail"))
        for affordance in controls["affordances"]:
            if affordance.enabled:
                allowed.update(affordance.actions)
        if submit_ids:
            allowed.add("submit")
        if reload_ids:
            allowed.add("reload")
        observation = ChallengeObservation(
            observation_id=observation_id,
            provider=self.provider,
            kind="interactive",
            modality="image",
            prompt=prompt,
            affordances=tuple(controls["affordances"]),
            allowed_actions=tuple(sorted(allowed)),
            width=width,
            height=height,
            dynamic=scene_changed,
            metadata={
                "surface_selector": self.surface_selector,
                "image_sha256": image_hash,
                "affordance_signature": signature,
                "scene_fingerprint": scene_fingerprint,
                "scene_changed_since_previous": scene_changed,
                "source": "browser_dom_and_screenshot",
            },
        )
        task = VisionTask(
            kind="interactive",
            prompt=prompt,
            images=(VisionImage(screenshot, label="challenge-surface.png"),),
            width=width,
            height=height,
            metadata={"provider": self.provider, "observation_id": observation_id},
        )
        self._current = _BrowserSceneState(
            observation=observation,
            task=task,
            surface=surface,
            root_box=root_box,
            controls=controls["locators"],
            submit_ids=tuple(submit_ids),
            reload_ids=tuple(reload_ids),
        )
        self.diagnostics.setdefault("browser_scene_observations", []).append(
            {
                "observation_id": observation_id,
                "prompt": prompt,
                "affordance_count": len(observation.affordances),
                "allowed_actions": list(observation.supported_actions),
                "image_sha256": image_hash,
                "dynamic": observation.dynamic,
                "scene_changed_since_previous": scene_changed,
            }
        )
        return observation

    async def _controls(
        self,
        surface: Any,
        root_box: dict[str, float] | None,
        surface_width: int,
        surface_height: int,
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        selector = (
            "button, input, textarea, select, canvas, "
            "[role='button'], [role='checkbox'], [role='radio'], [role='textbox'], "
            "[draggable='true'], [contenteditable='true']"
        )
        locator = surface.locator(selector)
        try:
            count = await locator.count()
        except Exception:
            count = 0
        affordances: list[ChallengeAffordance] = []
        locators: dict[str, Any] = {}
        submit_ids: list[str] = []
        reload_ids: list[str] = []
        for index in range(count):
            item = locator.nth(index)
            data = await _control_data(item, index)
            if data is None or data.get("visible") is False:
                continue
            role = _control_role(data)
            label = _control_label(data)
            enabled = not bool(data.get("disabled"))
            bounds = data.get("bounds")
            if isinstance(bounds, dict) and root_box:
                bounds = _clip_bounds(bounds, root_box, surface_width, surface_height)
                if bounds is None:
                    continue
            elif isinstance(bounds, dict):
                bounds = None
            if isinstance(bounds, dict) and (
                bounds.get("width", 0) <= 0 or bounds.get("height", 0) <= 0
            ):
                continue
            actions = _control_actions(role, data, label)
            if not actions:
                continue
            affordance_id = f"control-{index}"
            metadata = {"tag": data.get("tag", ""), "type": data.get("type", "")}
            affordances.append(
                ChallengeAffordance(
                    affordance_id=affordance_id,
                    role=role,
                    label=label,
                    x=bounds.get("x") if isinstance(bounds, dict) else None,
                    y=bounds.get("y") if isinstance(bounds, dict) else None,
                    width=bounds.get("width") if isinstance(bounds, dict) else None,
                    height=bounds.get("height") if isinstance(bounds, dict) else None,
                    enabled=enabled,
                    actions=tuple(actions),
                    metadata=metadata,
                )
            )
            locators[affordance_id] = item
            semantic = _button_semantic(label, data)
            if enabled and semantic == "submit":
                submit_ids.append(affordance_id)
            elif enabled and semantic == "reload":
                reload_ids.append(affordance_id)
        return {
            "affordances": affordances,
            "locators": locators,
        }, submit_ids, reload_ids

    async def vision_task(self, observation: ChallengeObservation) -> VisionTask | None:
        if self._current is None or self._current.observation.observation_id != observation.observation_id:
            return None
        return self._current.task

    async def execute(self, action: ChallengeAction) -> None:
        state = self._current
        if state is None or state.observation.observation_id != action.observation_id:
            raise ValueError("browser action does not target current observation")
        errors = action.validate(state.observation)
        if errors:
            raise ValueError("browser action rejected: " + ", ".join(errors))
        if action.kind == "click":
            await self._click(state, action.payload)
        elif action.kind == "type":
            target = state.controls[action.payload["affordance_id"]]
            await target.fill(action.payload["text"])
        elif action.kind == "press":
            target = state.controls.get(action.payload.get("affordance_id"))
            if target is not None:
                await target.press(action.payload["key"])
            else:
                await self.page.keyboard.press(action.payload["key"])
        elif action.kind == "point":
            for point in action.payload["points"]:
                await state.surface.click(position={"x": point["x"], "y": point["y"]})
        elif action.kind == "drag":
            await self._drag(state, action.payload["paths"])
        elif action.kind in {"select", "choice"}:
            raise ValueError("generic browser session requires affordance or coordinate actions")
        elif action.kind == "submit":
            await self._semantic_click(state, state.submit_ids, "submit")
        elif action.kind == "reload":
            await self._semantic_click(state, state.reload_ids, "reload")
        elif action.kind == "wait":
            await self.page.wait_for_timeout(action.payload["milliseconds"])
        elif action.kind in {"noop", "fail"}:
            pass
        else:
            raise ValueError(f"unsupported generic browser action: {action.kind}")
        self.diagnostics.setdefault("browser_scene_actions", []).append(
            {
                "observation_id": action.observation_id,
                "kind": action.kind,
                "executed": True,
            }
        )
        self._actions_executed += 1
        self._current = None

    async def _click(self, state: _BrowserSceneState, payload: dict[str, Any]) -> None:
        if "affordance_id" in payload:
            await state.controls[payload["affordance_id"]].click(timeout=3000, delay=100)
            return
        point = payload["point"]
        await state.surface.click(position={"x": point["x"], "y": point["y"]})

    async def _drag(self, state: _BrowserSceneState, paths: list[dict[str, Any]]) -> None:
        if state.root_box is None:
            raise ValueError("generic browser drag requires a measurable surface bounds")
        box = state.root_box
        for path in paths:
            start = path["start"]
            end = path["end"]
            await self.page.mouse.move(box["x"] + start["x"], box["y"] + start["y"])
            await self.page.mouse.down()
            await self.page.mouse.move(
                box["x"] + end["x"],
                box["y"] + end["y"],
                steps=20,
            )
            await self.page.mouse.up()

    async def _semantic_click(
        self,
        state: _BrowserSceneState,
        ids: tuple[str, ...],
        semantic: str,
    ) -> None:
        if not ids:
            raise ValueError(f"generic browser session has no {semantic} affordance")
        await state.controls[ids[0]].click(timeout=3000, delay=100)

    async def verify(self) -> VendorVerification:
        if self._last_verification is not None and self._last_verification.accepted:
            return self._last_verification
        value = await self._read_verification()
        if value is not None:
            return value
        return VendorVerification(
            provider=self.provider,
            accepted=False,
            gaps=("browser_session_verifier_not_configured",),
        )

    async def _read_verification(self) -> VendorVerification | None:
        if self.verifier is not None:
            value = self.verifier()
            if inspect.isawaitable(value):
                value = await value
            if not isinstance(value, VendorVerification):
                raise TypeError("browser session verifier must return VendorVerification")
            return value
        if self._token_session is not None:
            return await self._token_session.verify()
        return None


async def _maybe_bounding_box(locator: Any) -> dict[str, float] | None:
    try:
        value = await locator.bounding_box()
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _clip_bounds(
    bounds: dict[str, Any],
    root_box: dict[str, Any],
    surface_width: int,
    surface_height: int,
) -> dict[str, float] | None:
    """Return finite bounds in surface coordinates, clipped to the screenshot."""

    try:
        values = {
            name: float(bounds[name])
            for name in ("x", "y", "width", "height")
        }
        root_x = float(root_box.get("x", 0))
        root_y = float(root_box.get("y", 0))
    except (KeyError, TypeError, ValueError):
        return None
    if not all(math.isfinite(value) for value in (*values.values(), root_x, root_y)):
        return None
    left = values["x"] - root_x
    top = values["y"] - root_y
    right = left + values["width"]
    bottom = top + values["height"]
    left = max(0.0, min(float(surface_width), left))
    top = max(0.0, min(float(surface_height), top))
    right = max(0.0, min(float(surface_width), right))
    bottom = max(0.0, min(float(surface_height), bottom))
    if right <= left or bottom <= top:
        return None
    return {
        "x": left,
        "y": top,
        "width": right - left,
        "height": bottom - top,
    }


async def _control_data(locator: Any, index: int) -> dict[str, Any] | None:
    try:
        value = await locator.evaluate(
            """(el, index) => {
              const rect = el.getBoundingClientRect();
              return {
                index,
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || '',
                role: el.getAttribute('role') || '',
                aria: el.getAttribute('aria-label') || '',
                title: el.getAttribute('title') || '',
                placeholder: el.getAttribute('placeholder') || '',
                name: el.getAttribute('name') || '',
                text: (el.innerText || el.value || '').trim().slice(0, 200),
                disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
                draggable: el.getAttribute('draggable') === 'true',
                contenteditable: el.getAttribute('contenteditable') === 'true',
                visible: rect.width > 0 && rect.height > 0 &&
                  getComputedStyle(el).display !== 'none' &&
                  getComputedStyle(el).visibility !== 'hidden' &&
                  getComputedStyle(el).opacity !== '0',
                bounds: {x: rect.x, y: rect.y, width: rect.width, height: rect.height},
              };
            }""",
            index,
        )
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _control_role(data: dict[str, Any]) -> str:
    role = str(data.get("role") or "").strip().casefold()
    if role:
        return role
    tag = str(data.get("tag") or "").casefold()
    input_type = str(data.get("type") or "").casefold()
    if tag in {"textarea"} or (tag == "input" and input_type in {"", "text", "search", "number"}):
        return "textbox"
    if tag == "input" and input_type in {"checkbox", "radio"}:
        return input_type
    if tag == "button":
        return "button"
    if tag == "select":
        return "combobox"
    if tag == "canvas":
        return "canvas"
    if data.get("contenteditable"):
        return "textbox"
    if data.get("draggable"):
        return "slider"
    return "control"


def _control_label(data: dict[str, Any]) -> str:
    for key in ("aria", "title", "placeholder", "text", "name"):
        value = str(data.get(key) or "").strip()
        if value:
            return value[:200]
    return ""


def _control_actions(role: str, data: dict[str, Any], label: str) -> tuple[str, ...]:
    del data
    actions: set[str] = set()
    if role in {"button", "checkbox", "radio", "switch", "control", "combobox"}:
        actions.add("click")
    if role in {"textbox", "combobox"}:
        actions.update(("type", "press"))
    if role in {"canvas", "slider"}:
        actions.update(("point", "drag", "click"))
    if _button_semantic(label, {"role": role}):
        actions.add("click")
    return tuple(sorted(actions))


def _button_semantic(label: str, data: dict[str, Any]) -> str | None:
    text = " ".join(
        part for part in (label, str(data.get("text") or "")) if part
    ).casefold()
    if any(word in text for word in ("verify", "submit", "continue", "check", "done")):
        return "submit"
    if any(word in text for word in ("reload", "refresh", "new challenge", "try again")):
        return "reload"
    return None


__all__ = ["BrowserChallengeSession", "VerificationReader"]
