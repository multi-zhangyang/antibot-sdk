from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_CANVAS_SIZE = 20
DEFAULT_BASE_URL = "http://127.0.0.1:8080"


@dataclass(frozen=True, slots=True)
class DonatelloShape:
    kind: str
    color: str | None = None
    values: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class DonatelloChallenge:
    challenge_id: str
    first_task: str
    second_task: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DonatelloCanvasHashes:
    red: str
    green: str
    blue: str
    alpha: str
    combined: str


@dataclass(frozen=True, slots=True)
class DonatelloSolution:
    challenge: DonatelloChallenge
    total_hash1: str
    total_hash2: str
    metrics2: str
    copy_mismatch: bool
    elapsed_ms: int
    first_hashes: DonatelloCanvasHashes
    second_hashes: DonatelloCanvasHashes | None = None

    @property
    def verify_body(self) -> dict[str, Any]:
        return {
            "id": self.challenge.challenge_id,
            "totalHash1": self.total_hash1,
            "totalHash2": self.total_hash2,
            "metrics2": self.metrics2,
            "copyMismatch": self.copy_mismatch,
        }


def parse_donatello_task(task: str) -> list[DonatelloShape]:
    shapes: list[DonatelloShape] = []
    for encoded in (task or "").split(";"):
        encoded = encoded.strip()
        if not encoded:
            continue
        parts = encoded.split(":")
        kind = parts[0].upper()
        try:
            if kind == "R" and len(parts) == 6:
                shapes.append(DonatelloShape(kind="R", color=_norm_color(parts[1]), values=tuple(int(x) for x in parts[2:6])))
            elif kind == "L" and len(parts) == 7:
                shapes.append(DonatelloShape(kind="L", color=_norm_color(parts[1]), values=tuple(int(x) for x in parts[2:7])))
            elif kind == "X" and len(parts) == 4:
                shapes.append(
                    DonatelloShape(
                        kind="X",
                        color=f"{_norm_color(parts[2])}:{_norm_color(parts[3])}",
                        values=(int(parts[1]),),
                    )
                )
            elif kind == "C" and len(parts) == 5:
                shapes.append(DonatelloShape(kind="C", color=_norm_color(parts[1]), values=tuple(int(x) for x in parts[2:5])))
            elif kind == "T" and len(parts) == 8:
                shapes.append(DonatelloShape(kind="T", color=_norm_color(parts[1]), values=tuple(int(x) for x in parts[2:8])))
            elif kind == "E" and len(parts) == 6:
                shapes.append(DonatelloShape(kind="E", color=_norm_color(parts[1]), values=tuple(int(x) for x in parts[2:6])))
            else:
                raise ValueError(f"unsupported Donatello shape: {encoded}")
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"invalid Donatello shape: {encoded}") from exc
    return shapes


def render_donatello_task(task: str, *, width: int = DEFAULT_CANVAS_SIZE, height: int | None = None) -> dict[str, bytearray]:
    """Render Donatello's task grammar into RGBA channel byte arrays.

    The first task in the reference server is intentionally limited to a
    chessboard background plus even rectangles/axis-aligned lines. Those paths
    match the Go server-side oracle and the JS worker exactly. Circle/triangle
    and ellipse are implemented as deterministic no-antialias approximations so
    the SDK can still produce stable second-task metrics without a browser; the
    reference server currently records but does not enforce that second hash.
    """

    height = height or width
    channels = {
        "r": bytearray(width * height),
        "g": bytearray(width * height),
        "b": bytearray(width * height),
        "a": bytearray(width * height),
    }
    for shape in parse_donatello_task(task):
        if shape.kind == "X":
            color1, color2 = str(shape.color).split(":", 1)
            _draw_chessboard(channels, width, height, shape.values[0], color1, color2)
        elif shape.kind == "R":
            w, h, x, y = shape.values
            _fill_rect(channels, width, height, x, y, x + w, y + h, _hex_to_rgba(str(shape.color)))
        elif shape.kind == "L":
            x1, y1, x2, y2, thickness = shape.values
            half = thickness // 2
            if x1 == x2:
                _fill_rect(channels, width, height, x1 - half, min(y1, y2), x1 + half, max(y1, y2), _hex_to_rgba(str(shape.color)))
            elif y1 == y2:
                _fill_rect(channels, width, height, min(x1, x2), y1 - half, max(x1, x2), y1 + half, _hex_to_rgba(str(shape.color)))
        elif shape.kind == "C":
            radius, cx, cy = shape.values
            _draw_circle(channels, width, height, radius, cx, cy, _hex_to_rgba(str(shape.color)))
        elif shape.kind == "T":
            _draw_triangle(channels, width, height, shape.values, _hex_to_rgba(str(shape.color)))
        elif shape.kind == "E":
            rx, ry, cx, cy = shape.values
            _draw_ellipse(channels, width, height, rx, ry, cx, cy, _hex_to_rgba(str(shape.color)))
    return channels


def donatello_canvas_hashes(task: str, *, canvas_size: int = DEFAULT_CANVAS_SIZE) -> DonatelloCanvasHashes:
    channels = render_donatello_task(task, width=canvas_size, height=canvas_size)
    r_hash = _sha256_bytes(channels["r"])
    g_hash = _sha256_bytes(channels["g"])
    b_hash = _sha256_bytes(channels["b"])
    a_hash = _sha256_bytes(channels["a"])
    combined = hashlib.sha256((r_hash + g_hash + b_hash + a_hash).encode("utf-8")).hexdigest()
    return DonatelloCanvasHashes(red=r_hash, green=g_hash, blue=b_hash, alpha=a_hash, combined=combined)


def donatello_alpha_metrics(task: str, *, canvas_size: int = DEFAULT_CANVAS_SIZE) -> str:
    alpha = render_donatello_task(task, width=canvas_size, height=canvas_size)["a"]
    return donatello_channel_metrics(alpha, canvas_size)


def donatello_channel_metrics(channel: bytes | bytearray, canvas_size: int = DEFAULT_CANVAS_SIZE) -> str:
    n = canvas_size
    total = n * n
    vals = [float(x) for x in channel[:total]]
    if len(vals) < total:
        vals.extend([0.0] * (total - len(vals)))
    s = sum(vals)
    s2 = sum(x * x for x in vals)
    mean = s / total
    std = math.sqrt(max(0.0, s2 / total - mean * mean))
    sorted_vals = sorted(vals)
    median = sorted_vals[total // 2]
    mn = min(vals) if vals else 0.0
    mx = max(vals) if vals else 0.0
    bins = [0.0] * 8
    for v in vals:
        bins[min(7, int(math.floor(v * 8 / 256)))] += 1.0
    bins = [x / total for x in bins]
    gsum = 0.0
    gmax = 0.0
    for y in range(n):
        for x in range(n):
            c = vals[y * n + x]
            rx = vals[y * n + x + 1] if x + 1 < n else c
            by = vals[(y + 1) * n + x] if y + 1 < n else c
            gm = math.hypot(rx - c, by - c)
            gsum += gm
            gmax = max(gmax, gm)
    feat = [mean / 255, std / 255, mn / 255, mx / 255, median / 255, *bins, (gsum / total) / 255, gmax / 255]
    return json.dumps(feat, separators=(",", ":"))


def parse_donatello_challenge(data: Any) -> DonatelloChallenge:
    if isinstance(data, str):
        data = _load_json_arg(data)
    if not isinstance(data, dict):
        raise ValueError("Donatello challenge must be a JSON object")
    challenge_id = data.get("id") or data.get("challenge_id") or data.get("challengeId")
    first_task = data.get("first_task") or data.get("firstTask") or data.get("task")
    second_task = data.get("second_task") or data.get("secondTask")
    if not challenge_id:
        raise ValueError("Donatello challenge requires id")
    if not first_task:
        raise ValueError("Donatello challenge requires first_task")
    return DonatelloChallenge(str(challenge_id), str(first_task), str(second_task) if second_task else None, data)


def solve_donatello_challenge(
    challenge: DonatelloChallenge | dict[str, Any] | str,
    *,
    canvas_size: int = DEFAULT_CANVAS_SIZE,
    copy_mismatch: bool = False,
) -> DonatelloSolution:
    started = time.monotonic()
    item = parse_donatello_challenge(challenge) if not isinstance(challenge, DonatelloChallenge) else challenge
    first = donatello_canvas_hashes(item.first_task, canvas_size=canvas_size)
    if item.second_task:
        second = donatello_canvas_hashes(item.second_task, canvas_size=canvas_size)
        total_hash2 = second.alpha
        metrics2 = donatello_alpha_metrics(item.second_task, canvas_size=canvas_size)
    else:
        second = None
        total_hash2 = first.alpha
        metrics2 = donatello_channel_metrics(render_donatello_task(item.first_task, width=canvas_size)["a"], canvas_size)
    return DonatelloSolution(
        challenge=item,
        total_hash1=first.combined,
        total_hash2=total_hash2,
        metrics2=metrics2,
        copy_mismatch=bool(copy_mismatch),
        elapsed_ms=int((time.monotonic() - started) * 1000),
        first_hashes=first,
        second_hashes=second,
    )


def verify_donatello_solution(
    challenge: DonatelloChallenge | dict[str, Any] | str,
    solution: DonatelloSolution | dict[str, Any],
    *,
    canvas_size: int = DEFAULT_CANVAS_SIZE,
) -> bool:
    try:
        item = parse_donatello_challenge(challenge) if not isinstance(challenge, DonatelloChallenge) else challenge
        body = solution.verify_body if isinstance(solution, DonatelloSolution) else solution
        if str(body.get("id")) != item.challenge_id:
            return False
        expected = solve_donatello_challenge(item, canvas_size=canvas_size)
        if str(body.get("totalHash1")) != expected.total_hash1:
            return False
        if item.second_task and str(body.get("totalHash2")) != expected.total_hash2:
            return False
        return isinstance(body.get("metrics2"), str) and len(str(body.get("metrics2"))) > 2
    except Exception:
        return False


def extract_donatello_challenge_id(html: str) -> str | None:
    patterns = [
        r"challenge_id\s*=\s*['\"]([^'\"]+)['\"]",
        r"challengeId\s*=\s*['\"]([^'\"]+)['\"]",
        r"data-challenge-id=['\"]([^'\"]+)['\"]",
        r"/challenge\?id=([A-Za-z0-9_.:-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


class DonatelloSolver:
    """Protocol solver for Donatello canvas/subpixel challenge.

    It reconstructs the first-task canvas oracle and emits the same JSON body
    that the reference page posts, without starting a browser.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        page_url: str | None = None,
        challenge_id: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        verify_url: str | None = None,
        submit: bool = False,
        canvas_size: int = DEFAULT_CANVAS_SIZE,
        copy_mismatch: bool = False,
        timeout_sec: int = 10,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "base_url": base_url,
            "page_url": page_url,
            "challenge_url": challenge_url,
            "verify_url": verify_url,
            "submit": submit,
            "canvas_size": canvas_size,
            "copy_mismatch": copy_mismatch,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
        }
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "donatello_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="donatello",
                ok=ok,
                captcha_type="canvas_fingerprint_challenge",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("challenge_id"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            data = self._load_challenge(
                base_url=base_url,
                page_url=page_url,
                challenge_id=challenge_id,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
                diagnostics=diagnostics,
            )
            challenge = parse_donatello_challenge(data)
            solution = solve_donatello_challenge(challenge, canvas_size=canvas_size, copy_mismatch=copy_mismatch)
            diagnostics.update(
                {
                    "challenge_id": challenge.challenge_id,
                    "first_task_len": len(challenge.first_task),
                    "second_task_len": len(challenge.second_task or ""),
                    "solve_ms": solution.elapsed_ms,
                    "validation_gap": "reference POST records totalHash fields but does not reject mismatches",
                }
            )
            raw["challenge"] = challenge.raw or data
            raw["solution"] = {
                "body": solution.verify_body,
                "firstHashes": asdict(solution.first_hashes),
                "secondHashes": asdict(solution.second_hashes) if solution.second_hashes else None,
                "elapsedMs": solution.elapsed_ms,
            }
            final_ticket = json.dumps(solution.verify_body, separators=(",", ":"))
            verify_code = "solved"
            if submit or verify_url:
                final_ticket, verify_code = self._submit(
                    verify_url or _api_url(base_url, "/challenge"),
                    solution.verify_body,
                    timeout_sec,
                    proxy_server,
                    headers,
                    raw,
                    errors,
                )
                if verify_code != "verified":
                    return finish(ok=False, ticket=final_ticket, verify_code=verify_code)
            return finish(ok=True, ticket=final_ticket, verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        base_url: str,
        page_url: str | None,
        challenge_id: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
        diagnostics: dict[str, Any],
    ) -> Any:
        if challenge_json is not None:
            return _load_json_arg(challenge_json) if isinstance(challenge_json, str) else challenge_json
        loaded = _load_json_arg(None, challenge_file)
        if loaded is not None:
            return loaded
        if not challenge_id and page_url is not None:
            resp = requests.get(page_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
            raw["pageRequest"] = {"url": page_url}
            raw["pageResponse"] = {"status": resp.status_code, "url": resp.url}
            if resp.status_code >= 400:
                raise RuntimeError(f"Donatello page HTTP {resp.status_code}")
            challenge_id = extract_donatello_challenge_id(resp.text)
            if not challenge_id:
                raise ValueError("failed to extract Donatello challenge_id from page")
            diagnostics["page_challenge_id"] = challenge_id
        if not challenge_id and challenge_url is None:
            page = page_url or base_url
            resp = requests.get(page, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
            raw["pageRequest"] = {"url": page}
            raw["pageResponse"] = {"status": resp.status_code, "url": resp.url}
            if resp.status_code >= 400:
                raise RuntimeError(f"Donatello page HTTP {resp.status_code}")
            challenge_id = extract_donatello_challenge_id(resp.text)
            if not challenge_id:
                raise ValueError("failed to extract Donatello challenge_id from page")
            diagnostics["page_challenge_id"] = challenge_id
        if challenge_url is None:
            challenge_url = _api_url(base_url, "/challenge")
            if challenge_id:
                challenge_url += ("&" if "?" in challenge_url else "?") + urlencode({"id": challenge_id})
        resp = requests.get(challenge_url, headers=headers, timeout=timeout_sec, proxies=_requests_proxies(proxy_server))
        raw["challengeRequest"] = {"url": challenge_url}
        raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
        try:
            data = resp.json()
        except ValueError:
            raw["challengeResponse"]["text"] = resp.text[:500]
            data = None
        else:
            raw["challengeResponse"]["json"] = data
        if resp.status_code >= 400:
            message = "challenge_failed"
            if isinstance(data, dict):
                message = str(data.get("error") or data.get("message") or message)
            raise RuntimeError(f"Donatello challenge HTTP {resp.status_code}: {message}")
        if data is None:
            raise ValueError("Donatello challenge response is not JSON")
        return data

    def _submit(
        self,
        verify_url: str,
        body: dict[str, Any],
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
        errors: list[str],
    ) -> tuple[str | None, str]:
        resp = requests.post(
            verify_url,
            headers={"Content-Type": "application/json", **(headers or {})},
            json=body,
            timeout=timeout_sec,
            proxies=_requests_proxies(proxy_server),
        )
        raw["verifyRequest"] = {"url": verify_url, "body": body}
        raw["verifyResponse"] = {"status": resp.status_code, "url": resp.url}
        try:
            data = resp.json()
        except ValueError:
            data = None
            raw["verifyResponse"]["text"] = resp.text[:500]
        else:
            raw["verifyResponse"]["json"] = data
        if resp.status_code >= 400:
            message = "verify_failed"
            if isinstance(data, dict):
                message = str(data.get("error") or data.get("message") or message)
            errors.append(message)
            return json.dumps(body, separators=(",", ":")), f"http_{resp.status_code}"
        if isinstance(data, dict) and (data.get("status") == "ok" or data.get("success") or data.get("verified")):
            return json.dumps(data, separators=(",", ":")), "verified"
        errors.append(str((data or {}).get("error") if isinstance(data, dict) else "verify_failed"))
        return json.dumps(body, separators=(",", ":")), "verify_failed"


def _norm_color(value: str) -> str:
    value = value.strip().lstrip("#").upper()
    if not re.fullmatch(r"[0-9A-F]{6}", value):
        raise ValueError(f"invalid RGB color: {value}")
    return value


def _hex_to_rgba(value: str) -> tuple[int, int, int, int]:
    value = _norm_color(value)
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16), 255


def _fill_rect(
    channels: dict[str, bytearray],
    width: int,
    height: int,
    x0: int,
    y0: int,
    x1: int,
    y1: int,
    rgba: tuple[int, int, int, int],
) -> None:
    x0 = max(0, min(width, x0))
    x1 = max(0, min(width, x1))
    y0 = max(0, min(height, y0))
    y1 = max(0, min(height, y1))
    if x0 >= x1 or y0 >= y1:
        return
    r, g, b, a = rgba
    for y in range(y0, y1):
        start = y * width + x0
        end = y * width + x1
        channels["r"][start:end] = bytes([r]) * (end - start)
        channels["g"][start:end] = bytes([g]) * (end - start)
        channels["b"][start:end] = bytes([b]) * (end - start)
        channels["a"][start:end] = bytes([a]) * (end - start)


def _draw_chessboard(
    channels: dict[str, bytearray],
    width: int,
    height: int,
    grid_size: int,
    color1: str,
    color2: str,
) -> None:
    if grid_size <= 0:
        return
    cell_size = width // grid_size
    if cell_size <= 0:
        cell_size = 2
    denom = max(1, grid_size * grid_size - 1)
    for i in range(grid_size):
        for j in range(grid_size):
            progress = (i * grid_size + j) / denom
            color = _interpolate_color(color1, color2, progress)
            _fill_rect(channels, width, height, i * cell_size, j * cell_size, i * cell_size + cell_size, j * cell_size + cell_size, _hex_to_rgba(color))


def _interpolate_color(color1: str, color2: str, progress: float) -> str:
    r1, g1, b1, _ = _hex_to_rgba(color1)
    r2, g2, b2, _ = _hex_to_rgba(color2)

    def rounded(v: float) -> int:
        out = int(math.floor((v / 25.0) + 0.5) * 25)
        return max(0, min(255, out))

    r = rounded(r1 + progress * (r2 - r1))
    g = rounded(g1 + progress * (g2 - g1))
    b = rounded(b1 + progress * (b2 - b1))
    return f"{r:02X}{g:02X}{b:02X}"


def _draw_circle(channels: dict[str, bytearray], width: int, height: int, radius: int, cx: int, cy: int, rgba: tuple[int, int, int, int]) -> None:
    rr = radius * radius
    for y in range(cy - radius, cy + radius + 1):
        for x in range(cx - radius, cx + radius + 1):
            if (x - cx) * (x - cx) + (y - cy) * (y - cy) <= rr:
                _set_pixel(channels, width, height, x, y, rgba)


def _draw_ellipse(channels: dict[str, bytearray], width: int, height: int, rx: int, ry: int, cx: int, cy: int, rgba: tuple[int, int, int, int]) -> None:
    if rx <= 0 or ry <= 0:
        return
    for y in range(cy - ry, cy + ry + 1):
        for x in range(cx - rx, cx + rx + 1):
            if ((x - cx) ** 2) / (rx * rx) + ((y - cy) ** 2) / (ry * ry) <= 1.0:
                _set_pixel(channels, width, height, x, y, rgba)


def _draw_triangle(channels: dict[str, bytearray], width: int, height: int, values: tuple[int, ...], rgba: tuple[int, int, int, int]) -> None:
    x1, y1, x2, y2, x3, y3 = values
    min_x = min(x1, x2, x3)
    max_x = max(x1, x2, x3)
    min_y = min(y1, y2, y3)
    max_y = max(y1, y2, y3)
    area = _edge(x1, y1, x2, y2, x3, y3)
    if area == 0:
        return
    for y in range(min_y, max_y + 1):
        for x in range(min_x, max_x + 1):
            px = x + 0.5
            py = y + 0.5
            w0 = _edge(x2, y2, x3, y3, px, py)
            w1 = _edge(x3, y3, x1, y1, px, py)
            w2 = _edge(x1, y1, x2, y2, px, py)
            if (w0 >= 0 and w1 >= 0 and w2 >= 0) or (w0 <= 0 and w1 <= 0 and w2 <= 0):
                _set_pixel(channels, width, height, x, y, rgba)


def _edge(x1: float, y1: float, x2: float, y2: float, x3: float, y3: float) -> float:
    return (x3 - x1) * (y2 - y1) - (y3 - y1) * (x2 - x1)


def _set_pixel(channels: dict[str, bytearray], width: int, height: int, x: int, y: int, rgba: tuple[int, int, int, int]) -> None:
    if x < 0 or x >= width or y < 0 or y >= height:
        return
    idx = y * width + x
    r, g, b, a = rgba
    channels["r"][idx] = r
    channels["g"][idx] = g
    channels["b"][idx] = b
    channels["a"][idx] = a


def _sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _api_url(base: str | None, path: str) -> str:
    if not base:
        raise ValueError("base_url is required")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)
