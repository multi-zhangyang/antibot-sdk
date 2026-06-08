from __future__ import annotations

import asyncio
import base64
import json
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

import cv2
import numpy as np
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class AJCaptchaEndpoints:
    base_url: str
    get_path: str = "/captcha/get"
    check_path: str = "/captcha/check"
    verify_path: str | None = None

    def url(self, path: str | None) -> str | None:
        if not path:
            return None
        if path.startswith("http://") or path.startswith("https://"):
            return path
        # Treat base_url as an API prefix, not as an HTML document path.  This
        # keeps both `http://host` + `/captcha/get` and
        # `http://host/captcha-api` + `/captcha/get` useful.
        return urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))

    @property
    def get_url(self) -> str:
        return str(self.url(self.get_path))

    @property
    def check_url(self) -> str:
        return str(self.url(self.check_path))

    @property
    def verification_url(self) -> str | None:
        return self.url(self.verify_path)


def _js_number(value: float | int) -> str:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite coordinate: {value!r}")
    rounded = round(number)
    if abs(number - rounded) < 1e-6:
        return str(int(rounded))
    return f"{number:.4f}".rstrip("0").rstrip(".")


def build_ajcaptcha_point_json(x: float | int, y: float | int = 5) -> str:
    """Return the compact JSON shape used by AJ-Captcha frontends.

    JS `JSON.stringify({x: 123, y: 5.0})` does not keep spaces or a `.0`
    suffix.  Keeping that formatting matters because the second-stage
    `captchaVerification` is AES(token + '---' + plaintext_point_json).
    """

    return f'{{"x":{_js_number(x)},"y":{_js_number(y)}}}'


def _validate_aes_key(secret_key: str) -> bytes:
    key = secret_key.encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise ValueError("AJ-Captcha AES key must be 16/24/32 UTF-8 bytes")
    return key


def encrypt_ajcaptcha_text(plain_text: str, secret_key: str | None) -> str:
    """AES/ECB/PKCS7 + base64, matching AJ-Captcha Java/CryptoJS code."""

    if not secret_key:
        return plain_text
    cipher = AES.new(_validate_aes_key(secret_key), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_ajcaptcha_text(cipher_text: str, secret_key: str | None) -> str:
    if not secret_key:
        return cipher_text
    cipher = AES.new(_validate_aes_key(secret_key), AES.MODE_ECB)
    data = base64.b64decode(cipher_text)
    return unpad(cipher.decrypt(data), AES.block_size).decode("utf-8")


def _decode_image_base64(value: str) -> bytes:
    if not value:
        raise ValueError("empty image base64")
    text = value.strip()
    if "," in text and text[:64].lower().startswith("data:image"):
        text = text.split(",", 1)[1]
    return base64.b64decode(text)


def _image_size(image_bytes: bytes) -> dict[str, int]:
    img = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("failed to decode image")
    return {"width": int(img.shape[1]), "height": int(img.shape[0])}


def _match_best_in_y_band(
    *,
    source: np.ndarray,
    template: np.ndarray,
    method_name: str,
    trim_x0: int,
    trim_y0: int,
    expected_y: int,
    y_tolerance: int,
    candidates: list[dict[str, Any]],
) -> None:
    if template.size == 0 or source.size == 0 or not np.any(template):
        return
    if source.shape[0] < template.shape[0] or source.shape[1] < template.shape[1]:
        return
    res = cv2.matchTemplate(source, template, cv2.TM_CCORR_NORMED)
    if res.size == 0:
        return
    ylo = max(0, expected_y - y_tolerance)
    yhi = min(res.shape[0] - 1, expected_y + y_tolerance)
    if yhi < ylo:
        return
    band = res[ylo : yhi + 1, :]
    _min_val, score, _min_loc, loc = cv2.minMaxLoc(band)
    if not math.isfinite(float(score)):
        return
    match_x, match_y = int(loc[0]), int(loc[1]) + ylo
    candidates.append(
        {
            "name": method_name,
            "score": float(score),
            "distance_x": int(match_x - trim_x0),
            "distance_y": int(match_y - trim_y0),
            "match_x": match_x,
            "match_y": match_y,
        }
    )


def detect_ajcaptcha_block_gap(
    original_bytes: bytes,
    jigsaw_bytes: bytes,
    *,
    y_tolerance: int = 8,
) -> dict[str, Any]:
    """Locate AJ-Captcha `blockPuzzle` gap from `/captcha/get` images.

    The background returned by AJ-Captcha has the real puzzle region blurred and
    outlined in white.  The jigsaw image keeps the original pixels and, more
    importantly, the exact alpha mask.  Matching the alpha-mask edge against
    white/edge maps is more stable than dragging a browser slider and also
    avoids confusing unrelated background texture with the true gap.
    """

    bg_arr = np.frombuffer(original_bytes, dtype=np.uint8)
    jig_arr = np.frombuffer(jigsaw_bytes, dtype=np.uint8)
    bg = cv2.imdecode(bg_arr, cv2.IMREAD_COLOR)
    jigsaw = cv2.imdecode(jig_arr, cv2.IMREAD_UNCHANGED)
    if bg is None or jigsaw is None:
        raise ValueError("failed to decode AJ-Captcha images")
    if jigsaw.ndim != 3:
        raise ValueError("AJ-Captcha jigsaw image must be RGB/RGBA")

    if jigsaw.shape[2] >= 4:
        alpha = jigsaw[:, :, 3]
        mask = ((alpha > 30).astype(np.uint8)) * 255
    else:
        gray_jigsaw = cv2.cvtColor(jigsaw[:, :, :3], cv2.COLOR_BGR2GRAY)
        # Fallback for non-alpha ports: most generated jigsaw images use black
        # or transparent-looking padding, so non-dark pixels are the cutout.
        mask = ((gray_jigsaw > 8).astype(np.uint8)) * 255

    ys, xs = np.where(mask > 0)
    if len(xs) == 0 or len(ys) == 0:
        raise ValueError("AJ-Captcha jigsaw alpha mask is empty")

    trim_x0, trim_x1 = int(xs.min()), int(xs.max()) + 1
    trim_y0, trim_y1 = int(ys.min()), int(ys.max()) + 1
    tpl_mask = mask[trim_y0:trim_y1, trim_x0:trim_x1]
    tpl_edge = cv2.Canny(tpl_mask, 40, 140)
    kernel2 = np.ones((2, 2), np.uint8)
    kernel3 = np.ones((3, 3), np.uint8)

    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(bg, cv2.COLOR_BGR2HSV)
    bg_edge = cv2.Canny(gray, 35, 125)
    white = (((gray > 220) & (hsv[:, :, 1] < 95)).astype(np.uint8)) * 255
    white_edge = cv2.Canny(white, 20, 80)

    maps: dict[str, np.ndarray] = {
        "white": white,
        "white_dilate2": cv2.dilate(white, kernel2),
        "white_edge": white_edge,
        "edge": bg_edge,
        "edge_dilate2": cv2.dilate(bg_edge, kernel2),
        "edge_dilate3": cv2.dilate(bg_edge, kernel3),
    }

    expected_y = trim_y0
    candidates: list[dict[str, Any]] = []
    for name, source in maps.items():
        _match_best_in_y_band(
            source=source,
            template=tpl_edge,
            method_name=f"{name}_alpha_edge",
            trim_x0=trim_x0,
            trim_y0=trim_y0,
            expected_y=expected_y,
            y_tolerance=max(2, y_tolerance),
            candidates=candidates,
        )

    # Broader fallback for implementations that crop/resize the jigsaw image
    # differently.  Keep it separate and let scoring pick it only if the normal
    # vertical alignment does not produce a strong candidate.
    if candidates and max(float(c["score"]) for c in candidates) < 0.20:
        for name, source in ("edge_global", bg_edge), ("white_global", white):
            _match_best_in_y_band(
                source=source,
                template=tpl_edge,
                method_name=f"{name}_alpha_edge",
                trim_x0=trim_x0,
                trim_y0=trim_y0,
                expected_y=expected_y,
                y_tolerance=max(bg.shape[0], jigsaw.shape[0]),
                candidates=candidates,
            )

    # Texture fallback: useful when the hole outline is very faint.  It is not
    # the first choice because the real hole area is intentionally blurred.
    try:
        template_rgb = jigsaw[:, :, :3][trim_y0:trim_y1, trim_x0:trim_x1]
        color_res = cv2.matchTemplate(bg, template_rgb, cv2.TM_CCORR_NORMED, mask=tpl_mask)
        ylo = max(0, expected_y - max(2, y_tolerance))
        yhi = min(color_res.shape[0] - 1, expected_y + max(2, y_tolerance))
        band = color_res[ylo : yhi + 1, :]
        _min_val, score, _min_loc, loc = cv2.minMaxLoc(band)
        if math.isfinite(float(score)):
            match_x, match_y = int(loc[0]), int(loc[1]) + ylo
            candidates.append(
                {
                    "name": "color_template",
                    "score": float(score),
                    "distance_x": int(match_x - trim_x0),
                    "distance_y": int(match_y - trim_y0),
                    "match_x": match_x,
                    "match_y": match_y,
                }
            )
    except Exception:
        pass

    if not candidates:
        raise ValueError("AJ-Captcha gap detector produced no candidates")

    max_x = max(0, int(bg.shape[1] - jigsaw.shape[1] + 3))
    aligned = [
        c
        for c in candidates
        if 0 <= int(c["distance_x"]) <= max_x and abs(int(c["distance_y"])) <= max(3, y_tolerance)
    ]
    pool = aligned or [c for c in candidates if 0 <= int(c["distance_x"]) <= max_x] or candidates

    def rank(c: dict[str, Any]) -> tuple[float, float, int]:
        name = str(c.get("name") or "")
        # Edge/white alpha matching is the protocol-specific signal; raw color
        # gets a slight penalty because it can lock onto repeated scenery.
        family_bonus = 0.08 if "alpha_edge" in name else -0.08
        return (float(c["score"]) + family_bonus, -abs(int(c["distance_y"])), -int(c["distance_x"]))

    chosen = max(pool, key=rank)
    return {
        "distance_x": int(chosen["distance_x"]),
        "distance_y": int(chosen["distance_y"]),
        "match_x": int(chosen["match_x"]),
        "match_y": int(chosen["match_y"]),
        "score": float(chosen["score"]),
        "method": chosen["name"],
        "candidates": sorted(candidates, key=lambda c: float(c["score"]), reverse=True)[:12],
        "bg_size": {"width": int(bg.shape[1]), "height": int(bg.shape[0])},
        "jigsaw_size": {"width": int(jigsaw.shape[1]), "height": int(jigsaw.shape[0])},
        "trim": {"x0": trim_x0, "y0": trim_y0, "x1": trim_x1, "y1": trim_y1},
    }


def _redact_large_fields(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in {"originalImageBase64", "jigsawImageBase64"} and isinstance(v, str):
                out[k] = f"<base64:{len(v)}>"
            elif k == "secretKey" and v:
                out[k] = "<present>"
            else:
                out[k] = _redact_large_fields(v)
        return out
    if isinstance(value, list):
        return [_redact_large_fields(v) for v in value]
    return value


def _response_json(resp: requests.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except Exception as e:
        raise ValueError(f"non-json response status={resp.status_code}") from e
    if not isinstance(data, dict):
        raise ValueError("response JSON is not an object")
    return data


def _response_ok(data: dict[str, Any]) -> bool:
    if str(data.get("repCode") or "") == "0000":
        return True
    if data.get("success") is True or data.get("successRes") is True:
        return True
    if data.get("error") is False and data.get("repCode") in (None, ""):
        return True
    return False


def _extract_rep_data(data: dict[str, Any]) -> dict[str, Any]:
    rep_data = data.get("repData")
    if isinstance(rep_data, dict):
        return rep_data
    # Some ports return the payload itself rather than wrapping it in repData.
    if any(k in data for k in ("originalImageBase64", "jigsawImageBase64", "token", "secretKey")):
        return data
    return {}


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


class AJCaptchaSolver:
    """AJ-Captcha / Anji `blockPuzzle` protocol solver.

    This provider does not launch a browser.  It replays the documented
    `/captcha/get` -> `/captcha/check` flow, detects the gap from returned image
    bytes, then returns the second-stage `captchaVerification` value that the
    normal frontend would submit to the business API.
    """

    def __init__(self, *, session_factory: Callable[[], requests.Session] | None = None):
        self.session_factory = session_factory or requests.Session

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        max_attempts = max(1, int(kwargs.pop("max_attempts", 2) or 1))
        if max_attempts == 1:
            return await asyncio.to_thread(self._solve_sync, **kwargs)

        attempts: list[dict[str, Any]] = []
        last: CaptchaResult | None = None
        for attempt in range(1, max_attempts + 1):
            ret = await asyncio.to_thread(self._solve_sync, **kwargs)
            gap = ret.diagnostics.get("gap") if isinstance(ret.diagnostics, dict) else None
            attempts.append(
                {
                    "attempt": attempt,
                    "ok": ret.ok,
                    "verify_code": ret.verify_code,
                    "errors": ret.errors,
                    "point_source": ret.diagnostics.get("point_source"),
                    "submit_x": ret.diagnostics.get("submit_x"),
                    "gap_method": gap.get("method") if isinstance(gap, dict) else None,
                    "gap_score": gap.get("score") if isinstance(gap, dict) else None,
                }
            )
            ret.raw["attempt"] = attempt
            ret.raw["maxAttempts"] = max_attempts
            ret.raw["attempts"] = attempts
            ret.diagnostics["attempt"] = attempt
            ret.diagnostics["max_attempts"] = max_attempts
            ret.diagnostics["attempts"] = attempts
            if ret.ok:
                return ret
            last = ret
        assert last is not None
        return last

    def _solve_sync(
        self,
        *,
        base_url: str | None = None,
        target_url: str | None = None,
        get_path: str = "/captcha/get",
        check_path: str = "/captcha/check",
        verify_path: str | None = None,
        captcha_type: str = "blockPuzzle",
        client_uid: str | None = None,
        canonical_width: int = 310,
        point_y: int = 5,
        timeout_sec: int = 20,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        save_images: bool = True,
        min_score: float = 0.15,
        use_returned_point: bool = True,
        verify_after_check: bool = False,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        base = base_url or target_url
        raw: dict[str, Any] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "captchaType": captcha_type,
            "get": {},
            "check": {},
        }
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "base_url": base,
            "get_path": get_path,
            "check_path": check_path,
            "verify_path": verify_path,
            "captcha_type": captcha_type,
            "capability": "protocol_solver",
            "canonical_width": canonical_width,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
        }
        errors: list[str] = []
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(
            *,
            ok: bool,
            ticket: str | None = None,
            randstr: str | None = None,
            verify_code: str | None = None,
        ) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "ajcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="ajcaptcha",
                ok=ok,
                captcha_type="slider_protocol",
                capability="protocol_solver",
                ticket=ticket,
                randstr=randstr,
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        if not base:
            errors.append("base_url is required")
            return finish(ok=False)

        endpoints = AJCaptchaEndpoints(
            base_url=base,
            get_path=get_path,
            check_path=check_path,
            verify_path=verify_path,
        )
        diagnostics["get_url"] = endpoints.get_url
        diagnostics["check_url"] = endpoints.check_url
        diagnostics["verification_url"] = endpoints.verification_url

        req_headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "User-Agent": DEFAULT_USER_AGENT,
        }
        if headers:
            req_headers.update(headers)
        proxies = _requests_proxies(proxy_server)
        session = self.session_factory()

        try:
            get_payload: dict[str, Any] = {"captchaType": captcha_type}
            if client_uid:
                get_payload["clientUid"] = client_uid
            get_resp = session.post(
                endpoints.get_url,
                json=get_payload,
                headers=req_headers,
                timeout=timeout_sec,
                proxies=proxies,
            )
            get_data = _response_json(get_resp)
            raw["get"] = {
                "status": get_resp.status_code,
                "ok": _response_ok(get_data),
                "response": _redact_large_fields(get_data),
            }
            if not _response_ok(get_data):
                errors.append(str(get_data.get("repMsg") or get_data.get("message") or "captcha_get_failed"))
                return finish(ok=False, verify_code=str(get_data.get("repCode") or "") or None)

            rep_data = _extract_rep_data(get_data)
            token = str(rep_data.get("token") or "")
            secret_key = rep_data.get("secretKey") or ""
            if not token:
                errors.append("captcha get response has no token")
                return finish(ok=False, verify_code=str(get_data.get("repCode") or "") or None)

            point_source = "cv_gap"
            returned_point = rep_data.get("point") if isinstance(rep_data.get("point"), dict) else None
            original_b64 = rep_data.get("originalImageBase64")
            jigsaw_b64 = rep_data.get("jigsawImageBase64")
            if use_returned_point and returned_point and returned_point.get("x") is not None:
                submit_x = float(returned_point.get("x"))
                submit_y = float(returned_point.get("y", point_y))
                gap_info = {
                    "distance_x": submit_x,
                    "distance_y": 0,
                    "score": 1.0,
                    "method": "returned_point",
                }
                point_source = "returned_point"
            else:
                if not original_b64 or not jigsaw_b64:
                    errors.append("captcha get response has no image pair")
                    return finish(ok=False, randstr=token, verify_code=str(get_data.get("repCode") or "") or None)
                original_bytes = _decode_image_base64(str(original_b64))
                jigsaw_bytes = _decode_image_base64(str(jigsaw_b64))
                if output_root is not None and save_images:
                    ori_path = output_root / "ajcaptcha_original.png"
                    jig_path = output_root / "ajcaptcha_jigsaw.png"
                    ori_path.write_bytes(original_bytes)
                    jig_path.write_bytes(jigsaw_bytes)
                    artifacts["original"] = str(ori_path)
                    artifacts["jigsaw"] = str(jig_path)
                gap_info = detect_ajcaptcha_block_gap(original_bytes, jigsaw_bytes)
                bg_size = gap_info.get("bg_size") or _image_size(original_bytes)
                bg_width = int(bg_size["width"])
                detected_x = float(gap_info["distance_x"])
                submit_x = detected_x * float(canonical_width) / float(bg_width)
                submit_y = float(point_y)
                if float(gap_info.get("score") or 0.0) < min_score:
                    diagnostics.update(
                        {
                            "gap": gap_info,
                            "point_source": point_source,
                            "submit_x": submit_x,
                            "submit_y": submit_y,
                        }
                    )
                    errors.append(f"low_gap_confidence:{gap_info.get('score')}")
                    return finish(ok=False, randstr=token, verify_code=str(get_data.get("repCode") or "") or None)

            point_json = build_ajcaptcha_point_json(submit_x, submit_y)
            point_json_encrypted = encrypt_ajcaptcha_text(point_json, secret_key)
            captcha_verification = encrypt_ajcaptcha_text(f"{token}---{point_json}", secret_key)
            diagnostics.update(
                {
                    "token": token,
                    "secret_key_present": bool(secret_key),
                    "point_source": point_source,
                    "point_json": point_json,
                    "submit_x": submit_x,
                    "submit_y": submit_y,
                    "gap": gap_info,
                }
            )

            check_payload: dict[str, Any] = {
                "captchaType": captcha_type,
                "pointJson": point_json_encrypted,
                "token": token,
            }
            if client_uid:
                check_payload["clientUid"] = client_uid
            check_resp = session.post(
                endpoints.check_url,
                json=check_payload,
                headers=req_headers,
                timeout=timeout_sec,
                proxies=proxies,
            )
            check_data = _response_json(check_resp)
            raw["check"] = {
                "status": check_resp.status_code,
                "ok": _response_ok(check_data),
                "response": _redact_large_fields(check_data),
            }
            verify_code = str(check_data.get("repCode") or "") or None
            if not _response_ok(check_data):
                errors.append(str(check_data.get("repMsg") or check_data.get("message") or "captcha_check_failed"))
                return finish(ok=False, randstr=token, verify_code=verify_code)

            if verify_after_check and endpoints.verification_url:
                verify_payload = {"captchaVerification": captcha_verification}
                verify_resp = session.post(
                    endpoints.verification_url,
                    json=verify_payload,
                    headers=req_headers,
                    timeout=timeout_sec,
                    proxies=proxies,
                )
                verify_data = _response_json(verify_resp)
                raw["verify"] = {
                    "status": verify_resp.status_code,
                    "ok": _response_ok(verify_data),
                    "response": _redact_large_fields(verify_data),
                }
                if not _response_ok(verify_data):
                    errors.append(str(verify_data.get("repMsg") or verify_data.get("message") or "captcha_verify_failed"))
                    return finish(ok=False, ticket=captcha_verification, randstr=token, verify_code=str(verify_data.get("repCode") or "") or None)

            raw["token"] = token
            raw["pointJson"] = point_json
            raw["success"] = {"captchaVerification": captcha_verification, "token": token}
            return finish(ok=True, ticket=captcha_verification, randstr=token, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
