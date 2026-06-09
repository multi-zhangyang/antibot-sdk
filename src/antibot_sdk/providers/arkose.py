from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

PROVIDER = "arkose"
CAPABILITY = "arkose_bda_token"
CAPTCHA_TYPE = "arkose_funcaptcha_bda_token"
DEFAULT_SURL = "https://client-api.arkoselabs.com"
DEFAULT_CAPI_VERSION = "1.5.5"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


@dataclass(frozen=True, slots=True)
class ArkoseTokenInfo:
    token: str
    fields: dict[str, str]

    @property
    def session_id(self) -> str:
        return self.fields.get("r", "")

    @property
    def public_key(self) -> str:
        return self.fields.get("pk", "")

    @property
    def surl(self) -> str:
        return self.fields.get("surl", "")

    @property
    def analytics_tier(self) -> str:
        return self.fields.get("at", "")

    @property
    def suppressed(self) -> bool:
        return self.fields.get("sup") == "1"


@dataclass(frozen=True, slots=True)
class ArkosePublicKeyRequest:
    url: str
    headers: dict[str, str]
    body: dict[str, str]
    form: str
    bda: str


@dataclass(frozen=True, slots=True)
class ArkoseTokenResponse:
    raw: dict[str, Any]
    token: str
    token_info: ArkoseTokenInfo | None
    challenge_url: str = ""
    challenge_url_cdn: str = ""
    mbio: bool | None = None
    kbio: bool | None = None
    tbio: bool | None = None


BASE_FINGERPRINT: dict[str, Any] = {
    "DNT": "unknown",
    "L": "en-US",
    "D": 24,
    "PR": 1,
    "S": [1920, 1080],
    "AS": [1920, 1040],
    "TO": 0,
    "SS": True,
    "LS": True,
    "IDB": True,
    "B": False,
    "ODB": True,
    "CPUC": "unknown",
    "PK": "Win32",
    "CFP": "canvas winding:yes~canvas fp:data:image/png;base64,fixture",
    "FR": False,
    "FOS": False,
    "FB": False,
    "JSF": ["Arial", "Calibri", "Consolas", "Courier New", "Segoe UI", "Times New Roman"],
    "P": [
        "Chrome PDF Plugin::Portable Document Format::application/x-google-chrome-pdf~pdf",
        "Chrome PDF Viewer::::application/pdf~pdf",
        "Native Client::::application/x-nacl~,application/x-pnacl~",
    ],
    "T": [0, False, False],
    "H": 8,
    "SWF": False,
}

BASE_ENHANCED_FP: dict[str, Any] = {
    "webgl_extensions": "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_filter_anisotropic;OES_element_index_uint;OES_standard_derivatives;OES_texture_float;OES_vertex_array_object;WEBGL_debug_renderer_info;WEBGL_depth_texture;WEBGL_lose_context",
    "webgl_extensions_hash": "",
    "webgl_renderer": "WebKit WebGL",
    "webgl_vendor": "WebKit",
    "webgl_version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
    "webgl_shading_language_version": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
    "webgl_aliased_line_width_range": "[1, 1]",
    "webgl_aliased_point_size_range": "[1, 1023]",
    "webgl_antialiasing": "yes",
    "webgl_bits": "8,8,24,8,8,0",
    "webgl_max_params": "16,64,16384,4096,8192,32,8192,31,16,32,4096",
    "webgl_max_viewport_dims": "[8192, 8192]",
    "webgl_unmasked_vendor": "Google Inc. (Google)",
    "webgl_unmasked_renderer": "ANGLE (Google, Vulkan 1.3.0, SwiftShader driver)",
    "webgl_hash_webgl": "",
    "user_agent_data_brands": "Chromium,Google Chrome,Not=A?Brand",
    "user_agent_data_mobile": None,
    "navigator_connection_downlink": None,
    "navigator_connection_downlink_max": None,
    "network_info_rtt": None,
    "network_info_save_data": False,
    "network_info_rtt_type": None,
    "screen_pixel_depth": 24,
    "navigator_device_memory": 8,
    "navigator_languages": "en-US,en",
    "window_inner_width": 1920,
    "window_inner_height": 947,
    "window_outer_width": 1920,
    "window_outer_height": 1040,
    "browser_detection_firefox": False,
    "browser_detection_brave": False,
    "audio_codecs": '{"ogg":"probably","mp3":"probably","wav":"probably","m4a":"maybe","aac":"probably"}',
    "video_codecs": '{"ogg":"probably","h264":"probably","webm":"probably","mpeg4v":"","mpeg4a":"","theora":""}',
    "media_query_dark_mode": False,
    "headless_browser_phantom": False,
    "headless_browser_selenium": False,
    "headless_browser_nightmare_js": False,
    "document__referrer": "",
    "window__ancestor_origins": [],
    "window__tree_index": [0],
    "window__tree_structure": "[[]]",
    "window__location_href": "",
    "client_config__sitedata_location_href": "",
    "client_config__surl": DEFAULT_SURL,
    "client_config__language": None,
    "navigator_battery_charging": True,
    "audio_fingerprint": "124.04347527516074",
}


def arkose_encrypt(data: str, key: str, *, salt: str | bytes | None = None) -> str:
    salt_bytes = _coerce_salt(salt)
    salted = b""
    dx = b""
    key_bytes = key.encode("utf-8")
    for _ in range(3):
        dx = hashlib.md5(dx + key_bytes + salt_bytes).digest()
        salted += dx
    cipher = AES.new(salted[:32], AES.MODE_CBC, salted[32:48])
    encrypted = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    return json.dumps(
        {
            "ct": base64.b64encode(encrypted).decode("ascii"),
            "iv": salted[32:48].hex(),
            "s": salt_bytes.hex(),
        },
        separators=(",", ":"),
    )


def arkose_decrypt(payload: str | dict[str, Any], key: str) -> str:
    data = json.loads(payload) if isinstance(payload, str) else payload
    salt = bytes.fromhex(str(data["s"]))
    salted = b""
    dx = b""
    key_bytes = key.encode("utf-8")
    for _ in range(3):
        dx = hashlib.md5(dx + key_bytes + salt).digest()
        salted += dx
    cipher = AES.new(salted[:32], AES.MODE_CBC, bytes.fromhex(str(data["iv"])))
    return unpad(cipher.decrypt(base64.b64decode(str(data["ct"]))), AES.block_size).decode("utf-8")


def arkose_time_key(user_agent: str, *, now: int | float | None = None) -> str:
    ts = int(time.time() if now is None else now)
    return user_agent + str(ts - (ts % 21600))


def arkose_cfp_hash(value: str) -> int:
    out = 0
    for char in value:
        out = ((out << 5) - out + ord(char)) & 0xFFFFFFFF
    if out >= 0x80000000:
        out -= 0x100000000
    return out


def arkose_x64hash128(value: str, seed: int = 0) -> str:
    data = bytes(ord(char) & 0xFF for char in value)
    length = len(data)
    nblocks = length // 16
    h1 = seed & 0xFFFFFFFFFFFFFFFF
    h2 = seed & 0xFFFFFFFFFFFFFFFF
    c1 = 0x87C37B91114253D5
    c2 = 0x4CF5AD432745937F
    mask = 0xFFFFFFFFFFFFFFFF

    for block in range(nblocks):
        chunk = data[block * 16 : block * 16 + 16]
        k1 = int.from_bytes(chunk[:8], "little")
        k2 = int.from_bytes(chunk[8:], "little")
        k1 = (k1 * c1) & mask
        k1 = _rotl64(k1, 31)
        k1 = (k1 * c2) & mask
        h1 ^= k1
        h1 = _rotl64(h1, 27)
        h1 = (h1 + h2) & mask
        h1 = (h1 * 5 + 0x52DCE729) & mask
        k2 = (k2 * c2) & mask
        k2 = _rotl64(k2, 33)
        k2 = (k2 * c1) & mask
        h2 ^= k2
        h2 = _rotl64(h2, 31)
        h2 = (h2 + h1) & mask
        h2 = (h2 * 5 + 0x38495AB5) & mask

    tail = data[nblocks * 16 :]
    k1 = 0
    k2 = 0
    for index, byte in enumerate(tail[:8]):
        k1 ^= byte << (index * 8)
    for index, byte in enumerate(tail[8:]):
        k2 ^= byte << (index * 8)
    if k2:
        k2 = (k2 * c2) & mask
        k2 = _rotl64(k2, 33)
        k2 = (k2 * c1) & mask
        h2 ^= k2
    if k1:
        k1 = (k1 * c1) & mask
        k1 = _rotl64(k1, 31)
        k1 = (k1 * c2) & mask
        h1 ^= k1

    h1 ^= length
    h2 ^= length
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    h1 = _fmix64(h1)
    h2 = _fmix64(h2)
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    return f"{h1:016x}{h2:016x}"


def arkose_prepare_f(fingerprint: dict[str, Any]) -> str:
    parts = []
    for value in fingerprint.values():
        parts.append(";".join(str(v) for v in value) if isinstance(value, list) else str(value))
    return "~~~".join(parts)


def arkose_prepare_fe(fingerprint: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in fingerprint.items():
        if key == "CFP":
            out.append(f"{key}:{arkose_cfp_hash(str(value))}")
        elif key == "P" and isinstance(value, list):
            out.append(f"{key}:{','.join(str(v).split('::', 1)[0] for v in value)}")
        else:
            out.append(f"{key}:{value}")
    return out


def arkose_build_enhanced_fp(
    fingerprint: dict[str, Any],
    *,
    user_agent: str,
    pkey: str,
    surl: str = DEFAULT_SURL,
    site: str | None = None,
    language: str | None = "en",
) -> list[dict[str, Any]]:
    enhanced = dict(BASE_ENHANCED_FP)
    enhanced["screen_pixel_depth"] = fingerprint.get("D", 24)
    enhanced["navigator_languages"] = fingerprint.get("L", "en-US")
    screen = fingerprint.get("S") if isinstance(fingerprint.get("S"), list) else [1920, 1080]
    enhanced["window_outer_width"] = screen[0]
    enhanced["window_outer_height"] = screen[1]
    enhanced["window_inner_width"] = screen[0]
    enhanced["window_inner_height"] = max(0, int(screen[1]) - 83)
    enhanced["browser_detection_firefox"] = "Firefox/" in user_agent
    enhanced["browser_detection_brave"] = "Brave/" in user_agent
    enhanced["client_config__language"] = language or None
    enhanced["client_config__surl"] = surl
    enhanced["window__location_href"] = (
        f"{surl}/v2/{pkey}/{DEFAULT_CAPI_VERSION}/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html"
    )
    if site:
        enhanced["document__referrer"] = site
        enhanced["window__ancestor_origins"] = [site]
        enhanced["client_config__sitedata_location_href"] = site
    enhanced["webgl_extensions_hash"] = arkose_x64hash128(str(enhanced["webgl_extensions"]), 0)
    webgl_material = ",".join(str(v) for k, v in enhanced.items() if k.startswith("webgl_") and k != "webgl_hash_webgl")
    enhanced["webgl_hash_webgl"] = arkose_x64hash128(webgl_material, 0)
    return [{"key": key, "value": value} for key, value in enhanced.items()]


def arkose_build_bda(
    *,
    pkey: str,
    user_agent: str = DEFAULT_USER_AGENT,
    surl: str = DEFAULT_SURL,
    site: str | None = None,
    language: str = "en",
    fingerprint: dict[str, Any] | None = None,
    now: int | float | None = None,
    salt: str | bytes | None = None,
    rng: random.Random | None = None,
) -> str:
    fp = dict(BASE_FINGERPRINT)
    if fingerprint:
        fp.update(fingerprint)
    fe = arkose_prepare_fe(fp)
    rnd = rng or random.SystemRandom()
    bda = [
        {"key": "api_type", "value": "js"},
        {"key": "p", "value": 1},
        {"key": "f", "value": arkose_x64hash128(arkose_prepare_f(fp), 31)},
        {"key": "n", "value": base64.b64encode(str(int(time.time() if now is None else now)).encode()).decode()},
        {"key": "wh", "value": f"{_rand_hex(rnd)}|{_rand_hex(rnd)}"},
        {
            "key": "enhanced_fp",
            "value": arkose_build_enhanced_fp(
                fp,
                user_agent=user_agent,
                pkey=pkey,
                surl=surl,
                site=site,
                language=language,
            ),
        },
        {"key": "fe", "value": fe},
        {"key": "ife_hash", "value": arkose_x64hash128(", ".join(fe), 38)},
        {"key": "cs", "value": 1},
        {"key": "jsbd", "value": json.dumps({"HL": 4, "DT": "", "NWD": "false", "DOTO": 1, "DMTO": 1}, separators=(",", ":"))},
    ]
    encrypted = arkose_encrypt(json.dumps(bda, separators=(",", ":")), arkose_time_key(user_agent, now=now), salt=salt)
    return base64.b64encode(encrypted.encode("utf-8")).decode("ascii")


def arkose_decode_bda(bda: str, *, user_agent: str = DEFAULT_USER_AGENT, now: int | float | None = None) -> list[dict[str, Any]]:
    encrypted = base64.b64decode(bda).decode("utf-8")
    decoded = json.loads(arkose_decrypt(encrypted, arkose_time_key(user_agent, now=now)))
    if not isinstance(decoded, list):
        raise ValueError("Arkose BDA must decode to a list")
    return decoded


def arkose_build_public_key_request(
    *,
    pkey: str,
    surl: str = DEFAULT_SURL,
    site: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    language: str = "en",
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    rnd: str | None = None,
    bda: str | None = None,
    now: int | float | None = None,
    salt: str | bytes | None = None,
) -> ArkosePublicKeyRequest:
    if not pkey:
        raise ValueError("Arkose public key is required")
    req_headers = {
        "User-Agent": user_agent,
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "sec-fetch-mode": "cors",
    }
    if headers:
        for key, value in headers.items():
            if str(key).lower() == "user-agent":
                req_headers["User-Agent"] = str(value)
            else:
                req_headers[str(key)] = str(value)
    effective_user_agent = req_headers["User-Agent"]
    if site:
        req_headers.setdefault("Origin", surl)
        req_headers.setdefault(
            "Referer",
            f"{surl}/v2/{pkey}/{DEFAULT_CAPI_VERSION}/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html",
        )
    final_bda = bda or arkose_build_bda(
        pkey=pkey,
        user_agent=effective_user_agent,
        surl=surl,
        site=site,
        language=language,
        now=now,
        salt=salt,
    )
    body: dict[str, str] = {
        "bda": final_bda,
        "public_key": pkey,
        "userbrowser": effective_user_agent,
        "capi_version": DEFAULT_CAPI_VERSION,
        "capi_mode": "inline",
        "style_theme": "default",
        "rnd": rnd or str(random.random()),
        "language": language,
    }
    if site:
        body["site"] = _site_origin(site)
    for key, value in (data or {}).items():
        body[f"data[{key}]"] = str(value)
    return ArkosePublicKeyRequest(
        url=urljoin(surl.rstrip("/") + "/", f"fc/gt2/public_key/{pkey}"),
        headers=req_headers,
        body=body,
        form=urlencode(body),
        bda=final_bda,
    )


def parse_arkose_token(token: str | dict[str, Any]) -> ArkoseTokenInfo:
    raw = token.get("token", "") if isinstance(token, dict) else str(token)
    text = raw[6:] if raw.startswith("token=") else raw
    fields = {key: value for key, value in parse_qsl(text.replace("|", "&"), keep_blank_values=True)}
    if text and "token" not in fields:
        fields["token"] = text.split("|", 1)[0]
    return ArkoseTokenInfo(token=fields.get("token", text), fields=fields)


def parse_arkose_token_response(data: dict[str, Any] | str) -> ArkoseTokenResponse:
    parsed = json.loads(data) if isinstance(data, str) else data
    if not isinstance(parsed, dict):
        raise ValueError("Arkose token response must be a JSON object")
    token = str(parsed.get("token") or "")
    info = parse_arkose_token(token) if token else None
    return ArkoseTokenResponse(
        raw=parsed,
        token=token,
        token_info=info,
        challenge_url=str(parsed.get("challenge_url") or ""),
        challenge_url_cdn=str(parsed.get("challenge_url_cdn") or ""),
        mbio=_bool_or_none(parsed.get("mbio")),
        kbio=_bool_or_none(parsed.get("kbio")),
        tbio=_bool_or_none(parsed.get("tbio")),
    )


class ArkoseSolver:
    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        pkey: str,
        surl: str = DEFAULT_SURL,
        site: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        language: str = "en",
        data: dict[str, str] | None = None,
        data_json: str | dict[str, str] | None = None,
        bda: str | None = None,
        token_response_json: str | dict[str, Any] | None = None,
        submit: bool = False,
        timeout_sec: int = 15,
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        now: int | float | None = None,
        salt: str | None = None,
        output_dir: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        user_agent = user_agent or DEFAULT_USER_AGENT
        errors: list[str] = []
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "mode": "bda_token_primitive",
            "submit": submit,
            "surl": surl,
            "site": site,
            "pkey_present": bool(pkey),
            "proxy": redacted_proxy(proxy),
        }

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            raw["ok"] = ok
            raw["elapsedMs"] = elapsed_ms
            return CaptchaResult(
                provider=PROVIDER,
                ok=ok,
                captcha_type=CAPTCHA_TYPE,
                capability=CAPABILITY,
                ticket=ticket,
                verify_code=verify_code,
                elapsed_ms=elapsed_ms,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            merged_data = _load_data(data, data_json)
            request = arkose_build_public_key_request(
                pkey=pkey,
                surl=surl,
                site=site,
                user_agent=user_agent,
                language=language,
                data=merged_data,
                headers=headers,
                bda=bda,
                now=now,
                salt=salt,
            )
            raw["request"] = {
                "url": request.url,
                "bodyKeys": sorted(request.body),
                "formPrefix": request.form[:240],
            }
            diagnostics["bda_length"] = len(request.bda)
            diagnostics["request_body_keys"] = sorted(request.body)

            token_response: ArkoseTokenResponse | None = None
            if token_response_json is not None:
                token_response = parse_arkose_token_response(_load_json_arg(token_response_json))
                raw["tokenResponse"] = token_response.raw
            elif submit:
                resp = requests.post(
                    request.url,
                    data=request.form.encode("utf-8"),
                    headers=request.headers,
                    timeout=timeout_sec,
                    proxies=parse_proxy(proxy),
                )
                raw["submitResponse"] = {
                    "status": resp.status_code,
                    "url": resp.url,
                    "headers": dict(resp.headers),
                    "bodyPrefix": resp.text[:500],
                }
                if not 200 <= resp.status_code < 400:
                    errors.append(f"Arkose public_key endpoint HTTP {resp.status_code}")
                    return finish(ok=False, ticket=request.bda, verify_code=str(resp.status_code))
                token_response = parse_arkose_token_response(resp.text)
                raw["tokenResponse"] = token_response.raw

            if token_response is None:
                raw["bda"] = request.bda
                _write_artifact(output_dir, raw)
                return finish(ok=True, ticket=request.bda, verify_code="bda_built")

            info = token_response.token_info
            diagnostics.update(
                {
                    "token_present": bool(token_response.token),
                    "session_id": info.session_id if info else "",
                    "suppressed": bool(info and info.suppressed),
                    "challenge_url_present": bool(token_response.challenge_url or token_response.challenge_url_cdn),
                    "mbio": token_response.mbio,
                    "kbio": token_response.kbio,
                    "tbio": token_response.tbio,
                }
            )
            _write_artifact(output_dir, raw)
            return finish(
                ok=bool(token_response.token),
                ticket=token_response.token or request.bda,
                verify_code="token" if token_response.token else "missing_token",
            )
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            _write_artifact(output_dir, raw)
            return finish(ok=False)


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF


def _fmix64(value: int) -> int:
    value ^= value >> 33
    value = (value * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 33
    value = (value * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 33
    return value


def _coerce_salt(value: str | bytes | None) -> bytes:
    if value is None:
        return bytes(random.SystemRandom().choice(b"abcdefghijklmnopqrstuvwxyz") for _ in range(8))
    if isinstance(value, bytes):
        raw = value
    else:
        raw = value.encode("utf-8")
    if len(raw) != 8:
        raise ValueError("Arkose AES salt must be exactly 8 bytes/lowercase letters")
    return raw


def _rand_hex(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(32))


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return bool(value)


def _site_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return value.rstrip("/")


def _load_json_arg(value: str | dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return value
    text = value.strip()
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8").strip()
    return json.loads(text)


def _load_data(data: dict[str, str] | None, data_json: str | dict[str, str] | None) -> dict[str, str]:
    out = {str(k): str(v) for k, v in (data or {}).items()}
    if data_json is not None:
        parsed = _load_json_arg(data_json)
        if not isinstance(parsed, dict):
            raise ValueError("Arkose data_json must be a JSON object")
        out.update({str(k): str(v) for k, v in parsed.items()})
    return out


def _write_artifact(output_dir: str | None, raw: dict[str, Any]) -> None:
    if not output_dir:
        return
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "arkose_run.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = [
    "CAPABILITY",
    "CAPTCHA_TYPE",
    "DEFAULT_CAPI_VERSION",
    "DEFAULT_SURL",
    "DEFAULT_USER_AGENT",
    "PROVIDER",
    "ArkosePublicKeyRequest",
    "ArkoseSolver",
    "ArkoseTokenInfo",
    "ArkoseTokenResponse",
    "arkose_build_bda",
    "arkose_build_enhanced_fp",
    "arkose_build_public_key_request",
    "arkose_cfp_hash",
    "arkose_decode_bda",
    "arkose_decrypt",
    "arkose_encrypt",
    "arkose_prepare_f",
    "arkose_prepare_fe",
    "arkose_time_key",
    "arkose_x64hash128",
    "parse_arkose_token",
    "parse_arkose_token_response",
]
