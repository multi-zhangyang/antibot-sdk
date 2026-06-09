from __future__ import annotations

import asyncio
import base64
import html
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

COOKIE_NAME = "acw_sc__v2"
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)
DEFAULT_SHUFFLE = (
    15,
    35,
    29,
    24,
    33,
    16,
    1,
    38,
    10,
    9,
    19,
    31,
    40,
    27,
    22,
    23,
    25,
    13,
    6,
    11,
    39,
    18,
    20,
    8,
    14,
    21,
    32,
    26,
    2,
    30,
    7,
    4,
    17,
    5,
    3,
    28,
    34,
    37,
    12,
    36,
)
DEFAULT_XOR_KEY = "3000176000856006061501533003690027800375"
_HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_NUMBER_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|\d+)")


@dataclass(frozen=True, slots=True)
class AcwScV2Challenge:
    arg1: str
    shuffle: tuple[int, ...] = DEFAULT_SHUFFLE
    xor_key: str = DEFAULT_XOR_KEY
    key_source: str = "static"
    array_name: str | None = None
    decoder_name: str | None = None
    rotation: int | None = None
    ciphers: tuple[str, ...] = ()
    decoder_keys: dict[int, str] = field(default_factory=dict)
    page_url: str | None = None
    raw_html: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def cookie_name(self) -> str:
        return COOKIE_NAME


@dataclass(frozen=True, slots=True)
class AcwScV2Solution:
    challenge: AcwScV2Challenge
    cookie_value: str
    elapsed_ms: int
    cookie_name: str = COOKIE_NAME

    @property
    def cookie_header(self) -> str:
        return f"{self.cookie_name}={self.cookie_value}"

    @property
    def ticket_payload(self) -> dict[str, Any]:
        return {
            "cookie_name": self.cookie_name,
            "cookie_value": self.cookie_value,
            "cookie_header": self.cookie_header,
        }


def extract_acw_arg1(html_text: str) -> str:
    code = extract_inline_javascript(html_text)
    for match in re.finditer(r"\b(?:var|let|const)\s+arg1\s*=\s*", code):
        literal = _read_js_string(code, match.end())
        if literal is not None:
            value, _ = literal
            return _validate_arg1(value)
    raise ValueError("ACW SC V2 challenge missing var arg1")


def extract_inline_javascript(html_text: str) -> str:
    text = str(html_text)
    scripts: list[str] = []
    for match in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", text, re.I | re.S):
        attrs = match.group(1) or ""
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        scripts.append(html.unescape(match.group(2)))
    return "\n".join(scripts) if scripts else html.unescape(text)


def parse_acwscv2_challenge(
    data: AcwScV2Challenge | dict[str, Any] | str,
    *,
    page_url: str | None = None,
) -> AcwScV2Challenge:
    if isinstance(data, AcwScV2Challenge):
        return _merge_page_url(data, page_url=page_url)
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("@"):
            return parse_acwscv2_challenge(
                Path(text[1:]).read_text(encoding="utf-8"),
                page_url=page_url,
            )
        if text.startswith("{"):
            return parse_acwscv2_challenge(json.loads(text), page_url=page_url)
        return parse_acwscv2_challenge_html(text, page_url=page_url)
    if not isinstance(data, dict):
        raise ValueError("ACW SC V2 challenge must be HTML, JSON object, @file, or dataclass")
    if "html" in data:
        return parse_acwscv2_challenge_html(
            str(data["html"]),
            page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
        )
    arg1 = _validate_arg1(data.get("arg1") or data.get("challenge") or "")
    shuffle = _validate_shuffle(data.get("shuffle") or data.get("shuffles") or DEFAULT_SHUFFLE)
    xor_key = _validate_xor_key(data.get("xor_key") or data.get("xorKey") or DEFAULT_XOR_KEY)
    return AcwScV2Challenge(
        arg1=arg1,
        shuffle=shuffle,
        xor_key=xor_key,
        key_source=str(data.get("key_source") or data.get("keySource") or "provided"),
        page_url=str(data.get("page_url") or data.get("pageUrl") or page_url or "") or None,
        raw=data,
    )


def parse_acwscv2_challenge_html(
    html_text: str,
    *,
    page_url: str | None = None,
    allow_static_fallback: bool = True,
) -> AcwScV2Challenge:
    text = str(html_text)
    code = extract_inline_javascript(text)
    arg1 = extract_acw_arg1(code)
    array_name, ciphers = _extract_cipher_array(code)
    rotation = _extract_rotation(code, array_name) if array_name and ciphers else None
    rotated = _rotate_left(ciphers, rotation or 0) if ciphers else []
    decoder_name, keys = _extract_decoder_keys(code)
    shuffle, shuffle_source = _extract_shuffle(code)
    xor_key = None
    key_source = "static"
    if len(rotated) > 3 and keys.get(3):
        try:
            xor_key = _rc4(_convert_cipher(rotated[3]), keys[3])
            xor_key = _validate_xor_key(xor_key)
            key_source = "dynamic"
        except Exception:
            xor_key = None
    if xor_key is None:
        if not allow_static_fallback:
            raise ValueError("ACW SC V2 challenge missing dynamic RC4 key material")
        xor_key = DEFAULT_XOR_KEY
        if shuffle_source == "static":
            key_source = "static"
        else:
            key_source = "static_key_dynamic_shuffle"
    return AcwScV2Challenge(
        arg1=arg1,
        shuffle=shuffle,
        xor_key=xor_key,
        key_source=key_source,
        array_name=array_name,
        decoder_name=decoder_name,
        rotation=rotation,
        ciphers=tuple(ciphers),
        decoder_keys=keys,
        page_url=page_url,
        raw_html=text,
        raw={
            "hasCookieMarker": COOKIE_NAME in text,
            "hasCipherArray": bool(ciphers),
            "shuffleSource": shuffle_source,
        },
    )


def solve_acwscv2_cookie(challenge: AcwScV2Challenge | dict[str, Any] | str) -> AcwScV2Solution:
    started = time.monotonic()
    item = parse_acwscv2_challenge(challenge)
    shuffled = unbox(item.arg1, item.shuffle)
    cookie_value = hex_xor(shuffled, item.xor_key)
    return AcwScV2Solution(
        challenge=item,
        cookie_value=_validate_cookie_value(cookie_value),
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def solve_acwscv2_value(challenge: AcwScV2Challenge | dict[str, Any] | str) -> str:
    return solve_acwscv2_cookie(challenge).cookie_value


def verify_acwscv2_solution(
    challenge: AcwScV2Challenge | dict[str, Any] | str,
    solution: AcwScV2Solution | dict[str, Any] | str,
) -> bool:
    try:
        expected = solve_acwscv2_cookie(challenge).cookie_value
        supplied = _solution_cookie_value(solution)
        return expected == supplied
    except Exception:
        return False


def unbox(value: str, shuffle: tuple[int, ...] | list[int]) -> str:
    src = str(value)
    out: list[str] = []
    for index in shuffle:
        pos = int(index) - 1
        if 0 <= pos < len(src):
            out.append(src[pos])
    return "".join(out)


def hex_xor(hex_str1: str, hex_str2: str) -> str:
    h1 = _validate_even_hex(hex_str1, "hex_str1")
    h2 = _validate_even_hex(hex_str2, "hex_str2")
    out: list[str] = []
    limit = min(len(h1), len(h2))
    for i in range(0, limit, 2):
        out.append(f"{int(h1[i : i + 2], 16) ^ int(h2[i : i + 2], 16):02x}")
    return "".join(out)


class AcwScV2Solver:
    """Protocol solver for ACW/Aliyun ``acw_sc__v2`` JavaScript cookie challenges."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_html: str | None = None,
        challenge_file: str | None = None,
        base_url: str | None = None,
        target_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        timeout_sec: int = DEFAULT_TIMEOUT,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "browser": "not_used",
            "base_url": base_url,
            "target_url": target_url,
            "submit_url": submit_url,
            "submit": submit,
            "timeout_sec": timeout_sec,
            "proxy": redacted_proxy(proxy_server),
            "user_agent": user_agent,
        }
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "acwscv2_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="acwscv2",
                ok=ok,
                captcha_type="aliyun_acw_sc_v2_js_cookie",
                capability="protocol_solver",
                ticket=ticket,
                randstr=diagnostics.get("arg1"),
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            proxies = _requests_proxies(proxy_server)
            session = requests.Session()
            request_headers = _request_headers(headers, user_agent=user_agent)
            session.headers.update(request_headers)
            challenge = self._load_challenge(
                challenge_html=challenge_html,
                challenge_file=challenge_file,
                base_url=base_url or target_url,
                timeout_sec=timeout_sec,
                session=session,
                proxies=proxies,
                raw=raw,
            )
            solution = solve_acwscv2_cookie(challenge)
            diagnostics.update(
                {
                    "arg1": challenge.arg1,
                    "key_source": challenge.key_source,
                    "array_name": challenge.array_name,
                    "decoder_name": challenge.decoder_name,
                    "rotation": challenge.rotation,
                    "shuffle_len": len(challenge.shuffle),
                    "cipher_count": len(challenge.ciphers),
                    "cookie_name": solution.cookie_name,
                    "cookie_value": solution.cookie_value,
                    "solve_ms": solution.elapsed_ms,
                    "page_url": challenge.page_url,
                }
            )
            raw["challenge"] = _challenge_raw(challenge)
            raw["solution"] = solution.ticket_payload
            ticket_payload = solution.ticket_payload
            verify_code = "solved"
            if submit:
                retry_url = submit_url or challenge.page_url or base_url or target_url
                if not retry_url:
                    errors.append("ACW SC V2 submit requested but submit_url/base_url/target_url is missing")
                    return finish(
                        ok=False,
                        ticket=json.dumps(ticket_payload, separators=(",", ":")),
                        verify_code=verify_code,
                    )
                submit_data = self._retry_with_cookie(
                    url=retry_url,
                    solution=solution,
                    session=session,
                    proxies=proxies,
                    timeout_sec=timeout_sec,
                    raw=raw,
                )
                diagnostics["submitted"] = True
                diagnostics["submit_status"] = submit_data["status"]
                diagnostics["blocked_again"] = submit_data["blocked_again"]
                if submit_data["status"] >= 400 or submit_data["blocked_again"]:
                    errors.append("ACW SC V2 retry did not clear challenge")
                    return finish(
                        ok=False,
                        ticket=json.dumps(ticket_payload, separators=(",", ":")),
                        verify_code="submit_failed",
                    )
                verify_code = "verified"
            return finish(ok=True, ticket=json.dumps(ticket_payload, separators=(",", ":")), verify_code=verify_code)
        except Exception as exc:
            raw["error"] = {"type": type(exc).__name__, "message": str(exc)}
            errors.append(str(exc))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge_html: str | None,
        challenge_file: str | None,
        base_url: str | None,
        timeout_sec: int,
        session: requests.Session,
        proxies: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> AcwScV2Challenge:
        if challenge_file:
            text = Path(challenge_file).read_text(encoding="utf-8")
            return parse_acwscv2_challenge_html(text, page_url=base_url)
        if challenge_html:
            text = Path(challenge_html[1:]).read_text(encoding="utf-8") if challenge_html.startswith("@") else challenge_html
            return parse_acwscv2_challenge_html(text, page_url=base_url)
        if not base_url:
            raise ValueError("ACW SC V2 solve requires challenge_html/challenge_file/base_url/target_url")
        resp = session.get(base_url, timeout=timeout_sec, proxies=proxies)
        raw["challengeResponse"] = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "bodyPrefix": resp.text[:160],
        }
        return parse_acwscv2_challenge_html(resp.text, page_url=resp.url or base_url)

    def _retry_with_cookie(
        self,
        *,
        url: str,
        solution: AcwScV2Solution,
        session: requests.Session,
        proxies: dict[str, str] | None,
        timeout_sec: int,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        session.cookies.set(solution.cookie_name, solution.cookie_value)
        resp = session.get(
            url,
            headers={"Cookie": solution.cookie_header},
            timeout=timeout_sec,
            proxies=proxies,
            allow_redirects=True,
        )
        data = {
            "status": resp.status_code,
            "url": resp.url,
            "contentType": resp.headers.get("content-type"),
            "blocked_again": is_acwscv2_challenge_html(resp.text),
            "bodyPrefix": resp.text[:120],
        }
        raw["submitResponse"] = data
        return data


def is_acwscv2_challenge_html(text: str) -> bool:
    body = str(text)
    return "arg1" in body and (COOKIE_NAME in body or "reload(" in body or "_0x4818" in body)


def _challenge_raw(challenge: AcwScV2Challenge) -> dict[str, Any]:
    return {
        "arg1": challenge.arg1,
        "keySource": challenge.key_source,
        "arrayName": challenge.array_name,
        "decoderName": challenge.decoder_name,
        "rotation": challenge.rotation,
        "cipherCount": len(challenge.ciphers),
        "shuffle": list(challenge.shuffle),
        "pageUrl": challenge.page_url,
        "hasHtml": bool(challenge.raw_html),
    }


def _extract_cipher_array(code: str) -> tuple[str | None, list[str]]:
    arrays = _extract_array_declarations(code)
    preferred: tuple[str | None, list[str]] = (None, [])
    for name, values in arrays:
        strings = [v for v in values if isinstance(v, str)]
        if len(strings) < 4 or len(strings) != len(values):
            continue
        if name == "_0x4818":
            return name, strings
        if not preferred[1] or len(strings) > len(preferred[1]):
            preferred = (name, strings)
    return preferred


def _extract_rotation(code: str, array_name: str | None) -> int | None:
    if not array_name:
        return None
    name = re.escape(array_name)
    patterns = [
        rf"\}}\s*\(\s*{name}\s*,\s*({_NUMBER_RE.pattern})\s*\)",
        rf"\}}\s*\)\s*\(\s*{name}\s*,\s*({_NUMBER_RE.pattern})\s*\)",
        rf"\(\s*{name}\s*,\s*({_NUMBER_RE.pattern})\s*\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, code, re.S)
        if match:
            return _parse_js_int(match.group(1))
    return None


def _extract_decoder_keys(code: str) -> tuple[str | None, dict[int, str]]:
    by_name: dict[str, dict[int, str]] = {}
    for match in re.finditer(r"\b(_0x[0-9a-fA-F]+)\s*\(", code):
        parsed = _parse_decoder_call_args(code, match.end())
        if parsed is None:
            continue
        index, key = parsed
        by_name.setdefault(match.group(1), {})[index] = key
    if not by_name:
        return None, {}
    candidates = sorted(
        by_name.items(),
        key=lambda item: (3 in item[1], len(item[1])),
        reverse=True,
    )
    name, keys = candidates[0]
    return name, keys


def _parse_decoder_call_args(code: str, pos: int) -> tuple[int, str] | None:
    idx_value: str | int | None
    pos = _skip_ws(code, pos)
    string = _read_js_string(code, pos)
    if string is not None:
        idx_value, pos = string
    else:
        number = _read_js_number(code, pos)
        if number is None:
            return None
        idx_value, pos = number
    pos = _skip_ws(code, pos)
    if pos >= len(code) or code[pos] != ",":
        return None
    pos = _skip_ws(code, pos + 1)
    key = _read_js_string(code, pos)
    if key is None:
        return None
    key_value, _ = key
    try:
        index = _parse_js_int(str(idx_value)) if isinstance(idx_value, str) else idx_value
    except ValueError:
        return None
    return index, key_value


def _extract_shuffle(code: str) -> tuple[tuple[int, ...], str]:
    for _name, values in _extract_array_declarations(code):
        if len(values) != 40 or not all(isinstance(v, int) for v in values):
            continue
        shuffle = tuple(int(v) for v in values)
        if sorted(shuffle) == list(range(1, 41)):
            return shuffle, "dynamic"
    return DEFAULT_SHUFFLE, "static"


def _extract_array_declarations(code: str) -> list[tuple[str, list[str | int]]]:
    arrays: list[tuple[str, list[str | int]]] = []
    pattern = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[")
    for match in pattern.finditer(code):
        begin = match.end() - 1
        end = _find_matching_bracket(code, begin)
        if end is None:
            continue
        values = _parse_array_values(code[begin + 1 : end])
        arrays.append((match.group(1), values))
    return arrays


def _parse_array_values(body: str) -> list[str | int]:
    values: list[str | int] = []
    pos = 0
    while pos < len(body):
        pos = _skip_ws_and_commas(body, pos)
        if pos >= len(body):
            break
        string = _read_js_string(body, pos)
        if string is not None:
            value, pos = string
            values.append(value)
            continue
        number = _read_js_number(body, pos)
        if number is not None:
            value, pos = number
            values.append(value)
            continue
        pos += 1
    return values


def _read_js_string(text: str, pos: int) -> tuple[str, int] | None:
    if pos >= len(text) or text[pos] not in {'"', "'"}:
        return None
    quote = text[pos]
    pos += 1
    out: list[str] = []
    while pos < len(text):
        ch = text[pos]
        if ch == quote:
            return "".join(out), pos + 1
        if ch != "\\":
            out.append(ch)
            pos += 1
            continue
        pos += 1
        if pos >= len(text):
            out.append("\\")
            break
        esc = text[pos]
        pos += 1
        if esc in {"'", '"', "\\", "/"}:
            out.append(esc)
        elif esc == "b":
            out.append("\b")
        elif esc == "f":
            out.append("\f")
        elif esc == "n":
            out.append("\n")
        elif esc == "r":
            out.append("\r")
        elif esc == "t":
            out.append("\t")
        elif esc == "v":
            out.append("\v")
        elif esc == "0":
            out.append("\0")
        elif esc == "x" and pos + 2 <= len(text):
            out.append(chr(int(text[pos : pos + 2], 16)))
            pos += 2
        elif esc == "u":
            if pos < len(text) and text[pos] == "{":
                end = text.find("}", pos + 1)
                if end != -1:
                    out.append(chr(int(text[pos + 1 : end], 16)))
                    pos = end + 1
                else:
                    out.append("u")
            elif pos + 4 <= len(text):
                out.append(chr(int(text[pos : pos + 4], 16)))
                pos += 4
            else:
                out.append("u")
        elif esc in {"\n", "\r"}:
            if esc == "\r" and pos < len(text) and text[pos] == "\n":
                pos += 1
        else:
            out.append(esc)
    return None


def _read_js_number(text: str, pos: int) -> tuple[int, int] | None:
    match = _NUMBER_RE.match(text, pos)
    if not match:
        return None
    return _parse_js_int(match.group(0)), match.end()


def _parse_js_int(value: str) -> int:
    text = str(value).strip()
    sign = -1 if text.startswith("-") else 1
    if text[:1] in "+-":
        text = text[1:]
    base = 16 if text.lower().startswith("0x") else 10
    return sign * int(text, base)


def _find_matching_bracket(text: str, begin: int) -> int | None:
    if begin >= len(text) or text[begin] != "[":
        return None
    depth = 0
    pos = begin
    while pos < len(text):
        ch = text[pos]
        if ch in {'"', "'"}:
            parsed = _read_js_string(text, pos)
            if parsed is None:
                return None
            _, pos = parsed
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return pos
        pos += 1
    return None


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _skip_ws_and_commas(text: str, pos: int) -> int:
    while pos < len(text) and (text[pos].isspace() or text[pos] == ","):
        pos += 1
    return pos


def _rotate_left(values: list[str], count: int) -> list[str]:
    if not values:
        return []
    amount = int(count) % len(values)
    return values[amount:] + values[:amount]


def _convert_cipher(cipher: str) -> str:
    text = str(cipher).strip()
    padded = text + ("=" * (-len(text) % 4))
    return base64.b64decode(padded).decode("utf-8")


def _rc4(data: str, key: str) -> str:
    if not key:
        raise ValueError("ACW SC V2 RC4 key is empty")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % len(key)])) % 256
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    out: list[str] = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(chr(ord(ch) ^ s[(s[i] + s[j]) % 256]))
    return "".join(out)


def _solution_cookie_value(solution: AcwScV2Solution | dict[str, Any] | str) -> str:
    if isinstance(solution, AcwScV2Solution):
        return solution.cookie_value
    if isinstance(solution, dict):
        for key in ("cookie_value", "cookieValue", COOKIE_NAME, "ticket"):
            if solution.get(key) is not None:
                return _solution_cookie_value(str(solution[key]))
    text = str(solution).strip()
    if text.startswith("{"):
        return _solution_cookie_value(json.loads(text))
    if COOKIE_NAME in text and "=" in text:
        match = re.search(rf"(?:^|[,;\s]){re.escape(COOKIE_NAME)}=([^;\s,]+)", text)
        if match:
            text = match.group(1)
    return _validate_cookie_value(text)


def _merge_page_url(item: AcwScV2Challenge, *, page_url: str | None = None) -> AcwScV2Challenge:
    if not page_url:
        return item
    return AcwScV2Challenge(
        arg1=item.arg1,
        shuffle=item.shuffle,
        xor_key=item.xor_key,
        key_source=item.key_source,
        array_name=item.array_name,
        decoder_name=item.decoder_name,
        rotation=item.rotation,
        ciphers=item.ciphers,
        decoder_keys=item.decoder_keys,
        page_url=page_url,
        raw_html=item.raw_html,
        raw=item.raw,
    )


def _request_headers(headers: dict[str, str] | None = None, *, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if headers:
        out.update({str(k): str(v) for k, v in headers.items()})
    return out


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _validate_arg1(value: Any) -> str:
    text = str(value).strip()
    if not _HEX40_RE.fullmatch(text):
        raise ValueError("ACW SC V2 arg1 must be 40 hex chars")
    return text.upper()


def _validate_cookie_value(value: Any) -> str:
    text = str(value).strip().lower()
    if not _HEX40_RE.fullmatch(text):
        raise ValueError("ACW SC V2 cookie value must be 40 hex chars")
    return text


def _validate_xor_key(value: Any) -> str:
    text = str(value).strip()
    if not _HEX40_RE.fullmatch(text):
        raise ValueError("ACW SC V2 xor key must be 40 hex chars")
    return text.lower()


def _validate_even_hex(value: Any, name: str) -> str:
    text = str(value).strip()
    if len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise ValueError(f"{name} must be even-length hex")
    return text


def _validate_shuffle(value: Any) -> tuple[int, ...]:
    try:
        shuffle = tuple(int(v) for v in value)
    except TypeError as exc:
        raise ValueError("ACW SC V2 shuffle must be iterable") from exc
    if len(shuffle) != 40 or sorted(shuffle) != list(range(1, 41)):
        raise ValueError("ACW SC V2 shuffle must be a permutation of 1..40")
    return shuffle


__all__ = [
    "COOKIE_NAME",
    "DEFAULT_SHUFFLE",
    "DEFAULT_XOR_KEY",
    "AcwScV2Challenge",
    "AcwScV2Solution",
    "AcwScV2Solver",
    "extract_acw_arg1",
    "extract_inline_javascript",
    "hex_xor",
    "is_acwscv2_challenge_html",
    "parse_acwscv2_challenge",
    "parse_acwscv2_challenge_html",
    "solve_acwscv2_cookie",
    "solve_acwscv2_value",
    "unbox",
    "verify_acwscv2_solution",
]
