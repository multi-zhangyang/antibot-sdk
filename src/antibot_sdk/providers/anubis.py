from __future__ import annotations

import asyncio
import hashlib
import html
import json
import math
import re
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, TimeoutError as FuturesTimeout, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

ANUBIS_API_PREFIX = "/.within.website/x/cmd/anubis/api/"
ANUBIS_TEST_COOKIE = "techaro.lol-anubis-cookie-verification"
DEFAULT_MAX_ATTEMPTS = 50_000_000
DEFAULT_TIMEOUT_SEC = 30


@dataclass(slots=True)
class AnubisChallenge:
    random_data: str
    difficulty: int = 4
    algorithm: str = "fast"
    challenge_id: str | None = None
    redir: str | None = None
    base_prefix: str = ""


@dataclass(slots=True)
class AnubisSolution:
    challenge: AnubisChallenge
    nonce: int
    response: str
    took_ms: int
    checked: int

    @property
    def pass_params(self) -> dict[str, str]:
        params = {
            "id": self.challenge.challenge_id or "",
            "response": self.response,
            "nonce": str(self.nonce),
            "elapsedTime": str(max(0, self.took_ms)),
        }
        if self.challenge.redir is not None:
            params["redir"] = self.challenge.redir
        return params


def anubis_hash_hex(random_data: str, nonce: int | str) -> str:
    h = hashlib.sha256()
    h.update(str(random_data).encode("utf-8"))
    h.update(str(nonce).encode("utf-8"))
    return h.hexdigest()


def anubis_pow_matches(response_hex: str, difficulty: int) -> bool:
    difficulty = max(0, int(difficulty))
    return str(response_hex).lower().startswith("0" * difficulty)


def verify_anubis_solution(random_data: str, difficulty: int, nonce: int | str, response: str | None = None) -> bool:
    digest = anubis_hash_hex(random_data, nonce)
    if response is not None and digest != str(response).lower():
        return False
    return anubis_pow_matches(digest, difficulty)


def solve_anubis_challenge(
    challenge: AnubisChallenge | dict[str, Any] | str,
    *,
    difficulty: int | None = None,
    algorithm: str | None = None,
    start: int = 0,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> AnubisSolution | None:
    item = parse_anubis_challenge(challenge, default_difficulty=difficulty, default_algorithm=algorithm)
    if item.algorithm not in ("fast", "slow"):
        raise ValueError(f"unsupported Anubis algorithm: {item.algorithm!r}")
    started = time.monotonic()
    nonce, checked = _solve_pow(
        item.random_data,
        item.difficulty,
        start=start,
        max_attempts=max_attempts,
        workers=workers,
        timeout_sec=timeout_sec,
    )
    if nonce is None:
        return None
    return AnubisSolution(
        challenge=item,
        nonce=nonce,
        response=anubis_hash_hex(item.random_data, nonce),
        took_ms=int((time.monotonic() - started) * 1000),
        checked=checked,
    )


def parse_anubis_challenge(
    value: AnubisChallenge | dict[str, Any] | str,
    *,
    default_difficulty: int | None = None,
    default_algorithm: str | None = None,
    challenge_id: str | None = None,
    redir: str | None = None,
    base_prefix: str = "",
) -> AnubisChallenge:
    if isinstance(value, AnubisChallenge):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("<") or "anubis_challenge" in text:
            return parse_anubis_challenge_page(
                text,
                default_difficulty=default_difficulty,
                default_algorithm=default_algorithm,
                redir=redir,
            )
        try:
            data = json.loads(text)
        except Exception:
            return AnubisChallenge(
                random_data=text,
                difficulty=int(default_difficulty if default_difficulty is not None else 4),
                algorithm=str(default_algorithm or "fast"),
                challenge_id=challenge_id,
                redir=redir,
                base_prefix=base_prefix,
            )
        return parse_anubis_challenge(
            data,
            default_difficulty=default_difficulty,
            default_algorithm=default_algorithm,
            challenge_id=challenge_id,
            redir=redir,
            base_prefix=base_prefix,
        )
    if not isinstance(value, dict):
        raise ValueError("Anubis challenge must be object, string or HTML page")

    data = value
    if "anubis_challenge" in data and isinstance(data["anubis_challenge"], dict):
        data = data["anubis_challenge"]

    rules = data.get("rules") if isinstance(data.get("rules"), dict) else {}
    challenge_obj = data.get("challenge")

    cid = challenge_id or _str_or_none(data.get("id"))
    random_data: str | None = None
    method: str | None = None
    ch_diff: int | None = None

    if isinstance(challenge_obj, dict):
        cid = cid or _str_or_none(challenge_obj.get("id"))
        random_data = _str_or_none(
            challenge_obj.get("randomData")
            or challenge_obj.get("random_data")
            or challenge_obj.get("challenge")
            or challenge_obj.get("data")
        )
        method = _str_or_none(challenge_obj.get("method"))
        if challenge_obj.get("difficulty") is not None:
            ch_diff = int(challenge_obj["difficulty"])
    elif isinstance(challenge_obj, str):
        random_data = challenge_obj

    random_data = random_data or _str_or_none(data.get("randomData") or data.get("random_data") or data.get("data"))
    if not random_data:
        raise ValueError("Anubis challenge requires randomData/challenge string")

    difficulty_raw = (
        ch_diff
        if ch_diff is not None
        else rules.get("difficulty", data.get("difficulty", default_difficulty if default_difficulty is not None else 4))
    )
    algorithm_raw = method or rules.get("algorithm") or data.get("algorithm") or default_algorithm or "fast"
    return AnubisChallenge(
        random_data=random_data,
        difficulty=max(0, int(difficulty_raw)),
        algorithm=str(algorithm_raw or "fast"),
        challenge_id=cid,
        redir=redir or _str_or_none(data.get("redir")),
        base_prefix=str(data.get("base_prefix") or data.get("basePrefix") or base_prefix or ""),
    )


def parse_anubis_challenge_page(
    html_text: str,
    *,
    default_difficulty: int | None = None,
    default_algorithm: str | None = None,
    redir: str | None = None,
) -> AnubisChallenge:
    payload = _extract_json_script(html_text, "anubis_challenge")
    if payload is None:
        raise ValueError("failed to find Anubis anubis_challenge JSON script")
    base_prefix = _extract_json_script(html_text, "anubis_base_prefix") or ""
    return parse_anubis_challenge(
        payload,
        default_difficulty=default_difficulty,
        default_algorithm=default_algorithm,
        redir=redir,
        base_prefix=str(base_prefix or ""),
    )


def _extract_json_script(html_text: str, script_id: str) -> Any | None:
    pattern = re.compile(
        r'<script[^>]+id=["\']' + re.escape(script_id) + r'["\'][^>]*>(.*?)</script>',
        re.IGNORECASE | re.DOTALL,
    )
    m = pattern.search(html_text or "")
    if not m:
        return None
    text = html.unescape(m.group(1).strip())
    if not text:
        return None
    return json.loads(text)


def _solve_pow(
    random_data: str,
    difficulty: int,
    *,
    start: int,
    max_attempts: int,
    workers: int,
    timeout_sec: int | float | None,
) -> tuple[int | None, int]:
    workers = max(1, int(workers or 1))
    start = max(0, int(start))
    max_attempts = max(1, int(max_attempts))
    difficulty = max(0, int(difficulty))
    if workers <= 1 or max_attempts < 100_000:
        deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
        return _solve_range(random_data, difficulty, start, start + max_attempts, deadline)

    chunk = math.ceil(max_attempts / workers)
    deadline = time.monotonic() + float(timeout_sec) if timeout_sec else None
    checked_total = 0
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = []
        for idx in range(workers):
            lo = start + idx * chunk
            hi = min(start + max_attempts, lo + chunk)
            if lo >= hi:
                break
            futures.append(pool.submit(_solve_range, random_data, difficulty, lo, hi, deadline))
        pending = set(futures)
        try:
            while pending:
                wait_timeout = None
                if deadline is not None:
                    wait_timeout = max(0.0, deadline - time.monotonic())
                    if wait_timeout <= 0:
                        break
                done, pending = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
                if not done:
                    break
                for fut in done:
                    nonce, checked = fut.result()
                    checked_total += checked
                    if nonce is not None:
                        for other in pending:
                            other.cancel()
                        return nonce, checked_total
        except FuturesTimeout:
            pass
        finally:
            for fut in pending:
                fut.cancel()
    return None, checked_total


def _solve_range(
    random_data: str,
    difficulty: int,
    start: int,
    end_exclusive: int,
    deadline: float | None = None,
) -> tuple[int | None, int]:
    checked = 0
    prefix = "0" * max(0, int(difficulty))
    for nonce in range(int(start), int(end_exclusive)):
        if deadline is not None and checked and checked % 4096 == 0 and time.monotonic() >= deadline:
            return None, checked
        checked += 1
        digest = anubis_hash_hex(random_data, nonce)
        if digest.startswith(prefix):
            return nonce, checked
    return None, checked


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_json_arg(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _api_url(base_url: str | None, path: str) -> str | None:
    if not base_url:
        return None
    base = base_url.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _infer_pass_url(challenge_url: str | None, page_url: str | None, base_prefix: str = "") -> str | None:
    if challenge_url and challenge_url.rstrip("/").endswith("/make-challenge"):
        return challenge_url.rstrip("/")[: -len("/make-challenge")] + "/pass-challenge"
    src = page_url or challenge_url
    if not src:
        return None
    return urljoin(src, (base_prefix.rstrip("/") if base_prefix else "") + ANUBIS_API_PREFIX + "pass-challenge")


class AnubisSolver:
    """Anubis proof-of-work protocol solver.

    Anubis `fast` and `slow` currently validate SHA256(randomData + nonce) with
    a hex leading-zero difficulty.  This provider parses the JSON/HTML challenge,
    computes nonce/response locally, and can optionally call `pass-challenge` to
    obtain the Anubis auth cookie.  It does not launch a browser.
    """

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge: str | None = None,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        page_url: str | None = None,
        base_url: str | None = None,
        pass_url: str | None = None,
        redir: str | None = None,
        difficulty: int | None = None,
        algorithm: str | None = None,
        start: int = 0,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        submit: bool = False,
        ensure_test_cookie: bool = True,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        artifacts: dict[str, str] = {}
        errors: list[str] = []
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "page_url": page_url,
            "pass_url": pass_url,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
        }
        output_root: Path | None = None
        if output_dir:
            output_root = Path(output_dir)
            output_root.mkdir(parents=True, exist_ok=True)
            artifacts["outputDir"] = str(output_root)

        session = requests.Session()
        session.headers.update(headers or {})
        proxies = _requests_proxies(proxy_server)

        def finish(*, ok: bool, ticket: str | None = None, verify_code: str | None = None) -> CaptchaResult:
            raw["ok"] = ok
            raw["elapsedMs"] = int((time.monotonic() - started) * 1000)
            if output_root is not None:
                out = output_root / "anubis_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="anubis",
                ok=ok,
                captcha_type="proof_of_work",
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
            if base_url:
                challenge_url = challenge_url or _api_url(base_url, ANUBIS_API_PREFIX + "make-challenge")
                pass_url = pass_url or _api_url(base_url, ANUBIS_API_PREFIX + "pass-challenge")

            item = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                page_url=page_url,
                redir=redir,
                difficulty=difficulty,
                algorithm=algorithm,
                timeout_sec=timeout_sec,
                session=session,
                proxies=proxies,
                raw=raw,
            )
            diagnostics.update(
                {
                    "algorithm": item.algorithm,
                    "difficulty": item.difficulty,
                    "challenge_id": item.challenge_id,
                    "random_data_prefix": item.random_data[:16],
                    "base_prefix": item.base_prefix,
                }
            )
            solution = solve_anubis_challenge(
                item,
                start=start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("no Anubis nonce found before timeout/max_attempts")
                return finish(ok=False)

            raw["solution"] = {
                "nonce": solution.nonce,
                "response": solution.response,
                "elapsedTime": solution.took_ms,
                "checked": solution.checked,
            }
            raw["passParams"] = solution.pass_params
            diagnostics.update({"nonce": solution.nonce, "checked": solution.checked, "solve_ms": solution.took_ms})

            ticket = json.dumps(solution.pass_params, ensure_ascii=False, separators=(",", ":"))
            verify_code = "solved"
            if submit or pass_url:
                if not pass_url:
                    pass_url = _infer_pass_url(challenge_url, page_url, item.base_prefix)
                if not pass_url:
                    errors.append("submit requested but pass_url cannot be inferred")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                if ensure_test_cookie and item.challenge_id and ANUBIS_TEST_COOKIE not in session.cookies:
                    session.cookies.set(ANUBIS_TEST_COOKIE, item.challenge_id)
                params = dict(solution.pass_params)
                params.setdefault("redir", redir or item.redir or "/")
                resp = session.get(
                    pass_url,
                    params=params,
                    timeout=timeout_sec,
                    proxies=proxies,
                    allow_redirects=False,
                )
                raw["passResponse"] = {
                    "status": resp.status_code,
                    "url": resp.url,
                    "location": resp.headers.get("location"),
                    "setCookie": bool(resp.headers.get("set-cookie")),
                }
                if resp.status_code not in (200, 302, 303, 307, 308):
                    errors.append(f"Anubis pass-challenge rejected solution: HTTP {resp.status_code}")
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                cookie_dict = session.cookies.get_dict()
                raw["cookies"] = {k: (v[:12] + "..." if len(v) > 16 else v) for k, v in cookie_dict.items()}
                auth_cookie = next((v for k, v in cookie_dict.items() if k != ANUBIS_TEST_COOKIE), "")
                ticket = auth_cookie or ticket
                verify_code = "passed"
                diagnostics["submitted"] = True
                diagnostics["pass_status"] = resp.status_code
            return finish(ok=True, ticket=ticket, verify_code=verify_code)
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)

    def _load_challenge(
        self,
        *,
        challenge: str | None,
        challenge_json: Any,
        challenge_file: str | None,
        challenge_url: str | None,
        page_url: str | None,
        redir: str | None,
        difficulty: int | None,
        algorithm: str | None,
        timeout_sec: int,
        session: requests.Session,
        proxies: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> AnubisChallenge:
        if challenge:
            raw["challengeSource"] = "inline"
            return parse_anubis_challenge(challenge, default_difficulty=difficulty, default_algorithm=algorithm, redir=redir)
        data = challenge_json
        if isinstance(data, str):
            data = _load_json_arg(data)
        if data is None:
            data = _load_json_arg(None, challenge_file)
        if data is not None:
            raw["challengeSource"] = "json"
            return parse_anubis_challenge(data, default_difficulty=difficulty, default_algorithm=algorithm, redir=redir)
        if challenge_url:
            params = {"redir": redir} if redir else None
            resp = session.get(challenge_url, params=params, timeout=timeout_sec, proxies=proxies)
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url, "setCookie": bool(resp.headers.get("set-cookie"))}
            resp.raise_for_status()
            data = resp.json()
            raw["challengeSource"] = "url"
            return parse_anubis_challenge(data, default_difficulty=difficulty, default_algorithm=algorithm, redir=redir)
        if page_url:
            resp = session.get(page_url, timeout=timeout_sec, proxies=proxies)
            raw["pageResponse"] = {"status": resp.status_code, "url": resp.url, "setCookie": bool(resp.headers.get("set-cookie"))}
            resp.raise_for_status()
            raw["challengeSource"] = "page"
            return parse_anubis_challenge_page(resp.text, default_difficulty=difficulty, default_algorithm=algorithm, redir=redir)
        raise ValueError("Anubis requires challenge, challenge_json, challenge_file, challenge_url or page_url")
