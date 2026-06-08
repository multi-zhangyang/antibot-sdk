from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

P_CAPTCHA_TYPE = "QuadraticResidueProblem"
WOODALLS: dict[str, int] = {
    "751*2^751-1": 751 * 2**751 - 1,
    "83*2^5318-1": 83 * 2**5318 - 1,
    "7755*2^7755-1": 7755 * 2**7755 - 1,
    "9531*2^9531-1": 9531 * 2**9531 - 1,
    "12379*2^12379-1": 12379 * 2**12379 - 1,
    "7911*2^15823-1": 7911 * 2**15823 - 1,
    "18885*2^18885-1": 18885 * 2**18885 - 1,
    "22971*2^22971-1": 22971 * 2**22971 - 1,
}
WOODALL_ALIASES: dict[str, str] = {
    "2xs": "751*2^751-1",
    "xs": "83*2^5318-1",
    "sm": "7755*2^7755-1",
    "md": "9531*2^9531-1",
    "lg": "12379*2^12379-1",
    "xl": "7911*2^15823-1",
    "2xl": "18885*2^18885-1",
    "3xl": "22971*2^22971-1",
}
DEFAULT_TIMEOUT_SEC = 30


@dataclass(slots=True)
class PCaptchaChallenge:
    raw: str
    woodall: str
    prime: int
    residues: list[int]
    challenge_id: str | None = None

    @property
    def rounds(self) -> int:
        return len(self.residues)

    @property
    def bits(self) -> int:
        return self.prime.bit_length()


@dataclass(slots=True)
class PCaptchaSolution:
    challenge: PCaptchaChallenge
    roots: list[int]
    took_ms: int

    @property
    def answer(self) -> str:
        return ",".join(bigint_to_base64(x) for x in self.roots)

    @property
    def submit_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {"answer": self.answer}
        if self.challenge.challenge_id:
            body["id"] = self.challenge.challenge_id
        return body


def bigint_to_base64(value: int) -> str:
    if value < 0:
        raise ValueError("cannot encode negative bigint")
    hex_value = f"{int(value):x}"
    if len(hex_value) % 2:
        hex_value = "0" + hex_value
    if not hex_value:
        raise ValueError("empty bigint")
    return base64.b64encode(bytes.fromhex(hex_value)).decode("ascii")


def base64_to_bigint(value: str) -> int:
    text = (value or "").strip()
    text += "=" * ((4 - len(text) % 4) % 4)
    raw = base64.b64decode(text)
    if not raw:
        raise ValueError("empty bigint base64")
    return int.from_bytes(raw, "big")


def parse_pcaptcha_challenge(raw: str, *, challenge_id: str | None = None) -> PCaptchaChallenge:
    text = (raw or "").strip()
    if "," not in text:
        raise ValueError("P-Captcha challenge must be '<type>,<base64 problem>'")
    challenge_type, encoded = text.split(",", 1)
    if challenge_type != P_CAPTCHA_TYPE:
        raise ValueError(f"unsupported P-Captcha challenge type: {challenge_type!r}")
    decoded = base64.b64decode(encoded).decode("utf-8")
    parts = decoded.split(",")
    if len(parts) < 2:
        raise ValueError("P-Captcha problem requires woodall and at least one residue")
    woodall = resolve_woodall(parts[0])
    prime = WOODALLS[woodall]
    residues = [base64_to_bigint(x) for x in parts[1:] if x]
    if not residues:
        raise ValueError("P-Captcha problem has no residues")
    return PCaptchaChallenge(raw=text, woodall=woodall, prime=prime, residues=residues, challenge_id=challenge_id)


def solve_pcaptcha_challenge(challenge: PCaptchaChallenge | str, *, challenge_id: str | None = None) -> PCaptchaSolution:
    item = parse_pcaptcha_challenge(challenge, challenge_id=challenge_id) if isinstance(challenge, str) else challenge
    started = time.monotonic()
    roots = [modular_sqrt(n, item.prime) for n in item.residues]
    for residue, root in zip(item.residues, roots, strict=True):
        if (root * root) % item.prime != residue:
            raise ValueError("P-Captcha modular square root verification failed")
    return PCaptchaSolution(challenge=item, roots=roots, took_ms=int((time.monotonic() - started) * 1000))


def verify_pcaptcha_answer(challenge: PCaptchaChallenge | str, answer: str, *, challenge_id: str | None = None) -> bool:
    item = parse_pcaptcha_challenge(challenge, challenge_id=challenge_id) if isinstance(challenge, str) else challenge
    try:
        roots = [base64_to_bigint(x) for x in (answer or "").split(",") if x]
    except Exception:
        return False
    if len(roots) != len(item.residues):
        return False
    return all((root * root) % item.prime == residue for root, residue in zip(roots, item.residues, strict=True))


def generate_pcaptcha_challenge_from_roots(
    roots: list[int],
    *,
    woodall: str = "2xs",
    challenge_id: str | None = None,
) -> PCaptchaChallenge:
    woodall_key = resolve_woodall(woodall)
    prime = WOODALLS[woodall_key]
    residues = [(int(x) * int(x)) % prime for x in roots]
    problem = ",".join([woodall_key, *(bigint_to_base64(x) for x in residues)])
    raw = f"{P_CAPTCHA_TYPE},{base64.b64encode(problem.encode('utf-8')).decode('ascii')}"
    return PCaptchaChallenge(raw=raw, woodall=woodall_key, prime=prime, residues=residues, challenge_id=challenge_id)


def resolve_woodall(value: str) -> str:
    key = str(value or "").strip()
    if key in WOODALL_ALIASES:
        key = WOODALL_ALIASES[key]
    if key not in WOODALLS:
        raise ValueError(f"unsupported P-Captcha Woodall prime: {value!r}")
    return key


def modular_sqrt(n: int, p: int) -> int:
    """Return one square root of n mod prime p.

    P-Captcha's current Woodall primes are all 3 mod 4, so the common path is
    the closed-form exponent n^((p+1)/4).  A Tonelli-Shanks fallback is kept for
    compatibility with future primes.
    """

    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        raise ValueError("not a quadratic residue modulo p")
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    return _tonelli_shanks(n, p)


def _tonelli_shanks(n: int, p: int) -> int:
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) == 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while t not in (0, 1):
        i = 1
        t2i = (t * t) % p
        while t2i != 1 and i < m:
            t2i = (t2i * t2i) % p
            i += 1
        if i == m:
            raise ValueError("Tonelli-Shanks failed")
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return 0 if t == 0 else r


def extract_pcaptcha_challenge(data: Any) -> tuple[str, str | None]:
    if isinstance(data, str):
        return data.strip(), None
    if isinstance(data, dict):
        raw = data.get("challenge") or data.get("rawChallenge") or data.get("captcha")
        cid = data.get("id") or data.get("challengeId") or data.get("challenge_id")
        if isinstance(raw, str):
            return raw, str(cid) if cid is not None else None
        nested = data.get("data")
        if isinstance(nested, (dict, str)):
            raw2, cid2 = extract_pcaptcha_challenge(nested)
            return raw2, str(cid) if cid is not None else cid2
    raise ValueError("failed to extract P-Captcha challenge from response")


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _load_challenge_json(value: str | None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if not value:
        return None
    text = value.strip()
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _looks_successful_validation(data: Any, status_code: int) -> bool:
    if isinstance(data, dict):
        for key in ("success", "ok", "valid", "verified"):
            if key in data:
                return bool(data[key])
        text = " ".join(str(v).lower() for v in data.values() if isinstance(v, (str, int, float, bool)))
        if "invalid" in text or "failed" in text or "false" in text:
            return False
        if "valid" in text or "processed" in text or "success" in text:
            return True
    return 200 <= int(status_code) < 300


class PCaptchaSolver:
    """P-Captcha quadratic-residue protocol solver.

    P-Captcha is a self-hosted PoW CAPTCHA where the browser solves modular
    square roots over Woodall primes.  This provider parses the raw challenge,
    solves the quadratic residues locally, and optionally submits `{id, answer}`
    to a validation endpoint.  It never launches a browser.
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
        challenge_id: str | None = None,
        validate_url: str | None = None,
        validate: bool = False,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
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
            "validate_url": validate_url,
            "validate": validate,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
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
                out = output_root / "pcaptcha_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="pcaptcha",
                ok=ok,
                captcha_type="quadratic_residue_pow",
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
            raw_challenge, cid = self._load_challenge(
                challenge=challenge,
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                challenge_id=challenge_id,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=headers,
                raw=raw,
            )
            item = parse_pcaptcha_challenge(raw_challenge, challenge_id=cid)
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "woodall": item.woodall,
                    "rounds": item.rounds,
                    "prime_bits": item.bits,
                }
            )
            solution = solve_pcaptcha_challenge(item)
            raw["challenge"] = {"type": P_CAPTCHA_TYPE, "woodall": item.woodall, "rounds": item.rounds}
            raw["solution"] = {
                "answer": solution.answer,
                "rootCount": len(solution.roots),
                "tookMs": solution.took_ms,
            }
            raw["submitBody"] = solution.submit_body
            diagnostics["solve_ms"] = solution.took_ms

            ticket = solution.answer
            verify_code = "solved"
            if validate or validate_url:
                if not validate_url:
                    errors.append("validate requested but validate_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code=verify_code)
                resp = requests.post(
                    validate_url,
                    headers={"Content-Type": "application/json", **(headers or {})},
                    json=solution.submit_body,
                    timeout=timeout_sec,
                    proxies=_requests_proxies(proxy_server),
                )
                raw["validateResponse"] = {"status": resp.status_code, "url": validate_url}
                resp.raise_for_status()
                try:
                    validate_data: Any = resp.json()
                except Exception:
                    validate_data = {"text": resp.text[:500]}
                raw["validateResponse"]["json"] = validate_data
                if not _looks_successful_validation(validate_data, resp.status_code):
                    errors.append("P-Captcha validation endpoint rejected answer")
                    return finish(ok=False, ticket=ticket, verify_code="validate_failed")
                verify_code = "validated"
                diagnostics["validated"] = True
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
        challenge_id: str | None,
        timeout_sec: int,
        proxy_server: str | None,
        headers: dict[str, str] | None,
        raw: dict[str, Any],
    ) -> tuple[str, str | None]:
        if challenge:
            raw["challengeSource"] = "inline"
            return challenge, challenge_id
        data = challenge_json
        if isinstance(data, str):
            data = _load_challenge_json(data)
        if data is None:
            data = _load_challenge_json(None, challenge_file)
        if data is not None:
            raw_challenge, cid = extract_pcaptcha_challenge(data)
            raw["challengeSource"] = "json"
            return raw_challenge, challenge_id or cid
        if challenge_url:
            resp = requests.get(
                challenge_url,
                headers=headers,
                timeout=timeout_sec,
                proxies=_requests_proxies(proxy_server),
            )
            raw["challengeResponse"] = {"status": resp.status_code, "url": resp.url}
            resp.raise_for_status()
            ctype = (resp.headers or {}).get("content-type", "")
            if "json" in ctype.lower():
                data = resp.json()
            else:
                text = resp.text.strip()
                try:
                    data = json.loads(text)
                except Exception:
                    data = text
            raw_challenge, cid = extract_pcaptcha_challenge(data)
            raw["challengeSource"] = "url"
            return raw_challenge, challenge_id or cid
        raise ValueError("P-Captcha requires challenge, challenge_json, challenge_file or challenge_url")
