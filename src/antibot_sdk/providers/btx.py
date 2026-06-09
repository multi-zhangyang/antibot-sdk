from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ..models import CaptchaResult
from ..proxy import parse_proxy, redacted_proxy

M31_MODULUS = 0x7FFFFFFF
MAX_U64 = (1 << 64) - 1
DEFAULT_MAX_MATMUL_N = 128
DEFAULT_MAX_MATMUL_R = 32
DEFAULT_MAX_TRIES = 1_000_000
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_RESPONSE_FIELD = "btx_proof"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

HEADER_CHALLENGE = "X-BTX-Challenge"
HEADER_CHALLENGE_ID = "X-BTX-Challenge-Id"
HEADER_PROOF_NONCE = "X-BTX-Proof-Nonce"
HEADER_PROOF_DIGEST = "X-BTX-Proof-Digest"

NOISE_TAG_EL = "matmul_noise_EL_v1"
NOISE_TAG_ER = "matmul_noise_ER_v1"
NOISE_TAG_FL = "matmul_noise_FL_v1"
NOISE_TAG_FR = "matmul_noise_FR_v1"
TRANSCRIPT_COMPRESS_TAG = "matmul-compress-v1"


@dataclass(slots=True)
class BtxHeaderContext:
    version: int
    previousblockhash: str
    merkleroot: str
    time: int
    bits: str
    nonce64_start: int
    matmul_dim: int
    seed_a: str
    seed_b: str


@dataclass(slots=True)
class BtxMatmulParams:
    n: int
    b: int
    r: int
    q: int
    seed_a: str
    seed_b: str
    min_dimension: int | None = None
    max_dimension: int | None = None


@dataclass(slots=True)
class BtxChallenge:
    challenge_id: str | None
    target: str
    header_context: BtxHeaderContext
    matmul: BtxMatmulParams
    response_field: str = DEFAULT_RESPONSE_FIELD
    raw: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        out = dict(self.raw or {})
        if out:
            return out
        return {
            "challenge_id": self.challenge_id,
            "challenge": {
                "target": self.target,
                "header_context": {
                    "version": self.header_context.version,
                    "previousblockhash": self.header_context.previousblockhash,
                    "merkleroot": self.header_context.merkleroot,
                    "time": self.header_context.time,
                    "bits": self.header_context.bits,
                    "nonce64_start": self.header_context.nonce64_start,
                    "matmul_dim": self.header_context.matmul_dim,
                    "seed_a": self.header_context.seed_a,
                    "seed_b": self.header_context.seed_b,
                },
                "matmul": {
                    "n": self.matmul.n,
                    "b": self.matmul.b,
                    "r": self.matmul.r,
                    "q": self.matmul.q,
                    "min_dimension": self.matmul.min_dimension,
                    "max_dimension": self.matmul.max_dimension,
                    "seed_a": self.matmul.seed_a,
                    "seed_b": self.matmul.seed_b,
                },
            },
        }


@dataclass(slots=True)
class Matrix:
    rows: int
    cols: int
    data: list[int]


@dataclass(slots=True)
class BtxSolution:
    challenge: BtxChallenge
    nonce64_hex: str
    digest_hex: str
    attempts: int
    solve_time_ms: int

    @property
    def nonce(self) -> int:
        return int(self.nonce64_hex, 16)

    @property
    def proof(self) -> dict[str, Any]:
        return build_btx_proof(self.challenge, self)

    @property
    def headers(self) -> dict[str, str]:
        return build_btx_submit_headers(self.challenge, self)

    @property
    def submit_body(self) -> dict[str, str]:
        return build_btx_submit_body(self.challenge, self)

    def to_payload(self) -> dict[str, Any]:
        return {
            "nonce64_hex": self.nonce64_hex,
            "digest_hex": self.digest_hex,
            "attempts": self.attempts,
            "solveTimeMs": self.solve_time_ms,
            "proof": self.proof,
            "headers": self.headers,
            "submitBody": self.submit_body,
        }


def parse_btx_challenge(
    value: BtxChallenge | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> BtxChallenge:
    if isinstance(value, BtxChallenge):
        if response_field:
            value.response_field = response_field
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("BTX challenge is empty")
        if text.startswith("@"):
            return parse_btx_challenge(
                Path(text[1:]).read_text(encoding="utf-8"),
                response_field=response_field,
            )
        return parse_btx_challenge(json.loads(text), response_field=response_field)
    if not isinstance(value, dict):
        raise ValueError("BTX challenge must be a JSON object, JSON string, or BtxChallenge")

    envelope = value
    payload = value if "matmul" in value else None
    nested = value.get("challenge")
    if isinstance(nested, dict):
        if "matmul" in nested:
            payload = nested
        elif isinstance(nested.get("challenge"), dict) and "matmul" in nested["challenge"]:
            envelope = nested
            payload = nested["challenge"]
    if not isinstance(payload, dict):
        raise ValueError("BTX challenge requires challenge payload with matmul/header_context")

    ctx_raw = payload.get("header_context")
    mat_raw = payload.get("matmul")
    if not isinstance(ctx_raw, dict) or not isinstance(mat_raw, dict):
        raise ValueError("BTX challenge requires header_context and matmul objects")

    ctx = BtxHeaderContext(
        version=int(ctx_raw["version"]),
        previousblockhash=str(ctx_raw["previousblockhash"]),
        merkleroot=str(ctx_raw["merkleroot"]),
        time=int(ctx_raw["time"]),
        bits=str(ctx_raw["bits"]),
        nonce64_start=_parse_u64(ctx_raw.get("nonce64_start", 0)),
        matmul_dim=int(ctx_raw["matmul_dim"]),
        seed_a=str(ctx_raw["seed_a"]),
        seed_b=str(ctx_raw["seed_b"]),
    )
    mat = BtxMatmulParams(
        n=int(mat_raw["n"]),
        b=int(mat_raw["b"]),
        r=int(mat_raw["r"]),
        q=int(mat_raw.get("q", M31_MODULUS)),
        min_dimension=_optional_int(mat_raw.get("min_dimension")),
        max_dimension=_optional_int(mat_raw.get("max_dimension")),
        seed_a=str(mat_raw["seed_a"]),
        seed_b=str(mat_raw["seed_b"]),
    )
    target = str(payload["target"])
    validate_btx_matmul_params(mat.n, mat.b, mat.r, q=mat.q)
    _parse_hex_fixed(target, 32, "target")
    _parse_hex_fixed(ctx.previousblockhash, 32, "previousblockhash")
    _parse_hex_fixed(ctx.merkleroot, 32, "merkleroot")
    _parse_hex_fixed(ctx.seed_a, 32, "header_context.seed_a")
    _parse_hex_fixed(ctx.seed_b, 32, "header_context.seed_b")
    _parse_hex_fixed(mat.seed_a, 32, "matmul.seed_a")
    _parse_hex_fixed(mat.seed_b, 32, "matmul.seed_b")
    _parse_bits_hex(ctx.bits)
    if ctx.matmul_dim < 0 or ctx.matmul_dim > 0xFFFF:
        raise ValueError(f"BTX header_context.matmul_dim={ctx.matmul_dim} out of uint16 range")

    return BtxChallenge(
        challenge_id=_first_str(envelope, "challenge_id", "challengeId", "id")
        or _first_str(value, "challenge_id", "challengeId", "id"),
        target=target,
        header_context=ctx,
        matmul=mat,
        response_field=response_field
        or _first_str(value, "responseField", "response_field", "field", "name")
        or DEFAULT_RESPONSE_FIELD,
        raw=value,
    )


def validate_btx_matmul_params(
    n: int,
    b: int,
    r: int,
    *,
    q: int = M31_MODULUS,
    max_n: int = DEFAULT_MAX_MATMUL_N,
    max_r: int = DEFAULT_MAX_MATMUL_R,
) -> None:
    if q != M31_MODULUS:
        raise ValueError(f"BTX M31 q must be {M31_MODULUS}, got {q}")
    if n <= 0 or b <= 0 or r <= 0:
        raise ValueError(f"invalid BTX matmul params n={n} b={b} r={r}")
    if n > max_n:
        raise ValueError(f"BTX n={n} exceeds pure-python max {max_n}")
    if r > max_r:
        raise ValueError(f"BTX r={r} exceeds pure-python max {max_r}")
    if b > n:
        raise ValueError(f"BTX b={b} exceeds n={n}")
    if n % b:
        raise ValueError(f"BTX n={n} not divisible by b={b}")


def btx_attempt_digest_hex(challenge: BtxChallenge | dict[str, Any] | str, nonce: int | str) -> str:
    item = parse_btx_challenge(challenge)
    digest_raw = _btx_attempt_digest_raw(item, _parse_solution_nonce(nonce))
    return _bytes_le_to_hex_be(digest_raw)


def solve_btx_challenge(
    challenge: BtxChallenge | dict[str, Any] | str,
    *,
    nonce_start: int | str | None = None,
    max_attempts: int = DEFAULT_MAX_TRIES,
    workers: int = 1,
    timeout_sec: int | float | None = DEFAULT_TIMEOUT_SEC,
) -> BtxSolution | None:
    item = parse_btx_challenge(challenge)
    started = time.monotonic()
    start = _parse_u64(nonce_start if nonce_start is not None else item.header_context.nonce64_start)
    deadline_epoch = time.time() + float(timeout_sec) if timeout_sec else None
    nonce, digest_hex, checked = solve_btx_nonce(
        item,
        nonce_start=start,
        max_attempts=max_attempts,
        workers=workers,
        deadline_epoch=deadline_epoch,
    )
    if nonce is None or digest_hex is None:
        return None
    return BtxSolution(
        challenge=item,
        nonce64_hex=f"{nonce & MAX_U64:016x}",
        digest_hex=digest_hex,
        attempts=checked,
        solve_time_ms=int((time.monotonic() - started) * 1000),
    )


def solve_btx_nonce(
    challenge: BtxChallenge | dict[str, Any] | str,
    *,
    nonce_start: int | str | None = None,
    max_attempts: int = DEFAULT_MAX_TRIES,
    workers: int = 1,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    item = parse_btx_challenge(challenge)
    start = _parse_u64(nonce_start if nonce_start is not None else item.header_context.nonce64_start)
    max_attempts = max(1, int(max_attempts))
    workers = max(1, int(workers or 1))
    precomputed = _prepare_btx_precomputed(item)
    if workers <= 1 or max_attempts < 32:
        return _solve_btx_range(item.to_payload(), start, max_attempts, deadline_epoch)

    chunk = math.ceil(max_attempts / workers)
    ranges = []
    for idx in range(workers):
        lo = (start + idx * chunk) & MAX_U64
        size = min(chunk, max_attempts - idx * chunk)
        if size > 0:
            ranges.append((lo, size))

    checked_total = 0
    completed: dict[int, tuple[int | None, str | None, int]] = {}
    pool = ProcessPoolExecutor(max_workers=len(ranges))
    futures = {
        pool.submit(
            _solve_btx_range_prepared,
            item.to_payload(),
            precomputed["A"],
            precomputed["B"],
            precomputed["target_value"],
            lo,
            size,
            deadline_epoch,
        ): idx
        for idx, (lo, size) in enumerate(ranges)
    }
    try:
        wait_timeout = None if deadline_epoch is None else max(0.0, deadline_epoch - time.time())
        for fut in as_completed(futures, timeout=wait_timeout):
            idx = futures[fut]
            nonce, digest_hex, checked = fut.result()
            completed[idx] = (nonce, digest_hex, checked)
            checked_total += checked
            best_ready: tuple[int, str] | None = None
            for prior_idx in range(len(ranges)):
                if prior_idx not in completed:
                    break
                p_nonce, p_digest, _ = completed[prior_idx]
                if p_nonce is not None and p_digest is not None:
                    best_ready = (p_nonce, p_digest)
                    break
            if best_ready is not None:
                for other in futures:
                    other.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
                return best_ready[0], best_ready[1], checked_total
    except FuturesTimeout:
        pool.shutdown(wait=False, cancel_futures=True)
        return None, None, checked_total
    except Exception:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True, cancel_futures=True)
    return None, None, checked_total


def verify_btx_solution(
    challenge: BtxChallenge | dict[str, Any] | str,
    solution: BtxSolution | dict[str, Any] | str,
) -> bool:
    try:
        item = parse_btx_challenge(challenge)
        if isinstance(solution, BtxSolution):
            nonce_hex = solution.nonce64_hex
            digest_hex = solution.digest_hex
        elif isinstance(solution, dict):
            nonce_hex = str(solution.get("nonce64_hex") or solution.get("nonce") or "")
            digest_hex = str(solution.get("digest_hex") or solution.get("digest") or "")
        else:
            nonce_hex = str(solution)
            digest_hex = ""
        nonce = _parse_u64(nonce_hex, base=16)
        computed = _btx_attempt_digest_raw(item, nonce)
        computed_hex = _bytes_le_to_hex_be(computed)
        return (
            computed_hex == digest_hex.lower()
            and _bytes_le_to_int(computed) <= _bytes_be_to_int(_parse_hex_fixed(item.target, 32, "target"))
        )
    except Exception:
        return False


def build_btx_proof(
    challenge: BtxChallenge | dict[str, Any] | str,
    solution: BtxSolution | dict[str, Any] | str,
) -> dict[str, Any]:
    item = parse_btx_challenge(challenge)
    if isinstance(solution, BtxSolution):
        nonce_hex = solution.nonce64_hex
        digest_hex = solution.digest_hex
    elif isinstance(solution, dict):
        nonce_hex = str(solution.get("nonce64_hex") or solution.get("nonce") or "")
        digest_hex = str(solution.get("digest_hex") or solution.get("digest") or "")
    else:
        nonce_hex = str(solution)
        digest_hex = btx_attempt_digest_hex(item, nonce_hex)
    return {"challenge": item.to_payload(), "nonce64_hex": nonce_hex, "digest_hex": digest_hex}


def build_btx_submit_headers(
    challenge: BtxChallenge | dict[str, Any] | str,
    solution: BtxSolution | dict[str, Any] | str,
) -> dict[str, str]:
    item = parse_btx_challenge(challenge)
    proof = build_btx_proof(item, solution)
    headers = {
        HEADER_CHALLENGE: _json_compact(item.to_payload()),
        HEADER_PROOF_NONCE: str(proof["nonce64_hex"]),
        HEADER_PROOF_DIGEST: str(proof["digest_hex"]),
    }
    if item.challenge_id:
        headers[HEADER_CHALLENGE_ID] = item.challenge_id
    return headers


def build_btx_submit_body(
    challenge: BtxChallenge | dict[str, Any] | str,
    solution: BtxSolution | dict[str, Any] | str,
    *,
    response_field: str | None = None,
) -> dict[str, str]:
    item = parse_btx_challenge(challenge)
    return {response_field or item.response_field: _json_compact(build_btx_proof(item, solution))}


def serialize_btx_header(ctx: BtxHeaderContext, nonce64: int) -> bytes:
    buf = bytearray()
    buf += int(ctx.version & 0xFFFFFFFF).to_bytes(4, "little")
    buf += _parse_uint256_hex_to_le(ctx.previousblockhash, "previousblockhash")
    buf += _parse_uint256_hex_to_le(ctx.merkleroot, "merkleroot")
    buf += int(ctx.time & 0xFFFFFFFF).to_bytes(4, "little")
    buf += int(_parse_bits_hex(ctx.bits)).to_bytes(4, "little")
    buf += int(nonce64 & MAX_U64).to_bytes(8, "little")
    if ctx.matmul_dim < 0 or ctx.matmul_dim > 0xFFFF:
        raise ValueError(f"BTX header matmul_dim={ctx.matmul_dim} out of uint16 range")
    buf += int(ctx.matmul_dim).to_bytes(2, "little")
    buf += _parse_uint256_hex_to_le(ctx.seed_a, "seed_a")
    buf += _parse_uint256_hex_to_le(ctx.seed_b, "seed_b")
    return bytes(buf)


def compute_btx_header_hash(ctx: BtxHeaderContext, nonce64: int) -> bytes:
    return hashlib.sha256(serialize_btx_header(ctx, nonce64)).digest()


def derive_btx_sigma(ctx: BtxHeaderContext, nonce64: int) -> bytes:
    return hashlib.sha256(compute_btx_header_hash(ctx, nonce64)).digest()[::-1]


def btx_from_seed_rect(seed: bytes, rows: int, cols: int) -> Matrix:
    if len(seed) != 32:
        raise ValueError(f"BTX seed must be 32 bytes, got {len(seed)}")
    return Matrix(rows=rows, cols=cols, data=[_field_from_oracle(seed, i) for i in range(rows * cols)])


def btx_generate_noise(sigma_be: bytes, n: int, r: int) -> dict[str, Matrix]:
    return {
        "E_L": btx_from_seed_rect(_derive_noise_seed(NOISE_TAG_EL, sigma_be), n, r),
        "E_R": btx_from_seed_rect(_derive_noise_seed(NOISE_TAG_ER, sigma_be), r, n),
        "F_L": btx_from_seed_rect(_derive_noise_seed(NOISE_TAG_FL, sigma_be), n, r),
        "F_R": btx_from_seed_rect(_derive_noise_seed(NOISE_TAG_FR, sigma_be), r, n),
    }


def btx_canonical_matmul(a_prime: Matrix, b_prime: Matrix, b: int, sigma_be: bytes) -> tuple[Matrix, bytes]:
    if a_prime.rows != a_prime.cols or b_prime.rows != b_prime.cols or a_prime.rows != b_prime.rows:
        raise ValueError("BTX canonical matmul requires equal square matrices")
    if b <= 0 or a_prime.rows % b:
        raise ValueError("BTX canonical matmul invalid block size")
    n = a_prime.rows
    block_count = n // b
    c_prime = _zeros(n, n)
    hasher = _TranscriptHasher(sigma_be, b)
    a_block = [0] * (b * b)
    b_block = [0] * (b * b)
    c_block = [0] * (b * b)
    for i in range(block_count):
        for j in range(block_count):
            for pos in range(len(c_block)):
                c_block[pos] = 0
            for ell in range(block_count):
                _read_block(a_prime, i, ell, b, a_block)
                _read_block(b_prime, ell, j, b, b_block)
                _multiply_and_accumulate_block(a_block, b_block, c_block, b)
                hasher.add_intermediate(c_block)
            _write_block(c_prime, i, j, b, c_block)
    return c_prime, hasher.finalize()


class BtxSolver:
    """BTX MatMul service-challenge protocol solver."""

    async def solve(self, **kwargs: Any) -> CaptchaResult:
        return await asyncio.to_thread(self._solve_sync, **kwargs)

    def _solve_sync(
        self,
        *,
        challenge_json: Any = None,
        challenge_file: str | None = None,
        challenge_url: str | None = None,
        submit_url: str | None = None,
        submit: bool = False,
        submit_method: str = "POST",
        submit_json: Any = None,
        response_field: str | None = None,
        nonce_start: int | str | None = None,
        max_attempts: int = DEFAULT_MAX_TRIES,
        workers: int = 1,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        proxy_server: str | None = None,
        output_dir: str | None = None,
        headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> CaptchaResult:
        started = time.monotonic()
        raw: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
        errors: list[str] = []
        artifacts: dict[str, str] = {}
        diagnostics: dict[str, Any] = {
            "challenge_url": challenge_url,
            "submit_url": submit_url if submit else None,
            "submit": submit,
            "proxy": redacted_proxy(proxy_server),
            "browser": "not_used",
            "workers": workers,
            "max_attempts": max_attempts,
            "engine": "pure_python",
            "max_n": DEFAULT_MAX_MATMUL_N,
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
                out = output_root / "btx_run.json"
                out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
                artifacts["out"] = str(out)
            return CaptchaResult(
                provider="btx",
                ok=ok,
                captcha_type="matmul_service_pow",
                capability="protocol_solver",
                ticket=ticket,
                verify_code=verify_code,
                elapsed_ms=raw["elapsedMs"],
                artifacts=artifacts,
                diagnostics=diagnostics,
                raw=raw,
                errors=[] if ok else errors or ["solve_failed"],
            )

        try:
            request_headers = _merge_headers(headers, user_agent)
            source = _load_btx_source(
                challenge_json=challenge_json,
                challenge_file=challenge_file,
                challenge_url=challenge_url,
                timeout_sec=timeout_sec,
                proxy_server=proxy_server,
                headers=request_headers,
                raw=raw,
            )
            item = parse_btx_challenge(source, response_field=response_field)
            raw["challenge"] = item.to_payload()
            diagnostics.update(
                {
                    "challenge_id": item.challenge_id,
                    "target": item.target,
                    "n": item.matmul.n,
                    "b": item.matmul.b,
                    "r": item.matmul.r,
                    "nonce_start": nonce_start
                    if nonce_start is not None
                    else item.header_context.nonce64_start,
                    "header_matmul_dim": item.header_context.matmul_dim,
                    "seed_dim_match": item.header_context.matmul_dim == item.matmul.n,
                    "seed_a_match": item.header_context.seed_a.lower() == item.matmul.seed_a.lower(),
                    "seed_b_match": item.header_context.seed_b.lower() == item.matmul.seed_b.lower(),
                }
            )
            solution = solve_btx_challenge(
                item,
                nonce_start=nonce_start,
                max_attempts=max_attempts,
                workers=workers,
                timeout_sec=timeout_sec,
            )
            if solution is None:
                errors.append("BTX solve failed: timeout or max_attempts exhausted")
                return finish(ok=False, verify_code="pow_failed")
            if not verify_btx_solution(item, solution):
                errors.append("BTX internal verification failed")
                return finish(ok=False, verify_code="pow_invalid")
            raw["solution"] = solution.to_payload()
            diagnostics.update(
                {
                    "nonce64_hex": solution.nonce64_hex,
                    "digest_hex": solution.digest_hex,
                    "attempts": solution.attempts,
                    "solve_ms": solution.solve_time_ms,
                }
            )
            ticket = _json_compact(solution.proof)
            if submit:
                if not submit_url:
                    errors.append("BTX submit requested but submit_url is missing")
                    return finish(ok=False, ticket=ticket, verify_code="submit_missing_url")
                submit_resp = _submit_btx_solution(
                    submit_url=submit_url,
                    submit_method=submit_method,
                    submit_json=submit_json,
                    solution=solution,
                    headers=request_headers,
                    timeout_sec=timeout_sec,
                    proxy_server=proxy_server,
                )
                raw["submitResponse"] = submit_resp
                if not submit_resp.get("ok"):
                    errors.append(f"BTX submit failed: HTTP {submit_resp.get('status')}")
                    return finish(ok=False, ticket=ticket, verify_code="submit_failed")
                diagnostics["submitted"] = True
                return finish(ok=True, ticket=ticket, verify_code="validated")
            return finish(ok=True, ticket=ticket, verify_code="solved")
        except Exception as e:
            raw["error"] = {"type": type(e).__name__, "message": str(e)}
            errors.append(str(e))
            return finish(ok=False)


class _TranscriptHasher:
    def __init__(self, sigma_be: bytes, b: int):
        self._hasher = hashlib.sha256()
        self._compress_vec = _derive_compression_vector(sigma_be, b)
        self._b = b

    def add_intermediate(self, c_block: list[int]) -> None:
        if len(c_block) != self._b * self._b:
            raise ValueError(f"BTX c_block must be {self._b * self._b} elements")
        compressed = _field_dot(c_block, self._compress_vec)
        self._hasher.update(int(compressed).to_bytes(4, "little"))

    def finalize(self) -> bytes:
        return hashlib.sha256(self._hasher.digest()).digest()


def _prepare_btx_precomputed(item: BtxChallenge) -> dict[str, Any]:
    seed_a = _parse_hex_fixed(item.matmul.seed_a, 32, "seed_a")
    seed_b = _parse_hex_fixed(item.matmul.seed_b, 32, "seed_b")
    return {
        "A": btx_from_seed_rect(seed_a, item.matmul.n, item.matmul.n),
        "B": btx_from_seed_rect(seed_b, item.matmul.n, item.matmul.n),
        "target_value": _bytes_be_to_int(_parse_hex_fixed(item.target, 32, "target")),
    }


def _solve_btx_range(
    challenge_payload: dict[str, Any],
    nonce_start: int,
    attempts: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    item = parse_btx_challenge(challenge_payload)
    precomputed = _prepare_btx_precomputed(item)
    return _solve_btx_range_prepared(
        challenge_payload,
        precomputed["A"],
        precomputed["B"],
        precomputed["target_value"],
        nonce_start,
        attempts,
        deadline_epoch,
    )


def _solve_btx_range_prepared(
    challenge_payload: dict[str, Any],
    matrix_a: Matrix,
    matrix_b: Matrix,
    target_value: int,
    nonce_start: int,
    attempts: int,
    deadline_epoch: float | None = None,
) -> tuple[int | None, str | None, int]:
    item = parse_btx_challenge(challenge_payload)
    checked = 0
    nonce = int(nonce_start) & MAX_U64
    for _ in range(max(1, int(attempts))):
        if deadline_epoch is not None and checked and checked % 8 == 0 and time.time() >= deadline_epoch:
            return None, None, checked
        digest = _btx_attempt_digest_raw_precomputed(item, matrix_a, matrix_b, nonce)
        checked += 1
        if _bytes_le_to_int(digest) <= target_value:
            return nonce, _bytes_le_to_hex_be(digest), checked
        if nonce == MAX_U64:
            return None, None, checked
        nonce = (nonce + 1) & MAX_U64
    return None, None, checked


def _btx_attempt_digest_raw(challenge: BtxChallenge, nonce: int) -> bytes:
    precomputed = _prepare_btx_precomputed(challenge)
    return _btx_attempt_digest_raw_precomputed(
        challenge,
        precomputed["A"],
        precomputed["B"],
        nonce,
    )


def _btx_attempt_digest_raw_precomputed(
    challenge: BtxChallenge,
    matrix_a: Matrix,
    matrix_b: Matrix,
    nonce: int,
) -> bytes:
    sigma_be = derive_btx_sigma(challenge.header_context, nonce)
    noise = btx_generate_noise(sigma_be, challenge.matmul.n, challenge.matmul.r)
    e = _mat_mul(noise["E_L"], noise["E_R"])
    f = _mat_mul(noise["F_L"], noise["F_R"])
    a_prime = _mat_add(matrix_a, e)
    b_prime = _mat_add(matrix_b, f)
    _, digest = btx_canonical_matmul(a_prime, b_prime, challenge.matmul.b, sigma_be)
    return digest


def _zeros(rows: int, cols: int) -> Matrix:
    return Matrix(rows=rows, cols=cols, data=[0] * (rows * cols))


def _mat_add(a: Matrix, b: Matrix) -> Matrix:
    if a.rows != b.rows or a.cols != b.cols:
        raise ValueError(f"BTX mat_add dim mismatch {a.rows}x{a.cols} vs {b.rows}x{b.cols}")
    return Matrix(a.rows, a.cols, [_field_add(x, y) for x, y in zip(a.data, b.data)])


def _mat_mul(a: Matrix, b: Matrix) -> Matrix:
    if a.cols != b.rows:
        raise ValueError(f"BTX mat_mul inner mismatch {a.cols} vs {b.rows}")
    out = _zeros(a.rows, b.cols)
    b_cols = [[b.data[k * b.cols + j] for k in range(b.rows)] for j in range(b.cols)]
    for i in range(a.rows):
        row = a.data[i * a.cols : (i + 1) * a.cols]
        for j, col in enumerate(b_cols):
            out.data[i * b.cols + j] = _field_dot(row, col)
    return out


def _read_block(m: Matrix, bi: int, bj: int, b: int, out: list[int]) -> None:
    row_start = bi * b
    col_start = bj * b
    for r in range(b):
        src = (row_start + r) * m.cols + col_start
        dst = r * b
        out[dst : dst + b] = m.data[src : src + b]


def _write_block(m: Matrix, bi: int, bj: int, b: int, block: list[int]) -> None:
    row_start = bi * b
    col_start = bj * b
    for r in range(b):
        dst = (row_start + r) * m.cols + col_start
        src = r * b
        m.data[dst : dst + b] = block[src : src + b]


def _multiply_and_accumulate_block(a: list[int], b_buf: list[int], c: list[int], b: int) -> None:
    cols = [[b_buf[k * b + j] for k in range(b)] for j in range(b)]
    for j, col in enumerate(cols):
        for i in range(b):
            row_start = i * b
            folded = _field_dot(a[row_start : row_start + b], col)
            c[row_start + j] = _field_add(c[row_start + j], folded)


def _derive_compression_vector(sigma_be: bytes, b: int) -> list[int]:
    if b <= 0:
        raise ValueError("BTX transcript block size must be positive")
    seed = hashlib.sha256(TRANSCRIPT_COMPRESS_TAG.encode("utf-8") + sigma_be).digest()
    return [_field_from_oracle(seed, k) for k in range(b * b)]


def _derive_noise_seed(domain_tag: str, sigma_be: bytes) -> bytes:
    if len(sigma_be) != 32:
        raise ValueError(f"BTX sigma must be 32 bytes, got {len(sigma_be)}")
    if len(domain_tag) != 18:
        raise ValueError(f"BTX noise domain tag must be 18 chars, got {len(domain_tag)}")
    return hashlib.sha256(domain_tag.encode("utf-8") + sigma_be).digest()


def _field_add(a: int, b: int) -> int:
    s = int(a) + int(b)
    return s - M31_MODULUS if s >= M31_MODULUS else s


def _field_dot(a: list[int], b: list[int]) -> int:
    acc = 0
    pending = 0
    for x, y in zip(a, b):
        acc += int(x) * int(y)
        pending += 1
        if pending == 4:
            acc = _reduce64(acc)
            pending = 0
    return _reduce64(acc)


def _reduce64(x: int) -> int:
    v = (int(x) & M31_MODULUS) + (int(x) >> 31)
    v = (v & M31_MODULUS) + (v >> 31)
    while v >= M31_MODULUS:
        v -= M31_MODULUS
    return v


def _field_from_oracle(seed: bytes, index: int) -> int:
    if len(seed) != 32:
        raise ValueError(f"BTX oracle seed must be 32 bytes, got {len(seed)}")
    index_le = int(index & 0xFFFFFFFF).to_bytes(4, "little")
    for retry in range(256):
        material = seed + index_le
        if retry > 0:
            material += int(retry).to_bytes(4, "little")
        digest = hashlib.sha256(material).digest()
        candidate = int.from_bytes(digest[:4], "little") & M31_MODULUS
        if candidate < M31_MODULUS:
            return candidate
    digest = hashlib.sha256(seed + index_le + b"oracle-fallback").digest()
    return int.from_bytes(digest[:4], "little") % M31_MODULUS


def _load_btx_source(
    *,
    challenge_json: Any,
    challenge_file: str | None,
    challenge_url: str | None,
    timeout_sec: int,
    proxy_server: str | None,
    headers: dict[str, str],
    raw: dict[str, Any],
) -> Any:
    data = _load_json_arg(challenge_json, challenge_file)
    if data is not None:
        raw["challengeSource"] = "json"
        return data
    if not challenge_url:
        raise ValueError("BTX solve requires --challenge-json, --challenge-file, or --challenge-url")
    resp = requests.get(
        challenge_url,
        headers=headers,
        timeout=timeout_sec,
        proxies=_requests_proxies(proxy_server),
    )
    raw["challengeResponse"] = {
        "status": resp.status_code,
        "url": challenge_url,
        "contentType": resp.headers.get("Content-Type", ""),
        "hasBtxHeader": bool(resp.headers.get(HEADER_CHALLENGE)),
    }
    header_challenge = resp.headers.get(HEADER_CHALLENGE)
    if header_challenge:
        raw["challengeSource"] = "header"
        return json.loads(header_challenge)
    if not (200 <= resp.status_code < 500):
        resp.raise_for_status()
    try:
        payload = resp.json()
    except Exception:
        payload = json.loads(resp.text)
    raw["challengeResponse"]["json"] = payload
    raw["challengeSource"] = "url_json"
    if isinstance(payload, dict) and isinstance(payload.get("challenge"), dict):
        return payload["challenge"]
    return payload


def _submit_btx_solution(
    *,
    submit_url: str,
    submit_method: str,
    submit_json: Any,
    solution: BtxSolution,
    headers: dict[str, str],
    timeout_sec: int,
    proxy_server: str | None,
) -> dict[str, Any]:
    req_headers = dict(headers)
    req_headers.update(solution.headers)
    body = _load_json_arg(submit_json, None)
    method = submit_method.upper()
    resp = requests.request(
        method,
        submit_url,
        json=body,
        headers=req_headers,
        timeout=timeout_sec,
        proxies=_requests_proxies(proxy_server),
    )
    try:
        payload: Any = resp.json()
    except Exception:
        payload = resp.text[:1000]
    ok = 200 <= resp.status_code < 400
    if isinstance(payload, dict) and payload.get("valid") is False:
        ok = False
    return {"ok": ok, "status": resp.status_code, "body": payload}


def _load_json_arg(value: Any = None, file_path: str | None = None) -> Any:
    if file_path:
        return json.loads(Path(file_path).read_text(encoding="utf-8"))
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return None
    if text.startswith("@"):
        return json.loads(Path(text[1:]).read_text(encoding="utf-8"))
    return json.loads(text)


def _requests_proxies(proxy_server: str | None) -> dict[str, str] | None:
    cfg = parse_proxy(proxy_server) if proxy_server else None
    if not cfg:
        return None
    return {"http": cfg.url, "https": cfg.url}


def _merge_headers(headers: dict[str, str] | None = None, user_agent: str | None = None) -> dict[str, str]:
    out = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        out.update(headers)
    return out


def _parse_hex_fixed(hex_value: str, byte_len: int, field: str) -> bytes:
    h = str(hex_value)
    if h.startswith(("0x", "0X")):
        h = h[2:]
    if len(h) != byte_len * 2:
        raise ValueError(f"BTX {field}: expected {byte_len * 2} hex chars, got {len(h)}")
    try:
        return bytes.fromhex(h)
    except ValueError as e:
        raise ValueError(f"BTX {field}: invalid hex") from e


def _parse_uint256_hex_to_le(hex_value: str, field: str) -> bytes:
    return _parse_hex_fixed(hex_value, 32, field)[::-1]


def _parse_bits_hex(bits: str) -> int:
    h = str(bits)
    if h.startswith(("0x", "0X")):
        h = h[2:]
    if len(h) != 8:
        raise ValueError(f"BTX bits: expected 8 hex chars, got {len(h)}")
    return int(h, 16)


def _parse_u64(value: Any, *, base: int | None = None) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        n = value
    else:
        text = str(value).strip()
        if base is not None:
            n = int(text[2:] if text.startswith(("0x", "0X")) else text, base)
        elif text.startswith(("0x", "0X")):
            n = int(text[2:], 16)
        else:
            n = int(text, 10)
    if n < 0 or n > MAX_U64:
        raise ValueError(f"BTX nonce64 out of range: {value}")
    return n


def _parse_solution_nonce(value: Any) -> int:
    if isinstance(value, str):
        text = value.strip()
        if len(text) == 16 and all(c in "0123456789abcdefABCDEF" for c in text):
            return _parse_u64(text, base=16)
    return _parse_u64(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _bytes_be_to_int(bytes_value: bytes) -> int:
    return int.from_bytes(bytes_value, "big")


def _bytes_le_to_int(bytes_value: bytes) -> int:
    return int.from_bytes(bytes_value, "little")


def _bytes_le_to_hex_be(bytes_value: bytes) -> str:
    return bytes_value[::-1].hex()


def _first_str(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return None


def _json_compact(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
