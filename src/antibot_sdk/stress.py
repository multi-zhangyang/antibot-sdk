from __future__ import annotations

import asyncio
import statistics
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def percentile(values: list[int], pct: float) -> int | None:
    if not values:
        return None
    xs = sorted(values)
    idx = min(len(xs) - 1, max(0, round((len(xs) - 1) * pct)))
    return xs[idx]


def compact_result(result: Any) -> dict[str, Any]:
    data = asdict(result) if hasattr(result, "__dataclass_fields__") else result
    if not isinstance(data, dict):
        return {"value": repr(data)}
    raw = data.get("raw")
    if isinstance(raw, dict):
        data["raw"] = {
            k: v
            for k, v in {
                "ok": raw.get("ok"),
                "verifyResponse": raw.get("verifyResponse"),
                "verifyFailureCode": raw.get("verifyFailureCode"),
                "attempt": raw.get("attempt"),
                "maxAttempts": raw.get("maxAttempts"),
                "attempts": raw.get("attempts"),
                "candidate": raw.get("candidate"),
                "error": raw.get("error"),
                "watchdog": raw.get("watchdog"),
                "success": raw.get("success"),
                "type": raw.get("type"),
            }.items()
            if v not in (None, "", [], {})
        }
    return data


async def run_stress(
    *,
    name: str,
    runs: int,
    concurrency: int,
    per_run_timeout: int | None,
    run_once: Callable[[int], Awaitable[Any]],
    output_json: str | None = None,
) -> dict[str, Any]:
    runs = max(1, int(runs))
    concurrency = max(1, min(int(concurrency), runs))
    sem = asyncio.Semaphore(concurrency)
    started_wall = utc_now()
    started = time.monotonic()

    async def one(i: int) -> dict[str, Any]:
        async with sem:
            t0 = time.monotonic()
            try:
                coro = run_once(i)
                result = await asyncio.wait_for(coro, timeout=per_run_timeout) if per_run_timeout else await coro
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                data = compact_result(result)
                return {
                    "run": i,
                    "ok": bool(data.get("ok")),
                    "elapsed_ms": elapsed_ms,
                    "verify_code": data.get("verify_code"),
                    "errors": data.get("errors") or [],
                    "diagnostics": data.get("diagnostics") or {},
                    "artifacts": data.get("artifacts") or {},
                    "result": data,
                }
            except asyncio.TimeoutError:
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                return {
                    "run": i,
                    "ok": False,
                    "elapsed_ms": elapsed_ms,
                    "errors": [f"timeout after {per_run_timeout}s"],
                    "exception_type": "TimeoutError",
                }
            except Exception as e:
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                return {
                    "run": i,
                    "ok": False,
                    "elapsed_ms": elapsed_ms,
                    "errors": [str(e)],
                    "exception_type": type(e).__name__,
                }

    records = await asyncio.gather(*(one(i) for i in range(1, runs + 1)))
    ok_records = [r for r in records if r.get("ok")]
    fail_records = [r for r in records if not r.get("ok")]
    elapsed = [int(r["elapsed_ms"]) for r in records if r.get("elapsed_ms") is not None]
    attempt_counts: list[int] = []
    attempt_code_counts: Counter[str] = Counter()
    for r in records:
        raw = ((r.get("result") or {}).get("raw") or {}) if isinstance(r.get("result"), dict) else {}
        if isinstance(raw, dict):
            if isinstance(raw.get("attempt"), int):
                attempt_counts.append(int(raw["attempt"]))
            for a in raw.get("attempts") or []:
                if isinstance(a, dict):
                    code = str(a.get("verifyCode") or a.get("verifyFailureCode") or a.get("error") or "").strip()
                    if code:
                        attempt_code_counts[code] += 1
    summary = {
        "name": name,
        "started_at": started_wall,
        "ended_at": utc_now(),
        "wall_ms": int((time.monotonic() - started) * 1000),
        "runs": runs,
        "concurrency": concurrency,
        "ok": len(ok_records),
        "fail": len(fail_records),
        "success_rate": round(len(ok_records) / runs, 4),
        "avg_ms": round(statistics.mean(elapsed), 1) if elapsed else None,
        "p50_ms": percentile(elapsed, 0.50),
        "p95_ms": percentile(elapsed, 0.95),
        "attempts": {
            "avg": round(statistics.mean(attempt_counts), 2) if attempt_counts else None,
            "max": max(attempt_counts) if attempt_counts else None,
            "code_counts": dict(attempt_code_counts),
        },
        "failure_errors": [
            {
                "run": r.get("run"),
                "elapsed_ms": r.get("elapsed_ms"),
                "verify_code": r.get("verify_code"),
                "errors": r.get("errors"),
                "diagnostics": r.get("diagnostics"),
            }
            for r in fail_records
        ],
    }
    payload = {"summary": summary, "records": records}
    if output_json:
        p = Path(output_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        import json

        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        summary["output_json"] = str(p)
    return payload
