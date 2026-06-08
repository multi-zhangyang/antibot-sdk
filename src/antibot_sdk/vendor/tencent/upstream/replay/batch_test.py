#!/usr/bin/env python3
"""批量后台测试 solve_final.py, 输出真实成功率."""
import json, time
import sys
sys.path.insert(0, '.')
from solve_final import solve_one

N = 20
ok = 0
details = []

for i in range(N):
    print(f"[{i+1}/{N}] start")
    t0 = time.time()
    ret = solve_one(headless=True, verbose=False)
    elapsed = time.time() - t0
    if ret and ret.get("ticket"):
        ok += 1
        details.append({"run": i+1, "ok": True, "elapsed_ms": int(elapsed*1000), "gap_x": ret.get("gap_x"), "conf": ret.get("conf")})
        print(f"  -> PASS {elapsed:.1f}s gap={ret.get('gap_x')} conf={ret.get('conf'):.3f}")
    else:
        details.append({"run": i+1, "ok": False, "elapsed_ms": int(elapsed*1000)})
        print(f"  -> FAIL {elapsed:.1f}s")
    time.sleep(2)

summary = {
    "total": N,
    "ok": ok,
    "fail": N - ok,
    "success_rate": round(ok/N*100, 1),
    "avg_ms": round(sum(d["elapsed_ms"] for d in details)/N, 0),
    "details": details,
}
print("\n===== SUMMARY =====")
print(json.dumps(summary, indent=2))
