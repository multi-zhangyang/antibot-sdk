# Sliding Puzzle Solver

Browser automation + ONNX vision pipeline for Tencent sliding-puzzle challenges.

## Baseline verdict

`v2.1` is the current committed baseline. It is stable for the currently verified Tencent Cloud product-page slider and the bundled `TJCaptcha.js` direct-DOM demo under serial execution. It is not a browserless protocol baseline: the solver still intentionally keeps Chromium in the loop for TDC VM `collect/eks` generation.

| Scope | Verdict | Evidence |
|---|---|---|
| Tencent Cloud product page, serial `POOL_SIZE=1` | baseline stable | `100/100` benchmark: `93/100` passed; earlier `20/20` + `10/10` online passes |
| Bundled `TJCaptcha.js` direct-DOM demo | baseline stable | `3/3` passes |
| Same template, same runtime geometry | usable baseline | dynamic `rate/init_x` + reload retry |
| Different appid/business template | needs re-benchmark | selectors/entry trigger may change |
| Browserless raw HTTP replay | not baseline | `collect/eks` remains browser/TDC-bound |

Promotion rule: keep `v2.1` as the stable baseline while serial online success stays >= `90%` over `100` runs. Latest 100-run evidence is `93.0%` (`93/100`, avg `18253ms`); after that, `no_frame` was addressed with page retry and a focused `30`-run regression reached `29/30`. A drop dominated by `code=50` means vision/trajectory tuning; a drop dominated by `code=12` means TDC/browser fingerprint/context handling; a drop dominated by `no_frame` means entry trigger/frame wait issues.

## Current status

| Metric | Value |
|--------|-------|
| Verified CLI | `replay/solve_optimized.py` |
| Verified service | `replay/captcha_server_v2.py` |
| Online 100-run evidence | `93/100` passed, avg `18253ms` |
| Online long run | `20/20` passed, avg `16561ms` |
| Online v2.1 regression | `10/10` passed, avg `17645ms` |
| Page retry regression | `29/30` passed, avg `17500ms` |
| Local `TJCaptcha.js` regression | `3/3` passed, avg `16763ms` |
| Matrix Zhuque AI Detect profile | ticket smoke `1/1`; backend evidence `evil_level=0`, `confidence=1` |
| Gap detection | `captcha-recognizer` confidence typically `0.93-0.96` |

## Site profiles

The solver now separates generic TencentCaptcha runtime logic from business-site parameters in `replay/site_profiles.py`.

| Profile | Target | Appid | Flow | Evidence |
|---|---|---:|---|---|
| `cloud_product` | `https://cloud.tencent.com/product/captcha` | `199999861` | visible slider demo | historical v2.1 93/100 benchmark |
| `matrix_ai_detect` | `https://matrix.tencent.com/ai-detect/ai_gen_txt` | `2089775896` | Zhuque AI Detect captcha + Matrix WS backend gate | `notes/matrix_profile_ticket_smoke.json`, `notes/matrix_ai_detect_e2e_summary.json` |
| `generic` | explicit `TCAPTCHA_TARGET_URL` | env override | ad-hoc experiments | caller-provided |

Matrix-specific facts now recorded in `notes/matrix-ai-detect-site.md`:

- SDK: `https://captcha.gtimg.com/TCaptcha.js`
- prehandle: `https://t.captcha.qq.com/cap_union_prehandle`
- verify: `https://t.captcha.qq.com/cap_union_new_verify`
- normal first challenge: `show_type=unconscious` / direct-pass ticket
- backend acceptance requires stable guest `fp`, same egress IP, and Matrix WS `evil_level=0`
- verified backend result: `availableUses:3 -> evil_level:0 -> confidence:1 -> availableUses:2`

Profile smoke:

```bash
cd /root/ctf/tencent-captcha
TCAPTCHA_PROFILE=matrix_ai_detect \
TCAPTCHA_PROXY_SERVER=http://127.0.0.1:18092 \
TCAPTCHA_POOL_SIZE=1 TCAPTCHA_BROWSER_MAX_USES=1 TCAPTCHA_BENCH_N=1 \
TCAPTCHA_BENCH_JSON=notes/matrix_profile_ticket_smoke.json \
python3 -u replay/solve_optimized.py
```

Backend acceptance summary without spending another detect quota:

```bash
python3 replay/matrix_guest_e2e.py --out notes/matrix_ai_detect_e2e_summary.json
```

The Matrix summary is redacted by default: reusable guest `fp`, proxy values, captcha egress IPs, tickets, tokens, and object URLs are reported only as presence/count metadata or `"<redacted>"`. Use `--include-sensitive` only for local scratch output that stays under ignored `notes/`.

## How it works

1. **Gap detection**: `captcha-recognizer` (`Slider.identify`) locates the notch bbox on the background image.
2. **Runtime coordinate mapping**: v2 reads rendered DOM + real image width:
   - `rate = bg_css_width / bg_raw_width`
   - `init_x = piece_css_left / rate`
   - `dist_css = (gap_x - init_x) * rate`
3. **Slide simulation**: Playwright `mouse.move/down/up` with `crack_tcaptcha` ease-in-out trajectory.
4. **Credential capture**: browser TDC VM generates `collect/eks`; verify response is captured via Playwright `response` plus in-page XHR/fetch hook.

Raw protocol replay is still not the default path: `collect` is tied to browser fingerprint and runtime trajectory state; mismatches return `errorCode=12`.

## Layout

```
replay/
  solve_optimized.py      # v2 CLI solver: profiles + dynamic geometry + dual verify capture
  site_profiles.py        # per-business-site appid/target/flow metadata
  matrix_guest_e2e.py     # Matrix backend captcha-acceptance evidence wrapper
  captcha_server_v2.py    # v2 FastAPI service: POST /solve, GET /stats, GET /health
  browser_pool.py         # lazy Chromium process pool; fresh context/page per solve; optional proxy
  gap_detect.py           # captcha-recognizer primary + Sobel consensus/fallback
  solve_final.py          # older stable single-browser baseline
hooks/
  xhr_verify_capture.js   # standalone browser hook for verify XHR/fetch capture
raw/ deobf/ notes/        # ignored analysis artifacts
```

## Install

```bash
cd /root/ctf/tencent-captcha
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
playwright install chromium
python -m compileall -q replay
```

## Quickstart

```bash
cd /root/ctf/tencent-captcha
. venv/bin/activate
python -m compileall -q replay
```

### CLI smoke

Single online solve:

```bash
cd replay
TCAPTCHA_POOL_SIZE=1 TCAPTCHA_BROWSER_MAX_USES=1 TCAPTCHA_BENCH_N=1 python -u solve_optimized.py
```

Local `TJCaptcha.js` demo smoke:

```bash
TCAPTCHA_TARGET_URL=file:///root/ctf/tencent-captcha/archive/replay/demo.html \
TCAPTCHA_POOL_SIZE=1 TCAPTCHA_BROWSER_MAX_USES=1 TCAPTCHA_BENCH_N=1 \
python -u solve_optimized.py
```

### Service

```bash
cd /root/ctf/tencent-captcha/replay
TCAPTCHA_POOL_SIZE=1 TCAPTCHA_BROWSER_MAX_USES=1 python -u captcha_server_v2.py
```

```bash
curl -s http://127.0.0.1:8999/health
curl -s -X POST http://127.0.0.1:8999/solve
curl -s -X POST http://127.0.0.1:8999/solve \
  -H 'content-type: application/json' \
  -d '{"target_url":"file:///root/ctf/tencent-captcha/archive/replay/demo.html"}'
curl -s -X POST http://127.0.0.1:8999/solve \
  -H 'content-type: application/json' \
  -d '{"profile":"matrix_ai_detect","verbose":false}'
curl -s http://127.0.0.1:8999/stats
```

Response includes runtime mapping evidence:

```json
{
  "ok": true,
  "ticket": "tr03...",
  "randstr": "@I5V",
  "gap_x": 471,
  "conf": 0.9584,
  "method": "recognizer",
  "rate": 0.5059523809523809,
  "init_x": 49.999962352941175,
  "elapsed_ms": 18781
}
```

## Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `TCAPTCHA_PROFILE` | `cloud_product` | site profile: `cloud_product`, `matrix_ai_detect`, `generic` |
| `TCAPTCHA_TARGET_URL` | profile target | challenge/demo page override |
| `TCAPTCHA_APPID` | profile appid | appid override for direct `TencentCaptcha(appid, ...)` flows |
| `TCAPTCHA_PROXY_SERVER` | unset | Playwright proxy, e.g. `http://127.0.0.1:18092` |
| `TCAPTCHA_PROXY_USER` / `TCAPTCHA_PROXY_PASS` | unset | proxy auth if needed |
| `TCAPTCHA_FP` / `TCAPTCHA_FP_FILE` | sibling warmed fp if present | stable Matrix guest fp for `matrix_ai_detect`; API/benchmark output redacts the value |
| `TCAPTCHA_POOL_SIZE` | `2` | max Chromium processes; lazy-started |
| `TCAPTCHA_BROWSER_MAX_USES` | `2` | rotate browser after N solves |
| `TCAPTCHA_HEADLESS` | `1` | `0` for headed mode |
| `TCAPTCHA_BENCH_N` | `10` | CLI benchmark count |
| `TCAPTCHA_MAX_ATTEMPTS` | `2` | per-page reload retry count; use `3` when `code=50` clusters |
| `TCAPTCHA_PAGE_RETRIES` | `2` | retry fresh page flow on `no_frame` / navigation failures |
| `TCAPTCHA_FRAME_WAIT_SEC` | `18` | captcha frame/render wait timeout |
| `TCAPTCHA_PORT` | `8999` | service port |
| `TCAPTCHA_BENCH_JSON` | unset | write benchmark summary JSON |
| `TCAPTCHA_ALLOW_SOBEL` | `0` | allow Sobel-only fallback when recognizer fails |

## Key reverse refs

- `deobf/dy-ele.formatted.js:3570` — verify request fields: `collect/tlg/eks/sess/ans/pow_*`
- `deobf/dy-ele.formatted.js:4280` — `getRate() = operation_width / bg_raw_width`
- `deobf/dy-ele.formatted.js:4913` — `DynAnswerType_POS = floor(curCSSPosition / rate)`
- `deobf/tdc.formatted.js:661` — TDC VM entry, constants `0x9e3779b9`, `0x13c6ef3720`

## Benchmark

Long-run online benchmark with JSON output:

```bash
cd /root/ctf/tencent-captcha/replay
TCAPTCHA_POOL_SIZE=1 \
TCAPTCHA_BROWSER_MAX_USES=1 \
TCAPTCHA_MAX_ATTEMPTS=2 \
TCAPTCHA_PAGE_RETRIES=2 \
TCAPTCHA_BENCH_N=100 \
TCAPTCHA_BENCH_JSON=../bench_v2_100.json \
python -u solve_optimized.py
```

Expected fields in `TCAPTCHA_BENCH_JSON`:

```json
{
  "total": 100,
  "ok": 93,
  "fail": 7,
  "success_rate": 93.0,
  "avg_ms": 18253,
  "details": [
    {"run": 1, "ok": true, "gap_x": 471, "conf": 0.95, "method": "recognizer", "rate": 0.5059523809523809}
  ]
}
```

## V2.1 stability notes

- `replay/gap_detect.py` caches the `captcha-recognizer` ONNX `Slider` session per process.
- Sobel no longer overrides recognizer on low-but-usable confidence; it is only used for consensus or when `TCAPTCHA_ALLOW_SOBEL=1`.
- `replay/solve_optimized.py` fetches the background image inside the captcha frame first, then falls back to `requests`.
- `captcha_server_v2.py` accepts optional JSON body `{ "target_url": "...", "verbose": false }`.
- `TCAPTCHA_PAGE_RETRIES` retries the fresh page flow when the product page occasionally fails to render a stable captcha frame.
