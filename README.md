# antibot-sdk

面向浏览器验证码与人机验证的异步 Python SDK、Captcha Solver Agent Harness 和 HTTP 服务。
项目把浏览器执行、视觉推理、厂商协议、动作校验和成功证据放在同一套可审计的运行时中：
模型只能提出当前 challenge 的动作，只有真实厂商响应和最终 token 同时满足证据门禁时，结果才会
被标记为成功。

项目适合需要以下能力的团队：

- 在真实浏览器中处理页面级验证码，而不是只拼接 sitekey 和伪造 token；
- 用统一的 observation/action 协议接入新的验证码厂商和题型；
- 让视觉模型处理 Canvas、网格、点选、旋转和拖拽，同时保留确定性状态机；
- 保存脱敏回放，检查动作是否真的执行、厂商是否真的通过，并计算保守的覆盖矩阵；
- 以 SDK、CLI 或有界并发 HTTP API 运行在本地开发机和无桌面的 VPS 上。

## 能力矩阵

状态只描述仓库中有证据支持的范围，不代表所有站点、地区、题库或风险策略都能通过。

| 厂商 | 已接入能力 | 当前证据状态 | 成功判定 |
| --- | --- | --- | --- |
| Cloudflare / Turnstile | 页面级浏览器流、managed challenge、Turnstile response、会话 cookie | 浏览器流可用；站点结果取决于真实会话 | clearance、非测试 token、vendor pass 或站点验证证据 |
| Tencent Captcha | 滑块、文字点选、统一 `drag` / `point` action | 已实现；独立在线矩阵需按站点复测 | `cap_union_new_verify` 的 `errorCode=0` + 非空 ticket |
| Aliyun Captcha V3 | 无痕、一点即过、纯滑块、拼图、图像复原；V2/V3 popup/embed 自动分型 | 拼图、无痕和图像复原有厂商 `T001` 有限样本；纯滑块有站点差分二次校验证据 | `ok` 只接受 `VerifyResult=true` + `T001`；站点差分证明单独报告，`T005/T006` 不计生产通过 |
| GeeTest v4 | `ai`、`slide`、`winlinze`、`match` | 已实现；题型和站点需要分别验证 | 厂商 pass token / flow evidence |
| hCaptcha | HSW/MessagePack、binary、point、bounding-box、multiple-choice、drag-drop、ONNX fallback | `tree-climbing` 与 point 有真实有限样本；不是通用成功率承诺 | `checkcaptcha pass=true` + 厂商 token；配置站点断言时还需提交成功 |
| Google reCAPTCHA | v2 动态 3x3、静态网格、token/callback、站点提交 | 动态 cars、bus、bicycles 有限矩阵证据；多 challenge 不逐题归因 | Google token；配置站点断言时还需提交成功 |
| Arkose Labs FunCaptcha | enforcement frame、Canvas/DOM、轨道轮播、图片选择、点选、旋转、拖拽、统一 Harness | 轨道轮播已有真实有限样本；同次运行也观察到厂商拒绝，不代表通用成功率 | 最终 callback/field token + 明确的 `/fc/ca/ pass=true` |

### 证据状态

| 状态 | 含义 |
| --- | --- |
| `implemented_pending_live_verification` | 代码路径和本地契约已实现，但尚未形成目标厂商的在线通过证据 |
| `live_verified_limited_matrix` | 有真实厂商证据，但样本、题族或独立运行数不足以代表通用成功率 |
| `generalized` | 达到覆盖和基准策略的独立运行、题族、动作完整性与成功率门槛 |
| `explicit_failure` | 结构未知、证据不足或动作不安全时明确失败，不猜测 token |

项目不会用页面消失、checkbox 点击、HTTP 200、初始化 token、模型答案或“看起来通过”的文字
替代厂商证据。Arkose 的 GT2 初始化 token 也不会被当成最终完成 token。

## 安装

项目使用 `src/` 布局，推荐 Python 3.10+ 与 `uv`：

```bash
uv sync
uv run playwright install chromium
uv run antibot diagnose
```

Aliyun runner 和带鉴权代理的 Cloudflare 路径需要 Node.js 22.12+ 以及 vendored
`proxy-chain`：

```bash
uv run antibot install-js-deps
```

可选组件：

```bash
# HTTP 服务
uv sync --extra service

# Pydantic AI planner
uv sync --extra agent

# hCaptcha 本地 ONNX fallback
uv sync --extra hcaptcha
uv run antibot install-hcaptcha-engine
```

hCaptcha 模型按需下载到 `~/.cache/antibot/hcaptcha`，安装器会校验兼容依赖和模型哈希。

## 快速开始

### CLI 自动路由

```bash
uv run antibot auto \
  'https://www.geetest.com/en/adaptive-captcha-demo' \
  --provider geetest \
  --variant ai \
  --raw
```

### 指定 provider

```bash
uv run antibot solve tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --profile cloud_product \
  --appid 199999861 \
  --headless true \
  --timeout 120 \
  --raw
```

```bash
uv run antibot solve geetest \
  --target-url 'https://www.geetest.com/en/adaptive-captcha-demo' \
  --variant match \
  --headless true \
  --timeout 90 \
  --raw
```

### Aliyun Captcha V3

默认 `auto` 优先读取 `InitCaptchaV3.CaptchaType`，并以当前阿里云组件的 DOM、提示文字和
图层作为回退证据，区分五种现行形态：`TRACELESS -> invisible`、
`CHECK_BOX -> one_click`、`SLIDING -> slider`、`PUZZLE -> puzzle`、
`INPAINTING -> image_restore`。未知厂商类型不会被猜成已支持题型。空间推理形态已由厂商于
2025-08-28 下线，不在当前矩阵中。

```bash
uv run antibot solve aliyun \
  --target-url 'https://your-target.example/login' \
  --captcha-type auto \
  --headless true \
  --timeout 180 \
  --raw
```

图像复原需要视觉网关；密钥只从指定环境变量进入 Node 子进程，不写入 options JSON、结果或日志：

```bash
export ANTIBOT_VISION_BASE_URL='https://gateway.example/v1'
export ANTIBOT_VISION_API_KEY='runtime-only-secret'

uv run antibot solve aliyun \
  --target-url 'https://your-target.example/login' \
  --captcha-type image_restore \
  --vision-base-url "$ANTIBOT_VISION_BASE_URL" \
  --vision-model 'your-vision-model' \
  --vision-api-key-env ANTIBOT_VISION_API_KEY \
  --vision-min-confidence 0.5 \
  --output-dir /tmp/antibot-aliyun \
  --raw
```

`captcha_type=auto` 会结合独立拼图块、单张大图和提示文字区分拼图与图像复原；定制 DOM
无法提供足够证据时，应显式传 `puzzle` 或 `image_restore`。生产成功门要求线上
`VerifyCaptchaV3` 同时返回 `VerifyResult=true` 和 `VerifyCode=T001`。`T005`（测试模式）与
`T006`（白名单模式）会保留在 `verify_code` 和脱敏诊断中，但 `ok` 始终为 `false`。
每次可见挑战会在动作前保存仅覆盖验证码区域的 `aliyun_challenge_<type>.png`；图像复原还会
分别保存原始背景、透明碎片和求解时的验证码裁剪图。以下是严格 `T001` 样本中的验证码裁剪，
不包含承载页面、账户数据或验证令牌：

![Aliyun image restoration challenge crop](docs/assets/aliyun-image-restore-example.png)

站点业务接口不暴露 `VerifyCaptchaV3` 响应时，可以显式启用差分验证。runner 会在内存中复用
同一业务请求，只将 `captchaVerifyParam` 换成无效对照值；结果仅保存 URL、长度、HTTP 状态和
脱敏响应摘要，不保存请求体、账号、密码或验证码参数。必须同时配置真实响应与对照响应模式，
两者匹配且响应不同才会得到 `site_secondary_check_pass`；该结论不会将 `ok` 改成 `true`：

```bash
export ANTIBOT_SITE_LOGIN='runtime-site-login'
export ANTIBOT_SITE_PASSWORD='runtime-site-password'

antibot solve aliyun \
  --target-url 'https://your-target.example/login' \
  --captcha-type slider \
  --pre-captcha-fill "#login=$ANTIBOT_SITE_LOGIN" \
  --pre-captcha-fill "#password=$ANTIBOT_SITE_PASSWORD" \
  --site-verification-control \
  --site-verification-accepted-pattern 'credentials rejected' \
  --site-verification-rejected-pattern 'captcha rejected'
```

当前有限在线证据按题型记录：拼图有 3 次独立运行返回 HTTP 200、`Code=Success`、
`Success=true`、`VerifyResult=true`、`VerifyCode=T001`；图像复原有一次相同严格条件的
`T001`，同一串行运行的前一次题面为 `F015`；纯滑块有一次真实参数与无效参数的站点二次校验
差分通过，但未观察到厂商直返 `T001`；无痕有一次 `T001` 和一次 `F008`。这些只是有限成功/
失败样本，不代表稳定成功率。一点即过已实现 `CHECK_BOX` 协议分型、可见控件定位、自然鼠标
点击和动作后厂商校验等待，但仍待独立在线 `T001`，因此能力状态保持
`implemented_pending_independent_live_matrix`。承载页面不进入求解策略：页面入口、表单和
提交动作只通过显式运行时参数提供，题型与算法只依据阿里云组件的实时协议响应、DOM、图层和
验证响应选择。

### Arkose Labs FunCaptcha

视觉网关凭据只通过环境变量提供，不写入源码、JSON、回放或日志：

```bash
export ANTIBOT_VISION_BASE_URL='https://gateway.example/v1'
export ANTIBOT_VISION_API_KEY='runtime-only-secret'

uv run antibot solve arkose \
  --target-url 'https://your-authorized-target.example/arkose' \
  --vision-base-url "$ANTIBOT_VISION_BASE_URL" \
  --vision-model 'your-vision-model' \
  --vision-api-key-env ANTIBOT_VISION_API_KEY \
  --arkose-max-rounds 12 \
  --output-dir /tmp/antibot-arkose \
  --raw
```

Arkose 成功必须同时具备：

1. callback 或 hidden field 中的非空最终 token；
2. `/fc/ca/` response body 中明确的 `answered`、`solved`、`pass`、`success` 等语义；
3. 若指定站点提交断言，提交后的 selector/text 也必须匹配。

Python Harness 的 OpenAI-compatible 视觉后端使用 SSE 流式请求：请求体包含 `stream: true`，
不会发送 `max_tokens`。`--vision-extra-json` 不能覆盖 `model`、`messages`、`stream` 或
`max_tokens`。Aliyun Node 图像复原路径使用同一聊天补全协议的非流式结构化 JSON 响应。

### hCaptcha 官方页面流

以下示例要求真实厂商响应和页面提交都成功：

```bash
export ANTIBOT_VISION_BASE_URL='https://gateway.example/v1'
export ANTIBOT_VISION_API_KEY='runtime-only-secret'

uv run antibot solve hcaptcha \
  --target-url 'https://accounts.hcaptcha.com/demo' \
  --vision-base-url "$ANTIBOT_VISION_BASE_URL" \
  --vision-model 'your-vision-model' \
  --vision-api-key-env ANTIBOT_VISION_API_KEY \
  --submit-selector '#hcaptcha-demo-submit' \
  --success-selector '.hcaptcha-success' \
  --success-text 'Verification Success!' \
  --timeout 180 \
  --raw
```

### Google reCAPTCHA 页面流

```bash
export ANTIBOT_VISION_API_KEY='runtime-only-secret'

uv run antibot solve recaptcha \
  --target-url 'https://2captcha.com/demo/recaptcha-v2' \
  --vision-base-url 'https://gateway.example/v1' \
  --vision-model 'your-vision-model' \
  --vision-api-key-env ANTIBOT_VISION_API_KEY \
  --submit-selector 'form:has(#g-recaptcha) button[type="submit"]' \
  --success-text 'Captcha is passed successfully!' \
  --timeout 180 \
  --raw
```

### Cloudflare / Turnstile

Cloudflare provider 是页面级浏览器流，不是 `sitekey -> token` 的纯协议接口：

```bash
uv run antibot solve cloudflare \
  --target-url 'https://example.com' \
  --mode auto \
  --headless auto \
  --max-wait 120 \
  --raw
```

可选模式为 `auto`、`turnstile`、`managed` 和 `scrape`。`scrape` 只读取页面状态和会话 cookie，
不会主动求解。

## Python API

```python
import asyncio

from antibot_sdk import AntibotClient


async def main() -> None:
    async with AntibotClient() as client:
        result = await client.solve_arkose(
            target_url="https://your-authorized-target.example/arkose",
            headless=True,
            timeout_sec=180,
            vision_base_url="https://gateway.example/v1",
            vision_model="your-vision-model",
            vision_api_key_env="ANTIBOT_VISION_API_KEY",
        )
        print(result.ok)
        print(result.diagnostics.get("arkose_session_verification"))


asyncio.run(main())
```

阿里云也可通过客户端显式选择题型；视觉地址、模型和密钥都由运行时配置提供：

```python
import asyncio

from antibot_sdk import AntibotClient


async def solve_aliyun() -> None:
    async with AntibotClient() as client:
        result = await client.solve_aliyun(
            target_url="https://your-target.example/login",
            captcha_type="image_restore",
            headless=True,
            vision_base_url="https://gateway.example/v1",
            vision_model="your-vision-model",
            vision_api_key_env="ANTIBOT_VISION_API_KEY",
        )
        print(result.ok, result.captcha_type, result.verify_code)


asyncio.run(solve_aliyun())
```

统一 Harness 也可以直接接入新的 provider session：

```python
from antibot_sdk import CaptchaHarness

loop_result = await CaptchaHarness().solve_session(
    session,
    vision_backend,
)

assert loop_result.accepted
```

Session 需要实现 `observe()`、`vision_task()`、`execute()` 和 `verify()`。Harness 会负责：

- observation/action 的 schema 和 observation id 作用域；
- 题型、候选索引、坐标、答案数量和 affordance 校验；
- 超时、动作预算、动态 challenge replacement 和 re-observe；
- `executed=true` 的浏览器执行记录；
- 厂商 token、vendor pass、站点提交和 verifier event 的证据汇总。

模型不能直接写入 `CaptchaResult.ok`、ticket、cookie 或 vendor verification。

## HTTP 服务

安装 service extra 后启动：

```bash
uv run antibot serve \
  --host 0.0.0.0 \
  --port 8000 \
  --max-concurrency 2 \
  --default-timeout 180
```

主要端点：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `GET` | `/health/live` | 进程存活检查 |
| `GET` | `/health/ready` | 浏览器、Node 和 provider 依赖检查 |
| `GET` | `/v1/capabilities` | 当前能力矩阵和证据策略 |
| `GET` | `/v1/profiles` | 内置站点 profile |
| `POST` | `/v1/solve` | 单项 provider 或自动路由求解 |
| `POST` | `/v1/batch` | 有界并发批量求解，保持输入顺序 |

请求示例：

```bash
curl -sS http://127.0.0.1:8000/v1/solve \
  -H 'content-type: application/json' \
  -H 'x-request-id: demo-001' \
  -d '{
    "target_url": "https://www.geetest.com/en/adaptive-captcha-demo",
    "provider": "geetest",
    "timeout_sec": 90,
    "options": {"variant": "ai", "headless": true}
  }'
```

所有响应都会返回 `x-request-id` 和 `x-process-time-ms`。单项浏览器失败保留为结构化 `ok=false`；
格式错误、超时和未捕获异常分别使用 `400`、`504` 和 `500`。

## 回放、覆盖与成功率

```bash
uv run antibot replay-eval /tmp/antibot-runs
```

回放会重新校验 observation/action 关联，而不是信任 provider 写入的 `valid` 或 `executed`。
报告包含题型、prompt family、视觉模型、耗时、token 长度、vendor pass/fail、verifier event、
affordance/action 统计、planner backend、动态 scene replacement 和 trace integrity。

一次 run 经历多个 challenge 时，最终通过会记录为 `multi_challenge_ambiguous`，不会把成功分摊给
每个题型。

平台成功率使用独立 source 运行，不以单个 `result.ok` 作为成功率：

- 默认至少 20 个不重复 source、3 个 prompt family、20 个 challenge instance；
- 每个 run 都必须有真实 vendor evidence 和完整动作 trace；
- 默认目标成功率为 `0.95`；
- 重复回放同一个 source 只计一次；
- 样本不足时返回 `insufficient_samples`，不会发布看似精确的百分比。

当前仓库不发布跨厂商总成功率。已有在线证据只用于能力矩阵中的明确题型和有限样本状态，不能
外推到未验证题库、站点或风险策略。

## 代理、VPS 与资源

2 vCPU / 2 GB RAM 的 VPS 默认采用单浏览器、单 episode；每次 solve 结束都会关闭 page、context、
browser 和 Playwright。不要在同一进程中无限并发浏览器。

无桌面环境下 `headless=auto` 会自动降级到 headless。需要 headed 时使用：

```bash
xvfb-run -a uv run antibot solve geetest \
  --target-url 'https://www.geetest.com/en/adaptive-captcha-demo' \
  --variant ai \
  --headless false
```

显式代理：

```bash
uv run antibot solve cloudflare \
  --target-url 'https://example.com' \
  --proxy 'http://user:pass@host:8080' \
  --headless true \
  --raw
```

环境变量代理需要显式启用：

```bash
export ANTIBOT_USE_ENV_PROXY=1
export ANTIBOT_PROXY='http://user:pass@host:8080'
uv run antibot diagnose
```

代理凭据、视觉 API key、cookie、ticket 和完整验证码 token 不应写入仓库、命令历史、回放或日志。
结果文件只保留脱敏 URL、token 长度、证据摘要和可复现的截图/元数据。

## 项目结构

```text
src/antibot_sdk/
  client.py                 SDK facade and provider routing
  cli.py                    CLI entrypoints
  harness/                  observation/action contracts, loop, replay and adapters
  providers/                provider-specific browser/protocol sessions
  vision.py                 streaming OpenAI-compatible vision backend
  service.py                FastAPI service and bounded batch execution
  capabilities.py           capability and evidence matrix
  persistence.py            redacted result persistence
  proxy.py                  proxy parsing and authenticated bridge support
tests/                      unit, contract, replay and provider-session tests
docs/agent-harness.md       Harness architecture and extension guide
examples/                   local provider fixtures
```

## 开发与验证

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,service,hcaptcha]'
playwright install chromium

pytest -q
ruff check .
python -m compileall -q src/antibot_sdk
uv build
```

浏览器和厂商网络流是独立的在线验证层；单元测试不会把 fake token 当作 live pass。提交前应同时
检查测试、构建、`git diff --check`、敏感字段扫描和真实 provider 证据。

## License

MIT License。详见 [LICENSE](LICENSE)。
