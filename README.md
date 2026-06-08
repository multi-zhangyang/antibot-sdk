# antibot-sdk

`antibot-sdk` 是一个把 **浏览器自动化 / Cloudflare/Turnstile 流程 / hCaptcha / 腾讯滑块验证码 / 阿里云滑块验证码 / AJ-Captcha 协议滑块 / ALTCHA PoW / Anubis PoW / FriendlyCaptcha PoW / Cap PoW / mCaptcha PoW / Wicketkeeper JWT PoW / P-Captcha 二次剩余 PoW / GeeTest v4 / 网易易盾滑动拼图** 收敛到一起的 Python SDK + CLI 工具集。

这个项目不是 Codex skill，而是独立 SDK，目标是把三个已有方向统一成一个可复用、可压测、可继续扩展的工程：

- Pydoll / CDP 浏览器运行器：页面打开、指纹补丁、Cloudflare/Turnstile/Managed Challenge 相关流程观察与自动化。
- Turnstile：新增浏览器 hook/observer provider，采集 `turnstile.render()` 配置、callback token、`cf-turnstile-response`、widget DOM 和网络现场。
- hCaptcha：新增浏览器 hook/observer provider，采集 `hcaptcha.render()`、callback token、`h-captcha-response/g-recaptcha-response`、Enterprise `rqdata`、widget DOM 和网络现场。
- reCAPTCHA / reCAPTCHA Enterprise：新增浏览器 hook/observer provider，采集 `grecaptcha.render()`、`grecaptcha.enterprise.execute()`、action、callback/execute token、`g-recaptcha-response` 和网络现场。
- Submit Verification：把 `token_collected / server_verified / flow_passed` 拆开，用真实页面提交和 success/failure oracle 验证“token 采集 ≠ 真过验证”。
- Tencent Captcha：封装腾讯滑块的页面触发、浏览器池、缺口识别、轨迹拖拽、ticket/randstr 输出。
- Aliyun Captcha：封装阿里云滑块的 Node/Puppeteer runner、站点 profile、attempt/session retry、错误归一、artifact 保留。
- AJ-Captcha / Anji：新增纯 HTTP 协议 solver，走 `/captcha/get` 图像缺口定位、AES `pointJson`、`/captcha/check`，输出二次校验用的 `captchaVerification`，不启动浏览器。
- ALTCHA：新增 PoW 协议 solver，解析 challenge / `WWW-Authenticate: Altcha ...`，计算 number，输出表单 base64 payload 或 M2M Authorization header，不启动浏览器。
- Anubis：新增 `fast/slow` PoW 协议 solver，解析 challenge 页面或 make-challenge JSON，计算 `SHA256(randomData+nonce)` 前导零，可生成 `pass-challenge` 参数或直接换取 auth cookie，不启动浏览器。
- FriendlyCaptcha：新增 classic `friendly-pow` 协议 solver，获取 puzzle 后本地计算 blake2b nonce，输出 `frc-captcha-solution` payload，不启动浏览器。
- Cap / @cap.js：新增 SHA-256 PoW 协议 solver，支持 v1 seeded challenge 与 format-2 `sha256-pow`，可输出 `/redeem` body 或直接换取 Cap token，不启动浏览器。
- mCaptcha：新增 SHA-256 PoW 协议 solver，复现 Rust/JS 的 `bincode(String)+u128 score` 规则，获取 `/api/v1/pow/config` 后本地找 nonce，可提交 `/api/v1/pow/verify` 换 token，不启动浏览器。
- Wicketkeeper：新增 EdDSA-JWT PoW 协议 solver，获取 `/v0/challenge` 后计算 `SHA256(challenge+nonce)` 前导零，可提交 `/v0/siteverify` 换 success JWT，不启动浏览器。
- P-Captcha：新增 QuadraticResidueProblem 协议 solver，解析 Woodall prime challenge，用模平方根直接求 answer，可提交 `{id, answer}`，不启动浏览器。
- GeeTest v4：从 observer 升级出滑动 solver alpha，抓取 bg/slice、CV 匹配缺口、生成拖动轨迹，并提取 `lot_number/captcha_output/pass_token/gen_time`。
- 网易易盾 / Yidun：滑动拼图 solver alpha，抓取 bg/front、OpenCV 定位缺口、模拟滑块轨迹，并提取 `validate/token/zoneId`。
- Policy Engine：把 `F001/F015/NONE/gap/candidate/watchdog timeout` 等失败归类，决定是否换 session，并输出下一步调参建议。
- Stress Harness：统一压测入口，输出 summary、records、attempt code 分布、失败现场。

---

## 现在这个 SDK 可以干什么

### 能力矩阵 / 产品边界

当前版本明确收缩到“几何可解 + 流程可观测”两条线，不把文字点选、语义选图、复杂拖拽包装成主能力。

| Provider | 定位 | `captcha_type` | 状态 | 输出 |
| :--- | :--- | :--- | :--- | :--- |
| Tencent Captcha | 真实 solver | `slider` | primary | `ticket/randstr` |
| Aliyun Captcha | 真实 solver | `slider` | primary | `VerifyCode` / artifacts |
| AJ-Captcha / Anji | 协议 solver | `slider_protocol` | alpha | `captchaVerification/token` |
| ALTCHA | 协议 solver | `proof_of_work` | alpha | base64 payload / Authorization header |
| Anubis | 协议 solver | `proof_of_work` | alpha | pass-challenge params / auth cookie |
| FriendlyCaptcha | 协议 solver | `proof_of_work` | alpha | `frc-captcha-solution` payload |
| Cap / @cap.js | 协议 solver | `proof_of_work` | alpha | `/redeem` body / Cap token |
| mCaptcha | 协议 solver | `proof_of_work` | alpha | verify body / mCaptcha token |
| Wicketkeeper | 协议 solver | `proof_of_work` | alpha | hidden-input solution / success JWT |
| P-Captcha | 协议 solver | `quadratic_residue_pow` | alpha | `answer` / `{id, answer}` |
| GeeTest v4 | 真实 solver | `slider` | alpha | `pass_token/lot_number` |
| NetEase Yidun | 真实 solver | `jigsaw` | alpha | `validate/token/zoneId` |
| Turnstile | 流程/Token 观察采集 | `token_widget` | observer | widget token / artifacts |
| hCaptcha | 流程/Token 观察采集 | `token_widget` | observer | widget token / artifacts |
| reCAPTCHA / Enterprise | 流程/Token 观察采集 | `token_widget` | observer | widget/execute token / artifacts |

不作为 SDK 主能力：

- 文字点选：需要模型训练和样本闭环，OCR/混淆表 demo 不上线。
- 语义选图：需要通用视觉语义模型和真实站点样本，不承诺。
- 复杂拖拽/排序：规则和行为链路不稳定，只保留几何明确的滑块/拼图类。

CLI 可直接查看当前能力边界：

```bash
antibot capabilities
```

统一 `CaptchaResult` 输出字段：

```json
{
  "provider": "tencent",
  "ok": true,
  "captcha_type": "slider",
  "capability": "solver",
  "ticket": "...",
  "randstr": "...",
  "verify_code": "success",
  "elapsed_ms": 1234,
  "artifacts": {},
  "diagnostics": {},
  "raw": {},
  "errors": []
}
```

### 1. 普通页面 / Cloudflare 类页面自动化

- 使用 Pydoll + Chromium 打开页面。
- 自动注入基础浏览器指纹补丁。
- 支持 selector 提取、点击、截图、HTML 保存。
- 支持代理、UA、platform、headless/headed。
- 可用于验证页面是否 clear/challenge/blocked。

命令示例：

```bash
antibot run https://example.com \
  --selector heading=h1 \
  --screenshot /tmp/page.png
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.open(
        "https://example.com",
        selectors={"heading": "h1"},
    )
    print(ret.ok, ret.state, ret.selectors)
```

---

### 2. Cloudflare Turnstile

Turnstile provider 面向嵌入式 widget，第一版目标是 **可探测、可触发、可采集、可压测、可复盘**。

能力：

- 在页面最早阶段 hook `window.turnstile`。
- 记录 `turnstile.render(container, options)` 的 sitekey、action、cData、size、theme、execution、appearance。
- wrap `callback / error-callback / expired-callback / timeout-callback`。
- 采集成功 token：
  - `callback(token)`
  - `turnstile.getResponse()`
  - `input/textarea[name="cf-turnstile-response"]`
- 自动尝试 `turnstile.execute()`，并点击可见 widget/iframe 容器。
- 保留 `turnstile_run.json`、截图、HTML、Turnstile/Cloudflare 相关网络记录。
- 支持代理、headless/headed、trigger selector、stress 压测。

命令示例：

```bash
antibot solve turnstile \
  --url 'https://target.example/path-with-turnstile' \
  --output-dir /tmp/turnstile-run
```

指定触发按钮：

```bash
antibot solve turnstile \
  --url 'https://target.example/path-with-turnstile' \
  --trigger '.cf-turnstile' \
  --trigger 'iframe[src*="challenges.cloudflare.com"]'
```

压测：

```bash
antibot stress turnstile \
  --url 'https://target.example/path-with-turnstile' \
  --runs 10 \
  --concurrency 2 \
  --timeout 90 \
  --output-json /tmp/turnstile-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_turnstile(
        target_url="https://target.example/path-with-turnstile",
        output_dir="/tmp/turnstile-run",
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("sitekey"))
```

当前定位：

- 对无感/低风险直接出 token、页面自身成功 callback、测试页/集成页的 Turnstile token 链路有效。
- Cloudflare Managed Challenge 页面仍优先使用 `antibot run --mode managed/turnstile` 的 Pydoll 路径；`solve turnstile` 更偏嵌入式 widget token 采集。

---

### 3. hCaptcha

hCaptcha provider 沿用 Turnstile/GeeTest 的 hook-observer 架构，第一版先把 **render 参数、token、Enterprise 参数、网络现场和压测** 做完整。

能力：

- 在页面最早阶段 hook `window.hcaptcha`，同时兼容 hCaptcha 的 `window.grecaptcha` 兼容层。
- 记录 `hcaptcha.render(container, options)`：
  - `sitekey`
  - `size/theme/tabindex`
  - Enterprise 常见 `rqdata`
  - endpoint/assethost/imghost/reportapi 等站点配置线索
- wrap `callback / error-callback / expired-callback / chalexpired-callback / open-callback / close-callback`。
- 采集成功 token：
  - `callback(token)`
  - `hcaptcha.getResponse()`
  - `textarea/input[name="h-captcha-response"]`
  - `textarea/input[name="g-recaptcha-response"]`
- 自动尝试 `hcaptcha.execute()`，并点击可见 widget/iframe 容器。
- 保留 `hcaptcha_run.json`、截图、HTML、hCaptcha 相关网络记录。
- 支持代理、headless/headed、trigger selector、stress 压测。

命令示例：

```bash
antibot solve hcaptcha \
  --url 'https://target.example/path-with-hcaptcha' \
  --output-dir /tmp/hcaptcha-run
```

指定触发按钮：

```bash
antibot solve hcaptcha \
  --url 'https://target.example/path-with-hcaptcha' \
  --trigger '.h-captcha' \
  --trigger 'iframe[src*="hcaptcha.com"]'
```

压测：

```bash
antibot stress hcaptcha \
  --url 'https://target.example/path-with-hcaptcha' \
  --runs 10 \
  --concurrency 2 \
  --timeout 90 \
  --output-json /tmp/hcaptcha-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_hcaptcha(
        target_url="https://target.example/path-with-hcaptcha",
        output_dir="/tmp/hcaptcha-run",
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("sitekey"))
```

当前定位：

- 对无感/低风险直接出 token、页面自身 callback、测试页/集成页的 hCaptcha token 链路有效。
- 遇到真实图片/多轮 challenge 时，当前版本只保留完整现场，不把图片挑战求解作为 SDK 主能力。

---

### 4. reCAPTCHA / reCAPTCHA Enterprise

reCAPTCHA provider 面向 v2 widget、invisible、v3/Enterprise score/action 模式，第一版先做 **render/execute/token/action/network artifact**。

能力：

- 在页面最早阶段 hook `window.grecaptcha`。
- 自动 wrap `window.grecaptcha.enterprise`。
- 记录 `grecaptcha.render(container, options)`：
  - `sitekey`
  - `size/theme/badge`
  - `action`
  - callback 名称或函数
- 记录 `grecaptcha.execute(sitekey, {action})` / `grecaptcha.enterprise.execute(sitekey, {action})`：
  - execute sitekey
  - action
  - API 类型：`grecaptcha` 或 `grecaptcha.enterprise`
- wrap `callback / expired-callback / error-callback`。
- 采集成功 token：
  - `callback(token)`
  - `execute()` Promise 返回 token
  - `grecaptcha.getResponse()`
  - `textarea/input[name="g-recaptcha-response"]`
- 自动尝试历史 render/execute 参数，点击可见 widget/iframe 容器。
- 保留 `recaptcha_run.json`、截图、HTML、reCAPTCHA/Enterprise 网络记录。
- 支持代理、headless/headed、trigger selector、stress 压测。

命令示例：

```bash
antibot solve recaptcha \
  --url 'https://target.example/path-with-recaptcha' \
  --output-dir /tmp/recaptcha-run
```

压测：

```bash
antibot stress recaptcha \
  --url 'https://target.example/path-with-recaptcha' \
  --runs 10 \
  --concurrency 2 \
  --timeout 90 \
  --output-json /tmp/recaptcha-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_recaptcha(
        target_url="https://target.example/path-with-recaptcha",
        output_dir="/tmp/recaptcha-run",
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("sitekey"), ret.diagnostics.get("action"))
```

当前定位：

- 对 v3/Enterprise 低风险直接出 token、页面自身 callback/execute、测试页/集成页 token 链路有效。
- 遇到 v2 图片/checkbox 交互挑战时，当前版本先保留完整现场，不把图片挑战求解作为 SDK 主能力。

---

### 5. 真过闭环验证层（Submit Verification）

这一层是当前版本最重要的底层改动：明确把 **采集 token** 和 **真过页面验证** 分开，避免把 observer 拿到 token 误判成已经过站点。

状态字段拆成三层：

```text
token_collected   # 是否有 token/ticket/pass_token
server_verified   # 页面提交后 success oracle 是否匹配；不是官方 siteverify API 调用
flow_passed       # 真实表单/页面流程是否通过
```

能力：

- 支持 reCAPTCHA / hCaptcha / Turnstile 的 token 注入与表单提交。
- 自动写入默认字段：
  - reCAPTCHA -> `g-recaptcha-response`
  - hCaptcha -> `h-captcha-response`
  - Turnstile -> `cf-turnstile-response`
- 支持自定义 token selector、submit selector、成功/失败 selector、期望 URL。
- 支持提交前预填表单和点击步骤。
- 失败分类会归一成：`token_missing`、`token_rejected`、`action_mismatch`、`hostname_mismatch`、`low_score`、`session_binding_failed`、`image_challenge_required`、`form_flow_failed`、`navigation_failed`、`timeout`、`unknown`。
- 输出 `verification_run.json`、`verification_page.png`、`verification_page.html`，便于复盘为什么没过。

命令示例：

```bash
antibot verify recaptcha \
  --url 'https://target.example/form' \
  --captcha-json /tmp/recaptcha-run/recaptcha_run.json \
  --submit '#submit' \
  --success '.login-ok' \
  --failure '.captcha-error' \
  --output-dir /tmp/verify-recaptcha
```

直接传 token：

```bash
antibot verify hcaptcha \
  --url 'https://target.example/form' \
  --token 'P1_xxx' \
  --token-field 'h-captcha-response' \
  --submit 'button[type=submit]' \
  --expected-url-contains '/dashboard'
```

Python 示例：

```python
import asyncio
from antibot_sdk import SubmitFlow, verify_submit_flow

async def main():
    ret = await verify_submit_flow(
        SubmitFlow(
            provider="turnstile",
            url="https://target.example/form",
            token="0.xxx",
            submit_selector="button[type=submit]",
            success_selector=".success",
            failure_selector=".captcha-error",
            output_dir="/tmp/verify-turnstile",
        )
    )
    print(ret.ok, ret.state, ret.failure_class, ret.reason)

asyncio.run(main())
```

当前定位：

- observer provider 负责 **采集现场和 token**。
- verification 层负责 **把 token 放回真实页面提交，并用 oracle 判断是否真过**。
- `server_verified=true` 在当前实现里表示“页面提交后的 success oracle 命中”，不是直接调用 Google/hCaptcha/Cloudflare 官方 verify API。
- 如果失败，会尽量把原因归到 action/hostname/score/session/图片挑战/流程错误等类别，方便下一轮策略调参。

### 6. 腾讯滑块验证码

能力：

- 内置 `cloud_product` profile。
- 支持自动打开腾讯云产品页 demo 并触发滑块。
- 使用 Playwright BrowserPool，压测时默认共享池，减少冷启动和资源抖动。
- 动态识别背景图缺口，计算真实 DOM 坐标和拖动距离。
- 输出 `ticket`、`randstr`、识别置信度、gap、rate、init_x 等诊断信息。
- 超时/异常后按 SDK 自己的 browser marker 精准清理，不影响其他 Playwright 任务。
- 支持代理，包括 `host:port:user:pass` 这种代理池格式。

命令示例：

```bash
antibot solve tencent \
  --profile cloud_product \
  --headless
```

使用代理：

```bash
antibot solve tencent \
  --profile cloud_product \
  --proxy 'host:port:user:pass'
```

压测：

```bash
antibot stress tencent \
  --profile cloud_product \
  --runs 10 \
  --concurrency 3 \
  --timeout 140 \
  --output-json /tmp/tencent-stress.json
```

旧隔离模式：

```bash
antibot stress tencent \
  --profile cloud_product \
  --runs 10 \
  --concurrency 3 \
  --isolated
```

---

### 7. 阿里云滑块验证码

能力：

- 封装 `aliyun-captcha-repro` 的 Node runner。
- 内置 Qoder 注册页高难 profile：`qoder_signup`。
- 自动完成 Qoder 注册表单两段流程，触发 `#aliyunCaptcha-*` 滑块。
- 支持 slot-mask 缺口识别、候选 raw 窗口过滤、轨迹控制、F001/F015 恢复。
- 支持 attempt retry、session retry、timeout cleanup、artifact 输出。
- Node runner 内置 per-stage watchdog：`proxy.anonymize / browser.launch / page.goto / preCaptchaAction / wait_ready / read_gap / drag / runtime snapshot / close` 都有独立阈值。
- 每个 Aliyun 结果会带 `diagnostics.policy`，将失败分类成 `reputation_or_session`、`geometry_or_delta`、`watchdog_or_timeout`、`transient_candidate_or_dom` 等。
- timeout 时如果现场 JSON 已经 `T001`，会按成功返回，并在 diagnostics 标记恢复信息。
- 支持代理池格式 `host:port:user:pass`。

命令示例：

```bash
antibot solve aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --output-dir /tmp/antibot-qoder
```

使用代理：

```bash
antibot solve aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --proxy 'host:port:user:pass'
```

压测：

```bash
antibot stress aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --proxy 'host:port:user:pass' \
  --runs 20 \
  --concurrency 1 \
  --timeout 300 \
  --output-dir /tmp/aliyun-stress \
  --output-json /tmp/aliyun-stress.json
```

Qoder + proxy 默认策略：

- 单 session 最多 3 attempts。
- 最多 2 次 session retry。
- 每次 session retry 最多 2 attempts。
- 目标是降低坏 session 内的 200s+ 长尾。
- 如果某一阶段卡死，watchdog 会快速写入现场 JSON，例如：

```json
{
  "watchdog": {
    "label": "page.goto",
    "timeoutMs": 65000,
    "elapsedMs": 65012
  }
}
```

仍然可以手动覆盖：

```bash
antibot stress aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --proxy 'host:port:user:pass' \
  --max-attempts 5 \
  --session-retries 1 \
  --session-retry-max-attempts 2
```

---

### 8. AJ-Captcha / Anji 协议滑块

AJ-Captcha 的 `blockPuzzle` 是当前更适合 SDK 化的一类：接口、坐标、AES 和二次校验链路都在协议层闭合，不需要打开 Chromium，也不需要模拟拖动。

能力：

- 纯 HTTP 调用 `/captcha/get` 获取 `originalImageBase64 / jigsawImageBase64 / token / secretKey`。
- 使用 jigsaw alpha mask 在背景图中定位真实缺口：
  - `white_alpha_edge`
  - `edge_alpha_edge`
  - `edge_dilate*_alpha_edge`
  - `color_template` fallback
- 按前端逻辑生成紧凑坐标：`{"x":123,"y":5}`。
- 按官方 Java/CryptoJS 逻辑生成：
  - `pointJson = AES/ECB/PKCS7(point_json, secretKey)`
  - `captchaVerification = AES/ECB/PKCS7(token + "---" + point_json, secretKey)`
- POST `/captcha/check` 完成一次校验，返回业务侧二次校验要用的 `captchaVerification`。
- 支持 API prefix，例如 `http://host` 或 `http://host/captcha-api`。
- 默认最多 2 次 fresh token attempt；遇到一次性 token 失效、坐标误判或服务端并发抖动时自动重新 `/captcha/get`。
- 支持 artifact：`ajcaptcha_run.json / ajcaptcha_original.png / ajcaptcha_jigsaw.png`。
- 支持 stress 压测，且不消耗浏览器内存。

命令示例：

```bash
antibot solve ajcaptcha \
  --base-url 'http://127.0.0.1:18080' \
  --output-dir /tmp/ajcaptcha-run
```

带 API 前缀：

```bash
antibot solve ajcaptcha \
  --base-url 'https://target.example/captcha-api' \
  --get-path /captcha/get \
  --check-path /captcha/check
```

压测：

```bash
antibot stress ajcaptcha \
  --base-url 'http://127.0.0.1:18080' \
  --runs 50 \
  --concurrency 5 \
  --timeout 20 \
  --max-attempts 2 \
  --output-json /tmp/ajcaptcha-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_ajcaptcha(
        base_url="http://127.0.0.1:18080",
        output_dir="/tmp/ajcaptcha-run",
    )
    print(ret.ok, ret.ticket, ret.randstr)
```

当前定位：

- 这是协议 solver，不是浏览器滑动 solver；在 VPS/headless 环境更稳、更省内存。
- 默认只支持 `blockPuzzle`，不把 AJ-Captcha 的 `clickWord` 文字点选纳入主能力。
- 若目标服务端直接返回 `point`，SDK 会优先走返回点位；默认部署不返回时走 CV 缺口定位。

---

### 9. ALTCHA PoW 协议验证码

ALTCHA 不是图片验证码，而是轻量 Proof-of-Work 验证：服务端返回 `algorithm / challenge / salt / signature / maxnumber`，客户端寻找一个 `number`，使得：

```text
hash(salt + number) == challenge
```

这类非常适合协议层 SDK：不需要浏览器，不需要识图，也不需要模拟鼠标。

能力：

- GET challenge endpoint，或直接读取 challenge JSON。
- 解析 M2M 的 `WWW-Authenticate: Altcha ...`。
- 支持 `SHA-1 / SHA-256 / SHA-512`。
- 输出两种业务侧可用结果：
  - 表单/widget：base64 JSON payload，通常填入 `input[name="altcha"]`。
  - M2M/API：`Authorization: Altcha algorithm=..., number=...` header。
- 支持 `workers` 多进程分片搜索，默认单 worker，避免 VPS 内存/CPU 被打爆。
- 支持 artifact：`altcha_run.json`。

命令示例：

```bash
antibot solve altcha \
  --challenge-url 'https://target.example/altcha/challenge'
```

直接传 challenge JSON：

```bash
antibot solve altcha \
  --challenge-json '{"algorithm":"SHA-256","challenge":"...","salt":"...","signature":"...","maxnumber":1000000}'
```

M2M `WWW-Authenticate`：

```bash
antibot solve altcha \
  --www-authenticate 'Altcha challenge={"algorithm":"SHA-256","challenge":"...","salt":"...","signature":"...","maxnumber":1000000}' \
  --mode m2m
```

压测：

```bash
antibot stress altcha \
  --challenge-url 'https://target.example/altcha/challenge' \
  --runs 50 \
  --concurrency 5 \
  --timeout 30
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_altcha(
        challenge_url="https://target.example/altcha/challenge",
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 支持 ALTCHA v1 PoW 协议，属于真实协议 solver。
- `ticket` 在默认 `form` 模式下是 base64 payload；在 `m2m` 模式下是 `Authorization: Altcha challenge={...}` header。
- 如果服务端启用了自定义高 `maxnumber`，建议按 VPS 资源显式设置 `--workers` 和 `--timeout`。

---

### 10. Anubis PoW

Anubis 是现在不少站点用来挡 AI 抓取/自动化访问的自托管 PoW 网关。它的核心不是图片验证码，而是浏览器执行 JS worker：寻找一个 `nonce`，使得：

```text
SHA256(randomData + nonce).hex().startswith("0" * difficulty)
```

SDK 现在把这条链路做成纯协议 solver：

- 可解析 challenge 页面里的 `anubis_challenge` JSONScript。
- 可解析 devel/test 或反代暴露的 `make-challenge` JSON：`rules/challenge/id`。
- 支持 `fast/slow` 两个当前等价的 SHA-256 PoW 方法。
- 输出：
  - 不 submit：`pass-challenge` 所需参数 JSON。
  - `--submit`：GET `/pass-challenge`，返回 Anubis auth cookie。
- 自动处理 Anubis 的 cookie-check 辅助 cookie；不启动浏览器。

命令示例：

```bash
antibot solve anubis \
  --page-url 'https://target.example/path-with-anubis' \
  --submit
```

直接使用 API prefix：

```bash
antibot solve anubis \
  --base-url 'https://target.example' \
  --redir '/' \
  --submit
```

只解 PoW，不提交：

```bash
antibot solve anubis \
  --challenge 'randomDataHex' \
  --difficulty 4
```

压测：

```bash
antibot stress anubis \
  --base-url 'https://target.example' \
  --submit \
  --runs 30 \
  --concurrency 5 \
  --timeout 30
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_anubis(
        page_url="https://target.example/path-with-anubis",
        submit=True,
        timeout_sec=30,
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是协议层 PoW solver，不是打开页面跑 JS worker。
- 已和 Anubis 官方 Go test fixture 对齐：`SHA256("hunter"+"0")`。
- 难度越高平均搜索空间越大：difficulty=4 约 16^4 次量级。VPS 上默认单 worker，可显式调 `--workers`。

---

### 11. FriendlyCaptcha classic PoW

FriendlyCaptcha classic 的核心不是图片识别，而是 `friendly-pow`：服务端返回一个 signed puzzle，浏览器 widget 在 worker/WASM 里计算多个 8 字节 nonce，最后把结果写入隐藏字段 `frc-captcha-solution`。

SDK 现在把这条链路下沉成纯协议 solver：

- GET puzzle endpoint，兼容官方形态：
  - `https://api.friendlycaptcha.com/api/v1/puzzle?sitekey=...`
  - 响应 `{"data":{"puzzle":"<signature>.<base64 puzzle>"}}`
- 也支持直接传入 puzzle 字符串或文件。
- 解析 puzzle buffer：
  - solution count：offset `14`
  - difficulty：offset `15`
  - threshold：`floor(2^((255.999-d)/8))`
- 按 FriendlyCaptcha 的 `friendly-pow` 逻辑求解：
  - puzzle buffer 补零到 128 bytes
  - `input[120] = puzzle_index`
  - 搜索 `input[123] + input[124:128]` nonce
  - `blake2b-256(input)` 前 4 字节 little-endian 小于 threshold 即命中
- 输出完整 hidden field payload：

```text
<signature>.<puzzle_b64>.<solutions_b64>.<diagnostics_b64>
```

命令示例：

```bash
antibot solve friendlycaptcha \
  --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' \
  --sitekey 'FCxxxxx'
```

直接传 puzzle：

```bash
antibot solve friendlycaptcha \
  --puzzle 'signature.base64Puzzle'
```

压测：

```bash
antibot stress friendlycaptcha \
  --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' \
  --sitekey 'FCxxxxx' \
  --runs 20 \
  --concurrency 2 \
  --timeout 60
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_friendlycaptcha(
        puzzle_url="https://api.friendlycaptcha.com/api/v1/puzzle",
        sitekey="FCxxxxx",
    )
    print(ret.ok, ret.ticket)
```

当前定位：

- 这是 FriendlyCaptcha classic PoW solver，不是 hCaptcha/reCAPTCHA 那种图片挑战 solver。
- 默认单 worker，`--workers` 可加速，但 VPS 上不建议盲目开太大。
- 默认每段 solution 最多搜索 `10,000,000` 次，可用 `--max-attempts-per-solution` 调整。

---

### 12. Cap / @cap.js PoW

Cap 是 self-hosted CAPTCHA 方向里比较适合 SDK 化的一类：核心是 SHA-256 proof-of-work。SDK 当前只做协议层可验证的部分，不启动浏览器。

支持两种主流形态：

- v1 seeded challenge：服务端返回 `token` 和 `challenge: {c, s, d}`，SDK 按 Cap PRNG 生成每个 `salt/target` 并搜索 nonce。
- format-2 `sha256-pow`：服务端直接返回 `challenges: [{protocol:"sha256-pow", payload:{salt,target}}]`，SDK 逐个求解并输出 `{nonce}`。

输出有两种：

- 不 redeem：`ticket` 是可直接 POST 给业务 `/redeem` 的 JSON body：`{"token":"...","solutions":[...]}`。
- 设置 `--api-endpoint` 或 `--redeem`：自动 POST `/redeem`，`ticket` 返回最终 Cap token。

命令示例：

```bash
antibot solve cap \
  --api-endpoint 'https://target.example/cap/'
```

只解 seeded token，不请求网络：

```bash
antibot solve cap \
  --token 'challenge token' \
  --c 50 \
  --s 32 \
  --d 4
```

直接传 challenge JSON：

```bash
antibot solve cap \
  --challenge-json '{"token":"...","challenge":{"c":50,"s":32,"d":4}}'
```

压测：

```bash
antibot stress cap \
  --api-endpoint 'https://target.example/cap/' \
  --runs 50 \
  --concurrency 5 \
  --timeout 60
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_cap(
        api_endpoint="https://target.example/cap/",
        timeout_sec=60,
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 支持 Cap v1 seeded SHA-256 PoW 与 format-2 `sha256-pow`。
- format-2 的 `rsw`、`instrumentation` 不伪装成已解决；遇到时会明确返回 unsupported diagnostics。
- 默认单 worker，适合 VPS；高 `d` 或高 `c` 时再显式调 `--workers` 和 `--timeout`。

---

### 13. P-Captcha QuadraticResidueProblem

P-Captcha 比普通 hashcash 更有意思：服务端给出 Woodall prime `p` 下的一组二次剩余 `n = x² mod p`，浏览器 worker 用 Tonelli-Shanks 求模平方根并把答案串提交给服务端。SDK 当前把这条链路下沉成纯 Python 协议 solver。

关键点：

- challenge 形态：`QuadraticResidueProblem,<base64(problem)>`。
- `problem` 解码后是：`<woodall>,<n1_base64>,<n2_base64>...`。
- 官方内置 Woodall prime alias：`2xs/xs/sm/md/lg/xl/2xl/3xl`。
- 当前这些 Woodall prime 都满足 `p % 4 == 3`，所以无需暴力，直接：

```text
root = n^((p + 1) / 4) mod p
```

- 输出 answer：把每个 root 按官方 bigint/base64 规则编码后用逗号连接。
- 如果传入 `--validate-url --validate`，SDK 会 POST：

```json
{"id":"challenge-id","answer":"root1_b64,root2_b64"}
```

命令示例：

```bash
antibot solve pcaptcha \
  --challenge-url 'https://target.example/api/challenge'
```

带服务端校验：

```bash
antibot solve pcaptcha \
  --challenge-url 'https://target.example/api/challenge' \
  --validate-url 'https://target.example/api/validate' \
  --validate
```

直接传 raw challenge：

```bash
antibot solve pcaptcha \
  --challenge 'QuadraticResidueProblem,...' \
  --id 'challenge-id'
```

压测：

```bash
antibot stress pcaptcha \
  --challenge-url 'https://target.example/api/challenge' \
  --validate-url 'https://target.example/api/validate' \
  --validate \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_pcaptcha(
        challenge_url="https://target.example/api/challenge",
        validate_url="https://target.example/api/validate",
        validate=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是数学协议 solver，不是浏览器模拟。
- 对官方 QuadraticResidueProblem/Woodall primes 有完整解析、求根、answer 编码、可选服务端校验。
- 若未来 P-Captcha 增加新的 problem type，当前版本会明确 unsupported，不伪装成通过。

---

### 14. mCaptcha PoW

mCaptcha 是 self-hosted PoW CAPTCHA。浏览器 widget 的流程是：`POST /api/v1/pow/config` 取 `string/difficulty_factor/salt`，本地搜索 nonce，再 `POST /api/v1/pow/verify` 换取服务端 token。SDK 当前把这条链路做成纯协议 solver。

关键点：

- 官方 Rust verifier 会先对 challenge string 做 `bincode::serialize(&String)`。SDK 已复现：`u64 little-endian byte length + UTF-8 bytes`。
- 哈希输入：`salt || bincode(String) || decimal_nonce`。
- score：SHA-256 digest 前 16 字节按 big-endian `u128` 解释。
- 通过条件：

```text
score >= u128::MAX - u128::MAX / difficulty_factor
```

命令示例：

```bash
antibot solve mcaptcha \
  --base-url 'https://captcha.example' \
  --sitekey 'site-key'
```

只解 PoW，不提交 `/verify`：

```bash
antibot solve mcaptcha \
  --config-json '{"key":"site-key","string":"...","difficulty_factor":50,"salt":"..."}' \
  --no-submit
```

带服务端 token 校验：

```bash
antibot solve mcaptcha \
  --base-url 'https://captcha.example' \
  --sitekey 'site-key' \
  --secret 'owner-secret' \
  --siteverify
```

压测：

```bash
antibot stress mcaptcha \
  --base-url 'https://captcha.example' \
  --sitekey 'site-key' \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_mcaptcha(
        base_url="https://captcha.example",
        sitekey="site-key",
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是协议层 PoW solver，不开浏览器，适合 VPS/headless 受限环境。
- 已和官方 `mcaptcha_pow_sha256 0.5.0` Rust fixture 对齐。
- difficulty_factor 越大平均搜索空间越大，VPS 上默认单 worker，避免 CPU 打满。

---

### 15. Wicketkeeper JWT PoW

Wicketkeeper 是 self-hosted PoW CAPTCHA：服务端签发 EdDSA JWT challenge，前端 worker 搜索 nonce，后端 `/v0/siteverify` 校验 JWT、PoW 和 replay 状态后返回 success JWT。SDK 当前把这条链路做成纯协议 solver。

关键点：

- challenge endpoint：`GET /v0/challenge`。
- challenge 响应：`challenge / difficulty / token`，其中 token 是包含 `cid/diff/iat/exp` 的 EdDSA JWT。
- PoW 输入：`challenge + nonce`。
- 通过条件：SHA-256 hex 字符串满足指定数量的前导 0 nibble。
- verify endpoint：`POST /v0/siteverify`，提交：

```json
{"token":"challenge.jwt","nonce":"73720","response":"000021ae..."}
```

命令示例：

```bash
antibot solve wicketkeeper \
  --base-url 'https://captcha.example'
```

只解 PoW，不提交 `/siteverify`：

```bash
antibot solve wicketkeeper \
  --challenge-json '{"challenge":"hunter","difficulty":4,"token":"challenge.jwt"}' \
  --no-submit
```

压测：

```bash
antibot stress wicketkeeper \
  --base-url 'https://captcha.example' \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_wicketkeeper(
        base_url="https://captcha.example",
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是协议层 JWT + PoW solver，不打开浏览器。
- 已按 upstream `client/src/solvers/fast.js` 与 `server/handlers.go` 复现：`SHA256(challenge+nonce)` + leading-zero nibble。
- success JWT 仍由服务端签发，SDK 不伪造签名，只完成客户端应做的 PoW 和提交闭环。

---

### 16. GeeTest v4 / 极验

GeeTest v4 现在不再只是 observer，已经加入 **slide solver alpha**：能在官方 v4 slide demo 上完成图片定位、轨迹拖动和成功载荷提取。但这个能力还不是稳定通杀，真实站点仍会受风险策略、设备指纹、轨迹质量和出口 IP 影响。

能力：

- 在页面最早阶段 hook `window.initGeetest4`。
- 记录 GeeTest v4 config，例如 `captchaId/captcha_id`、`product`。
- wrap CAPTCHA 实例的 `appendTo / bindForm / showCaptcha / verify / onReady / onSuccess / getValidate` 等方法。
- 自动尝试调用 `showCaptcha()`，并点击页面中的 GeeTest 相关元素。
- 对滑动验证自动抽取：
  - `.geetest_bg` 背景图
  - `.geetest_slice_bg` 滑块图
  - `.geetest_btn` / track DOM 坐标
- 使用 OpenCV 估算缺口距离，当前会综合：
  - 原始 slice 色彩模板匹配 `color_template`
  - 基于 DOM/服务端 `ypos` 的纵向约束
  - 背景中低饱和/暗色缺口阴影匹配 `shadow_dark`
- 保存 `geetest_slide_bg_N.png` 和 `geetest_slide_slice_N.png`。
- 生成带缓动、抖动和 hold 的浏览器 mouse trace 进行拖拽。
- 当页面触发 `onSuccess` 时，自动读取 v4 成功载荷：

```json
{
  "lot_number": "...",
  "captcha_output": "...",
  "pass_token": "...",
  "gen_time": "..."
}
```

- 保留 `geetest_run.json`、截图、HTML、GeeTest 相关网络记录。
- 支持代理、headless/headed、trigger selector、stress 压测。

命令示例：

```bash
antibot solve geetest \
  --url 'https://target.example/path-with-geetest' \
  --output-dir /tmp/geetest-run \
  --slide-attempts 3
```

指定触发按钮：

```bash
antibot solve geetest \
  --url 'https://target.example/path-with-geetest' \
  --trigger '.login-submit' \
  --trigger '.geetest_btn' \
  --slide-attempts 3
```

只做 observer，不拖动：

```bash
antibot solve geetest \
  --url 'https://target.example/path-with-geetest' \
  --no-slide-solve
```

压测：

```bash
antibot stress geetest \
  --url 'https://target.example/path-with-geetest' \
  --runs 10 \
  --concurrency 2 \
  --timeout 90 \
  --slide-attempts 4 \
  --output-json /tmp/geetest-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_geetest(
        target_url="https://target.example/path-with-geetest",
        trigger_selectors=[".geetest_btn"],
        output_dir="/tmp/geetest-run",
    )
    print(ret.ok, ret.ticket, ret.randstr, ret.raw.get("success"))
```

当前定位：

- 已能处理无感/低风险直接成功、页面自身成功回调、以及本地/测试页面的 GeeTest v4 成功链路。
- 官方 `slide-popup-zh.html` 已出现单轮成功：返回 `pass_token/lot_number/captcha_output/gen_time`。
- 最近一次官方 `slide-popup-zh.html` stress：`3/3`，avg≈16.35s，p95≈21.5s；其中既有 `color_template` 命中，也有 `shadow_dark` 命中。
- 但样本仍小，真实站点不能包装成稳定通杀；下一步还要扩大到 10/20 轮和不同 GeeTest 皮肤。
- 下一步重点是多特征缺口定位、轨迹模型分层、失败后刷新/重试策略，而不是再做 observer。

---

### 17. 网易易盾 / Yidun 滑动拼图

Yidun 现在保留 **jigsaw solver alpha**，不是单纯 observer。当前在网易易盾官方 `trial/jigsaw` 页面可以完成：图片提取、缺口定位、滑块拖动、服务端 check 返回 `validate/token/zoneId`。

关键实现点：

- 在页面最早阶段 hook `window.initNECaptcha`。
- hook 使用 `Proxy` 包装，保留官方 loader 需要的 `.use()` 等静态属性，避免破坏运行链路。
- 记录 `captchaId/mode/captchaType/width`、实例方法、网络 `api/v3/get/check`。
- 抽取：
  - `.yidun_bg-img` 背景图
  - `.yidun_jigsaw` 拼图 front PNG
  - `.yidun_slider` / control / panel 坐标
- OpenCV 定位策略：
  - `shadow_dark`
  - `shadow_dark_blur`
  - `shadow_dark_low_sat`
  - `color_template` fallback
- 处理 Yidun 的关键几何坑：front 图片显示位置通常比 slider left 少半个视觉差值，SDK 会自动加 `(front_width - slider_width) / 2` 补偿。
- 成功时输出：

```json
{
  "validate": "...",
  "token": "...",
  "zoneId": "NANP"
}
```

滑动拼图命令：

```bash
antibot solve yidun \
  --url 'https://dun.163.com/trial/jigsaw' \
  --output-dir /tmp/yidun-run \
  --timeout 90 \
  --slide-attempts 3
```

压测：

```bash
antibot stress yidun \
  --url 'https://dun.163.com/trial/jigsaw' \
  --runs 10 \
  --concurrency 1 \
  --timeout 90 \
  --slide-attempts 3 \
  --output-json /tmp/yidun-stress.json
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_yidun(
        target_url="https://dun.163.com/trial/jigsaw",
        output_dir="/tmp/yidun-run",
    )
    print(ret.ok, ret.ticket, ret.randstr, ret.raw.get("success"))
```

当前定位：

- 已验证官方 `trial/jigsaw` 单次 solve 成功，能拿到 `validate/token/zoneId`。
- 这条线仍是 alpha：复杂业务站点可能叠加设备指纹、IP reputation、业务态绑定；后续重点只放在滑块几何类场景。

---

### 18. 自动分发模式

SDK 可以根据 URL 粗略判断 provider：

- Qoder / Aliyun 相关 URL -> `aliyun`
- AJ-Captcha / Anji / `/captcha/get` 相关 URL -> `ajcaptcha`
- ALTCHA 相关 URL -> `altcha`
- Anubis / `.within.website/x/cmd/anubis` 相关 URL -> `anubis`
- FriendlyCaptcha / `frc-captcha` 相关 URL -> `friendlycaptcha`
- Cap / trycap / cap-widget 相关 URL -> `cap`
- mCaptcha / `/api/v1/pow/config` 相关 URL -> `mcaptcha`
- Wicketkeeper / `/v0/challenge` 相关 URL -> `wicketkeeper`
- P-Captcha / QuadraticResidueProblem 相关 URL -> `pcaptcha`
- Tencent / TCaptcha 相关 URL -> `tencent`
- GeeTest / gcaptcha4 相关 URL -> `geetest`
- Yidun / NetEase Dun / necaptcha / dun.163.com 相关 URL -> `yidun`
- hCaptcha / h-captcha / js.hcaptcha.com 相关 URL -> `hcaptcha`
- reCAPTCHA / g-recaptcha / recaptcha.net 相关 URL -> `recaptcha`
- Turnstile / challenges.cloudflare.com 相关 URL -> `turnstile`
- Cloudflare Managed Challenge / cf-challenge 相关 URL -> `cloudflare/browser`
- 其他 -> 普通浏览器打开

```bash
antibot auto 'https://qoder.com/users/sign-up' \
  --proxy 'host:port:user:pass' \
  --timeout 300
```

---

### 19. 代理格式

支持以下格式：

```text
host:port
host:port:user:pass
http://host:port
http://user:pass@host:port
socks5://host:port
socks5://user:pass@host:port
```

代理会在日志/diagnostics 中自动脱敏：

```text
http://***:***@host:port
```

---

## 安装和初始化

推荐开发态：

```bash
cd antibot-sdk
uv sync
uv run playwright install chromium
uv run --with-editable . antibot install-js-deps
```

如果只是运行 CLI：

```bash
uv run --with-editable . antibot diagnose
```

Node 依赖说明：

- Aliyun provider 使用 `src/antibot_sdk/vendor/aliyun` 下的 Node runner。
- 首次运行前需要：

```bash
uv run --with-editable . antibot install-js-deps
```

---

## Python API

```python
import asyncio
from antibot_sdk import AntibotClient

async def main():
    async with AntibotClient() as client:
        page = await client.open(
            "https://example.com",
            selectors={"heading": "h1"},
        )
        print(page.ok, page.state, page.selectors)

        tencent = await client.solve_tencent(
            profile="cloud_product",
            headless=True,
        )
        print(tencent.ok, tencent.ticket, tencent.randstr)

        turnstile = await client.solve_turnstile(
            target_url="https://target.example/path-with-turnstile",
            output_dir="/tmp/turnstile-run",
        )
        print(turnstile.ok, turnstile.ticket, turnstile.diagnostics.get("sitekey"))

        hcaptcha = await client.solve_hcaptcha(
            target_url="https://target.example/path-with-hcaptcha",
            output_dir="/tmp/hcaptcha-run",
        )
        print(hcaptcha.ok, hcaptcha.ticket, hcaptcha.diagnostics.get("sitekey"))

        recaptcha = await client.solve_recaptcha(
            target_url="https://target.example/path-with-recaptcha",
            output_dir="/tmp/recaptcha-run",
        )
        print(recaptcha.ok, recaptcha.ticket, recaptcha.diagnostics.get("action"))

        anubis = await client.solve_anubis(
            page_url="https://target.example/path-with-anubis",
            submit=True,
            timeout_sec=30,
        )
        print(anubis.ok, anubis.ticket, anubis.verify_code)

        cap = await client.solve_cap(
            api_endpoint="https://target.example/cap/",
            timeout_sec=60,
        )
        print(cap.ok, cap.ticket, cap.verify_code)

        pcaptcha = await client.solve_pcaptcha(
            challenge_url="https://target.example/api/challenge",
            validate_url="https://target.example/api/validate",
            validate=True,
        )
        print(pcaptcha.ok, pcaptcha.ticket, pcaptcha.verify_code)

        yidun = await client.solve_yidun(
            target_url="https://dun.163.com/trial/jigsaw",
            output_dir="/tmp/yidun-run",
        )
        print(yidun.ok, yidun.ticket, yidun.randstr, yidun.raw.get("success"))

        # token 采集后，再做真实提交闭环验证
        from antibot_sdk import SubmitFlow, verify_submit_flow

        verified = await verify_submit_flow(
            SubmitFlow(
                provider="recaptcha",
                url="https://target.example/form",
                token=recaptcha.ticket,
                submit_selector="button[type=submit]",
                success_selector=".login-ok",
                failure_selector=".captcha-error",
                output_dir="/tmp/verify-recaptcha",
            )
        )
        print(verified.ok, verified.state, verified.failure_class, verified.reason)

        aliyun = await client.solve_aliyun(
            target_url="https://qoder.com/users/sign-up",
            site_profile="qoder_signup",
            proxy_server="host:port:user:pass",
            timeout_sec=300,
        )
        print(aliyun.ok, aliyun.verify_code, aliyun.diagnostics)

        # 只做策略判断，不启动浏览器
        from antibot_sdk import aliyun_policy_decision

        decision = aliyun_policy_decision(codes=["F001", "F001"], has_proxy=True)
        print(decision.failure_class, decision.should_retry_session)

asyncio.run(main())
```

---

## CLI 总览

```bash
# 环境诊断
antibot diagnose

# 查看内置 profile
antibot profiles

# 安装 Aliyun Node 依赖
antibot install-js-deps

# Pydoll/CDP 浏览器运行
antibot run https://example.com --selector heading=h1

# 自动分发
antibot auto 'https://qoder.com/users/sign-up' --proxy 'host:port:user:pass'

# Tencent
antibot solve tencent --profile cloud_product --headless
antibot stress tencent --profile cloud_product --runs 10 --concurrency 3

# Turnstile
antibot solve turnstile --url 'https://target.example/path-with-turnstile'
antibot stress turnstile --url 'https://target.example/path-with-turnstile' --runs 10

# hCaptcha
antibot solve hcaptcha --url 'https://target.example/path-with-hcaptcha'
antibot stress hcaptcha --url 'https://target.example/path-with-hcaptcha' --runs 10

# reCAPTCHA
antibot solve recaptcha --url 'https://target.example/path-with-recaptcha'
antibot stress recaptcha --url 'https://target.example/path-with-recaptcha' --runs 10

# AJ-Captcha
antibot solve ajcaptcha --base-url 'http://127.0.0.1:18080'
antibot stress ajcaptcha --base-url 'http://127.0.0.1:18080' --runs 50 --concurrency 5

# ALTCHA
antibot solve altcha --challenge-url 'https://target.example/altcha/challenge'
antibot stress altcha --challenge-url 'https://target.example/altcha/challenge' --runs 50 --concurrency 5

# Anubis
antibot solve anubis --page-url 'https://target.example/path-with-anubis' --submit
antibot solve anubis --challenge 'randomDataHex' --difficulty 4
antibot stress anubis --base-url 'https://target.example' --submit --runs 30 --concurrency 5

# FriendlyCaptcha
antibot solve friendlycaptcha --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' --sitekey 'FCxxxxx'
antibot stress friendlycaptcha --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' --sitekey 'FCxxxxx' --runs 20

# Cap / @cap.js
antibot solve cap --api-endpoint 'https://target.example/cap/'
antibot solve cap --token 'challenge token' --c 50 --s 32 --d 4
antibot stress cap --api-endpoint 'https://target.example/cap/' --runs 50 --concurrency 5

# mCaptcha
antibot solve mcaptcha --base-url 'https://captcha.example' --sitekey 'site-key'
antibot stress mcaptcha --base-url 'https://captcha.example' --sitekey 'site-key' --runs 20

# Wicketkeeper
antibot solve wicketkeeper --base-url 'https://captcha.example'
antibot stress wicketkeeper --base-url 'https://captcha.example' --runs 20

# P-Captcha
antibot solve pcaptcha --challenge-url 'https://target.example/api/challenge'
antibot solve pcaptcha --challenge-url 'https://target.example/api/challenge' --validate-url 'https://target.example/api/validate' --validate
antibot stress pcaptcha --challenge-url 'https://target.example/api/challenge' --validate-url 'https://target.example/api/validate' --validate --runs 20

# Submit verification，证明 token 是否真过页面流程
antibot verify recaptcha --url 'https://target.example/form' --captcha-json /tmp/recaptcha-run/recaptcha_run.json --submit '#submit' --success '.ok' --failure '.captcha-error'
antibot verify hcaptcha --url 'https://target.example/form' --token 'P1_xxx' --submit '#submit' --success '.ok'
antibot verify turnstile --url 'https://target.example/form' --token '0.xxx' --submit '#submit' --expected-url-contains '/dashboard'

# GeeTest
antibot solve geetest --url 'https://target.example/path-with-geetest'
antibot stress geetest --url 'https://target.example/path-with-geetest' --runs 10

# Yidun
antibot solve yidun --url 'https://dun.163.com/trial/jigsaw'
antibot stress yidun --url 'https://dun.163.com/trial/jigsaw' --runs 10 --concurrency 1

# Aliyun
antibot solve aliyun --url 'https://qoder.com/users/sign-up' --site-profile qoder_signup
antibot stress aliyun --url 'https://qoder.com/users/sign-up' --site-profile qoder_signup --runs 10
```

---

## Artifact 输出

Aliyun 每次运行会保留现场文件，便于复盘：

```text
aliyun_captcha_run.json
attempt_N/aliyun_captcha_run.json
aliyun_bg_selected.png
aliyun_puzzle_selected.png
qoder_precaptcha.png
```

Turnstile / hCaptcha / reCAPTCHA / AJ-Captcha / ALTCHA / Anubis / FriendlyCaptcha / Cap / P-Captcha / GeeTest / Yidun 会保留：

```text
turnstile_run.json / hcaptcha_run.json / recaptcha_run.json / geetest_run.json
turnstile_page.png / hcaptcha_page.png / recaptcha_page.png / geetest_page.png
turnstile_page.html / hcaptcha_page.html / recaptcha_page.html / geetest_page.html
ajcaptcha_run.json / ajcaptcha_original.png / ajcaptcha_jigsaw.png
altcha_run.json
anubis_run.json
friendlycaptcha_run.json
cap_run.json
pcaptcha_run.json
geetest_slide_bg_N.png / geetest_slide_slice_N.png
yidun_run.json / yidun_page.png / yidun_page.html
yidun_slide_bg_N.jpg / yidun_slide_front_N.png
```

Submit verification 会保留：

```text
verification_run.json
verification_page.png
verification_page.html
```

Stress 输出 JSON 结构：

```text
summary:
  name
  runs / concurrency
  ok / fail / success_rate
  avg_ms / p50_ms / p95_ms
  attempts.avg / attempts.max / attempts.code_counts
  failure_errors

records:
  每一轮的 compact result、diagnostics、artifacts、errors
```

---

## 项目结构

```text
src/antibot_sdk/
  client.py                 # SDK facade: AntibotClient
  cli.py                    # antibot CLI
  models.py                 # BrowserResult / CaptchaResult
  policy.py                 # Aliyun failure policy / retry decision
  profiles.py               # Aliyun site profile / URL provider detect
  proxy.py                  # 通用代理解析与脱敏
  stress.py                 # 统一压测框架
  verification.py           # token 提交闭环 / success oracle / failure classifier
  providers/
    browser.py              # Pydoll/CDP provider
    cloudflare.py           # Pydoll runner
    tencent.py              # Tencent provider adapter
    aliyun.py               # Aliyun provider adapter
    ajcaptcha.py            # AJ-Captcha blockPuzzle protocol solver
    altcha.py               # ALTCHA PoW protocol solver
    anubis.py               # Anubis SHA-256 PoW protocol solver
    friendlycaptcha.py      # FriendlyCaptcha classic PoW protocol solver
    cap.py                  # Cap/@cap.js SHA-256 PoW protocol solver
    mcaptcha.py             # mCaptcha SHA-256 PoW protocol solver
    wicketkeeper.py         # Wicketkeeper JWT PoW protocol solver
    pcaptcha.py             # P-Captcha quadratic residue protocol solver
    geetest.py              # GeeTest v4 hook + slide solver alpha
    hcaptcha.py             # hCaptcha hook/observer provider
    recaptcha.py            # reCAPTCHA/Enterprise hook/observer provider
    turnstile.py            # Cloudflare Turnstile hook/observer provider
    yidun.py                # 网易易盾 hook + jigsaw solver alpha
  vendor/
    tencent/                # Tencent solver + upstream snapshot
    aliyun/                 # Aliyun Node bridge/runner/site profiles

tests/
  test_profiles.py
  test_proxy.py
  test_stress.py
  test_verification.py
  test_ajcaptcha.py
  test_altcha.py
  test_anubis.py
  test_friendlycaptcha.py
  test_cap.py
  test_pcaptcha.py
  test_yidun_slide.py
```

---

## 当前验证记录

最近一轮关键验证：

```text
pytest: 45 passed
node -c bridge.js/site_profiles.js/runner.js: passed
uv build: success
watchdog smoke: ALIYUN_GOTO_WATCHDOG_MS=1 能写入 watchdog JSON
geetest mock: initGeetest4/onSuccess/getValidate 链路通过
geetest official slide: 单次 solve 成功提取 pass_token/lot_number/captcha_output/gen_time
geetest official slide stress: 最新 3/3，avg≈16.35s，p95≈21.5s，命中过 color_template/shadow_dark 两种定位分支
yidun official jigsaw: 单次 solve 成功提取 validate/token/zoneId；stress 2/2，avg≈30.3s，p95≈34.7s
turnstile mock: render/callback/input token 链路通过
hcaptcha mock: render/callback/input token 链路通过
recaptcha mock: render/enterprise execute/callback/input token 链路通过
verify mock: success oracle 命中时 state=passed/server_verified=true/flow_passed=true
verify mock: invalid-input-response 会归类为 token_rejected
```

腾讯：

```text
stress tencent --runs 10 --concurrency 3: 10/10
stress tencent --proxy ... --runs 4 --concurrency 2: 4/4
```

阿里云 / Qoder：

```text
无代理默认 profile：可恢复 F001/F015/gap not found，成功率可达 5/5，但有长尾。
代理池 3 轮：3/3，平均 attempt 1.33。
代理池快 session 5 轮：5/5，avg≈82643ms，p95≈156790ms，max_attempt=3。
本轮 proxy + watchdog 回归 2 轮：2/2，avg≈43157ms，max_attempt=1。
```

资源清理：

```text
Tencent marker residual: 0
Aliyun temp profile dirs: 0
```

GeeTest：

```text
本地 v4 mock 页面：ok=true，成功提取 lot_number/captcha_output/pass_token/gen_time。
```

Yidun：

```text
官方 trial/jigsaw 页面：ok=true，成功提取 validate/token/zoneId。
官方 trial/jigsaw stress 2 轮：2/2，avg≈30.3s，p95≈34.7s。
关键修复：initNECaptcha hook 改为 Proxy，保留 .use() 静态方法；拖动距离加入 front/slider 视觉偏移补偿。
```

AJ-Captcha：

```text
本地协议 mock：ok=true，成功生成 AES pointJson 与 captchaVerification。
合成干扰图样本：alpha-edge 缺口定位误差 <= 2px。
官方 Go 实现串行压测 20 轮：20/20，avg≈126.8ms，p95≈194ms。
官方 Go 实现并发压测 20 轮/concurrency=4/max-attempts=3：19/20；失败集中在 demo 服务自身共享状态/内存缓存并发抖动。
```

ALTCHA：

```text
本地 challenge server：ok=true，成功输出 base64 payload。
M2M header 解析：WWW-Authenticate -> AltchaChallenge -> Authorization header。
固定 SHA-256 challenge：成功定位 number，并可反解 payload JSON。
```

Anubis：

```text
官方 Go fixture：SHA256("hunter"+"0") = 2652bd...0500e，difficulty=0 命中。
HTML JSONScript 解析：anubis_challenge/anubis_base_prefix 回归通过。
本地 make-challenge + pass-challenge：ok=true，成功返回 auth cookie。
本地 Anubis stress 30 轮/concurrency=5：30/30，avg≈41.3ms，p95≈227ms。
```

FriendlyCaptcha：

```text
friendly-pow 官方 easy fixture：成功命中 nonce bytes 00 00 00 00 9a 00 00 00。
本地 puzzle endpoint：ok=true，成功输出 frc-captcha-solution payload。
诊断字段按官方 DataView 默认 big-endian 生成。
```

Cap / @cap.js：

```text
Cap PRNG/FNV 与 upstream core/src/prng.js 交叉校验。
官方 core generateChallenge/validateChallenge v1：Python solve body 被 validateChallenge 接受。
官方 core format-2 sha256-pow：Python solutions=[{nonce:...}] 被 validateChallenge 接受。
本地 v1 seeded challenge + /redeem：ok=true，成功返回 Cap token。
本地 format-2 sha256-pow + /redeem：ok=true，成功返回 Cap token。
本地 Cap stress 30 轮/concurrency=5：30/30，avg≈54.1ms，p95≈81ms。
unsupported 协议回归：format-2 rsw 明确返回 unsupported_protocols。
```

mCaptcha：

```text
官方 mcaptcha_pow_sha256 0.5.0 fixture：Python nonce/result 与 Rust prove_work(&String, difficulty) 对齐。
本地 mock config + verify + siteverify：ok=true，成功返回 mCaptcha token。
本地 mCaptcha stress 20 轮/concurrency=4：20/20，avg≈29.8ms，p95≈50ms。
```

Wicketkeeper：

```text
upstream client/src/solvers/fast.js + server/handlers.go：确认 SHA256(challenge+nonce) 与 leading-zero nibble 规则。
fixture challenge=hunter,difficulty=4：nonce=73720，response=000021aed34dbacfb31c00533eecdc3099fe858b8377273a12cc9cdfecfaebe4。
本地 mock challenge + siteverify stress 20 轮/concurrency=4：20/20，avg≈23.2ms，p95≈35ms。
```

P-Captcha：

```text
官方 @p-captcha/node generateChallenge + validateAnswer：Python answer 被 validateAnswer 接受。
本地 QuadraticResidueProblem 解析/求模平方根/answer base64 编码回归通过。
本地 P-Captcha challenge + validate stress 20 轮/concurrency=4：20/20，avg≈57.2ms，p95≈84ms。
```

Turnstile：

```text
本地 mock 页面：ok=true，成功提取 callback/input token、sitekey、action。
stress turnstile mock 2 轮：2/2。
```

hCaptcha：

```text
本地 mock 页面：ok=true，成功提取 callback/input token、sitekey、size/theme。
stress hcaptcha mock 2 轮：2/2。
```

reCAPTCHA / Enterprise：

```text
本地 mock 页面：ok=true，成功提取 Enterprise execute token、sitekey、action。
stress recaptcha mock 2 轮：2/2。
```

---

## 已知调优点

- Qoder/Aliyun 的 `F001` 常和出口 IP / session reputation / 当前页面状态有关。
- AJ-Captcha 的主要误差来自白色描边过弱、服务端自定义模板/尺寸、以及干扰图与真实模板相似；优先调 `--min-score`、保存 `ajcaptcha_original.png / ajcaptcha_jigsaw.png` 复盘。
- ALTCHA 是 PoW，不是识图；耗时主要由 `maxnumber`、命中位置和 `workers` 决定。VPS 上默认单 worker，避免把 CPU 打满。
- Anubis 是 SHA-256 前导零 PoW；difficulty 每加 1，平均搜索空间约乘 16。页面解析和提交 cookie 是协议闭环，但高 difficulty 仍会吃 CPU。
- FriendlyCaptcha classic 也是 PoW；耗时主要由 difficulty、solution count、命中位置和 worker 数决定。默认 `10,000,000` 次/段 solution 上限，真实站点不够时调 `--max-attempts-per-solution`。
- Cap PoW 耗时主要由 `c/s/d`、format-2 target 长度、命中位置和 worker 数决定；遇到 `rsw/instrumentation` 时不要硬解，当前版本会按 unsupported 返回。
- mCaptcha PoW 耗时主要由 `difficulty_factor`、nonce 命中位置和 worker 数决定；默认单 worker，压测时先控制并发避免把 VPS CPU 打满。
- Wicketkeeper difficulty 是前导 0 nibble 个数，每 +1 平均搜索空间约乘 16；success JWT 只能由服务端 `/siteverify` 签发。
- P-Captcha 当前不是暴力搜索，而是模平方根；耗时主要由 Woodall prime bit 数和 rounds 决定，`2xs` 约 761 bits，`3xl` 约 22974 bits。
- Yidun 的误差主要来自三类：浅色缺口的 `color_template` / 暗色缺口的 `shadow_*` 分支选择、front 图片相对 slider 的视觉偏移、以及轨迹/IP/设备指纹。
- 代理池能明显降低部分 F001，但仍会出现 `NONE`、`gap not found`、`candidate rejected` 等临时状态。
- 当前最佳基线是：**Qoder + proxy + 快 session 策略**。
- watchdog 阈值可通过环境变量覆盖，例如：

```bash
antibot solve aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --env ALIYUN_PRE_ACTION_WATCHDOG_MS=90000 \
  --env ALIYUN_READ_GAP_WATCHDOG_MS=25000
```

- 如果要继续扩大压测，建议先跑：

```bash
antibot stress aliyun \
  --url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --proxy 'host:port:user:pass' \
  --runs 20 \
  --concurrency 1 \
  --timeout 300
```

---

## 打包

```bash
python -m compileall -q src/antibot_sdk tests
node -c src/antibot_sdk/vendor/aliyun/bridge.js
node -c src/antibot_sdk/vendor/aliyun/src/site_profiles.js
node -c src/antibot_sdk/vendor/aliyun/src/runner.js
uv run --with-editable . --with pytest pytest -q
uv build
```

生成：

```text
dist/antibot_sdk-0.1.0-py3-none-any.whl
dist/antibot_sdk-0.1.0.tar.gz
```

`dist/` 默认不提交到仓库。
