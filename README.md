# antibot-sdk

`antibot-sdk` 是一个把 **浏览器自动化 / Cloudflare/Turnstile 流程 / hCaptcha / 腾讯滑块验证码 / 阿里云滑块验证码 / GeeTest v4** 收敛到一起的 Python SDK + CLI 工具集。

这个项目不是 Codex skill，而是独立 SDK，目标是把三个已有方向统一成一个可复用、可压测、可继续扩展的工程：

- Pydoll / CDP 浏览器运行器：页面打开、指纹补丁、Cloudflare/Turnstile/Managed Challenge 相关流程观察与自动化。
- Turnstile：新增浏览器 hook/observer provider，采集 `turnstile.render()` 配置、callback token、`cf-turnstile-response`、widget DOM 和网络现场。
- hCaptcha：新增浏览器 hook/observer provider，采集 `hcaptcha.render()`、callback token、`h-captcha-response/g-recaptcha-response`、Enterprise `rqdata`、widget DOM 和网络现场。
- reCAPTCHA / reCAPTCHA Enterprise：新增浏览器 hook/observer provider，采集 `grecaptcha.render()`、`grecaptcha.enterprise.execute()`、action、callback/execute token、`g-recaptcha-response` 和网络现场。
- Tencent Captcha：封装腾讯滑块的页面触发、浏览器池、缺口识别、轨迹拖拽、ticket/randstr 输出。
- Aliyun Captcha：封装阿里云滑块的 Node/Puppeteer runner、站点 profile、attempt/session retry、错误归一、artifact 保留。
- GeeTest v4：新增浏览器 hook/observer provider，采集 `initGeetest4` 配置、实例方法、运行事件、`getValidate()` 成功载荷和网络现场。
- Policy Engine：把 `F001/F015/NONE/gap/candidate/watchdog timeout` 等失败归类，决定是否换 session，并输出下一步调参建议。
- Stress Harness：统一压测入口，输出 summary、records、attempt code 分布、失败现场。

---

## 现在这个 SDK 可以干什么

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
- 遇到真实图片/多轮 challenge 时，当前版本会先保留完整现场；下一步再接图片识别、任务分类和 Enterprise 风控策略。

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
- 遇到 v2 图片/checkbox 交互挑战时，当前版本先保留完整现场；下一步再接图片识别、anchor/reload 流分析和 Enterprise assessment 结果归一。

---

### 5. 腾讯滑块验证码

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

### 6. 阿里云滑块验证码

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

### 7. GeeTest v4 / 极验

第一版 GeeTest provider 先做 **可探测、可触发、可采集、可压测**，为后续轨迹/图像/行为模型接入打底。

能力：

- 在页面最早阶段 hook `window.initGeetest4`。
- 记录 GeeTest v4 config，例如 `captchaId/captcha_id`、`product`。
- wrap CAPTCHA 实例的 `appendTo / bindForm / showCaptcha / verify / onReady / onSuccess / getValidate` 等方法。
- 自动尝试调用 `showCaptcha()`，并点击页面中的 GeeTest 相关元素。
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
  --output-dir /tmp/geetest-run
```

指定触发按钮：

```bash
antibot solve geetest \
  --url 'https://target.example/path-with-geetest' \
  --trigger '.login-submit' \
  --trigger '.geetest_btn'
```

压测：

```bash
antibot stress geetest \
  --url 'https://target.example/path-with-geetest' \
  --runs 10 \
  --concurrency 2 \
  --timeout 90 \
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
- 如果遇到真实图片/滑块挑战，当前版本会先完整保留现场；下一步再接入识别、轨迹和按站点 profile 的行为策略。

---

### 8. 自动分发模式

SDK 可以根据 URL 粗略判断 provider：

- Qoder / Aliyun 相关 URL -> `aliyun`
- Tencent / TCaptcha 相关 URL -> `tencent`
- GeeTest / gcaptcha4 相关 URL -> `geetest`
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

### 9. 代理格式

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

# GeeTest
antibot solve geetest --url 'https://target.example/path-with-geetest'
antibot stress geetest --url 'https://target.example/path-with-geetest' --runs 10

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

Turnstile / hCaptcha / reCAPTCHA / GeeTest 会保留：

```text
turnstile_run.json / hcaptcha_run.json / recaptcha_run.json / geetest_run.json
turnstile_page.png / hcaptcha_page.png / recaptcha_page.png / geetest_page.png
turnstile_page.html / hcaptcha_page.html / recaptcha_page.html / geetest_page.html
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
  providers/
    browser.py              # Pydoll/CDP provider
    cloudflare.py           # Pydoll runner
    tencent.py              # Tencent provider adapter
    aliyun.py               # Aliyun provider adapter
    geetest.py              # GeeTest v4 hook/observer provider
    hcaptcha.py             # hCaptcha hook/observer provider
    recaptcha.py            # reCAPTCHA/Enterprise hook/observer provider
    turnstile.py            # Cloudflare Turnstile hook/observer provider
  vendor/
    tencent/                # Tencent solver + upstream snapshot
    aliyun/                 # Aliyun Node bridge/runner/site profiles

tests/
  test_profiles.py
  test_proxy.py
  test_stress.py
```

---

## 当前验证记录

最近一轮关键验证：

```text
pytest: 12 passed
node -c bridge.js/site_profiles.js/runner.js: passed
uv build: success
watchdog smoke: ALIYUN_GOTO_WATCHDOG_MS=1 能写入 watchdog JSON
geetest mock: initGeetest4/onSuccess/getValidate 链路通过
turnstile mock: render/callback/input token 链路通过
hcaptcha mock: render/callback/input token 链路通过
recaptcha mock: render/enterprise execute/callback/input token 链路通过
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
