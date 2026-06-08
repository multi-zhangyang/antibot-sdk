# antibot-sdk

`antibot-sdk` 是一个把 **浏览器自动化 / Cloudflare 流程 / 腾讯滑块验证码 / 阿里云滑块验证码** 收敛到一起的 Python SDK + CLI 工具集。

这个项目不是 Codex skill，而是独立 SDK，目标是把三个已有方向统一成一个可复用、可压测、可继续扩展的工程：

- Pydoll / CDP 浏览器运行器：页面打开、指纹补丁、Cloudflare/Turnstile/Managed Challenge 相关流程观察与自动化。
- Tencent Captcha：封装腾讯滑块的页面触发、浏览器池、缺口识别、轨迹拖拽、ticket/randstr 输出。
- Aliyun Captcha：封装阿里云滑块的 Node/Puppeteer runner、站点 profile、attempt/session retry、错误归一、artifact 保留。
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

### 2. 腾讯滑块验证码

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

### 3. 阿里云滑块验证码

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

### 4. 自动分发模式

SDK 可以根据 URL 粗略判断 provider：

- Qoder / Aliyun 相关 URL -> `aliyun`
- Tencent / TCaptcha 相关 URL -> `tencent`
- Cloudflare / Turnstile 相关 URL -> `cloudflare/browser`
- 其他 -> 普通浏览器打开

```bash
antibot auto 'https://qoder.com/users/sign-up' \
  --proxy 'host:port:user:pass' \
  --timeout 300
```

---

### 5. 代理格式

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
pytest: 8 passed
node -c bridge.js/site_profiles.js/runner.js: passed
uv build: success
watchdog smoke: ALIYUN_GOTO_WATCHDOG_MS=1 能写入 watchdog JSON
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
