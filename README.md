# antibot-sdk

一个面向“过人机验证”的精简 SDK。当前只保留三条可维护链路：

- **Cloudflare 浏览器人机验证流**：Pydoll/CDP 启动 Chrome，补 UA/CH/基础指纹，等待 Managed Challenge / Turnstile 页面状态稳定，输出 `BrowserResult` 与截图/HTML 等证据。
- **阿里云 Captcha V3 滑块**：Node/Puppeteer runner、DOM hook、缺口定位、轨迹提交、失败策略。
- **腾讯 Captcha 滑块**：Playwright runtime、缺口识别、轨迹生成、verify 响应捕获、浏览器池压测。

之前堆进去的 PoW、WAF、VM、旧 demo/provider 仍然保持删除；这次只把 Cloudflare 这种“人机验证浏览器流”加回，不恢复半成品。

## 安装

```bash
uv sync
uv run playwright install chromium
uv run antibot install-js-deps   # 安装阿里云 Node runner 依赖
```

## CLI

### 查看能力

```bash
uv run antibot capabilities
uv run antibot profiles
uv run antibot diagnose
```

### Cloudflare / 浏览器人机验证流

```bash
uv run antibot run 'https://example.com' \
  --mode auto \
  --headless auto \
  --max-wait 90 \
  --screenshot /tmp/cf.png \
  --raw
```

等价入口：

```bash
uv run antibot solve cloudflare \
  --target-url 'https://example.com' \
  --mode managed \
  --headless false \
  --max-wait 120 \
  --raw
```

常用参数：

- `--mode auto|turnstile|managed|scrape`
- `--headless auto|true|false`
- `--browser-binary /path/to/chrome`
- `--proxy host:port:user:pass` 或标准代理 URL
- `--profile-dir` 复用浏览器 profile
- `--selector key=css` 抽取页面字段
- `--click css` 页面稳定后点击
- `--screenshot` / `--html-output` / `--output-json` 保存证据

注意：Cloudflare 这里是浏览器流，不是纯协议 token solver；真实通过率仍取决于浏览器、出口 IP、UA/CH、TLS/HTTP2 指纹和目标站策略。

### 腾讯滑块

```bash
uv run antibot solve tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --profile cloud_product \
  --headless true \
  --timeout 120 \
  --raw
```

常用参数：

- `--profile cloud_product|matrix_ai_detect|generic`
- `--appid` 显式指定业务 appid
- `--proxy host:port:user:pass` 或标准代理 URL
- `--pool-size` / `--browser-max-uses` 用于服务化或压测

### 阿里云滑块

```bash
uv run antibot solve aliyun \
  --target-url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --headless auto \
  --timeout 180 \
  --raw
```

常用参数：

- `--site-profile auto|qoder_signup`
- `--chrome-path` 指定本机 Chrome/Chromium
- `--selector key=value` 覆盖页面选择器
- `--profile-json '{...}'` 传入轨迹参数
- `--env KEY=VALUE` 传给 Node runner
- `--max-attempts` / `--session-retries` 控制重试

### 自动路由

```bash
uv run antibot auto 'https://cloud.tencent.com/product/captcha' --raw
uv run antibot auto 'https://qoder.com/users/sign-up' --raw
uv run antibot auto 'https://example.cloudflare-protected.site' --provider cloudflare --raw
```

自动路由现在支持：`cloudflare`、`aliyun`、`tencent`。

### 压测

```bash
uv run antibot stress tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --runs 5 \
  --concurrency 1 \
  --timeout 120

uv run antibot stress aliyun \
  --target-url 'https://qoder.com/users/sign-up' \
  --runs 3 \
  --concurrency 1 \
  --timeout 180
```

VPS 上建议先 `concurrency=1`，不要盲目多开浏览器。

## SDK 用法

### Cloudflare 浏览器流

```python
import asyncio
from antibot_sdk import AntibotClient

async def main():
    async with AntibotClient() as client:
        ret = await client.solve_cloudflare(
            target_url="https://example.com",
            mode="auto",
            headless="auto",
            max_wait=90,
            screenshot="/tmp/cf.png",
        )
        print(ret.ok, ret.state, ret.final_url)

asyncio.run(main())
```

### 腾讯滑块

```python
import asyncio
from antibot_sdk import AntibotClient

async def main():
    async with AntibotClient() as client:
        ret = await client.solve_tencent(
            target_url="https://cloud.tencent.com/product/captcha",
            profile="cloud_product",
            headless=True,
            timeout_sec=120,
        )
        print(ret.ok, ret.ticket, ret.randstr)

asyncio.run(main())
```

### 阿里云滑块

```python
import asyncio
from antibot_sdk import AntibotClient

async def main():
    async with AntibotClient() as client:
        ret = await client.solve_aliyun(
            target_url="https://qoder.com/users/sign-up",
            site_profile="qoder_signup",
            timeout_sec=180,
        )
        print(ret.ok, ret.verify_code, ret.artifacts)

asyncio.run(main())
```

## 仓库边界

当前主能力只有：

1. Cloudflare/Pydoll 浏览器人机验证流；
2. 腾讯滑块；
3. 阿里云滑块。

后续要扩展新的验证码，必须先满足：

1. 有真实网站线上证据；
2. 有可复现领取/提交链路；
3. 有本地测试或 mock 闭环；
4. 不把半成品塞进 SDK 主能力表。
