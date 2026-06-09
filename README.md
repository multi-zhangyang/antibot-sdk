# antibot-sdk

人机验证 SDK，提供 Cloudflare 浏览器验证流、腾讯滑块、阿里云滑块、GeeTest v4 的 Python API 与 CLI。

## 功能

| Provider | 类型 | SDK | CLI |
| --- | --- | --- | --- |
| Cloudflare | 浏览器验证流 | `solve_cloudflare()` / `open()` | `antibot run` / `antibot solve cloudflare` |
| Tencent Captcha | 滑块验证码 | `solve_tencent()` | `antibot solve tencent` |
| Aliyun Captcha V3 | 滑块验证码 | `solve_aliyun()` | `antibot solve aliyun` |
| GeeTest v4 | 人机验证 | `solve_geetest()` | `antibot solve geetest` |

## 安装

```bash
uv sync
uv run playwright install chromium
uv run antibot install-js-deps
```

## CLI

### Cloudflare

```bash
uv run antibot run 'https://example.com' \
  --mode auto \
  --headless auto \
  --max-wait 90 \
  --screenshot /tmp/cf.png \
  --raw
```

```bash
uv run antibot solve cloudflare \
  --target-url 'https://example.com' \
  --mode managed \
  --headless false \
  --max-wait 120 \
  --raw
```

### Tencent Captcha

```bash
uv run antibot solve tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --profile cloud_product \
  --headless true \
  --timeout 120 \
  --raw
```

### Aliyun Captcha V3

```bash
uv run antibot solve aliyun \
  --target-url 'https://qoder.com/users/sign-up' \
  --site-profile qoder_signup \
  --headless auto \
  --timeout 180 \
  --raw
```

### GeeTest v4

```bash
uv run antibot solve geetest \
  --target-url 'https://www.geetest.com/en/adaptive-captcha-demo' \
  --headless true \
  --timeout 60 \
  --raw
```

```bash
uv run antibot solve geetest \
  --target-url 'https://gt4.geetest.com/demov4/slide-popup-zh.html' \
  --click-selector '#btn' \
  --timeout 75 \
  --raw
```

### 自动路由

```bash
uv run antibot auto 'https://cloud.tencent.com/product/captcha' --raw
uv run antibot auto 'https://qoder.com/users/sign-up' --raw
uv run antibot auto 'https://www.geetest.com/en/adaptive-captcha-demo' --raw
uv run antibot auto 'https://example.com' --provider cloudflare --raw
```

### 压测

```bash
uv run antibot stress tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --runs 5 \
  --concurrency 1 \
  --timeout 120
```

```bash
uv run antibot stress aliyun \
  --target-url 'https://qoder.com/users/sign-up' \
  --runs 3 \
  --concurrency 1 \
  --timeout 180
```

### 信息

```bash
uv run antibot capabilities
uv run antibot profiles
uv run antibot diagnose
```

## Python API

### Cloudflare

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

### Tencent Captcha

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

### Aliyun Captcha V3

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

### GeeTest v4

```python
import asyncio
from antibot_sdk import AntibotClient

async def main():
    async with AntibotClient() as client:
        ret = await client.solve_geetest(
            target_url="https://www.geetest.com/en/adaptive-captcha-demo",
            headless=True,
            timeout_sec=60,
        )
        print(ret.ok, ret.ticket, ret.verify_code)

asyncio.run(main())
```
