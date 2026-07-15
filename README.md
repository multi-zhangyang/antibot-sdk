# antibot-sdk

人机验证 SDK，提供 Cloudflare 浏览器验证流、腾讯滑块、阿里云滑块、GeeTest v4 的 Python API 与 CLI。

## 功能

| Provider | 能力 | SDK | CLI |
| --- | --- | --- | --- |
| Cloudflare | 浏览器验证流 | `solve_cloudflare()` / `open()` | `antibot run` / `antibot solve cloudflare` |
| Tencent Captcha | 滑块验证码 | `solve_tencent()` | `antibot solve tencent` |
| Aliyun Captcha V3 | 滑块验证码 | `solve_aliyun()` | `antibot solve aliyun` |
| GeeTest v4 | `ai` / `slide` / `winlinze` / `match` | `solve_geetest()` | `antibot solve geetest` |

## 安装

```bash
uv sync
uv run playwright install chromium
uv run antibot install-js-deps
```

> `install-js-deps` 不仅给阿里云 Node runner 装依赖，也会装 `proxy-chain`。  
> Cloudflare/Pydoll 在 VPS 上使用**带账号密码的代理**时依赖它做本地匿名桥接（Chrome 的 `--proxy-server` 不能直接带 user:pass）。

## VPS / 无桌面环境

本仓库面向 headless 服务器做了适配：

| 场景 | 行为 |
| --- | --- |
| 无 `DISPLAY` + `headless=auto/managed` | 自动走 headless，避免 Chrome 直接起不来 |
| 无 `DISPLAY` + `headless=false` | 强制降级 headless，并写诊断日志 |
| 需要真 headed | 用 `xvfb-run -a uv run antibot ... --headless false` |
| 代理 `http://user:pass@host:port` | Playwright 路径原生支持；Cloudflare 路径自动 bridge 到 `127.0.0.1` |
| 代理 `socks5://user:pass@host:port` | 同上（Tencent/GeeTest 走 Playwright；Cloudflare 走 bridge） |
| 环境变量代理 | 设 `ANTIBOT_USE_ENV_PROXY=1` 后读取 `ANTIBOT_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` |

诊断：

```bash
uv run antibot diagnose
```

关注字段：`display`、`proxy_chain_installed`、`vps_ready`、`env_proxy`。

带鉴权代理的 Cloudflare 示例：

```bash
uv run antibot solve cloudflare \
  --target-url 'https://example.com' \
  --mode scrape \
  --headless true \
  --proxy 'http://user:pass@host:8080' \
  --raw
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

公开可用目标（实测）：

| Profile | URL | AppId | 说明 |
| --- | --- | --- | --- |
| `cloud_product` | `https://cloud.tencent.com/product/captcha` | `199999861` | 官方产品页滑动拼图 demo，按钮 `#captcha_click` |
| `cloud_product_text` | 同上 | `199999888` | 官方文字点选 demo（已支持，OCR 依次点击 + 确定） |
| `local_harness` | 本地 `examples/tencent/local_harness.html` | `199999861` | 稳定压测用，不依赖营销页 CTA |
| `matrix_ai_detect` | `https://matrix.tencent.com/ai-detect/ai_gen_txt` | `2089775896` | 朱雀 AI 检测，多为无感/direct-pass |

> 说明：`007.qq.com`、heroku 旧 demo 等大多已 404/502。社区文章里的 appid 多数无法公开复用。  
> 官方产品页公开 appid 来自其 `captcha.js`：`199999861/726/888/399`。

```bash
# 官方产品页滑动 demo
uv run antibot solve tencent \
  --target-url 'https://cloud.tencent.com/product/captcha' \
  --profile cloud_product \
  --appid 199999861 \
  --headless true \
  --timeout 120 \
  --raw
```

```bash
# 本地 harness（推荐压测；先起静态服务）
python3 -m http.server 8765 --directory examples/tencent
uv run antibot solve tencent \
  --target-url 'http://127.0.0.1:8765/local_harness.html' \
  --profile local_harness \
  --appid 199999861 \
  --headless true \
  --timeout 90 \
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
  --variant ai \
  --headless true \
  --timeout 60 \
  --raw
```

```bash
uv run antibot solve geetest \
  --target-url 'https://gt4.geetest.com/demov4/slide-popup-zh.html' \
  --click-selector '#btn' \
  --variant slide \
  --timeout 75 \
  --raw
```

```bash
uv run antibot solve geetest \
  --target-url 'https://www.geetest.com/en/adaptive-captcha-demo' \
  --variant winlinze \
  --headless true \
  --timeout 90 \
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

### 自动路由

```bash
uv run antibot auto 'https://cloud.tencent.com/product/captcha' --raw
uv run antibot auto 'https://qoder.com/users/sign-up' --raw
uv run antibot auto 'https://www.geetest.com/en/adaptive-captcha-demo' --provider geetest --variant winlinze --raw
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
            variant="match",
            headless=True,
            timeout_sec=90,
        )
        print(ret.ok, ret.ticket, ret.randstr, ret.diagnostics)

asyncio.run(main())
```
