# antibot-sdk

一个精简版滑块验证码 SDK。当前只保留两条真正有用、可继续维护的链路：

- **阿里云 Captcha V3 滑块**：Node/Puppeteer runner、DOM hook、缺口定位、轨迹提交、失败策略。
- **腾讯 Captcha 滑块**：Playwright runtime、缺口识别、轨迹生成、verify 响应捕获、浏览器池压测。

之前堆进去的 PoW、WAF、VM、token widget、旧 demo/provider 已从仓库移除，避免“看着多、实际没用”的噪音。

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
```

自动路由只识别 `aliyun` 和 `tencent`，其他目标会明确返回 unsupported。

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

当前版本不再声称支持非滑块方向。没有稳定线上验证的内容已经删掉。

后续要扩展时，必须先满足：

1. 有真实网站线上证据；
2. 有可复现领取/提交链路；
3. 有本地测试或 mock 闭环；
4. 不把半成品塞进 SDK 主能力表。
