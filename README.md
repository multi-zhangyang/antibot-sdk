# antibot-sdk

`antibot-sdk` 是一个把 **浏览器自动化 / Cloudflare/Turnstile 流程 / hCaptcha / 腾讯滑块验证码 / 阿里云滑块验证码 / AJ-Captcha 协议滑块 / ALTCHA PoW / Anubis PoW / Auro AES-GCM 行为 PoW / FriendlyCaptcha PoW / FCaptcha signals-bound PoW / TrustCaptcha fingerprint 多任务 PoW / @strav/captcha stateless HMAC PoW / PrivateCaptcha Compute PoW / Portcullis Argon2 PoW / Cap PoW / crypto-puzzle RSW Time-lock / Captxa JA4-bound PoW / Swetrix CAPTCHA PoW / Crovly fingerprint 行为 PoW / chpio pow-captcha Target PoW / Impost Argon2id PoW / Kerberus u128-score PoW / PaulDotSH bcrypt PoW / guns.lol seal PoW/BLAKE3 / HashGuard JWT PoW / mCaptcha PoW / Wicketkeeper JWT PoW / yourcaptcha 行为 PoW / silent-challenge 被动 PoW / P-Captcha 二次剩余 PoW / pow_captcha Buffer PoW / PoW Bot Deterrent scrypt PoW / POWChallenge Argon2id Memory PoW / pow-reaction JWT 多轮 PoW / Prosopo Procaptcha PoW / Tollbooth SHA256-Balloon/Navigator Attestation / GeeTest v4 / 网易易盾滑动拼图** 收敛到一起的 Python SDK + CLI 工具集。

这个项目不是 Codex skill，而是独立 SDK，目标是把三个已有方向统一成一个可复用、可压测、可继续扩展的工程：

- Pydoll / CDP 浏览器运行器：页面打开、指纹补丁、Cloudflare/Turnstile/Managed Challenge 相关流程观察与自动化。
- Turnstile：新增浏览器 hook/observer provider，采集 `turnstile.render()` 配置、callback token、`cf-turnstile-response`、widget DOM 和网络现场。
- hCaptcha：新增浏览器 hook/observer provider，采集 `hcaptcha.render()`、callback token、`h-captcha-response/g-recaptcha-response`、Enterprise `rqdata`、widget DOM 和网络现场。
- reCAPTCHA / reCAPTCHA Enterprise：新增浏览器 hook/observer provider，采集 `grecaptcha.render()`、`grecaptcha.enterprise.execute()`、action、callback/execute token、`g-recaptcha-response` 和网络现场。
- Submit Verification：把 `token_collected / server_verified / flow_passed` 拆开，用真实页面提交和 success/failure oracle 验证“token 采集 ≠ 真过验证”。
- Tencent Captcha：封装腾讯滑块的页面触发、浏览器池、缺口识别、轨迹拖拽、ticket/randstr 输出。
- Aliyun Captcha：封装阿里云滑块的 Node/Puppeteer runner、站点 profile、attempt/session retry、错误归一、artifact 保留。
- AJ-Captcha / Anji：新增纯 HTTP 协议 solver，走 `/captcha/get` 图像缺口定位、AES `pointJson`、`/captcha/check`，输出二次校验用的 `captchaVerification`，不启动浏览器。
- ALTCHA：升级 v1/v2 PoW 协议 solver，v1 反查 `hash(salt+number)`，v2 复现 `PBKDF2/SHA-* / SCRYPT / ARGON2ID` KDF challenge、HMAC 签名与 verify-compatible fast path，输出表单 base64 payload 或 M2M Authorization header，不启动浏览器。
- Anubis：新增 `fast/slow` PoW 协议 solver，解析 challenge 页面或 make-challenge JSON，计算 `SHA256(randomData+nonce)` 前导零，可生成 `pass-challenge` 参数或直接换取 auth cookie，不启动浏览器。
- Auro.Network：新增 AES-GCM 行为数据 + PoW 协议 solver，获取 `/enckey`，生成鼠标 telemetry 并 AES-GCM 加密，提交 `/api/pow/setup` 后搜索 `SHA256(prefix+nonce)`，可 `/api/pow/validate`，不启动浏览器。
- FriendlyCaptcha：新增 classic `friendly-pow` 协议 solver，获取 puzzle 后本地计算 blake2b nonce，输出 `frc-captcha-solution` payload，不启动浏览器。
- FCaptcha：新增 behavior/environment signals + `signalsHash` 绑定 SHA-256 PoW 协议 solver，补齐 `meta.challengeNonce`、canonical `signalsJson` 和最小提交耗时，可提交 `/api/verify` 换 token，不启动浏览器。
- TrustCaptcha：新增 v3 fingerprint/integrity + 多任务 PoW 协议 solver，合成 `browserInformation/fingerprints/integrityHash`，复现 worker 的 `SHA256(input||"tcn"+counter)`，提交 `/v2/verifications/{id}/challenges` 换 `tc-verification-token`，不启动浏览器。
- @strav/captcha：新增 stateless HMAC token + hashcash PoW 协议 solver，解析公开 token payload 的 `salt/difficulty/jti`，复现 `SHA256(salt+":"+nonce)` 前导 bit 搜索，输出 middleware 可验的 `_captcha/_captcha_answer` 字段，不启动浏览器。
- PrivateCaptcha：新增 compute puzzle 协议 solver，解析 `puzzle.signature`，复现 blake2b-256 threshold 多解 PoW 与 solutions metadata，输出 `private-captcha-solution` payload，不启动浏览器。
- Portcullis：新增 Argon2id + SHA-256 双阶段 PoW 协议 solver，解析 signed challenge，计算内存硬化 base hash 后搜索 nonce，可提交 `/api/v1/verify` 换 `captcha_token`，不启动浏览器。
- Cap / @cap.js：升级 SHA-256 PoW + RSW time-lock 协议 solver，支持 v1 seeded challenge、format-2 `sha256-pow` 和 `rsw`，可输出 `/redeem` body 或直接换取 Cap token，不启动浏览器。
- crypto-puzzle：新增 RSW time-lock puzzle solver，解析 archive，顺序 repeated-squaring 恢复 AES-GCM/PBKDF2 secret，解出 message/token，可提交 verify，不启动浏览器。
- Captxa：新增 simple mode browser metrics + JA4-bound opaque token + SHA-256 PoW 协议 solver，补低风险环境字段，复现 `SHA256(pow32||nonce_le64)` leading-zero，可提交 `/solve/simp` 换 `X-Captcha-Token`，不启动浏览器。
- Swetrix CAPTCHA：新增 privacy CAPTCHA 协议 solver，解析 `/generate` 的 `challenge+difficulty`，复现 `SHA256(challenge+":"+nonce)` 前导十六进制零 PoW，可提交 `/verify` 换 token，并可选 `/validate` 服务端校验，不启动浏览器。
- Crovly：新增 fingerprintHash + environment + behavior 绑定的 PoW 协议 solver，复现 widget 的 `SHA256(nonce+counter)` 前导 bit 搜索，按 `X-Site-Key` 提交 `/verify` 换 token，不启动浏览器。
- chpio/pow-captcha：新增 signed multi-challenge target-match PoW solver，复现 `signedData` 的 UTF-16LE SHA-256 签名与 `SHA256(solution_le||nonce)` target bit 匹配，可提交 redeem，不启动浏览器。
- Impost：新增 Zig/WASM Argon2id PoW solver，复现 `t=3,m=8192KiB,p=1` 的内存硬化 hash，支持 `leading_zeroes` 与 `target_number` 两种策略，输出 `{challenge, nonce}`，不启动浏览器。
- Kerberus：新增多盐 u128-score PoW solver，预计算 `SHA256(salt+serializedInput)`，搜索 `SHA256(prefixHash||nonce_dec)` 前 16 字节评分超过阈值，输出 `Solution{id, nonces}`，不启动浏览器。
- PaulDotSH/pow-captcha：新增 bcrypt exact/prefix PoW solver，复现 `bcrypt::verify` 与 `bcrypt::hash_with_salt(salt[0:16])` 两条链路，输出 `CaptchaServerInfo` 风格 JSON，不启动浏览器。
- guns.lol：新增 `_gs_sets` seal PoW solver，解析 `_2xa` 空位模板，枚举十六进制 seal 使 `SHA256(seal+_n+_org_ts)=o09`，再生成 BLAKE3 `_oo` 提交标签，不启动浏览器。
- HashGuard：新增 target-threshold PoW + JWT proof token 协议 solver，复现 `SHA256(challengeId:seed:nonce) <= target`，提交 `/pow/verifications` 换 proofToken，并可选 `/pow/assertions/introspect`，不启动浏览器。
- mCaptcha：新增 SHA-256 PoW 协议 solver，复现 Rust/JS 的 `bincode(String)+u128 score` 规则，获取 `/api/v1/pow/config` 后本地找 nonce，可提交 `/api/v1/pow/verify` 换 token，不启动浏览器。
- Wicketkeeper：新增 EdDSA-JWT PoW 协议 solver，获取 `/v0/challenge` 后计算 `SHA256(challenge+nonce)` 前导零，可提交 `/v0/siteverify` 换 success JWT，不启动浏览器。
- yourcaptcha：新增行为 signals + HMAC challenge + SHA-256 exact PoW 协议 solver，合成低风险 telemetry 获取低 `maxnumber`，搜索 `SHA256(salt+number)`，可提交 verify，不启动浏览器。
- silent-challenge：新增 motion/navigator attestation + SHA-256 balloon memory-hard PoW 协议 solver，合成高分行为/环境 payload，搜索 balloon nonce，可提交 `/challenge/:id/verify`，不启动浏览器。
- P-Captcha：新增 QuadraticResidueProblem 协议 solver，解析 Woodall prime challenge，用模平方根直接求 answer，可提交 `{id, answer}`，不启动浏览器。
- pow_captcha：新增二进制 buffer reconstruction PoW solver，解析 serialized quiz、按 uncertainty ranges 做 mixed-radix 搜索，输出命中 SHA-256 的 answer，不启动浏览器。
- PoW Bot Deterrent：新增 scrypt-WASM PoW 协议 solver，解析 base64 JSON challenge，复现 `scrypt(nonce_bytes, preimage_bytes, N/r/p/klen)` 与尾部阈值比较，可提交 `/Verify`，不启动浏览器。
- POWChallenge / powchallenge-server：新增 Argon2id memory-hard PoW 协议 solver，解析 `GET /challenge` 的 `req_id/challenge/difficulty`，复现 `t=1,m=19456KiB,p=1` 前导零 bit 校验，可提交 `/verify`，不启动浏览器。
- pow-reaction：新增 JWT 签名多轮 PoW 协议 solver，解析 HS256 challenge、clientId/context 绑定和 rounds，复现 `SHA256(round+"."+nonce)` 前导零 bit，可提交 reactions endpoint，不启动浏览器。
- Prosopo Procaptcha PoW：新增纯协议 PoW solver，复现 `@prosopo/util` 的 `SHA256(nonce+challenge)` 前导十六进制零搜索，可构造 signed timestamp submit body 并提交 provider endpoint，不启动浏览器。
- Tollbooth / libcaptcha：新增 SHA-256 与 SHA256-Balloon memory-hard PoW solver，同时支持 navigator-attestation 的 HTTP poll 稀疏 signals token flow，输出 verify form / clearance token，不启动浏览器。
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
| Auro.Network | 协议 solver | `encrypted_behavior_pow` | alpha | validate body / Auro token |
| FriendlyCaptcha | 协议 solver | `proof_of_work` | alpha | `frc-captcha-solution` payload |
| FCaptcha | 协议 solver | `signals_bound_pow` | alpha | verify body / FCaptcha token |
| PrivateCaptcha | 协议 solver | `compute_pow` | alpha | `private-captcha-solution` payload |
| Portcullis | 协议 solver | `argon2_pow` | alpha | verify body / `captcha_token` |
| Cap / @cap.js | 协议 solver | `proof_of_work` | alpha | `/redeem` body / Cap token |
| crypto-puzzle | 协议 solver | `rsw_time_lock_puzzle` | alpha | decrypted message/token |
| Captxa | 协议 solver | `ja4_bound_pow` | alpha | solve body / `X-Captcha-Token` |
| Swetrix CAPTCHA | 协议 solver | `swetrix_pow` | alpha | verify body / Swetrix token |
| Crovly | 协议 solver | `fingerprint_behavior_pow` | alpha | verify body / Crovly token |
| chpio/pow-captcha | 协议 solver | `target_match_pow` | alpha | challenge solution body / redeemed token |
| Impost | 协议 solver | `argon2id_pow` | alpha | `{challenge, nonce}` / validated message |
| Kerberus | 协议 solver | `u128_score_pow` | alpha | `Solution{id, nonces}` / validated token |
| PaulDotSH/pow-captcha | 协议 solver | `bcrypt_pow` | alpha | `CaptchaServerInfo` JSON / validated token |
| guns.lol | 协议 solver | `seal_pow_blake3` | alpha | `{seal, _oo}` / validated token |
| HashGuard | 协议 solver | `jwt_proof_pow` | alpha | proofToken JWT / introspection result |
| TrustCaptcha | 协议 solver | `fingerprint_multi_pow` | alpha | `tc-verification-token` / submit body |
| @strav/captcha | 协议 solver | `stateless_hmac_pow` | alpha | `_captcha/_captcha_answer` submit body |
| mCaptcha | 协议 solver | `proof_of_work` | alpha | verify body / mCaptcha token |
| Wicketkeeper | 协议 solver | `proof_of_work` | alpha | hidden-input solution / success JWT |
| yourcaptcha | 协议 solver | `behavior_pow` | alpha | captcha payload / verified result |
| silent-challenge | 协议 solver | `passive_pow` | alpha | challenge verify body / signed token |
| P-Captcha | 协议 solver | `quadratic_residue_pow` | alpha | `answer` / `{id, answer}` |
| pow_captcha | 协议 solver | `buffer_reconstruction_pow` | alpha | answer buffer / verify body |
| PoW Bot Deterrent | 协议 solver | `scrypt_pow` | alpha | nonce / validated OK |
| POWChallenge / powchallenge-server | 协议 solver | `argon2id_memory_pow` | alpha | verify body / validated message |
| pow-reaction | 协议 solver | `signed_multi_round_pow` | alpha | `{challenge, solutions, reaction}` / success |
| Prosopo Procaptcha PoW | 协议 solver | `prosopo_pow` | alpha | submit body / `verified=true` |
| Tollbooth / libcaptcha | 协议 solver | `tollbooth_protocol` | alpha | verify form / clearance token |
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

ALTCHA 不是图片验证码，而是 Proof-of-Work/KDF 验证。SDK 现在同时支持两代协议：

- v1：服务端返回 `algorithm / challenge / salt / signature / maxnumber`，客户端寻找 `number`：

```text
hash(salt + number) == challenge
```

- v2：服务端返回 `{parameters, signature}`，客户端把 `nonce || counter_uint32_be` 作为 password，按 `parameters.algorithm` 走 KDF，直到 derived key 命中 `keyPrefix`：

```text
derivedKey = KDF(password=nonce||counter, salt, cost, keyLength, memoryCost, parallelism)
pass = hex(derivedKey).startswith(keyPrefix)
```

已复现的 v2 KDF：`SHA-256/384/512`、`PBKDF2/SHA-256/384/512`、`SCRYPT`、`ARGON2ID`。

更有意思的是 v2 官方 `verifySolution()` 在没有 `keySignature` 的分支会重算并比较提交的 `derivedKey`，但不重新检查 `keyPrefix`；SDK 因此提供默认 `--v2-strategy auto` 的 verify-compatible fast path：无 `keySignature` 时只派生一次 counter=0 就能构造与官方 verifier 兼容的 payload；如果目标服务端额外检查 prefix，可切到 `--v2-strategy prefix` 做严格搜索。

这类非常适合协议层 SDK：不需要浏览器，不需要识图，也不需要模拟鼠标。

能力：

- GET challenge endpoint，或直接读取 challenge JSON。
- 解析 M2M 的 `WWW-Authenticate: Altcha ...`。
- v1 支持 `SHA-1 / SHA-256 / SHA-512`。
- v2 支持 `SHA / PBKDF2 / SCRYPT / ARGON2ID`，支持 challenge HMAC 签名交叉校验。
- 输出业务侧可用结果：
  - v1/v2 表单/widget：base64 JSON payload，通常填入 `input[name="altcha"]`。
  - v1 M2M/API：`Authorization: Altcha algorithm=..., number=...` header。
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

ALTCHA v2 严格 prefix 搜索：

```bash
antibot solve altcha \
  --challenge-json '{"parameters":{"algorithm":"PBKDF2/SHA-256","cost":1,"keyLength":32,"nonce":"39baf91a19d671f8231217f9e28342a6","salt":"5e00d5d152e1a5db7d44fb6404a40a5e","keyPrefix":"722e"}}' \
  --v2-strategy prefix \
  --max-number 200
```

ALTCHA v2 默认 verify-compatible fast path：

```bash
antibot solve altcha \
  --challenge-json '{"parameters":{"algorithm":"PBKDF2/SHA-256","cost":5000,"keyLength":32,"nonce":"...","salt":"...","keyPrefix":"00"},"signature":"..."}' \
  --hmac-signature-secret 'optional-cross-check-secret'
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

- 支持 ALTCHA v1 hashcash 与 v2 KDF PoW，属于真实协议 solver。
- `ticket` 在默认 `form` 模式下是 base64 payload；v1 `m2m` 模式下是 `Authorization: Altcha challenge={...}` header。
- v2 默认 `auto` 策略会优先走官方 verifier 兼容快速路径；需要真实 prefix 命中时使用 `--v2-strategy prefix`。
- 如果服务端启用了高 `maxnumber`、高 PBKDF2 cost、SCRYPT 或 ARGON2ID，建议按 VPS 资源显式设置 `--workers` 和 `--timeout`。

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

### 11. Auro.Network AES-GCM 行为 PoW

Auro.Network 这一类比普通 hashcash 多一层“环境数据加密”：前端先用 `x-client` 拉 `/enckey`，把鼠标轨迹 JSON 用 AES-GCM 加密后作为 multipart 字段 `mouse + iv` 提交到 `/api/pow/setup`，服务端再返回 `prefix/difficulty`，最后客户端搜索 `SHA256(prefix + nonce)` 的前导 0 hex，并把 `{prefix, nonce}` 交给 `/api/pow/validate`。

关键点：

- `client_guid`：贯穿 `/enckey`、`/api/pow/setup`、`/api/pow/validate` 的 `x-client`。
- 鼠标 telemetry：紧凑 JSON，形如 `[{"x":199,"y":51,"t":...}, ...]`。
- 加密：AES-GCM，12 字节 IV，输出 `base64(ciphertext || tag)`；multipart 字段名为 `mouse` 和 `iv`。
- PoW：`hash = SHA256((prefix + decimal_nonce).utf8).hexdigest()`。
- 通过条件：`hash.startswith("0" * difficulty)`，difficulty 是 hex nibble 数。
- 不启动浏览器；可以直接从 endpoint 拉 key/setup，也可以传 fixture 的 `--challenge-json` 只解 PoW。

命令示例：

```bash
antibot solve auro   --base-url 'https://auro.network'   --timeout 60
```

只解 PoW fixture：

```bash
antibot solve auro   --challenge-json '{"prefix":"prefix-","difficulty":3}'   --no-submit   --max-attempts 10000
```

压测：

```bash
antibot stress auro   --challenge-json '{"prefix":"prefix-","difficulty":3}'   --no-submit   --runs 20   --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_auro(
        challenge_json={"prefix": "prefix-", "difficulty": 3},
        submit=False,
        max_attempts=10_000,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("nonce"))
```

当前定位：

- 这是协议层“行为 telemetry 加密 + PoW”solver，不是滑块/浏览器模拟。
- 已复现本地逆向材料里的 `/enckey -> AES-GCM(mouse,iv) -> /api/pow/setup -> SHA256(prefix+nonce) -> /api/pow/validate` 链路。
- Auro live 域名当前在 VPS 上 DNS 解析失败，因此 live evidence 暂缺；SDK 用本地 mock 完整闭环验证，真实端恢复后可直接用 `--base-url` 复测。
- difficulty 每 +1 平均搜索空间约乘 16；VPS 上先降 `--concurrency`，再按需调 `--workers`。

---

### 12. FriendlyCaptcha classic PoW

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

### 12.1 FCaptcha signals-bound PoW

FCaptcha 的核心不是图片识别，而是“行为/环境 signals + PoW 绑定”。浏览器 widget 会先生成 behavioral/environmental payload，再对紧凑 JSON 做哈希，把这个 `signalsHash` 拼进 PoW 输入：

```text
signalsJson = JSON.stringify(signals)
signalsHash = SHA256(signalsJson)
hash = SHA256(prefix + ":" + signalsHash + ":" + nonce)
```

SDK 当前把这条链路做成纯协议 solver：

- `GET /api/pow/challenge?siteKey=...` 获取 `challengeId/prefix/difficulty/nonce/sig`。
- 合成低风险 behavioral/environmental signals：
  - 鼠标轨迹点数、抖动、方向变化、overshoot、点击精度；
  - `navigator/platform/languages/plugins/window.chrome`；
  - WebGL/Canvas/WebRTC/Speech/Fonts/Permissions/DOMRect 等环境字段。
- `meta.challengeNonce` 必须等于服务端 challenge 里的 `nonce`，否则会被判定 signals 没绑定本次 challenge。
- 以 canonical `signalsJson` 计算 `signalsHash`，再搜索 PoW nonce。
- 服务端有不可伪造的 `serverElapsed < 1500ms` 检查，所以 CLI/SDK 默认 `--min-submit-ms 1600`。
- 可提交 `/api/verify` 或 `/api/score`，成功后返回 FCaptcha token。

只解 challenge，不提交：

```bash
antibot solve fcaptcha \
  --challenge-json '{"challengeId":"fc-1","prefix":"fc-1:1700000000000:2","difficulty":2,"nonce":"server-nonce","siteKey":"site-key"}' \
  --site-key site-key \
  --raw
```

完整协议闭环：

```bash
antibot solve fcaptcha \
  --base-url 'https://captcha.example' \
  --site-key site-key \
  --submit \
  --min-submit-ms 1600 \
  --raw
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_fcaptcha(
        base_url="https://captcha.example",
        site_key="site-key",
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是 behavior/environment signalsHash-bound PoW solver，不启动浏览器，适合 VPS/headless 受限环境。
- `signalsJson` 一旦改变，`signalsHash` 和 PoW 都必须重算；不能先解 PoW 再改 signals。
- 若真实部署接入 JA4/TLS 指纹、强 IP reputation 或高 difficulty，SDK 仍能输出正确客户端提交体，但成功率会受网络出口和服务端策略影响。

---

### 13. PrivateCaptcha Compute PoW

PrivateCaptcha 是 self-hosted compute puzzle：前端从 `/puzzle?sitekey=...` 拉到 `puzzle.signature`，worker 对 puzzle bytes 做 blake2b-256 PoW，最后把 `solutions.puzzle.signature` 放进隐藏字段 `private-captcha-solution`。SDK 当前把这条链路做成纯协议 solver。

关键点：

- puzzle bytes 结构：`version + propertyID(16) + puzzleID(u64LE) + difficulty + solutionsCount + expiration(u32LE) + userData(16)`。
- 浏览器会把 puzzle bytes 扩展到 128 字节。
- 每个 solution 为 8 字节：`puzzleIndex + 3 reserved bytes + 4-byte nonce`。
- PoW：`blake2b-256(puzzle_buffer_with_solution)`，取 digest 前 4 字节 little-endian。
- threshold：复现 upstream Go `2^((255.999999999-difficulty)/8)`。
- 输出 widget response：`base64(metadata+solutions).puzzle_b64.signature_b64`。

命令示例：

```bash
antibot solve privatecaptcha \
  --puzzle-url 'https://api.privatecaptcha.com/puzzle' \
  --sitekey 'site-key'
```

只解本地 puzzle，不请求网络：

```bash
antibot solve privatecaptcha \
  --puzzle 'puzzle_b64.signature_b64' \
  --max-attempts-per-solution 50000000
```

提交到 PrivateCaptcha `/verify`：

```bash
antibot solve privatecaptcha \
  --puzzle-url 'https://captcha.example/puzzle' \
  --sitekey 'site-key' \
  --verify-url 'https://captcha.example/verify' \
  --api-key 'api-key' \
  --submit
```

提交到 reCAPTCHA-compatible `/siteverify`：

```bash
antibot solve privatecaptcha \
  --puzzle-url 'https://captcha.example/puzzle' \
  --sitekey 'site-key' \
  --siteverify-url 'https://captcha.example/siteverify' \
  --secret 'owner-secret' \
  --submit
```

压测：

```bash
antibot stress privatecaptcha \
  --puzzle-url 'https://captcha.example/puzzle' \
  --sitekey 'site-key' \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_privatecaptcha(
        puzzle_url="https://captcha.example/puzzle",
        sitekey="site-key",
        verify_url="https://captcha.example/verify",
        api_key="api-key",
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code)
```

当前定位：

- 这是协议层 compute PoW solver，不启动浏览器。
- 已按 upstream `widget/js/puzzle.utils.js`、`pkg/puzzle/solver.go`、`pkg/puzzle/solutions.go` 对齐。
- 已用 upstream Go `VerifySolutions()` 交叉验证 Python 产出的 payload。
- difficulty 每 +8 平均搜索空间约乘 2；真实站点高 difficulty/多 solution 时会吃 CPU，VPS 上先控并发。

---

### 14. Portcullis Argon2id + SHA-256 PoW

Portcullis 是更硬一点的 PoW CAPTCHA：不是直接对 nonce 做 hash，而是先对 challenge 做一次 Argon2id 内存硬化，得到 32 字节 `base_hash`，再在内循环里搜索 `SHA256(base_hash || nonce_le_8)` 的前导零 bit。challenge 本身带 HMAC-SHA256 签名，客户端解题后原样回传 challenge/sig/nonce，服务端 `/api/v1/verify` 换 `captcha_token`。

关键点：

- challenge endpoint：`POST /api/v1/challenge`，请求 `{"site_key":"pk_test"}`。
- challenge 字段：`id/salt/diff/exp/site_key/m_cost/t_cost/p_cost`。
- Phase 1：`Argon2id(password=id, salt=salt, m/t/p, out=32)`。
- Phase 2：`SHA256(base_hash || nonce_le_8)`。
- 通过条件：digest 前导零 bit 数 `>= diff`。
- verify endpoint：`POST /api/v1/verify`，提交 `challenge/sig/nonce`，成功返回 `captcha_token`。
- 可选 siteverify：`POST /api/v1/siteverify`，提交 `token/secret_key/client_ip/user_agent`。

命令示例：

```bash
antibot solve portcullis \
  --base-url 'https://captcha.example' \
  --sitekey 'pk_test' \
  --submit
```

只解本地 challenge，不请求网络：

```bash
antibot solve portcullis \
  --challenge-json '{"challenge":{"id":"...","salt":"...","diff":18,"exp":9999999999999,"site_key":"pk_test","m_cost":4096,"t_cost":1,"p_cost":1},"sig":"..."}' \
  --max-iters 10000000
```

带业务后端核验：

```bash
antibot solve portcullis \
  --base-url 'https://captcha.example' \
  --sitekey 'pk_test' \
  --submit \
  --siteverify-url 'https://captcha.example/api/v1/siteverify' \
  --secret-key 'sk_test_secret_at_least16'
```

压测：

```bash
antibot stress portcullis \
  --base-url 'https://captcha.example' \
  --sitekey 'pk_test' \
  --submit \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_portcullis(
        base_url="https://captcha.example",
        sitekey="pk_test",
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code, ret.diagnostics.get("nonce"))
```

当前定位：

- 这是协议层内存硬化 PoW solver，不启动浏览器。
- 已和 upstream `captcha-core/src/pow.rs` / `challenge.rs` 对齐。
- SDK 不伪造 challenge 签名；有 `sig` 时原样回传，签名仍由服务端验证。
- `m_cost/t_cost/diff` 都会显著影响耗时，VPS 上优先使用低并发，必要时再开 `--workers`。

---

### 15. Cap / @cap.js PoW

Cap 是 self-hosted CAPTCHA 方向里比较适合 SDK 化的一类：老链路是 SHA-256 proof-of-work，新链路加入了 format-2 RSW time-lock puzzle。SDK 当前只做协议层可验证的部分，不启动浏览器。

支持两种主流形态：

- v1 seeded challenge：服务端返回 `token` 和 `challenge: {c, s, d}`，SDK 按 Cap PRNG 生成每个 `salt/target` 并搜索 nonce。
- format-2 `sha256-pow`：服务端直接返回 `challenges: [{protocol:"sha256-pow", payload:{salt,target}}]`，SDK 逐个求解并输出 `{nonce}`。
- format-2 `rsw`：服务端返回 `payload:{N,x,t}`，SDK 执行顺序型 modular squaring：`y = x; repeat t: y = y*y mod N`，输出 `{y}`。

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

- 支持 Cap v1 seeded SHA-256 PoW、format-2 `sha256-pow` 与 format-2 `rsw` time-lock puzzle。
- format-2 的 `instrumentation` 不伪装成已解决；遇到时会明确返回 unsupported diagnostics。
- 默认单 worker，适合 VPS；高 `d` 或高 `c` 时再显式调 `--workers` 和 `--timeout`。

---

### 15.1 Captxa simple JA4-bound PoW

Captxa simple mode 不是图片滑块，链路是“浏览器环境预检 + JA4/IP 绑定 opaque token + SHA-256 PoW”。服务端 `/challenge/simp` 先检查 browser metrics、JA4 与 UA 是否一致，然后返回：

```json
{
  "challenge_token": "opaque-chaCha20-poly1305-token",
  "pow_challenge": "16-byte-hex",
  "pow_difficulty": 18
}
```

`challenge_token` 内部是服务端临时 key 加密的：

```text
SIMP|ip|short_ja4|short_ja4o|timestamp|pow_hex
```

客户端不需要也不能解这个 token；只需要原样回传，并完成 PoW：

```text
seed = hex(pow_challenge) padded to 32 bytes
hash = SHA256(seed || uint64_le(nonce))
pass = leading_zero_bits(hash) >= pow_difficulty
```

SDK 当前支持：

- 合成低风险 browser metrics：`webglrenderer/timezone/hardwareconcurrency/innerw/innerh/availw/availh/devicememory/webdriver/...`；
- 解析 `/challenge/simp` 响应或本地 fixture；
- 搜索 `pow_solution`；
- 可选提交 `/solve/simp`，读取响应头 `X-Captcha-Token`；
- 不启动浏览器，不做复杂滑块。

命令示例：

```bash
antibot solve captxa \
  --base-url 'https://captcha.example' \
  --submit \
  --timeout 60 \
  --raw
```

只解 fixture：

```bash
antibot solve captxa \
  --challenge-json '{"challenge_token":"opaque","pow_challenge":"0102030405060708090a0b0c0d0e0f10","pow_difficulty":12}'
```

当前定位：

- 这是 simple mode 协议 solver；complex slider 仍不作为本轮主能力。
- 真实部署的 JA4 由 TLS 层算，SDK 能完成客户端 PoW 与环境 payload，但出口 TLS 指纹/UA 不匹配时服务端可能下发 complex。

---

### 15.1.1 crypto-puzzle RSW Time-lock Puzzle

`crypto-puzzle` 是一个 time-lock puzzle 生成器，README 里明确把它作为透明 captcha / anti-spam PoW 使用。它和普通前缀零 hashcash 不一样：服务端生成 puzzle 时知道 `p/q`，可以用 `φ(n)` 快速构造；客户端解题端不知道 `φ(n)`，必须执行确定数量的顺序平方，不能靠多线程或 GPU 线性加速。

核心链路：

```text
archive = len(n)||n||len(a)||a||len(t)||t||len(Ck)||Ck||Cm
b = a^(2^t) mod n        # 解题端等价为 t 次连续平方
K = Ck - b                # BigInt -> minimal big-endian bytes
message = AES-GCM-Decrypt(Cm, PBKDF2-SHA256(K, salt, rounds=1))
```

SDK 当前支持：

- 解析 npm `crypto-puzzle@5.0.3` archive binary/base64/hex/JSON；
- 复现 `fast-mod-exp` 生成链路对应的解题端 `sfme(a,t,n)`：顺序 repeated-squaring；
- 复现 `tiny-encryptor` v1：`version|salt32|rounds_be32|iv16|ciphertext|tag16`，PBKDF2-HMAC-SHA256 + AES-GCM；
- 输出解密后的 `message/token`，可选提交 `{solution,message}` 到 verify endpoint；
- 不启动浏览器。

命令示例：

```bash
antibot solve cryptopuzzle \
  --puzzle 'AAAAAgyhAAAAAQUAAAABGQAAACARERER...' \
  --expected-message 'crypto-puzzle-pass-token' \
  --timeout 60
```

完整 API 闭环：

```bash
antibot solve cryptopuzzle \
  --base-url 'https://target.example/crypto-puzzle' \
  --submit \
  --timeout 60
```

当前定位：

- 这是 RSW time-lock 协议 solver，不是图片验证码；
- `t` 是顺序成本，压测时不要盲目提高并发；
- 如果站点把解出的 message 当作一次性 token，live 压测必须每轮重新拉 challenge。

---

### 15.2 Swetrix CAPTCHA challenge:nonce PoW

Swetrix CAPTCHA 是一个隐私取向的开源 CAPTCHA，客户端不做图片识别，而是在 iframe 内点击后走 PoW 协议：

```text
POST /v1/captcha/generate {pid}
-> {challenge, difficulty}

hash = SHA256(challenge + ":" + nonce)
pass = hash 前 difficulty 个十六进制字符全为 0

POST /v1/captcha/verify {pid, challenge, nonce, solution}
-> {success, token, timestamp, challenge, pid}
```

服务端还提供 `/validate`：后端把 widget token 和项目 secret 发过去，校验 token 是否有效、过期或重放。SDK 当前支持：

- 从 `/generate` 拉取 challenge，或读取本地 fixture；
- 按浏览器 worker 的规则复现 `SHA256(challenge+":"+nonce)`；
- 用 digest 字节做前导十六进制零判断，避免每次循环都转 hex；
- 可多进程 worker 搜索高 difficulty；
- 可提交 `/verify` 换 token，并可选调用 `/validate`；
- 不启动浏览器。

命令示例：

```bash
antibot solve swetrix \
  --pid 'AP00000000000' \
  --submit \
  --secret 'PASS000000000000000000' \
  --raw
```

只解 fixture：

```bash
antibot solve swetrix \
  --pid 'AP00000000000' \
  --challenge-json '{"challenge":"swetrix-fixture-challenge","difficulty":4}'
```

当前定位：

- 这是 PoW 协议 solver，不是图像/文字 solver；
- 真实项目的 difficulty 可能由 auto mode 根据 UA、headers、IP reputation、重放/失败率动态提高，SDK 已补齐常见浏览器头并保留 `workers/max-attempts/timeout` 调参。

---

### 15.3 Crovly fingerprint/behavior-bound PoW

Crovly widget 的客户端链路不是图片识别，而是三段绑定：

```text
GET  /challenge  Header: X-Site-Key
-> {nonce, difficulty, badge?, color?, size?}

counter = first uint32 where leadingZeroBits(SHA256(nonce + counter)) >= difficulty
fingerprintHash = SHA256(canvas|webgl|audio|screen|timezone|language|platform|deviceMemory|hardwareConcurrency)
environment = {webdriver, chromeAbsent, noPlugins, swiftShader, notificationDenied, zeroScreen, noLanguages}
behavior = {mm, md, mdc, msv, kc, kdv, sc, sdc, tc, el, mac, mte, kte, ...hold?}

POST /verify Header: X-Site-Key
{nonce, counter, solveTimeMs, fingerprintHash, environment, behavior}
-> {passed, token, expiresAt?}
```

SDK 当前支持：

- 复现 widget worker 的 `SHA256(nonce+counter)`，按 **前导 bit** 判断 difficulty；
- 默认生成低风险 `fingerprintHash/environment/behavior`，不依赖 headless browser；
- 支持覆盖 fingerprint/profile/environment/behavior/hold signals，方便接真实采集器；
- 可从 `/challenge` 拉取、读取 fixture，或提交 `/verify` 换 token；
- 可多进程 worker 搜索，并提供 `min-submit-ms/min-solve-ms` 调整时序；
- VPS/headless 受限时仍可纯 HTTP 运行，不启动浏览器。

命令示例：

```bash
antibot solve crovly \
  --api-url 'https://api.crovly.com' \
  --site-key 'crvl_site_xxx' \
  --submit \
  --timeout 60

antibot solve crovly \
  --challenge-json '{"nonce":"crovly-fixture","difficulty":12}' \
  --timeout 5 \
  --raw

antibot stress crovly \
  --challenge-json '{"nonce":"crovly-fixture","difficulty":12}' \
  --runs 20 \
  --concurrency 4
```

当前定位：

- 这是协议 solver，不是文字点选/语义识图 solver；
- 真实站点如果把 fingerprint、行为、IP reputation 和站点会话强绑定，可能需要接入站点侧采集到的 profile/signals；
- SDK 已把最核心的 challenge/PoW/verify body 打通，后续优化重点是 profile 采样池、时序建模和失败反馈自适应。

---

### 16. chpio/pow-captcha Target-match PoW

chpio/pow-captcha 不是“前导零 hashcash”，而是服务端一次发多个 `(nonce,target)` 任务：客户端枚举 8 字节 little-endian `solution`，直到 `SHA256(solution_le_8 || nonce_bytes)` 的前 `difficultyBits` 位和 `target` 对齐。challenge 外层用 `signedData` 包住，签名规则是 `SHA256(UTF16LE(data_json + ":" + secret))`。

关键点：

- 支持 raw challenge：`{"magic":"2104...","challenges":[[nonce_b64,target_b64]],"difficultyBits":18}`。
- 支持 signed challenge：`{"data":"...json...","hash":"...base64..."}`，可用 `--secret` 做本地/fixture 交叉校验。
- 搜索输入复现 upstream `solver.ts` / WASM：`solution` 是 8 字节 little-endian，hash buffer 是 `solution || nonce`。
- target 匹配支持非整字节难度，例如 18 bits 会比对 2 个整字节 + 第 3 字节高 2 bit。
- 输出 `{challengesSigned, solutions}`；如果传 `--redeem-url --submit`，可提交 redeem endpoint。
- 不启动浏览器，适合 VPS/headless 受限环境。

命令示例：

```bash
antibot solve chpiopow   --challenge-json '{"magic":"2104f639-ba1b-48f3-9443-889128163f5a","challenges":[["AQI=","AwQF"]],"difficultyBits":18}'   --max-attempts-per-challenge 100000
```

拉取 signed challenge 并 redeem：

```bash
antibot solve chpiopow   --challenge-url 'https://captcha.example/chpiopow/challenge'   --redeem-url 'https://captcha.example/chpiopow/redeem'   --submit   --timeout 60
```

压测：

```bash
antibot stress chpiopow   --challenge-url 'https://captcha.example/chpiopow/challenge'   --redeem-url 'https://captcha.example/chpiopow/redeem'   --submit   --runs 20   --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_chpiopow(
        challenge_json={
            "magic": "2104f639-ba1b-48f3-9443-889128163f5a",
            "challenges": [["AQI=", "AwQF"]],
            "difficultyBits": 18,
        },
        max_attempts_per_challenge=100_000,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("solution_ints"))
```

当前定位：

- 这是协议层 signed multi-challenge target-match PoW solver，不做浏览器模拟。
- 已和 upstream `solver.spec.ts` fixture 对齐：`[1,2] / [3,4,5] / 18bits -> solution bytes [45,176,0,0,0,0,0,0]`。
- `secret` 只用于本地签名交叉校验或验证 signed redeem response；真实服务端 secret 不需要、也不应放入 SDK。
- difficultyBits 每 +1 平均搜索空间约乘 2；challengeCount 越多 CPU 越重，VPS 上先降 `--concurrency`。

---

### 17. Impost Zig/WASM Argon2id PoW

Impost 是一个把 PoW solver 编译成 Zig WASM worker 的验证码组件。它比普通 hashcash 更重：每次尝试不是 SHA-256，而是 Argon2id 内存硬化 KDF。SDK 当前把 WASM 里的核心参数复现成纯 Python 协议 solver。

关键点：

- algorithm：`argon2id`。
- Argon2 参数：`time_cost=3`，`memory_cost=8192KiB`，`parallelism=1`，输出 32 字节。
- 输入绑定：`secret = decimal_nonce_utf8`，`salt = challenge.salt.utf8`。
- `leading_zeroes`：要求 Argon2id 输出 hex 具有指定数量的前导 `0`。
- `target_number`：服务端先随机一个数字并计算 target，客户端枚举 nonce 直到 Argon2id hex 等于 target。
- upstream worker 从 nonce `0` 开始。
- 不启动浏览器；支持本地 JSON、challenge endpoint、可选 verify endpoint。

命令示例：

```bash
antibot solve impost   --challenge-json '{"algorithm":"argon2id","strategy":"target_number","salt":"impost-salt","target":"001f1f03c8591bd692761601e1402ae569e0151ef8d5ba3d083e803ac4f2cd5e"}'   --max-attempts 5
```

拉 challenge 并提交 verify：

```bash
antibot solve impost   --challenge-url 'https://captcha.example/impost/challenge'   --verify-url 'https://captcha.example/impost/verify'   --submit   --timeout 60
```

压测：

```bash
antibot stress impost   --challenge-json '{"algorithm":"argon2id","strategy":"leading_zeroes","salt":"impost-salt","difficulty":2}'   --runs 10   --concurrency 2   --max-attempts 20
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_impost(
        challenge_json={
            "algorithm": "argon2id",
            "strategy": "leading_zeroes",
            "salt": "impost-salt",
            "difficulty": 2,
        },
        max_attempts=20,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("nonce"))
```

当前定位：

- 这是协议层 Argon2id PoW solver，不做浏览器模拟。
- 已和 upstream `packages/solver/src/argon2.zig` / `validator.zig` 的参数和校验方式对齐。
- 单次 hash 需要约 8MiB 内存，VPS 上压测时优先控制 `--concurrency` 和 `--workers`。

---

### 18. Kerberus u128-score 多盐 PoW

Kerberus 是 Kotlin Multiplatform PoW CAPTCHA 库，核心不是直接比较 hash 前导零，而是对每个 salt 先做 prefix hash，再把 hash 的前 16 字节当作 u128 score 和 difficultyFactor 派生阈值比较。它的设计重点是多个小 challenge 降低耗时方差。

关键点：

- challenge：`{"id":"...","salts":["..."],"difficultyFactor":5000}`。
- 输入绑定：`serializedInput` 会拼到每个 salt 后面，先计算 `prefixHash = SHA256((salt + serializedInput).utf8)`。
- nonce 搜索：upstream 从 `nonce=1` 开始，计算 `SHA256(prefixHash || decimal_nonce_utf8)`。
- score：取 digest 前 16 字节，按 big-endian u128 解释。
- 阈值：`threshold = (2^128 - 1) - floor((2^128 - 1) / difficultyFactor)`。
- 通过条件：`score >= threshold`。
- 输出：`Solution{id, nonces}`，每个 salt 一个 nonce。
- 不启动浏览器；支持本地 JSON、challenge endpoint、可选 validate endpoint。

命令示例：

```bash
antibot solve kerberus   --challenge-json '{"id":"kerb-1","salts":["salt-a","salt-b"],"difficultyFactor":50}'   --serialized-input 'JRTFM'   --max-attempts-per-salt 1000
```

拉 challenge 并提交 validate：

```bash
antibot solve kerberus   --challenge-url 'https://captcha.example/kerberus/challenge'   --validate-url 'https://captcha.example/kerberus/validate'   --submit   --timeout 60
```

压测：

```bash
antibot stress kerberus   --challenge-json '{"id":"kerb-1","salts":["salt-a","salt-b"],"difficultyFactor":50}'   --serialized-input 'JRTFM'   --runs 20   --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_kerberus(
        challenge_json={"id": "kerb-1", "salts": ["salt-a", "salt-b"], "difficultyFactor": 50},
        serialized_input="JRTFM",
        max_attempts_per_salt=1_000,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("nonces"))
```

当前定位：

- 这是协议层多盐 u128-score PoW solver，不做浏览器模拟。
- 已和 upstream `PowTest.kt` 的 `Validate dart` fixture 对齐。
- difficultyFactor 越大平均命中越慢；salt 数越多总工作量越大，VPS 上先控制 `--concurrency`。

---

### 19. PaulDotSH/pow-captcha bcrypt PoW

PaulDotSH/pow-captcha 是 Rust 版 bcrypt PoW CAPTCHA，核心不是 SHA 前导零，而是 bcrypt 的内存/CPU 成本。它有两种模式：`Exact` 用完整 bcrypt hash 反查小范围 nonce；`Prefix` 用服务端给的 salt 前 16 字节作为 bcrypt salt，客户端枚举 nonce 后比较 bcrypt 字符串前缀。

关键点：

- challenge JSON：`{hash, salt, captchaType, size, cost}`。
- `exact`：验证 `bcrypt.verify((salt + nonce).utf8, hash)`，搜索范围通常是 `0..size`。
- `prefix`：构造 bcrypt salt：`$2b$cost$bcrypt_base64(salt.utf8[:16])`。
- `prefix` 校验：`bcrypt.hashpw((salt + nonce).utf8, constructed_salt)[:size] == hash[:size]`。
- upstream CLI 输出的是 bitcode/base64 的 `CaptchaServerInfo`；SDK 当前用等价 JSON 暴露 `clientInfo + nonce`，便于 HTTP mock 与业务层提交。
- 不启动浏览器；支持本地 JSON、challenge endpoint、可选 verify endpoint。

命令示例：

```bash
antibot solve paulpow   --challenge-json '{"hash":"$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC","salt":"abcdefghijklmnopXYZ","captchaType":"prefix","size":30,"cost":4}'   --max-attempts 10
```

拉 challenge 并提交 verify：

```bash
antibot solve paulpow   --challenge-url 'https://captcha.example/paulpow/challenge'   --verify-url 'https://captcha.example/paulpow/verify'   --submit
```

压测：

```bash
antibot stress paulpow   --challenge-json '{"hash":"$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC","salt":"abcdefghijklmnopXYZ","captchaType":"prefix","size":30,"cost":4}'   --runs 8   --concurrency 2   --max-attempts 10
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_paulpow(
        challenge_json={
            "hash": "$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC",
            "salt": "abcdefghijklmnopXYZ",
            "captchaType": "prefix",
            "size": 30,
            "cost": 4,
        },
        max_attempts=10,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("nonce"))
```

当前定位：

- 这是协议层 bcrypt exact/prefix PoW solver，不做浏览器模拟。
- 已和 Rust `bcrypt::hash_with_salt` 的自定义 radix-64 salt 编码对齐。
- bcrypt cost 默认可能很重；VPS 上先用低 `--concurrency`，真实 cost=12 时不要无脑压测。

---

### 20. guns.lol seal PoW / BLAKE3 `_oo`

guns.lol 这类 challenge 把参数塞在页面里的 `const _gs_sets = {...}`，核心不是普通前导零 PoW，而是“补全 64 字节 seal 空位 + 服务端 hash 目标 + BLAKE3 提交标签”。SDK 当前把这条链路做成纯协议 solver，不启动浏览器，适合 VPS 上低资源压测。

关键点：

- 页面或 JSON 中提取：`o09`、`_n`、`_org_ts`、`_2xa`。
- `_2xa` 是 base64url blob：包含 `dd`、原始空位顺序、8 字节 BLAKE3 key、`64-dd` 字节 seal 模板。
- 求解：枚举 `16^dd` 个十六进制填充，直到：

```text
SHA256(seal + _n + _org_ts) == bytes.fromhex(o09)
```

- 提交：按原始空位顺序取 solution chars，构造 prefix，再计算：

```text
_oo = base64url(prefix || BLAKE3(prefix + key + target)[:8])
```

- 输出：`{"seal":"...","_oo":"..."}`，可直接 POST 到业务 verify endpoint。
- 不启动浏览器；支持本地 JSON、HTML 页面、challenge endpoint、可选 verify endpoint。

命令示例：

```bash
antibot solve gunslol   --challenge-json '{"o09":"3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a","_n":"auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2","_org_ts":"1777135187","_2xa":"oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA"}'
```

从页面抓 `_gs_sets` 并提交 verify：

```bash
antibot solve gunslol   --page-url 'https://guns.lol/example'   --verify-url 'https://target.example/verify'   --submit
```

压测：

```bash
antibot stress gunslol   --challenge-json '{"o09":"3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a","_n":"auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2","_org_ts":"1777135187","_2xa":"oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA"}'   --runs 20   --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_gunslol(
        challenge_json={
            "o09": "3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a",
            "_n": "auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2",
            "_org_ts": "1777135187",
            "_2xa": "oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA",
        },
        workers=1,
    )
    print(ret.ok, ret.ticket, ret.diagnostics.get("_oo"))
```

当前定位：

- 这是协议层 seal PoW + BLAKE3 tag solver，不做浏览器模拟。
- 已用公开 README fixture 对齐：seal=`c88a698743d20cfdc8e57f9117d6bc4e8f6d9be865810ad0bcd5a6fd26a05419`，`_oo=UQViMDk2NgEAAABD-WCuD2rtiQ`。
- 难度主要由 `dd` 决定：`dd=5` 约 104 万次 SHA-256；VPS 上压测先控制 `--concurrency`，再按 CPU 调整 `--workers`。

---

### 20.1 HashGuard target-threshold PoW + JWT proofToken

HashGuard 的客户端链路是典型的“挑战签发 → 本地阈值 PoW → proofToken JWT”协议：

```text
POST /v1/pow/challenges {context?}
-> {challengeId, algorithm, seed, difficultyBits, target, issuedAt, expiresAt}

hash = SHA256(challengeId + ":" + seed + ":" + nonce)
pass = hash <= target   # 64 hex 字符串同长阈值比较

POST /v1/pow/verifications {challengeId, nonce, clientMetrics:{solveTimeMs}}
-> {proofToken, expiresAt}

POST /v1/pow/assertions/introspect {proofToken, consume}
-> {valid, subject, context, issuedAt, expiresAt}
```

SDK 当前支持：

- 读取 fixture 或请求 `/pow/challenges`；
- 从 `difficultyBits` 自动推导 target，或直接使用服务端 target；
- 复现官方 client/WASM 的 `SHA256(challengeId:seed:nonce) <= target`；
- 可多进程 worker 搜索；
- 可提交 `/pow/verifications` 换 proofToken，并可选 introspect；
- 不启动浏览器。

命令示例：

```bash
antibot solve hashguard \
  --base-url 'https://hashguard.example' \
  --context 'login' \
  --submit \
  --introspect \
  --timeout 60

antibot solve hashguard \
  --challenge-json '{"challengeId":"hg-fixture-1","seed":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficultyBits":12}' \
  --timeout 5

antibot stress hashguard \
  --challenge-json '{"challengeId":"hg-fixture-1","seed":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficultyBits":12}' \
  --runs 20 \
  --concurrency 4
```

当前定位：

- 这是协议层 PoW solver，不涉及文字/图片识别；
- proofToken 是否单次可用由服务端 introspection/消费状态决定；
- 真实服务可能按 IP/路由动态提高 `difficultyBits`，SDK 保留 `workers/max-attempts/min-solve-ms` 调参。

---

### 20.2 TrustCaptcha v3 fingerprint + multi-task PoW

TrustCaptcha v3 的前端不是图片识别，而是“浏览器信息 + 指纹摘要 + integrityHash + 多个 SHA-256 PoW task”的协议：

```text
POST /v2/verifications
{
  siteKey,
  widget:{boxCreationTimestamp,startSolvingTimestamp,timezone,minimalDataMode,settings,...},
  metadata:{framework,libraryVersion},
  browserInformation,
  fingerprints:{audio,canvas,webgl,navigator,fonts,screen},
  honeypotFields,
  userEvents,
  integrityHash
}
-> 200 {challenge:{verificationId,difficulty,tasks:[{number,input}]}}
-> 201 {finished:{verificationToken,expiresInMs}}

nonce = first "tcn" + counter where leadingZeroBits(SHA256(base64(input) || nonce)) >= difficulty

POST /v2/verifications/{verificationId}/challenges
{
  startSolvingTimestamp,
  solvedTimestamp,
  tasks:[{number,nonce}],
  honeypotFields,
  userEvents
}
-> 201 {finished:{verificationToken,expiresInMs}}
```

SDK 当前支持：

- 从 fixture 直接解 challenge，或请求 `/v2/verifications` 后解题；
- 合成低风险 `browserInformation/fingerprints/honeypotFields/userEvents`；
- 按 upstream worker 复现 `SHA256(input||"tcn"+counter)` 前导 bit PoW；
- 多 task 并行 worker 搜索；
- 可提交 `/v2/verifications/{id}/challenges` 换 `tc-verification-token`；
- 不启动浏览器，适合 VPS/headless 受限环境。

命令示例：

```bash
antibot solve trustcaptcha \
  --site-key 'tc_site_xxx' \
  --api-url 'https://api.trustcomponent.com' \
  --target-url 'https://target.example/form' \
  --timeout 60

antibot solve trustcaptcha \
  --challenge-json '{"verificationId":"tc-fixture-1","difficulty":12,"tasks":[{"number":1,"input":"dHJ1c3RjYXB0Y2hhLWZpeHR1cmUtYQ=="}]}' \
  --no-submit \
  --timeout 5

antibot stress trustcaptcha \
  --challenge-json '{"verificationId":"tc-fixture-1","difficulty":12,"tasks":[{"number":1,"input":"dHJ1c3RjYXB0Y2hhLWZpeHR1cmUtYQ=="}]}' \
  --no-submit \
  --runs 20 \
  --concurrency 4
```

当前定位：

- 这是协议层 solver，不是文字点选/语义识图；
- 服务端仍可能结合站点配置、来源域、IP reputation、license/bypass token 等策略动态拒绝；
- 后续优化重点是 profile 采样池、事件时序模型和失败状态自适应。

---

### 20.3 @strav/captcha stateless HMAC token PoW

`@strav/captcha` 的 PoW 不是图片验证码，而是 Strav 表单中间件签发的无状态 HMAC token。token 形态：

```text
token = base64url(JSON payload) + "." + base64url(HMAC-SHA256(body, secret))
payload = {v,t:"pow",s:salt,d:difficulty,iat,exp,jti}

nonce = first decimal counter where leadingZeroBits(SHA256(salt + ":" + nonce)) >= difficulty

submit body:
{
  website: "",
  _captcha: token,
  _captcha_answer: nonce
}
```

SDK 当前支持：

- 解析 `@strav/captcha` view helper HTML、`/__captcha/pow` JSON，或直接传 token；
- 解码 token 公开 payload，提取 `salt/difficulty/jti/exp`；
- 可选用服务端 secret 本地验 HMAC 签名；
- 复现 `pow_challenge.ts` 的 hashcash 规则；
- 输出 middleware / validation-rule 可验的提交字段；
- 不启动浏览器。

命令示例：

```bash
antibot solve stravcaptcha \
  --challenge-url 'https://target.example/__captcha/pow' \
  --timeout 60

antibot solve stravcaptcha \
  --challenge-json '{"token":"base64url.payload.base64url_mac","props":{"challenge":"0123456789abcdef0123456789abcdef","difficulty":12}}' \
  --timeout 5

antibot stress stravcaptcha \
  --challenge-url 'https://target.example/__captcha/pow' \
  --runs 20 \
  --concurrency 4
```

当前定位：

- 这是无状态 token + PoW 协议 solver；
- SDK 不伪造 HMAC，只解析服务端已签发 token 并完成客户端应做的 work；
- replay 是否消费由目标服务端 Cache / middleware 控制。

---

### 21. P-Captcha QuadraticResidueProblem

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

### 22. pow_captcha Buffer Reconstruction PoW

pow_captcha 不是普通前导零 hashcash，而是把“正确 buffer 的 SHA-256、当前被污染 buffer、每个不确定字节的取值范围”序列化到 quiz 里。前端 `takeTest`/WASM 会按 mixed-radix 方式枚举这些不确定字节，直到 `SHA256(candidate_buffer)` 命中目标 hash。SDK 当前把这条链路复现成纯 Python 协议 solver。

关键点：

- `SERIAL` 格式：`a1/a2/count + uncertainties + target_hash + corrupted_buffer`。
- 每个 uncertainty 包含：`index/min/max/base`，支持 wrap-around 取值范围。
- 搜索顺序复现 upstream C/WASM：每轮先从后往前对 uncertainty 做一次“加一”，再比较 SHA-256。
- 输出 answer：`answer` base64、`answerHex`，可选 POST 给业务 verify endpoint。
- 不启动浏览器；默认单 worker，支持 `--workers` 分片搜索。

命令示例：

```bash
antibot solve powcaptcha \
  --quiz-b64 'AP8AAQAAAAPbwbTJAP/kjVdbXaXGOAQBJfZdsP4+JElLduqYZFfZhgA=' \
  --max-attempts 10
```

从 challenge endpoint 拉 quiz，并提交 verify：

```bash
antibot solve powcaptcha \
  --challenge-url 'https://target.example/powcaptcha/challenge' \
  --verify-url 'https://target.example/powcaptcha/verify' \
  --submit \
  --timeout 60
```

压测：

```bash
antibot stress powcaptcha \
  --challenge-url 'https://target.example/powcaptcha/challenge' \
  --verify-url 'https://target.example/powcaptcha/verify' \
  --submit \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient

async with AntibotClient() as client:
    ret = await client.solve_powcaptcha(
        challenge_url="https://target.example/powcaptcha/challenge",
        verify_url="https://target.example/powcaptcha/verify",
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code, ret.diagnostics.get("search_space"))
```

当前定位：

- 这是协议层 buffer reconstruction PoW solver，不是 OCR/视觉识别。
- 已和 upstream `pow.js` / `C/takeTest.c` 的 `takeTest` 行为对齐，包括“先 increment 再 hash”的枚举顺序。
- 大 search space 仍会吃 CPU；VPS 上先控制 `--concurrency`，必要时再开 `--workers`。

---

### 22.1 PoW Bot Deterrent scrypt-WASM PoW

PoW Bot Deterrent 是一个 self-hosted 反机器人组件，设计上接近表单验证码：服务端批量签发 challenge，浏览器 worker 调 WASM scrypt 搜索 nonce，业务后端再把 `challenge + nonce` 提交给 `/Verify`。

它比普通 SHA-256 hashcash 更值得 SDK 化的点在于：

- worker 不是直接 SHA-256，而是 `scrypt`，每次尝试带 CPU/内存成本；
- challenge 是 base64 JSON，包含完整 scrypt 参数；
- 难度不是前导零，而是比较 scrypt 输出十六进制尾部：

```text
hash = scrypt(password=nonce_bytes, salt=preimage_bytes, N, r, p, klen)
endOfHash = hash_hex[-len(difficulty):]
pass = endOfHash <= difficulty
```

SDK 当前支持：

- 解析 `/GetChallenges?difficultyLevel=...` 返回的 base64 challenge；
- 复现 upstream difficulty threshold 生成逻辑；
- 本地搜索 nonce，支持 `--workers` 分片；
- 可选提交 `/Verify?challenge=...&nonce=...`，成功返回 `OK`；
- 不启动浏览器，不加载 WASM，直接用 Python `hashlib.scrypt` 复现协议。

只解 challenge：

```bash
antibot solve powbot \
  --challenge 'base64-json-challenge' \
  --timeout 60 \
  --raw
```

完整协议闭环：

```bash
antibot solve powbot \
  --base-url 'https://pow.example' \
  --api-token '32hex-token' \
  --difficulty-level 5 \
  --submit
```

压测：

```bash
antibot stress powbot \
  --challenge 'base64-json-challenge' \
  --runs 20 \
  --concurrency 4 \
  --timeout 30
```

当前定位：

- 这是 scrypt-WASM PoW 协议 solver，不做浏览器模拟。
- 默认单 worker；真实默认 `N=4096,r=8,p=1,klen=16` 时每次尝试比 SHA-256 重很多，VPS 上不要盲目提高 `--concurrency`。
- 如果走 `/Verify`，challenge 是一次性状态，压测应使用 `/GetChallenges` 新取 challenge，不要重复提交同一个 challenge。

---

### 22.2 POWChallenge / powchallenge-server Argon2id Memory PoW

`powchallenge-server` 这一类挑战比普通 hashcash 更重：服务端签发 32-byte challenge，浏览器 client-js/WASM 用 Argon2id 反复计算 nonce，服务端验证 hash 前导零 bit。它适合 VPS/headless 受限环境下做协议层 solver，因为全流程不依赖页面渲染或识图。

核心参数与 upstream 对齐：

```text
challenge = base64(16 random bytes || 16 ip_salt bytes)
hash = Argon2id(secret=nonce_bytes, salt=challenge_bytes, t=1, m=19456KiB, p=1, hash_len=32)
pass = leading_zero_bits(hash) >= difficulty
POST /verify {req_id, challenge, timestamp, difficulty, nonce}
```

SDK 当前支持：

- `GET /challenge` 获取 `{req_id, challenge, difficulty}`；
- 复现 Argon2id `t=1,m=19456KiB,p=1` memory-hard PoW；
- nonce 默认用 `counter.to_bytes(32, "little")`，也支持 `--nonce-seed` 模拟浏览器随机 seed 后递增；
- 输出标准 padded base64 nonce，同时兼容解析 base64url/no-padding；
- 可提交 `/verify` 完成闭环；
- 不启动浏览器。

只解本地 challenge：

```bash
antibot solve powchallenge \
  --challenge-json '{"req_id":"019aa0e6-b33f-7000-8000-000000000001","challenge":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","difficulty":2}' \
  --max-attempts 20 \
  --timeout 10 \
  --raw
```

完整协议闭环：

```bash
antibot solve powchallenge \
  --base-url 'https://powchallenge.example' \
  --submit \
  --timeout 60
```

压测：

```bash
antibot stress powchallenge \
  --base-url 'https://powchallenge.example' \
  --submit \
  --runs 10 \
  --concurrency 2 \
  --timeout 60
```

当前定位：

- 这是 Argon2id memory-hard 协议 solver，不是滑块/图片 solver；
- 每次尝试约 19 MiB 内存成本，VPS 上默认单 worker，压测时不要盲目拉高 `--workers/--concurrency`；
- 服务端 challenge 绑定 IP 且一次性删除，live 压测必须每轮重新拉 `/challenge`。

---

### 22.3 pow-reaction JWT signed multi-round PoW

`pow-reaction` 是一个把“反刷 reaction/表单动作”做成 PoW captcha 的 Svelte 组件。它的关键不在图像，而在 **签名 challenge + clientId/context 绑定 + 多轮 PoW + redeem 防重放**：

```text
POST /reactions/challenge {reaction}
-> {challenge: HS256_JWT}

JWT payload:
{id, reaction, difficulty, exp, clientId, rounds[]}

for each round in rounds:
  hash = SHA256(round + "." + nonce)
  pass = leading_zero_bits(hash) >= difficulty

POST /reactions {challenge, solutions, reaction}
-> {success:true}
```

服务端会校验：

- JWT HS256 签名和 `exp`；
- `reaction` 是否和服务端实例一致；
- `clientId` 是否匹配当前请求上下文，例如 IP + pageId + salt；
- `solutions.length == rounds.length`；
- 每轮 `SHA256(round.nonce)` 的前导零 bit；
- challenge `id` 是否已 redeem。

SDK 当前支持：

- 解码 signed JWT challenge，提取 `difficulty/rounds/reaction/clientId/exp`；
- 可选 `--secret` 做 HS256 签名交叉校验；
- 复现浏览器 worker 规则 `SHA256(round+"."+nonce)`；
- 多轮 round 顺序/并发求解，输出 `solutions[]`；
- 可提交 reaction endpoint 完成闭环；
- 不启动浏览器。

命令示例：

```bash
antibot solve powreaction \
  --base-url 'https://pow-reaction.pages.dev/demo/reactions' \
  --reaction '👍' \
  --submit \
  --workers 4 \
  --raw
```

只解本地 challenge：

```bash
antibot solve powreaction \
  --challenge-json '{"challenge":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}' \
  --timeout 30
```

当前定位：

- 这是 JWT signed multi-round PoW 协议 solver，不是滑块/图片 solver；
- 真实站点的 challenge 通常绑定 IP/pageId，必须用同一请求上下文拉 challenge 并提交；
- 压测 live endpoint 时不要重复提交同一个 signed challenge，因为服务端会 redeem 防重放。

---

### 22.4 Prosopo Procaptcha PoW

Prosopo Procaptcha 的 PoW 模式不是图片识别，核心在 provider 签发 challenge、用户对 timestamp 签名、客户端搜索 nonce 后提交。当前 SDK 复现公开 npm 包里的 PoW 算法和 HTTP body 结构：

```text
POST /v1/prosopo/provider/client/captcha/pow {user, dapp, sessionId?, simdReadings?}
-> {challenge, difficulty, timestamp, signature:{provider:{challenge}}}

hash = SHA256(str(nonce) + challenge)
pass = hex(hash).startswith("0" * difficulty)

POST /v1/prosopo/provider/client/pow/solution
{challenge, difficulty, signature:{provider,user}, user, dapp, nonce, verifiedTimeout?, ...}
-> {verified:true} 或 escalation
```

SDK 当前支持：

- 读取本地 fixture，或按 provider URL 拉取 challenge；
- 复现 `@prosopo/util` 的 `solvePoW(data, difficulty)`：十进制 nonce 字符串拼接 challenge 后 SHA-256；
- difficulty 按 hex 前缀零数量处理，不是 bit 数；
- 构造 submit body，保留 `signature.provider.challenge` 和用户 timestamp 签名；
- 支持 `behavioralData/salt/simdReadings/clientMetaData` 这些可选字段透传；
- 不启动浏览器。

只解本地 challenge：

```bash
antibot solve procaptcha \
  --challenge-json '{"challenge":"prosopo-fixture","difficulty":3,"timestamp":"1780955164000","signature":{"provider":{"challenge":"0x..."}}}' \
  --timeout 10 \
  --raw
```

完整协议提交：

```bash
antibot solve procaptcha \
  --provider-url 'https://provider.example' \
  --user '5F...' \
  --dapp '5F...' \
  --user-timestamp-signature '0x...' \
  --submit \
  --timeout 60
```

当前定位：

- 这是协议 PoW solver，不解决 Procaptcha image/puzzle escalation；
- 真实提交要求用户账户 timestamp 签名，SDK 不伪造钱包/扩展 signer，只接收外部签名值；
- 如果 provider 返回 escalation，说明 PoW 被接受或进入下一层风控，但后续 image/puzzle 不纳入当前 SDK 主能力。

---

### 22.5 Tollbooth / libcaptcha SHA256-Balloon + Navigator Attestation

Tollbooth 是 libcaptcha 在 2026 发布的 Python bot-challenge middleware。它比普通 hashcash 更有意思：默认 challenge handler 是 `SHA256Balloon`，用 memory-hard balloon hashing 搜索 nonce；另一个 `NavigatorAttestation` handler 走多轮 HTTP poll/WebSocket，服务端给每轮 nonce 和 checks，客户端提交 browser signals，最后服务端签发 token。

PoW 核心链路：

```text
GET protected resource
-> HTML 或 JSON {challenge:{id,data,difficulty,spaceCost,timeCost,delta,verifyPath,csrfToken}}

result = SHA256Balloon(data + str(nonce), spaceCost, timeCost, delta)
pass = leading_zero_bits(result) >= difficulty

POST /.tollbooth/verify form {id, nonce, redirect, csrf_token?}
-> clearance JWT/cookie 或 JSON token
```

Navigator attestation 核心链路：

```text
POST /.tollbooth/verify JSON {id, init:true}
-> {type:"challenge", round, nonce, checks[]}
POST /.tollbooth/verify JSON {id, nonce, round, signals}
-> ... next round ... -> {type:"result", token}
POST /.tollbooth/verify form {id, nonce:token, csrf_token?}
```

SDK 当前支持：

- 解析 Tollbooth JSON challenge 和 HTML 里的 `JSON.parse(CHALLENGE_DATA)`；
- 复现 `sha256` 与 `sha256-balloon` 两种 handler；
- 支持 `spaceCost/timeCost/delta` 自定义参数，默认单 worker，避免 VPS 被 memory-hard hash 打满；
- 支持 `navigator-attestation` HTTP poll：不启浏览器，提交稀疏 signals 走服务端 token flow；
- 支持 form submit 到 `/.tollbooth/verify`，读取 JSON token 或 302 `Set-Cookie`；
- 不做图像/audio/cup 等语义验证码。

只解本地 fixture：

```bash
antibot solve tollbooth \
  --challenge-json '{"id":"tb-fixture","data":"tollbooth-fixture","difficulty":8,"spaceCost":8,"timeCost":1,"delta":1,"verifyPath":"/.tollbooth/verify","redirect":"/protected","csrfToken":"csrf"}' \
  --timeout 5 \
  --raw
```

完整 protected resource 闭环：

```bash
antibot solve tollbooth \
  --challenge-url 'https://target.example/protected' \
  --submit \
  --timeout 60
```

Navigator attestation：

```bash
antibot solve tollbooth \
  --challenge-url 'https://target.example/protected-json' \
  --navigator-strategy empty \
  --submit
```

当前定位：

- 这是 Tollbooth 协议 solver，不是通用浏览器隐身；
- `navigator-attestation` 当前利用其 0.3.9.x scoring 对“缺失 category 不扣分”的协议特性，提交稀疏 signals 让服务端自行签 token；
- 真实站点如果自定义 handler、强制完整 signal schema、提高 difficulty 或绑定额外 headers，需要按现场字段继续补环境。

---

### 23. mCaptcha PoW

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

### 24. Wicketkeeper JWT PoW

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

### 25. yourcaptcha 行为 PoW

yourcaptcha 的关键不是图片识别，而是“先上报 behavioral signals，服务端按风险分调 `maxnumber`，再做 exact SHA-256 PoW”。SDK 当前把这条链路做成协议层 solver：不启动浏览器，在 VPS/headless 受限环境下也能稳定跑。

关键点：

- challenge endpoint 通常接收：`POST /api/captcha/challenge`，body 为 `{"signals": ...}`。
- 服务端按 `scoreSignals(signals)` 得到风险分与 `maxnumber`；低风险默认 `maxnumber=50000`。
- salt 里嵌入过期时间、服务端时间戳和风险分：`baseSalt:expiresAt:serverTimestamp:riskScore`。
- challenge 为 exact hash：

```text
SHA256(salt + String(number)) == challenge
```

- `signature = HMAC_SHA256(secret, challenge)` 只由服务端签发和校验；SDK 不需要 secret，也不伪造签名，只原样带回。
- verify body 会提交 `{algorithm, challenge, number, salt, signature, signals}`；服务端会重新评分 signals，并检查提交时间和分数漂移。

命令示例：

```bash
antibot solve yourcaptcha \
  --challenge-url 'https://target.example/api/captcha/challenge' \
  --verify-url 'https://target.example/api/captcha/verify' \
  --submit
```

只解本地 challenge JSON，不请求网络：

```bash
antibot solve yourcaptcha \
  --challenge-json '{"algorithm":"SHA-256","challenge":"...","maxnumber":50000,"salt":"...","signature":"..."}'
```

压测：

```bash
antibot stress yourcaptcha \
  --challenge-json '{"algorithm":"SHA-256","challenge":"...","maxnumber":50000,"salt":"...","signature":"..."}' \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient, generate_yourcaptcha_signals

async with AntibotClient() as client:
    ret = await client.solve_yourcaptcha(
        challenge_url="https://target.example/api/captcha/challenge",
        verify_url="https://target.example/api/captcha/verify",
        signals_json=generate_yourcaptcha_signals(),
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code, ret.diagnostics.get("number"))
```

当前定位：

- 这是行为 telemetry + exact PoW solver，不做图片/OCR/文字点选。
- 默认合成一份低风险 browser-like signals：`hasWebdriver=false`、非 headless 分辨率、Canvas/WebGL/language/keyboard/mouse/focus 字段齐全。
- 真实服务端 secret 不需要放进 SDK；HMAC 签名只做服务端完整性约束。
- 如果目标站点在服务端额外绑定 session/cookie/origin，需要把同一会话 headers/cookie 传给 challenge 与 verify。

---

### 26. silent-challenge 被动 attestation + balloon PoW

silent-challenge 比普通 hashcash 更高级：它把 motion attestation、navigator attestation、QuickJS/WASM VM response 和 SHA-256 balloon PoW 合成一个被动挑战。SDK 当前做协议层可闭环部分：不启动浏览器，直接补 motion/navigator 环境，并复现 memory-hard balloon hash 搜索 nonce。

关键点：

- challenge endpoint：`POST /challenge`。
- challenge 响应：`{challengeId, pow:{prefix,difficulty,spaceCost,timeCost,delta}, ttl}`。
- PoW 不是普通 `SHA256(prefix+nonce)`，而是 balloon hash：

```text
input = prefix + String(nonce)
buffer[0] = SHA256(u32le(counter=0) || input)
填充 spaceCost 个 32-byte block
按 timeCost/delta 做依赖混合
要求最后 block 的 leading zero bits >= difficulty
```

- verify body 提交：`{nonce, motion, signals, vmResponse?}`。
- SDK 默认不跑 QuickJS/WASM VM；利用默认权重下 motion + navigator + pow 已足够通过 combined threshold 的事实，提交高分 motion/navigator payload，`vmResponse` 保持缺失并在 flags 里暴露。
- 如果目标部署强制 VM 单项阈值或自定义权重，当前版本会显示为验证失败，不伪装通过。

命令示例：

```bash
antibot solve silentchallenge \
  --base-url 'https://target.example' \
  --submit
```

只解本地 challenge JSON，不请求网络：

```bash
antibot solve silentchallenge \
  --challenge-json '{"challengeId":"...","pow":{"prefix":"...","difficulty":10,"spaceCost":512,"timeCost":1,"delta":3}}'
```

压测：

```bash
antibot stress silentchallenge \
  --challenge-json '{"challengeId":"fixture-id","pow":{"prefix":"fixture-prefix-","difficulty":8,"spaceCost":8,"timeCost":1,"delta":3}}' \
  --runs 20 \
  --concurrency 4
```

Python 示例：

```python
from antibot_sdk import AntibotClient, generate_silentchallenge_motion, generate_silentchallenge_signals

async with AntibotClient() as client:
    ret = await client.solve_silentchallenge(
        base_url="https://target.example",
        motion_json=generate_silentchallenge_motion(),
        signals_json=generate_silentchallenge_signals(),
        submit=True,
    )
    print(ret.ok, ret.ticket, ret.verify_code, ret.diagnostics.get("nonce"))
```

当前定位：

- 这是 motion/navigator 补环境 + memory-hard PoW solver，不做浏览器模拟。
- 已按 upstream `src/crypto.js` 的 counter、little-endian counter、big-endian digest index、`spaceCost/timeCost/delta` 混合顺序复现。
- 默认 synthetic motion 在 upstream scorer 中为 human 档，navigator signals 为 trusted 档；默认 middleware 即使 `vmResponse` 缺失也能通过 combined threshold。
- PoW 耗时主要由 `difficulty × spaceCost × timeCost × delta` 决定；VPS 上优先控制并发。

---

### 27. GeeTest v4 / 极验

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

### 28. 网易易盾 / Yidun 滑动拼图

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

### 29. 自动分发模式

SDK 可以根据 URL 粗略判断 provider：

- Qoder / Aliyun 相关 URL -> `aliyun`
- AJ-Captcha / Anji / `/captcha/get` 相关 URL -> `ajcaptcha`
- ALTCHA 相关 URL -> `altcha`
- Anubis / `.within.website/x/cmd/anubis` 相关 URL -> `anubis`
- Auro.Network / `/api/pow/setup` / `/api/pow/validate` 相关 URL -> `auro`
- FriendlyCaptcha / `frc-captcha` 相关 URL -> `friendlycaptcha`
- FCaptcha / `/api/pow/challenge` / `/api/verify` 相关 URL -> `fcaptcha`
- PrivateCaptcha / private-captcha / api.privatecaptcha.com 相关 URL -> `privatecaptcha`
- Portcullis / pow-captcha / `/api/v1/challenge` 相关 URL -> `portcullis`
- Cap / trycap / cap-widget 相关 URL -> `cap`
- crypto-puzzle / cryptopuzzle / time-lock-puzzle 相关 URL -> `cryptopuzzle`
- Captxa / `/challenge/simp` / `/solve/simp` 相关 URL -> `captxa`
- Swetrix CAPTCHA / `swetrixcaptcha` / `/v1/captcha/generate` 相关 URL -> `swetrix`
- Crovly / `get.crovly.com/widget.js` / `api.crovly.com/challenge` 相关 URL -> `crovly`
- chpio / chpiopow / signedData magic 相关 URL -> `chpiopow`
- Impost / impost-captcha 相关 URL -> `impost`
- Kerberus / difficultyFactor / serializedInput 相关 URL -> `kerberus`
- PaulDotSH / bcrypt_pow / paulpow 相关 URL -> `paulpow`
- guns.lol / `_gs_sets` / `_2xa` 相关 URL -> `gunslol`
- HashGuard / `/pow/challenges` / `/pow/verifications` 相关 URL -> `hashguard`
- TrustCaptcha / TrustComponent / `/v2/verifications` 相关 URL -> `trustcaptcha`
- @strav/captcha / `/__captcha/pow` / `_captcha_answer` 相关 URL -> `stravcaptcha`
- mCaptcha / `/api/v1/pow/config` 相关 URL -> `mcaptcha`
- Wicketkeeper / `/v0/challenge` 相关 URL -> `wicketkeeper`
- yourcaptcha / `/api/captcha/challenge` / `/api/captcha/verify` 相关 URL -> `yourcaptcha`
- silent-challenge / silentchallenge / libcaptcha 相关 URL -> `silentchallenge`
- P-Captcha / QuadraticResidueProblem 相关 URL -> `pcaptcha`
- pow_captcha / powcaptcha / takeTest 相关 URL -> `powcaptcha`
- PoW Bot Deterrent / `/GetChallenges?difficultyLevel=` 相关 URL -> `powbot`
- POWChallenge / powchallenge-server 相关 URL -> `powchallenge`
- pow-reaction / `/reactions/challenge` 相关 URL -> `powreaction`
- Prosopo / Procaptcha / `/v1/prosopo/provider/client/captcha/pow` 相关 URL -> `procaptcha`
- Tollbooth / libcaptcha / `/.tollbooth/verify` / `sha256-balloon` 相关 URL -> `tollbooth`
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

### 30. 代理格式

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

        privatecaptcha = await client.solve_privatecaptcha(
            puzzle_url="https://captcha.example/puzzle",
            sitekey="site-key",
        )
        print(privatecaptcha.ok, privatecaptcha.ticket, privatecaptcha.verify_code)

        portcullis = await client.solve_portcullis(
            base_url="https://captcha.example",
            sitekey="pk_test",
            submit=True,
        )
        print(portcullis.ok, portcullis.ticket, portcullis.verify_code)

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

        powcaptcha = await client.solve_powcaptcha(
            challenge_url="https://target.example/powcaptcha/challenge",
            verify_url="https://target.example/powcaptcha/verify",
            submit=True,
        )
        print(powcaptcha.ok, powcaptcha.ticket, powcaptcha.diagnostics.get("search_space"))

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

# Auro.Network
antibot solve auro --base-url 'https://auro.network'
antibot solve auro --challenge-json '{"prefix":"prefix-","difficulty":3}' --no-submit --max-attempts 10000
antibot stress auro --challenge-json '{"prefix":"prefix-","difficulty":3}' --no-submit --runs 20 --concurrency 4

# FriendlyCaptcha
antibot solve friendlycaptcha --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' --sitekey 'FCxxxxx'
antibot stress friendlycaptcha --puzzle-url 'https://api.friendlycaptcha.com/api/v1/puzzle' --sitekey 'FCxxxxx' --runs 20

# PrivateCaptcha
antibot solve privatecaptcha --puzzle-url 'https://captcha.example/puzzle' --sitekey 'site-key'
antibot solve privatecaptcha --puzzle 'puzzle_b64.signature_b64'
antibot stress privatecaptcha --puzzle-url 'https://captcha.example/puzzle' --sitekey 'site-key' --runs 20

# Portcullis
antibot solve portcullis --base-url 'https://captcha.example' --sitekey 'pk_test' --submit
antibot solve portcullis --challenge-json '{"challenge":{"id":"...","salt":"...","diff":18,"exp":9999999999999,"site_key":"pk_test"},"sig":"..."}'
antibot stress portcullis --base-url 'https://captcha.example' --sitekey 'pk_test' --runs 20

# Cap / @cap.js
antibot solve cap --api-endpoint 'https://target.example/cap/'
antibot solve cap --token 'challenge token' --c 50 --s 32 --d 4
antibot stress cap --api-endpoint 'https://target.example/cap/' --runs 50 --concurrency 5
antibot solve cap --challenge-json '{"token":"format-two-rsw-token","format":2,"challenges":[{"protocol":"rsw","payload":{"N":"5b","x":"05","t":10}}]}'

# chpio/pow-captcha
antibot solve chpiopow --challenge-json '{"magic":"2104f639-ba1b-48f3-9443-889128163f5a","challenges":[["AQI=","AwQF"]],"difficultyBits":18}' --max-attempts-per-challenge 100000
antibot solve chpiopow --challenge-url 'https://captcha.example/chpiopow/challenge' --redeem-url 'https://captcha.example/chpiopow/redeem' --submit
antibot stress chpiopow --challenge-url 'https://captcha.example/chpiopow/challenge' --runs 20 --concurrency 4

# Impost
antibot solve impost --challenge-json '{"algorithm":"argon2id","strategy":"target_number","salt":"impost-salt","target":"001f1f03c8591bd692761601e1402ae569e0151ef8d5ba3d083e803ac4f2cd5e"}' --max-attempts 5
antibot solve impost --challenge-url 'https://captcha.example/impost/challenge' --verify-url 'https://captcha.example/impost/verify' --submit
antibot stress impost --challenge-json '{"algorithm":"argon2id","strategy":"leading_zeroes","salt":"impost-salt","difficulty":2}' --runs 10 --concurrency 2 --max-attempts 20

# Kerberus
antibot solve kerberus --challenge-json '{"id":"kerb-1","salts":["salt-a","salt-b"],"difficultyFactor":50}' --serialized-input 'JRTFM' --max-attempts-per-salt 1000
antibot solve kerberus --challenge-url 'https://captcha.example/kerberus/challenge' --validate-url 'https://captcha.example/kerberus/validate' --submit
antibot stress kerberus --challenge-json '{"id":"kerb-1","salts":["salt-a","salt-b"],"difficultyFactor":50}' --serialized-input 'JRTFM' --runs 20 --concurrency 4

# PaulDotSH/pow-captcha
antibot solve paulpow --challenge-json '{"hash":"$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC","salt":"abcdefghijklmnopXYZ","captchaType":"prefix","size":30,"cost":4}' --max-attempts 10
antibot solve paulpow --challenge-url 'https://captcha.example/paulpow/challenge' --verify-url 'https://captcha.example/paulpow/verify' --submit
antibot stress paulpow --challenge-json '{"hash":"$2b$04$WUHhXETkX0fnYkrqZU3ta.8fgEd9BkOc6WYotoKsxTqtUY77MC9KC","salt":"abcdefghijklmnopXYZ","captchaType":"prefix","size":30,"cost":4}' --runs 8 --concurrency 2 --max-attempts 10

# guns.lol
antibot solve gunslol --challenge-json '{"o09":"3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a","_n":"auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2","_org_ts":"1777135187","_2xa":"oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA"}'
antibot solve gunslol --page-url 'https://guns.lol/example' --verify-url 'https://target.example/verify' --submit
antibot stress gunslol --challenge-json '{"o09":"3ffcf8567b45ac19c1d6bf9e20b1770ce1068f3dc409b87e2659d6a132dfcc0a","_n":"auR64ybDXa6A5eyEsLIqsRiNEcqEIOE2","_org_ts":"1777135187","_2xa":"oUAFJQw_BBsAAQIEA2blekXYbMz_Yzg4YTk4NzQzZDJjZmRjOGU1N2Y5MTE3ZGJjNGU4ZjZkOWU4NjU4MTBhZDBiY2Q1YTZmZDI2YTA1NDHTB1wf2McZRA"}' --runs 20 --concurrency 4

# HashGuard
antibot solve hashguard --base-url 'https://hashguard.example' --context 'login' --submit --introspect
antibot solve hashguard --challenge-json '{"challengeId":"hg-fixture-1","seed":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficultyBits":12}' --timeout 5
antibot stress hashguard --challenge-json '{"challengeId":"hg-fixture-1","seed":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","difficultyBits":12}' --runs 20 --concurrency 4

# TrustCaptcha
antibot solve trustcaptcha --site-key 'tc_site_xxx' --api-url 'https://api.trustcomponent.com' --target-url 'https://target.example/form'
antibot solve trustcaptcha --challenge-json '{"verificationId":"tc-fixture-1","difficulty":12,"tasks":[{"number":1,"input":"dHJ1c3RjYXB0Y2hhLWZpeHR1cmUtYQ=="}]}' --no-submit --timeout 5
antibot stress trustcaptcha --challenge-json '{"verificationId":"tc-fixture-1","difficulty":12,"tasks":[{"number":1,"input":"dHJ1c3RjYXB0Y2hhLWZpeHR1cmUtYQ=="}]}' --no-submit --runs 20 --concurrency 4

# @strav/captcha
antibot solve stravcaptcha --challenge-url 'https://target.example/__captcha/pow'
antibot solve stravcaptcha --challenge-json '{"token":"base64url.payload.base64url_mac","props":{"challenge":"0123456789abcdef0123456789abcdef","difficulty":12}}' --timeout 5
antibot stress stravcaptcha --challenge-url 'https://target.example/__captcha/pow' --runs 20 --concurrency 4

# mCaptcha
antibot solve mcaptcha --base-url 'https://captcha.example' --sitekey 'site-key'
antibot stress mcaptcha --base-url 'https://captcha.example' --sitekey 'site-key' --runs 20

# Wicketkeeper
antibot solve wicketkeeper --base-url 'https://captcha.example'
antibot stress wicketkeeper --base-url 'https://captcha.example' --runs 20

# yourcaptcha
antibot solve yourcaptcha --challenge-url 'https://target.example/api/captcha/challenge' --verify-url 'https://target.example/api/captcha/verify' --submit
antibot stress yourcaptcha --challenge-json '{"algorithm":"SHA-256","challenge":"...","maxnumber":50000,"salt":"...","signature":"..."}' --runs 20 --concurrency 4

# silent-challenge
antibot solve silentchallenge --base-url 'https://target.example' --submit
antibot stress silentchallenge --challenge-json '{"challengeId":"fixture-id","pow":{"prefix":"fixture-prefix-","difficulty":8,"spaceCost":8,"timeCost":1,"delta":3}}' --runs 20 --concurrency 4

# P-Captcha
antibot solve pcaptcha --challenge-url 'https://target.example/api/challenge'
antibot solve pcaptcha --challenge-url 'https://target.example/api/challenge' --validate-url 'https://target.example/api/validate' --validate
antibot stress pcaptcha --challenge-url 'https://target.example/api/challenge' --validate-url 'https://target.example/api/validate' --validate --runs 20

# crypto-puzzle RSW time-lock
antibot solve cryptopuzzle --puzzle 'AAAAAgyhAAAAAQUAAAABGQAAACARERER...' --timeout 60
antibot solve cryptopuzzle --base-url 'https://target.example/crypto-puzzle' --submit --timeout 60
antibot stress cryptopuzzle --challenge-url 'https://target.example/crypto-puzzle/challenge' --runs 10 --concurrency 2

# pow_captcha
antibot solve powcaptcha --quiz-b64 'AP8AAQAAAAPbwbTJAP/kjVdbXaXGOAQBJfZdsP4+JElLduqYZFfZhgA=' --max-attempts 10
antibot solve powcaptcha --challenge-url 'https://target.example/powcaptcha/challenge' --verify-url 'https://target.example/powcaptcha/verify' --submit
antibot stress powcaptcha --challenge-url 'https://target.example/powcaptcha/challenge' --runs 20 --concurrency 4

# POWChallenge / powchallenge-server
antibot solve powchallenge --base-url 'https://powchallenge.example' --submit --timeout 60
antibot solve powchallenge --challenge-json '{"req_id":"019aa0e6-b33f-7000-8000-000000000001","challenge":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","difficulty":2}' --max-attempts 20 --timeout 10
antibot stress powchallenge --base-url 'https://powchallenge.example' --submit --runs 10 --concurrency 2

# pow-reaction
antibot solve powreaction --base-url 'https://pow-reaction.pages.dev/demo/reactions' --reaction '👍' --submit --workers 4
antibot solve powreaction --challenge-json '{"challenge":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}' --timeout 30
antibot stress powreaction --challenge-json '{"challenge":"eyJ..."}' --runs 20 --concurrency 4

# Prosopo Procaptcha PoW
antibot solve procaptcha --challenge-json '{"challenge":"prosopo-fixture","difficulty":3,"timestamp":"1780955164000","signature":{"provider":{"challenge":"0x..."}}}' --timeout 10
antibot solve procaptcha --provider-url 'https://provider.example' --user '5F...' --dapp '5F...' --user-timestamp-signature '0x...' --submit
antibot stress procaptcha --challenge-json '{"challenge":"prosopo-fixture","difficulty":3,"timestamp":"1780955164000","signature":{"provider":{"challenge":"0x..."}}}' --runs 20 --concurrency 4

# Tollbooth / libcaptcha
antibot solve tollbooth --challenge-url 'https://target.example/protected' --submit --timeout 60
antibot solve tollbooth --challenge-json '{"id":"tb-fixture","data":"tollbooth-fixture","difficulty":8,"spaceCost":8,"timeCost":1,"delta":1}' --timeout 5
antibot stress tollbooth --challenge-url 'https://target.example/protected' --submit --runs 10 --concurrency 2

# Crovly
antibot solve crovly --api-url 'https://api.crovly.com' --site-key 'crvl_site_xxx' --submit --timeout 60
antibot solve crovly --challenge-json '{"nonce":"crovly-fixture","difficulty":12}' --timeout 5
antibot stress crovly --challenge-json '{"nonce":"crovly-fixture","difficulty":12}' --runs 20 --concurrency 4

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

Turnstile / hCaptcha / reCAPTCHA / AJ-Captcha / ALTCHA / Anubis / FriendlyCaptcha / FCaptcha / TrustCaptcha / @strav/captcha / Cap / Captxa / Swetrix / Crovly / HashGuard / yourcaptcha / silent-challenge / P-Captcha / pow_captcha / PoW Bot / pow-reaction / GeeTest / Yidun 会保留：

```text
turnstile_run.json / hcaptcha_run.json / recaptcha_run.json / geetest_run.json
turnstile_page.png / hcaptcha_page.png / recaptcha_page.png / geetest_page.png
turnstile_page.html / hcaptcha_page.html / recaptcha_page.html / geetest_page.html
ajcaptcha_run.json / ajcaptcha_original.png / ajcaptcha_jigsaw.png
altcha_run.json
anubis_run.json
friendlycaptcha_run.json
fcaptcha_run.json
cap_run.json
cryptopuzzle_run.json
captxa_run.json
swetrix_run.json
yourcaptcha_run.json
silentchallenge_run.json
pcaptcha_run.json
powcaptcha_run.json
powbot_run.json
powchallenge_run.json
powreaction_run.json
procaptcha_run.json
tollbooth_run.json
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
    auro.py                 # Auro AES-GCM mouse telemetry + SHA-256 PoW protocol solver
    friendlycaptcha.py      # FriendlyCaptcha classic PoW protocol solver
    fcaptcha.py             # FCaptcha behavior/environment signalsHash-bound PoW solver
    privatecaptcha.py       # PrivateCaptcha blake2b compute PoW protocol solver
    portcullis.py           # Portcullis Argon2id + SHA-256 PoW protocol solver
    cap.py                  # Cap/@cap.js SHA-256 PoW protocol solver
    cryptopuzzle.py         # crypto-puzzle RSW time-lock archive solver
    captxa.py               # Captxa browser metrics + JA4-bound SHA-256 PoW solver
    swetrix.py              # Swetrix challenge:nonce SHA-256 PoW protocol solver
    crovly.py               # Crovly fingerprint/behavior-bound SHA-256 bit PoW solver
    chpiopow.py             # chpio/pow-captcha signed target-match PoW protocol solver
    hashguard.py            # HashGuard target-threshold SHA-256 PoW + JWT proof-token solver
    trustcaptcha.py         # TrustCaptcha fingerprint/integrity + multi-task SHA-256 PoW solver
    stravcaptcha.py         # @strav/captcha stateless HMAC token + hashcash PoW solver
    mcaptcha.py             # mCaptcha SHA-256 PoW protocol solver
    wicketkeeper.py         # Wicketkeeper JWT PoW protocol solver
    yourcaptcha.py          # yourcaptcha behavioral signals + SHA-256 exact PoW protocol solver
    silentchallenge.py      # silent-challenge motion/navigator attestation + balloon PoW solver
    pcaptcha.py             # P-Captcha quadratic residue protocol solver
    powcaptcha.py           # pow_captcha buffer reconstruction PoW protocol solver
    powbot.py               # PoW Bot Deterrent scrypt-WASM PoW protocol solver
    powchallenge.py         # POWChallenge Argon2id memory-hard PoW protocol solver
    powreaction.py          # pow-reaction HS256 JWT multi-round SHA-256 PoW solver
    procaptcha.py           # Prosopo Procaptcha SHA-256 hex-prefix PoW solver
    tollbooth.py            # Tollbooth SHA256-Balloon + navigator-attestation protocol solver
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
  test_fcaptcha.py
  test_privatecaptcha.py
  test_portcullis.py
  test_cap.py
  test_cryptopuzzle.py
  test_captxa.py
  test_swetrix.py
  test_crovly.py
  test_pcaptcha.py
  test_powcaptcha.py
  test_powbot.py
  test_powchallenge.py
  test_powreaction.py
  test_procaptcha.py
  test_tollbooth.py
  test_hashguard.py
  test_yourcaptcha.py
  test_silentchallenge.py
  test_yidun_slide.py
```

---

## 当前验证记录

最近一轮关键验证：

```text
pytest: 133 passed
Swetrix fixture/mock/live/stress: /generate + SHA256(challenge:nonce) PoW + /verify + /validate 验证通过
Crovly fixture/mock/stress: /challenge + fingerprint/environment/behavior + SHA256(nonce+counter) bit-PoW + /verify 验证通过
HashGuard fixture/mock/stress: /pow/challenges + SHA256(challengeId:seed:nonce)<=target + /pow/verifications + /pow/assertions/introspect 验证通过
TrustCaptcha fixture/mock/stress: /v2/verifications + fingerprint/integrityHash + 多任务 SHA256(input||tcnN) PoW + /challenges 验证通过
@strav/captcha fixture/mock/stress: /__captcha/pow + HMAC token payload + SHA256(salt:nonce) PoW + middleware submit body 验证通过
Captxa fixture/mock/stress: browser metrics + JA4-bound opaque token + SHA-256 PoW simple mode 验证通过
FCaptcha fixture/mock/stress: signalsHash-bound PoW、本地 /api/pow/challenge + /api/verify 验证通过
PoW Bot Deterrent fixture/mock/stress: scrypt-WASM PoW、本地 /GetChallenges + /Verify 验证通过
pow-reaction fixture/mock/live/stress: HS256 JWT + 多轮 SHA256(round.nonce) PoW + reactions submit 验证通过
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
ALTCHA v2 官方 KDF 向量：PBKDF2/SHA-256、SHA-256、SCRYPT、ARGON2ID 全部对齐。
ALTCHA v2 verify-compatible fast path：无 keySignature 分支 counter=0 单次派生可生成官方 verifier 兼容 payload；strict prefix 模式可命中 counter=123 fixture。
```

Anubis：

```text
官方 Go fixture：SHA256("hunter"+"0") = 2652bd...0500e，difficulty=0 命中。
HTML JSONScript 解析：anubis_challenge/anubis_base_prefix 回归通过。
本地 make-challenge + pass-challenge：ok=true，成功返回 auth cookie。
本地 Anubis stress 30 轮/concurrency=5：30/30，avg≈41.3ms，p95≈227ms。
```

Auro.Network：

```text
ptraced_Auro.Network/solver.py：确认 /enckey、AES-GCM mouse+iv、/api/pow/setup、SHA256(prefix+nonce)、/api/pow/validate 链路。
AES-GCM fixture：32-byte key + 12-byte IV，Python 加密输出可 decrypt_and_verify 回原始紧凑 mouse JSON。
PoW fixture：prefix=prefix-,difficulty=3 -> nonce=822，hash=000db5e4c4065ac7540a4c5ccc65613467f0fe1601501c21308322d8a737a449。
本地 mock /enckey + /api/pow/setup + /api/pow/validate：ok=true，成功返回 auro-token。
本地 Auro fixture stress 20 轮/concurrency=4：20/20，avg≈13.8ms，p95≈24ms。
live DNS evidence gap：当前 VPS 对 auro.network 解析失败，未写入为“官方 live 通过”。
```

FriendlyCaptcha：

```text
friendly-pow 官方 easy fixture：成功命中 nonce bytes 00 00 00 00 9a 00 00 00。
本地 puzzle endpoint：ok=true，成功输出 frc-captcha-solution payload。
诊断字段按官方 DataView 默认 big-endian 生成。
```

PrivateCaptcha：

```text
upstream widget/js/puzzle.utils.js + pkg/puzzle/solver.go：确认 blake2b-256、u32LE prefix、thresholdFromDifficulty、8-byte solution 格式。
fixture difficulty=64,solutionsCount=2：Python 输出 solutions 000000000000000c / 0100000000000089。
Python 产出 payload 被 upstream Go ParseVerifyPayload + VerifySolutions 接受：code=no-error。
本地 mock /puzzle + /verify：ok=true，成功返回 pc-token。
本地 PrivateCaptcha fixture stress 20 轮/concurrency=4：20/20，avg≈1.2ms，p95≈3ms。
```

Portcullis：

```text
upstream captcha-core/src/pow.rs + challenge.rs：确认 Argon2id(id,salt,m/t/p,out=32) + SHA256(base||nonce_le_8) + leading_zero_bits 规则。
Rust/Python cross-check fixture：base_hash=9ad549858f257bbed625072cd542f88746b3a3a2f711fb97454ac955c02e41dd。
fixture diff=12,m_cost=8,t_cost=1：nonce=1756，hash=0007dc26538be91230b0bcde0acc3a824b064dc19b1d17ec5d259255c19dc820。
本地 mock challenge + verify + siteverify：ok=true，成功返回 captcha_token。
本地 Portcullis fixture stress 20 轮/concurrency=4：20/20，avg≈8.8ms，p95≈13ms。
```

Cap / @cap.js：

```text
Cap PRNG/FNV 与 upstream core/src/prng.js 交叉校验。
官方 core generateChallenge/validateChallenge v1：Python solve body 被 validateChallenge 接受。
官方 core format-2 sha256-pow：Python solutions=[{nonce:...}] 被 validateChallenge 接受。
官方 core/src/rsw.js 与 docs/guide/rsw.md：确认 RSW client solve = repeated modular squaring，widget submit `{y}`。
本地 v1 seeded challenge + /redeem：ok=true，成功返回 Cap token。
本地 format-2 sha256-pow + /redeem：ok=true，成功返回 Cap token。
本地 format-2 rsw + sha256-pow + /redeem：ok=true，成功返回 Cap token，fixture `{N=0x5b,x=0x05,t=10}` -> `y=4f`。
本地 Cap RSW fixture stress 20 轮/concurrency=4：20/20。
unsupported 协议回归：format-2 instrumentation 明确返回 unsupported_protocols。
```

chpio/pow-captcha：

```text
upstream pkgs/pow-captcha/src/solver/solver.ts + solver-wasm/src/lib.rs：确认 SHA256(solution_le_8||nonce) 与 target difficultyBits 匹配规则。
upstream wire.ts：确认 signedData hash = SHA256(UTF16LE(data_json + ":" + secret))。
solver.spec.ts fixture：nonce=[1,2], target=[3,4,5], difficultyBits=18 -> solution=LbAAAAAAAAA= / int=45101。
本地 mock signed challenge + redeem signedData：ok=true，成功验证 redeemed magic。
本地 chpiopow fixture stress 20 轮/concurrency=4：20/20，avg≈543.9ms，p95≈741ms。
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

yourcaptcha：

```text
upstream src/server/challenge.ts / verify.ts / signals.ts：确认 HMAC(challenge)、SHA256(salt+number)、风险分 maxnumber、提交时间和 score drift 规则。
低风险 synthetic signals：score=0.0，maxnumber=50000。
本地 exact PoW fixture：number=17，attempts=18，hash 命中 challenge。
本地 mock /challenge + /verify：ok=true，成功返回 yourcaptcha-token。
本地 challenge-json stress 20 轮/concurrency=4：20/20。
```

silent-challenge：

```text
upstream src/crypto.js：确认 balloon hash counter、u32LE counter、u32BE digest index、spaceCost/timeCost/delta 混合顺序。
fixture input=fixture-prefix-269,space=8,time=1,delta=3 -> hash=008d7af48e4b4a31436732d1d9b78cfabbbc4ab8dc7c3a22d9e50d554cf2358a，leadingZeroBits=8。
upstream createChallengeManager debug：synthetic motion score=0.72，navigator score=0.90，vmResponse 缺失时 combined=0.591，cleared=true，返回 signed token。
本地 mock /challenge + /challenge/:id/verify：ok=true，成功返回 silent-token。
本地 challenge-json stress 20 轮/concurrency=4：20/20。
```

P-Captcha：

```text
官方 @p-captcha/node generateChallenge + validateAnswer：Python answer 被 validateAnswer 接受。
本地 QuadraticResidueProblem 解析/求模平方根/answer base64 编码回归通过。
本地 P-Captcha challenge + validate stress 20 轮/concurrency=4：20/20，avg≈57.2ms，p95≈84ms。
```

pow_captcha：

```text
upstream pow.js + C/takeTest.c：确认 SERIAL 格式、uncertainty mixed-radix increment、SHA256(buffer) 命中规则。
WASM/takeTest fixture：quiz=AP8AAQAAAAPbwbTJAP/kjVdbXaXGOAQBJfZdsP4+JElLduqYZFfZhgA=，answer=02，attempts=2。
makeTest(16,"abcd",32,127) sample：Python 解出 answer=abcd，search_space=16。
本地 mock challenge + verify：ok=true，成功返回 pow-token。
本地 pow_captcha fixture stress 20 轮/concurrency=4：20/20，avg≈0.5ms，p95≈1ms。
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
- Auro.Network 多一层 AES-GCM 行为 telemetry；如果只给 `prefix/difficulty` 就是纯 PoW，如果走完整 `/enckey -> setup -> validate`，要保证 `x-client` 全程一致。
- FriendlyCaptcha classic 也是 PoW；耗时主要由 difficulty、solution count、命中位置和 worker 数决定。默认 `10,000,000` 次/段 solution 上限，真实站点不够时调 `--max-attempts-per-solution`。
- PrivateCaptcha compute puzzle 的 difficulty 每 +8 平均搜索空间约乘 2，solutionsCount 常是多解；先控制 `--concurrency`，再按 CPU 调 `--workers`。
- Portcullis 多了 Argon2id 内存成本，`m_cost` 默认可到 19456 KiB；压测时先用低 concurrency，避免 VPS 内存抖动。
- Cap PoW 耗时主要由 `c/s/d`、format-2 target 长度、命中位置和 worker 数决定；RSW 耗时由 `t` 和模数位数决定，是顺序型 time-lock，不能像 SHA-256 那样简单靠 worker 横向切开；遇到 `instrumentation` 时当前版本按 unsupported 返回。
- chpio/pow-captcha 是 target-match PoW；difficultyBits 每 +1 平均搜索空间约乘 2，challengeCount 越多 CPU 越重，VPS 上优先降 `--concurrency`。
- mCaptcha PoW 耗时主要由 `difficulty_factor`、nonce 命中位置和 worker 数决定；默认单 worker，压测时先控制并发避免把 VPS CPU 打满。
- Wicketkeeper difficulty 是前导 0 nibble 个数，每 +1 平均搜索空间约乘 16；success JWT 只能由服务端 `/siteverify` 签发。
- yourcaptcha 的主要优化点是 signals 风险分和 exact PoW 搜索空间；低风险 `maxnumber=50000` 很轻，高风险会升到 `10_000_000`，VPS 上压测先控制 `--concurrency`。
- silent-challenge 的耗时主要来自 balloon PoW：`spaceCost=512,difficulty=10` 平均会比普通 SHA-256 慢很多；默认 VM response 不生成，若目标强制 VM 阈值则需要后续升级 VM bundle 解密/签名链路。
- P-Captcha 当前不是暴力搜索，而是模平方根；耗时主要由 Woodall prime bit 数和 rounds 决定，`2xs` 约 761 bits，`3xl` 约 22974 bits。
- pow_captcha 是 buffer reconstruction PoW；耗时取决于 uncertainty 个数、各自 base 的乘积 search_space、命中位置和 worker 数。VPS 上优先降并发，再考虑多 worker。
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
