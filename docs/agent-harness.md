# Captcha Solver Agent Harness

## 目标

Harness 不让模型自由声称“已通过”，也不把每个厂商写成互不相干的一次性脚本。系统分成三层：

1. **确定性运行时**：控制状态、超时、动作预算、工具权限、证据和回放。
2. **Agent planner**：根据观察选择已注册工具和策略，不直接生成成功结果。
3. **Provider tools**：执行浏览器、协议解析、视觉识别、点击/拖拽，并捕获真实厂商响应。

当前 episode 状态固定为：

```text
created -> observing -> planning -> acting -> verifying -> completed|failed
```

`CaptchaHarness` 只向 planner 暴露目标 host/path、provider hint、工具列表和剩余预算。代理配置、
API key、cookie、ticket 和 token 不进入 planner 上下文或 Harness 事件。

需要直接接入通用 session 时使用 `CaptchaHarness.solve_session(session, vision_backend)`；该模式不
注册或调用旧的 `provider.solve` 黑盒工具，适合新厂商 adapter 先接入统一循环，再逐步补充厂商
验证策略。

## 框架选型

| 框架 | 结论 | 原因 |
| --- | --- | --- |
| [Pydantic AI](https://ai.pydantic.dev/) | 采用为可选 planner 层 | Python 原生、类型化输出/依赖注入、OpenAI-compatible Chat Completions、自带 Evals 与 OTel |
| [Pydantic AI Harness](https://pydantic.dev/docs/ai/harness/) | 按需借鉴 capability 模式 | 完整 Harness 偏代码/研究 Agent；本项目需要低延迟、严格动作预算和厂商证据门槛 |
| [LangGraph](https://docs.langchain.com/oss/python/langgraph/overview) | 暂不作为核心依赖 | durable graph 很强；当前单次 challenge 是短 episode，加入完整图运行时收益不抵依赖和复杂度 |
| [Deep Agents](https://docs.langchain.com/oss/python/deepagents/overview) | 不直接采用 | 文件系统、Shell、subagent 和长上下文是主要卖点，不是 canvas/network challenge 的关键路径 |
| [Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/overview/) | 观察 | Agent/Harness/Workflow 能力完整，但处于快速演进期，迁移成本和 API 稳定性仍需验证 |
| [Google ADK 2.0](https://google.github.io/adk-docs/) | 暂不采用 | graph、session、部署完整，但多语言/Google Cloud 能力对当前 Python SDK 偏重 |
| [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) | 不作为核心依赖 | Agent loop 简洁，但本项目要继续支持通用 Chat Completions 网关和自有视觉协议 |

最终选择是：**自有确定性 Harness + 可插拔 planner**。默认 `HeuristicPlanner` 不增加运行依赖；
安装 `agent` extra 后可使用 `PydanticAIPlanner`。未来如果出现跨机器恢复、人工审批和长任务队列，
再把 episode checkpoint 接到 LangGraph 或 Temporal，而不是重写 provider tools。

## 统一题目契约

Provider 的 DOM、HSW、MessagePack 和网络字段仍然是 adapter 的私有实现；Harness 只消费厂商无关
的中间表示：

- `ChallengeObservation`：当前渲染图、题型、候选索引、坐标尺寸、答案数量限制、DOM
  `affordances`、允许动作和 observation id。
- `ChallengeAffordance`：当前 scene 中一个可交互目标的稳定 id、role、label、bounds、enabled
  状态和动作能力。id 只在当前 observation 内有效，动态 DOM 替换后不能复用。
- `ChallengeAction`：`select`、`point`、`box`、`choice`、`drag`、`click`、`type`、`press`、
  `wait`、`submit`、`reload` 等动作。
- `VendorVerification`：厂商 token、vendor pass、站点验证和 verifier event 的证据摘要。
- `ChallengeExecutor`：在浏览器输入前验证 observation 作用域、题型-动作兼容性、索引、坐标、
  几何和答案数量，并把 valid/invalid action 写入 trace；浏览器动作完成后才会标记 `executed=true`。
- `ChallengeAgentLoop`：只依赖 adapter session 的 `observe`、`vision_task`、`execute`、`verify`，
  按 `observe -> decide -> validate -> execute -> re-observe -> verify` 运行；`ChallengeStrategyRegistry`
  允许新增题型而不改循环核心。

动态换图会生成新的 observation id；旧 observation 的索引、坐标和 affordance id 不能复用。
`BrowserChallengeSession` 是通用 Playwright 扩展入口：它只读取标准 DOM 控件和 surface
截图，不内置厂商 selector，并将动作执行异常留在 `executed=false`。未知题型若没有 adapter
声明的 affordances 会安全失败；即使有 affordances，也必须接入真实 `VendorVerification`，
planner 不能伪造 token 或成功结果。

## 工具边界

旧 provider-runner 模式当前注册的工具：

| Tool | 输入 | 输出 | 权限 |
| --- | --- | --- | --- |
| `provider.solve` | provider + 原始用户 options | `CaptchaResult` / `BrowserResult` | 可启动一个 provider 浏览器流 |

通用 session 模式不把 adapter 包装成黑盒工具，而是直接调用 `ChallengeAgentLoop`；因此新题型的
动作、重观察和验证都能被 Harness trace 看到。

Provider adapter 现在通过统一 trace 接口接入观察/执行分离；新厂商只需实现 session 的协议/DOM
翻译和题图转换，后续可以在不修改 Harness 核心的情况下注册更多厂商和策略：

```text
browser.observe
network.observe_vendor_challenge
vision.solve
vision.compare
browser.click_points
browser.drag_path
vendor.verify
replay.search
```

当前完整的 session adapter 包括通用 `BrowserChallengeSession`、`RecaptchaChallengeSession`、
`ArkoseChallengeSession`、`TurnstileChallengeSession` 和 `TokenChallengeSession`。`BrowserChallengeSession` 负责通用 DOM/image 交互；
`RecaptchaChallengeSession` 把 Google 的 bframe、网格
稳定性等待、动态 tile replacement、reload/submit 和 token 收集封装在 provider 边界内；
`ChallengeAgentLoop` 不读取 Google DOM，也不把一次点击当作成功。hCaptcha 的 HSW/MessagePack
仍保留在现有 provider adapter 中，后续按同一 session 边界迁移。

`ArkoseChallengeSession` 将当前 FunCaptcha Canvas/DOM 游戏面映射为 `select`、`point`、
`choice` 或 `drag`，并用截图哈希约束 action 生命周期。它把 gt2 初始化 token 与挑战后新增的
callback/field token 分开；成功必须同时捕获最终 token 和 `/fc/ca/` 的明确 pass 语义。

对于不暴露图像题的行为/协议流，`TokenChallengeSession` 接受真实 token reader 和可选的页面
submitter，适用于 Turnstile、reCAPTCHA v3 等被动挑战。它只记录 token 长度和 verifier event，
不记录 token 内容；没有 token 或厂商 pass 证据时，验证一定失败。

`TurnstileChallengeSession` 是 Cloudflare 的显式 adapter。它把 provider-specific response
selectors 保留在 `providers/turnstile.py`，并在通用 token loop 之后增加证据门：没有真实 Turnstile
token，或没有 verifier 网络事件、vendor pass、站点验证中的任一证据，`VendorVerification.accepted`
都为 `False`。Cloudflare 官方 testing-key 的 `XXXX.DUMMY.TOKEN.XXXX` 也会被明确拒绝。
因此 widget 消失、checkbox 点击和本地伪造 token 都不会通过。

`TencentChallengeSession` 保留腾讯的 iframe/template、缺口检测、动态几何映射和轨迹执行在
`providers/tencent_session.py`，向 Harness 暴露标准 `slider -> drag` 与 `word_click -> point`
动作。成功必须由 `cap_union_new_verify` 返回 `errorCode=0` 和 ticket 证明；拒绝码、缺失响应和
低置信度缺口都会进入结构化 gap，而不是被当作 UI 成功。

Planner 不能传入任意 URL、任意脚本或伪造的 provider result。工具参数必须通过类型校验，动作后必须
重新观察。坐标只属于当前 observation，不能作为跨 episode memory。

## 证据策略

Harness 保留 provider result 的所有诊断，并额外写入 `diagnostics.harness`。hCaptcha 成功至少要求：

- provider result 自身为 `ok=true`；
- `hcaptcha_verification_responses` 中存在真实 `pass=true`；
- 捕获厂商 token。

reCAPTCHA 成功至少要求 provider 自身为 `ok=true` 且捕获 Google 生成的响应 token；仅点击
checkbox、提交视觉答案或看到 challenge 消失都不构成成功。配置了页面 Submit 验证时，
`site_verification.ok=true` 还必须成立。

Arkose 成功至少要求 provider 自身为 `ok=true`、最终 callback/field token 非空且
`arkose_verification_responses` 中存在 `/fc/ca/ pass=true`。`/fc/gt2/public_key/` HTTP 200、
初始化 token、Canvas 消失或模型 action 都不单独构成成功。

如果底层错误返回 `ok=true` 但缺少对应厂商证据，Harness 会降级为失败。在线运行只保存 token
长度、Google `/userverify` 等 verifier event 和站点断言结果，不保存或展示 token 内容。

## 回放与评估

```bash
antibot replay-eval /tmp/antibot-runs
```

评估器汇总：challenge type、prompt family、视觉模型、finish reason、token 长度、耗时、canvas
对齐、厂商 pass/fail、vendor verifier event、observation/action 数量、affordance/action
种类、planner backend、动态 scene replacement 和 action 校验失败。reCAPTCHA
还统计动态/静态轮次、图片替换、action label、`/userverify` 和尝试次数。一个 run 如果经历多个
challenge，最终 pass 只记为 `multi_challenge_ambiguous`，不会分摊成每个题型都成功。

Replay 不信任 provider 写入的 `valid`/`executed` 标志：它会从 JSON 重建 observation/action，
重新执行题型、索引、坐标和数量校验，并检查重复 observation id、缺失关联和 validity 不一致。
任何 trace integrity error 都会阻断 generalized。

平台级成功率使用独立的 `BenchmarkPolicy`，不会把 `result.ok` 单独当成成功：默认至少需要 20 个
不重复 source、3 个 prompt family、20 个 challenge instance、每次 `VendorVerification` 被接受、
完整 action trace，且 observed success rate >= 0.95。重复 source 只算一次；输出为
`qualified`、`failed` 或 `insufficient_samples`。因此一次在线通过、同一个结果文件反复回放、
或只有页面消失而没有 token/vendor evidence，都不能推动平台切换。

覆盖状态是保守的：

- `live_sample`：只有样本运行，或没有厂商证据。
- `live_verified_limited_matrix`：至少有厂商证据，但题族、实例或独立运行数不足，或者有失败/不确定动作。
- `generalized`：默认至少 3 个独立 run、2 个 prompt family、3 个 challenge instance、3 个厂商证据，
  所有 run 成功，统一 observation/action trace 完整，且没有 invalid、unexecuted 或 uncertain action。
  阈值由 `CoveragePolicy` 控制。

因此单次真实 E2E 只能证明一条 `live_sample` 或有限矩阵路径，不能被 CLI、README 或 agent 自动宣称为通用成功。

## 资源原则

2C2G 环境默认单浏览器、单 episode。视觉任务可以在 challenge 内受控并发，但 planner 不自动派生
subagent。模型路由优先满足 challenge 有效期：先选低延迟视觉模型，只有结构化输出不完整或置信度
不足才升级模型；完成后必须关闭 browser/context/session。
