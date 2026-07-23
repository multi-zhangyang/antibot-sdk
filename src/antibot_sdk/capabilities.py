from __future__ import annotations

from copy import deepcopy
from typing import Any

CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "provider": "cloudflare",
        "name": "Cloudflare browser human-verification flow",
        "category": "browser_flow",
        "captcha_type": "managed_challenge",
        "status": "active",
        "output": "BrowserResult / state / cookies / cf_clearance / optional turnstile_token / artifacts",
        "scope": (
            "Cloudflare/Turnstile 页面级人机验证浏览器流：Pydoll/CDP 启动 Chrome，补 UA/CH/指纹，"
            "按 mode=auto|turnstile|managed|scrape 处理挑战，等待页面稳定后返回 state 与会话 cookie。"
            "成功时常可拿到 cf_clearance/__cf_bm 等 cookie，以及页面内嵌 Turnstile response（若存在）。"
            "TurnstileChallengeSession 只在真实 token 加 verifier 网络事件、vendor pass 或站点验证"
            "证据成立时接受；不是只给 sitekey 就返回 token 的纯协议 solver。"
        ),
        "modes": {
            "auto": "默认：打开页面，发现 challenge 再启用 auto-solve + manual probe",
            "turnstile": "强制走 Turnstile/checkbox 自动求解路径",
            "managed": "强制 managed challenge 路径；有 DISPLAY 时倾向 headed",
            "scrape": "不主动求解，只打开页面并报告状态/cookie",
        },
    },
    "recaptcha": {
        "provider": "recaptcha",
        "name": "Google reCAPTCHA page widget flow",
        "category": "browser_flow",
        "captcha_type": "recaptcha_v2_or_v3",
        "status": "active_limited_matrix",
        "output": "widget token in CaptchaResult.ticket / diagnostics / optional artifacts",
        "scope": (
            "页面级 reCAPTCHA v2/v3 浏览器流：打开实际业务页，捕获 callback 或隐藏响应字段，"
            "并通过 RecaptchaChallengeSession + ChallengeAgentLoop 使用开放词汇视觉后端处理 v2 的 "
            "3x3 动态换图和 4x4 静态网格。有限在线矩阵已经观察到 Google /userverify、"
            "捕获厂商 token 并完成站点提交。"
            "当前仅是有限题型矩阵；没有 token 时明确失败，不能把 checkbox 或模型答案当成通过。"
        ),
        "variants": {
            "v2/dynamic_3x3/cars": "live_verified_limited_matrix",
            "v2/dynamic_3x3/bus": "live_verified_limited_matrix",
            "v2/dynamic_3x3/bicycles": "live_verified_limited_matrix",
            "v2/static_4x4/stairs_traffic_lights_motorcycles_buses": (
                "live_attempted_multi_challenge_ambiguous"
            ),
            "v2/uncertain_answer_reload": "implemented_live_path_pending_observation",
            "v2/audio": "unsupported",
            "v3/token_capture": "passive_only",
            "unknown_or_new_tasks": "explicit_failure",
        },
    },
    "hcaptcha": {
        "provider": "hcaptcha",
        "name": "hCaptcha page widget flow",
        "category": "browser_flow",
        "captcha_type": "hcaptcha",
        "status": "active",
        "output": "widget token in CaptchaResult.ticket / diagnostics / optional artifacts",
        "scope": (
            "页面级 hCaptcha 浏览器 solver：兼容当前 HSW + MessagePack challenge 响应。支持通过"
            "标准 OpenAI-compatible 多模态后端处理 binary、point、bounding-box、multiple-choice"
            "和 drag-drop，并保留本地 ONNX 作为未配置视觉后端时的 fallback。有限在线矩阵已"
            "观察到 tree-climbing 与计数 point challenge 的 checkcaptcha pass=true；样本量"
            "仍不足以宣称通用成功率。drag-drop 已在线执行但该次厂商拒绝，未知题型结构化失败。"
        ),
        "variants": {
            "image_label_area_select/tree_climbing_animals": "live_verified",
            "open_vocabulary/binary": "implemented_pending_live_matrix",
            "open_vocabulary/point": "live_verified_limited_matrix",
            "open_vocabulary/bounding_box": "implemented_pending_live_matrix",
            "open_vocabulary/multiple_choice": "implemented_pending_live_matrix",
            "open_vocabulary/drag_drop": "live_attempted_vendor_rejected",
            "legacy_onnx_labeled_tasks": "fallback",
            "unknown_or_new_tasks": "explicit_failure",
        },
    },
    "arkose": {
        "provider": "arkose",
        "name": "Arkose Labs FunCaptcha page widget flow",
        "category": "browser_flow",
        "captcha_type": "funcaptcha",
        "status": "live_verified_limited_matrix",
        "output": "final callback/field token in CaptchaResult.ticket plus redacted /fc/ca/ evidence",
        "scope": (
            "页面级 Arkose Labs FunCaptcha 浏览器流：在真实页面中捕获 Canvas/DOM 游戏面，"
            "将图片选择、坐标点击、旋转按钮和拖拽映射到统一 Harness observation/action，"
            "使用流式 OpenAI-compatible 视觉后端处理。仅当最终 callback/field token 与"
            "Arkose /fc/ca/ pass=true 同时存在时接受；gt2 初始化握手、HTTP 200 或 UI 消失"
            "都不算成功。轨道轮播题已有一次完整的在线 pass=true + 最终 token 证据，但同一"
            "运行的前一组三题被厂商拒绝，因此仅属于有限题型样本，不代表通用成功率。"
        ),
        "variants": {
            "orbit_carousel": "live_verified_limited_matrix",
            "image_selection": "implemented_pending_live_matrix",
            "point_game": "implemented_pending_live_matrix",
            "rotation_controls": "implemented_pending_live_matrix",
            "drag_drop": "implemented_pending_live_matrix",
            "unknown_or_new_tasks": "explicit_failure",
        },
    },
    "tencent": {
        "provider": "tencent",
        "name": "Tencent Captcha",
        "category": "solver",
        "captcha_type": "slider",
        "status": "active",
        "output": "ticket / randstr",
        "scope": (
            "腾讯滑块验证码：Playwright 运行时、缺口识别、轨迹生成、verify 响应捕获；"
            "TencentChallengeSession 将 slider/文字点选转换为统一 observation/action，"
            "只有 cap_union_new_verify 返回 errorCode=0 且存在 ticket 才接受。"
        ),
        "variants": {
            "slider": "implemented_pending_independent_live_matrix",
            "word_click": "implemented_pending_independent_live_matrix",
            "unknown_or_new_tasks": "explicit_failure",
        },
    },
    "aliyun": {
        "provider": "aliyun",
        "name": "Aliyun Captcha V3",
        "category": "solver",
        "captcha_type": "slider",
        "status": "active",
        "output": "VerifyResult / VerifyCode / artifacts",
        "scope": "阿里云滑块验证码：Node/Puppeteer runner、DOM hook、缺口定位、轨迹与失败策略。",
    },
    "geetest": {
        "provider": "geetest",
        "name": "GeeTest v4",
        "category": "solver",
        "captcha_type": "geetest_v4",
        "status": "active",
        "output": "pass_token / lot_number / captcha_output / flow events",
        "scope": "GeeTest v4：Playwright 驱动真实页面，hook initGeetest4，捕获 gcaptcha4 load/verify；支持 ai 直通、slide 滑块 CV、winlinze/Gobang 棋盘规则解、match/IconCrush 三消规则解。",
        "variants": {
            "ai": "active",
            "slide": "active",
            "winlinze": "active",
            "match": "active",
            "icon": "observe",
        },
    },
}


def list_capabilities() -> dict[str, Any]:
    from .harness.adapters import default_adapter_registry

    adapters = default_adapter_registry()
    items = [deepcopy(item) for item in CAPABILITY_MATRIX.values()]
    solvers = [item for item in items if item.get("category") == "solver"]
    browser_flows = [item for item in items if item.get("category") == "browser_flow"]
    return {
        "solvers": solvers,
        "browser_flows": browser_flows,
        "flow_observers": browser_flows,
        "harness": {
            "status": "active",
            "entrypoints": [
                "AntibotClient.solve_agent",
                "CaptchaHarness.solve_session",
                "antibot harness",
                "POST /v1/harness/solve",
            ],
            "runtime": "typed deterministic state machine with optional Pydantic AI planner",
            "contract": {
                "schema_version": 1,
                "observation": "ChallengeObservation",
                "action": "ChallengeAction",
                "verification": "VendorVerification",
                "executor": "ChallengeExecutor",
                "agent_loop": "ChallengeAgentLoop",
                "strategy_registry": "ChallengeStrategyRegistry",
                "session_adapters": (
                    "BrowserChallengeSession for generic Playwright DOM/image scenes; "
                    "RecaptchaChallengeSession for image grids; "
                    "ArkoseChallengeSession for evidence-gated Canvas/DOM games; "
                    "TurnstileChallengeSession for evidence-gated Cloudflare tokens; "
                    "TencentChallengeSession for evidence-gated Tencent slider/point scenes; "
                    "TokenChallengeSession for passive protocol tokens"
                ),
                "interactive_actions": (
                    "click, type, press, wait, point, drag, submit, reload, noop, fail"
                ),
                "unknown_scene_policy": (
                    "unknown scenes require adapter-declared affordances and a real verifier; "
                    "otherwise the loop fails explicitly"
                ),
                "action_validation": (
                    "observation-scoped affordance ids, indexes, coordinates, choices, geometry, "
                    "kind compatibility, enabled controls, and answer-count limits"
                ),
                "action_lifecycle": "proposed -> valid|invalid -> executed",
                "evidence_gate": (
                    "no verifier, token, vendor pass, or site evidence means accepted=false; "
                    "UI disappearance alone is never success"
                ),
                "replay_metrics": (
                    "normalized kinds, affordances, action kinds, planner backends, "
                    "dynamic scene replacements, invalid/unexecuted/uncertain actions"
                ),
                "benchmark_gate": (
                    "BenchmarkPolicy requires 20 independent source runs by default, 3 prompt families, "
                    "20 challenge instances, real vendor evidence, clean traces, and observed success "
                    "rate >= 0.95 before a provider is qualified"
                ),
            },
            "adapters": list(adapters.describe()),
            "tools": [
                "provider.solve",
                "vision.solve",
                "challenge.observe",
                "challenge.execute",
                "challenge.agent_loop",
                "vendor.verify",
                "replay-eval (offline)",
            ],
            "coverage_statuses": [
                "live_sample",
                "live_verified_limited_matrix",
                "generalized",
            ],
            "evidence_policy": (
                "provider results remain authoritative; hCaptcha additionally requires "
                "checkcaptcha pass=true and a captured vendor token; reCAPTCHA requires "
                "a captured Google-generated token; Cloudflare requires captured session "
                "evidence (clearance, non-testing token, or site verification); Tencent and "
                "GeeTest require their vendor ticket/pass_token; Arkose requires both a final "
                "token and an explicit /fc/ca/ vendor pass"
            ),
        },
        "unsupported": [],
    }
