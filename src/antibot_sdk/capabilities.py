from __future__ import annotations

from typing import Any

CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "provider": "cloudflare",
        "name": "Cloudflare browser human-verification flow",
        "category": "browser_flow",
        "captcha_type": "managed_challenge",
        "status": "active",
        "output": "BrowserResult / final page state / artifacts",
        "scope": "Cloudflare/Turnstile 页面级人机验证浏览器流：Pydoll/CDP 启动 Chrome，补 UA/CH/指纹，等待 challenge 稳定，提取页面状态；不是纯协议 token solver。",
    },
    "tencent": {
        "provider": "tencent",
        "name": "Tencent Captcha",
        "category": "solver",
        "captcha_type": "slider",
        "status": "active",
        "output": "ticket / randstr",
        "scope": "腾讯滑块验证码：Playwright 运行时、缺口识别、轨迹生成、verify 响应捕获。",
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
        "scope": "GeeTest v4：Playwright 驱动真实页面，hook initGeetest4，捕获 gcaptcha4 load/verify，滑块模式抓取 bg/slice 并用 CV 缺口匹配生成拖拽轨迹。",
    },
}


def list_capabilities() -> dict[str, list[dict[str, Any]]]:
    items = [dict(item) for item in CAPABILITY_MATRIX.values()]
    solvers = [item for item in items if item.get("category") == "solver"]
    browser_flows = [item for item in items if item.get("category") == "browser_flow"]
    return {"solvers": solvers, "browser_flows": browser_flows, "flow_observers": browser_flows, "unsupported": []}
