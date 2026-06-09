from __future__ import annotations

from typing import Any

CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
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
}


def list_capabilities() -> dict[str, list[dict[str, Any]]]:
    solvers = [dict(item) for item in CAPABILITY_MATRIX.values()]
    return {"solvers": solvers, "flow_observers": [], "unsupported": []}
