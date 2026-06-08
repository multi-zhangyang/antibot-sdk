from __future__ import annotations

from copy import deepcopy
from typing import Any


CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
    "tencent": {
        "provider": "tencent",
        "name": "Tencent Captcha",
        "category": "solver",
        "captcha_type": "slider",
        "status": "primary",
        "output": "ticket/randstr",
        "scope": "腾讯滑块：缺口识别 + 轨迹拖拽 + ticket/randstr 提取。",
    },
    "aliyun": {
        "provider": "aliyun",
        "name": "Aliyun Captcha",
        "category": "solver",
        "captcha_type": "slider",
        "status": "primary",
        "output": "verify_code/session artifacts",
        "scope": "阿里云滑块：站点 profile + CV 缺口 + 轨迹拖拽 + attempt/session retry。",
    },
    "ajcaptcha": {
        "provider": "ajcaptcha",
        "name": "AJ-Captcha / Anji",
        "category": "solver",
        "captcha_type": "slider_protocol",
        "status": "alpha",
        "output": "captchaVerification/token",
        "scope": "AJ-Captcha blockPuzzle：/captcha/get 图像缺口定位 + AES pointJson + /captcha/check 协议提交；不启动浏览器。",
    },
    "altcha": {
        "provider": "altcha",
        "name": "ALTCHA",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "base64 payload / Authorization header",
        "scope": "ALTCHA v1 PoW：解析 challenge 或 WWW-Authenticate，计算 number，输出表单 payload 或 M2M Authorization header；不启动浏览器。",
    },
    "anubis": {
        "provider": "anubis",
        "name": "Anubis",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "pass-challenge params / auth cookie",
        "scope": "Anubis fast/slow PoW：解析页面或 make-challenge JSON，计算 SHA256(randomData+nonce) 前导零，生成 pass-challenge 参数，可提交换 cookie；不启动浏览器。",
    },
    "friendlycaptcha": {
        "provider": "friendlycaptcha",
        "name": "FriendlyCaptcha",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "frc-captcha-solution payload",
        "scope": "FriendlyCaptcha classic PoW：获取 puzzle，按 friendly-pow/blake2b 求解多段 nonce，输出隐藏表单字段 payload；不启动浏览器。",
    },
    "cap": {
        "provider": "cap",
        "name": "Cap / @cap.js",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "redeem body / Cap token",
        "scope": "Cap v1 seeded PoW 与 format-2 sha256-pow：本地 SHA-256 nonce 搜索，可输出 /redeem body 或直接 redeem token；不启动浏览器。",
    },
    "mcaptcha": {
        "provider": "mcaptcha",
        "name": "mCaptcha",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "verify body / mCaptcha token",
        "scope": "mCaptcha SHA-256 PoW：获取 /api/v1/pow/config，复现 bincode(String)+u128 score nonce 搜索，可提交 /verify 换 token；不启动浏览器。",
    },
    "pcaptcha": {
        "provider": "pcaptcha",
        "name": "P-Captcha",
        "category": "solver",
        "captcha_type": "quadratic_residue_pow",
        "status": "alpha",
        "output": "answer / validated token flow",
        "scope": "P-Captcha QuadraticResidueProblem：解析 Woodall prime challenge，用模平方根直接求 answer，可提交 {id, answer}；不启动浏览器。",
    },
    "wicketkeeper": {
        "provider": "wicketkeeper",
        "name": "Wicketkeeper",
        "category": "solver",
        "captcha_type": "proof_of_work",
        "status": "alpha",
        "output": "hidden-input solution / success JWT",
        "scope": "Wicketkeeper EdDSA-JWT PoW：获取 /v0/challenge，计算 SHA256(challenge+nonce) 前导零，可提交 /v0/siteverify 换 success JWT；不启动浏览器。",
    },
    "geetest": {
        "provider": "geetest",
        "name": "GeeTest v4",
        "category": "solver",
        "captcha_type": "slider",
        "status": "alpha",
        "output": "pass_token/lot_number",
        "scope": "GeeTest v4 滑动：bg/slice 提取、CV 匹配、轨迹拖拽、validate 提取。",
    },
    "yidun": {
        "provider": "yidun",
        "name": "NetEase Yidun",
        "category": "solver",
        "captcha_type": "jigsaw",
        "status": "alpha",
        "output": "validate/token/zoneId",
        "scope": "网易易盾滑动拼图：bg/front 提取、OpenCV 缺口定位、轨迹拖拽。",
    },
    "turnstile": {
        "provider": "turnstile",
        "name": "Cloudflare Turnstile",
        "category": "flow_observer",
        "captcha_type": "token_widget",
        "status": "observer",
        "output": "widget token / artifacts",
        "scope": "嵌入式 widget 的 render/execute/callback/input token 采集与提交链路复盘。",
    },
    "hcaptcha": {
        "provider": "hcaptcha",
        "name": "hCaptcha",
        "category": "flow_observer",
        "captcha_type": "token_widget",
        "status": "observer",
        "output": "widget token / artifacts",
        "scope": "render 参数、Enterprise rqdata、callback/input token、网络现场采集；不承诺图片挑战求解。",
    },
    "recaptcha": {
        "provider": "recaptcha",
        "name": "reCAPTCHA / Enterprise",
        "category": "flow_observer",
        "captcha_type": "token_widget",
        "status": "observer",
        "output": "widget/execute token / artifacts",
        "scope": "render/execute/action/token/network artifact 采集；不承诺高风险交互挑战求解。",
    },
}

UNSUPPORTED_CAPABILITIES: list[dict[str, str]] = [
    {
        "captcha_type": "text_click",
        "name": "文字点选",
        "reason": "需要模型训练和样本闭环；OCR/混淆表 demo 不作为 SDK 能力。",
    },
    {
        "captcha_type": "semantic_image_select",
        "name": "语义选图",
        "reason": "需要通用视觉语义模型和站点样本；当前不承诺。",
    },
    {
        "captcha_type": "complex_drag_sort",
        "name": "复杂拖拽/排序",
        "reason": "规则和行为链路不稳定；只保留几何明确的滑块/拼图类。",
    },
]


def list_capabilities() -> dict[str, Any]:
    """Return the product capability boundary used by README and CLI."""

    matrix = deepcopy(CAPABILITY_MATRIX)
    solvers = [item for item in matrix.values() if item["category"] == "solver"]
    flow_observers = [item for item in matrix.values() if item["category"] == "flow_observer"]
    return {
        "schema_version": 1,
        "solvers": solvers,
        "flow_observers": flow_observers,
        "unsupported": deepcopy(UNSUPPORTED_CAPABILITIES),
    }
