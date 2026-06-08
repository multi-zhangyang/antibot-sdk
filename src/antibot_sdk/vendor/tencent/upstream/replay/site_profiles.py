#!/usr/bin/env python3
"""Tencent captcha site profiles.

Keep per-site business parameters out of the generic slider solver.  The
Tencent captcha runtime is shared, but business pages differ in appid, SDK
host, trigger method, backend verifier, and whether the first challenge is an
invisible/direct-pass ticket or a visible slider.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Literal, Optional

FlowKind = Literal["cloud_slider_demo", "matrix_ai_detect", "generic"]


@dataclass(frozen=True)
class SiteProfile:
    name: str
    target_url: str
    appid: Optional[str]
    flow: FlowKind
    sdk_url: str
    prehandle_host: str
    verify_path: str = "cap_union_new_verify"
    default_locale: str = "zh-CN"
    needs_stable_fp: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


PROFILES: dict[str, SiteProfile] = {
    "cloud_product": SiteProfile(
        name="cloud_product",
        target_url="https://cloud.tencent.com/product/captcha",
        appid="199999861",
        flow="cloud_slider_demo",
        sdk_url="https://turing.captcha.qcloud.com/TCaptcha.js",
        prehandle_host="https://turing.captcha.qcloud.com",
        notes="Tencent Cloud product-page slider demo; historical v2.1 benchmark target.",
    ),
    "matrix_ai_detect": SiteProfile(
        name="matrix_ai_detect",
        target_url="https://matrix.tencent.com/ai-detect/ai_gen_txt",
        appid="2089775896",
        flow="matrix_ai_detect",
        sdk_url="https://captcha.gtimg.com/TCaptcha.js",
        prehandle_host="https://t.captcha.qq.com",
        default_locale="en-US",
        needs_stable_fp=True,
        notes=(
            "Zhuque AI Detection text page. Native page creates TencentCaptcha with appid "
            "2089775896; normal first challenge is show_type=unconscious/direct-pass, "
            "but backend Matrix WS only proceeds when captcha ticket verifies as evil_level=0."
        ),
    ),
    "generic": SiteProfile(
        name="generic",
        target_url="https://cloud.tencent.com/product/captcha",
        appid=None,
        flow="generic",
        sdk_url="",
        prehandle_host="",
        notes="Fallback profile for explicit TCAPTCHA_TARGET_URL experiments.",
    ),
}


def get_profile(name: str | None) -> SiteProfile:
    key = (name or "cloud_product").strip() or "cloud_product"
    if key not in PROFILES:
        valid = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown TCAPTCHA_PROFILE={key!r}; valid: {valid}")
    return PROFILES[key]


def profile_for_url(url: str, preferred: str | None = None) -> SiteProfile:
    if preferred:
        return get_profile(preferred)
    if "matrix.tencent.com/ai-detect" in url:
        return PROFILES["matrix_ai_detect"]
    if "cloud.tencent.com/product/captcha" in url:
        return PROFILES["cloud_product"]
    p = PROFILES["generic"]
    return SiteProfile(
        name="generic",
        target_url=url,
        appid=p.appid,
        flow=p.flow,
        sdk_url=p.sdk_url,
        prehandle_host=p.prehandle_host,
        notes=p.notes,
    )
