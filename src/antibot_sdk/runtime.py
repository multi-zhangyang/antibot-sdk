from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import Any


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def runtime_diagnostics(browser_binary: str | None = None) -> dict[str, Any]:
    """Return side-effect-free dependency and provider readiness diagnostics."""

    from .providers.aliyun import (
        AliyunCaptchaSolver,
        discover_chrome,
        node_is_compatible,
        node_version,
    )
    from .providers.cloudflare import diagnose_environment

    chrome = browser_binary or discover_chrome()
    modules = {
        name: _module_available(name)
        for name in (
            "pydoll",
            "playwright",
            "captcha_recognizer",
            "crack_tcaptcha",
            "cv2",
            "numpy",
            "PIL",
            "fastapi",
            "uvicorn",
            "hcaptcha_challenger",
            "msgpack",
            "onnxruntime",
            "skimage",
            "sklearn",
            "ftfy",
        )
    }
    node = shutil.which("node")
    npm = shutil.which("npm")
    detected_node_version = node_version(node)
    node_compatible = node_is_compatible(node)
    aliyun_js = AliyunCaptchaSolver.js_deps_installed()
    proxy_chain = (
        AliyunCaptchaSolver.vendor_dir() / "node_modules" / "proxy-chain"
    ).exists()
    try:
        hcaptcha_engine_version = version("hcaptcha-challenger")
    except PackageNotFoundError:
        hcaptcha_engine_version = None
    vision_config = {
        "base_url": bool(os.environ.get("ANTIBOT_VISION_BASE_URL")),
        "model": os.environ.get("ANTIBOT_VISION_MODEL"),
        "api_key": bool(os.environ.get("ANTIBOT_VISION_API_KEY")),
    }
    vision_ready = bool(
        vision_config["base_url"] and vision_config["model"] and vision_config["api_key"]
    )
    arkose_vision_config = {
        **vision_config,
        "model": vision_config["model"] or "gpt-5.4",
    }
    arkose_vision_ready = bool(
        arkose_vision_config["base_url"] and arkose_vision_config["api_key"]
    )
    providers = {
        "cloudflare": {
            "ready": bool(modules["pydoll"] and chrome),
            "requires": {"pydoll": modules["pydoll"], "browser": bool(chrome)},
        },
        "tencent": {
            "ready": bool(
                modules["playwright"]
                and modules["captcha_recognizer"]
                and modules["crack_tcaptcha"]
                and chrome
            ),
            "requires": {
                "playwright": modules["playwright"],
                "captcha_recognizer": modules["captcha_recognizer"],
                "crack_tcaptcha": modules["crack_tcaptcha"],
                "browser": bool(chrome),
            },
        },
        "geetest": {
            "ready": bool(
                modules["playwright"]
                and modules["cv2"]
                and modules["numpy"]
                and modules["PIL"]
                and chrome
            ),
            "requires": {
                "playwright": modules["playwright"],
                "opencv": modules["cv2"],
                "numpy": modules["numpy"],
                "pillow": modules["PIL"],
                "browser": bool(chrome),
            },
        },
        "recaptcha": {
            "ready": bool(modules["playwright"] and chrome),
            "coverage": "widget/token browser flow; challenge solver not live-verified",
            "requires": {
                "playwright": modules["playwright"],
                "browser": bool(chrome),
            },
        },
        "arkose": {
            "ready": bool(modules["playwright"] and modules["PIL"] and chrome),
            "coverage": (
                "evidence-gated FunCaptcha Canvas/DOM flow; orbit carousel live-verified "
                "with a limited matrix"
            ),
            "open_vocabulary_vision": {
                "ready": arkose_vision_ready,
                "configuration": arkose_vision_config,
                "stream": True,
                "max_tokens_sent": False,
            },
            "requires": {
                "playwright": modules["playwright"],
                "pillow": modules["PIL"],
                "browser": bool(chrome),
            },
        },
        "hcaptcha": {
            "ready": bool(
                modules["playwright"]
                and modules["hcaptcha_challenger"]
                and modules["msgpack"]
                and modules["onnxruntime"]
                and modules["cv2"]
                and modules["numpy"]
                and modules["PIL"]
                and modules["skimage"]
                and modules["sklearn"]
                and modules["ftfy"]
                and chrome
            ),
            "coverage": (
                "HSW/MessagePack protocol; optional open-vocabulary vision for binary, point, "
                "bounding-box, multiple-choice and drag-drop; prompt-specific local fallback"
            ),
            "engine_version": hcaptcha_engine_version,
            "open_vocabulary_vision": {
                "ready": vision_ready,
                "configuration": vision_config,
            },
            "requires": {
                "playwright": modules["playwright"],
                "hcaptcha_challenger": modules["hcaptcha_challenger"],
                "msgpack": modules["msgpack"],
                "onnxruntime": modules["onnxruntime"],
                "opencv": modules["cv2"],
                "numpy": modules["numpy"],
                "pillow": modules["PIL"],
                "scikit_image": modules["skimage"],
                "scikit_learn": modules["sklearn"],
                "ftfy": modules["ftfy"],
                "browser": bool(chrome),
            },
        },
        "aliyun": {
            "ready": bool(node_compatible and chrome and aliyun_js),
            "requires": {
                "node": bool(node),
                "node_version": (
                    ".".join(str(part) for part in detected_node_version)
                    if detected_node_version
                    else None
                ),
                "node_compatible": node_compatible,
                "minimum_node_version": "22.12.0",
                "browser": bool(chrome),
                "js_dependencies": aliyun_js,
            },
        },
    }
    ready = [name for name, item in providers.items() if item["ready"]]
    return {
        "status": "ok" if len(ready) == len(providers) else "degraded",
        "python": sys.version.split()[0],
        "browser": chrome,
        "node": node,
        "node_version": (
            ".".join(str(part) for part in detected_node_version)
            if detected_node_version
            else None
        ),
        "npm": npm,
        "modules": modules,
        "providers": providers,
        "ready_providers": ready,
        "service_dependencies_ready": modules["fastapi"] and modules["uvicorn"],
        "proxy_chain_installed": proxy_chain,
        "cloudflare": diagnose_environment(browser_binary),
    }
