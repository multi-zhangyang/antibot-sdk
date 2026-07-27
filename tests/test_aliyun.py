import asyncio
import json
from pathlib import Path
import subprocess

import pytest

import antibot_sdk.providers.aliyun as aliyun
import antibot_sdk.cli as cli
from antibot_sdk.models import CaptchaResult
from antibot_sdk.providers.aliyun import (
    ALIYUN_CAPTCHA_TYPES,
    ALIYUN_NON_PRODUCTION_VERIFY_CODES,
    ALIYUN_PASS_VERIFY_CODES,
    AliyunCaptchaSolver,
    aliyun_verify_passed,
    normalize_aliyun_captcha_type,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "auto"),
        ("detect", "auto"),
        ("traceless", "invisible"),
        ("one-click", "one_click"),
        ("checkbox", "one_click"),
        ("slide", "slider"),
        ("jigsaw", "puzzle"),
        ("image restoration", "image_restore"),
    ],
)
def test_normalize_aliyun_captcha_type(value, expected) -> None:
    assert normalize_aliyun_captcha_type(value) == expected


def test_normalize_aliyun_captcha_type_rejects_unknown_values() -> None:
    with pytest.raises(ValueError, match="unsupported Aliyun captcha type"):
        normalize_aliyun_captcha_type("spatial_reasoning")

    assert set(ALIYUN_CAPTCHA_TYPES) == {
        "auto",
        "invisible",
        "one_click",
        "slider",
        "puzzle",
        "image_restore",
    }


def test_aliyun_verify_passed_requires_production_code_and_result() -> None:
    assert ALIYUN_PASS_VERIFY_CODES == {"T001"}
    assert aliyun_verify_passed({"VerifyResult": True, "VerifyCode": "T001"})
    assert aliyun_verify_passed(
        {"Result": {"VerifyResult": True, "VerifyCode": "t001"}}
    )
    assert not aliyun_verify_passed({"VerifyResult": False, "VerifyCode": "T001"})
    assert not aliyun_verify_passed({"VerifyResult": True})


@pytest.mark.parametrize("code", ["T005", "T006"])
def test_aliyun_verify_passed_rejects_non_production_modes(code) -> None:
    assert ALIYUN_NON_PRODUCTION_VERIFY_CODES == {"T005", "T006"}
    assert not aliyun_verify_passed({"VerifyResult": True, "VerifyCode": code})
    assert not aliyun_verify_passed({"Result": {"VerifyResult": True, "VerifyCode": code}})


def test_aliyun_verify_passed_rejects_failure_codes() -> None:
    assert not aliyun_verify_passed({"VerifyResult": False, "VerifyCode": "F015"})
    assert not aliyun_verify_passed(None)


def test_compact_cli_raw_redacts_aliyun_verification_material() -> None:
    compact = cli._compact_raw(
        {
            "ok": True,
            "verifyResponse": {
                "VerifyResult": True,
                "VerifyCode": "T001",
                "securityToken": "one-time-security-token",
                "certifyId": "one-time-certify-id",
            },
        }
    )

    assert compact["verifyResponse"] == {
        "VerifyResult": True,
        "VerifyCode": "T001",
    }
    assert "securityToken" not in json.dumps(compact)
    assert "certifyId" not in json.dumps(compact)


def test_node_challenge_type_contract_detects_official_variants() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "challenge_types.js"
    script = f"""
const c = require({json.dumps(str(module))});
const cases = [
  c.detectCaptchaType({{ text: '确认您不是机器人', checkbox: {{ visible: true }} }}),
  c.detectCaptchaType({{ text: '请按住滑块，拖动到最右边', sliderRect: {{ x: 1 }} }}),
  c.detectCaptchaType({{ text: '请拖动滑块完成拼图', imgSrc: 'a', puzzleSrc: 'b' }}),
  c.detectCaptchaType({{ text: '拖动滑块还原完整图片', imgSrc: 'a', sliderRect: {{ x: 1 }} }}),
  c.detectCaptchaType({{ verifyResponse: {{ VerifyResult: true, VerifyCode: 'T001' }}, visibleChallenge: false }}),
  c.detectCaptchaType({{
    text: '请按住滑块，拖动到最右边',
    imgSrc: 'business-image',
    puzzleSrc: 'nearby-icon',
    sliderRect: {{ x: 1 }},
    selectorAuto: {{ puzzle: true }},
  }}),
  c.detectCaptchaType({{
    text: '请拖动滑块',
    imgSrc: 'restoration-image',
    imageRect: {{ width: 300 }},
    sliderRect: {{ x: 1 }},
    selectorAuto: {{ puzzle: true }},
  }}),
  c.detectCaptchaType({{ vendorCaptchaType: 'CHECK_BOX', text: 'generic entry' }}),
  c.detectCaptchaType({{ vendorCaptchaType: 'TRACELESS', sliderRect: {{ x: 1 }} }}),
  c.detectCaptchaType({{ vendorCaptchaType: 'SLIDING', imgSrc: 'nearby-image' }}),
  c.detectCaptchaType({{ vendorCaptchaType: 'PUZZLE' }}),
  c.detectCaptchaType({{ vendorCaptchaType: 'INPAINTING' }}),
];
process.stdout.write(JSON.stringify({{
  cases,
  vendorAliases: [
    c.normalizeVendorCaptchaType('check-box'),
    c.normalizeVendorCaptchaType('unknown-future-type'),
  ],
  pass: c.PASS_VERIFY_CODES,
  nonProduction: c.NON_PRODUCTION_VERIFY_CODES,
  strictPass: [
    c.verifyPassed({{ VerifyResult: true, VerifyCode: 'T001' }}),
    c.verifyPassed({{ VerifyResult: false, VerifyCode: 'T001' }}),
    c.verifyPassed({{ VerifyResult: true, VerifyCode: 'T005' }}),
    c.verifyPassed({{ VerifyResult: true, VerifyCode: 'T006' }}),
  ],
}}));
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["cases"] == [
        "one_click",
        "slider",
        "puzzle",
        "image_restore",
        "invisible",
        "slider",
        "image_restore",
        "one_click",
        "invisible",
        "slider",
        "puzzle",
        "image_restore",
    ]
    assert payload["vendorAliases"] == ["one_click", None]
    assert payload["pass"] == ["T001"]
    assert payload["nonProduction"] == ["T005", "T006"]
    assert payload["strictPass"] == [True, False, False, False]


def test_node_challenge_readiness_requires_type_specific_evidence() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "challenge_types.js"
    script = f"""
const c = require({json.dumps(str(module))});
const cases = [
  c.captchaReady({{ verifyResponse: {{ VerifyResult: true, VerifyCode: 'T001' }}, visibleChallenge: false }}),
  c.captchaReady({{ checkbox: {{ visible: true }}, text: '一点即过' }}),
  c.captchaReady({{ slider: {{ visible: true }}, track: {{ visible: true }}, text: '拖动到最右' }}),
  c.captchaReady({{ slider: {{ visible: true }}, imgSrc: 'a', puzzleSrc: 'b', text: '拼图' }}),
  c.captchaReady({{ slider: {{ visible: true }}, imgSrc: 'a', bodyRect: {{ width: 300 }}, text: '图像复原' }}),
  c.captchaReady({{ sliderRect: {{ x: 1 }}, imgSrc: 'business-image' }}),
];
process.stdout.write(JSON.stringify(cases));
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == [True, True, True, True, True, False]


def test_node_image_restore_strip_match_is_local_and_reports_ambiguity() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "runner.js"
    package_dir = AliyunCaptchaSolver.vendor_dir()
    script = f"""
const {{ PNG }} = require('pngjs');
const r = require({json.dumps(str(module))});
function makeBackground(unique) {{
  const png = new PNG({{ width: 80, height: 30 }});
  for (let y = 0; y < png.height; y++) for (let x = 0; x < png.width; x++) {{
    const i = (y * png.width + x) * 4;
    png.data[i] = unique ? (x * 7 + y * 3) % 256 : 120;
    png.data[i + 1] = unique ? (x * 5 + y * 11) % 256 : 120;
    png.data[i + 2] = unique ? (x * 13 + y * 2) % 256 : 120;
    png.data[i + 3] = 255;
  }}
  return png;
}}
function fragmentFrom(bg, target) {{
  const png = new PNG({{ width: 8, height: bg.height }});
  for (let y = 4; y < bg.height - 4; y++) for (let x = 0; x < png.width; x++) {{
    const si = (y * bg.width + target + x) * 4, di = (y * png.width + x) * 4;
    png.data[di] = bg.data[si]; png.data[di + 1] = bg.data[si + 1]; png.data[di + 2] = bg.data[si + 2]; png.data[di + 3] = 255;
  }}
  return png;
}}
const uniqueBg = makeBackground(true), flatBg = makeBackground(false);
const uniqueFragment = fragmentFrom(uniqueBg, 47);
const matched = r.detectRestoreStrip(PNG.sync.write(uniqueBg), PNG.sync.write(uniqueFragment), {{ maxDistance: 60, cssWidth: 80 }});
const ambiguous = r.detectRestoreStrip(PNG.sync.write(flatBg), PNG.sync.write(fragmentFrom(flatBg, 47)), {{ maxDistance: 60, cssWidth: 80 }});
const rendered = PNG.sync.read(r.renderRestoreCandidate(PNG.sync.write(uniqueBg), PNG.sync.write(uniqueFragment), 47));
const focused = PNG.sync.read(r.renderRestoreCandidateFocus(PNG.sync.write(uniqueBg), PNG.sync.write(uniqueFragment), 47));
const projected = r.restorePuzzleTravel(100, 260);
const inverted = r.restoreSliderTravel(projected, 260);
const visionCandidates = r.buildRestoreVisionCandidates({{
  css_per_png: 1,
  candidates: [{{ target_left_png: 1 }}, {{ target_left_png: 164 }}],
}}, 174, 9);
const clusteredCandidates = r.buildRestoreVisionCandidates({{
  css_per_png: 1,
  candidates: [
    {{ target_left_png: 236 }},
    {{ target_left_png: 229 }},
    {{ target_left_png: 215 }},
    {{ target_left_png: 222 }},
    {{ target_left_png: 92 }},
  ],
}}, 260, 9);
const refinementCandidates = r.buildRestoreRefinementCandidates(108, visionCandidates, 174, 9);
process.stdout.write(JSON.stringify({{ matched, ambiguous, rendered: {{ width: rendered.width, height: rendered.height }}, focused: {{ width: focused.width, height: focused.height }}, projected, inverted, visionCandidates, clusteredCandidates, refinementCandidates }}));
"""
    completed = subprocess.run(
        ["node", "-e", script],
        cwd=package_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["matched"]["source"] == "local_strip_match"
    assert payload["matched"]["target_left_png"] == 47
    assert payload["matched"]["distance_px"] == 47
    assert payload["matched"]["confidence"] >= 0.72
    assert payload["ambiguous"]["confidence"] < 0.72
    assert len(payload["ambiguous"]["candidates"]) >= 2
    assert payload["rendered"] == {"width": 80, "height": 30}
    assert payload["focused"] == {"width": 256, "height": 120}
    assert payload["projected"] == pytest.approx(43.195266, abs=0.001)
    assert payload["inverted"] == pytest.approx(100, abs=0.001)
    assert [candidate["target_left_png"] for candidate in payload["visionCandidates"]] == [
        0,
        22,
        44,
        65,
        87,
        109,
        131,
        152,
        174,
    ]
    assert [
        candidate["target_left_png"] for candidate in payload["clusteredCandidates"]
    ] == [0, 33, 65, 92, 130, 163, 195, 236, 260]
    assert payload["refinementCandidates"] == [
        87,
        93,
        98,
        104,
        109,
        115,
        120,
        126,
        131,
    ]


def test_cdp_drag_reports_pre_release_geometry() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "runner.js"
    script = f"""
const r = require({json.dumps(str(module))});
let geometryRead = 0;
const snapshots = [
  {{
    image: {{left: 100, top: 20, width: 300, height: 300}},
    puzzle: {{left: 100, top: 20, width: 20, height: 300}},
    slider: {{left: 100, top: 340, width: 40, height: 40}},
    body: {{left: 100, top: 340, width: 300, height: 40}},
    puzzleLeftPx: 0,
    sliderLeftPx: 0,
  }},
  {{
    image: {{left: 100, top: 20, width: 300, height: 300}},
    puzzle: {{left: 282.25, top: 20, width: 20, height: 300}},
    slider: {{left: 315.75, top: 340, width: 40, height: 40}},
    body: {{left: 100, top: 340, width: 300, height: 40}},
    puzzleLeftPx: 182.25,
    sliderLeftPx: 215.75,
  }},
];
const page = {{
  mouse: {{
    move: async () => {{}},
    down: async () => {{}},
    up: async () => {{}},
  }},
  evaluate: async (_fn, spec) => spec ? snapshots[geometryRead++] : null,
}};
(async () => {{
  const result = await r.runCdpMouse(page, {{
    startX: 120,
    startY: 360,
    requestedSliderDistancePx: 215.75,
    warm: [],
    points: [{{x: 335.75, y: 360, t: 0}}],
    releaseHoldMs: 0,
    releaseHoldJitterMs: 0,
  }});
  process.stdout.write(JSON.stringify(result.geometry));
}})();
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    geometry = json.loads(completed.stdout)

    assert geometry["requestedSliderDistancePx"] == 215.75
    assert geometry["pointerDistancePx"] == 215.75
    assert geometry["observedSliderDisplacementPx"] == 215.75
    assert geometry["observedPuzzleDisplacementPx"] == 182.25
    assert geometry["observedSliderLeftPx"] == 215.75
    assert geometry["observedPuzzleLeftPx"] == 182.25
    assert geometry["observedImageLeftPx"] == 100


def test_restore_boundary_continuity_and_integer_slider_quantization() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "runner.js"
    package_dir = AliyunCaptchaSolver.vendor_dir()
    script = f"""
const {{ PNG }} = require('pngjs');
const r = require({json.dumps(str(module))});
const background = new PNG({{ width: 80, height: 30 }});
const fragment = new PNG({{ width: 8, height: 30 }});
for (let i = 0; i < background.data.length; i += 4) {{
  background.data[i] = 25;
  background.data[i + 1] = 35;
  background.data[i + 2] = 45;
  background.data[i + 3] = 255;
}}
for (let y = 4; y <= 14; y++) for (let x = 0; x < fragment.width; x++) {{
  const i = (y * fragment.width + x) * 4;
  fragment.data[i] = 205;
  fragment.data[i + 1] = 155;
  fragment.data[i + 2] = 55;
  fragment.data[i + 3] = 255;
}}
for (let y = 15; y <= 24; y++) for (let x = 47; x < 55; x++) {{
  const i = (y * background.width + x) * 4;
  background.data[i] = 205;
  background.data[i + 1] = 155;
  background.data[i + 2] = 55;
}}
const continuity = r.detectRestoreBoundaryContinuity(
  PNG.sync.write(background),
  PNG.sync.write(fragment),
  {{ maxDistance: 60, cssWidth: 80 }},
);
const fallback = r.selectRestoreBoundaryFallback({{
  directions: [
    {{direction: 'left', distance_px: 11, score: 19.6, score_margin: 0.43, confidence: 0.6}},
    {{direction: 'top', distance_px: 10, score: 21.3, score_margin: 0.46, confidence: 0.53}},
    {{direction: 'right', distance_px: 148, score: 12, score_margin: 0.5, confidence: 0.9}},
  ],
}}, {{candidates: [{{distance_px: 10, score: 82}}, {{distance_px: 136, score: 42}}]}}, 43);
const rejectedFallback = r.selectRestoreBoundaryFallback({{
  directions: [
    {{direction: 'right', distance_px: 156, score: 8.8, score_margin: 0.61, confidence: 1}},
    {{direction: 'top', distance_px: 157, score: 9, score_margin: 0.57, confidence: 1}},
  ],
}}, {{candidates: [{{distance_px: 131, score: 39}}, {{distance_px: 181, score: 28}}]}}, 58);
const raw = r.restoreSliderTravel(118, 260);
const quantized = r.restoreQuantizedSliderTravel(118, 260);
process.stdout.write(JSON.stringify({{
  continuity,
  fallback,
  rejectedFallback,
  raw,
  quantized,
  projected: r.restorePuzzleTravel(quantized, 260),
}}));
"""
    completed = subprocess.run(
        ["node", "-e", script],
        cwd=package_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    best = payload["continuity"]["directions"][0]

    assert best["direction"] == "bottom"
    assert best["target_left_png"] == 47
    assert best["score"] == 0
    assert best["score_margin"] == 1
    assert payload["fallback"] == {
        "distance_px": 10,
        "confidence": 0.7,
        "tolerance_px": 4.3,
        "directions": ["left", "top"],
        "direction_targets_px": [11, 10],
        "local_target_px": 10,
        "local_score": 82,
        "spread_px": 1,
    }
    assert payload["rejectedFallback"] is None
    assert payload["raw"] == pytest.approx(171.7975, abs=0.001)
    assert payload["quantized"] == 172
    assert payload["projected"] == pytest.approx(118.2627, abs=0.001)


def test_node_site_verification_logger_is_redacted_and_cannot_set_vendor_pass() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "runner.js"
    script = f"""
const r = require({json.dumps(str(module))});
class FakePage {{
  on(name, callback) {{ if (name === 'response') this.onResponse = callback; }}
}}
(async () => {{
  const page = new FakePage();
  const result = {{ net: [] }};
  r.attachResponseLogger(page, result);
  await page.onResponse({{
    url: () => 'https://site.example/api/login',
    request: () => ({{
      method: () => 'POST',
      postData: () => JSON.stringify({{
        username: 'user@example.test',
        password: 'request-password',
        captchaVerifyParam: 'request-captcha-secret',
      }}),
    }}),
    status: () => 401,
    headers: () => ({{ 'content-type': 'application/json' }}),
    text: async () => JSON.stringify({{
      code: 'INVALID_CREDENTIALS',
      success: false,
      message: 'captcha accepted; credentials rejected',
      accessToken: 'response-token-secret',
      data: {{ verifyCode: 'T001', sessionId: 'response-session-secret' }},
    }}),
  }});
  process.stdout.write(JSON.stringify({{
    detected: r.requestCarriesCaptchaVerifyParam('x=1&CaptchaVerifyParam=secret'),
    mutated: JSON.parse(r.mutateCaptchaVerifyParam(
      JSON.stringify({{ captchaVerifyParam: 'original-secret', nested: {{ ok: true }} }}),
      'invalid-control'
    )).captchaVerifyParam,
    evidence: r.classifySiteVerificationEvidence({{
      siteVerificationNetwork: {{ responseSummary: {{ value: {{ message: 'credentials rejected' }} }} }},
      siteVerificationControlNetwork: {{ responseSummary: {{ value: {{ message: 'captcha rejected' }} }} }},
    }}, {{
      siteVerificationAcceptedPattern: 'credentials rejected',
      siteVerificationRejectedPattern: 'captcha rejected',
    }}),
    official: [
      r.isAliyunVerificationEndpoint('https://tenant.captcha-open.aliyuncs.com/'),
      r.isAliyunVerificationEndpoint('https://tenant.captcha-open-southeast.aliyuncs.com/'),
      r.isAliyunVerificationEndpoint('https://site.example/api/captcha/login'),
    ],
    result,
  }}));
}})();
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    result = payload["result"]
    serialized = json.dumps(result)

    assert payload["detected"] is True
    assert payload["mutated"] == "invalid-control"
    assert payload["evidence"] == {
        "classification": "site_secondary_check_pass",
        "site_secondary_pass": True,
        "responses_differ": True,
        "accepted_pattern_configured": True,
        "accepted_pattern_matched": True,
        "rejected_pattern_configured": True,
        "rejected_pattern_matched": True,
        "vendor_production_pass": False,
    }
    assert payload["official"] == [True, True, False]
    assert "request-password" not in serialized
    assert "request-captcha-secret" not in serialized
    assert "response-token-secret" not in serialized
    assert "response-session-secret" not in serialized
    assert result["net"] == []
    assert "verifyNetwork" not in result
    assert "verifyResponse" not in result
    site = result["siteVerificationNetwork"]
    assert site["method"] == "POST"
    assert site["url"] == "https://site.example/api/login"
    assert site["status"] == 401
    assert site["requestBodyLen"] > 0
    assert site["responseBodyLen"] > 0
    assert site["contentType"] == "application/json"
    assert site["responseSummary"] == {
        "kind": "json",
        "value": {
            "code": "INVALID_CREDENTIALS",
            "success": False,
            "message": "captcha accepted; credentials rejected",
            "accessToken": "[redacted]",
            "data": {
                "verifyCode": "T001",
                "sessionId": "[redacted]",
            },
        },
    }


def test_node_response_logger_uses_vendor_init_captcha_type() -> None:
    module = AliyunCaptchaSolver.vendor_dir() / "src" / "runner.js"
    script = f"""
const r = require({json.dumps(str(module))});
class FakePage {{
  on(name, callback) {{ if (name === 'response') this.onResponse = callback; }}
}}
(async () => {{
  const page = new FakePage();
  const result = {{ net: [] }};
  r.attachResponseLogger(page, result);
  await page.onResponse({{
    url: () => 'https://tenant.captcha-open.aliyuncs.com/',
    request: () => ({{
      method: () => 'POST',
      postData: () => 'Action=InitCaptchaV3&SceneId=runtime-scene',
    }}),
    status: () => 200,
    text: async () => JSON.stringify({{
      Code: 'Success',
      Success: true,
      CaptchaType: 'CHECK_BOX',
      StaticPath: '3.28.0/ck.runtime-asset',
      DeviceConfig: 'sensitive-runtime-material',
    }}),
  }});
  process.stdout.write(JSON.stringify({{ initCaptcha: result.initCaptcha, netCount: result.net.length }}));
}})();
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert payload == {
        "initCaptcha": {
            "vendorType": "CHECK_BOX",
            "captchaType": "one_click",
            "staticPath": "3.28.0/ck.runtime-asset",
        },
        "netCount": 1,
    }


def test_aliyun_rejects_reserved_vision_extra_fields_before_launch(monkeypatch) -> None:
    monkeypatch.setattr(aliyun, "node_version", lambda _node=None: (22, 12, 0))
    monkeypatch.setattr(aliyun, "node_is_compatible", lambda _node=None: True)
    monkeypatch.setattr(
        AliyunCaptchaSolver,
        "js_deps_installed",
        staticmethod(lambda: True),
    )

    with pytest.raises(ValueError, match="cannot override reserved request fields: messages"):
        asyncio.run(
            AliyunCaptchaSolver(node="node").solve(
                target_url="https://example.test/captcha",
                use_env_proxy=False,
                vision_extra_body={"messages": []},
            )
        )


def test_solver_passes_type_and_vision_config_without_serializing_secret(
    monkeypatch, tmp_path
) -> None:
    captured = {}

    class FakeProcess:
        pid = 12345
        returncode = 0

        async def communicate(self):
            raw = {
                "ok": True,
                "captchaType": "image_restore",
                "verifyResponse": {"VerifyResult": True, "VerifyCode": "T001"},
                "verifyNetwork": {
                    "url": "https://captcha-open.example.aliyuncs.com/",
                    "status": 200,
                    "text": json.dumps(
                        {
                            "Code": "Success",
                            "Success": True,
                            "Result": {"VerifyResult": True, "VerifyCode": "T001"},
                        }
                    ),
                },
                "outputDir": str(tmp_path),
                "out": str(tmp_path / "result.json"),
            }
            return json.dumps(raw).encode(), b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        options_path = args[2]
        captured["options"] = json.loads(Path(options_path).read_text(encoding="utf-8"))
        captured["env"] = kwargs["env"]
        return FakeProcess()

    monkeypatch.setattr(aliyun, "node_version", lambda _node=None: (22, 12, 0))
    monkeypatch.setattr(aliyun, "node_is_compatible", lambda _node=None: True)
    monkeypatch.setattr(
        AliyunCaptchaSolver,
        "js_deps_installed",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(aliyun, "discover_chrome", lambda: None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(
        AliyunCaptchaSolver(node="node").solve(
            target_url="https://example.test/captcha",
            captcha_type="image-restoration",
            output_dir=str(tmp_path),
            out=str(tmp_path / "result.json"),
            use_env_proxy=False,
            vision_base_url="https://vision.example/v1",
            vision_model="test-vision-model",
            vision_api_key="runtime-secret",
            vision_api_key_env="TEST_ALIYUN_VISION_KEY",
            vision_min_confidence=0.6,
            vision_retries=3,
            pre_captcha_fills={"#email": "runtime-user"},
            pre_captcha_presses=["Enter"],
            pre_captcha_clicks=["text:Continue"],
            site_verification_control=True,
            site_verification_accepted_pattern="credentials rejected",
            site_verification_rejected_pattern="captcha rejected",
        )
    )

    assert result.ok is True
    assert result.captcha_type == "image_restore"
    assert result.verify_code == "T001"
    assert result.diagnostics["vendor_verification"] == {
        "observed": True,
        "endpoint_host": "captcha-open.example.aliyuncs.com",
        "http_status": 200,
        "response_code": "Success",
        "response_success": True,
        "verify_result": True,
        "verify_code": "T001",
        "classification": "production_pass",
        "production_pass": True,
    }
    assert captured["options"]["captchaType"] == "image_restore"
    assert captured["options"]["vision"] == {
        "baseUrl": "https://vision.example/v1",
        "model": "test-vision-model",
        "apiKeyEnv": "TEST_ALIYUN_VISION_KEY",
        "timeoutMs": 180000,
        "minConfidence": 0.6,
        "retries": 3,
    }
    assert captured["options"]["preCaptchaFills"] == [
        {"selector": "#email", "value": "runtime-user"}
    ]
    assert captured["options"]["preCaptchaPresses"] == ["Enter"]
    assert captured["options"]["preCaptchaClicks"] == ["text:Continue"]
    assert captured["options"]["siteVerificationControl"] is True
    assert (
        captured["options"]["siteVerificationAcceptedPattern"]
        == "credentials rejected"
    )
    assert (
        captured["options"]["siteVerificationRejectedPattern"]
        == "captcha rejected"
    )
    assert "runtime-secret" not in json.dumps(captured["options"])
    assert captured["env"]["TEST_ALIYUN_VISION_KEY"] == "runtime-secret"


def test_solver_does_not_accept_raw_ok_without_vendor_pass(monkeypatch, tmp_path) -> None:
    class FakeProcess:
        pid = 12345
        returncode = 0

        async def communicate(self):
            raw = {
                "ok": True,
                "captchaType": "slider",
                "siteVerificationEvidence": {
                    "classification": "site_secondary_check_pass",
                    "site_secondary_pass": True,
                    "vendor_production_pass": False,
                },
                "outputDir": str(tmp_path),
                "out": str(tmp_path / "result.json"),
            }
            return json.dumps(raw).encode(), b""

    async def fake_create_subprocess_exec(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr(aliyun, "node_version", lambda _node=None: (22, 12, 0))
    monkeypatch.setattr(aliyun, "node_is_compatible", lambda _node=None: True)
    monkeypatch.setattr(
        AliyunCaptchaSolver,
        "js_deps_installed",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(aliyun, "discover_chrome", lambda: None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(
        AliyunCaptchaSolver(node="node").solve(
            target_url="https://example.test/captcha",
            output_dir=str(tmp_path),
            out=str(tmp_path / "result.json"),
            use_env_proxy=False,
        )
    )

    assert result.ok is False
    assert result.errors == ["vendor_verification_not_observed"]
    assert result.diagnostics["site_verification_evidence"][
        "site_secondary_pass"
    ] is True
    assert (
        result.diagnostics["failure_class"]
        == "site_secondary_verified_vendor_result_not_observable"
    )


@pytest.mark.parametrize(
    ("code", "classification"),
    [("T005", "test_mode"), ("T006", "whitelist_mode")],
)
def test_solver_reports_non_production_mode_without_accepting_it(
    monkeypatch, tmp_path, code, classification
) -> None:
    class FakeProcess:
        pid = 12345
        returncode = 0

        async def communicate(self):
            raw = {
                "ok": True,
                "captchaType": "invisible",
                "verifyResponse": {"VerifyResult": True, "VerifyCode": code},
                "verifyNetwork": {
                    "url": "https://captcha-open.example.aliyuncs.com/",
                    "status": 200,
                    "text": json.dumps(
                        {
                            "Code": "Success",
                            "Success": True,
                            "Result": {"VerifyResult": True, "VerifyCode": code},
                        }
                    ),
                },
                "outputDir": str(tmp_path),
                "out": str(tmp_path / "result.json"),
            }
            return json.dumps(raw).encode(), b""

    async def fake_create_subprocess_exec(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr(aliyun, "node_version", lambda _node=None: (22, 12, 0))
    monkeypatch.setattr(aliyun, "node_is_compatible", lambda _node=None: True)
    monkeypatch.setattr(
        AliyunCaptchaSolver,
        "js_deps_installed",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(aliyun, "discover_chrome", lambda: None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(
        AliyunCaptchaSolver(node="node").solve(
            target_url="https://example.test/captcha",
            output_dir=str(tmp_path),
            out=str(tmp_path / "result.json"),
            use_env_proxy=False,
        )
    )

    assert result.ok is False
    assert result.verify_code == code
    assert result.errors == ["solve_failed"]
    assert result.diagnostics["vendor_verification"]["classification"] == classification
    assert result.diagnostics["vendor_verification"]["production_pass"] is False


def test_image_restore_reports_incomplete_vision_configuration(monkeypatch) -> None:
    monkeypatch.setattr(aliyun, "node_version", lambda _node=None: (22, 12, 0))
    monkeypatch.setattr(aliyun, "node_is_compatible", lambda _node=None: True)
    monkeypatch.setattr(
        AliyunCaptchaSolver,
        "js_deps_installed",
        staticmethod(lambda: True),
    )
    monkeypatch.delenv("ANTIBOT_VISION_BASE_URL", raising=False)
    monkeypatch.delenv("ANTIBOT_VISION_MODEL", raising=False)
    monkeypatch.delenv("ANTIBOT_VISION_API_KEY", raising=False)

    result = asyncio.run(
        AliyunCaptchaSolver(node="node").solve(
            target_url="https://example.test/captcha",
            captcha_type="image_restore",
            use_env_proxy=False,
        )
    )

    assert result.ok is False
    assert result.captcha_type == "image_restore"
    assert "incomplete vision backend configuration" in result.errors[0]


def test_aliyun_cli_forwards_multi_challenge_and_vision_options(monkeypatch, capsys) -> None:
    class FakeClient:
        last = None

        def __init__(self, **_kwargs):
            self.calls = []
            FakeClient.last = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, _exc_type, _exc, _tb):
            return None

        async def solve_aliyun(self, **kwargs):
            self.calls.append(kwargs)
            return CaptchaResult(
                provider="aliyun",
                ok=True,
                captcha_type=kwargs["captcha_type"],
                capability="solver",
                verify_code="T001",
            )

    monkeypatch.setattr(cli, "AntibotClient", FakeClient)

    rc = asyncio.run(
        cli.amain(
            [
                "solve",
                "aliyun",
                "--target-url",
                "https://example.test/captcha",
                "--captcha-type",
                "image_restore",
                "--vision-base-url",
                "https://vision.example/v1",
                "--vision-model",
                "test-vision-model",
                "--vision-api-key-env",
                "TEST_VISION_KEY",
                "--vision-min-confidence",
                "0.55",
                "--vision-retries",
                "4",
                "--restore-distance-px",
                "121.5",
                "--pre-captcha-fill",
                "#login_phoneOrEmail=user@example.test",
                "--pre-captcha-fill",
                "#login_password=runtime-password",
                "--pre-captcha-press",
                "Enter",
                "--pre-captcha-click",
                "text:Continue",
                "--site-verification-control",
                "--site-verification-accepted-pattern",
                "credentials rejected",
                "--site-verification-rejected-pattern",
                "captcha rejected",
            ]
        )
    )

    assert rc == 0
    client = FakeClient.last
    assert client is not None
    kwargs = client.calls[0]
    assert kwargs["captcha_type"] == "image_restore"
    assert kwargs["vision_base_url"] == "https://vision.example/v1"
    assert kwargs["vision_model"] == "test-vision-model"
    assert kwargs["vision_api_key_env"] == "TEST_VISION_KEY"
    assert kwargs["vision_min_confidence"] == 0.55
    assert kwargs["vision_retries"] == 4
    assert kwargs["restore_distance_px"] == 121.5
    assert kwargs["pre_captcha_fills"] == {
        "#login_phoneOrEmail": "user@example.test",
        "#login_password": "runtime-password",
    }
    assert kwargs["pre_captcha_presses"] == ["Enter"]
    assert kwargs["pre_captcha_clicks"] == ["text:Continue"]
    assert kwargs["site_verification_control"] is True
    assert kwargs["site_verification_accepted_pattern"] == "credentials rejected"
    assert kwargs["site_verification_rejected_pattern"] == "captcha rejected"
    assert '"captcha_type": "image_restore"' in capsys.readouterr().out
