import asyncio
import json
from types import SimpleNamespace

from antibot_sdk.models import BrowserResult, CaptchaResult
import antibot_sdk.cli as cli


class _FakePool:
    def __init__(self) -> None:
        self.size = 2
        self.max_uses = 9
        self.pool_id = "fake-pool"
        self.started = 0
        self.stopped = 0

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1


class _FakeTencent:
    def __init__(self) -> None:
        self.pool = _FakePool()
        self.create_pool_calls = 0
        self.solve_with_pool_calls = 0
        self.solve_calls = 0

    def create_pool(self, **kwargs):
        self.create_pool_calls += 1
        self.create_pool_kwargs = kwargs
        return self.pool, SimpleNamespace(name="cloud_product", appid="199999861")

    async def solve_with_pool(self, pool, **kwargs):
        assert pool is self.pool
        self.solve_with_pool_calls += 1
        return CaptchaResult(
            provider="tencent",
            ok=True,
            captcha_type="slider",
            capability="solver",
            ticket=f"ticket-{self.solve_with_pool_calls}",
            randstr="@rand",
            diagnostics={"pool_id": pool.pool_id, "method": "fake"},
        )

    async def solve(self, **kwargs):  # pragma: no cover - should not be used by stress path
        self.solve_calls += 1
        raise AssertionError("stress tencent should reuse solve_with_pool, not solve()")


class _FakeCloudflareClient:
    last = None

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.open_calls = []
        self.solve_cloudflare_calls = []
        _FakeCloudflareClient.last = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def open(self, url, **kwargs):
        self.open_calls.append((url, kwargs))
        return BrowserResult(
            ok=True,
            state="clear",
            url=url,
            final_url=url + "/done",
            diagnostics={"mode": kwargs.get("mode")},
        )

    async def solve_cloudflare(self, target_url, **kwargs):
        self.solve_cloudflare_calls.append((target_url, kwargs))
        return BrowserResult(
            ok=True,
            state="clear",
            url=target_url,
            final_url=target_url + "/done",
            diagnostics={"mode": kwargs.get("mode")},
        )


class _FakeWidgetClient:
    last = None

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.calls = []
        _FakeWidgetClient.last = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def solve_recaptcha(self, **kwargs):
        self.calls.append(kwargs)
        return CaptchaResult(
            provider="recaptcha",
            ok=True,
            captcha_type="recaptcha_v2",
            capability="browser_flow",
            ticket="test-widget-token",
        )


class _FakeClient:
    last = None

    def __init__(self, **kwargs) -> None:
        self.tencent = _FakeTencent()
        _FakeClient.last = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def solve_tencent(self, **kwargs):
        self.solve_tencent_kwargs = kwargs
        return CaptchaResult(
            provider="tencent",
            ok=True,
            captcha_type="slider",
            ticket="ticket-from-fake",
            verify_code="0",
        )


class _FakeHarnessClient:
    last = None

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.calls = []
        _FakeHarnessClient.last = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def solve_agent(self, target_url, **kwargs):
        self.calls.append((target_url, kwargs))
        return CaptchaResult(
            provider=kwargs["provider"],
            ok=True,
            captcha_type="slider",
            capability="agent_harness",
            ticket="agent-ticket",
            diagnostics={"harness": {"state": "completed"}},
        )


def test_tencent_stress_reuses_single_browser_pool(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeClient)

    rc = asyncio.run(
        cli.amain(
            [
                "stress",
                "tencent",
                "--target-url",
                "https://cloud.tencent.com/product/captcha",
                "--runs",
                "3",
                "--concurrency",
                "2",
                "--timeout",
                "5",
            ]
        )
    )

    assert rc == 0
    client = _FakeClient.last
    assert client is not None
    assert client.tencent.create_pool_calls == 1
    assert client.tencent.solve_with_pool_calls == 3
    assert client.tencent.solve_calls == 0
    assert client.tencent.pool.started == 1
    assert client.tencent.pool.stopped == 1
    assert '"success_rate": 1.0' in capsys.readouterr().out


def test_tencent_solve_cli_forwards_unique_output_path(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeClient)
    destination = tmp_path / "run-001" / "result.json"

    rc = asyncio.run(
        cli.amain(
            [
                "solve",
                "tencent",
                "--target-url",
                "https://cloud.tencent.com/product/captcha",
                "--output-json",
                str(destination),
            ]
        )
    )

    assert rc == 0
    client = _FakeClient.last
    assert client is not None
    assert client.solve_tencent_kwargs["output_json"] == str(destination)
    assert '"verify_code": "0"' in capsys.readouterr().out


def test_run_cloudflare_uses_browser_flow(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeCloudflareClient)

    rc = asyncio.run(
        cli.amain(
            [
                "run",
                "https://example.com",
                "--mode",
                "managed",
                "--headless",
                "false",
                "--selector",
                "title=h1",
            ]
        )
    )

    assert rc == 0
    client = _FakeCloudflareClient.last
    assert client is not None
    assert client.open_calls[0][0] == "https://example.com"
    assert client.open_calls[0][1]["mode"] == "managed"
    assert client.open_calls[0][1]["selectors"] == {"title": "h1"}
    assert '"state": "clear"' in capsys.readouterr().out


def test_solve_cloudflare_uses_cloudflare_entrypoint(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeCloudflareClient)

    rc = asyncio.run(
        cli.amain(
            [
                "solve",
                "cloudflare",
                "--target-url",
                "https://example.com",
                "--mode",
                "auto",
            ]
        )
    )

    assert rc == 0
    client = _FakeCloudflareClient.last
    assert client is not None
    assert client.solve_cloudflare_calls[0][0] == "https://example.com"
    assert client.solve_cloudflare_calls[0][1]["mode"] == "auto"
    assert '"final_url": "https://example.com/done"' in capsys.readouterr().out


def test_solve_recaptcha_forwards_widget_browser_options(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeWidgetClient)

    rc = asyncio.run(
        cli.amain(
            [
                "solve",
                "recaptcha",
                "--target-url",
                "https://example.test/form",
                "--proxy",
                "http://proxy.test:8080",
                "--trigger",
                "#open-captcha",
                "--timeout",
                "15",
                "--no-auto-click",
                "--submit-selector",
                "#submit",
                "--success-selector",
                ".success",
                "--success-text",
                "Challenge Success!",
                "--vision-base-url",
                "https://vision.example/v1",
                "--vision-model",
                "vision-model",
                "--vision-api-key-env",
                "TEST_VISION_KEY",
                "--vision-min-confidence",
                "0.7",
                "--hcaptcha-max-attempts",
                "7",
                "--recaptcha-max-attempts",
                "4",
                "--recaptcha-max-rounds",
                "9",
            ]
        )
    )

    assert rc == 0
    client = _FakeWidgetClient.last
    assert client is not None
    assert client.calls[0]["target_url"] == "https://example.test/form"
    assert client.calls[0]["proxy_server"] == "http://proxy.test:8080"
    assert client.calls[0]["click_selectors"] == ["#open-captcha"]
    assert client.calls[0]["timeout_sec"] == 15
    assert client.calls[0]["auto_click"] is False
    assert client.calls[0]["submit_selector"] == "#submit"
    assert client.calls[0]["success_selectors"] == [".success"]
    assert client.calls[0]["success_text"] == "Challenge Success!"
    assert client.calls[0]["vision_base_url"] == "https://vision.example/v1"
    assert client.calls[0]["vision_model"] == "vision-model"
    assert client.calls[0]["vision_api_key_env"] == "TEST_VISION_KEY"
    assert client.calls[0]["vision_min_confidence"] == 0.7
    assert client.calls[0]["hcaptcha_max_attempts"] == 7
    assert client.calls[0]["recaptcha_max_attempts"] == 4
    assert client.calls[0]["recaptcha_max_rounds"] == 9
    assert '"ticket": "test-widget-token"' in capsys.readouterr().out


def test_install_hcaptcha_engine_uses_compat_dependencies_and_no_deps_for_legacy_engine(
    monkeypatch, capsys
) -> None:
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda command, check: calls.append(command))

    rc = asyncio.run(cli.amain(["install-hcaptcha-engine"]))

    assert rc == 0
    assert any("onnxruntime>=1.16" in command for command in calls)
    assert calls[-1][-2:] == ["--no-deps", "hcaptcha-challenger==0.10.1.post2"]
    assert '"version": "0.10.1.post2"' in capsys.readouterr().out


def test_cli_reports_version(capsys) -> None:
    import pytest

    with pytest.raises(SystemExit) as exc:
        asyncio.run(cli.amain(["--version"]))

    assert exc.value.code == 0
    assert "antibot 0.3.0" in capsys.readouterr().out


def test_harness_cli_forwards_typed_budget_and_provider_options(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "AntibotClient", _FakeHarnessClient)

    rc = asyncio.run(
        cli.amain(
            [
                "harness",
                "--target-url",
                "https://cloud.tencent.com/product/captcha",
                "--provider",
                "tencent",
                "--timeout",
                "45",
                "--max-steps",
                "8",
                "--proxy",
                "http://proxy.test:8080",
                "--options-json",
                '{"profile":"cloud_product"}',
            ]
        )
    )

    assert rc == 0
    client = _FakeHarnessClient.last
    assert client is not None
    target_url, kwargs = client.calls[0]
    assert target_url == "https://cloud.tencent.com/product/captcha"
    assert kwargs["provider"] == "tencent"
    assert kwargs["profile"] == "cloud_product"
    assert kwargs["proxy"] == "http://proxy.test:8080"
    assert kwargs["budget"].timeout_sec == 45
    assert kwargs["budget"].max_steps == 8
    assert '"state": "completed"' in capsys.readouterr().out


def test_replay_eval_cli_reports_vendor_evidence(tmp_path, capsys) -> None:
    result = tmp_path / "result.json"
    result.write_text(
        json.dumps(
            {
                "provider": "hcaptcha",
                "ok": True,
                "diagnostics": {
                    "hcaptcha_challenges": [
                        {"request_type": "image_label_binary", "prompt": "select buses"}
                    ],
                    "hcaptcha_verification_responses": [{"pass": True}],
                },
            }
        ),
        encoding="utf-8",
    )

    rc = asyncio.run(cli.amain(["replay-eval", str(result)]))

    assert rc == 0
    output = capsys.readouterr().out
    assert '"vendor_pass_runs": 1' in output
    assert '"single_challenge_vendor_pass_runs": 1' in output
