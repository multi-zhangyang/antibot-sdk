import asyncio

from antibot_sdk.client import AntibotClient
from antibot_sdk.models import CaptchaResult, SolveRequest


class _ConcurrentTencent:
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self.calls = []

    async def solve(self, *, target_url: str, delay: float = 0.01, **kwargs):
        self.calls.append({"target_url": target_url, "delay": delay, **kwargs})
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(delay)
            if target_url.endswith("/raise"):
                raise RuntimeError("provider exploded")
            return CaptchaResult(
                provider="tencent",
                ok=not target_url.endswith("/fail"),
                captcha_type="slider",
                capability="solver",
                ticket=target_url.rsplit("/", 1)[-1],
                diagnostics={
                    "tencent_verification_responses": [
                        {
                            "error_code": "50" if target_url.endswith("/fail") else "0",
                            "accepted": not target_url.endswith("/fail"),
                        }
                    ]
                },
                errors=["rejected"] if target_url.endswith("/fail") else [],
            )
        finally:
            self.active -= 1


class _FakeWidgets:
    def __init__(self) -> None:
        self.calls = []

    async def solve(self, *, target_url: str, provider: str, **kwargs):
        self.calls.append({"target_url": target_url, "provider": provider, **kwargs})
        return CaptchaResult(
            provider=provider,
            ok=True,
            captcha_type=provider,
            capability="browser_flow",
            ticket="widget-token",
        )


def test_client_initializes_providers_lazily() -> None:
    client = AntibotClient()

    assert client._browser is None
    assert client._aliyun is None
    assert client._geetest is None
    assert client._tencent is None
    assert client._widgets is None


def test_client_registry_routes_widget_providers_and_forwards_defaults() -> None:
    async def run():
        client = AntibotClient(
            browser_binary="/opt/chrome",
            default_proxy="http://proxy.test:8080",
            use_env_proxy=False,
        )
        widgets = _FakeWidgets()
        client.widgets = widgets
        recaptcha = await client.solve(
            "https://example.test/recaptcha",
            provider="recaptcha",
            timeout_sec=12,
        )
        hcaptcha = await client.solve_hcaptcha("https://example.test/hcaptcha")
        return recaptcha, hcaptcha, widgets.calls

    recaptcha, hcaptcha, calls = asyncio.run(run())

    assert recaptcha.provider == "recaptcha"
    assert hcaptcha.provider == "hcaptcha"
    assert [call["provider"] for call in calls] == ["recaptcha", "hcaptcha"]
    assert calls[0]["browser_binary"] == "/opt/chrome"
    assert calls[0]["proxy_server"] == "http://proxy.test:8080"
    assert calls[0]["use_env_proxy"] is False
    assert calls[0]["timeout_sec"] == 12


def test_solve_batch_preserves_order_bounds_concurrency_and_isolates_errors() -> None:
    async def run():
        client = AntibotClient()
        provider = _ConcurrentTencent()
        client.tencent = provider
        result = await client.solve_batch(
            [
                SolveRequest(
                    target_url="https://example.test/first",
                    provider="tencent",
                    request_id="a",
                ),
                {
                    "url": "https://example.test/fail",
                    "provider": "tencent",
                    "request_id": "b",
                },
                SolveRequest(
                    target_url="https://example.test/raise",
                    provider="tencent",
                    request_id="c",
                ),
                SolveRequest(
                    target_url="https://example.test/slow",
                    provider="tencent",
                    request_id="d",
                    timeout_sec=0.01,
                    options={"delay": 0.1},
                ),
            ],
            concurrency=2,
        )
        return result, provider

    result, provider = asyncio.run(run())

    assert [item.request_id for item in result.items] == ["a", "b", "c", "d"]
    assert result.total == 4
    assert result.succeeded == 1
    assert result.failed == 3
    assert result.ok is False
    assert result.items[0].result.ticket == "first"
    assert result.items[1].errors == ["rejected"]
    assert result.items[2].error_type == "RuntimeError"
    assert result.items[3].error_type == "TimeoutError"
    assert provider.max_active <= 2


def test_solve_batch_accepts_empty_input() -> None:
    result = asyncio.run(AntibotClient().solve_batch([]))

    assert result.ok is True
    assert result.total == 0
    assert result.concurrency == 0


def test_client_forwards_default_browser_binary_to_tencent() -> None:
    async def run():
        client = AntibotClient(browser_binary="/opt/chrome")
        provider = _ConcurrentTencent()
        client.tencent = provider
        await client.solve_tencent(target_url="https://example.test/captcha")
        return provider.calls

    calls = asyncio.run(run())

    assert calls[0]["browser_binary"] == "/opt/chrome"


def test_client_forwards_explicit_environment_proxy_policy() -> None:
    async def run():
        client = AntibotClient(use_env_proxy=False)
        provider = _ConcurrentTencent()
        client.tencent = provider
        await client.solve_tencent(target_url="https://example.test/captcha")
        return provider.calls

    calls = asyncio.run(run())

    assert calls[0]["use_env_proxy"] is False


def test_client_agent_entrypoint_wraps_provider_result_with_harness_trace() -> None:
    async def run():
        client = AntibotClient()
        provider = _ConcurrentTencent()
        client.tencent = provider
        result = await client.solve_agent(
            "https://cloud.tencent.com/product/captcha",
            provider="tencent",
            profile="cloud_product",
        )
        return result, provider.calls

    result, calls = asyncio.run(run())

    assert result.ok is True
    assert calls[0]["profile"] == "cloud_product"
    assert result.diagnostics["harness"]["state"] == "completed"
