import asyncio
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


class _FakeClient:
    last = None

    def __init__(self, **kwargs) -> None:
        self.tencent = _FakeTencent()
        _FakeClient.last = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


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
