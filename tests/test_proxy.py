import asyncio

from antibot_sdk.proxy import (
    LocalAnonymizedProxy,
    chromium_proxy_server,
    normalize_proxy_url,
    parse_proxy,
    prepare_chromium_proxy,
    redacted_proxy,
    resolve_runtime_proxy,
)


def test_parse_host_port_user_pass_proxy_pool_format():
    cfg = parse_proxy("1.2.3.4:18081:user:p@ss:with:colon")
    assert cfg is not None
    assert cfg.scheme == "http"
    assert cfg.host == "1.2.3.4"
    assert cfg.port == 18081
    assert cfg.username == "user"
    assert cfg.password == "p@ss:with:colon"
    assert cfg.server == "http://1.2.3.4:18081"
    assert normalize_proxy_url("1.2.3.4:18081:user:p@ss:with:colon").startswith(
        "http://user:"
    )
    assert redacted_proxy("1.2.3.4:18081:user:p@ss") == "http://***:***@1.2.3.4:18081"


def test_parse_standard_proxy_url():
    cfg = parse_proxy("http://alice:s3cr%3Aet@example.com:8080")
    assert cfg is not None
    assert cfg.playwright() == {
        "server": "http://example.com:8080",
        "username": "alice",
        "password": "s3cr:et",
    }


def test_chromium_proxy_server_strips_auth():
    assert chromium_proxy_server("http://user:pass@1.2.3.4:8080") == "http://1.2.3.4:8080"
    assert chromium_proxy_server("socks5://user:pass@1.2.3.4:1090") == "socks5://1.2.3.4:1090"
    assert chromium_proxy_server("http://1.2.3.4:8080") == "http://1.2.3.4:8080"


def test_resolve_runtime_proxy_explicit_and_env(monkeypatch):
    monkeypatch.delenv("ANTIBOT_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("ANTIBOT_USE_ENV_PROXY", raising=False)

    assert resolve_runtime_proxy(None) is None
    explicit = resolve_runtime_proxy("http://u:p@10.0.0.1:8080")
    assert explicit is not None
    assert explicit.host == "10.0.0.1"

    monkeypatch.setenv("ANTIBOT_PROXY", "socks5://u:p@10.0.0.2:1090")
    assert resolve_runtime_proxy(None) is None  # opt-in only
    env_cfg = resolve_runtime_proxy(None, use_env=True)
    assert env_cfg is not None
    assert env_cfg.scheme == "socks5"
    assert env_cfg.port == 1090


def test_prepare_chromium_proxy_direct_no_auth():
    server, bridge, diag = asyncio.run(prepare_chromium_proxy("http://1.2.3.4:8080"))
    assert server == "http://1.2.3.4:8080"
    assert bridge is None
    assert diag["mode"] == "direct"


def test_local_anonymized_proxy_skips_bridge_without_auth():
    bridge = LocalAnonymizedProxy("http://1.2.3.4:8080")

    async def _run():
        local = await bridge.start()
        assert local == "http://1.2.3.4:8080"
        await bridge.close()

    asyncio.run(_run())
