import asyncio

from antibot_sdk.proxy import (
    LocalAnonymizedProxy,
    chromium_proxy_server,
    normalize_proxy_url,
    parse_proxy,
    prepare_chromium_proxy,
    proxy_free_environment,
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


def test_parse_proxy_rejects_unsupported_schemes_and_invalid_ports():
    import pytest

    with pytest.raises(ValueError, match="unsupported proxy scheme"):
        parse_proxy("ftp://example.com:21")
    with pytest.raises(ValueError, match="invalid proxy port"):
        parse_proxy("example.com:70000")


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


def test_proxy_free_environment_removes_implicit_proxy_configuration(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://user:pass@example.com:8080")
    monkeypatch.setenv("NO_PROXY", "localhost")
    monkeypatch.setenv("UNRELATED_SETTING", "kept")

    child_env = proxy_free_environment()

    assert "HTTPS_PROXY" not in child_env
    assert "NO_PROXY" not in child_env
    assert child_env["UNRELATED_SETTING"] == "kept"


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


def test_cloudflare_cookie_helpers():
    from antibot_sdk.providers.cloudflare import (
        compact_network_events,
        cookies_to_header,
        cookie_to_dict,
        summarize_session_cookies,
    )

    cookies = [
        cookie_to_dict({"name": "cf_clearance", "value": "xyz", "domain": ".example.com", "path": "/", "secure": True}),
        cookie_to_dict({"name": "session", "value": "1", "domain": "example.com"}),
        cookie_to_dict({"name": "__cf_bm", "value": "bm", "domain": ".example.com"}),
    ]
    assert cookies_to_header(cookies) == "cf_clearance=xyz; session=1; __cf_bm=bm"
    summary = summarize_session_cookies(cookies)
    assert summary["has_cf_clearance"] is True
    assert summary["cf_clearance_len"] == 3
    assert "cf_clearance" in summary["names"]
    assert any(item["name"] == "__cf_bm" for item in summary["interesting"])

    events = compact_network_events(
        [
            {
                "params": {
                    "type": "XHR",
                    "request": {
                        "url": (
                            "https://user:secret@challenges.cloudflare.com/turnstile/verify"
                            "?token=vendor-secret#fragment"
                        ),
                        "method": "post",
                    },
                }
            },
            {
                "params": {
                    "type": "XHR",
                    "request": {
                        "url": (
                            "https://challenges.cloudflare.com/turnstile/verify"
                            "?token=another-secret"
                        ),
                        "method": "POST",
                    },
                }
            },
        ]
    )
    assert events == [
        {
            "url": "https://challenges.cloudflare.com/turnstile/verify",
            "method": "POST",
            "resource_type": "XHR",
        }
    ]
    assert "secret" not in str(events)


def test_cloudflare_result_json_is_persisted(tmp_path):
    from antibot_sdk.providers.cloudflare import RunResult, persist_run_result

    output = tmp_path / "nested" / "cloudflare.json"
    result = RunResult(ok=True, url="https://example.com", state="clear")

    persist_run_result(result, str(output))

    assert output.is_file()
    assert result.artifacts["output_json"] == str(output.resolve())
    assert '"state": "clear"' in output.read_text(encoding="utf-8")


def test_cloudflare_invalid_viewport_is_a_structured_failure(monkeypatch):
    import asyncio

    import antibot_sdk.providers.cloudflare as cloudflare
    from antibot_sdk.providers.cloudflare import RunnerConfig, run_once

    monkeypatch.setattr(cloudflare, "_PYDOLL_IMPORT_ERROR", None)
    monkeypatch.setattr(cloudflare, "Chrome", object())

    result = asyncio.run(
        run_once(
            RunnerConfig(
                url="https://example.com",
                mode="scrape",
                viewport="not-a-viewport",
            )
        )
    )

    assert result.ok is False
    assert "Invalid browser configuration" in result.errors[0]
