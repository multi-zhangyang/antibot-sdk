from antibot_sdk.proxy import normalize_proxy_url, parse_proxy, redacted_proxy


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

