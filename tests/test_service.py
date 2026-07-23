from fastapi.testclient import TestClient

from antibot_sdk.client import AntibotClient
from antibot_sdk.models import CaptchaResult
from antibot_sdk.service import ServiceSettings, create_app


class _FakeTencent:
    async def solve(self, *, target_url: str, **kwargs):
        return CaptchaResult(
            provider="tencent",
            ok=True,
            captcha_type="slider",
            capability="solver",
            ticket=target_url.rsplit("/", 1)[-1],
            diagnostics={
                "options": kwargs,
                "tencent_verification_responses": [
                    {"error_code": "0", "accepted": True}
                ],
            },
        )


class _FakeWidgets:
    async def solve(self, *, target_url: str, provider: str, **kwargs):
        return CaptchaResult(
            provider=provider,
            ok=True,
            captcha_type=provider,
            capability="browser_flow",
            ticket=f"{provider}-token",
            diagnostics={"target_url": target_url, "options": kwargs},
        )


def _client_factory() -> AntibotClient:
    client = AntibotClient()
    client.tencent = _FakeTencent()
    client.widgets = _FakeWidgets()
    return client


def test_service_metadata_and_single_solve_contract() -> None:
    app = create_app(
        ServiceSettings(max_concurrency=2, default_timeout_sec=5),
        client_factory=_client_factory,
    )

    with TestClient(app) as http:
        live = http.get("/health/live", headers={"x-request-id": "health-1"})
        capabilities = http.get("/v1/capabilities")
        solved = http.post(
            "/v1/solve",
            headers={"x-request-id": "req-1"},
            json={
                "target_url": "https://example.test/ticket-1",
                "provider": "tencent",
                "options": {"headless": True},
            },
        )

    assert live.status_code == 200
    assert live.headers["x-request-id"] == "health-1"
    assert capabilities.status_code == 200
    assert "solvers" in capabilities.json()
    assert solved.status_code == 200
    assert solved.headers["x-request-id"] == "req-1"
    assert solved.json()["provider"] == "tencent"
    assert solved.json()["result"]["ticket"] == "ticket-1"


def test_service_batch_contract() -> None:
    app = create_app(client_factory=_client_factory)

    with TestClient(app) as http:
        response = http.post(
            "/v1/batch",
            json={
                "concurrency": 2,
                "requests": [
                    {
                        "target_url": "https://example.test/a",
                        "provider": "tencent",
                        "request_id": "a",
                    },
                    {
                        "target_url": "https://example.test/b",
                        "provider": "tencent",
                        "request_id": "b",
                    },
                ],
            },
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["ok"] is True
    assert payload["succeeded"] == 2
    assert [item["request_id"] for item in payload["items"]] == ["a", "b"]


def test_service_routes_explicit_widget_provider() -> None:
    app = create_app(client_factory=_client_factory)

    with TestClient(app) as http:
        response = http.post(
            "/v1/solve",
            json={
                "target_url": "https://example.test/form",
                "provider": "recaptcha",
                "options": {"headless": True, "timeout_sec": 20},
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] == "recaptcha"
    assert payload["result"]["ticket"] == "recaptcha-token"


def test_service_exposes_harness_solve_with_episode_trace() -> None:
    app = create_app(client_factory=_client_factory)

    with TestClient(app) as http:
        response = http.post(
            "/v1/harness/solve",
            json={
                "target_url": "https://example.test/harness-ticket",
                "provider": "tencent",
                "options": {"headless": True},
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] == "tencent"
    assert payload["result"]["ticket"] == "harness-ticket"
    assert payload["result"]["diagnostics"]["harness"]["state"] == "completed"
