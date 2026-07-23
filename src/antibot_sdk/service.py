import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable

from ._version import __version__
from .capabilities import list_capabilities
from .client import AntibotClient
from .models import SolveRequest
from .profiles import list_profiles
from .runtime import runtime_diagnostics


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    max_concurrency: int = 2
    default_timeout_sec: float = 180.0
    browser_binary: str | None = None
    default_proxy: str | None = None
    use_env_proxy: bool | None = None
    client_options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if self.default_timeout_sec <= 0:
            raise ValueError("default_timeout_sec must be positive")


def _request_options(body: Any) -> dict[str, Any]:
    options = dict(body.options)
    for reserved in ("target_url", "url", "provider"):
        options.pop(reserved, None)
    return options


def create_app(
    settings: ServiceSettings | None = None,
    *,
    client_factory: Callable[[], AntibotClient] | None = None,
):
    """Create the optional FastAPI application without importing FastAPI at SDK import time."""

    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import JSONResponse
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise RuntimeError(
            "The HTTP service requires optional dependencies; "
            "install with `pip install -e '.[service]'` or `uv sync --extra service`"
        ) from exc

    config = settings or ServiceSettings()
    limiter = asyncio.Semaphore(config.max_concurrency)

    class SolveBody(BaseModel):
        target_url: str = Field(min_length=1)
        provider: str = "auto"
        options: dict[str, Any] = Field(default_factory=dict)
        timeout_sec: float | None = Field(default=None, gt=0, le=1800)
        request_id: str | None = None

    class BatchBody(BaseModel):
        requests: list[SolveBody] = Field(min_length=1, max_length=100)
        concurrency: int = Field(default=2, ge=1, le=20)
        default_timeout_sec: float | None = Field(default=None, gt=0, le=1800)

    def make_client() -> AntibotClient:
        if client_factory is not None:
            return client_factory()
        return AntibotClient(
            browser_binary=config.browser_binary,
            default_proxy=config.default_proxy,
            use_env_proxy=config.use_env_proxy,
            **config.client_options,
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with make_client() as client:
            app.state.antibot_client = client
            yield

    app = FastAPI(
        title="antibot-sdk service",
        version=__version__,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        started = time.monotonic()
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        response.headers["x-process-time-ms"] = str(
            int((time.monotonic() - started) * 1000)
        )
        return response

    @app.get("/health/live", tags=["health"])
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health", tags=["health"])
    @app.get("/health/ready", tags=["health"])
    async def health_ready():
        diagnostics = runtime_diagnostics(config.browser_binary)
        status_code = 200 if diagnostics["ready_providers"] else 503
        return JSONResponse(diagnostics, status_code=status_code)

    @app.get("/v1/capabilities", tags=["metadata"])
    async def capabilities() -> dict[str, Any]:
        return list_capabilities()

    @app.get("/v1/profiles", tags=["metadata"])
    async def profiles() -> dict[str, Any]:
        return list_profiles()

    async def execute_solve(body: SolveBody, request: Request, *, use_harness: bool):
        timeout = body.timeout_sec or config.default_timeout_sec
        request_id = body.request_id or request.state.request_id
        try:
            async with limiter:
                method = (
                    request.app.state.antibot_client.solve_agent
                    if use_harness
                    else request.app.state.antibot_client.solve
                )
                operation = method(
                    body.target_url,
                    provider=body.provider,
                    **_request_options(body),
                )
                result = await asyncio.wait_for(operation, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                status_code=504,
                detail={"request_id": request_id, "error": f"timeout after {timeout}s"},
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail={"request_id": request_id, "error": str(exc)},
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "request_id": request_id,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            ) from exc
        return {
            "request_id": request_id,
            "provider": result.provider if hasattr(result, "provider") else "cloudflare",
            "result": result.to_dict(),
        }

    @app.post("/v1/solve", tags=["solve"])
    async def solve(body: SolveBody, request: Request):
        return await execute_solve(body, request, use_harness=False)

    @app.post("/v1/harness/solve", tags=["harness"])
    async def harness_solve(body: SolveBody, request: Request):
        return await execute_solve(body, request, use_harness=True)

    @app.post("/v1/batch", tags=["solve"])
    async def batch(body: BatchBody, request: Request):
        batch_requests = [
            SolveRequest(
                target_url=item.target_url,
                provider=item.provider,
                options=_request_options(item),
                timeout_sec=item.timeout_sec,
                request_id=item.request_id,
            )
            for item in body.requests
        ]
        timeout = body.default_timeout_sec or config.default_timeout_sec
        try:
            async with limiter:
                result = await request.app.state.antibot_client.solve_batch(
                    batch_requests,
                    concurrency=min(body.concurrency, config.max_concurrency),
                    default_timeout_sec=timeout,
                )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return result.to_dict()

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError):
        return JSONResponse(
            status_code=503,
            content={
                "detail": {
                    "request_id": request.state.request_id,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                }
            },
        )

    return app
