"""
src/api/rest/app.py
===================
FastAPI Application Entrypoint.
Configures CORS, Request ID tracing middleware, Redis sliding-window rate limiting,
and routes for authentication and incident workflows.
"""

import time
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from src.api.rest.middleware.rate_limiter import default_rate_limiter
from src.api.rest.routes.auth import router as auth_router
from src.api.rest.routes.incidents import router as incidents_router
from src.config import settings

logger = structlog.get_logger(__name__)


def create_app() -> FastAPI:
    """
    FastAPI Application Factory.
    """
    app = FastAPI(
        title="AutoSOC REST Gateway",
        description="Autonomous Cyber Incident Response & SOC Co-Pilot API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )

    # 1. CORS Configuration (Allows frontend React/Vue dashboard connectivity)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 2. X-Request-ID and Performance Logging Middleware
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", f"req-{uuid.uuid4().hex[:8]}")
        start_time = time.time()

        # Enforce rate limiting across API endpoints (except docs and health)
        if request.url.path.startswith("/api/"):
            client_ip = request.client.host if request.client else "127.0.0.1"
            is_limited = await default_rate_limiter.is_rate_limited(client_ip)
            if is_limited:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please slow down."},
                    headers={"Retry-After": str(default_rate_limiter.window_seconds)}
                )

        response = await call_next(request)
        process_time_ms = round((time.time() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = str(process_time_ms)

        return response

    # 3. Healthcheck Endpoint
    @app.get("/healthz", tags=["System"])
    async def health_check():
        return {
            "status": "HEALTHY",
            "environment": settings.app_env,
            "version": "0.1.0"
        }

    # 4. Include Routers
    app.include_router(auth_router)
    app.include_router(incidents_router)

    return app


app = create_app()


if __name__ == "__main__":
    import atexit
    import subprocess
    import uvicorn

    def _cleanup_docker():
        try:
            logger.info("stopping_docker_containers")
            subprocess.run(["docker", "compose", "down"], check=False)
        except Exception:
            pass

    atexit.register(_cleanup_docker)
    uvicorn.run(
        "src.api.rest.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )

