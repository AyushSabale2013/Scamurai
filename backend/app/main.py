"""PhishGuard AI FastAPI application."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.errors import install_error_handlers
from .api.routes import analytics, health, model_info, prediction
from .core.config import get_settings
from .core.logging import configure_logging
from .ml.model_loader import ModelUnavailableError, load_model

log = logging.getLogger("phishguard.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    app.state.model, app.state.model_error = None, None
    try:
        app.state.model = load_model(settings.artifact_dir)  # loaded once, never retrained here
    except ModelUnavailableError as exc:
        app.state.model_error = str(exc)
        log.error("Model not loaded", extra={"fields": {"reason": str(exc)}})
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="PhishGuard AI", version="1.0.0", lifespan=lifespan,
                  description="URL-only phishing risk assessment. Submitted URLs are parsed as strings and never visited.")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def guard_and_log(request: Request, call_next):
        start = time.perf_counter()
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_request_bytes:
            return JSONResponse(status_code=413, content={"error": {"code": "payload_too_large", "message": "Request body is too large."}})
        response = await call_next(request)
        # method, route and status only: never the body or query string
        log.info("request", extra={"fields": {"method": request.method, "path": request.url.path, "status": response.status_code,
                                              "ms": round((time.perf_counter() - start) * 1000, 1)}})
        return response

    install_error_handlers(app)
    for r in (health.router, prediction.router, model_info.router, analytics.router):
        app.include_router(r, prefix="/api")
    return app


app = create_app()
