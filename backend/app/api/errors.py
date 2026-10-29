"""Consistent error envelope: {"error": {"code", "message", "details?"}}."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

log = logging.getLogger("phishguard.api")


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None):
        self.status, self.code, self.message, self.details = status, code, message, details


def _body(code: str, message: str, details=None) -> dict:
    err = {"code": code, "message": message}
    if details is not None:
        err["details"] = details
    return {"error": err}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api(_: Request, exc: APIError):
        return JSONResponse(status_code=exc.status, content=_body(exc.code, exc.message, exc.details))

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Report where/what failed without echoing submitted values (they may contain URLs).
        details = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "issue": e["type"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content=_body("validation_error", "Request body failed validation.", details))

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(status_code=exc.status_code, content=_body(code, str(exc.detail)))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        log.error("Unhandled error", exc_info=True)
        return JSONResponse(status_code=500, content=_body("internal_error", "Unexpected server error."))
