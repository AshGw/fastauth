from __future__ import annotations

from typing import Callable, Awaitable, final
from fastauth.csrf import CSRFValidationFilter
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastauth.adapters.fastapi.request import FastAPIRequest
from fastauth.adapters.fastapi.response import FastAPIResponse


@final
class CSRFMitigationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: FastAPIRequest,  # type: ignore[override]
        call_next: Callable[[FastAPIRequest], Awaitable[FastAPIResponse]],  # type: ignore[override]
    ) -> Response:
        response = await call_next(request)
        CSRFValidationFilter(request=request, response=response)()
        return response
