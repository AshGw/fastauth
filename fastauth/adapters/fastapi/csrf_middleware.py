from __future__ import annotations

from typing import Callable, Awaitable, final
from fastauth.csrf import CSRFValidationFilter
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware


@final
class CSRFMitigationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        CSRFValidationFilter(request=request, response=response)()
        return response
