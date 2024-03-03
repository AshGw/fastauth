import logging

from typing import Optional, final
from fastapi import Request
from fastauth.csrf import CSRF
from typing import Awaitable, Callable
from starlette.responses import Response
from fastauth.const_data import CookieData, StatusCode
from fastauth.utils import name_cookie
from fastauth.config import FastAuthConfig
from fastauth._types import CSRFToken

logger = logging.getLogger("fastauth.adapters.fastapi.csrf")

REASON_NO_CSRF_COOKIE = "CSRF cookie is absent / not set"
REASON_BAD_TOKEN = (
    "CSRF token is incorrect, the received HMAC and the generated one do not match."
)


@final
class CSRFValidationFilter(CSRF, FastAuthConfig):
    def __init__(self, request: Request, response: Response) -> None:
        self.request = request
        self.response = response

    def __call__(self) -> None:
        token = self.get_csrf_token_cookie()
        if not token:
            self.set_csrf_token_cookie()
            return self.reject(reason=REASON_NO_CSRF_COOKIE, request=self.request)
        if not self.validate_csrf_token(token):
            return self.reject(reason=REASON_BAD_TOKEN, request=self.request)
        return self.accept()

    def get_csrf_token_cookie(self) -> Optional[CSRFToken]:
        token = self.request.cookies.get(name_cookie(name=CookieData.CSRFToken.name))
        return CSRFToken(token) if token else None

    # TODO: delegate this to the Cookie class
    def set_csrf_token_cookie(self) -> None:
        self.response.set_cookie(
            key=name_cookie(name=CookieData.CSRFToken.name),
            value=self.gen_csrf_token(),
            max_age=CookieData.CSRFToken.max_age,
            httponly=False,
            secure=self.request.url.is_secure,
            samesite="lax",
            path="/",
            domain=None,
        )

    @classmethod
    def reject(cls, reason: str, request: Request) -> None:
        logger.warning(
            "Forbidden (%s): %s",
            reason,
            request.url,
            extra={
                "status_code": StatusCode.FORBIDDEN,
                "request": request,
            },
        )
        cls.passed_csrf_validation = False

    @classmethod
    def accept(cls) -> None:
        cls.passed_csrf_validation = True


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
