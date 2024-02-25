import logging
from typing import Optional, final
from fastapi import Request
from fastauth.csrf import CSRF
from os import urandom
from typing import Awaitable, Callable
from starlette.responses import Response
from fastauth.const_data import CookieData, StatusCode
from fastauth._types import FallbackSecrets
from fastauth.utils import name_cookie
from fastauth.config import FastAuthConfig


logger = logging.getLogger("fastauth.adapters.fastapi.csrf")

REASON_NO_CSRF_COOKIE = "CSRF cookie is absent / not set"
REASON_BAD_TOKEN = (
    "CSRF token is incorrect, the received HMAC and the generated one do not match."
)


SECRET = "137332f341b7813b88a4a9c44d8a6179"
JWT_EMBEDDED = urandom(16).hex()


@final
class CSRFValidationFilter(CSRF, FastAuthConfig):
    def __init__(
        self, request: Request, response: Response, secrets: FallbackSecrets
    ) -> None:
        self.request = request
        self.response = response
        self.secrets = secrets
        self.jwt_embedded_value = JWT_EMBEDDED
        self.collision_value = urandom(16).hex()

    def __call__(self) -> None:
        token = self.get_csrf_token()
        if token is None:
            self.set_csrf_token_cookie()
            self.reject(reason=REASON_NO_CSRF_COOKIE, request=self.request)
            return
        if not self.validate_csrf_token(token, secrets=self.secrets):
            self.reject(reason=REASON_BAD_TOKEN, request=self.request)
            return
        self.accept()

    def get_csrf_token(self) -> Optional[str]:
        return self.request.cookies.get(name_cookie(name=CookieData.CSRFToken.name))

    def set_csrf_token_cookie(self) -> None:
        self.response.set_cookie(
            key=name_cookie(name=CookieData.CSRFToken.name),
            value=self.gen_csrf_token(
                jwt_embedded_value=self.jwt_embedded_value,
                collision_value=self.collision_value,
                secrets=self.secrets,
            ),
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
                "status_code": StatusCode.NO_CONTENT,
                "request": request,
            },
        )
        cls.passed_csrf_validation = False

    @classmethod
    def accept(cls) -> None:
        cls.passed_csrf_validation = True


from starlette.middleware.base import BaseHTTPMiddleware


@final
class CSRFValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        CSRFValidationFilter(request=request, response=response)()
        return response
