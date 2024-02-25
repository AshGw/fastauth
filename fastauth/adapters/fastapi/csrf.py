import logging
from typing import Optional
from fastapi import Request
import hmac
from os import urandom
from typing import Awaitable, Callable
from starlette.responses import Response
import hashlib
from fastauth.const_data import CookieData, StatusCode
from fastauth.utils import name_cookie
from fastauth.config import FastAuthConfig

import enum

logger = logging.getLogger("fastauth.adapters.fastapi.csrf")

REASON_NO_CSRF_COOKIE = "CSRF cookie is absent / not set"
REASON_BAD_TOKEN = (
    "CSRF token is incorrect, the received HMAC and the generated one do not match."
)


secret = "137332f341b7813b88a4a9c44d8a6179"
jwt_embedded_value = urandom(16).hex()
collision_value = urandom(16).hex()


class _Result(enum.Enum):
    Err = enum.auto()
    Ok = enum.auto()


class CSRFValidationFilter(FastAuthConfig):
    def __init__(self, request: Request, response: Response) -> None:
        self.request = request
        self.response = response

    def __call__(self) -> _Result:
        token = self.get_csrf_token()
        if token is None:
            self.set_csrf_token_cookie()
            return self.reject(reason=REASON_NO_CSRF_COOKIE, request=self.request)
        if not self.validate_csrf_token(token):
            return self.reject(reason=REASON_BAD_TOKEN, request=self.request)
        return self.accept()

    def get_csrf_token(self) -> Optional[str]:
        return self.request.cookies.get(name_cookie(name=CookieData.CSRFToken.name))

    def validate_csrf_token(self, token: str) -> bool:
        hmac_hash, message_payload = token.split(".")
        calculated_hmac = self.create_hmac(
            secret=secret, message_payload=message_payload
        )
        return hmac.compare_digest(calculated_hmac, hmac_hash)

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

    def gen_csrf_token(self) -> str:
        message_payload = jwt_embedded_value + collision_value
        hmac_hash = self.create_hmac(secret=secret, message_payload=message_payload)
        token = hmac_hash + "." + message_payload
        return token

    @staticmethod
    def create_hmac(secret: str, message_payload: str) -> str:
        return hmac.new(
            bytes(secret, "utf-8"),
            bytes(message_payload, "utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def reject(reason: str, request: Request) -> _Result:
        logger.warning(
            "Forbidden (%s): %s",
            reason,
            request.url,
            extra={
                "status_code": StatusCode.NO_CONTENT,
                "request": request,
            },
        )
        return _Result.Err

    @staticmethod
    def accept() -> _Result:
        return _Result.Ok


from starlette.middleware.base import BaseHTTPMiddleware


class CSRFValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        CSRFValidationFilter(request=request, response=response)()
        return response
