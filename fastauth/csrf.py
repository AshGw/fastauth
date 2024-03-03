from __future__ import annotations

import logging
import hmac
import hashlib

from os import urandom
from fastauth._types import FallbackSecrets, CSRFToken
from fastauth.const_data import CookieData, StatusCode
from fastauth.utils import name_cookie
from fastauth.config import FastAuthConfig
from fastauth.adapters.response import FastAuthResponse
from fastauth.adapters.request import FastAuthRequest
from fastauth.cookies import Cookies

from typing import ClassVar, Optional, final

logger = logging.getLogger("fastauth.adapters.fastapi.csrf")


# TODO: make it an actual singleton
class CSRF:
    fallback_secrets: ClassVar[Optional[FallbackSecrets]] = None

    @classmethod
    def init_once(
        cls,
        fallback_secrets: FallbackSecrets,
    ) -> None:
        cls.fallback_secrets = fallback_secrets

    @classmethod
    def validate_csrf_token(cls, token: CSRFToken) -> bool:
        if cls.fallback_secrets is not None:
            hmac_hash, message_payload = token.split(".")
            for secret in cls.fallback_secrets:
                calculated_hmac = cls.create_hmac(
                    secret=secret, message_payload=message_payload
                )
                return hmac.compare_digest(calculated_hmac, hmac_hash)
        return False

    @classmethod
    def gen_csrf_token(cls) -> CSRFToken:
        if cls.fallback_secrets is not None:
            random_value: str = urandom(16).hex()
            message_payload = random_value
            hmac_hash = cls.create_hmac(
                secret=cls.fallback_secrets.secret_1,  # TODO: actually rotate em all
                message_payload=message_payload,
            )
            token = hmac_hash + "." + message_payload
            return CSRFToken(token)
        raise ValueError("JWT embedded value or fallback secrets not set.")

    @staticmethod
    def create_hmac(secret: str, message_payload: str) -> str:
        return hmac.new(
            bytes(secret, "utf-8"),
            bytes(message_payload, "utf-8"),
            hashlib.sha256,
        ).hexdigest()


@final
class CSRFValidationFilter(CSRF, FastAuthConfig):
    def __init__(self, request: FastAuthRequest, response: FastAuthResponse) -> None:
        self.request = request
        self.response = response
        self.c = Cookies(request=request, response=response)

    def __call__(self) -> None:
        token = self.get_csrf_token_cookie()
        if not token:
            self.set_csrf_token_cookie()
            return self.reject(
                reason="CSRF cookie is absent / not set", request=self.request
            )
        if not self.validate_csrf_token(token):
            return self.reject(
                reason="CSRF token is incorrect, the received HMAC"
                " and the generated one do not match.",
                request=self.request,
            )
        return self.accept()

    def get_csrf_token_cookie(self) -> Optional[CSRFToken]:
        token = self.c.get(key=name_cookie(name=CookieData.CSRFToken.name))
        return CSRFToken(token) if token else None

    # TODO: delegate this to the Cookie class
    def set_csrf_token_cookie(self) -> None:
        self.c.set(
            key=name_cookie(name=CookieData.CSRFToken.name),
            value=self.gen_csrf_token(),
            max_age=CookieData.CSRFToken.max_age,
        )

    @classmethod
    def reject(cls, reason: str, request: FastAuthRequest) -> None:
        logger.warning(
            "Forbidden (%s): %s",
            reason,
            request.slashless_base_url(),
            extra={
                "status_code": StatusCode.FORBIDDEN,
                "request": request,
            },
        )
        cls.passed_csrf_validation = False

    @classmethod
    def accept(cls) -> None:
        cls.passed_csrf_validation = True
