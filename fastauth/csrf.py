from __future__ import annotations

import logging
import hmac
import hashlib

from os import urandom

from starlette.requests import Request
from starlette.responses import Response

from fastauth.libtypes import FallbackSecrets, CSRFToken
from fastauth.const_data import CookieData, StatusCode
from fastauth.config import FastAuthConfig
from fastauth.cookies import Cookies
from typing import ClassVar, Optional, final

logger = logging.getLogger("fastauth.adapters.fastapi.csrf")


class CSRF:
    fallback_secrets: ClassVar[Optional[list[str]]] = None
    current_secret_index: ClassVar[int] = 0

    @classmethod
    def init_once(
        cls,
        *,
        fallback_secrets: FallbackSecrets,
    ) -> None:
        cls.fallback_secrets = [secret for secret in fallback_secrets if secret]
        cls.current_secret_index = 0

    @classmethod
    def is_token_valid(cls, *, token: CSRFToken) -> bool:
        if cls.fallback_secrets is not None:
            hmac_hash, message_payload = token.split(".")
            for i in range(len(cls.fallback_secrets)):
                calculated_hmac = cls.create_hmac(
                    secret=cls.fallback_secrets[i], message_payload=message_payload
                )
                if hmac.compare_digest(calculated_hmac, hmac_hash):
                    # Rotate to the next secret
                    cls.current_secret_index = (cls.current_secret_index + 1) % len(
                        cls.fallback_secrets
                    )
                    return True
        return False

    @classmethod
    def gen_csrf_token(cls) -> CSRFToken:
        if cls.fallback_secrets is not None:
            random_value: str = urandom(16).hex()
            message_payload = random_value
            secret = cls.fallback_secrets[
                cls.current_secret_index
            ]  # Use the current secret as default
            hmac_hash = cls.create_hmac(
                secret=secret,
                message_payload=message_payload,
            )
            token = hmac_hash + "." + message_payload
            cls.current_secret_index = (cls.current_secret_index + 1) % len(
                cls.fallback_secrets
            )  # Rotate to the next secret
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
    def __init__(self, request: Request, response: Response) -> None:
        self.request = request
        self.response = response
        self.cookie_handler = Cookies(request=request, response=response)

    def _get_csrf_token_cookie(self) -> Optional[CSRFToken]:
        token = self.cookie_handler.get(CookieData.CSRFToken.name)
        return CSRFToken(token) if token else None

    def _set_csrf_token_cookie(self) -> None:
        self.cookie_handler.set(
            key=CookieData.CSRFToken.name,
            value=CSRF.gen_csrf_token(),
            max_age=CookieData.CSRFToken.max_age,
        )

    def __call__(self) -> None:
        token = self._get_csrf_token_cookie()
        if not token:
            self._set_csrf_token_cookie()
            return self.reject(
                reason="CSRF cookie is absent / not set", request=self.request
            )
        if not self.is_token_valid(token=token):
            return self.reject(
                reason="CSRF token is incorrect, the received HMAC"
                " and the generated one do not match.",
                request=self.request,
            )
        return self.accept()

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
