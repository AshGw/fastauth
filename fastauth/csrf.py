import hmac
import hashlib
from os import urandom
from fastauth._types import FallbackSecrets
from typing import ClassVar, Optional


def _gen_collision_value() -> str:
    return urandom(16).hex()


class CSRF:
    collision_value: ClassVar[str] = _gen_collision_value()
    fallback_secrets: ClassVar[Optional[FallbackSecrets]] = None
    jwt_embedded_value: ClassVar[Optional[str]] = None

    @classmethod
    def validate_csrf_token(cls, token: str) -> bool:
        if cls.fallback_secrets is not None:
            hmac_hash, message_payload = token.split(".")
            for secret in cls.fallback_secrets:
                calculated_hmac = cls.create_hmac(
                    secret=secret, message_payload=message_payload
                )
                return hmac.compare_digest(calculated_hmac, hmac_hash)
        return False

    @classmethod
    def gen_csrf_token(cls) -> str:
        if cls.jwt_embedded_value is not None and cls.fallback_secrets is not None:
            message_payload = cls.jwt_embedded_value + cls.collision_value
            hmac_hash = cls.create_hmac(
                secret=cls.fallback_secrets.secret_1,
                message_payload=message_payload,
            )
            token = hmac_hash + "." + message_payload
            return token
        raise ValueError("JWT embedded value or fallback secrets not set.")

    @staticmethod
    def create_hmac(secret: str, message_payload: str) -> str:
        return hmac.new(
            bytes(secret, "utf-8"),
            bytes(message_payload, "utf-8"),
            hashlib.sha256,
        ).hexdigest()
