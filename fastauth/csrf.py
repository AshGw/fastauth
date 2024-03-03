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
        cls.check_classvars()
        hmac_hash, message_payload = token.split(".")
        for secret in cls.fallback_secrets:  # type: ignore  # we know better
            calculated_hmac = cls.create_hmac(
                secret=secret, message_payload=message_payload
            )
            return hmac.compare_digest(calculated_hmac, hmac_hash)
        return False

    @classmethod
    def gen_csrf_token(cls) -> str:
        cls.check_classvars()
        message_payload = cls.jwt_embedded_value + cls.collision_value  # type: ignore
        hmac_hash = cls.create_hmac(
            secret=cls.fallback_secrets.secret_1,
            message_payload=message_payload,  # type: ignore
        )
        token = hmac_hash + "." + message_payload
        return token

    @staticmethod
    def create_hmac(secret: str, message_payload: str) -> str:
        return hmac.new(
            bytes(secret, "utf-8"),
            bytes(message_payload, "utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def classvars_are_set(cls) -> bool:
        if not (
            cls.fallback_secrets
            or cls.collision_value
            or cls.jwt_embedded_value
            or cls.collision_value
        ):
            return False
        return True

    @classmethod
    def check_classvars(cls) -> None:
        if not cls.classvars_are_set():
            raise ValueError
