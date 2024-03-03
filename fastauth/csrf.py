import hmac
import hashlib
from os import urandom
from fastauth._types import FallbackSecrets, CSRFToken
from typing import ClassVar, Optional


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
