import hmac
import hashlib
from fastauth._types import FallbackSecrets


class CSRF:
    @classmethod
    def validate_csrf_token(cls, token: str, secrets: FallbackSecrets) -> bool:
        hmac_hash, message_payload = token.split(".")
        for secret in secrets:
            calculated_hmac = cls.create_hmac(
                secret=secret, message_payload=message_payload
            )
            if hmac.compare_digest(calculated_hmac, hmac_hash):
                return True
        return False

    @classmethod
    def gen_csrf_token(
        cls, jwt_embedded_value: str, collision_value: str, secrets: FallbackSecrets
    ) -> str:
        message_payload = jwt_embedded_value + collision_value
        hmac_hash = cls.create_hmac(
            secret=secrets.secret_1, message_payload=message_payload
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
