from datetime import datetime, timedelta
from fastauth._types import FallbackSecrets
from fastauth.jwts.operations import (
    encipher_user_info,
    decipher_jwt,
    UserInfo,
    JWT_MAX_AGE,
    ISSUER,
    SUBJECT,
)
from fastauth.jwts.helpers import generate_secret
from dataclasses import dataclass

NOW = datetime.utcnow()


def test_all() -> None:
    data = TestData()
    user_info = UserInfo(
        name=data.name,
        email=data.email,
        user_id=data.user_id,
        avatar=data.avatar,
    )

    encrypted_jwt = encipher_user_info(
        user_info, data.fallback_secrets, data.jwt_max_age
    )

    decrypted_payload = decipher_jwt(encrypted_jwt, data.fallback_secrets)
    assert decrypted_payload["user_info"]["name"] == data.name
    assert decrypted_payload["user_info"]["avatar"] == data.avatar
    assert decrypted_payload["user_info"]["user_id"] == data.user_id
    assert decrypted_payload["user_info"]["email"] == data.email
    assert decrypted_payload["iss"] == data.iss
    assert decrypted_payload["sub"] == data.sub
    assert decrypted_payload["iat"] <= decrypted_payload["exp"]


@dataclass
class TestData:
    __test__ = False
    fallback_secrets = FallbackSecrets(
        secret_1=generate_secret(),
        secret_2=generate_secret(),
        secret_3=generate_secret(),
        secret_4=generate_secret(),
        secret_5=generate_secret(),
    )
    name = "John doe"
    email = "johndoe@example.com"
    user_id = "123"
    avatar = "https://s3.amazonaws.com/bucket/avatar"
    extras = {"extra": "s"}
    iss = ISSUER
    sub = SUBJECT
    iat = NOW
    exp = NOW + timedelta(seconds=JWT_MAX_AGE)
    jwt_max_age = JWT_MAX_AGE
