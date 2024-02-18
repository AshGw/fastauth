from jose.jwt import encode as encode_jwt
from jose.jwt import decode as decode_jwt
from jose.exceptions import JOSEError
from jose.jwt import ALGORITHMS
from jose.jwe import encrypt, decrypt
from datetime import datetime, timedelta
from fastauth.data import CookiesData
from fastauth.jwts.helpers import validate_secret_key
from fastauth._types import JWT, UserInfo, FallbackSecrets
from typing import Optional, Final

_JWT_MAX_AGE: Final = CookiesData.JWT.max_age
_JWT_ALGORITHM: Final = ALGORITHMS.HS256
_JWE_ALGORITHM: Final = ALGORITHMS.A256GCM
_ISSUER: Final = "fastauth"
_SUBJECT: Final = "client"


def encipher_user_info(
    user_info: UserInfo,
    fallback_secrets: FallbackSecrets,
    max_age: int = _JWT_MAX_AGE,
) -> str:
    now = datetime.utcnow()
    e: Optional[JOSEError] = None
    for secret in fallback_secrets:
        key = validate_secret_key(secret)
        try:
            plain_jwt: str = encode_jwt(
                claims=JWT(
                    iss=_ISSUER,
                    sub=_SUBJECT,
                    iat=now,
                    exp=now + timedelta(seconds=max_age),
                    user_info=user_info,
                ),
                key=key,
                algorithm=_JWT_ALGORITHM,
            )

            encrypted_jwt: str = (
                encrypt(
                    plaintext=plain_jwt.encode(),
                    key=key,
                    algorithm=ALGORITHMS.DIR,
                    encryption=_JWE_ALGORITHM,
                )
                .rstrip(b"=")
                .decode()
            )

            return encrypted_jwt
        except JOSEError as exc:  # pragma: no cover
            e = exc
    raise (
        e if e is not None else ValueError(e)
    )  # pragma: no cover # the latter never happens


def decipher_jwt(encrypted_jwt: str, fallback_secrets: FallbackSecrets) -> JWT:
    e: Optional[JOSEError] = None
    for secret in fallback_secrets:
        key = validate_secret_key(secret)
        try:
            decrypted_jwt: str = (
                decrypt(jwe_str=encrypted_jwt, key=key).rstrip(b"=").decode()
            )
            jwt: JWT = decode_jwt(
                token=decrypted_jwt,
                key=key,
                algorithms=_JWT_ALGORITHM,
                issuer=_ISSUER,
                subject=_SUBJECT,
            )
            return jwt
        except JOSEError as exc:
            e = exc
    raise e if e is not None else ValueError(e)
