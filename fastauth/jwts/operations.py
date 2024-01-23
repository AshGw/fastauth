from jose.jwt import encode as encode_jwt  # type: ignore
from jose.jwt import decode as decode_jwt
from jose.jwt import ALGORITHMS
from jose.jwe import encrypt, decrypt  # type: ignore
from datetime import datetime, timedelta
from fastauth.data import CookiesData
from fastauth.jwts.helpers import validate_key
from fastauth.types import JWT, UserInfo

JWT_MAX_AGE = CookiesData.JWT.max_age
JWT_ALGORITHM = ALGORITHMS.HS256
JWE_ALGORITHM = ALGORITHMS.A256GCM
ISSUER = "fastauth"
SUBJECT = "client"


def encipher_user_info(user_info: UserInfo, key: str, exp: int = JWT_MAX_AGE) -> str:
    """
    Encrypts a given user-info payload and returns an encrypted JWT.
    :param user_info: The UserInfo payload
    :param key: The secret key for the entire oauth flow
    :param exp: expiry date of jwt
    :raises: JOSEError
    :return: The encrypted JWT
    """
    validate_key(key)
    now = datetime.utcnow()
    plain_jwt: str = encode_jwt(
        claims=JWT(
            iss=ISSUER,
            sub=SUBJECT,
            iat=now,
            exp=now + timedelta(seconds=exp),
            user_info=user_info,
        ),
        key=key[:32],
        algorithm=JWT_ALGORITHM,
    )
    encrypted_jwt: str = (
        encrypt(
            plaintext=plain_jwt.encode(),
            key=key,
            algorithm=ALGORITHMS.DIR,
            encryption=JWE_ALGORITHM,
        )
        .rstrip(b"=")
        .decode()
    )
    return encrypted_jwt


def decipher_jwt(encrypted_jwt: str, key: str) -> JWT:
    """
    Decrypts an encrypted JWT and returns the payload.
    :param encrypted_jwt: The encrypted JWT.
    :param key: The secret key for the entire oauth flow.
    :raises: JOSEError
    :return: JWT
    """
    validate_key(key)
    decrypted_jwt: str = decrypt(jwe_str=encrypted_jwt, key=key).rstrip(b"=").decode()
    jwt: JWT = decode_jwt(
        token=decrypted_jwt,
        key=key[:32],
        algorithms=JWT_ALGORITHM,
        issuer=ISSUER,
        subject=SUBJECT,
    )
    return jwt
