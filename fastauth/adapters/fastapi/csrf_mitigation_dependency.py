from typing import Optional
from fastapi import Response, Request
import hmac
from os import urandom
from starlette.exceptions import HTTPException
import hashlib
from fastauth.const_data import CookieData
from fastauth.utils import name_cookie


secret = "137332f341b7813b88a4a9c44d8a6179"
jwt_embedded_value = urandom(16).hex()
collision_value = urandom(16).hex()


class CSRFMitigationDependency:
    def __init__(self, request: Request, response: Response) -> None:
        self.request = request
        self.response = response

    def __call__(self):
        csrf_token = self.get_csrf_token()
        if not csrf_token:
            self.set_csrf_token_cookie()
            raise HTTPException(status_code=403, detail="CSRF token is missing")
        if not self.verify_csrf_token(csrf_token):
            raise HTTPException(
                status_code=403, detail="CSRF token verification failed"
            )
        return True

    def get_csrf_token(self) -> Optional[str]:
        return self.request.cookies.get(name_cookie(name=CookieData.CSRFToken.name))

    def verify_csrf_token(self, token: str) -> bool:
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
            secure=True,
            samesite="lax",
            path="/",
            domain=None,
        )

    def gen_csrf_token(self) -> str:
        message_payload = jwt_embedded_value + collision_value
        hmac_hash = self.create_hmac(secret=secret, message_payload=message_payload)
        csrf_token = hmac_hash + "." + message_payload
        return csrf_token

    def create_hmac(self, secret: str, message_payload: str) -> str:
        return hmac.new(
            bytes(secret, "utf-8"),
            bytes(message_payload, "utf-8"),
            hashlib.sha256,
        ).hexdigest()
