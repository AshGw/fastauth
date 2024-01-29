from typing import Optional
from logging import Logger

from jose.exceptions import JOSEError  # type: ignore

from fastauth._types import JWT, ViewableJWT
from fastauth.data import CookiesData
from fastauth.utils import name_cookie
from fastauth.requests import OAuthRequest
from fastauth.responses import OAuthResponse
from fastauth.cookies import Cookies
from fastauth.jwts.operations import decipher_jwt
from fastauth.data import StatusCode
from fastauth.exceptions import JSONWebTokenTampering


class JWTHandler:
    def __init__(
        self,
        *,
        request: OAuthRequest,
        response: OAuthResponse,
        secret: str,
        logger: Logger,
        debug: bool,
    ) -> None:
        self.logger = logger
        self.request = request
        self.secret = secret
        self.debug = debug
        self.cookie = Cookies(request=request, response=response)

    def get_jwt(self) -> OAuthResponse:
        encrypted_jwt: Optional[str] = self.cookie.get(
            name_cookie(name=CookiesData.JWT.name)
        )
        if encrypted_jwt:
            try:
                jwt: JWT = decipher_jwt(encrypted_jwt=encrypted_jwt, key=self.secret)
                return OAuthResponse(
                    content=ViewableJWT(jwt=jwt), status_code=StatusCode.OK
                )
            except JOSEError as e:
                self._handle_error(e)

        return OAuthResponse(
            content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
        )

    def _handle_error(self, error: JOSEError) -> None:  # pragma: no cover
        err = JSONWebTokenTampering(error=error)
        self.logger.warning(err)
        if self.debug:
            raise err
