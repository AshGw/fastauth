from typing import Optional
from logging import Logger

from jose.exceptions import JOSEError

from fastauth._types import JWT, ViewableJWT
from fastauth.data import CookiesData
from fastauth.requests import OAuthRequest
from fastauth.responses import OAuthResponse
from fastauth._types import OAuthBaseResponse, FallbackSecrets
from fastauth.cookies import Cookies
from fastauth.jwts.operations import decipher_jwt
from fastauth.data import StatusCode
from fastauth.exceptions import JSONWebTokenTampering


class JWTHandler:
    def __init__(
        self,
        *,
        request: OAuthRequest,
        response: OAuthBaseResponse,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        debug: bool,
    ) -> None:
        self.logger = logger
        self.request = request
        self.fallback_secrets = fallback_secrets
        self.debug = debug
        self.cookie = Cookies(request=request, response=response)

    def get_jwt(self) -> OAuthResponse:
        encrypted_jwt = self._get_jwt_cookie()
        if encrypted_jwt:
            try:
                jwt: JWT = decipher_jwt(
                    encrypted_jwt=encrypted_jwt, fallback_secrets=self.fallback_secrets
                )
                return OAuthResponse(
                    content=ViewableJWT(jwt=jwt), status_code=StatusCode.OK
                )
            except JOSEError as e:
                self._handle_error(e)

        return OAuthResponse(
            content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
        )

    def _get_jwt_cookie(self) -> Optional[str]:  # pragma: no cover
        return self.cookie.get(CookiesData.JWT.name)

    def _handle_error(self, error: JOSEError) -> None:  # pragma: no cover
        err = JSONWebTokenTampering(error=error)
        self.logger.warning(err)
        if self.debug:
            raise err
