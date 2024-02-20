from typing import Optional
from logging import Logger

from jose.exceptions import JOSEError


from fastauth.adapters.fastapi.response import FastAPIResponse, FastAPIBaseResponse
from fastauth._types import JWT, ViewableJWT
from fastauth.const_data import CookieData
from fastauth.adapters.request import FastAuthRequest
from fastauth._types import FallbackSecrets
from fastauth.cookies import Cookies
from fastauth.jwts.operations import decipher_jwt
from fastauth.const_data import StatusCode
from fastauth.exceptions import JSONWebTokenTampering


class JWTHandler:
    def __init__(
        self,
        *,
        request: FastAuthRequest,
        response: FastAPIBaseResponse,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        debug: bool,
    ) -> None:
        self.logger = logger
        self.request = request
        self.fallback_secrets = fallback_secrets
        self.debug = debug
        self.cookie = Cookies(request=request, response=response)

    def get_jwt(self) -> FastAPIResponse:
        encrypted_jwt = self._get_jwt_cookie()
        if encrypted_jwt:
            try:
                jwt: JWT = decipher_jwt(
                    encrypted_jwt=encrypted_jwt, fallback_secrets=self.fallback_secrets
                )
                return FastAPIResponse(
                    content=ViewableJWT(jwt=jwt), status_code=StatusCode.OK
                )
            except JOSEError as e:
                self._handle_error(e)

        return FastAPIResponse(
            content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
        )

    def _get_jwt_cookie(self) -> Optional[str]:  # pragma: no cover
        return self.cookie.get(CookieData.JWT.name)

    def _handle_error(self, error: JOSEError) -> None:  # pragma: no cover
        err = JSONWebTokenTampering(error=error)
        self.logger.warning(err)
        if self.debug:
            raise err
