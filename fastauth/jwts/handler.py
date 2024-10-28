from typing import Optional
from logging import Logger

from jose.exceptions import JOSEError
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from fastauth.adapters.use_response import use_response
from fastauth.libtypes import JWT, ViewableJWT
from fastauth.const_data import CookieData
from fastauth.libtypes import FallbackSecrets
from fastauth.cookies import Cookies
from fastauth.jwts.operations import decipher_jwt
from fastauth.const_data import StatusCode
from fastauth.exceptions import JSONWebTokenTampering


class JWTHandler:
    def __init__(
        self,
        *,
        request: Request,
        response: Response,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        debug: bool,
    ) -> None:
        self.logger = logger
        self.request = request
        self.response = response
        self.fallback_secrets = fallback_secrets
        self.debug = debug
        self.cookie = Cookies(request=self.request, response=self.response)
        self.json_response = use_response(response_type="json")

    def get_jwt(self) -> JSONResponse:
        encrypted_jwt = self._get_jwt_cookie()
        if encrypted_jwt:
            try:
                jwt: JWT = decipher_jwt(
                    encrypted_jwt=encrypted_jwt, fallback_secrets=self.fallback_secrets
                )
                return self.json_response(  # type: ignore
                    content=ViewableJWT(jwt=jwt), status_code=StatusCode.OK
                )
            except JOSEError as e:
                self._handle_error(e)

        return self.json_response(  # type: ignore
            content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
        )

    def _get_jwt_cookie(self) -> Optional[str]:  # pragma: no cover
        return self.cookie.get(CookieData.JWT.name)

    def _handle_error(self, error: JOSEError) -> None:  # pragma: no cover
        err = JSONWebTokenTampering(error=error)
        self.logger.warning(err)
        if self.debug:
            raise err
