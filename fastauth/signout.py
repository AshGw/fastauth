from logging import Logger
from typing import List
from fastauth.const_data import CookieData, StatusCode
from fastauth._types import FallbackSecrets
from fastauth.cookies import Cookies
from fastauth.adapters.response import FastAuthRedirectResponse
from fastauth.adapters.fastapi.response import FastAPIRedirectResponse
from fastauth.adapters.request import FastAuthRequest
from fastauth.jwts.operations import decipher_jwt
from fastauth.exceptions import JSONWebTokenTampering
from jose.exceptions import JWTError


class Signout:
    def __init__(
        self,
        *,
        post_signout_uri: str,
        request: FastAuthRequest,
        fallback_secrets: FallbackSecrets,
        error_uri: str,
        logger: Logger,
        debug: bool,
    ):
        self.post_signout_uri = post_signout_uri
        self.error_uri = error_uri
        self.request = request
        self.fallback_secrets = fallback_secrets
        self.logger = logger
        self.debug = debug
        self.__base_url = request.slashless_base_url()
        self.success_response = FastAPIRedirectResponse(
            url=self.__base_url + self.post_signout_uri
        )
        self.failure_response = FastAPIRedirectResponse(
            url=self.__base_url + self.error_uri, status_code=StatusCode.BAD_REQUEST
        )
        self.cookie = Cookies(request=request, response=self.success_response)

    def __call__(self) -> FastAuthRedirectResponse:
        encrypted_jwt = self.cookie.get(CookieData.JWT.name)
        if encrypted_jwt:
            try:
                decipher_jwt(
                    encrypted_jwt=encrypted_jwt, fallback_secrets=self.fallback_secrets
                )
            except JWTError as e:
                error = JSONWebTokenTampering(error=e)
                self.logger.warning(error)
                if self.debug:
                    raise error
                return self.failure_response

        cookies: List[str] = [
            CookieData.State.name,
            CookieData.Codeverifier.name,
            CookieData.JWT.name,
            CookieData.CSRFToken.name,
        ]
        for cookie in cookies:
            self.cookie.delete(
                key=cookie,
            )
        return self.success_response
