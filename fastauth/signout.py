from logging import Logger
from typing import List
from fastauth.data import CookiesData, StatusCode
from fastauth._types import FallbackSecrets
from fastauth.cookies import Cookies
from fastauth.utils import get_base_url
from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from fastauth.jwts.operations import decipher_jwt
from fastauth.exceptions import JSONWebTokenTampering
from jose.exceptions import JWTError


class Signout:
    def __init__(
        self,
        *,
        post_signout_uri: str,
        request: OAuthRequest,
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
        self.__base_url = get_base_url(request)
        self.success_response = OAuthRedirectResponse(
            url=self.__base_url + self.post_signout_uri
        )
        self.failure_response = OAuthRedirectResponse(
            url=self.__base_url + self.error_uri, status_code=StatusCode.BAD_REQUEST
        )
        self.cookie = Cookies(request=request, response=self.success_response)

    def __call__(self) -> OAuthRedirectResponse:
        encrypted_jwt = self.cookie.get(CookiesData.JWT.name)
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
            CookiesData.State.name,
            CookiesData.Codeverifier.name,
            CookiesData.JWT.name,
            CookiesData.CSRFToken.name,
        ]
        for cookie in cookies:
            self.cookie.delete(
                key=cookie,
            )
        return self.success_response
