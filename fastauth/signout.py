from logging import Logger
from typing import List
from fastauth.data import CookiesData, StatusCode
from fastauth.cookies import Cookies
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
        secret: str,
        error_uri: str,
        logger: Logger,
        debug: bool,
    ):
        self.post_signout_uri = post_signout_uri
        self.error_uri = error_uri
        self.request = request
        self.secret = secret
        self.logger = logger
        self.debug = debug
        self.success_response = OAuthRedirectResponse(self.post_signout_uri)
        self.failure_response = OAuthRedirectResponse(
            url=self.error_uri, status_code=StatusCode.BAD_REQUEST
        )
        self.cookie = Cookies(request=request, response=self.success_response)

    def __call__(self) -> OAuthRedirectResponse:
        encrypted_jwt = self.cookie.get(CookiesData.JWT.name)
        if encrypted_jwt:
            try:
                decipher_jwt(encrypted_jwt=encrypted_jwt, key=self.secret)
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
