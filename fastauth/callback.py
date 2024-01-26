from logging import Logger
from fastauth.providers.base import Provider
from fastauth.data import CookiesData
from fastauth.cookies import Cookie
from fastauth.utils import name_cookie, gen_csrf_token
from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from fastauth.jwts.operations import encipher_user_info
from fastauth.exceptions import InvalidState, CodeVerifierNotFound

from fastauth.types import UserInfo
from typing import Optional


#  application/x-www-form-urlencoded
#  multipart/form-data
#  text/plain
# text/xml
# application/xml
# application/octet-stream


class _CallbackPrep:
    def __init__(
        self,
        request: OAuthRequest,
        secret: str,
        state: str,
        post_signin_uri: str,
        error_uri: str,
        logger: Logger,
        debug: bool,
    ) -> None:
        self.secret = secret
        self.logger = logger
        self.state = state
        self.debug = debug
        self.success_response = OAuthRedirectResponse(post_signin_uri)
        self.error_response = OAuthRedirectResponse(error_uri)
        self.cookie = Cookie(request=request, response=self.success_response)

    def _is_state_valid(self) -> bool:
        if (
            self.cookie.get(name_cookie(name=CookiesData.State.name))
            != self.state
        ):
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        return True

    def _get_code_verifier(self) -> Optional[str]:
        code_verifier: Optional[str] = self.cookie.get(
            name_cookie(name=CookiesData.Codeverifier.name)
        )
        if code_verifier is None:
            err = CodeVerifierNotFound()
            self.logger.error(err)
            if self.debug:
                raise err
            return None
        return code_verifier

    def set_jwt(self, user_info: UserInfo) -> None:
        max_age: int = CookiesData.JWT.max_age
        self.cookie.set(
            key=name_cookie(name=CookiesData.JWT.name),
            value=encipher_user_info(
                user_info=user_info, key=self.secret, max_age=max_age
            ),
            max_age=max_age,
        )

    def set_csrf_token(self) -> None:
        self.cookie.set(
            key=name_cookie(name=CookiesData.CSRFToken.name),
            value=gen_csrf_token(),
            max_age=CookiesData.CSRFToken.max_age,
        )


class Callback(_CallbackPrep):
    def __init__(
        self,
        *,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        secret: str,
        logger: Logger,
        request: OAuthRequest,
        debug: bool,
    ) -> None:
        super().__init__(
            request=request,
            secret=secret,
            state=state,
            logger=logger,
            debug=debug,
            post_signin_uri=post_signin_uri,
            error_uri=error_uri,
        )
        self.provider = provider
        self.code = code

    def get_user_info(self) -> Optional[UserInfo]:
        valid_state: bool = self._is_state_valid()
        if not valid_state:
            return None
        code_verifier: Optional[str] = self._get_code_verifier()
        if code_verifier is None:
            return None
        access_token: Optional[str] = self.provider.get_access_token(
            code_verifier=code_verifier, code=self.code, state=self.state
        )
        if access_token is None:
            return None
        user_info: Optional[UserInfo] = self.provider.get_user_info(access_token)
        return user_info

    def __call__(self) -> OAuthRedirectResponse:
        user_info: Optional[UserInfo] = self.get_user_info()
        if not user_info:
            return self.error_response
        self.set_jwt(user_info=user_info)
        self.set_csrf_token()
        return self.success_response
