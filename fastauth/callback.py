from logging import Logger
from fastauth.providers.base import Provider
from fastauth.data import CookiesData
from fastauth.cookies import Cookie
from fastauth.utils import auth_cookie_name, gen_csrf_token
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


class _CallbackPrerequisites:
    def __init__(
        self, request: OAuthRequest, state: str, logger: Logger, debug: bool
    ) -> None:
        self.request = request
        self.logger = logger
        self.state = state
        self.debug = debug

    def _is_state_valid(self) -> bool:
        if (
            self.request.cookies.get(
                auth_cookie_name(cookie_name=CookiesData.State.name)
            )
            != self.state
        ):
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        else:
            return True

    def _get_code_verifier(self) -> Optional[str]:
        code_verifier: Optional[str] = self.request.cookies.get(
            auth_cookie_name(cookie_name=CookiesData.Codeverifier.name)
        )
        if code_verifier is None:
            err = CodeVerifierNotFound()
            self.logger.error(err)
            if self.debug:
                raise err
            return None
        else:
            return code_verifier


class Callback(_CallbackPrerequisites):
    def __init__(
        self,
        *,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        secret: str,
        jwt_max_age: int,
        logger: Logger,
        request: OAuthRequest,
        debug: bool,
    ) -> None:
        super().__init__(request, state, logger, debug)
        self.provider = provider
        self.post_signin_uri = post_signin_uri
        self.error_uri = error_uri
        self.code = code
        self.secret = secret
        self.jwt_max_age = jwt_max_age
        self.res = OAuthRedirectResponse(self.post_signin_uri)
        self.cookie = Cookie(request=self.request, response=self.res)

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

    def set_jwt(self, user_info: UserInfo) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=CookiesData.JWT.name),
            value=encipher_user_info(
                user_info=user_info, key=self.secret, exp=self.jwt_max_age
            ),
            httponly=True,
            secure=self.request.url.is_secure,
            path="/",
            samesite="lax",
            max_age=self.jwt_max_age,
        )

    def set_csrf_token(self) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=CookiesData.CSRFToken.name),
            value=gen_csrf_token(),
            httponly=True,
            secure=self.request.url.is_secure,
            path="/",
            samesite="lax",
            max_age=None,
        )

    def __call__(self) -> OAuthRedirectResponse:
        user_info: Optional[UserInfo] = self.get_user_info()
        if not user_info:
            return OAuthRedirectResponse(url=self.error_uri)
        self.set_jwt(user_info=user_info)
        self.set_csrf_token()
        return self.res
