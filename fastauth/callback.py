from logging import Logger
from fastauth.providers.base import Provider
from fastauth.data import Cookies
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
class Callback:
    def __init__(
        self,
        *,
        provider: Provider,
        post_signin_url: str,
        error_uri: str,
        code: str,
        state: str,
        secret: str,
        jwt_max_age: int,
        logger: Logger,
        req: OAuthRequest,
        debug: bool,
    ):
        self.provider = provider
        self.post_signin_url = post_signin_url
        self.error_uri = error_uri
        self.code = code
        self.state = state
        self.secret = secret
        self.jwt_max_age = jwt_max_age
        self.logger = logger
        self.req = req
        self.debug = debug
        self.res = OAuthRedirectResponse(self.post_signin_url)

    def check_state(self) -> bool:
        if (
            self.req.cookies.get(auth_cookie_name(cookie_name=Cookies.State.name))
            != self.state
        ):
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        else:
            return True

    def get_code_verifier(self) -> Optional[str]:
        code_verifier: Optional[str] = self.req.cookies.get(
                auth_cookie_name(cookie_name=Cookies.Codeverifier.name)
            )
        if (
            code_verifier
            is None
        ):
            err = CodeVerifierNotFound()
            self.logger.error(err)
            if self.debug:
                raise err
            return None
        else:
            return code_verifier

    def get_user_info(self) -> Optional[UserInfo]:
        code_verifier: Optional[str] =  self.get_code_verifier()
        if code_verifier is None:
            return None
        access_token: Optional[str] = self.provider.get_access_token(
            code_verifier=code_verifier, code=self.code, state=self.state
        )
        if access_token is None:
            return None
        user_info: Optional[UserInfo] = self.provider.get_user_info(access_token)
        return user_info

    def set_cookie(self, name: str, value: str) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=name),
            value=value,
            httponly=True,
            secure=self.req.url.is_secure,
            path="/",
            samesite="lax",
            max_age=self.jwt_max_age,
        )

    def set_jwt(self, user_info: UserInfo) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=Cookies.JWT.name),
            value=encipher_user_info(user_info=user_info, key=self.secret, exp=self.jwt_max_age),
            httponly=True,
            secure=self.req.url.is_secure,
            path="/",
            samesite="lax",
            max_age=self.jwt_max_age,
        )

    def set_csrf_token(self) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=Cookies.CSRFToken.name),
            value=gen_csrf_token(),
            httponly=True,
            secure=self.req.url.is_secure,
            path="/",
            samesite="lax",
            max_age=None,
        )

    def redirect(self) -> OAuthRedirectResponse:
        from json import dump

        self.verify_state()
        info = self.get_user_info()
        with open("x.json", "w") as json_file:
            dump(info, json_file, indent=2)
        self.set_jwt(user_info=info)
        self.set_csrf_token()
        return self.res
