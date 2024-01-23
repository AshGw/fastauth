from logging import Logger
from fastauth.providers.base import Provider
from fastauth.data import Cookies
from fastauth.utils import auth_cookie_name, gen_csrf_token
from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from fastauth.jwts.operations import encipher_user_info
from fastauth.exceptions import InvalidState, InvalidCodeVerifier


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
        self.max_age = jwt_max_age
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


    def check_code_verifier(self) -> bool:
        """
        Here we check if the cookie holding it has not been deleted somehow
        :return:
        """
        if (
            self.req.cookies.get(auth_cookie_name(cookie_name=Cookies.Codeverifier.name))
            is None
        ):
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        else:
            return True

    def get_user_info(self) -> dict:
        code_verifier: str | None = self.req.cookies.get(
            auth_cookie_name(cookie_name=Cookies.Codeverifier.name)
        )
        if code_verifier is None:
            raise InvalidCodeVerifier()
            # TODO: error redirecting error flow
        access_token = self.provider.get_access_token(
            code_verifier=code_verifier, code=self.code, state=self.state
        )
        return self.provider.get_user_info(access_token)

    def set_cookie(self, name: str, value: str) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=name),
            value=value,
            httponly=True,
            secure=self.req.url.is_secure,
            path="/",
            samesite="lax",
            max_age=self.max_age,
        )

    def set_jwt(self, user_info: dict) -> None:
        self.set_cookie(
            Cookies.JWT.name,
            encipher_user_info(payload=user_info, key=self.secret, exp=self.max_age),
        )

    def set_csrf_token(self) -> None:
        self.set_cookie(Cookies.CSRFToken.name, gen_csrf_token())

    def redirect(self) -> OAuthRedirectResponse:
        from json import dump

        self.verify_state()
        info = self.get_user_info()
        with open("x.json", "w") as json_file:
            dump(info, json_file, indent=2)
        self.set_jwt(user_info=info)
        self.set_csrf_token()
        return self.res
