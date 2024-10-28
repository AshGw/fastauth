from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastauth.providers.base import Provider
from fastauth.const_data import CookieData
from fastauth.cookies import Cookies
from fastauth.utils import gen_oauth_params


class Authorize:
    def __init__(self, *, provider: Provider, request: Request) -> None:
        self.provider = provider
        self.oauth_params = gen_oauth_params()
        self.grant_redirection_response = self.provider.authorize(
            state=self.oauth_params.state,
            code_challenge=self.oauth_params.code_challenge,
            code_challenge_method=self.oauth_params.code_challenge_method,
        )
        self.cookie = Cookies(request=request, response=self.grant_redirection_response)

    def set_state_cookie(self) -> None:
        self.cookie.set(
            key=CookieData.State.name,
            value=self.oauth_params.state,
            max_age=CookieData.State.max_age,
        )

    def set_code_verifier_cookie(self) -> None:
        self.cookie.set(
            key=CookieData.Codeverifier.name,
            value=self.oauth_params.code_verifier,
            max_age=CookieData.Codeverifier.max_age,
        )

    def __call__(self) -> RedirectResponse:
        self.set_state_cookie()
        self.set_code_verifier_cookie()
        return self.grant_redirection_response
