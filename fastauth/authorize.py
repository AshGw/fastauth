from fastauth.providers.base import Provider
from fastauth.data import CookiesData
from fastauth.cookies import Cookie
from fastauth.requests import OAuthRequest
from fastauth.responses import OAuthRedirectResponse
from fastauth.utils import gen_oauth_params


class Authorize:
    def __init__(self, *, provider: Provider, request: OAuthRequest) -> None:
        self.provider = provider
        self.oauth_params = gen_oauth_params()
        self.response = self.provider.authorize(
            state=self.oauth_params.state,
            code_challenge=self.oauth_params.code_challenge,
            code_challenge_method=self.oauth_params.code_challenge_method,
        )
        self.cookie = Cookie(request=request, response=self.response)

    def set_state_cookie(self) -> None:
        self.cookie.set(
            key=CookiesData.State.name,
            value=self.oauth_params.state,
            max_age=CookiesData.State.max_age,
        )

    def set_code_verifier_cookie(self) -> None:
        self.cookie.set(
            key=CookiesData.Codeverifier.name,
            value=self.oauth_params.code_verifier,
            max_age=CookiesData.Codeverifier.max_age,
        )

    def __call__(self) -> OAuthRedirectResponse:
        self.set_state_cookie()
        self.set_code_verifier_cookie()
        return self.response
