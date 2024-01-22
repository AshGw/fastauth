from typing import Optional

from fastauth.providers.base import Provider
from fastauth.data import Cookies
from fastauth.requests import OAuthRequest
from fastauth.responses import OAuthRedirectResponse
from fastauth.utils import (
    auth_cookie_name,
    gen_oauth_params,
    gen_csrf_token
)


class Authorize:
    def __init__(self, *, provider: Provider, request: OAuthRequest) -> None:
        self.provider = provider
        self.request = request
        self.oauth_params = gen_oauth_params()
        self.res = self.provider.redirect(
            state=self.oauth_params.state,
            code_challenge=self.oauth_params.code_challenge,
            code_challenge_method=self.oauth_params.code_challenge_method,
        )

    def _set_cookie(
        self, name: str, value: str, max_age: Optional[int]
    ) -> None:
        self.res.set_cookie(
            key=auth_cookie_name(cookie_name=name),
            value=value,
            max_age=max_age,
            httponly=True,
            samesite="lax",
            secure=self.request.url.is_secure,
            path="/",
        )

    def set_cookies(self) -> None:
        self._set_cookie(
            name=Cookies.State.name,
            value=self.oauth_params.state,
            max_age=Cookies.State.max_age,
        )
        self._set_cookie(
            name=Cookies.Codeverifier.name,
            value=self.oauth_params.code_verifier,
            max_age=Cookies.Codeverifier.max_age,
        )
        self._set_cookie(
            name=Cookies.CSRFToken.name,
            value=gen_csrf_token(),
            max_age=Cookies.CSRFToken.max_age,
        )

    def __call__(self) -> OAuthRedirectResponse:
        self.set_cookies()
        return self.res
