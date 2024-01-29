from logging import Logger
from fastauth.providers.base import Provider
from fastauth.authorize import Authorize
from fastauth.callback import Callback
from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from fastauth.oauth2.base import OAuth2Base
from fastauth.data import CookiesData
from fastauth.log import logger as authlogger
from typing import Annotated


class OAuth2(OAuth2Base):
    def __init__(
        self,
        *,
        provider: Provider,
        secret: str,
        debug: bool = False,
        signin_uri: str = "/auth/signin",
        signout_url: str = "/auth/signout",
        callback_uri: str = "/auth/callback",
        jwt_uri: str = "/auth/jwt",
        csrf_token_uri: str = "/auth/csrf-token",
        post_signin_uri: str = "/",  # must be modified by the user
        post_signout_uri: str = "/",  # must be modified by the user
        error_uri: str = "/",  # must be modified by the user
        jwt_max_age: int = CookiesData.JWT.max_age,
        logger: Logger = authlogger,
    ) -> None:
        super().__init__(
            provider=provider,
            secret=secret,
            debug=debug,
            signin_uri=signin_uri + "/" + provider.provider,
            signout_url=signout_url,
            callback_uri=callback_uri,
            jwt_uri=jwt_uri,
            csrf_token_uri=csrf_token_uri,
            post_signin_uri=post_signin_uri,
            post_signout_uri=post_signout_uri,
            error_uri=error_uri,
            jwt_max_age=jwt_max_age,
            logger=logger,
        )

    def on_signin(self) -> None:
        @self.auth_route.get(self.signin_uri)
        async def authorize(req: OAuthRequest) -> OAuthRedirectResponse:
            return Authorize(provider=self.provider, request=req)()

        @self.auth_route.get(self.callback_uri + "/" + self.provider.provider)
        async def callback(
            req: OAuthRequest,
            code: Annotated[str, "valid for 15 minutes max"],
            state: Annotated[str, "valid for 15 minutes max"],
        ) -> OAuthRedirectResponse:
            return Callback(
                code=code,
                request=req,
                state=state,
                debug=self.debug,
                provider=self.provider,
                post_signin_uri=self.post_signin_uri,
                secret=self.secret,
                logger=self.logger,
                error_uri=self.error_uri,
                jwt_max_age=self.jwt_max_age,
            )()

    def on_signout(self) -> None:
        ...
