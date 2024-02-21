from typing import Optional, final

from fastapi import APIRouter, Query
from overrides import override

from fastauth._types import FallbackSecrets
from fastauth.providers.base import Provider
from fastauth.authorize import Authorize
from fastauth.callback import Callback
from fastauth.signout import Signout
from fastauth.adapters.fastapi.response import FastAPIResponse
from fastauth.signin import SignInCallback
from fastauth.oauth2_baseflow import OAuth2Base
from fastauth.adapters.fastapi.request import FastAPIRequest
from fastauth.jwts.handler import JWTHandler


@final
class FastAPIOAuthFlow(OAuth2Base):
    def __init__(
        self,
        *,
        provider: Provider,
        fallback_secrets: FallbackSecrets,
        signin_uri: str,
        signout_url: str,
        callback_uri: str,
        jwt_uri: str,
        csrf_token_uri: str,
        post_signin_uri: str,
        post_signout_uri: str,
        error_uri: str,
        jwt_max_age: int,
        signin_callback: Optional[SignInCallback],
    ) -> None:
        super().__init__(
            provider=provider,
            fallback_secrets=fallback_secrets,
            signin_uri=signin_uri + "/" + provider.provider,
            signout_url=signout_url,
            callback_uri=callback_uri,
            jwt_uri=jwt_uri,
            csrf_token_uri=csrf_token_uri,
            post_signin_uri=post_signin_uri,
            signin_callback=signin_callback,
            post_signout_uri=post_signout_uri,
            error_uri=error_uri,
            jwt_max_age=jwt_max_age,
        )

    @property
    def router(self) -> APIRouter:
        return self.auth_route

    @override
    def on_signin(self) -> None:
        @self.router.get(self.signin_uri)
        async def authorize(request: FastAPIRequest):  # type:ignore
            # Type is determined at runtime, FastAPIRedirectResponse is the type.
            return Authorize(provider=self.provider, request=request)()

        @self.router.get(self.callback_uri + "/" + self.provider.provider)
        async def callback(  #  type: ignore
            req: FastAPIRequest,
            code: str = Query(...),
            state: str = Query(...),
        ):
            return await Callback(
                framework=self.framework,
                code=code,
                request=req,
                state=state,
                fallback_secrets=self.fallback_secrets,
                debug=self.debug,
                provider=self.provider,
                post_signin_uri=self.post_signin_uri,
                signin_callback=self.signin_callback,
                logger=self.logger,
                error_uri=self.error_uri,
                jwt_max_age=self.jwt_max_age,
            )()

    @override
    def on_signout(self) -> None:
        @self.router.get(self.signout_uri)
        def signout(request: FastAPIRequest):  # type: ignore
            # Type is determined at runtime, FastAPIRedirectResponse is the type.
            return Signout(
                framework=self.framework,
                post_signout_uri=self.post_signout_uri,
                request=request,
                error_uri=self.error_uri,
                logger=self.logger,
                debug=self.debug,
                fallback_secrets=self.fallback_secrets,
            )()

    @override
    def jwt(self) -> None:
        @self.router.get(self.jwt_uri)
        def get_jwt(
            request: FastAPIRequest, response: FastAPIResponse
        ) -> FastAPIResponse:
            return JWTHandler(  # type: ignore # response type is determined at runtime
                framework=self.framework,
                request=request,
                response=response,
                fallback_secrets=self.fallback_secrets,
                logger=self.logger,
                debug=self.debug,
            ).get_jwt()

    @override
    def activate(self) -> None:
        self.on_signin()
        self.jwt()
        self.on_signout()
