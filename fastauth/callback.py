from logging import Logger
from fastauth.providers.base import Provider
from fastauth.data import CookiesData
from fastauth.cookies import Cookies
from fastauth.utils import gen_csrf_token, get_base_url
from fastauth.responses import OAuthRedirectResponse
from fastauth.requests import OAuthRequest
from fastauth._types import FallbackSecrets
from fastauth.jwts.operations import encipher_user_info
from fastauth.signin import SignIn
from fastauth.exceptions import InvalidState, CodeVerifierNotFound

from fastauth._types import UserInfo
from typing import Optional


class _CallbackBase:
    def __init__(
        self,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        request: OAuthRequest,
        jwt_max_age: int,
        signin_callback: Optional[SignIn],
        debug: bool,
    ) -> None:
        self.code = code
        self.provider = provider
        self.fallback_secrets = fallback_secrets
        self.logger = logger
        self.state = state
        self.debug = debug
        self.jwt_max_age = jwt_max_age
        self.signin_callback = signin_callback
        self.__base_url = get_base_url(request)
        self.success_response = OAuthRedirectResponse(
            url=self.__base_url + post_signin_uri
        )
        self.error_response = OAuthRedirectResponse(url=self.__base_url + error_uri)
        self.cookie = Cookies(request=request, response=self.success_response)

    def _is_state_valid(self) -> bool:
        if self.cookie.get(CookiesData.State.name) != self.state:
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        return True

    def _get_code_verifier(self) -> Optional[str]:
        code_verifier: Optional[str] = self.cookie.get(CookiesData.Codeverifier.name)
        if code_verifier is None:
            err = CodeVerifierNotFound()
            self.logger.error(err)
            if self.debug:
                raise err
            return None
        return code_verifier

    def set_jwt(self, user_info: UserInfo, max_age: int) -> None:
        self.cookie.set(
            key=CookiesData.JWT.name,
            value=encipher_user_info(
                user_info=user_info,
                max_age=max_age,
                fallback_secrets=self.fallback_secrets,
            ),
            max_age=max_age,
        )

    def set_csrf_token(self) -> None:
        self.cookie.set(
            key=CookiesData.CSRFToken.name,
            value=gen_csrf_token(),
            max_age=CookiesData.CSRFToken.max_age,
        )


class Callback(_CallbackBase):
    def __init__(
        self,
        *,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        jwt_max_age: int,
        signin_callback: Optional[SignIn],
        request: OAuthRequest,
        debug: bool,
    ) -> None:
        super().__init__(
            provider=provider,
            post_signin_uri=post_signin_uri,
            error_uri=error_uri,
            code=code,
            state=state,
            fallback_secrets=fallback_secrets,
            logger=logger,
            jwt_max_age=jwt_max_age,
            signin_callback=signin_callback,
            request=request,
            debug=debug,
        )

    async def get_user_info(self) -> Optional[UserInfo]:
        valid_state: bool = self._is_state_valid()
        if not valid_state:
            return None
        code_verifier: Optional[str] = self._get_code_verifier()
        if code_verifier is None:
            return None
        access_token: Optional[str] = await self.provider.get_access_token(
            code_verifier=code_verifier, code=self.code, state=self.state
        )
        if access_token is None:
            return None
        user_info: Optional[UserInfo] = await self.provider.get_user_info(access_token)
        return user_info

    async def __call__(self) -> OAuthRedirectResponse:
        user_info: Optional[UserInfo] = await self.get_user_info()
        if not user_info:
            return self.error_response
        self.set_jwt(user_info=user_info, max_age=self.jwt_max_age)
        self.set_csrf_token()
        if self.signin_callback:
            await self.signin_callback(user_info=user_info)
        return self.success_response
