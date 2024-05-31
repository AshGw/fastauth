from logging import Logger

from fastauth.providers.base import Provider
from fastauth.const_data import CookieData
from fastauth.frameworks import Framework
from fastauth.cookies import Cookies
from fastauth.adapters.request import FastAuthRequest
from fastauth.adapters.use_response import use_response
from fastauth.adapters.response import FastAuthResponse
from fastauth._types import FallbackSecrets, AccessToken
from fastauth.jwts.operations import encipher_user_info
from fastauth.signin import SignInCallback, check_signin_signature
from fastauth.exceptions import InvalidState, CodeVerifierNotFound
from fastauth.csrf import CSRF

from fastauth._types import UserInfo
from typing import Optional


class _CallbackCheck:
    def __init__(
        self,
        framework: Framework,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        request: FastAuthRequest,
        jwt_max_age: int,
        signin_callback: Optional[SignInCallback],
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
        __base_url = request.slashless_base_url()
        __response = use_response(framework=framework, response_type="redirect")
        self.success_response = __response(url=__base_url + post_signin_uri)  # type: ignore
        self.error_response = __response(url=__base_url + error_uri)  # type: ignore
        self.cookie = Cookies(request=request, response=self.success_response)

    def _is_state_valid(self) -> bool:
        if self.cookie.get(CookieData.State.name) != self.state:
            err = InvalidState()
            self.logger.error(err)
            if self.debug:
                raise err
            return False
        return True

    def _get_code_verifier(self) -> Optional[str]:
        code_verifier: Optional[str] = self.cookie.get(CookieData.Codeverifier.name)
        if code_verifier is None:
            err = CodeVerifierNotFound()
            self.logger.error(err)
            if self.debug:
                raise err
            return None
        return code_verifier


class Callback(_CallbackCheck):
    def __init__(
        self,
        *,
        framework: Framework,
        provider: Provider,
        post_signin_uri: str,
        error_uri: str,
        code: str,
        state: str,
        fallback_secrets: FallbackSecrets,
        logger: Logger,
        jwt_max_age: int,
        signin_callback: Optional[SignInCallback],
        request: FastAuthRequest,
        debug: bool,
    ) -> None:
        super().__init__(
            framework=framework,
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

    def set_jwt_cookie(self, user_info: UserInfo, max_age: int) -> None:
        self.cookie.set(
            key=CookieData.JWT.name,
            value=encipher_user_info(
                user_info=user_info,
                max_age=max_age,
                fallback_secrets=self.fallback_secrets,
            ),
            max_age=max_age,
        )

    def set_csrf_cookie(self) -> None:
        self.cookie.set(
            key=CookieData.CSRFToken.name,
            value=CSRF.gen_csrf_token(),
            max_age=CookieData.CSRFToken.max_age,
        )

    async def get_user_info(self) -> Optional[UserInfo]:
        valid_state: bool = self._is_state_valid()
        if not valid_state:
            return None
        code_verifier: Optional[str] = self._get_code_verifier()
        if code_verifier is None:
            return None
        access_token: Optional[AccessToken] = await self.provider.get_access_token(
            code_verifier=code_verifier, code=self.code, state=self.state
        )
        if access_token is None:
            return None
        user_info: Optional[UserInfo] = await self.provider.get_user_info(access_token)
        return user_info

    async def __call__(self) -> FastAuthResponse:
        user_info: Optional[UserInfo] = await self.get_user_info()
        if not user_info:
            return self.error_response
        self.set_csrf_cookie()
        self.set_jwt_cookie(user_info=user_info, max_age=self.jwt_max_age)
        if self.signin_callback:
            check_signin_signature(self.signin_callback)
            await self.signin_callback(user_info=user_info)
        return self.success_response
