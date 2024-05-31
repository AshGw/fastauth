from abc import ABC, abstractmethod
from typing import Optional
from fastauth._types import FallbackSecrets
from fastauth.signin import SignInCallback
from fastauth.config import FastAuthConfig
from fastauth.providers.base import Provider


class OAuth2Base(ABC, FastAuthConfig):
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
        signin_callback: Optional[SignInCallback] = None,
        post_signout_uri: str,
        error_uri: str,
        jwt_max_age: int,
    ) -> None:
        self.provider = provider
        self.signin_uri = signin_uri
        self.signout_uri = signout_url
        self.post_signin_uri = post_signin_uri
        self.post_signout_uri = post_signout_uri
        self.callback_uri = callback_uri
        self.jwt_uri = jwt_uri
        self.csrf_token_uri = csrf_token_uri
        self.error_uri = error_uri
        self.jwt_max_age = jwt_max_age
        self.fallback_secrets = fallback_secrets
        self.signin_callback = signin_callback

    @abstractmethod
    def on_signin(self) -> None:
        ...

    @abstractmethod
    def on_signout(self) -> None:
        ...

    @abstractmethod
    def jwt(self) -> None:
        ...

    @abstractmethod
    def activate(self) -> None:
        ...
