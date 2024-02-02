from abc import ABC, abstractmethod
from logging import Logger
from fastauth.providers.base import Provider
from fastapi import APIRouter


class OAuth2Base(ABC):
    def __init__(
        self,
        *,
        provider: Provider,
        secret: str,
        debug: bool,
        signin_uri: str,
        signout_url: str,
        callback_uri: str,
        jwt_uri: str,
        csrf_token_uri: str,
        post_signin_uri: str,
        post_signout_uri: str,
        error_uri: str,
        jwt_max_age: int,
        logger: Logger,
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
        self.logger = logger
        self.secret = secret
        self.debug = debug
        self.auth_route = APIRouter()

    @abstractmethod
    def on_signin(self) -> None:
        ...

    @abstractmethod
    def on_signout(self) -> None:
        ...

    @abstractmethod
    @property
    def get_router(self) -> APIRouter:
        ...
