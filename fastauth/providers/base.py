from abc import ABC, abstractmethod
from typing import Optional, Final
from logging import Logger
from httpx import post, get
from httpx import Response as HttpxResponse
from fastauth.responses import OAuthRedirectResponse
from fastauth.types import UserInfo, QueryParams
from typing import Dict, final


class Provider(ABC):
    """
    you would inherit from this base class to create your own provider
    """

    response_type: Final[str] = "code"
    grant_type: Final[str] = "authorization_code"

    def __init__(
        self,
        *,
        provider: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        authorizationUrl: str,
        tokenUrl: str,
        userInfo: str,
        debug: bool,
        logger: Logger,
    ) -> None:
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authorizationUrl = authorizationUrl
        self.tokenUrl = tokenUrl
        self.userInfo = userInfo
        self.debug = debug
        self.logger = logger

    @abstractmethod
    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:
        ...

    @abstractmethod
    def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:
        ...

    @abstractmethod
    def get_user_info(self, access_token: str) -> Optional[UserInfo]:
        ...

    @final
    def _access_token_request(
        self, *, code_verifier: str, code: str, state: str, **kwargs: str
    ) -> HttpxResponse:
        return post(
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            url=self.tokenUrl,
            data=self._token_request_payload(
                code=code,
                state=state,
                code_verifier=code_verifier,
                **kwargs,
            ),
        )

    @final
    def _user_info_request(self, *, access_token: str) -> HttpxResponse:
        return get(
            url=self.userInfo,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )

    @final
    def _token_request_payload(
        self,
        code: str,
        state: str,
        code_verifier: str,
        **kwargs: str,
    ) -> QueryParams:
        extra_args: Dict[str, str] = {
            key: value for _, (key, value) in enumerate(kwargs.items(), start=1)
        }
        qp: QueryParams = {
            "grant_type": self.grant_type,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "code": code,
            "state": state,
            "code_verifier": code_verifier,
            **extra_args,
        }

        return qp
