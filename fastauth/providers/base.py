from abc import ABC, abstractmethod
from functools import wraps
from typing import (
    Dict,
    final,
    Final,
    TypeVar,
    ParamSpec,
    Callable,
    Optional,
)

from httpx import AsyncClient
from starlette.responses import RedirectResponse

from fastauth.adapters.use_response import use_response
from fastauth.utils import querify_kwargs
from fastauth.libtypes import UserInfo, QueryParams, ProviderResponseData, AccessToken
from fastauth.config import FastAuthConfig


_T = TypeVar("_T")
_PSpec = ParamSpec("_PSpec")


class Provider(ABC, FastAuthConfig):
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
    ) -> None:
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authorizationUrl = authorizationUrl
        self.tokenUrl = tokenUrl
        self.userInfo = userInfo

    @abstractmethod
    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> RedirectResponse:
        ...

    @abstractmethod
    async def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[AccessToken]:
        ...

    @abstractmethod
    async def get_user_info(self, access_token: str) -> Optional[UserInfo]:
        ...

    @final
    def _grant_redirect(
        self,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
        **kwargs: str,
    ) -> RedirectResponse:
        # private as it's only here for testing it serves no other purpose
        self._grant_redirect_url = self._create_grant_uri(
            response_type=self.response_type,
            authorizationUrl=self.authorizationUrl,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            kwargs=kwargs,
        )
        self.redirect_response = use_response(response_type="redirect")
        return self.redirect_response(url=self._grant_redirect_url)  # type: ignore

    @final
    async def _request_access_token(
        self, *, code_verifier: str, code: str, state: str, **kwargs: str
    ) -> ProviderResponseData:
        async with AsyncClient() as client:
            res = await client.post(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                url=self.tokenUrl,
                data=self._token_request_payload(
                    code=code,
                    state=state,
                    code_verifier=code_verifier,
                    **kwargs,
                ),
            )
            return ProviderResponseData(
                status_code=res.status_code, json=res.json(), text=res.text
            )

    @final
    async def _request_user_info(self, *, access_token: str) -> ProviderResponseData:
        async with AsyncClient() as client:
            res = await client.get(
                url=self.userInfo,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )
            return ProviderResponseData(
                status_code=res.status_code, json=res.json(), text=res.text
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

    @final
    @staticmethod
    def _create_grant_uri(
        *,
        response_type: str,
        authorizationUrl: str,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
        kwargs: QueryParams,
    ) -> str:
        return (
            f"{authorizationUrl}?"
            f"response_type={response_type}"
            f"&client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
            f"&code_challenge={code_challenge}"
            f"&code_challenge_method={code_challenge_method}"
            f"{querify_kwargs(kwargs)}"
        )


def log_action(f: Callable[_PSpec, _T]) -> Callable[_PSpec, _T]:  # pragma: no cover
    @wraps(f)
    def wrap(*args: _PSpec.args, **kwargs: _PSpec.kwargs) -> _T:
        provider = next((arg for arg in args if isinstance(arg, Provider)), None)
        if not provider:
            raise RuntimeError(
                f"{f.__qualname__}: Can only log members of the {Provider} class"
            )
        if f.__name__ == provider.authorize.__name__:
            provider.logger.debug(
                f"Redirecting the client to the resource owner via"
                f" {provider.provider} authorization server"
            )
            return f(*args, **kwargs)

        if f.__name__ == provider.get_access_token.__name__:
            provider.logger.debug(
                f"Requesting the access token from {provider.provider} "
                f"authorization server"
            )
            return f(*args, **kwargs)

        if f.__name__ == provider.get_user_info.__name__:
            provider.logger.debug(
                f"Requesting user information from {provider.provider} "
                f"resource server"
            )
            return f(*args, **kwargs)
        raise RuntimeError(
            f"{f.__qualname__}: No logging implementation was found for this method"
        )

    return wrap
