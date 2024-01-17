from abc import ABC, abstractmethod
from typing import Mapping, Any, Optional

from fastauth.responses import OAuthRedirectResponse

class Provider(ABC):
    """
    you would inherit from this base class to create your own provider
    """

    response_type = "code"
    grant_type = "authorization_code"

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
    ) -> None: # pragma: no cover
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authorizationUrl = authorizationUrl
        self.tokenUrl = tokenUrl
        self.userInfo = userInfo

    @abstractmethod
    def redirect(
        self, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:
        ...

    @abstractmethod
    def get_access_token(self, *, code_verifier: str, code: str, state: str) ->  Optional[str]:
        ...

    @abstractmethod
    def get_user_info(self, access_token: str) -> Mapping[str,Any]:
        ...
