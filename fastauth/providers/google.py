from typing import Optional

from fastauth.exceptions import InvalidAccessToken
from fastauth.providers.base import Provider
from fastauth.data import OAuthURLs
from fastauth.responses import OAuthRedirectResponse
from fastauth.redirect import OAuthRedirect
from fastauth.utils import tokenUrl_payload
from httpx import post, get


class Google(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorizationUrl=OAuthURLs.Google.authorizationUrl,
            tokenUrl=OAuthURLs.Google.tokenUrl,
            userInfo=OAuthURLs.Google.userInfo,
            provider=OAuthURLs.Google.__name__.lower(),
        )

    def redirect(
        self, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:
        return OAuthRedirect(
            provider=self,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope="openid%20profile%20email",
            service="lso",
            access_type="offline",
            flowName="GeneralOAuthFlow",
        )()

    def get_access_token(self, *, code_verifier: str, code: str, state: str) -> Optional[str]:
        token_response = post(
            url=self.tokenUrl,
            data=tokenUrl_payload(
                provider=self,
                code=code,
                state=state,
                code_verifier=code_verifier,
            ),
        )
        if token_response.status_code not in {200, 201}:
            raise InvalidAccessToken()
        access_token: Optional[str] = token_response.json().get("access_token")
        return access_token

    def get_user_info(self, access_token: str) -> dict:
        user_info = get(
            url=self.userInfo,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        return user_info.json()
