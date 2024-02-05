from typing import Optional
from fastauth._types import UserInfo
from fastauth.providers.base import Provider
from fastauth.responses import OAuthRedirectResponse


class MockProvider(Provider):
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
            provider="mock",
            authorizationUrl="https://accounts.exmaple.com/authorize",
            tokenUrl="https://accounts.exmaple.com/api/token",
            userInfo="https://api.exmaple.com/v1/me",
        )

    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:  # pragma: no cover
        return OAuthRedirectResponse("/")

    async def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> Optional[str]:  # pragma: no cover
        _ = await self._request_access_token(
            code_verifier=code_verifier, code=code, state=state
        )
        return "none"

    async def get_user_info(
        self, _access_token: str
    ) -> Optional[UserInfo]:  # pragma: no cover
        _ = await self._request_user_info(access_token=_access_token)
        return UserInfo(user_id="...", name="...", avatar="...", email="...")
