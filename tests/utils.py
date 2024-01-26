from fastauth._types import UserInfo
from fastauth.providers.base import Provider
from fastauth.responses import OAuthRedirectResponse
from logging import Logger


class MockProvider(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        debug: bool,
        logger: Logger,
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            provider="mock",
            authorizationUrl="https://accounts.exmaple.com/authorize",
            tokenUrl="https://accounts.exmaple.com/api/token",
            userInfo="https://api.exmaple.com/v1/me",
            debug=debug,
            logger=logger,
        )

    def authorize(
        self, *, state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:  # pragma: no cover
        return OAuthRedirectResponse("/")

    def get_access_token(
        self, *, code_verifier: str, code: str, state: str
    ) -> str:  # pragma: no cover
        return "none"

    def get_user_info(self, _access_token: str) -> UserInfo:  # pragma: no cover
        return UserInfo(user_id="", email="", name="", avatar="")
