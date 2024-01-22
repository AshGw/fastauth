from fastauth import utils
from fastauth.types import UserInfo
from fastauth.providers.base import Provider
from fastauth.responses import OAuthRedirectResponse
from logging import getLogger

logger = getLogger("...")


def test_base_redirect_url():
    mp = _MockPovider(
        client_id="client_id",
        client_secret="client_secret",
        redirect_uri="https://example.com",
    )
    ins = _TokenUrlTester(
        mp,
        service="exampleService",
        access_type="offline",
        scope="openid%20profile%20email",
    )
    assert ins.payload() == {
        "grant_type": mp.grant_type,
        "client_id": mp.client_id,
        "client_secret": mp.client_secret,
        "redirect_uri": mp.redirect_uri,
        "access_type": "offline",
        "scope": "openid%20profile%20email",
        "service": "exampleService",
    }


class _MockPovider(Provider):
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
            authorizationUrl="authorizationUrl",
            tokenUrl="https://example.com/token",
            userInfo="https://example.com/info",
            provider="Mock",
            debug=True,
            logger=logger,
        )

    def redirect(
        self, *,state: str, code_challenge: str, code_challenge_method: str
    ) -> OAuthRedirectResponse:
        return OAuthRedirectResponse("/")

    def get_access_token(self, *, code_verifier: str, code: str, state: str) -> str:
        return "none"

    def get_user_info(self, _access_token: str) -> UserInfo:
        return UserInfo(
            user_id='',
            email='',
            name='',
            avatar=''
        )


class _TokenUrlTester:
    def __init__(self, provider: Provider, **kwargs: str):
        self.provider = provider
        self.kwargs = kwargs

    def payload(self):
        return utils.token_request_payload(provider=self.provider, **self.kwargs)
