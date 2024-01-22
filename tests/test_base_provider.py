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
    payload = mp._token_request_payload(
        code='code',
        code_verifier='code_verifier',
        state='state',
        service="exampleService",
        access_type="offline",
        scope="openid%20profile%20email",
    )
    assert payload== {
      'access_type': 'offline',
      'client_id': 'client_id',
      'client_secret': 'client_secret',
      'code': 'code',
      'code_verifier': 'code_verifier',
      'grant_type': 'authorization_code',
      'redirect_uri': 'https://example.com',
      'scope': 'openid%20profile%20email',
      'service': 'exampleService',
      'state': 'state',
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
    ) -> OAuthRedirectResponse: # pragma: no cover
        return OAuthRedirectResponse("/")

    def get_access_token(self, *, code_verifier: str, code: str, state: str) -> str:  # pragma: no cover
        return "none"

    def get_user_info(self, _access_token: str) -> UserInfo:  # pragma: no cover
        return UserInfo(
            user_id='',
            email='',
            name='',
            avatar=''
        )
