from fastauth.redirect import OAuthRedirect
from fastauth.providers.base import Provider


class MockProvider(Provider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        debug: bool,
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            provider='mock',
            authorizationUrl="https://accounts.exmaple.com/authorize",
            tokenUrl="https://accounts.exmaple.com/api/token",
            userInfo="https://api.exmaple.com/v1/me",
            debug=debug
        )
    def redirect(
        self,*, state: str, code_challenge: str, code_challenge_method: str): # pragma: no cover
        ...

    def get_access_token(self,*, code_verifier: str, code: str, state: str): # pragma: no cover
        ...

    def get_user_info(self,access_token: str): # pragma: no cover
        ...


def test_oauth_redirect_url():
    pv = MockProvider(
        client_id='client_id',
        client_secret="client_secret",
        redirect_uri="https://mysite.com/auth/callback/mock",
        debug = True,
    )
    redirect = OAuthRedirect(
        provider=pv,
        state='state',
        code_challenge='code_challenge',
        code_challenge_method='s256'
    )
    assert redirect.url == 'https://accounts.exmaple.com/authorize?response_type=code&client_id=client_id&redirect_uri=https://mysite.com/auth/callback/mock&state=state&code_challenge=code_challenge&code_challenge_method=s256&'
