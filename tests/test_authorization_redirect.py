from .utils import MockProvider
from fastauth.config import FastAuthConfig
from fastauth.frameworks import FastAPI


def test_oauth_redirect_url() -> None:
    FastAuthConfig.framework = FastAPI()
    pv = MockProvider(
        client_id="client_id",
        client_secret="client_secret",
        redirect_uri="https://mysite.com/auth/callback/mock",
    )

    pv._grant_redirect(
        state="state",
        code_challenge="code_challenge",
        code_challenge_method="s256",
    )
    assert (
        pv._grant_redirect_url
        == "https://accounts.exmaple.com/authorize?response_type=code&client_id=client_id&redirect_uri=https://mysite.com/auth/callback/mock&state=state&code_challenge=code_challenge&code_challenge_method=s256&"
    )
