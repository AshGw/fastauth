from .utils import MockProvider
from logging import getLogger

logger = getLogger(__name__)


def test_base_redirect_url():
    mp = MockProvider(
        client_id="client_id",
        client_secret="client_secret",
        redirect_uri="https://example.com",
        debug=True,
        logger=logger,
    )
    payload = mp._token_request_payload(
        code="code",
        code_verifier="code_verifier",
        state="state",
        service="exampleService",
        access_type="offline",
        scope="openid%20profile%20email",
    )
    assert payload == {
        "access_type": "offline",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "code": "code",
        "code_verifier": "code_verifier",
        "grant_type": "authorization_code",
        "redirect_uri": "https://example.com",
        "scope": "openid%20profile%20email",
        "service": "exampleService",
        "state": "state",
    }
