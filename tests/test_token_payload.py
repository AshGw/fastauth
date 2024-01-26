from logging import getLogger, Logger
from .utils import MockProvider

logger = getLogger(__name__)


class _Provider(MockProvider):
    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        client_secret: str,
        debug: bool,
        logger: Logger,
    ):
        super().__init__(
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_secret=client_secret,
            debug=debug,
            logger=logger,
        )

    @property
    def get_token_request_payload(self):
        return self._token_request_payload(
            code="code",
            code_verifier="code_verifier",
            state="state",
            kw1="one",
            kw2="two",
            kw3="three",
        )


def test_base_redirect_url():
    p = _Provider(
        client_id="client_id",
        redirect_uri="https://example.com/redirect",
        client_secret="client_secret",
        debug=True,
        logger=getLogger(__name__),
    )
    assert p.get_token_request_payload == {
        "grant_type": p.grant_type,
        "client_id": p.client_id,
        "client_secret": p.client_secret,
        "redirect_uri": p.redirect_uri,
        "code": "code",
        "state": "state",
        "code_verifier": "code_verifier",
        "kw1": "one",
        "kw2": "two",
        "kw3": "three",
    }
