import pytest
from fastauth.libtypes import QueryParams
from .utils import MockProvider


@pytest.fixture
def p() -> "Provider":
    return Provider(
        client_id="client_id",
        redirect_uri="https://example.com/redirect",
        client_secret="client_secret",
    )


def test_base_redirect_url(p) -> None:
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


class Provider(MockProvider):
    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        client_secret: str,
    ) -> None:
        super().__init__(
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_secret=client_secret,
        )

    @property
    def get_token_request_payload(self) -> QueryParams:
        return self._token_request_payload(
            code="code",
            code_verifier="code_verifier",
            state="state",
            kw1="one",
            kw2="two",
            kw3="three",
        )
