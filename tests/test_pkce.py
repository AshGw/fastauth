import pytest

from fastauth.utils import gen_oauth_params
from fastauth._types import OAuthParams
from hashlib import sha256
from base64 import urlsafe_b64encode


@pytest.fixture
def op() -> OAuthParams:
    return gen_oauth_params()


def test_gen_oauth_params(op) -> None:
    assert len(op) == 4
    assert len(op.state) == 128
    assert len(op.code_verifier) == 128
    assert len(op.code_challenge) == 43
    assert op.code_challenge_method == "S256"

    calculated_challenge = urlsafe_b64encode(
        sha256(op.code_verifier.encode("ascii")).digest()
    ).decode("ascii")[:-1]

    assert calculated_challenge == op.code_challenge
