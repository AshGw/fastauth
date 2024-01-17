from fastauth.utils import gen_oauth_params
from hashlib import sha256
from base64 import urlsafe_b64encode
def test_gen_oauth_params():
    result = gen_oauth_params()
    assert len(result) == 4
    assert len(result.state) == 128
    assert len(result.code_verifier) == 128
    assert len(result.code_challenge) == 43
    assert result.code_challenge_method == "S256"

    calculated_challenge = urlsafe_b64encode(
        sha256(result.code_verifier.encode("ascii")).digest()
    ).decode("ascii")[:-1]

    assert calculated_challenge == result.code_challenge
