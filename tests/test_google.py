import pytest
from unittest.mock import Mock
from unittest.mock import patch

from logging import getLogger
from dotenv import load_dotenv
from os import getenv

from fastauth.providers.google.google import Google
from fastauth.exceptions import InvalidTokenAquisitionRequest, InvalidAccessTokenName
from fastauth.utils import gen_oauth_params

load_dotenv()

google = Google(
    client_id=getenv("GOOGLE_CLIENT_ID"),
    client_secret=getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri=getenv("GOOGLE_REDIRECT_URI"),
    logger=getLogger("..."),
    debug=False,
)
# for debug
google_d_mode = Google(
    client_id=getenv("GOOGLE_CLIENT_ID"),
    client_secret=getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri=getenv("GOOGLE_REDIRECT_URI"),
    logger=getLogger("..."),
    debug=True,
)

OP = gen_oauth_params()

### Debug
...
### Normal


def test_all():
    with patch("fastauth.providers.google.google.Google._access_token_request") as mock_request:
        mock_response = Mock()

        with pytest.raises(InvalidTokenAquisitionRequest): # invalid code before patching
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')

        # simulate success response from Google
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        assert google_d_mode._access_token_request(
            code_verifier="..", code="..", state=".."
        ).status_code == 200
        # If the response is success then we're good
        google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')
        # The access token should not be None, but in some rare cases the actual name
        # of the access_token is  different, sometimes 'accessToken' 'token' etc...
        mock_response.json.return_value = {'accessToken':'valid'}
        mock_request.return_value = mock_response
        with pytest.raises(InvalidAccessTokenName):
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')


def test_two():
    with patch("fastauth.providers.google.google.Google._access_token_request") as mock_request:
        mock_response = Mock()

        with pytest.raises(InvalidTokenAquisitionRequest): # invalid code before patching
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')

        mock_response.json.return_value = {google.access_token_name: "valid"}
        mock_request.return_value = mock_response
        assert google_d_mode._access_token_request(
            code_verifier="..", code="..", state=".."
        ).json() == {google.access_token_name: "valid"}

        with pytest.raises(InvalidTokenAquisitionRequest): # invalid code before patching
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')


### Normal

def test_invalid_authorization_code():
    assert (
        google.get_access_token(
            state=OP.state, code_verifier=OP.code_verifier, code="invalid"
        )
        is None
    )


def test_invalid_access_token():
    user_info = google.get_user_info(access_token="...")
    assert user_info == None
