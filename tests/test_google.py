import pytest
from unittest.mock import Mock
from unittest.mock import patch

from logging import getLogger
from dotenv import load_dotenv
from os import getenv

from pydantic.error_wrappers import ValidationError

from fastauth.providers.google.google import Google
from fastauth.providers.google.user_schema import (
    GoogleUserJSONData,
    serialize,
)
from fastauth.exceptions import (
    InvalidTokenAcquisitionRequest,
    InvalidAccessTokenName,
    InvalidResourceAccessRequest,
)
from fastauth.utils import gen_oauth_params

load_dotenv()

google = Google(
    client_id=getenv("GOOGLE_CLIENT_ID"),
    client_secret=getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri=getenv("GOOGLE_REDIRECT_URI"),
    logger=getLogger("..."),
    debug=False,
)
# for debugging
google_d_mode = Google(
    client_id=getenv("GOOGLE_CLIENT_ID"),
    client_secret=getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri=getenv("GOOGLE_REDIRECT_URI"),
    logger=getLogger("..."),
    debug=True,
)

@pytest.fixture
def op():
    return gen_oauth_params()

@pytest.fixture
def JSON_valid_user_data():
    return GoogleUserJSONData(
        email="example@gmail.com",
        verified_email=True,
        given_name="John",
        family_name="Doe",
        picture="https://example.com/hosted/pic",
        locale="en",
        id="123",
        name="John Doe",
    )

def test_token_acquisition(op):
    with patch(
        "fastauth.providers.google.google.Google._access_token_request"
    ) as mock_request:
        mock_response = Mock()
        # invalid auth code, raise in debug
        with pytest.raises(
            InvalidTokenAcquisitionRequest
        ):
            google_d_mode.get_access_token(
                state=op.state, code_verifier=op.code_verifier, code="invalid"
            )

        # simulate success response from Google
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        assert (
            google_d_mode._access_token_request(
                code_verifier="..", code="..", state=".."
            ).status_code
            == 200
        )
        # If the response is successful then we're good

        # though since we're mocking, we need to have a valid access_token name
        mock_response.json.return_value = {google.access_token_name: "valid"}
        google_d_mode.get_access_token(
            state=op.state, code_verifier=op.code_verifier, code="invalid"
        )

        # The access token should not be None, but in some very rare cases the actual name
        # of the access_token is  different, sometimes 'accessToken' 'token' etc...
        mock_response.json.return_value = {"accessToken": "valid"}
        mock_request.return_value = mock_response
        with pytest.raises(InvalidAccessTokenName):
            google_d_mode.get_access_token(
                state=op.state, code_verifier=op.code_verifier, code="invalid"
            )
        # In non debug mode this should just return None:
        assert (
            google.get_access_token(
                state=op.state, code_verifier=op.code_verifier, code="invalid"
            )
            is None
        )


def test_user_info_acquisition(JSON_valid_user_data):
    with patch(
        "fastauth.providers.google.google.Google._user_info_request"
    ) as mock_request:
        mock_response = Mock()

        with pytest.raises(
            InvalidResourceAccessRequest
        ):  # invalid auth code before patching
            google_d_mode.get_user_info(access_token="invalid")
        # in normal mode this should return None
        assert google.get_user_info(access_token="invalid") is None
        # ok how about a success ?
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        assert (
            google_d_mode._user_info_request(access_token="valid_one").status_code
            == 200
        )
        # assert isinstance(google.get_user_info(access_token='invalid'),GoogleUserInfo)
        mock_response.json.return_value = JSON_valid_user_data
        mock_request.return_value = mock_response
        assert google.get_user_info(access_token="valid_one") == serialize(
            google_d_mode._user_info_request(access_token="valid_one").json()
        )

def test_serialize(JSON_valid_user_data):
    # Example data
    valid_data = JSON_valid_user_data
    # Expected result
    expected_result = {
        "user_id": "123",
        "email": "example@gmail.com",
        "name": "John Doe",
        "avatar": "https://example.com/hosted/pic",
        "extras": {
            "locale": "en",
            "verified_email": True,
            "given_name": "John",
            "family_name": "Doe",
        },
    }
    assert serialize(valid_data) == expected_result
    # now if data is invalid e.g avatar is not presented as a URL then

    with pytest.raises(
        ValidationError
    ):
        serialize(GoogleUserJSONData(
        email="example@gmail", # invalid email
        verified_email=True,
        given_name="John",
        family_name="Doe",
        picture="htps://example.com/hosted/pic", # not an actual HTTP(s) URL
        locale="en",
        id="123",
        name="John Doe",
    ))



def test_invalid_authorization_code(op):
    assert (
        google.get_access_token(
            state=op.state, code_verifier=op.code_verifier, code="invalid"
        )
        is None
    )


def test_invalid_access_token():
    user_info = google.get_user_info(access_token="...")
    assert user_info == None
