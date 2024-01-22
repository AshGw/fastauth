import pytest
from unittest.mock import Mock
from unittest.mock import patch

from logging import getLogger
from dotenv import load_dotenv
from os import getenv


from fastauth.providers.google.google import Google, SUCCESS_STATUS_CODES
from fastauth.providers.google.schemas import (
    GoogleUserJSONData,
    serialize_user_info,
)
from pydantic import ValidationError
from fastauth.exceptions import (
    InvalidTokenAcquisitionRequest,
    InvalidUserInfoAccessRequest,
    SchemaValidationError,
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
    ).dict()


def test_token_acquisition(op):
    with patch(
        "fastauth.providers.google.google.Google._access_token_request"
    ) as mock_request:
        mock_response = Mock()
        # invalid auth code, raise in debug
        with pytest.raises(InvalidTokenAcquisitionRequest):
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
            in SUCCESS_STATUS_CODES
        )
        # If the response is successful then we're good
        valid_token_response = {
            "access_token": "ya29.--MQ2DXEK727auj8---U4eLDI0g0171",
            "expires_in": 3599,
            "scope": "openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
            "token_type": "Bearer",
            "id_token": "...",
        }
        invalid_token_response = {
            "access_token": "",
            "expires_in": "3599",
            "scope": "openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
            "token_type": "Bearer",
            "id_token": "...",
        }
        # valid access token JSON data should raise no errors
        mock_response.json.return_value = valid_token_response
        google_d_mode.get_access_token(
            state=op.state, code_verifier=op.code_verifier, code="invalid"
        )
        # with invalid access token JSON data should raise in debug
        mock_response.json.return_value = invalid_token_response
        with pytest.raises(SchemaValidationError):
            google_d_mode.get_access_token(
                state=op.state, code_verifier=op.code_verifier, code="invalid"
            )

        # with invalid access token JSON data should return None in normal mode
        mock_response.json.return_value = invalid_token_response
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
            InvalidUserInfoAccessRequest
        ):  # invalid auth code before patching
            google_d_mode.get_user_info(access_token="invalid")
        # in normal mode this should return None
        assert google.get_user_info(access_token="invalid") is None
        # ok how about a success ?
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        assert (
            google_d_mode._user_info_request(access_token="valid_one").status_code
            in SUCCESS_STATUS_CODES
        )

        mock_response.json.return_value = JSON_valid_user_data
        mock_request.return_value = mock_response
        assert google.get_user_info(access_token="valid_one") == serialize_user_info(
            google_d_mode._user_info_request(access_token="valid_one").json()
        )

        # What if in 2077 google changes the way they send their data ?
        mock_response.json.return_value = {
            "id": "123",
            "email": "not@gmail",  #
            "verified_email": True,
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "htps://lh3.googleusercontent.com/a/abc",  # not an valid HTTP(s) URL
            "locale": "en",
        }
        mock_request.return_value = mock_response
        with pytest.raises(SchemaValidationError):  # raise in debug
            google_d_mode.get_user_info(access_token="valid_one")
        # no info if normal
        assert google.get_user_info(access_token="valid_one") is None


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
    assert serialize_user_info(valid_data) == expected_result
    # now if data is invalid e.g avatar is not presented as a URL then

    with pytest.raises(ValidationError):
        serialize_user_info(
            GoogleUserJSONData(
                email="example@gmail",  # invalid email
                verified_email=True,
                given_name="John",
                family_name="Doe",
                picture="htps://example.com/hosted/pic",  # not an actual HTTP(s) URL
                locale="en",
                id="123",
                name="John Doe",
            ).dict()
        )


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
