import pytest
from typing import cast, Dict, Any
from unittest.mock import AsyncMock
from unittest.mock import patch

from dotenv import load_dotenv
from os import getenv


from fastauth.providers.google.google import Google, SUCCESS_STATUS_CODES
from fastauth.providers.google.schemas import (
    GoogleUserJSONData,
    serialize_user_info,
)
from fastauth.exceptions import (
    InvalidUserInfoAccessRequest,
    SchemaValidationError,
)
from fastauth.utils import gen_oauth_params
from fastauth._types import OAuthParams
from fastauth.config import Config

load_dotenv()

client_id: str = cast(str, getenv("GOOGLE_CLIENT_ID"))
client_secret: str = cast(str, getenv("GOOGLE_CLIENT_SECRET"))
redirect_uri: str = cast(str, getenv("GOOGLE_REDIRECT_URI"))


@pytest.fixture
def google() -> Google:
    return Google(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )


@pytest.fixture
def op() -> OAuthParams:
    return gen_oauth_params()


@pytest.fixture
def valid_user_data() -> Dict[str, Any]:
    return GoogleUserJSONData(
        email="example@gmail.com",  # type: ignore
        verified_email=True,
        given_name="John",
        family_name="Doe",
        picture="https://example.com/hosted/pic",  # type: ignore
        locale="en",
        id="123",
        name="John Doe",
    ).dict()


@pytest.mark.asyncio
async def test_user_info_acquisition(valid_user_data, google) -> None:
    with patch(
        "fastauth.providers.google.google.Google._request_user_info"
    ) as mock_request:
        mock_response = AsyncMock()
        Config.debug = True
        with pytest.raises(
            InvalidUserInfoAccessRequest
        ):  # invalid auth code before patching
            await google.get_user_info(access_token="invalid")
        # in normal mode this should return None
        Config.debug = False
        mock_response.assert_awaited()
        assert google.get_user_info(access_token="invalid") is None
        # ok how about a success ?
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        Config.debug = True
        _ = await google._request_user_info(access_token="valid_one")
        assert _.status_code in SUCCESS_STATUS_CODES

        mock_response.json.return_value = valid_user_data
        mock_request.return_value = mock_response
        Config.debug = False
        _ = await google._request_user_info(access_token="valid_one")
        assert google.get_user_info(access_token="valid_one") == serialize_user_info(
            _.json()
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
            Config.debug = True
            await google.get_user_info(access_token="valid_one")
        # no info if normal
        Config.debug = False
        assert await google.get_user_info(access_token="valid_one") is None


import asyncio
from unittest.mock import AsyncMock


@pytest.fixture(scope="function")
async def mock_http_response(mocker: AsyncMock):
    mock_request = AsyncMock()
    await mocker.patch(
        "fastauth.providers.google.google.Google._request_user_info",
        side_effect=mock_request,
    )
    return mock_request


@pytest.fixture()
def event_loop(google):
    asyncio.run(google._request_user_info(access_token="valid_one"))
    return asyncio.get_event_loop()


@pytest.mark.asyncio
async def test_generate_new_asset(google, mock_http_response):
    Config.debug = True
    mock_http_response.return_value = 12345678
    await google._request_user_info(access_token="valid_one")
