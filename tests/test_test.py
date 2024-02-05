from unittest.mock import AsyncMock
import pytest
import pytest
from typing import cast, Dict, Any
from unittest.mock import AsyncMock

from dotenv import load_dotenv
from os import getenv


from fastauth.providers.google.google import Google
from fastauth.providers.google.schemas import (
    GoogleUserJSONData,
)

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


@pytest.fixture()
def user_info_request_mocker(mocker):
    async_mock = AsyncMock()
    mocker.patch("fastauth.providers.google.google.Google._request_user_info")
    return async_mock


@pytest.mark.asyncio
async def test_sum(user_info_request_mocker, google, valid_user_data):
    user_info_request_mocker.return_value = valid_user_data
    result = await google._request_user_info(access_token="invalid")
