from unittest.mock import AsyncMock
import pytest
import pytest
from typing import cast, Dict, Any
from unittest.mock import AsyncMock
from unittest.mock import patch

from dotenv import load_dotenv
from os import getenv


from fastauth.providers.google.google import Google
from fastauth.providers.google.schemas import (
    GoogleUserJSONData,
)
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
    ) as mock_inf_request:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = valid_user_data
        mock_inf_request.return_value = mock_response
        _ = await google._request_user_info(access_token="...")
        json = _.json
        status = _.status_code
        assert json == valid_user_data
        assert status == 200
        Config.debug = True
        _2 = await google.get_user_info(access_token="...")
        xx = _2.keys()
        assert xx == json.keys()
