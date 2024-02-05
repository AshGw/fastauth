import pytest
from typing import cast, Dict, Any

from dotenv import load_dotenv
from os import getenv


from fastauth.providers.google.google import Google
from fastauth.providers.google.schemas import (
    GoogleUserJSONData,
    serialize_user_info,
)
from pydantic import ValidationError
from fastauth.exceptions import (
    InvalidUserInfoAccessRequest,
    InvalidTokenAcquisitionRequest,
)
from fastauth.data import StatusCode
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


def test_serialize(valid_user_data) -> None:
    valid_data = valid_user_data
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
                email="example@gmail",  # type: ignore   # invalid email
                verified_email=True,
                given_name="John",
                family_name="Doe",
                picture="htps://example.com/hosted/pic",  # type: ignore   # not an actual HTTP(s) URL
                locale="en",
                id="123",
                name="John Doe",
            ).dict()
        )


@pytest.mark.asyncio
async def test_invalid_authorization_code(op: OAuthParams, google: Google) -> None:
    Config.debug = False
    assert (
        await google.get_access_token(
            state=op.state, code_verifier=op.code_verifier, code="..."
        )
        is None
    )


@pytest.mark.asyncio
async def test_invalid_authorization_code(op: OAuthParams, google: Google) -> None:
    Config.debug = True
    with pytest.raises(InvalidTokenAcquisitionRequest):
        _ = await google.get_access_token(
            state=op.state, code_verifier=op.code_verifier, code="..."
        )


@pytest.mark.asyncio
async def test_is_unauthorized(google):
    result = await google._request_user_info(access_token="...")
    assert result.status_code == StatusCode.UNAUTHORIZED


@pytest.mark.asyncio
async def test_user_info_with_invalid_token(google):
    Config.debug = True
    with pytest.raises(InvalidUserInfoAccessRequest):
        _ = await google.get_user_info(access_token="...")


@pytest.mark.asyncio
async def test_user_info_with_invalid_token(google):
    Config.debug = False
    _ = await google.get_user_info(access_token="...")
    assert _ is None
