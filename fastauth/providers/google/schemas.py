from __future__ import annotations

from fastauth.types import UserInfo, ProviderJSONResponse
from pydantic import BaseModel, EmailStr, HttpUrl, Field
from typing import TypedDict, Literal, Annotated


class GoogleUserInfo(UserInfo, total=False):
    extras: _GoogleUserExtraInfo


class GoogleAccessTokenResponse(BaseModel):
    access_token: str = Field(..., min_length=1)
    expires_in: Annotated[int, "1 hour expressed in seconds"]
    scope: str
    token_type: Literal["Bearer"]
    id_token: str


class GoogleUserJSONData(BaseModel):
    id: Annotated[str, "Represented as a string of integers"] = Field(..., min_length=1)
    email: EmailStr
    verified_email: bool
    name: Annotated[str, "Combo of the given name & family name"] = Field(
        ..., min_length=1
    )
    given_name: str
    family_name: str
    picture: HttpUrl
    locale: str


class _GoogleUserExtraInfo(TypedDict):
    locale: str
    verified_email: bool
    given_name: str
    family_name: str


def serialize_user_info(data: ProviderJSONResponse) -> GoogleUserInfo:
    user_data = GoogleUserJSONData.parse_obj(data)
    return GoogleUserInfo(
        user_id=user_data.id,
        email=user_data.email,
        name=user_data.name,
        avatar=user_data.picture,
        extras=_GoogleUserExtraInfo(
            locale=user_data.locale,
            verified_email=user_data.verified_email,
            given_name=user_data.given_name,
            family_name=user_data.family_name,
        ),
    )


def serialize_access_token(data: ProviderJSONResponse) -> str:
    token_data = GoogleAccessTokenResponse.parse_obj(data)
    return token_data.access_token
