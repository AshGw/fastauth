from __future__ import annotations

from fastauth.types import UserInfo
from pydantic import BaseModel, EmailStr, HttpUrl, Field
from typing import TypedDict, Annotated, Dict, Any


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


class GoogleUserInfo(UserInfo, total=False):
    extras: _GoogleUserExtraInfo


def serialize(data: Dict[Any, Any]) -> GoogleUserInfo:
    valid_data = GoogleUserJSONData.parse_obj(data)
    return GoogleUserInfo(
        user_id=valid_data.id,
        email=valid_data.email,
        name=valid_data.name,
        avatar=valid_data.picture,
        extras=_GoogleUserExtraInfo(
            locale=valid_data.locale,
            verified_email=valid_data.verified_email,
            given_name=valid_data.given_name,
            family_name=valid_data.family_name,
        ),
    )
