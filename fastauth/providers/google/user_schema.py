from __future__ import annotations

from fastauth.types import UserInfo
from pydantic import BaseModel, EmailStr, HttpUrl
from typing import TypedDict, Annotated


class GoogleUserJSONData(BaseModel):
    id: Annotated[str, 'string of integers']
    email: EmailStr
    verified_email: bool
    name: str
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


def serialize(data: GoogleUserJSONData) -> GoogleUserInfo:
    return GoogleUserInfo(
        user_id=data.id,
        email=data.email,
        name=data.name,
        avatar=data.picture,
        extras=_GoogleUserExtraInfo(
            locale=data.locale,
            verified_email=data.verified_email,
            given_name=data.given_name,
            family_name=data.family_name,
        ),
    )
