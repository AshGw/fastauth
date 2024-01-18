from __future__ import annotations

from fastauth.types import UserInfo
from typing import TypedDict


class GoogleUserJSONData(TypedDict):
    id: str
    email: str
    verified_email: bool
    name: str
    given_name: str
    family_name: str
    picture: str
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
        user_id=data["id"],
        email=data["email"],
        name=data["name"],
        avatar=data["picture"],
        extras=_GoogleUserExtraInfo(
            locale=data["locale"],
            verified_email=data["verified_email"],
            given_name=data["given_name"],
            family_name=data["family_name"],
        ),
    )
