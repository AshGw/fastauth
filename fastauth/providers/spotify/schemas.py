from __future__ import annotations

from fastauth.libtypes import UserInfo, ProviderJSONResponse
from pydantic import BaseModel, EmailStr, HttpUrl, Field, Extra
from typing import Literal, Annotated, List, TypedDict


class SpotifyUserInfo(UserInfo):
    extras: _SpotifyUserExtraInfo


class SpotifyUserJSONData(BaseModel, extra=Extra.allow):
    display_name: str
    external_urls: _ExternalURLs
    id: str
    images: List[_ProfileImage]
    type: Annotated[str, "user"]
    email: EmailStr


class SpotifyAccessTokenResponse(BaseModel):
    access_token: str = Field(..., min_length=1)
    token_type: Literal["Bearer"]
    expires_in: Annotated[int, "1 hour expressed in seconds"]
    refresh_token: str
    scope: str


class _SpotifyUserExtraInfo(TypedDict):
    spotify_url: str
    type: str


class _ProfileImage(BaseModel):
    url: HttpUrl
    height: int
    width: int


class _ExternalURLs(BaseModel, extra=Extra.ignore):
    spotify: HttpUrl


def serialize_user_info(data: ProviderJSONResponse) -> SpotifyUserInfo:
    user_data = SpotifyUserJSONData.parse_obj(data)
    if user_data.images and any(user_data.images):
        avatar_url = user_data.images.pop().url  # the second image is just bigger
    else:
        avatar_url = None
    return SpotifyUserInfo(
        user_id=user_data.id,
        email=user_data.email,
        name=user_data.display_name,
        avatar=avatar_url,
        extras=_SpotifyUserExtraInfo(
            spotify_url=user_data.external_urls.spotify, type=user_data.type
        ),
    )


def serialize_access_token(data: ProviderJSONResponse) -> str:
    token_data = SpotifyAccessTokenResponse.parse_obj(data)
    return token_data.access_token
