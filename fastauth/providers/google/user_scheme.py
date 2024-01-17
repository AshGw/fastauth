from fastauth.types import UserInfo
from typing import  TypedDict


class GoogleUserExtraInfo(TypedDict):
    ...

class GoogleUserInfo(UserInfo,total=False):
    extras: GoogleUserExtraInfo
