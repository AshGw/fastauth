from __future__ import annotations

import logging

from dataclasses import dataclass
from unittest.mock import patch

from fastauth.requests import OAuthRequest
from fastauth.data import CookiesData
from fastauth.utils import name_cookie
from fastauth.cookies import Cookies
from fastauth.jwts.operations import encipher_user_info
from fastauth._types import UserInfo
from fastauth.responses import OAuthResponse


def test_cookies():
    data = _TestData()
    req = OAuthRequest(scope={"type": "http"})
    res = OAuthResponse(content={"": ""})
    cookies = Cookies(request=req, response=res)
    with patch.object(
        Cookies,
        attribute="all",
        new_callable=lambda: {data.jwt_cookie_name: data.encrypted_jwt},
    ):
        assert cookies.all == {data.jwt_cookie_name: data.encrypted_jwt}


@dataclass
class _TestData:
    logger = logging.Logger(__name__)
    debug = False
    jwt_cookie_name = name_cookie(name=CookiesData.JWT.name)
    encrypted_jwt = encipher_user_info(
        user_info=UserInfo(
            avatar="...",
            name="...",
            user_id="...",
            email="...",
        ),
        key="_SECRET_KEY",
    )
