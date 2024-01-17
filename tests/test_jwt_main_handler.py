from __future__ import annotations
import logging

import pytest
from dataclasses import dataclass
from unittest.mock import patch
from fastauth.jwts.helpers import generate_secret
from fastauth.requests import OAuthRequest
from fastauth.jwts.handler import JWTHandler
from jose.exceptions import JWEError
from fastauth.data import Cookies
from fastauth.utils import auth_cookie_name
from fastauth.jwts.operations import encipher_user_info
from fastauth.types import UserInfo

SECRET_KEY = generate_secret()
SECRET_KEY2 = generate_secret()
def test_with_jwt_existence():
    data = _TestData()
    with patch.object(_Request,
                      attribute='cookies',
                      new_callable=lambda: {data.jwt_cookie_name: data.encrypted_jwt}
                      ):
        req = _Request(scope={"type": "http"})
        assert req.cookies == {data.jwt_cookie_name: data.encrypted_jwt}
        handler = JWTHandler(req=req,secret=SECRET_KEY,debug=True,logger=data.logger)
        handler.get_jwt() #


def test_with_altered_jwt_secret():
    data = _TestData()
    with patch.object(_Request,
                      attribute='cookies',
                      new_callable=lambda: {data.jwt_cookie_name: data.encrypted_jwt}
                      ):
        req = _Request(scope={"type": "http"})
        assert req.cookies == {data.jwt_cookie_name: data.encrypted_jwt}
        with pytest.raises(JWEError):
            JWTHandler(req=req, secret=SECRET_KEY2, debug=True, logger=data.logger).get_jwt()


class _Request(OAuthRequest):
    @property
    def cookies(self) -> dict:
        return {auth_cookie_name(cookie_name=Cookies.JWT.name):""}


@dataclass
class _TestData:
    logger = logging.Logger("fastauth")
    debug = False
    jwt_cookie_name= auth_cookie_name(cookie_name=Cookies.JWT.name)
    encrypted_jwt = encipher_user_info(user_info=UserInfo(
        avatar='...',name='...',user_id='...',email='...',extras=None
    ),
    key=SECRET_KEY)
