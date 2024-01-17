from __future__ import annotations
import logging

import pytest
from dataclasses import dataclass
from unittest.mock import patch
from fastauth.jwts.helpers import generate_secret
from fastauth.requests import OAuthRequest
from fastauth.jwts.handler import JWTHandler
from jose.exceptions import JWEError, JWEParseError
from fastauth.data import Cookies
from fastauth.utils import auth_cookie_name
from fastauth.jwts.operations import encipher_user_info
from fastauth.types import UserInfo, ViewableJWT
from fastauth.data import StatusCode
from fastauth.responses import OAuthResponse


_SECRET_KEY = generate_secret()
_SECRET_KEY2 = generate_secret()
def test_with_jwt_existence():
    data = _TestData()
    with patch.object(OAuthRequest,
                      attribute='cookies',
                      new_callable=lambda: {data.jwt_cookie_name: data.encrypted_jwt}
                      ):
        req = OAuthRequest(scope={"type": "http"})
        assert req.cookies == {data.jwt_cookie_name: data.encrypted_jwt}
        handler = JWTHandler(req=req,secret=_SECRET_KEY,debug=True,logger=data.logger)
        handler.get_jwt() #


def test_with_altered_jwe_secret():
    data = _TestData()
    with patch.object(OAuthRequest,
                      attribute='cookies',
                      new_callable=lambda: {data.jwt_cookie_name: data.encrypted_jwt}
                      ):
        req = OAuthRequest(scope={"type": "http"})
        assert req.cookies == {data.jwt_cookie_name: data.encrypted_jwt}
        with pytest.raises(JWEError):
            JWTHandler(req=req, secret=_SECRET_KEY2, debug=True, logger=data.logger).get_jwt()

def test_with_altered_jwe():
    data = _TestData()
    with patch.object(OAuthRequest,
                      attribute='cookies',
                      new_callable=lambda:
                      {data.jwt_cookie_name: data.encrypted_jwt[:-1]} # alter the last char
                      ):
        req = OAuthRequest(scope={"type": "http"})
        assert req.cookies == {data.jwt_cookie_name: data.encrypted_jwt[:-1]}
        with pytest.raises(JWEParseError):
            JWTHandler(req=req, secret=_SECRET_KEY2, debug=True, logger=data.logger).get_jwt()

def test_with_no_jwt():
    data = _TestData()
    with patch.object(OAuthRequest,
                      attribute='cookies',
                      new_callable=lambda: {}
                      ):
        req = OAuthRequest(scope={"type": "http"})
        assert req.cookies.get(data.jwt_cookie_name) == None
        handler = JWTHandler(req=req,secret=_SECRET_KEY,debug=True,logger=data.logger)
        actual_response = handler.get_jwt()
        expected_response = OAuthResponse(content=ViewableJWT(jwt=None),
                                          status_code=StatusCode.UNAUTHORIZED)

        assert actual_response.body == expected_response.body
        assert actual_response.status_code == expected_response.status_code


@dataclass
class _TestData:
    logger = logging.Logger("fastauth")
    debug = False
    jwt_cookie_name= auth_cookie_name(cookie_name=Cookies.JWT.name)
    encrypted_jwt = encipher_user_info(user_info=UserInfo(
        avatar='...',name='...',user_id='...',email='...',
    ),
    key=_SECRET_KEY)
