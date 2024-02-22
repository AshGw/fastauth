from __future__ import annotations

import logging
import pytest

from unittest.mock import patch
from _pytest.monkeypatch import MonkeyPatch

from fastauth.jwts.helpers import generate_secret
from fastauth.adapters.request import FastAuthRequest
from fastauth.jwts.handler import JWTHandler
from fastauth.exceptions import JSONWebTokenTampering, WrongKeyLength
from fastauth.const_data import CookieData
from fastauth.utils import name_cookie
from fastauth.cookies import Cookies
from fastauth.jwts.operations import encipher_user_info
from fastauth._types import UserInfo, ViewableJWT, FallbackSecrets
from fastauth.const_data import StatusCode
from fastauth.adapters.response import FastAuthResponse
from fastauth.frameworks import FastAPI
from fastauth.adapters.use_response import use_response

_secrets = FallbackSecrets(
    secret_1=generate_secret(),
    secret_2=generate_secret(),
    secret_3=generate_secret(),
    secret_4=generate_secret(),
    secret_5=generate_secret(),
)


@pytest.fixture
def testing_framework():
    return FastAPI()


@pytest.fixture
def secrets():
    return _secrets


@pytest.fixture
def invalid_secrets():
    """
    invalid as in not the same ones intended for use
    """
    return FallbackSecrets(
        secret_1=generate_secret(),
        secret_2=generate_secret(),
        secret_3=generate_secret(),
        secret_4=generate_secret(),
        secret_5=generate_secret(),
    )


@pytest.fixture
def invalid_length_secrets():
    return FallbackSecrets(
        secret_1=generate_secret()[:-5],
        secret_2=generate_secret()[:-20],
        secret_3="",
        secret_4=generate_secret() + "abc",
        secret_5=generate_secret(),
    )


@pytest.fixture
def mock_all_cookies(monkeypatch: MonkeyPatch) -> None:
    data = TestData()
    monkeypatch.setattr(
        target=Cookies, name="all", value={data.jwt_cookie_name: data.encrypted_jwt}
    )


@pytest.fixture
def req() -> FastAuthRequest:
    return FastAuthRequest()


@pytest.fixture
def res() -> FastAuthResponse:
    return FastAuthResponse()


@pytest.fixture
def data() -> TestData:
    return TestData()


def test_with_jwt_existence(
    data, mock_all_cookies, req, res, secrets, testing_framework
) -> None:
    cookies = Cookies(request=req, response=res)
    assert cookies.all == {data.jwt_cookie_name: data.encrypted_jwt}
    with patch(
        "fastauth.jwts.handler.JWTHandler._get_jwt_cookie"
    ) as mocked_get_jwt_cookie:
        mocked_get_jwt_cookie.return_value = data.encrypted_jwt
        handler = JWTHandler(
            framework=testing_framework,
            request=req,
            response=res,
            fallback_secrets=secrets,
            debug=True,
            logger=data.logger,
        )
        handler.get_jwt()


def test_with_wrong_jwe_secret(
    data, req, res, invalid_secrets, testing_framework
) -> None:
    with patch(
        "fastauth.jwts.handler.JWTHandler._get_jwt_cookie"
    ) as mocked_get_jwt_cookie:
        mocked_get_jwt_cookie.return_value = data.encrypted_jwt
        with pytest.raises(JSONWebTokenTampering):
            JWTHandler(
                framework=testing_framework,
                request=req,
                response=res,
                fallback_secrets=invalid_secrets,
                debug=True,
                logger=data.logger,
            ).get_jwt()


def test_with_invalid_length_jwe_secret(
    data, req, res, invalid_length_secrets, testing_framework
) -> None:
    with patch(
        "fastauth.jwts.handler.JWTHandler._get_jwt_cookie"
    ) as mocked_get_jwt_cookie:
        mocked_get_jwt_cookie.return_value = data.encrypted_jwt
        with pytest.raises(WrongKeyLength):
            JWTHandler(
                framework=testing_framework,
                request=req,
                response=res,
                fallback_secrets=invalid_length_secrets,
                debug=True,
                logger=data.logger,
            ).get_jwt()


def test_with_altered_jwe(data, req, res, secrets, testing_framework) -> None:
    altered_jwe = data.encrypted_jwt[:-1]  # alter a char
    with patch(
        "fastauth.jwts.handler.JWTHandler._get_jwt_cookie"
    ) as mocked_get_jwt_cookie:
        mocked_get_jwt_cookie.return_value = altered_jwe
        with pytest.raises(JSONWebTokenTampering):
            JWTHandler(
                framework=testing_framework,
                request=req,
                response=res,
                fallback_secrets=secrets,
                debug=True,
                logger=data.logger,
            ).get_jwt()


def test_with_no_jwt(data, req, res, secrets, testing_framework) -> None:
    with patch(
        "fastauth.jwts.handler.JWTHandler._get_jwt_cookie"
    ) as mocked_get_jwt_cookie:
        mocked_get_jwt_cookie.return_value = None
        handler = JWTHandler(
            framework=testing_framework,
            request=req,
            response=res,
            fallback_secrets=secrets,
            debug=True,
            logger=data.logger,
        )
        actual_response = handler.get_jwt()
        JSON_response = use_response(framework=testing_framework, response_type="json")
        expected_response = JSON_response(
            content=ViewableJWT(jwt=None), status_code=StatusCode.UNAUTHORIZED
        )

        assert actual_response.body == expected_response.body
        assert actual_response.status_code == expected_response.status_code


class TestData:
    logger = logging.Logger(__name__)
    jwt_cookie_name = name_cookie(name=CookieData.JWT.name)
    encrypted_jwt = encipher_user_info(
        user_info=UserInfo(
            avatar="...",
            name="...",
            user_id="...",
            email="...",
        ),
        fallback_secrets=_secrets,
    )
