from uuid import uuid4
from fastauth import utils
from fastauth.types import QueryParams


def test_auth_cookie_name():
    c_name = uuid4().hex
    result = utils.auth_cookie_name(cookie_name=c_name)
    assert result == "fastauth." + c_name


def test_csrf():
    token = utils.gen_csrf_token()
    assert len(token) == 84
    assert isinstance(token, str)


def test_querify_kwargst():
    kwargs: QueryParams = {
        "grant_type": "grant_type",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "redirect_uri": "redirect_uri",
        "extraOne": "one",
    }
    res = utils.querify_kwargs(kwargs)
    assert res == (
        "&client_id=client_id"
        "&client_secret=client_secret"
        "&extraOne=one"
        "&grant_type=grant_type"
        "&redirect_uri=redirect_uri"
    )
    empty_res = utils.querify_kwargs()
    assert empty_res == ""
