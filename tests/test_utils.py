from uuid import uuid4
from fastauth import utils

def test_auth_cookie_name():
    c_name = uuid4().hex
    result = utils.auth_cookie_name(cookie_name=c_name)
    assert result == "fastauth." + c_name


def test_gen_oauth_params():
    result = utils.gen_oauth_params()
    assert len(result) == 4
    state, code_verifier, code_challenge, code_challenge_method = result
    assert len(state) == 128
    assert len(code_verifier) == 128
    assert len(code_challenge) == 43
    assert code_challenge_method == "S256"


def test_csrf():
    token = utils.gen_csrf_token()
    assert len(token) == 84
    assert isinstance(token,str)


def test_querify_kwargst():
    res = utils.querify_kwargs({'x':'one','y':'two'})
    assert res == '&x=one&y=two'
    empty_res = utils.querify_kwargs()
    assert empty_res == ''
