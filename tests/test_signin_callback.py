import pytest

from fastauth.libtypes import UserInfo
from fastauth.signin import check_signin_signature


@pytest.mark.asyncio
async def test_valid_callback_signature():
    async def valid_callback(user_info: UserInfo) -> None:  # pragma: no cover
        pass

    check_signin_signature(valid_callback)


@pytest.mark.asyncio
async def test_invalid_callback_signature_missing_user_info():
    async def invalid_callback():  # pragma: no cover
        pass

    with pytest.raises(TypeError):
        check_signin_signature(invalid_callback)


@pytest.mark.asyncio
async def test_invalid_callback_signature_wrong_annotation():
    async def invalid_callback(user_info: int):  # pragma: no cover
        pass

    with pytest.raises(TypeError):
        check_signin_signature(invalid_callback)


@pytest.mark.asyncio
async def test_invalid_callback_signature_wrong_param_name():
    async def invalid_callback(user_nfo: UserInfo):  # pragma: no cover
        pass

    with pytest.raises(TypeError):
        check_signin_signature(invalid_callback)
