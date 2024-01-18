import httpx
import pytest
from unittest.mock import Mock
from unittest.mock import patch

from logging import getLogger
from dotenv import load_dotenv
from os import getenv

from fastauth.providers.google.google import  Google
from fastauth.exceptions import InvalidTokenAquisitionRequest
from fastauth.utils import gen_oauth_params

load_dotenv()

google = Google(
    client_id=getenv('GOOGLE_CLIENT_ID'),
    client_secret=getenv('GOOGLE_CLIENT_SECRET'),
    redirect_uri=getenv('GOOGLE_REDIRECT_URI'),
    logger=getLogger('...'),
    debug=False
)
# for debug
google_d_mode = Google(
    client_id=getenv('GOOGLE_CLIENT_ID'),
    client_secret=getenv('GOOGLE_CLIENT_SECRET'),
    redirect_uri=getenv('GOOGLE_REDIRECT_URI'),
    logger=getLogger('...'),
    debug=True
)

OP = gen_oauth_params()

### Debug
...
### Normal

def test_all():
    with patch('httpx.post') as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {google.access_token_name: 'valid'}
        mock_post.return_value = mock_response
        assert httpx.post('...').json() == {google.access_token_name: 'valid'}

        with pytest.raises(InvalidTokenAquisitionRequest): # invalid code
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')
        # now patching the return status to convey success
        mock_response.status_code = 200
        assert httpx.post('...').status_code == 200
        with pytest.raises(InvalidTokenAquisitionRequest): # invalid code
            google_d_mode.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid')

def test_invalid_authorization_code():
    assert google.get_access_token(state=OP.state, code_verifier=OP.code_verifier, code='invalid') is None


def test_invalid_access_token():
    user_info = google.get_user_info(access_token='...')
    assert user_info == None
