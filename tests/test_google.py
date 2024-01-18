from fastauth.providers.google.google import  Google
from logging import getLogger
from fastauth.utils import gen_oauth_params

google = Google(
    client_id='...',
    client_secret='...',
    redirect_uri='...',
    logger=getLogger('...'),
    debug=False
)

### Debug
...
### Normal
def test_invalid_authorization_code():
    op = gen_oauth_params()
    assert google.get_access_token(state=op.state,code_verifier=op.code_verifier,code='invalid') is None


def test_invalid_access_token():
    user_info = google.get_user_info(access_token='...')
    assert user_info == None
