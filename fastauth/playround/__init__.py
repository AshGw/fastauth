from pydantic import BaseModel
from typing import  Dict
class OAuthParamsBase(BaseModel):
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str


class OAuthParams(BaseModel):
    __root__: Dict[str, OAuthParamsBase]


good_data = {
  'Google': { 'state': 'va', 'code_verifier': 'ta','code_challenge': 'va', 'code_challenge_method': 'ta', 'authFlow':'blend' },
  'Spotify': {'state': 'va', 'code_verifier': 'ta', 'code_challenge': 'va', 'code_challenge_method': 'ta'},

}


OAuthParams.parse_obj(good_data)
# ok !
