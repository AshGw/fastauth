from typing import Tuple

State = str
CodeVerifier = str
CodeChallege = str
CodeChallegeMethod = str

OAuth2SecurityQueryParams = Tuple[State, CodeVerifier, CodeChallege, CodeChallegeMethod]
