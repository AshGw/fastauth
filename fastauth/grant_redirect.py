from fastauth.utils import base_redirect_url
from fastauth.responses import OAuthRedirectResponse
from fastauth.providers.base import Provider


class AuthGrantRedirect:
	def __init__(
		self,
		provider: Provider,
		state: str,
		code_challenge: str,
		code_challenge_method: str,
		**kwargs: str,
	):
		self.response_type = provider.response_type
		self.authorizationUrl = provider.authorizationUrl
		self.client_id = provider.client_id
		self.redirect_uri = provider.redirect_uri
		self.state = state
		self.code_challenge = code_challenge
		self.code_challenge_method = code_challenge_method
		self.kwargs = kwargs

	@property
	def url(self) -> str:
		return base_redirect_url(
			response_type=self.response_type,
			authorizationUrl=self.authorizationUrl,
			client_id=self.client_id,
			redirect_uri=self.redirect_uri,
			state=self.state,
			code_challenge=self.code_challenge,
			code_challenge_method=self.code_challenge_method,
			kwargs=self.kwargs,
		)

	def __call__(self) -> OAuthRedirectResponse:  # pragma: no cover
		return OAuthRedirectResponse(url=self.url)
