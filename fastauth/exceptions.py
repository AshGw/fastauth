class WrongKeyLength(Exception):
	pass


class InvalidState(Exception):
	pass


class InvalidCodeVerifier(Exception):
	pass


class InvalidTokenAquisitionRequest(Exception):
	pass


class InvalidResourceAccessRequest(Exception):
	"""
	The request for the resource is invalid, it's either due to an invalid `access_token`
	or the wrong `Content-Type` header.
	"""

	pass


class InvalidAccessTokenName(Exception):
	"""
	You might want to check in with your provider over how the `access_token` is named
	e.g: `accessToken` or `token` and so on.
	"""

	pass
