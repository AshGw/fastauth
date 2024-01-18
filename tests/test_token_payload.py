from fastauth import utils


class _TokenPayload:
    def __init__(self, **kwargs: str):
        self.kwargs = kwargs

    def final_url(self):
        return utils.base_redirect_url(
            code_challenge="code_challenge",
            client_id="client_id",
            code_challenge_method="s256",
            authorizationUrl="https://exmaple.com",
            redirect_uri="https://example.com/redirect",
            response_type="code",
            state="state",
            kwargs=self.kwargs,
        )


def test_base_redirect_url():
    ins = _TokenPayload(kwarg1="one", kwarg2="two", kwarg3="three")
    assert ins.final_url() == (
        "https://exmaple.com"
        "?response_type=code"
        "&client_id=client_id"
        "&redirect_uri=https://example.com/redirect&state=state"
        "&code_challenge=code_challenge"
        "&code_challenge_method=s256"
        "&kwarg1=one"
        "&kwarg2=two"
        "&kwarg3=three"
    )
