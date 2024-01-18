import validators
from fastauth.data import OAuthURLs


def test_urls():
    providers = [
        OAuthURLs.Google,
        OAuthURLs.GitHub,
        OAuthURLs.Reddit,
        OAuthURLs.Facebook,
        OAuthURLs.Instagram,
        OAuthURLs.Spotify,
    ]

    for provider in providers:
        for url_name, url in provider.__dict__.items():
            if (
                not url_name.startswith("__")
                and url_name is not None
                and not isinstance(url_name, type)
            ):
                assert validators.url(url)
