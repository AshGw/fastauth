""" This tests the .env.local for testing """

from dotenv import load_dotenv
from os import getenv

load_dotenv()


def test_secret():
    assert getenv("SECRET")


def test_google_credentials():
    assert getenv("GOOGLE_CLIENT_ID")
    assert getenv("GOOGLE_CLIENT_SECRET")
    assert getenv("GOOGLE_REDIRECT_URI")


def test_github_credentials():
    assert getenv("GITHUB_CLIENT_ID")
    assert getenv("GITHUB_CLIENT_SECRET")
    assert getenv("GITHUB_REDIRECT_URI")


def test_reddit_credentials():
    assert getenv("REDDIT_CLIENT_ID")
    assert getenv("REDDIT_CLIENT_SECRET")
    assert getenv("REDDIT_REDIRECT_URI")


def test_facebook_credentials():
    assert getenv("FACEBOOK_CLIENT_ID")
    assert getenv("FACEBOOK_CLIENT_SECRET")
    assert getenv("FACEBOOK_REDIRECT_URI")


def test_spotify_credentials():
    assert getenv("SPOTIFY_CLIENT_ID")
    assert getenv("SPOTIFY_CLIENT_SECRET")
    assert getenv("SPOTIFY_REDIRECT_URI")
