import pytest
import time

import jwtokens


EMPTY = "e30"
CLAIMS = "eyJpYXQiOjEwMCwiZXhwIjoyMDAsIm5iZiI6MCwiaXNzIjoidGVzdC1pc3MiLCJzdWIiOiJ0ZXN0LXN1YiIsImF1ZCI6InRlc3QtYXVkIiwianRpIjoidGVzdC1pZCJ9"
CLAIMS_FLOATS = "eyJpYXQiOjEwMCwiZXhwIjoyMDAuMCwibmJmIjowLjAsImlzcyI6InRlc3QtaXNzIiwic3ViIjoidGVzdC1zdWIiLCJhdWQiOiJ0ZXN0LWF1ZCIsImp0aSI6InRlc3QtaWQifQ"
CUSTOM = "eyJ1c2VybmFtZSI6InRlc3QtdXNlciIsImFkbWluIjp0cnVlLCJyb2xlcyI6WyJlZGl0b3IiLCJ2aWV3ZXIiXX0"
CUSTOM_CLAIMS = "eyJ1c2VybmFtZSI6InRlc3QtdXNlciIsImFkbWluIjp0cnVlLCJyb2xlcyI6WyJlZGl0b3IiLCJ2aWV3ZXIiXSwiaWF0IjoxMDAsImV4cCI6MjAwLCJuYmYiOjAsImlzcyI6InRlc3QtaXNzIiwic3ViIjoidGVzdC1zdWIiLCJhdWQiOiJ0ZXN0LWF1ZCIsImp0aSI6InRlc3QtaWQifQ"


@pytest.fixture(autouse=True)
def constant_time(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 100)


@pytest.mark.parametrize(
    "args,kwargs,expected",
    [
        ([], {}, EMPTY),
        ([{}], {}, EMPTY),
        (
            [],
            {
                "issued_timestamp": True,
                "expire_secs": 100,
                "not_before_secs": -100,
                "issuer": "test-iss",
                "subject": "test-sub",
                "audience": "test-aud",
                "jwt_id": "test-id",
            },
            CLAIMS,
        ),
        (
            [{"iat": 100, "exp": 200, "nbf": 0}],
            {
                "issuer": "test-iss",
                "subject": "test-sub",
                "audience": "test-aud",
                "jwt_id": "test-id",
            },
            CLAIMS,
        ),
        (
            [{"iat": 100, "exp": 200, "nbf": 0}],
            {
                "issuer": "test-iss",
                "subject": "test-sub",
                "audience": "test-aud",
                "jwt_id": "test-id",
            },
            CLAIMS,
        ),
        (
            [],
            {
                "issued_timestamp": True,
                "expire_secs": float(100),
                "not_before_secs": float(-100),
                "issuer": b"test-iss",
                "subject": b"test-sub",
                "audience": b"test-aud",
                "jwt_id": b"test-id",
            },
            CLAIMS_FLOATS,
        ),
        (
            [],
            {
                "issued_timestamp": True,
                "expire_secs": float(100),
                "not_before_secs": float(-100),
                "issuer": b"test-iss",
                "subject": b"test-sub",
                "audience": b"test-aud",
                "jwt_id": b"test-id",
            },
            CLAIMS_FLOATS,
        ),
        (
            [{"username": "test-user", "admin": True, "roles": ["editor", "viewer"]}],
            {},
            CUSTOM,
        ),
        (
            [{"username": "test-user", "admin": True, "roles": ["editor", "viewer"]}],
            {
                "issued_timestamp": True,
                "expire_secs": 100,
                "not_before_secs": -100,
                "issuer": "test-iss",
                "subject": "test-sub",
                "audience": "test-aud",
                "jwt_id": "test-id",
            },
            CUSTOM_CLAIMS,
        ),
    ],
)
def test_message(args, kwargs, expected):
    assert jwtokens.message(*args, **kwargs) == expected
