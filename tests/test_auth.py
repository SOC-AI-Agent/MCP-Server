"""The bearer gate in front of each connector."""

import pytest

from conftest import AUTH, TOKEN

# One protected POST route each, none of which reaches a platform when the body
# is empty — so getting past the gate shows up as a 400, not a network call.
PROTECTED = [
    ("Splunk", "/query"),
    ("Threatq", "/lookup"),
    ("Confluence", "/match"),
]


@pytest.mark.parametrize("name,path", PROTECTED)
def test_no_token_is_a_401(client, name, path):
    resp = client(name).post(path, json={})
    assert resp.status_code == 401
    assert resp.json() == {"detail": "unauthorized"}


@pytest.mark.parametrize("name,path", PROTECTED)
@pytest.mark.parametrize(
    "header",
    [
        f"Bearer {TOKEN}x",
        "Basic dGVzdDp0ZXN0",
        "Bearer",
        "",
    ],
    ids=["wrong-token", "wrong-scheme", "no-token-after-scheme", "empty"],
)
def test_a_bad_credential_is_a_401(client, name, path, header):
    resp = client(name).post(path, json={}, headers={"Authorization": header})
    assert resp.status_code == 401


@pytest.mark.parametrize("name,path", PROTECTED)
def test_a_non_ascii_token_is_a_401_not_a_crash(client, name, path):
    # compare_digest raises TypeError on a str holding a non-ASCII character,
    # which used to turn this into a 500 for anyone who could reach the port.
    resp = client(name).post(
        path, json={}, headers={"Authorization": "Bearer café".encode("latin-1")}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("name,path", PROTECTED)
def test_the_right_token_gets_past_the_gate(client, name, path):
    resp = client(name).post(path, json={}, headers=AUTH)
    assert resp.status_code == 400  # refused for the empty body, not for who asked


@pytest.mark.parametrize("name", ["Splunk", "Threatq"])
def test_health_needs_no_token(client, name):
    assert client(name).get("/health").status_code == 200
