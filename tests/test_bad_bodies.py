"""What the backend-facing routes do with a body that is not what they expect.

Every one of these is the caller's mistake, so every one is a 400 that says so
— never a 500, which reads as the connector being broken.
"""

import pytest

from conftest import AUTH

ROUTES = [
    ("Splunk", "/query"),
]

NOT_AN_OBJECT = [b"[]", b"null", b'"x"', b"123"]
NOT_JSON = [b"", b"{", b"\xff\xfe{"]


@pytest.mark.parametrize("name,path", ROUTES)
@pytest.mark.parametrize("body", NOT_AN_OBJECT + NOT_JSON, ids=repr)
def test_a_body_that_is_not_a_json_object_is_a_400(client, name, path, body):
    resp = client(name).post(path, content=body, headers=AUTH)
    assert resp.status_code == 400, resp.text
    assert resp.json()  # a JSON error the caller can read, not plain text


# Valid JSON, an object, and still nothing the route can use.
EMPTY_ENOUGH = [
    ("Splunk", "/query", {}),
    ("Splunk", "/query", {"spl": ""}),
    ("Splunk", "/query", {"spl": 123}),
    ("Splunk", "/query", {"spl": 'search index="main"', "count": "abc"}),
]


@pytest.mark.parametrize("name,path,body", EMPTY_ENOUGH, ids=lambda v: str(v)[:30])
def test_an_object_with_nothing_usable_is_a_400(client, name, path, body):
    resp = client(name).post(path, json=body, headers=AUTH)
    assert resp.status_code == 400, resp.text
