"""
A stand-in for ThreatQ, so the stack works end to end without a licensed one.

ThreatQ ships as an appliance to licensed customers; there is no public image
to run beside Splunk's. This answers the three calls the connector makes, in
the shape its documentation describes, so enrichment can be exercised for real:
a worker extracting indicators, checking them, and an agent reading the result.

Shaped from ThreatQ's REST API Reference v5.12, not from guesswork:

  * POST /api/token?grant_type=password&client_id=... with email and password
  * POST /api/indicators/search — looking up by value is a search; GET
    /api/indicators takes only limit, offset, sort and with
  * ?with=score,sources,adversaries,... — related objects are ABSENT unless
    asked for by name, and this enforces that. A connector that forgets `with`
    gets a record with no score, which is how the mistake shows up here instead
    of in production
  * 404 is "Object not found"

Still inferred: the exact criteria key for an indicator's value. Everything
else above is documented.

    uvicorn tests.fake_threatq:app --host 0.0.0.0 --port 8500
"""

import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# Short on purpose: the connector's refresh path only runs when a token
# actually expires, and an hour-long token means it never runs in testing.
TOKEN_TTL_SECONDS = 30

_issued: dict[str, float] = {}

# Values used by samples/alerts.json and the Splunk test data, so an alert
# carried through the whole pipeline finds something at the end of it.
KNOWN: dict[str, dict] = {
    "45.83.122.9": {
        "id": 90001,
        "score": {"generated_score": 9.0, "manual_score": None},
        "status": {"name": "Active"},
        "sources": [{"name": "Feed A"}, {"name": "Feed B"}, {"name": "Feed C"},
                    {"name": "Internal IR"}],
        "adversaries": [{"name": "APT29"}],
        "attributes": [{"name": "category", "value": "c2"}],
        "created_at": "2026-09-18T04:11:00Z",
        "updated_at": "2026-09-21T02:00:00Z",
    },
    "185.220.101.7": {
        "id": 90002,
        "score": {"generated_score": 7.5, "manual_score": None},
        "status": {"name": "Active"},
        "sources": [{"name": "Tor Project"}],
        "adversaries": [],
        "attributes": [{"name": "category", "value": "tor-exit-node"}],
        "created_at": "2025-02-01T00:00:00Z",
    },
    "cdn.badsite.io": {
        "id": 90003,
        "score": {"generated_score": 6.0, "manual_score": None},
        "status": {"name": "Review"},
        "sources": [{"name": "Feed A"}],
        "attributes": [{"name": "category", "value": "malware-hosting"}],
        "created_at": "2026-09-20T12:00:00Z",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "id": 90004,
        "score": {"generated_score": 10.0, "manual_score": None},
        "status": {"name": "Active"},
        "sources": [{"name": "Feed B"}],
        "attributes": [{"name": "malware_family", "value": "EICAR test file"}],
        "created_at": "2020-01-01T00:00:00Z",
    },
}

# Everything else is deliberately unknown. That is the case worth testing:
# "no record" is what gets misread as "clean", and 198.51.100.24 in the samples
# exists to make a model say so.


async def token(request: Request) -> JSONResponse:
    """
    OAuth2 password grant.

    Accepts any credentials — testing the connector's own auth is not what this
    is for — but does check that the fields are present, because a connector
    that forgets to send client_id should fail here rather than in production.
    """
    form = await request.form()
    missing = [f for f in ("grant_type", "client_id", "email", "password")
               if not form.get(f)]
    if missing:
        return JSONResponse(
            {"error": "invalid_request", "missing": missing}, status_code=400
        )

    issued = f"fake-{int(time.time() * 1000)}"
    _issued[issued] = time.time() + TOKEN_TTL_SECONDS
    return JSONResponse({
        "access_token": issued,
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    })


def _authorised(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return False
    expires = _issued.get(presented)
    if expires is None:
        # A static token — the bearer auth mode, which does not mint anything.
        return presented.startswith("fake") or len(presented) > 8
    return time.time() < expires


# Related objects, absent unless named in `with`. Keeping this list honest is
# the whole point: forget `with` against a real ThreatQ and every indicator
# comes back unscored, which reads as "nothing known" rather than as an error.
RELATED = ("score", "sources", "adversaries", "status", "type", "attributes")


def _project(record: dict, with_param: str) -> dict:
    """Base fields always; related objects only when asked for."""
    wanted = {w.strip() for w in with_param.split(",") if w.strip()}
    out = {k: v for k, v in record.items() if k not in RELATED}
    for name in RELATED:
        if name in wanted and name in record:
            out[name] = record[name]
    return out


async def search(request: Request) -> JSONResponse:
    """
    POST /api/indicators/search — how an indicator is found by its value.

    Criteria follow ThreatQ's SOLR-like convention. Only the simple
    single-field form is handled, which is what the connector sends.
    """
    if not _authorised(request):
        # 401 on an expired token is what drives the connector's refresh, so it
        # has to be a real answer rather than a courtesy.
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"errors": ["malformed body"]}, status_code=400)

    criteria = body.get("criteria") or {}
    value = criteria.get("value") if isinstance(criteria, dict) else None
    if not value:
        return JSONResponse({"errors": ["criteria.value is required"]}, status_code=400)

    record = KNOWN.get(value)
    if record is None:
        return JSONResponse({"data": [], "total": 0}, status_code=404)

    projected = _project(record, request.query_params.get("with", ""))
    return JSONResponse({"data": [projected], "total": 1})


async def indicators(request: Request) -> JSONResponse:
    """
    GET /api/indicators — the collection. Takes limit, offset, sort and with,
    and deliberately has NO value filter: a connector reaching for one here
    should find that out in testing.
    """
    if not _authorised(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with_param = request.query_params.get("with", "")
    limit = int(request.query_params.get("limit", 10) or 10)
    rows = [_project({**r, "value": v}, with_param) for v, r in KNOWN.items()]
    return JSONResponse({"data": rows[:limit], "total": len(rows)})


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "stand_in": True, "known": len(KNOWN)})


app = Starlette(
    routes=[
        Route("/api/token", token, methods=["POST"]),
        Route("/api/indicators/search", search, methods=["POST"]),
        Route("/api/indicators", indicators, methods=["GET"]),
        Route("/health", health, methods=["GET"]),
    ]
)
