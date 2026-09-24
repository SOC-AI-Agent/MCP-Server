"""Ask the running connector whether it can use ThreatQ. Exit 0 if so, 1 if not.

    docker compose exec -T soc-mcp-threatq python check_connection.py

Meant to run inside the container: the connector's own token is read from its
environment there, so it is never on a command line or in a job log. What is
printed is the /check-connection answer — no secrets, and it names the step
that failed.
"""

import json
import sys
import urllib.error
import urllib.request

from config import settings

request = urllib.request.Request(
    f"http://localhost:{settings.THREATQ_MCP_PORT}/check-connection",
    headers={"Authorization": f"Bearer {settings.THREATQ_MCP_AUTH_TOKEN}"},
)

try:
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read()
except urllib.error.HTTPError as exc:
    body = exc.read()  # a 502 is the answer, not a failure to get one
except OSError as exc:
    sys.exit(f"cannot reach the connector on localhost: {exc}")

print(body.decode(errors="replace"))

try:
    connected = json.loads(body).get("connected") is True
except ValueError:
    connected = False
sys.exit(0 if connected else 1)
