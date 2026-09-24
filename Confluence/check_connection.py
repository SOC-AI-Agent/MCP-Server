"""Ask the running connector whether it can use Confluence. Exit 0 if so, 1 if not.

    docker compose exec -T soc-mcp-confluence python check_connection.py
    
ีUse in ci/cd to verify the connector is up and running before running tests that depend on it.
"""

import json
import sys
import urllib.error
import urllib.request

from config import settings

request = urllib.request.Request(
    f"http://localhost:{settings.CONFLUENCE_MCP_PORT}/check-connection",
    headers={"Authorization": f"Bearer {settings.CONFLUENCE_MCP_AUTH_TOKEN}"},
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
