"""The two example env files and the connectors that read them, kept from drifting.

.env.example is what the deploy job fills from CI variables; .env.local.example is
the shorter skeleton for a local run. Both name settings that config.py defines,
and a name that is wrong in either one fails quietly: the connector reads its
default and nobody sees that the value they set was ignored.
"""

import re
import sys

import pytest

from conftest import ROOT

ACTIVE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")

# Read by the TLS stack, not by any connector's Settings.
NOT_A_SETTING = {"SSL_CERT_FILE"}

# validate_startup() refuses to start without each of these.
REFUSES_TO_START_WITHOUT = {
    "Splunk": ["MCP_AUTH_TOKEN", "SPLUNK_TOKEN", "SPLUNK_ALLOWED_INDEXES"],
    "Threatq": ["THREATQ_MCP_AUTH_TOKEN"],
    "Confluence": ["CONFLUENCE_MCP_AUTH_TOKEN", "CONFLUENCE_BASE_URL", "CONFLUENCE_API_TOKEN"],
}
# Not startup checks, but a connector cannot be used without them.
ALSO_NEEDED = [
    "SPLUNK_BASE_URL", "THREATQ_BASE_URL", "CONFLUENCE_SPACE_KEY",
    "THREATQ_CLIENT_ID", "THREATQ_EMAIL", "THREATQ_PASSWORD",  # oauth, the default mode
]


def settings_in(path) -> dict[str, str]:
    found = {}
    for line in path.read_text().splitlines():
        match = ACTIVE.match(line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


EXAMPLE = settings_in(ROOT / ".env.example")
LOCAL = settings_in(ROOT / ".env.local.example")


def test_the_local_skeleton_names_only_keys_the_example_has():
    assert set(LOCAL) <= set(EXAMPLE), sorted(set(LOCAL) - set(EXAMPLE))


def test_every_key_in_the_example_is_read_by_a_connector(connector):
    read = set(NOT_A_SETTING)
    for name in REFUSES_TO_START_WITHOUT:
        connector(name)
        read |= set(sys.modules["config"].Settings.model_fields)
    assert set(EXAMPLE) <= read, sorted(set(EXAMPLE) - read)


@pytest.mark.parametrize("key", [k for k in EXAMPLE if re.search(r"TOKEN|PASSWORD|SECRET", k)])
def test_no_secret_has_a_value_in_the_example(key):
    # A value here is what a deploy uses when its CI variable is missing.
    assert EXAMPLE[key] == ""


def test_the_skeleton_lists_what_a_connector_cannot_run_without():
    needed = {k for keys in REFUSES_TO_START_WITHOUT.values() for k in keys} | set(ALSO_NEEDED)
    assert needed <= set(LOCAL), sorted(needed - set(LOCAL))


@pytest.mark.parametrize(
    "name,key",
    [(name, key) for name, keys in REFUSES_TO_START_WITHOUT.items() for key in keys],
)
def test_the_connector_really_refuses_to_start_without_it(connector, name, key):
    # Keeps REFUSES_TO_START_WITHOUT honest: if validate_startup stops asking for
    # one, this fails and the skeleton no longer has to insist on it.
    with pytest.raises(RuntimeError):
        connector(name, **{key: ""})
