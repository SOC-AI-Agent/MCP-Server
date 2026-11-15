"""
Text-to-SPL by Splunk AI Assistant for SPL, through Splunk's own MCP server.

Optional, live only: with SPLUNK_SAIA_MCP_URL set, each request is forwarded to
the Text-to-SPL tool Splunk's MCP Server app publishes (`saia_generate_spl`) and
what it answers is handed back. The SPL is still checked and run by this service.
The text goes to Splunk AI Assistant, which processes it in Splunk Cloud.

A plain Splunk container has no assistant; leave the URL blank there and the
template (text_to_spl.py) writes the SPL.
"""

import json
import logging
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from config import settings

logger = logging.getLogger("saia")


class SaiaError(RuntimeError):
    """Anything that stops Text-to-SPL from answering."""


def endpoint() -> str:
    """The endpoint, accepting a bare base URL and adding the path Splunk serves MCP at."""
    url = httpx2.URL(settings.SPLUNK_SAIA_MCP_URL.strip())
    return str(url.copy_with(path="/services/mcp") if url.path in ("", "/") else url)


def _target() -> Any:
    """What the client connects to. Tests replace this with an in-process server."""
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {settings.SPLUNK_SAIA_MCP_TOKEN or settings.SPLUNK_TOKEN}"},
        verify=settings.SPLUNK_VERIFY_SSL,
        timeout=settings.SPLUNK_TIMEOUT,
    )
    return streamable_http_client(endpoint(), http_client=http)


def _prompt_arg(tool: Any) -> str:
    """The argument the tool takes the request in, read from its schema: whatever
    Splunk names it, this does not need a release to follow."""
    if settings.SPLUNK_SAIA_ARG:
        return settings.SPLUNK_SAIA_ARG
    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    strings = [name for name, spec in props.items() if (spec or {}).get("type") == "string"]
    for name in strings:
        if name in required:
            return name
    if strings:
        return strings[0]
    raise SaiaError(
        f"cannot tell which argument of {settings.SPLUNK_SAIA_TOOL} takes the request; set SPLUNK_SAIA_ARG"
    )


def _reason(exc: BaseException) -> str:
    """The first real error under the task groups the client wraps everything in."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return f"{type(exc).__name__}: {exc}"


async def generate(prompt: str) -> Any:
    """What Splunk's Text-to-SPL answered: the object it returned, else its text
    parsed as JSON, else the text."""
    name = settings.SPLUNK_SAIA_TOOL
    result = None
    try:
        async with Client(_target(), read_timeout_seconds=settings.SPLUNK_TIMEOUT) as client:
            tool = next((t for t in (await client.list_tools()).tools if t.name == name), None)
            if tool is not None:
                result = await client.call_tool(name, {_prompt_arg(tool): prompt})
    except SaiaError:
        raise
    except (Exception, BaseExceptionGroup) as exc:  # noqa: BLE001 — the caller needs the reason
        raise SaiaError(f"cannot use Splunk's MCP server at {endpoint()}: {_reason(exc)}") from exc
    if result is None:
        raise SaiaError(
            f"Splunk's MCP server has no {name}. Text-to-SPL needs Splunk AI Assistant "
            "for SPL installed and its tools enabled in the MCP Server app."
        )

    text = "\n".join(getattr(c, "text", "") for c in result.content if getattr(c, "type", "") == "text")
    if getattr(result, "is_error", False):
        raise SaiaError(f"{name}: {text or 'the tool reported an error'}")
    # A tool that returns an object says where the SPL is; one that returns text
    # is wrapped by its server ({"result": text}) and is read as the text it is.
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and any(isinstance(structured.get(k), str) for k in ("spl", "query", "search")):
        return structured
    try:
        return json.loads(text)
    except ValueError:
        return text
