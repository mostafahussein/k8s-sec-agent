"""MCP client for kagent-tool-server — calls k8s tools without local kubectl.

Connects to the kagent-tool-server StreamableHTTP MCP endpoint to execute
Kubernetes operations. Raw data returns to our code for sanitization —
no external LLM sees unsanitized cluster data.

Maintains a persistent MCP session to avoid per-call initialization overhead.
"""

import asyncio
import json
import logging
import os

import httpx

logger = logging.getLogger(__name__)

TOOL_SERVER_URL = os.environ.get(
    "KAGENT_TOOL_SERVER_URL",
    "http://kagent-tools.kagent:8084/mcp",
)

# Timeout for individual tool calls (seconds)
_TOOL_TIMEOUT = int(os.environ.get("TOOL_SERVER_TIMEOUT", "60"))


class _MCPSession:
    """Persistent MCP session to the kagent-tool-server.

    Initializes once on first tool call, then reuses the session ID and
    HTTP client for subsequent calls. Automatically reinitializes if the
    session is lost.
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._call_id: int = 0
        self._lock = asyncio.Lock()

    async def _ensure_initialized(self) -> None:
        """Initialize the MCP session if not already active."""
        if self._client is not None and self._session_id is not None:
            return

        # Close stale client if session was lost
        if self._client is not None:
            await self._client.aclose()

        self._client = httpx.AsyncClient(timeout=httpx.Timeout(_TOOL_TIMEOUT))
        self._call_id = 0

        init_payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "k8s-sec-agent", "version": "1.0"},
            },
        }
        resp = await self._client.post(
            TOOL_SERVER_URL,
            json=init_payload,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        resp.raise_for_status()
        self._session_id = resp.headers.get("mcp-session-id")

        # Send initialized notification
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        await self._client.post(
            TOOL_SERVER_URL,
            json=notif_payload,
            headers=self._headers(),
        )
        logger.debug("MCP session initialized (session_id=%s)", self._session_id)

    def _next_id(self) -> int:
        self._call_id += 1
        return self._call_id

    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        return headers

    async def _reset(self) -> None:
        """Reset the session so the next call reinitializes."""
        if self._client is not None:
            await self._client.aclose()
        self._client = None
        self._session_id = None
        self._call_id = 0

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Call a tool on the kagent-tool-server.

        Reuses the existing MCP session. Reinitializes automatically on
        connection errors.
        """
        async with self._lock:
            try:
                return await self._call_tool_inner(tool_name, arguments)
            except (httpx.HTTPStatusError, httpx.ConnectError, httpx.RemoteProtocolError):
                # Session may be stale — reinitialize and retry once
                logger.debug("MCP session lost, reinitializing")
                await self._reset()
                return await self._call_tool_inner(tool_name, arguments)

    async def _call_tool_inner(self, tool_name: str, arguments: dict) -> str:
        await self._ensure_initialized()
        assert self._client is not None

        call_payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        resp = await self._client.post(
            TOOL_SERVER_URL,
            json=call_payload,
            headers=self._headers(),
        )
        resp.raise_for_status()

        # Parse response — may be direct JSON or SSE
        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            result_data = _parse_sse_response(resp.text)
        else:
            result_data = resp.json()

        # Extract tool result
        if "error" in result_data:
            err = result_data["error"]
            raise RuntimeError(f"Tool {tool_name} failed: {err.get('message', err)}")

        result = result_data.get("result", {})
        if result.get("isError"):
            content = result.get("content", [])
            texts = [c["text"] for c in content if c.get("type") == "text"]
            raise RuntimeError(f"Tool {tool_name} failed: {' '.join(texts)}")

        content = result.get("content", [])
        texts = [c["text"] for c in content if c.get("type") == "text"]
        return "\n".join(texts)


# Module-level singleton
_session = _MCPSession()


def _parse_sse_response(text: str) -> dict:
    """Extract the JSON-RPC result from an SSE stream response."""
    for line in text.split("\n"):
        if line.startswith("data: "):
            payload = line[6:].strip()
            if not payload:
                continue
            try:
                data = json.loads(payload)
                # Return the first message that has an "id" (i.e., a response, not notification)
                if "id" in data:
                    return data
            except json.JSONDecodeError:
                continue
    raise RuntimeError("No JSON-RPC response found in SSE stream")


async def get_resources(
    resource_type: str,
    *,
    resource_name: str | None = None,
    namespace: str | None = None,
    all_namespaces: bool = False,
    output: str = "json",
) -> str:
    """Get Kubernetes resources via kagent-tool-server."""
    args: dict = {"resource_type": resource_type, "output": output}
    if resource_name:
        args["resource_name"] = resource_name
    if namespace:
        args["namespace"] = namespace
    if all_namespaces:
        args["all_namespaces"] = "true"
    return await _session.call_tool("k8s_get_resources", args)


async def get_resources_json(
    resource_type: str,
    *,
    resource_name: str | None = None,
    namespace: str | None = None,
    all_namespaces: bool = False,
) -> dict:
    """Get Kubernetes resources as parsed JSON."""
    text = await get_resources(
        resource_type,
        resource_name=resource_name,
        namespace=namespace,
        all_namespaces=all_namespaces,
        output="json",
    )
    return json.loads(text)


async def get_pod_logs(
    pod_name: str,
    *,
    namespace: str = "default",
    container: str | None = None,
    tail_lines: int = 50,
) -> str:
    """Get logs from a Kubernetes pod."""
    args: dict = {
        "pod_name": pod_name,
        "namespace": namespace,
        "tail_lines": tail_lines,
    }
    if container:
        args["container"] = container
    return await _session.call_tool("k8s_get_pod_logs", args)


async def apply_manifest(manifest: str) -> str:
    """Apply a YAML/JSON manifest to the cluster."""
    return await _session.call_tool("k8s_apply_manifest", {"manifest": manifest})


async def delete_resource(
    resource_type: str,
    resource_name: str,
    *,
    namespace: str = "default",
) -> str:
    """Delete a Kubernetes resource."""
    return await _session.call_tool("k8s_delete_resource", {
        "resource_type": resource_type,
        "resource_name": resource_name,
        "namespace": namespace,
    })


async def describe_resource(
    resource_type: str,
    resource_name: str,
    *,
    namespace: str | None = None,
) -> str:
    """Describe a Kubernetes resource in detail."""
    args: dict = {
        "resource_type": resource_type,
        "resource_name": resource_name,
    }
    if namespace:
        args["namespace"] = namespace
    return await _session.call_tool("k8s_describe_resource", args)


async def get_resource_yaml(
    resource_type: str,
    resource_name: str,
    *,
    namespace: str | None = None,
) -> str:
    """Get the YAML representation of a resource."""
    args: dict = {
        "resource_type": resource_type,
        "resource_name": resource_name,
    }
    if namespace:
        args["namespace"] = namespace
    return await _session.call_tool("k8s_get_resource_yaml", args)
