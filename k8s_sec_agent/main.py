"""Combined MCP server + privacy proxy — single process, shared sanitizer.

MCP server on /mcp  — tools for kagent declarative agent
Proxy on /v1/*       — rehydrating reverse proxy to upstream LLM
"""

import logging
import os

from fastapi import FastAPI
from k8s_sec_agent.mcp_server import mcp
from k8s_sec_agent.proxy import app as proxy_app

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

# Create the MCP ASGI app, mounted at root since we'll nest under /mcp
mcp_app = mcp.http_app(path="/")

# Main app with MCP lifespan (required for session management)
app = FastAPI(lifespan=mcp_app.lifespan)

# Mount MCP server at /mcp
app.mount("/mcp", mcp_app)

# Mount proxy at /v1
app.mount("/v1", proxy_app)


@app.get("/health")
async def health():
    return {"status": "ok"}
