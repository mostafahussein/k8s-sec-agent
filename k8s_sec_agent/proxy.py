"""OpenAI-compatible reverse proxy with response rehydration.

Sits between the kagent runtime and the upstream LLM API. Forwards
requests, intercepts responses, and replaces scope-prefixed pseudonymized
tokens (ns-a3f2-1, pod-b7c8-3) with real cluster names.
"""

import json
import logging
import os

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from k8s_sec_agent.sanitizer import has_mappings, rehydrate_all

logger = logging.getLogger(__name__)

UPSTREAM_BASE_URL = os.environ.get("UPSTREAM_LLM_URL", "https://openrouter.ai/api/v1")
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "300"))

app = FastAPI()


def _rehydrate_content(data: dict) -> dict:
    """Rehydrate pseudonymized tokens in an OpenAI chat completion response."""
    if not has_mappings():
        return data

    for choice in data.get("choices", []):
        msg = choice.get("message", {})
        if msg.get("content"):
            msg["content"] = rehydrate_all(msg["content"])
        # Also handle delta (streaming aggregated)
        delta = choice.get("delta", {})
        if delta.get("content"):
            delta["content"] = rehydrate_all(delta["content"])

    return data


def _build_upstream_headers(request: Request) -> dict:
    """Forward auth headers to the upstream LLM."""
    headers = {"Content-Type": "application/json"}
    auth = request.headers.get("authorization")
    if auth:
        headers["Authorization"] = auth
    # Forward OpenRouter-specific headers
    for key in ("x-api-key", "http-referer", "x-title"):
        val = request.headers.get(key)
        if val:
            headers[key] = val
    return headers


async def _collect_sse_text(response: httpx.Response) -> tuple[str, dict]:
    """Collect full text from SSE stream, return (text, last_chunk_data)."""
    full_text = ""
    last_data = {}
    async for line in response.aiter_lines():
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload.strip() == "[DONE]":
            break
        try:
            chunk = json.loads(payload)
            last_data = chunk
            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {})
                if delta.get("content"):
                    full_text += delta["content"]
        except json.JSONDecodeError:
            continue
    return full_text, last_data


def _make_sse_response(data: dict) -> StreamingResponse:
    """Convert a chat completion response to SSE format."""
    # Convert the non-streaming response into a single streaming chunk + DONE
    stream_chunk = dict(data)
    for choice in stream_chunk.get("choices", []):
        # Convert message to delta format
        if "message" in choice:
            choice["delta"] = choice.pop("message")
    payload = json.dumps(stream_chunk)

    async def generate():
        yield f"data: {payload}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    client_wants_stream = body.get("stream", False)
    headers = _build_upstream_headers(request)

    async with httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT)) as client:
        if client_wants_stream:
            # Stream from upstream, collect full text, rehydrate, re-emit
            body["stream"] = True
            async with client.stream(
                "POST",
                f"{UPSTREAM_BASE_URL}/chat/completions",
                json=body,
                headers=headers,
            ) as upstream_resp:
                full_text, last_chunk = await _collect_sse_text(upstream_resp)

            if full_text:
                if has_mappings():
                    full_text = rehydrate_all(full_text)

                # Build a complete response to re-stream
                response_data = {
                    "id": last_chunk.get("id", ""),
                    "object": "chat.completion",
                    "model": last_chunk.get("model", body.get("model", "")),
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": full_text},
                        "finish_reason": "stop",
                    }],
                }
                return _make_sse_response(response_data)
            else:
                # No text content (tool calls only) — return last chunk as-is
                return _make_sse_response(last_chunk)
        else:
            # Non-streaming: simple forward, rehydrate, return
            body["stream"] = False
            resp = await client.post(
                f"{UPSTREAM_BASE_URL}/chat/completions",
                json=body,
                headers=headers,
            )
            data = resp.json()
            data = _rehydrate_content(data)
            return Response(
                content=json.dumps(data),
                media_type="application/json",
                status_code=resp.status_code,
            )


@app.get("/models")
async def list_models(request: Request):
    """Proxy models endpoint."""
    headers = _build_upstream_headers(request)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{UPSTREAM_BASE_URL}/models", headers=headers)
    return Response(content=resp.content, media_type="application/json", status_code=resp.status_code)
