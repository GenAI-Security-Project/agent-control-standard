"""The ASGI app: POST /v1/responses forwarded upstream, with tool calls and tool results gated in shadow and enforce."""
from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from acs_gateway.config import GatewayConfig
from acs_gateway.transcript import ModelInputLog

# Headers that describe one hop, or that httpx recomputes, never cross the gateway.
_HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                          "transfer-encoding", "upgrade", "host", "content-length", "content-encoding"})


def _audit(event: str, **fields: Any) -> None:
    from acs.client import audit_event

    audit_event(event, **fields)


def openai_error(status: int, message: str, error_type: str, code: str | None = None) -> JSONResponse:
    """An error in the Responses API's own shape, so a client sees an ordinary API failure and nothing about ACS."""
    return JSONResponse({"error": {"message": message, "type": error_type, "param": None, "code": code}},
                        status_code=status)


def forward_headers(headers: Any) -> dict[str, str]:
    """The client's headers minus hop-by-hop ones and every x-acs-* lab header (A.8)."""
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_HEADERS and not k.lower().startswith("x-acs-")}


def _client_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_HEADERS}


class Gateway:
    """One gateway process: the upstream client, the logs and, outside off mode, the Guardian side."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.model_inputs = ModelInputLog(config.model_input_log)
        self.http: httpx.AsyncClient | None = None

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        # The model may think for minutes, so only connecting is bounded here and the client's own timeout governs.
        async with httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0)) as http:
            self.http = http
            yield
        self.http = None

    async def not_found(self, request: Request) -> Response:
        _audit("upstream_error", cause="route_not_found", method=request.method, path=request.url.path)
        return openai_error(404, "Unknown request URL.", "invalid_request_error", "unknown_url")

    async def responses(self, request: Request) -> Response:
        if request.method != "POST":
            return await self.not_found(request)
        raw = await request.body()
        body = _parse(raw)
        if isinstance(body, dict) and body.get("stream") is True:
            # Streaming is LAB-05 (issue #578). Refusing beats forwarding an ungoverned stream.
            return openai_error(501, "Streaming responses are not supported by this endpoint.",
                                "invalid_request_error", "unsupported_parameter")
        return await self.forward(raw, body, request)

    async def forward(self, raw: bytes, body: Any, request: Request) -> Response:
        self.model_inputs.append(body if body is not None else raw.decode("utf-8", "replace"))
        assert self.http is not None
        try:
            upstream = await self.http.post(f"{self.config.upstream_url}/responses", content=raw,
                                            headers=forward_headers(request.headers))
        except httpx.HTTPError as e:
            _audit("upstream_error", cause="upstream_unreachable", error=type(e).__name__)
            return openai_error(502, "The model service is unavailable.", "server_error", "upstream_unavailable")
        if not 200 <= upstream.status_code < 300:
            _audit("upstream_error", cause="upstream_status", http_status=upstream.status_code)
        return Response(upstream.content, status_code=upstream.status_code,
                        headers=_client_headers(upstream.headers))


def _parse(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def create_app(config: GatewayConfig) -> Starlette:
    gateway = Gateway(config)
    routes = [
        Route("/v1/responses", gateway.responses, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
        Route("/{path:path}", gateway.not_found, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
    ]
    app = Starlette(routes=routes, lifespan=gateway.lifespan)
    app.state.gateway = gateway
    return app
