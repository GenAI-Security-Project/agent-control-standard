"""The ASGI app: POST /v1/responses forwarded upstream, with tool calls and tool results gated in shadow and enforce."""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from acs_gateway.apply import (
    Applied,
    apply_call,
    apply_result,
    call_payload,
    is_foreign_call,
    is_foreign_output,
    NEUTRAL_LINE,
    neutral_message,
    neutralize_foreign_output,
    parse_arguments,
    result_payload,
    unsupported_tool,
)
from acs_gateway.config import GatewayConfig, check_client_state_dirs
from acs_gateway.guardian import TOOL_CALL_REQUEST, TOOL_CALL_RESULT, GuardianClient, StepResult
from acs_gateway.sessions import CachedOutcome, Session, SessionMap, conversation_key, fingerprint
from acs_gateway.transcript import ModelInputLog, Transcript

# Headers that describe one hop, or that the next hop recomputes, never cross the gateway.
_HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                          "transfer-encoding", "upgrade", "host", "content-length"})
# Governed modes edit bodies, so they ask only for encodings httpx decodes and relay the decoded body.
_GOVERNED_ACCEPT_ENCODING = "gzip, deflate"


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


def _client_headers(headers: httpx.Headers, *, decoded: bool) -> dict[str, str]:
    """The upstream's headers for the client, minus any x-acs-* lab header. A decoded body drops content-encoding."""
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_HEADERS and not k.lower().startswith("x-acs-")
            and not (decoded and k.lower() == "content-encoding")}


def is_stream(body: Any) -> bool:
    """Any stream value but an absent one or false asks for a stream, so a truthy oddity can't slip past the 501."""
    return isinstance(body, dict) and "stream" in body and body["stream"] is not False


class Gateway:
    """One gateway process: the upstream client, the logs and, outside off mode, the Guardian side."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.model_inputs = ModelInputLog(config.model_input_log)
        self.http: httpx.AsyncClient | None = None
        self.governed = config.mode != "off"
        self.enforce = config.mode == "enforce"
        self.sessions = SessionMap()
        self.guardian = GuardianClient(config, Transcript(config.transcript_dir)) if self.governed else None

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        if self.guardian is not None:
            check_client_state_dirs(os.environ)
            await asyncio.to_thread(self.guardian.wait_ready)
        # The model may think for minutes, so only connecting is bounded here and the client's own timeout governs.
        async with httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0)) as http:
            self.http = http
            yield
        self.http = None

    def bump_epoch(self) -> int:
        epoch = self.sessions.bump_epoch()
        _audit("epoch_bumped", epoch=epoch)
        return epoch

    async def not_found(self, request: Request) -> Response:
        _audit("upstream_error", cause="route_not_found", method=request.method, path=request.url.path)
        return openai_error(404, "Unknown request URL.", "invalid_request_error", "unknown_url")

    async def responses(self, request: Request) -> Response:
        if request.method != "POST":
            return await self.not_found(request)
        raw = await request.body()
        body = _parse(raw)
        headers = forward_headers(request.headers)
        if not self.governed:
            return await self._relay_verbatim(raw, body, headers)
        if is_stream(body):
            # Governed streaming is LAB-05 (issue #578). Refusing beats forwarding an ungoverned stream.
            return openai_error(501, "Streaming responses are not supported by this endpoint.",
                                "invalid_request_error", "unsupported_parameter")
        if request.headers.get("content-encoding", "identity").strip().lower() != "identity":
            return openai_error(415, "Compressed request bodies are not supported by this endpoint.",
                                "invalid_request_error", "unsupported_content_encoding")
        headers["accept-encoding"] = _GOVERNED_ACCEPT_ENCODING
        if not isinstance(body, dict):
            return openai_error(400, "The request body must be a JSON object.", "invalid_request_error")
        stateful = [f for f in ("previous_response_id", "conversation") if body.get(f) is not None]
        if stateful:
            # Server-side history hides earlier items from the gateway, so session keying and the result cache
            # can't see them. Lab convention: FinBot never sends either field (verified at 1450fc4).
            return openai_error(501, f"The {stateful[0]} parameter is not supported by this endpoint.",
                                "invalid_request_error", "unsupported_parameter")
        unsupported = unsupported_tool(body)
        if unsupported is not None:
            # Function tools only. Any other tool type runs where the gateway can't gate it: a hosted tool runs
            # upstream, and a client-run one has no toolCallRequest mapping yet.
            _audit("unsupported_tool_type", item_type=unsupported, direction="request_tools", mode=self.config.mode)
            return openai_error(501, "Only function tools are supported by this endpoint.",
                                "invalid_request_error", "unsupported_tool_type")
        session = self.sessions.get(conversation_key(body))
        async with session.lock:
            if session.handshake is None:
                await asyncio.to_thread(self.guardian.open, session)
            if await self._gate_input(session, body):
                raw = json.dumps(body).encode("utf-8")
        upstream = await self._upstream(raw, body, headers)
        if isinstance(upstream, Response):
            return upstream
        if not 200 <= upstream.status_code < 300:
            return _relay(upstream, None)
        reply = _parse(upstream.content)
        if not isinstance(reply, dict) or not isinstance(reply.get("output"), list):
            # A success the gateway can't read could carry calls it never gated, so it never reaches the client.
            _audit("upstream_error", cause="upstream_unparseable", http_status=upstream.status_code)
            return openai_error(502, "The model service returned an unreadable response.", "server_error",
                                "upstream_unreadable")
        async with session.lock:
            changed = await self._gate_output(session, reply)
        return _relay(upstream, reply if changed else None)

    async def _upstream(self, raw: bytes, body: Any, headers: dict[str, str]) -> httpx.Response | Response:
        self.model_inputs.append(body if body is not None else raw.decode("utf-8", "replace"))
        assert self.http is not None
        try:
            upstream = await self.http.post(f"{self.config.upstream_url}/responses", content=raw, headers=headers)
        except httpx.HTTPError as e:
            _audit("upstream_error", cause="upstream_unreachable", error=type(e).__name__)
            return openai_error(502, "The model service is unavailable.", "server_error", "upstream_unavailable")
        if not 200 <= upstream.status_code < 300:
            _audit("upstream_error", cause="upstream_status", http_status=upstream.status_code)
        return upstream

    async def _relay_verbatim(self, raw: bytes, body: Any, headers: dict[str, str]) -> Response:
        """Off mode relays the answer, streamed or not, as it arrives, encoding and headers included."""
        self.model_inputs.append(body if body is not None else raw.decode("utf-8", "replace"))
        assert self.http is not None
        try:
            upstream = await self.http.send(
                self.http.build_request("POST", f"{self.config.upstream_url}/responses", content=raw,
                                        headers=headers), stream=True)
        except httpx.HTTPError as e:
            _audit("upstream_error", cause="upstream_unreachable", error=type(e).__name__)
            return openai_error(502, "The model service is unavailable.", "server_error", "upstream_unavailable")
        if not 200 <= upstream.status_code < 300:
            _audit("upstream_error", cause="upstream_status", http_status=upstream.status_code)
        return StreamingResponse(upstream.aiter_raw(), status_code=upstream.status_code,
                                 headers=_client_headers(upstream.headers, decoded=False),
                                 background=BackgroundTask(upstream.aclose))

    async def _gate_input(self, session: Session, body: dict[str, Any]) -> bool:
        """Gate each new function_call_output before it reaches the model, and reapply cached outcomes on resends."""
        items = body.get("input")
        if not isinstance(items, list):
            return False
        names = {i.get("call_id"): i.get("name") for i in items if isinstance(i, dict) and i.get("type") == "function_call"}
        changed, kept = False, []
        for item in items:
            if isinstance(item, dict) and is_foreign_output(item):
                _audit("unsupported_tool_type", session_id=session.session_id, item_type=item.get("type"),
                       direction="input", mode=self.config.mode)
                if self.enforce:
                    item, changed = neutralize_foreign_output(item), True
                kept.append(item)
                continue
            call_id = item.get("call_id") if isinstance(item, dict) else None
            if not isinstance(call_id, str):
                kept.append(item)
                continue
            if item.get("type") == "function_call" and call_id in session.calls and self.enforce:
                cached = session.calls[call_id]
                if cached.item is None:
                    changed = True
                    continue
                if item.get("arguments") != cached.item.get("arguments"):
                    item, changed = {**item, "arguments": cached.item.get("arguments")}, True
            elif item.get("type") == "function_call_output":
                cached = session.results.get(call_id)
                if cached is not None and cached.fingerprint != fingerprint(item):
                    self._reused(session, TOOL_CALL_RESULT, cached.name, call_id)
                    if self.enforce:
                        item, changed = {**item, "output": NEUTRAL_LINE}, True
                    kept.append(item)
                    continue
                if cached is None:
                    known = session.calls.get(call_id)
                    name = names.get(call_id) or (known.name if known else "")
                    cached = await self._gate_result(session, item, name if isinstance(name, str) else "", known)
                    session.results[call_id] = cached
                if self.enforce and cached.item is not None and item.get("output") != cached.item.get("output"):
                    item, changed = {**item, "output": cached.item.get("output")}, True
            kept.append(item)
        if changed:
            body["input"] = kept
        return changed

    async def _gate_result(self, session: Session, item: dict[str, Any], name: str,
                           call: CachedOutcome | None) -> CachedOutcome:
        payload, parsed = result_payload(name, item.get("output"), call.request_id if call else None)
        result = await asyncio.to_thread(self.guardian.step, session, TOOL_CALL_RESULT, payload)
        applied = apply_result(item, payload, parsed, result)
        self._record(session, result, applied, name, item.get("call_id"))
        first = fingerprint(item)
        if not self.enforce or applied.decision == "allow":
            return CachedOutcome("delivered", name, item, result.request_id, first)
        return CachedOutcome("rewritten", name, applied.item, result.request_id, first)

    async def _gate_output(self, session: Session, reply: dict[str, Any]) -> bool:
        """Gate each new function_call before the client sees it (A.4)."""
        changed, removed, kept = False, False, []
        for item in reply["output"]:
            call_id = item.get("call_id") if isinstance(item, dict) else None
            if isinstance(item, dict) and is_foreign_call(item):
                _audit("unsupported_tool_type", session_id=session.session_id, item_type=item.get("type"),
                       direction="output", mode=self.config.mode)
                if self.enforce:
                    changed = removed = True
                else:
                    kept.append(item)
                continue
            if not isinstance(item, dict) or item.get("type") != "function_call":
                kept.append(item)
                continue
            if not isinstance(call_id, str):
                # No call_id means no cache key and no way to match its output, so enforce never delivers it.
                missing = StepResult(TOOL_CALL_REQUEST, None, cause="call_id_missing",
                                     failure_class="observed_agent_error")
                self._record(session, missing, Applied("deny", None, "call_id_missing"), str(item.get("name")), None)
                if self.enforce:
                    changed = removed = True
                else:
                    kept.append(item)
                continue
            cached = session.calls.get(call_id)
            if cached is not None and cached.fingerprint != fingerprint(item):
                self._reused(session, TOOL_CALL_REQUEST, str(item.get("name")), call_id)
                if self.enforce:
                    changed = removed = True
                else:
                    kept.append(item)
                continue
            if cached is None:
                cached = await self._gate_call(session, item)
                session.calls[call_id] = cached
            if not self.enforce:
                kept.append(item)
            elif cached.item is None:
                changed = removed = True
            else:
                changed = changed or cached.item != item
                kept.append(cached.item)
        if removed and not any(isinstance(i, dict) and i.get("type") in ("message", "function_call") for i in kept):
            kept.append(neutral_message())
        if changed:
            reply["output"] = kept
        return changed

    async def _gate_call(self, session: Session, item: dict[str, Any]) -> CachedOutcome:
        name = item.get("name") if isinstance(item.get("name"), str) else ""
        arguments = parse_arguments(item.get("arguments"))
        if arguments is None:
            # The client would fail to parse these arguments too, and nothing the Guardian could judge exists.
            result = StepResult(TOOL_CALL_REQUEST, None, cause="arguments_not_an_object",
                                failure_class="observed_agent_error")
        else:
            result = await asyncio.to_thread(self.guardian.step, session, TOOL_CALL_REQUEST,
                                             call_payload(name, arguments))
        applied = apply_call(item, arguments or {}, result)
        self._record(session, result, applied, name, item.get("call_id"))
        first = fingerprint(item)
        if not self.enforce or applied.decision == "allow":
            return CachedOutcome("delivered", name, item, result.request_id, first)
        if applied.item is None:
            return CachedOutcome("removed", name, None, result.request_id, first)
        return CachedOutcome("rewritten", name, applied.item, result.request_id, first)

    def _reused(self, session: Session, method: str, name: str, call_id: str) -> None:
        """A call_id already gated came back with other content. Enforce withholds it rather than re-gating, since
        the model or the client is the only party that could have reused it."""
        _audit("call_id_reused", session_id=session.session_id, epoch=session.epoch, method=method, tool=name,
               call_id=call_id, mode=self.config.mode)
        result = StepResult(method, None, cause="call_id_reused", failure_class="observed_agent_error")
        self._record(session, result, Applied("deny", None, "call_id_reused"), name, call_id)

    def _record(self, session: Session, result: StepResult, applied: Applied, name: str, call_id: Any) -> None:
        """One audit line per governed step: decision_applied in enforce, shadow_decision in shadow (A.7)."""
        cause = applied.cause or result.cause
        fields = {"session_id": session.session_id, "epoch": session.epoch, "method": result.method, "tool": name,
                  "call_id": call_id, "request_id": result.request_id, "decision": applied.decision,
                  "guardian_decision": result.decision.disposition if result.decision else None,
                  "reason_codes": result.reason_codes, "cause": cause, "failure_class": result.failure_class,
                  "evaluated": result.evaluated}
        _audit("decision_applied" if self.enforce else "shadow_decision", **fields)
        if result.failure_class == "signature_invalid":
            _audit("verification_failed", **fields)
        elif result.cause and result.cause.startswith("http_"):
            _audit("guardian_http_error", **fields)


def _relay(upstream: httpx.Response, edited: dict[str, Any] | None) -> Response:
    content = upstream.content if edited is None else json.dumps(edited).encode("utf-8")
    return Response(content, status_code=upstream.status_code, headers=_client_headers(upstream.headers, decoded=True))


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


MIN_ADMIN_TOKEN_BYTES = 32


def load_admin_token(path: Path) -> str:
    """The admin listener's bearer token: owner-only, no symlink, at least 32 bytes, like the HMAC secret."""
    if path.is_symlink():
        raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} is a symlink")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} must be mode 0600 or 0400")
    token = path.read_text(encoding="utf-8").strip()
    if len(token.encode("utf-8")) < MIN_ADMIN_TOKEN_BYTES:
        raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} must hold at least {MIN_ADMIN_TOKEN_BYTES} bytes")
    return token


def create_admin_app(gateway: Gateway, token: str) -> Starlette:
    """POST /epoch bumps the epoch, which `lab sign` and a policy reload call (A.4, PREMORTEM P3).

    Lab convention, waiting on LAB-15 (issue #588), which wires the CLI to it. It listens on its own port, never
    the model port, so the client FinBot can't reach it through POST /v1/responses.
    """
    expected = f"Bearer {token}".encode("utf-8")

    async def epoch(request: Request) -> Response:
        given = request.headers.get("authorization", "").encode("utf-8")
        if not hmac.compare_digest(given, expected):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"epoch": gateway.bump_epoch()})

    return Starlette(routes=[Route("/epoch", epoch, methods=["POST"])])
