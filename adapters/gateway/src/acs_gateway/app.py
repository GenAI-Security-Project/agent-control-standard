"""The ASGI app: POST /v1/responses forwarded upstream, with tool calls and tool results gated in shadow and enforce."""
from __future__ import annotations

import asyncio
import contextlib
import functools
import hmac
import json
import os
import stat
import time
import uuid
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from acs.client import Negotiated

from acs_gateway.apply import (
    Applied,
    apply_call,
    apply_result,
    call_payload,
    ALLOWED_OUTPUT_TYPES,
    item_type,
    NEUTRAL_LINE,
    neutral_message,
    parse_arguments,
    result_payload,
    unsupported_field,
    unsupported_input_item,
    unsupported_tool,
)
from acs_gateway.config import GatewayConfig, check_client_state_dirs
from acs_gateway.guardian import TOOL_CALL_REQUEST, TOOL_CALL_RESULT, GuardianClient, StepResult, StepToken
from acs_gateway.sessions import (
    CachedOutcome,
    Session,
    SessionMap,
    SessionsBusy,
    canonical,
    content,
    conversation_key,
    fingerprint,
    same_content,
)
from acs_gateway.strict import repeated_key
from acs_gateway.transcript import ModelInputLog, Transcript

# Headers that describe one hop, or that the next hop recomputes, never cross the gateway.
_HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                          "transfer-encoding", "upgrade", "host", "content-length"})
# Governed modes edit bodies, so they ask only for encodings httpx decodes and relay the decoded body.
_GOVERNED_ACCEPT_ENCODING = "gzip, deflate"
_STEP_GRACE_S = 1.0
_OPEN_RETRY_BACKOFF_S = 1.0
# What makes a function_call the call it is. A client rebuilding history may drop id and status, so those don't count.
_CALL_FIELDS = ("type", "name", "call_id", "arguments")


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
    """Any stream value but an absent one, null or false asks for a stream, so an oddity can't slip past the 501."""
    return isinstance(body, dict) and body.get("stream") is not None and body["stream"] is not False


class Gateway:
    """One gateway process: the upstream client, the logs and, outside off mode, the Guardian side."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.model_inputs = ModelInputLog(config.model_input_log)
        self.http: httpx.AsyncClient | None = None
        self.governed = config.mode != "off"
        self.enforce = config.mode == "enforce"
        self.sessions = SessionMap(config.max_sessions, on_evict=self._evicted)
        self.guardian = GuardianClient(config, Transcript(config.transcript_dir)) if self.governed else None
        self.executor: ThreadPoolExecutor | None = None

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        # acs.client blocks on sockets, so Guardian calls run on workers of their own, never the default pool. Each
        # startup gets a fresh executor, since shutdown ends the last one.
        executor = self.executor = ThreadPoolExecutor(max_workers=self.config.workers, thread_name_prefix="acs-gateway")
        try:
            if self.guardian is not None:
                check_client_state_dirs(os.environ)
                await asyncio.get_running_loop().run_in_executor(executor, self.guardian.wait_ready)
            # The model may think for minutes, so only connecting is bounded and the client's own timeout governs.
            async with httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0)) as http:
                self.http = http
                yield
        finally:
            self.http = None
            executor.shutdown(wait=False, cancel_futures=True)

    def _evicted(self, session: Session) -> None:
        _audit("session_evicted", session_id=session.session_id, epoch=session.epoch,
               max_sessions=self.config.max_sessions)

    async def _read_body(self, request: Request) -> bytes | None:
        """The request body, or None once it passes the size limit."""
        limit = self.config.max_body_bytes
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return None
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

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
        headers = forward_headers(request.headers)
        if not self.governed:
            # Off is a pure passthrough, with no size limit on either leg.
            return await self._relay_verbatim(await request.body(), headers)
        raw = await self._read_body(request)
        if raw is None:
            _audit("upstream_error", cause="request_too_large", max_body_bytes=self.config.max_body_bytes)
            return openai_error(413, "The request body is too large.", "invalid_request_error", "request_too_large")
        body = _parse(raw)
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
        repeated = _repeated_key_in_request(raw, body)
        if repeated is not None:
            key, where = repeated
            _audit("duplicate_json_key", key=key, where=where, mode=self.config.mode)
            if self.enforce:
                return openai_error(400, "The request body repeats a JSON key.", "invalid_request_error",
                                    "duplicate_json_key")
        field = unsupported_field(body)
        if field is not None:
            # An allowlist, so a new field fails closed in enforce. Shadow only observes, so every allowlist there
            # records and forwards, and shadow never blocks a run. Server-side history (previous_response_id, conversation,
            # item references) or a stored prompt would hide items or tools from the gateway.
            _audit("unsupported_field", field=field, mode=self.config.mode)
            if self.enforce:
                return openai_error(501, f"The {field} parameter is not supported by this endpoint.",
                                    "invalid_request_error", "unsupported_parameter")
        kind = unsupported_input_item(body)
        if kind is not None:
            _audit("unsupported_item_type", item_type=kind, direction="input", mode=self.config.mode)
            if self.enforce:
                return openai_error(501, f"Input items of type {kind} are not supported by this endpoint.",
                                    "invalid_request_error", "unsupported_item_type")
        unsupported = unsupported_tool(body)
        if unsupported is not None:
            # Function tools only. Any other tool type runs where the gateway can't gate it: a hosted tool runs
            # upstream, and a client-run one has no toolCallRequest mapping yet.
            _audit("unsupported_tool_type", item_type=unsupported, direction="request_tools", mode=self.config.mode)
            if self.enforce:
                return openai_error(501, "Only function tools are supported by this endpoint.",
                                    "invalid_request_error", "unsupported_tool_type")
        try:
            key = conversation_key(body)
        except RecursionError:
            return openai_error(400, "The request body is nested too deeply.", "invalid_request_error")
        try:
            pinned = self.sessions.get(key)
        except SessionsBusy:
            return self._busy()
        # Pinned from the input phase through the output phase, so eviction never splits one turn over two sessions.
        # A session the request moves to after an epoch bump is pinned too, in the same list.
        pins = [pinned]
        pinned.active += 1
        try:
            return await self._governed(key, raw, body, headers, pins)
        except SessionsBusy:
            # An epoch bump mid-request needed a new session and every slot was busy.
            return self._busy()
        finally:
            for session in pins:
                session.active -= 1

    def _busy(self) -> Response:
        _audit("sessions_full", max_sessions=self.config.max_sessions)
        return openai_error(503, "The service is busy. Try again shortly.", "server_error", "busy")

    async def _governed(self, key: str, raw: bytes, body: dict[str, Any], headers: dict[str, str],
                        pins: list[Session]) -> Response:
        session = None
        try:
            async with self._current(key) as session:
                _pin(session, pins)
                await self._ensure_open(session)
                if await self._gate_input(session, body):
                    raw = json.dumps(body).encode("utf-8")
        except SessionsBusy:
            raise
        except Exception as e:  # noqa: BLE001
            failed = self._gating_failed(session, "input", e)
            if failed is not None:
                return failed
        upstream = await self._upstream(raw, body, headers)
        if isinstance(upstream, Response):
            return upstream
        if not 200 <= upstream.status_code < 300:
            return _relay(upstream, None)
        reply = _parse(upstream.content)
        if self.enforce and repeated_key(upstream.content) is not None:
            # The client might read the other copy of a repeated key, one the gateway never gated.
            reply = None
        if not isinstance(reply, dict) or not isinstance(reply.get("output"), list):
            # A success the gateway can't read could carry calls it never gated, so it never reaches the client.
            _audit("upstream_error", cause="upstream_unparseable", http_status=upstream.status_code)
            return openai_error(502, "The model service returned an unreadable response.", "server_error",
                                "upstream_unreadable")
        try:
            async with self._current(key) as session:
                _pin(session, pins)
                # The input phase already made this request's one attempt, so only a new epoch's session opens here.
                if session.handshake is None:
                    await self._ensure_open(session)
                changed = await self._gate_output(session, reply)
        except SessionsBusy:
            raise
        except Exception as e:  # noqa: BLE001
            failed = self._gating_failed(session, "output", e)
            if failed is not None:
                return failed
            return _relay(upstream, None)
        return _relay(upstream, reply if changed else None)

    @contextlib.asynccontextmanager
    async def _current(self, key: str) -> AsyncIterator[Session]:
        """The key's session for the current epoch, locked. A bump that lands while this waits for the lock moves
        the request to the new epoch's session, so nothing finishes on a forgotten one."""
        while True:
            session = self.sessions.get(key)
            await session.lock.acquire()
            if session.epoch == self.sessions.epoch and not session.retired:
                break
            session.lock.release()
        try:
            yield session
        finally:
            session.lock.release()

    async def _ensure_open(self, session: Session) -> None:
        if _opened(session.handshake):
            return
        if session.open_failed_at is not None and time.monotonic() - session.open_failed_at < _OPEN_RETRY_BACKOFF_S:
            # A Guardian that just failed gets a moment before the next attempt. The stored failure keeps denying.
            return
        if session.handshake is not None:
            # acs.client stores a session's handshake first-wins, so a retry needs a fresh session_id.
            # One attempt per request, and every step denies until one succeeds.
            _audit("session_retried", previous_session_id=session.session_id,
                   cause=getattr(session.handshake, "cause", None) or "session_start_failed")
            session.session_id = str(uuid.uuid4())
        await asyncio.get_running_loop().run_in_executor(self.executor, self.guardian.open, session)
        session.open_failed_at = None if _opened(session.handshake) else time.monotonic()

    def _gating_failed(self, session: Session | None, phase: str, error: Exception) -> Response | None:
        """A fault in the gateway's own gating code: shadow forwards unchanged (None), enforce fails closed."""
        _audit("gateway_step_error", session_id=session.session_id if session else None, phase=phase, mode=self.config.mode,
               error=f"{type(error).__name__}: {error}")
        if not self.enforce:
            return None
        return openai_error(500, "The request could not be completed.", "server_error", "internal_error")

    async def _upstream(self, raw: bytes, body: Any, headers: dict[str, str]) -> UpstreamAnswer | Response:
        """POST upstream and read the whole answer, up to the size limit, so the gateway can gate it."""
        self.model_inputs.append(body if body is not None else raw.decode("utf-8", "replace"))
        assert self.http is not None
        try:
            upstream = await self.http.send(
                self.http.build_request("POST", f"{self.config.upstream_url}/responses", content=raw,
                                        headers=headers), stream=True)
            try:
                chunks, size = [], 0
                async for chunk in upstream.aiter_bytes():
                    size += len(chunk)
                    if size > self.config.max_body_bytes:
                        _audit("upstream_error", cause="upstream_too_large",
                               max_body_bytes=self.config.max_body_bytes)
                        return openai_error(502, "The model service returned a response that is too large.",
                                            "server_error", "upstream_too_large")
                    chunks.append(chunk)
            finally:
                await upstream.aclose()
        except httpx.HTTPError as e:
            _audit("upstream_error", cause="upstream_unreachable", error=type(e).__name__)
            return openai_error(502, "The model service is unavailable.", "server_error", "upstream_unavailable")
        if not 200 <= upstream.status_code < 300:
            _audit("upstream_error", cause="upstream_status", http_status=upstream.status_code)
        return UpstreamAnswer(upstream.status_code, upstream.headers, b"".join(chunks))

    async def _relay_verbatim(self, raw: bytes, headers: dict[str, str]) -> Response:
        """Off mode relays the answer, streamed or not, as it arrives, encoding and headers included."""
        if self.model_inputs.enabled:
            body = _parse(raw)
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
            call_id = item.get("call_id") if isinstance(item, dict) else None
            if not isinstance(call_id, str):
                kept.append(item)
                continue
            if item.get("type") == "function_call" and call_id in session.calls:
                cached = session.calls[call_id]
                if cached.item is None:
                    # Never delivered, so only a forged history carries it.
                    if self.enforce:
                        changed = True
                        continue
                elif any(item.get(f) != cached.item.get(f) for f in _CALL_FIELDS):
                    # Only the arguments are JSON, so only they are compared canonically. type, name and call_id are
                    # exact strings, so "1e2" never matches "100".
                    if (any(item.get(f) != cached.item.get(f) for f in ("type", "name", "call_id"))
                            or canonical(item.get("arguments")) != cached.canonical_arguments):
                        self._reused(session, TOOL_CALL_REQUEST, str(item.get("name")), call_id,
                                     decision="modify" if self.enforce else "deny")
                    if self.enforce:
                        # Any byte difference sends the call back as delivered, so the model reads exactly the call
                        # the Guardian judged, never the client's re-serialization of it.
                        item = {**item, **{f: cached.item.get(f) for f in _CALL_FIELDS}}
                        changed = True
            elif item.get("type") == "function_call_output":
                cached = session.results.get(call_id)
                if cached is not None and not same_content(item, cached):
                    self._reused(session, TOOL_CALL_RESULT, cached.name, call_id)
                    if self.enforce:
                        item, changed = {**item, "output": NEUTRAL_LINE}, True
                    kept.append(item)
                    continue
                if cached is None:
                    known = session.calls.get(call_id)
                    if known is not None:
                        # The gateway's own record names the tool, never the client's resent copy of the call.
                        name = known.name
                    else:
                        resent = names.get(call_id)
                        name = resent if isinstance(resent, str) else ""
                        _audit("result_name_from_client", session_id=session.session_id, call_id=call_id, tool=name)
                    cached = await self._gate_result(session, item, name, known)
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
        result = await self._step(session, TOOL_CALL_RESULT, payload)
        applied = apply_result(item, payload, parsed, result)
        self._record(session, result, applied, name, item.get("call_id"))
        first, raw = fingerprint(item), content(item)
        if not self.enforce or applied.decision == "allow":
            return CachedOutcome("delivered", name, item, result.request_id, first, raw)
        return CachedOutcome("rewritten", name, applied.item, result.request_id, first, raw)

    async def _gate_output(self, session: Session, reply: dict[str, Any]) -> bool:
        """Gate each new function_call before the client sees it (A.4)."""
        changed, removed, kept = False, False, []
        for item in reply["output"]:
            call_id = item.get("call_id") if isinstance(item, dict) else None
            if item_type(item) not in ALLOWED_OUTPUT_TYPES:
                _audit("unsupported_item_type", session_id=session.session_id, item_type=item_type(item),
                       direction="output", mode=self.config.mode)
                if self.enforce:
                    changed = removed = True
                    kept.append(_REMOVED)
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
                    kept.append(_REMOVED)
                else:
                    kept.append(item)
                continue
            cached = session.calls.get(call_id)
            if cached is not None and not same_content(item, cached):
                self._reused(session, TOOL_CALL_REQUEST, str(item.get("name")), call_id)
                if self.enforce:
                    changed = removed = True
                    kept.append(_REMOVED)
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
                kept.append(_REMOVED)
            else:
                changed = changed or cached.item != item
                kept.append(cached.item)
        if removed:
            kept = _without_orphaned_reasoning(kept)
        if removed and not any(isinstance(i, dict) and i.get("type") in ("message", "function_call") for i in kept):
            kept.append(neutral_message())
        if changed:
            reply["output"] = kept
        return changed

    async def _gate_call(self, session: Session, item: dict[str, Any]) -> CachedOutcome:
        name = item.get("name") if isinstance(item.get("name"), str) else ""
        arguments = parse_arguments(item.get("arguments"))
        if arguments is None:
            # Arguments that aren't one unambiguous JSON object leave the Guardian nothing it could judge safely.
            cause = "duplicate_json_key" if repeated_key(item.get("arguments")) else "arguments_not_an_object"
            result = StepResult(TOOL_CALL_REQUEST, None, cause=cause, failure_class="observed_agent_error")
        else:
            result = await self._step(session, TOOL_CALL_REQUEST, call_payload(name, arguments))
        applied = apply_call(item, arguments or {}, result)
        self._record(session, result, applied, name, item.get("call_id"))
        first, raw = fingerprint(item), content(item)
        if not self.enforce or applied.decision == "allow":
            return CachedOutcome("delivered", name, item, result.request_id, first, raw,
                                 canonical(item.get("arguments")))
        if applied.item is None:
            return CachedOutcome("removed", name, None, result.request_id, first, raw)
        return CachedOutcome("rewritten", name, applied.item, result.request_id, first, raw,
                             canonical(applied.item.get("arguments")))

    async def _step(self, session: Session, method: str, payload: dict[str, Any]) -> StepResult:
        """One Guardian step on the gateway's executor, under one deadline that starts when it is queued."""
        if session.retired:
            # A step of this request hung and retired the session, so its remaining steps deny without sending.
            return StepResult(method, None, cause="session_retired", failure_class="observed_agent_error")
        timeout = session.posture.timeout_for(method) if session.posture else self.config.decision_timeout_s
        token = StepToken(time.monotonic() + timeout)
        future = asyncio.get_running_loop().run_in_executor(
            self.executor, functools.partial(self.guardian.step, session, method, payload, token))
        try:
            # acs.client bounds the exchange itself. The grace covers a worker stuck outside it, such as a slow disk.
            return await asyncio.wait_for(asyncio.shield(future), timeout + _STEP_GRACE_S)
        except asyncio.TimeoutError:
            await self._settle_abandoned(session, method, token, future, timeout)
            return StepResult(method, token.request_id, cause="decision_timeout", failure_class="timeout")
        except asyncio.CancelledError:
            # The request itself was cancelled (a client disconnect, a shutdown). The step must not outlive it.
            await self._settle_abandoned(session, method, token, future, timeout)
            raise

    async def _settle_abandoned(self, session: Session, method: str, token: StepToken, future: Any,
                                timeout: float) -> None:
        """Stop a step the loop no longer waits for. An unclaimed step is cancelled and writes nothing. A claimed one
        holds the session lock while its lines land, for one more timeout at most, and past that the session retires
        and the worker writes and sends nothing more."""
        if token.cancel():
            return
        try:
            await asyncio.wait_for(asyncio.shield(future), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            token.retire()
            self.sessions.retire(session)
            _audit("session_retired", session_id=session.session_id, method=method, cause="step_hung",
                   request_id=token.request_id)

    def _reused(self, session: Session, method: str, name: str, call_id: str, decision: str = "deny") -> None:
        """A call_id already gated came back with other content. Enforce withholds it rather than re-gating, since
        the model or the client is the only party that could have reused it."""
        _audit("call_id_reused", session_id=session.session_id, epoch=session.epoch, method=method, tool=name,
               call_id=call_id, mode=self.config.mode)
        result = StepResult(method, None, cause="call_id_reused", failure_class="observed_agent_error")
        self._record(session, result, Applied(decision, None, "call_id_reused"), name, call_id)

    def _record(self, session: Session, result: StepResult, applied: Applied, name: str, call_id: Any) -> None:
        """One audit line per governed step: decision_applied in enforce, shadow_decision in shadow (A.7)."""
        cause = applied.cause or result.cause
        fields = {"session_id": session.session_id, "epoch": session.epoch, "method": result.method, "tool": name,
                  "call_id": call_id, "request_id": result.request_id, "decision": applied.decision,
                  "guardian_decision": result.decision.disposition if result.decision else None,
                  "reason_codes": result.reason_codes, "cause": cause, "failure_class": result.failure_class}
        _audit("decision_applied" if self.enforce else "shadow_decision", **fields)
        if result.failure_class == "signature_invalid":
            _audit("verification_failed", **fields)
        elif result.cause and result.cause.startswith("http_"):
            _audit("guardian_http_error", **fields)


def _pin(session: Session, pins: list[Session]) -> None:
    """Pin a session for the rest of the request, once."""
    if not any(pinned is session for pinned in pins):
        pins.append(session)
        session.active += 1


def _repeated_key_in_request(raw: bytes, body: dict[str, Any]) -> tuple[str, str] | None:
    """A key repeated anywhere in the body, or inside the JSON strings of a function_call's arguments or a
    function_call_output's output, which the model reads as text. Returns (key, where) or None."""
    key = repeated_key(raw)
    if key is not None:
        return key, "body"
    items = body.get("input")
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("type") in ("function_call", "function_call_output"):
            field = "arguments" if item["type"] == "function_call" else "output"
            key = repeated_key(item.get(field))
            if key is not None:
                return key, f"{item['type']}.{field}"
    return None


def _opened(handshake: Any) -> bool:
    """A handshake that negotiated and whose sessionStart got a decision."""
    return isinstance(handshake, Negotiated) and handshake.start_failure is None


# Marks where enforce removed an output item, so reasoning is judged by what its turn kept.
_REMOVED = object()


def _without_orphaned_reasoning(marked: list[Any]) -> list[Any]:
    """Drop each run of consecutive reasoning items when every item of its turn was removed.

    A run of reasoning belongs to the non-reasoning items after it, up to the next reasoning run, which is how a
    model emits one reasoning step before several parallel calls. A reasoning model rejects resent reasoning whose
    turn is gone, and also a call resent without its reasoning. So [R, removed, kept] keeps R, [R, removed] drops it,
    and [R1, R2, kept, R3, removed] keeps R1 and R2 and drops R3. A run with nothing after it stays.
    """
    kept: list[Any] = []
    run: list[Any] = []
    turn: list[Any] = []

    def close() -> None:
        survivors = [item for item in turn if item is not _REMOVED]
        if survivors or not turn:
            kept.extend(run)
        kept.extend(survivors)

    for item in marked:
        if isinstance(item, dict) and item.get("type") == "reasoning":
            if turn:
                close()
                run, turn = [], []
            run.append(item)
        else:
            turn.append(item)
    close()
    return kept


@dataclass(frozen=True)
class UpstreamAnswer:
    """A whole upstream answer, its body already decoded."""
    status_code: int
    headers: httpx.Headers
    content: bytes


def _relay(upstream: UpstreamAnswer, edited: dict[str, Any] | None) -> Response:
    content = upstream.content if edited is None else json.dumps(edited).encode("utf-8")
    return Response(content, status_code=upstream.status_code, headers=_client_headers(upstream.headers, decoded=True))


def _parse(raw: bytes) -> Any:
    """The decoded JSON, or None. Nesting past the parser's recursion limit counts as unparseable."""
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
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
    """The admin listener's bearer token, held to acs.client's HMAC secret rules: no symlink, a regular file, mode 0600
    or 0400, owned by the gateway's own uid, and at least 32 bytes.

    The checks and the read use one descriptor opened with O_NOFOLLOW, so the file can't be swapped between them, and
    O_NONBLOCK keeps a FIFO from stalling startup.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        if path.is_symlink():
            raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} is a symlink") from e
        raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} can't be opened: {e}") from e
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} must be mode 0600 or 0400")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ValueError(f"ACS_GATEWAY_ADMIN_TOKEN_FILE {path} is owned by uid {info.st_uid}, "
                             f"not the gateway's uid {os.geteuid()}")
        token = f.read().decode("utf-8").strip()
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
