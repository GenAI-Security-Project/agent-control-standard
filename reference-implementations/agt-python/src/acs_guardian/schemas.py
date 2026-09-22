"""JSON Schema validation against the repository's v0.1.0 schemas.

The schemas are loaded from ``specification/v0.1.0/`` in this repository by
relative path -- the same contract the TypeScript reference implementation's
``SCHEMA_ROOT`` relies on -- so the implementation is always validated against
the schemas under review rather than a copy that can drift. ``ACS_SPEC_ROOT``
overrides the location for an out-of-tree deployment.

Three validation points, each mapping to a registry code:

- the envelope shape (``request-envelope.json``) -> ``-32600``;
- the method's hook payload (``hooks/<method>.json``) -> ``-32602``;
- the response the Guardian is about to send (``response-envelope.json``) ->
  reported, never fatal (the outbound counterpart of the inbound checks; a
  response that fails it is logged, not replaced, because replacing it could
  turn a governed step into an ungoverned one).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from .errors import INVALID_PARAMS, INVALID_REQUEST, AcsError

SPEC_ROOT_ENV = "ACS_SPEC_ROOT"

_HANDSHAKE_SCHEMA_ID = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/handshake.json"

# method -> hook payload schema, relative to specification/v0.1.0.
_HOOK_SCHEMAS = {
    "steps/sessionStart": "hooks/session-start.json",
    "steps/agentTrigger": "hooks/agent-trigger.json",
    "steps/turnStart": "hooks/turn-start.json",
    "steps/userMessage": "hooks/user-message.json",
    "steps/agentResponse": "hooks/agent-response.json",
    "steps/knowledgeRetrieval": "hooks/knowledge-retrieval.json",
    "steps/memoryContextRetrieval": "hooks/memory-context-retrieval.json",
    "steps/memoryStore": "hooks/memory-store.json",
    "steps/toolCallRequest": "hooks/tool-call-request.json",
    "steps/toolCallResult": "hooks/tool-call-result.json",
    "steps/preCompact": "hooks/pre-compact.json",
    "steps/postCompact": "hooks/post-compact.json",
    "steps/subagentStart": "hooks/subagent-start.json",
    "steps/subagentStop": "hooks/subagent-stop.json",
    "steps/skillRegister": "hooks/skill-register.json",
    "steps/skillLoad": "hooks/skill-load.json",
    "steps/skillUnload": "hooks/skill-unload.json",
    "steps/turnEnd": "hooks/turn-end.json",
    "steps/sessionEnd": "hooks/session-end.json",
    "system/ping": "hooks/system-ping.json",
    "agbom/snapshot": "hooks/agbom-snapshot.json",
    "agbom/changed": "hooks/agbom-changed.json",
}

HOOK_METHODS = tuple(method for method in _HOOK_SCHEMAS if method.startswith("steps/"))


def default_spec_root() -> Path:
    override = os.environ.get(SPEC_ROOT_ENV)
    if override:
        return Path(override)
    # src/acs_guardian/schemas.py -> reference-implementations/agt-python -> repository root.
    return Path(__file__).resolve().parents[4] / "specification" / "v0.1.0"


def _first_error_message(error: ValidationError) -> tuple[str, str]:
    pointer = "/" + "/".join(str(part) for part in error.absolute_path) if error.absolute_path else ""
    return f"{error.message} at {pointer or '<root>'}", pointer


class SchemaRegistry:
    """Loads the v0.1.0 schemas once and validates envelopes, params, payloads, responses."""

    def __init__(self, spec_root: Path | None = None) -> None:
        self.spec_root = spec_root or default_spec_root()
        if not (self.spec_root / "request-envelope.json").is_file():
            # Fail fast and loudly: a Guardian that boots without schemas would
            # answer every handshake with a confusing -32602 instead.
            raise FileNotFoundError(
                f"ACS schemas not found under {self.spec_root}; run from the repository "
                f"or set {SPEC_ROOT_ENV} to a specification/v0.1.0 directory"
            )
        self._validators: dict[str, Draft202012Validator] = {}
        registry = Registry()
        schemas: dict[str, dict[str, Any]] = {}
        for path in sorted(self.spec_root.rglob("*.json")):
            try:
                schema = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(schema, dict):
                continue
            schema_id = schema.get("$id")
            if not isinstance(schema_id, str):
                continue
            registry = registry.with_resource(schema_id, Resource.from_contents(schema))
            schemas[schema_id] = schema
        self._registry = registry
        self._schemas = schemas

    def _validator(self, relative_path: str) -> Draft202012Validator:
        """Compile once per schema: the enforcement path is synchronous and hot."""
        cached = self._validators.get(relative_path)
        if cached is None:
            path = self.spec_root / relative_path
            schema = json.loads(path.read_text(encoding="utf-8"))
            cached = Draft202012Validator(schema, registry=self._registry)
            self._validators[relative_path] = cached
        return cached

    def validate_request(self, envelope: Any) -> None:
        """The JSON-RPC envelope shape. Failure is INVALID_REQUEST (-32600)."""
        if not isinstance(envelope, dict):
            raise AcsError(INVALID_REQUEST, "request is not a JSON-RPC object", signable=False)
        for error in self._validator("request-envelope.json").iter_errors(envelope):
            message, _ = _first_error_message(error)
            raise AcsError(INVALID_REQUEST, f"request envelope invalid: {message}", signable=False)

    def validate_client_hello(self, client_hello: Any) -> None:
        """The ClientHello shape (handshake.json $defs/ClientHello). Failure is INVALID_PARAMS."""
        schema = self._schemas.get(_HANDSHAKE_SCHEMA_ID, {}).get("$defs", {}).get("ClientHello")
        if not isinstance(schema, dict):
            raise AcsError(INVALID_PARAMS, "handshake schema is not available")
        for error in Draft202012Validator(schema, registry=self._registry).iter_errors(client_hello):
            message, _ = _first_error_message(error)
            raise AcsError(INVALID_PARAMS, f"ClientHello invalid: {message}")

    def validate_payload(self, method: str, payload: Any) -> None:
        """The method's hook payload. Failure is INVALID_PARAMS (-32602)."""
        relative = _HOOK_SCHEMAS.get(method)
        if relative is None:
            raise AcsError(INVALID_PARAMS, f"no payload schema for method {method}")
        for error in self._validator(relative).iter_errors(payload):
            message, pointer = _first_error_message(error)
            raise AcsError(
                INVALID_PARAMS,
                f"payload invalid for {method}: {message}",
                data={"pointer": pointer, "method": method},
            )

    def hook_schema_id(self, method: str) -> str | None:
        """The ``$id`` of a hook's schema, so tests can pin the method -> file mapping."""
        relative = _HOOK_SCHEMAS.get(method)
        if relative is None:
            return None
        schema = self._validator(relative).schema
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        return schema_id if isinstance(schema_id, str) else None

    def validate_response(self, response: Any) -> str | None:
        """Check the outbound response; return a finding, never raise (§ the module doc)."""
        try:
            for error in self._validator("response-envelope.json").iter_errors(response):
                message, _ = _first_error_message(error)
                return message
        except Exception as exc:  # a registry that will not build is reported, not thrown
            return f"response could not be checked: {exc}"
        return None
