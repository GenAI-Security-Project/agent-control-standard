"""
ACS v0.1.0 Guardian checks (summary-level Core + emission support).

SCOPE — read before trusting a green run. This suite exercises the
Core requirements enumerated in `docs/spec/conformance.md`'s SUMMARY
(lines 13-26) plus the normative sections those bullets cite, and
reference-stack coverage of the SHOULD/conditional items (MODIFY,
system/ping, Wrapped-MCP shape). It is deliberately NOT a
requirement-by-requirement audit of every normative MUST/REQUIRED in
the linked sections — those sections carry many more (handshake
negotiation edge cases, full decision semantics, hook completeness,
two-sided live payload validation) than are checked here. A green run
therefore means "the reference stack passes the summary-level Core
checks and the emission suite", NOT "ACS-Core conformant". Full
requirement-by-requirement ACS-Core conformance — spanning the
Guardian, the framework wiring, and production config, not the adapter
alone — is a separate tracked milestone (requirement ledger + missing
behavioral tests).

Each test docstring quotes the spec text it falsifies; CitationGuard
pins the cited lines so spec edits that move/rewrite them go red.

Run from the adapters/ directory:

    python -m unittest test_acs_core_conformance

The Wrapped-MCP namespace is validated for wire-format shape only
(envelope validates, Guardian returns a structured response, no crash);
full MCP request wrapping is NOT implemented, and whether it belongs in
Core at all is a pending spec-owner decision. See `Core10_WrappedMcp`.

Result: any FAIL/ERROR names the specific requirement that broke, with
the spec citation in the test docstring.

Adopter workflow: copy our adapters, modify for your stack, run this
file. A failure tells you which spec line you broke. A deployment that
legitimately omits a SHOULD/conditional item (no MODIFY support, no
MCP) may need to prune the corresponding reference-stack tests — the
MUST tests are not prunable.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac as _hmac
import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
GUARDIAN_SCRIPT = HERE / "example-guardian" / "example_guardian.py"
COMMON_DIR = HERE / "_common"

sys.path.insert(0, str(COMMON_DIR))
import acs_common  # noqa: E402

# Canonical schemas — REQUIRED for envelope/payload validation; the
# suite FAILS loudly without them rather than silently skipping.
# Default is the in-repo copy (one directory up) so a fresh clone
# validates against the schemas in this tree; ACS_SPEC_DIR overrides.
SPEC_DIR = Path(
    os.environ.get(
        "ACS_SPEC_DIR",
        str(Path(__file__).resolve().parents[1] / "specification" / "v0.1.0"),
    )
)

# A fixed signing secret used only inside this test process. Real
# deployments use ACS_HMAC_SECRET_FILE; we pass it via env.
TEST_HMAC_SECRET = "acs-core-conformance-test-secret-not-for-production"


# =============================================================================
# Test harness — spawns the Guardian, exchanges signed envelopes.
# Helpers come from adapters/_common/test_harness.py — see that file for
# the canonical implementations of launch_guardian, schema validators,
# and ProgrammableGuardian.
# =============================================================================

from test_harness import (  # noqa: E402
    launch_guardian,
    build_local_resolver as _build_local_resolver,
    validate_request_envelope as _validate_request_envelope,
    validate_response_envelope as _validate_response_envelope,
)


class CoreHarness(unittest.TestCase):
    """Base class — spawns a Guardian with HMAC signing required.

    Each test class inherits and adds tests. setUpClass spawns one
    Guardian for the class; tests share it. Each test creates a fresh
    session_id so per-session state (replay set, chain head) doesn't
    cross-contaminate.
    """

    HMAC_SECRET: str | None = TEST_HMAC_SECRET  # subclass can null to disable

    @classmethod
    def setUpClass(cls) -> None:
        if not SPEC_DIR.exists():
            raise RuntimeError(
                f"Canonical ACS schemas not found at {SPEC_DIR}. "
                "ACS-Core conformance tests REQUIRE the canonical v0.1.0 "
                "schemas. Set ACS_SPEC_DIR to a clone of "
                "GenAI-Security-Project/agent-control-standard/specification/v0.1.0/. "
                "This is a hard fail — schema validation is non-negotiable."
            )
        # Hard-fail if the date-time format checker is degraded: without
        # `rfc3339-validator` (pinned in requirements-test.txt) it is a
        # no-op and invalid-timestamp tests silently pass.
        from jsonschema import Draft202012Validator
        _fc = Draft202012Validator.FORMAT_CHECKER
        if _fc.conforms("not-a-date", "date-time"):
            raise RuntimeError(
                "jsonschema date-time format checker is degraded — "
                "'not-a-date' was accepted as a valid date-time. "
                "Install `rfc3339-validator` (pin in adapters/requirements-test.txt). "
                "Without it, conformance tests that assert invalid "
                "timestamps must fail validation will silently pass."
            )
        env = os.environ.copy()
        cls.statedir = tempfile.mkdtemp(prefix="acs-core-conformance-")
        env["ACS_GUARDIAN_STATE_DIR"] = cls.statedir
        if cls.HMAC_SECRET:
            env["ACS_HMAC_SECRET"] = cls.HMAC_SECRET
            env.pop("ACS_DEV_MODE", None)
        else:
            env["ACS_DEV_MODE"] = "1"
            env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc, cls.port = launch_guardian(env=env)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()
        import shutil
        shutil.rmtree(cls.statedir, ignore_errors=True)

    def _make_envelope(self, method: str, payload: dict | None = None, *,
                       session_id: str | None = None,
                       request_id: str | None = None,
                       timestamp: str | None = None,
                       sign: bool = True) -> dict:
        sid = session_id or str(uuid.uuid4())
        env = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {
                "acs_version": "0.1.0",
                "request_id": request_id or str(uuid.uuid4()),
                "timestamp": timestamp or acs_common.iso8601_now(),
                "metadata": {
                    "agent_id": "conformance-test",
                    "session_id": sid,
                    "platform": "test",
                },
                "payload": payload or {},
            },
        }
        if sign and self.HMAC_SECRET:
            key = acs_common.derive_session_key(self.HMAC_SECRET.encode(), sid)
            acs_common.sign_envelope(env, key=key, session_id=sid)
        return env

    def _post(self, envelope: dict) -> dict:
        body = json.dumps(envelope).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())


# =============================================================================
# CORE-01 — Handshake (conformance.md:17, §4)
# =============================================================================
#
# "Handshake — handshake/hello with ClientHello/ServerHello"
# §4: "Version mismatch terminates with UNSUPPORTED_VERSION (-32001)"
# §4: ServerHello required keys negotiated_version, methods_evaluated,
#     selected_transport, timeout_config
# =============================================================================

class Core01_Handshake(CoreHarness):

    def test_handshake_returns_server_hello(self) -> None:
        """conformance.md:17 — 'Handshake — handshake/hello with
        ClientHello/ServerHello'. A Guardian MUST respond to
        handshake/hello with a ServerHello in result.payload, AND
        the response envelope itself MUST validate against
        response-envelope.json."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        })  # signed — conformance.md:23 exempts only system/ping
        resp = self._post(env)
        self.assertIn("result", resp,
            f"handshake/hello must return a result; got {resp}")
        # Response envelope MUST validate against response-envelope.json
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"handshake response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))
        result = resp["result"]
        server_hello = result.get("payload", {})
        # handshake.json:70 — ServerHello required
        for required_field in ("negotiated_version", "methods_evaluated",
                               "selected_transport", "timeout_config"):
            self.assertIn(required_field, server_hello,
                f"ServerHello missing required field {required_field!r}; "
                f"got {server_hello}")
        self.assertEqual(server_hello["negotiated_version"], "0.1.0")
        self.assertIn("default_ms", server_hello["timeout_config"])

    def test_forward_compat_accepts_matching_major_version(self) -> None:
        """§4 forward-compat: 'Accept X.Y.Z matching major version.' A
        client advertising only 0.1.1 (same major as the Guardian's
        0.1.0) MUST be accepted, not refused with UNSUPPORTED_VERSION."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.1"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
        })
        resp = self._post(env)
        self.assertIn("result", resp,
            f"a matching-major (0.1.1) ClientHello must be accepted; got {resp}")
        self.assertEqual(resp["result"]["payload"]["negotiated_version"], "0.1.0")

    def test_client_hello_missing_required_field_refused(self) -> None:
        """handshake.json $defs/ClientHello requires acs_versions_supported,
        methods_implemented, transports_supported, provenance_producer;
        a ClientHello missing one MUST be refused."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            # transports_supported + provenance_producer MISSING
        })
        resp = self._post(env)
        self.assertIn("error", resp,
            f"a ClientHello missing required fields must be refused; got {resp}")
        self.assertEqual(resp["error"]["code"], -32600)

    def test_unknown_client_hello_fields_ignored(self) -> None:
        """Forward-compat: unknown EXTRA fields in a ClientHello are
        ignored, not rejected (the other half of the rule)."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "some_future_field": {"nested": True},  # unknown → ignore
        })
        resp = self._post(env)
        self.assertIn("result", resp,
            f"unknown ClientHello fields must be ignored, not rejected; got {resp}")

    def test_non_object_jsonrpc_returns_invalid_request(self) -> None:
        """A top-level JSON array (a JSON-RPC batch, unsupported in v0.1)
        or any non-object MUST return -32600, not crash the Guardian."""
        import urllib.request
        body = json.dumps([{"jsonrpc": "2.0", "method": "system/ping", "id": "1"}]).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                resp = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read().decode())
        self.assertIn("error", resp,
            f"a JSON-RPC batch/array must return an error, not crash; got {resp}")
        self.assertEqual(resp["error"]["code"], -32600)

    def test_unsigned_client_hello_is_refused(self) -> None:
        """conformance.md:23 — 'every request and response carries a
        signature'; the only exemption is system/ping (§13). An unsigned
        ClientHello to a signing-required Guardian MUST be refused with
        -32004: the HMAC key derives from the pre-shared secret +
        session_id, both known before the handshake."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        }, sign=False)
        resp = self._post(env)
        self.assertIn("error", resp,
            "unsigned ClientHello must be refused when signing is "
            f"required; got {resp}")
        self.assertEqual(resp["error"].get("code"), -32004,
            f"expected SIGNATURE_INVALID (-32004), got {resp['error']!r}")

    def test_version_mismatch_returns_unsupported_version(self) -> None:
        """§4: 'Version mismatch terminates with UNSUPPORTED_VERSION
        (-32001)'."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["99.0.0"],  # unsupported
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
        })  # signed: the signature gate runs before version negotiation
        resp = self._post(env)
        self.assertIn("error", resp,
            f"version-mismatch handshake must error; got {resp}")
        self.assertEqual(resp["error"]["code"], -32001,
            f"§4: code must be -32001 UNSUPPORTED_VERSION; got {resp['error']}")


# =============================================================================
# CORE-02 — Request envelope shape (conformance.md:18, §3, request-envelope.json)
# =============================================================================
#
# "JSON-RPC 2.0 with ACS extensions. request_id, timestamp, acs_version,
#  metadata required on every request."
#
# request-envelope.json:7-8 — top-level required {jsonrpc, method, id, params};
#                              additionalProperties: false
# request-envelope.json:10 — jsonrpc const "2.0"
# request-envelope.json:25 — AcsParams required {acs_version, request_id,
#                              timestamp, metadata, payload}
# request-envelope.json:62 — Metadata required {agent_id, session_id}
# =============================================================================

class Core02_EnvelopeShape(CoreHarness):

    def test_valid_envelope_passes_canonical_schema(self) -> None:
        """conformance.md:18 — 'request_id, timestamp, acs_version,
        metadata required on every request'. A correctly-built envelope
        MUST pass request-envelope.json validation including
        format-checker (uuid, date-time)."""
        env = self._make_envelope("steps/sessionStart", payload={})
        errors = _validate_request_envelope(env)
        self.assertEqual(errors, [],
            f"Conformant envelope FAILS request-envelope.json validation:\n  - "
            + "\n  - ".join(errors))

    def test_contradiction_validator_actually_works(self) -> None:
        """Falsifier check: a deliberately broken envelope MUST be
        rejected. Without this, a no-op validator would pass every
        positive-case test."""
        broken = {"jsonrpc": "2.0"}  # missing method, id, params entirely
        errors = _validate_request_envelope(broken)
        self.assertNotEqual(errors, [],
            "validator did not reject an envelope missing method/id/params — "
            "the schema check is a no-op")

    def test_jsonrpc_field_is_literal_2_0(self) -> None:
        """request-envelope.json:10 — `jsonrpc` is the literal string
        "2.0"; any other value MUST be rejected by schema validation."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["jsonrpc"] = "1.0"  # tamper
        errors = _validate_request_envelope(env)
        self.assertTrue(any("jsonrpc" in e for e in errors),
            f"jsonrpc != '2.0' must fail validation; got errors {errors}")

    def test_no_additional_top_level_fields_allowed(self) -> None:
        """request-envelope.json:8 — `additionalProperties: false` at
        envelope root. Any extra top-level key MUST be rejected."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["unknown_field"] = "should be rejected"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("unknown_field" in e or "Additional" in e for e in errors),
            f"Extra top-level field must be rejected; got {errors}")

    def test_acs_params_all_required_fields_present(self) -> None:
        """request-envelope.json:25 — AcsParams MUST contain
        acs_version, request_id, timestamp, metadata, payload."""
        env = self._make_envelope("steps/sessionStart", payload={})
        for required in ("acs_version", "request_id", "timestamp",
                          "metadata", "payload"):
            self.assertIn(required, env["params"],
                f"params must contain {required!r}")
        # Now drop each in turn; validator must reject every variant.
        for required in ("acs_version", "request_id", "timestamp",
                          "metadata", "payload"):
            broken = json.loads(json.dumps(env))
            del broken["params"][required]
            errors = _validate_request_envelope(broken)
            self.assertTrue(errors,
                f"envelope missing required params.{required} must fail; "
                f"validator passed instead")

    def test_metadata_required_agent_and_session_id(self) -> None:
        """request-envelope.json:62 — metadata MUST contain agent_id
        and session_id."""
        env = self._make_envelope("steps/sessionStart", payload={})
        for required in ("agent_id", "session_id"):
            self.assertIn(required, env["params"]["metadata"])
        # Drop each; validator rejects.
        for required in ("agent_id", "session_id"):
            broken = json.loads(json.dumps(env))
            del broken["params"]["metadata"][required]
            errors = _validate_request_envelope(broken)
            self.assertTrue(any(required in e for e in errors),
                f"envelope missing metadata.{required} must fail validation")

    def test_request_id_is_uuid(self) -> None:
        """request-envelope.json:32-35 — request_id format: uuid."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["request_id"] = "not-a-uuid"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("request_id" in e for e in errors),
            f"non-UUID request_id must fail validation; got {errors}")

    def test_timestamp_is_iso8601(self) -> None:
        """request-envelope.json:38-40 — timestamp format: date-time."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["timestamp"] = "yesterday"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("timestamp" in e for e in errors),
            f"non-ISO timestamp must fail validation; got {errors}")

    def test_acs_version_matches_semver(self) -> None:
        """request-envelope.json:27-30 — acs_version pattern ^\\d+\\.\\d+\\.\\d+$."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["acs_version"] = "v1"  # not semver
        errors = _validate_request_envelope(env)
        self.assertTrue(any("acs_version" in e for e in errors),
            f"non-semver acs_version must fail validation; got {errors}")

    def test_method_namespace_pattern(self) -> None:
        """request-envelope.json:13-14 — method MUST match
        ^(steps/|protocols/|agbom/|trace/|system/|handshake/|wrapped:).+"""
        env = self._make_envelope("arbitrary/method", payload={})
        errors = _validate_request_envelope(env)
        self.assertTrue(any("method" in e for e in errors),
            f"method outside reserved namespaces must fail validation")


# =============================================================================
# CORE-03 — Hook taxonomy minimum (conformance.md:19)
# =============================================================================
#
# "At minimum: sessionStart, userMessage or agentTrigger, toolCallRequest,
#  toolCallResult, agentResponse, sessionEnd"
# =============================================================================

class Core03_HookTaxonomyMinimum(CoreHarness):
    """Each hook in the Core minimum set must be accepted with a valid
    disposition (positive case) AND a malformed payload for that hook
    must be rejected by Guardian-side schema validation (contradiction).
    Without the contradiction, a Guardian that returns 'allow' for any
    payload — including malformed ones — would pass."""

    # (method, valid_payload, broken_payload, payload_schema_file)
    # Broken payloads exploit per-hook schema constraints — wrong types
    # on enum-constrained fields, missing-required fields, malformed
    # nested shapes. Each broken payload MUST fail validation; if it
    # doesn't, the schema isn't actually enforcing what it advertises.
    HOOKS = [
        ("steps/sessionStart", {},
         # policy_mode is enum strict/moderate/permissive; 123 is wrong type AND not in enum
         {"policy_mode": 123},
         "hooks/session-start.json"),
        ("steps/userMessage",
         {"content": [{"type": "text", "value": "hi"}]},
         {"content": "not-an-array"},  # user-message.json requires content to be array
         "hooks/user-message.json"),
        ("steps/toolCallRequest",
         {"tool": {"name": "Read"}, "arguments": {"file_path": {"value": "/tmp/x"}}},
         {"tool": {"name": "Read"}},  # missing required `arguments`
         "hooks/tool-call-request.json"),
        ("steps/toolCallResult",
         {"tool": {"name": "Read"}, "exit_status": "success",
          "outputs": [{"value": "ok"}]},
         {"tool": {"name": "Read"}, "exit_status": "magical"},  # bad enum value + missing outputs
         "hooks/tool-call-result.json"),
        ("steps/agentResponse",
         {"content": [{"type": "text", "value": "ok"}]},
         {},  # missing required content
         "hooks/agent-response.json"),
        ("steps/sessionEnd", {"reason": "completed"},
         {"reason": "nonsense"},  # not in enum
         "hooks/session-end.json"),
        # PR #21 (open; not in this branch) proposes adding
        # steps/subagentStart to the Core floor for subagent-capable
        # clients. The valid case must be accepted with a known
        # disposition (the example policy's default deny IS one); the
        # broken case must fail the canonical schema.
        ("steps/subagentStart",
         {"subagent_session_id": "22222222-2222-4222-8222-222222222222",
          "parent_session_id": "11111111-1111-4111-8111-111111111111",
          "parent_step_id": "33333333-3333-4333-8333-333333333333",
          "intent_derivation": "derived_from_parent"},
         {"subagent_session_id": "22222222-2222-4222-8222-222222222222",
          "parent_step_id": "33333333-3333-4333-8333-333333333333",
          "intent_derivation": "totally_made_up"},  # bad enum + missing parent_session_id
         "hooks/subagent-start.json"),
    ]

    def _send(self, method: str, payload: dict) -> dict:
        return self._post(self._make_envelope(method, payload))

    def _validate_hook_payload(self, payload: dict, schema_file: str) -> list:
        from jsonschema import Draft202012Validator
        schema, resolver = _build_local_resolver(schema_file)
        validator = Draft202012Validator(
            schema, resolver=resolver,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        return [
            f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
            for err in validator.iter_errors(payload)
        ]

    def test_each_minimum_hook_returns_known_disposition(self) -> None:
        """conformance.md:19 — each hook in the Core minimum set must
        produce a known disposition (allow/deny/modify/ask/defer). The
        set's membership is #21-sensitive: six hooks on this branch's
        spec text; PR #21 proposes subagentStart joining the floor.
        This proves wire acceptance only — enforcement is
        `test_guardian_actually_denies_what_policy_forbids`."""
        KNOWN = {"allow", "deny", "modify", "ask", "defer"}
        for method, payload, _broken, _schema in self.HOOKS:
            with self.subTest(method=method):
                resp = self._send(method, payload)
                self.assertIn("result", resp,
                    f"{method} must be accepted; got {resp}")
                self.assertIn(resp["result"].get("decision"), KNOWN,
                    f"{method} returned non-spec disposition "
                    f"{resp['result'].get('decision')!r}")

    def test_guardian_actually_denies_what_policy_forbids(self) -> None:
        """Enforcement counterproof: an allow-everything Guardian passes
        the disposition-shape test above; this one sends inputs the
        shipped policy MUST deny and asserts the deny comes back."""
        must_deny = [
            ("steps/toolCallRequest",
             {"tool": {"name": "Bash"},
              "arguments": {"command": {"value": "rm -rf /home/victim"}}},
             "destructive Bash"),
            ("steps/toolCallRequest",
             {"tool": {"name": "Task"},
              "arguments": {"prompt": {"value": "spawn a subagent"}}},
             "Task tool (subagent gate, ACS_ALLOW_SUBAGENT unset)"),
            ("steps/toolCallRequest",
             {"tool": {"name": "Write"},
              "arguments": {"file_path": {"value": "/etc/passwd"},
                            "content": {"value": "x"}}},
             "write to protected system path"),
            ("steps/subagentStart",
             {"subagent_session_id": "22222222-2222-4222-8222-222222222222",
              "parent_session_id": "11111111-1111-4111-8111-111111111111",
              "parent_step_id": "33333333-3333-4333-8333-333333333333",
              "intent_derivation": "fresh"},
             "subagentStart claiming fresh (non-derived) intent"),
        ]
        for method, payload, label in must_deny:
            with self.subTest(case=label):
                resp = self._send(method, payload)
                self.assertIn("result", resp,
                    f"{label}: expected a decision, got {resp}")
                self.assertEqual(resp["result"].get("decision"), "deny",
                    f"{label}: the shipped policy MUST deny this; got "
                    f"{resp['result'].get('decision')!r}. An "
                    f"allow-everything Guardian must not pass conformance.")
                # Folded from Core04.test_deny_response_includes_reasoning:
                # response-envelope.json:107 — a DENY MUST carry reasoning,
                # AND the deny response itself MUST validate against the
                # canonical response envelope (the _validate_response_envelope
                # assertion the fold originally dropped).
                self.assertTrue(resp["result"].get("reasoning"),
                    f"{label}: §6 + response-envelope.json — DENY MUST include "
                    f"non-empty reasoning")
                errs = _validate_response_envelope(resp)
                self.assertEqual(errs, [],
                    f"{label}: DENY response fails response-envelope.json:\n  - "
                    + "\n  - ".join(errs))

    def test_guardian_rejects_malformed_envelope_on_the_wire(self) -> None:
        """Over the wire: an envelope violating request-envelope.json
        (non-UUID request_id) MUST come back as JSON-RPC -32600, not a
        decision — Guardian-side validation runs in the serving path."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["request_id"] = "not-a-uuid"
        resp = self._post(env)
        self.assertIn("error", resp,
            "Guardian accepted an envelope with a non-UUID request_id — "
            "wire-side schema validation is not running")
        self.assertEqual(resp["error"].get("code"), -32600,
            f"expected -32600 Invalid Request, got {resp['error']!r}")

    def test_each_minimum_hooks_malformed_payload_fails_schema(self) -> None:
        """Contradiction check: a malformed payload for each minimum hook
        MUST fail the canonical hooks/*.json schema. Verifies the per-hook
        schemas actually constrain shape — not just rubber-stamp anything."""
        for method, _payload, broken, schema_file in self.HOOKS:
            with self.subTest(method=method):
                errors = self._validate_hook_payload(broken, schema_file)
                self.assertNotEqual(errors, [],
                    f"{method}: a deliberately broken payload {broken!r} "
                    f"was accepted by {schema_file} — schema is not "
                    f"actually constraining shape")


# =============================================================================
# CORE-04 — Dispositions (conformance.md:20, §6)
# =============================================================================
#
# This branch's spec text: "All five (ALLOW, DENY, MODIFY, ASK, DEFER)
# with required fields per §6". PR #21 (open; not in this branch)
# proposes relaxing MODIFY to SHOULD-support — the MODIFY tests below
# are reference-stack coverage (this stack implements it) either way.
# See the suite docstring's coverage claim.
# response-envelope.json:107-110 — conditional requirements:
#   deny -> reasoning required
#   modify -> reasoning + modifications required
#   ask -> reasoning + ask_details required
#   defer -> reasoning + defer_details required
# =============================================================================

class Core04_Dispositions(CoreHarness):

    def test_allow_response_validates(self) -> None:
        """§6 — ALLOW: no required fields beyond decision."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"ALLOW response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))
        self.assertEqual(resp["result"]["decision"], "allow")

    def test_allow_response_without_required_envelope_fields_rejected(self) -> None:
        """Contradiction: an allow response missing AcsResult required
        fields (type, acs_version, request_id, decision) MUST fail
        schema validation. Otherwise positive-case tests are tautological."""
        broken_responses = [
            # Missing type
            {"jsonrpc": "2.0", "id": "x",
             "result": {"acs_version": "0.1.0",
                        "request_id": "00000000-0000-4000-8000-000000000001",
                        "decision": "allow"}},
            # Missing acs_version
            {"jsonrpc": "2.0", "id": "x",
             "result": {"type": "final",
                        "request_id": "00000000-0000-4000-8000-000000000001",
                        "decision": "allow"}},
            # Missing request_id
            {"jsonrpc": "2.0", "id": "x",
             "result": {"type": "final", "acs_version": "0.1.0",
                        "decision": "allow"}},
            # Missing decision
            {"jsonrpc": "2.0", "id": "x",
             "result": {"type": "final", "acs_version": "0.1.0",
                        "request_id": "00000000-0000-4000-8000-000000000001"}},
            # Bogus decision value
            {"jsonrpc": "2.0", "id": "x",
             "result": {"type": "final", "acs_version": "0.1.0",
                        "request_id": "00000000-0000-4000-8000-000000000001",
                        "decision": "maybe"}},
        ]
        for i, broken in enumerate(broken_responses):
            with self.subTest(case=i):
                errors = _validate_response_envelope(broken)
                self.assertNotEqual(errors, [],
                    f"broken allow response {broken!r} (case {i}) was "
                    f"accepted by schema — validator is a no-op")

    def test_modify_without_modifications_rejected_by_schema(self) -> None:
        """response-envelope.json:108 — 'if decision const modify, then
        required: [reasoning, modifications]'. A response that claims
        modify but lacks modifications MUST fail schema validation."""
        # Synthesize a broken response (Guardian doesn't emit modify in
        # our example, so we construct one manually and validate it).
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "modify",
                "reasoning": "but no modifications field",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("modifications" in e for e in errors),
            f"modify-without-modifications must fail validation; got {errors}")

    def test_ask_without_ask_details_rejected_by_schema(self) -> None:
        """response-envelope.json:109 — 'if decision const ask, then
        required: [reasoning, ask_details]'."""
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "ask", "reasoning": "missing ask_details",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("ask_details" in e for e in errors),
            f"ask-without-ask_details must fail validation; got {errors}")

    def test_defer_without_defer_details_rejected_by_schema(self) -> None:
        """response-envelope.json:110 — 'if decision const defer, then
        required: [reasoning, defer_details]'."""
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "defer", "reasoning": "missing defer_details",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("defer_details" in e for e in errors),
            f"defer-without-defer_details must fail validation; got {errors}")


# =============================================================================
# CORE-04b — Dispositions driven LIVE through the adapters
# =============================================================================
#
# Hand-synthesized responses prove the wire can EXPRESS a disposition,
# not that anything implements it. This class scripts a
# ProgrammableGuardian to return modify / ask / defer and asserts each
# adapter's documented translation (mapping.md) actually happens.
# =============================================================================

class Core04b_DispositionsLiveThroughAdapters(unittest.TestCase):
    """Drive MODIFY / ASK / DEFER through the shell adapters against a
    scripted Guardian; assert the framework-native output shapes."""

    SECRET = "shared-test-harness-secret-not-for-production"

    def _scripted_guardian(self, decision_result: dict):
        import test_harness
        g = test_harness.ProgrammableGuardian()

        def handler(req: dict) -> dict:
            return {
                "type": "final", "acs_version": "0.1.0",
                "request_id": req["params"]["request_id"],
                "chain_hash": "0" * 64,
                **decision_result,
            }
        g.handlers["steps/toolCallRequest"] = handler
        return g

    def _run_claude(self, guardian) -> dict:
        env = os.environ.copy()
        env.update({
            "ACS_GUARDIAN_URL": guardian.url(),
            "ACS_HMAC_SECRET": self.SECRET,
            "ACS_HANDSHAKE": "0",
            # Hermetic per-call turn/session state.
            "ACS_SESSION_STATE_DIR": tempfile.mkdtemp(),
        })
        env.pop("ACS_HMAC_SECRET_FILE", None)
        proc = subprocess.run(
            [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")],
            input=json.dumps({
                "session_id": "44444444-4444-4444-8444-444444444444",
                "cwd": "/tmp", "hook_event_name": "PreToolUse",
                "tool_name": "Bash", "tool_input": {"command": "echo hi"},
            }),
            capture_output=True, text=True, env=env, timeout=15)
        return {"stdout": proc.stdout, "stderr": proc.stderr,
                "out": json.loads(proc.stdout) if proc.stdout.strip() else {}}

    def _run_cursor(self, guardian) -> dict:
        env = os.environ.copy()
        env.update({
            "ACS_GUARDIAN_URL": guardian.url(),
            "ACS_HMAC_SECRET": self.SECRET,
            "ACS_HANDSHAKE": "0",
            # Hermetic per-call turn/session state.
            "ACS_SESSION_STATE_DIR": tempfile.mkdtemp(),
        })
        env.pop("ACS_HMAC_SECRET_FILE", None)
        proc = subprocess.run(
            [sys.executable, str(HERE / "cursor" / "acs_adapter.py"),
             "preToolUse"],
            input=json.dumps({
                "conversation_id": "44444444-4444-4444-8444-444444444445",
                "workspace_roots": ["/tmp"],
                "tool_name": "Bash", "tool_input": {"command": "echo hi"},
            }),
            capture_output=True, text=True, env=env, timeout=15)
        return {"stdout": proc.stdout, "stderr": proc.stderr,
                "out": json.loads(proc.stdout) if proc.stdout.strip() else {}}

    def test_modify_applies_parameter_overrides_claude(self) -> None:
        """MODIFY with parameter_overrides → permissionDecision allow +
        updatedInput carrying the override (mapping.md disposition table)."""
        with self._scripted_guardian({
            "decision": "modify", "reasoning": "redacted",
            "modifications": {"parameter_overrides": {"command": "echo REDACTED"}},
        }) as g:
            r = self._run_claude(g)
        hso = r["out"].get("hookSpecificOutput", {})
        self.assertEqual(hso.get("permissionDecision"), "allow",
            f"MODIFY must surface as allow+updatedInput; got {r['out']!r}")
        self.assertEqual(hso.get("updatedInput"), {"command": "echo REDACTED"},
            "the Guardian's parameter_overrides must reach updatedInput")

    def test_modify_without_overrides_substitutes_deny_claude(self) -> None:
        """MODIFY with no applicable mutation substitutes to deny."""
        with self._scripted_guardian({
            "decision": "modify", "reasoning": "no overrides",
            "modifications": {},
        }) as g:
            r = self._run_claude(g)
        hso = r["out"].get("hookSpecificOutput", {})
        self.assertEqual(hso.get("permissionDecision"), "deny",
            f"MODIFY with empty modifications must substitute deny; got {r['out']!r}")

    def test_ask_is_native_on_claude_pretooluse(self) -> None:
        """ASK → permissionDecision 'ask' (native surface, not a block)."""
        with self._scripted_guardian({
            "decision": "ask", "reasoning": "needs approval",
            "ask_details": {"approver_types": ["human"]},
        }) as g:
            r = self._run_claude(g)
        hso = r["out"].get("hookSpecificOutput", {})
        self.assertEqual(hso.get("permissionDecision"), "ask",
            f"ASK must surface natively as permissionDecision ask; got {r['out']!r}")

    def test_defer_substitutes_deny_with_audit_claude(self) -> None:
        """DEFER → deny + defer_substituted_deny audit event (no native
        defer in permissionDecision; spec default timeout_decision deny)."""
        with self._scripted_guardian({
            "decision": "defer", "reasoning": "pending",
            "defer_details": {"resolution_method": "retry",
                              "resolution_timeout_ms": 1000,
                              "timeout_decision": "deny"},
        }) as g:
            r = self._run_claude(g)
        hso = r["out"].get("hookSpecificOutput", {})
        self.assertEqual(hso.get("permissionDecision"), "deny",
            f"DEFER must substitute to deny; got {r['out']!r}")
        self.assertIn("defer_substituted_deny", r["stderr"],
            "the DEFER→deny substitution must be audited")

    def test_defer_substitutes_ask_cursor(self) -> None:
        """Cursor documents DEFER → ask (no native defer). Assert it."""
        with self._scripted_guardian({
            "decision": "defer", "reasoning": "pending",
            "defer_details": {"resolution_method": "retry",
                              "resolution_timeout_ms": 1000,
                              "timeout_decision": "deny"},
        }) as g:
            r = self._run_cursor(g)
        self.assertEqual(r["out"].get("permission"), "ask",
            f"cursor maps defer→ask per mapping.md; got {r['out']!r}")

    def test_unusable_disposition_denies_regardless_of_posture(self) -> None:
        """§6.4:158 requires an arrived decision to be honored regardless of
        the posture. §6.3:146 makes one whose intent cannot be determined a
        DENY plus an audit event. Posture stays at the shipped fail-open default on
        purpose: it must have no effect on a decision that arrived."""
        for bad, unreadable in (("deny ", False), (" deny", False),
                                ("DENY\n", False), ("quarantine", True),
                                ("", True)):
            with self.subTest(disposition=bad):
                with self._scripted_guardian(
                        {"decision": bad, "reasoning": "policy hit"}) as g:
                    r = self._run_claude(g)
                hso = r["out"].get("hookSpecificOutput", {})
                self.assertEqual(hso.get("permissionDecision"), "deny",
                    f"{bad!r} must deny: normalization handles a padded verdict, "
                    f"§6.3:146 handles one that cannot be read. Got {r['out']!r}, "
                    f"and empty output runs the tool.")
                if unreadable:
                    self.assertIn("unusable_disposition", r["stderr"],
                        f"{bad!r} cannot be read at all, so §6.3:146's audit "
                        f"event is required")

    def test_non_string_and_non_object_verdicts_fail_closed(self) -> None:
        """A hostile/buggy Guardian can send a NON-STRING decision or a
        NON-OBJECT modifications; reading them with .strip()/.get()
        raises, and an uncaught raise is exit 1 = the host PROCEEDS.
        §6.3:146 requires fail-closed DENY when intent can't be
        determined. Posture stays at the fail-open default."""
        cases = [
            {"decision": 5},
            {"decision": {"v": "deny"}},
            {"decision": ["deny"]},
            {"decision": True},
            {"decision": "modify", "modifications": [1, 2]},
            {"decision": "modify", "modifications": "not-an-object"},
            {"decision": "modify",
             "modifications": {"parameter_overrides": "rm -rf /"}},
        ]
        for result in cases:
            with self.subTest(result=result):
                with self._scripted_guardian(result) as g:
                    r = self._run_claude(g)
                self.assertEqual(r["stderr"].count("Traceback"), 0,
                    f"adapter crashed on {result!r}; a crash is exit 1 and "
                    f"Claude Code proceeds. stderr={r['stderr'][:300]}")
                hso = r["out"].get("hookSpecificOutput", {})
                self.assertEqual(hso.get("permissionDecision"), "deny",
                    f"{result!r} must fail closed to deny (§6.3:146); "
                    f"got {r['out']!r} — empty/allow output runs the tool")
                with self._scripted_guardian(result) as g:
                    rc = self._run_cursor(g)
                self.assertEqual(rc["out"].get("permission"), "deny",
                    f"cursor: {result!r} must fail closed to deny; "
                    f"got {rc['out']!r}")


class Core04c_PromptGateAndMergeFailClosed(unittest.TestCase):
    """The prompt gate and the MODIFY-merge, driven live through the shell
    adapters:
      - a prompt hook can only allow or block, so any non-allow decision
        the host can't apply (modify on Claude; ask/defer/modify on
        Cursor) must BLOCK, never silently proceed;
      - parameter_overrides are per-argument edits, but updatedInput /
        updated_input REPLACE the whole input, so the adapter must MERGE
        overrides onto the original (dropping a non-overridden argument is
        a different effective payload than the Guardian intended)."""

    SECRET = "shared-test-harness-secret-not-for-production"

    def _guardian(self, method: str, result: dict):
        import test_harness
        g = test_harness.ProgrammableGuardian()
        g.handlers[method] = lambda req: {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "chain_hash": "0" * 64, **result}
        return g

    def _env(self, g):
        env = os.environ.copy()
        env.update({"ACS_GUARDIAN_URL": g.url(), "ACS_HMAC_SECRET": self.SECRET,
                    "ACS_HANDSHAKE": "0",
                    "ACS_SESSION_STATE_DIR": tempfile.mkdtemp()})
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env.pop("ACS_DEFAULT_DENY", None)   # shipped fail-open default on purpose
        return env

    def test_claude_modify_on_prompt_blocks(self) -> None:
        for disp in ("modify", "ask", "defer"):
            with self.subTest(disposition=disp):
                with self._guardian("steps/userMessage",
                                    {"decision": disp, "reasoning": "x"}) as g:
                    proc = subprocess.run(
                        [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")],
                        input=json.dumps({"session_id": "p-1", "cwd": "/tmp",
                                          "hook_event_name": "UserPromptSubmit",
                                          "prompt": "do a thing"}),
                        capture_output=True, text=True, env=self._env(g), timeout=15)
                out = json.loads(proc.stdout) if proc.stdout.strip() else {}
                self.assertEqual(out.get("decision"), "block",
                    f"{disp} on a Claude prompt must block (host can't apply it "
                    f"there), not silently proceed; got {out!r}")

    def test_cursor_non_allow_on_prompt_blocks_exit2(self) -> None:
        for disp in ("ask", "defer", "modify", "deny"):
            with self.subTest(disposition=disp):
                with self._guardian("steps/userMessage",
                                    {"decision": disp, "reasoning": "x"}) as g:
                    proc = subprocess.run(
                        [sys.executable, str(HERE / "cursor" / "acs_adapter.py"),
                         "beforeSubmitPrompt"],
                        input=json.dumps({"conversation_id": "conv-p-1",
                                          "workspace_roots": ["/tmp"],
                                          "prompt": "do a thing"}),
                        capture_output=True, text=True, env=self._env(g), timeout=15)
                self.assertEqual(proc.returncode, 2,
                    f"{disp} on a Cursor prompt must block via exit 2, not "
                    f"proceed (exit 0); got rc={proc.returncode}")

    def test_contradictory_modify_fails_closed(self) -> None:
        """§6.3:146 / modifications.json: a modify carrying BOTH wholesale
        `modified_content` AND structured edits, or overlapping structured
        targets, is un-interpretable and MUST fail closed to DENY — not be
        half-applied."""
        from jsonschema import Draft202012Validator
        schema = json.loads((SPEC_DIR / "modifications.json").read_text())
        validator = Draft202012Validator(schema)
        # `schema_valid` distinguishes contradictions expressible in JSON
        # Schema from the path-disjointness rule stated in prose.  The latter
        # cases MUST remain valid against the canonical schema and still be
        # refused by the adapter's semantic check.
        bad_mods = [
            ({"modified_content": "x",
              "parameter_overrides": {"command": "y"}}, False),
            ({"modified_content": "x",
              "redactions": [{"path": "/command"}]}, False),
            ({"redactions": [{"path": "/command"}],
              "parameter_overrides": {"command": "y"}}, True),
            # An override of the top-level `options` argument replaces the
            # whole subtree, so redacting one of its descendants conflicts.
            ({"redactions": [{"path": "/options/token"}],
              "parameter_overrides": {"options": {"token": "safe"}}}, True),
            # JSON Pointer escaping matters: `a/b` is encoded as `a~1b`.
            ({"redactions": [{"path": "/a~1b/secret"}],
              "parameter_overrides": {"a/b": {"secret": "safe"}}}, True),
            # The empty JSON Pointer targets the whole document and therefore
            # overlaps every parameter override.
            ({"redactions": [{"path": ""}],
              "parameter_overrides": {"command": "echo safe"}}, True),
            # The schema's description requires RFC 6901, but JSON Schema
            # cannot express that grammar here.  Bare paths and invalid
            # escapes are schema-valid yet semantically unusable.
            ({"redactions": [{"path": "options"}],
              "parameter_overrides": {"command": "echo safe"}}, True),
            ({"redactions": [{"path": "/options/~2token"}],
              "parameter_overrides": {"command": "echo safe"}}, True),
            # Runtime code cannot assume the Guardian validated its own
            # response first.  Invalid structured members must not be ignored
            # while a valid-looking override is applied.
            ({"redactions": [42],
              "parameter_overrides": {"command": "echo safe"}}, False),
            ({"redactions": "not-an-array",
              "parameter_overrides": {"command": "echo safe"}}, False),
        ]
        for mods, schema_valid in bad_mods:
            with self.subTest(mods=mods):
                errors = list(validator.iter_errors(mods))
                self.assertEqual(not errors, schema_valid,
                    f"test fixture has the wrong canonical-schema status: "
                    f"errors={[e.message for e in errors]}")
                result = {"decision": "modify", "reasoning": "x",
                          "modifications": mods}
                with self._guardian("steps/toolCallRequest", result) as g:
                    proc = subprocess.run(
                        [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")],
                        input=json.dumps({"session_id": "cx-1", "cwd": "/tmp",
                                          "hook_event_name": "PreToolUse",
                                          "tool_name": "Bash",
                                          "tool_input": {"command": "echo hi"},
                                          "tool_use_id": "cx1"}),
                        capture_output=True, text=True, env=self._env(g), timeout=15)
                out = json.loads(proc.stdout) if proc.stdout.strip() else {}
                self.assertEqual(
                    out.get("hookSpecificOutput", {}).get("permissionDecision"),
                    "deny",
                    f"contradictory modify {mods!r} must fail closed to deny, "
                    f"not be half-applied; got {out!r}")

    def test_modify_overrides_merge_preserves_other_args(self) -> None:
        """Override one argument; the others (a timeout) must survive."""
        result = {"decision": "modify", "reasoning": "redact",
                  "modifications": {"parameter_overrides": {"command": "echo safe"}}}
        tool_input = {"command": "rm -rf /", "timeout": 5}
        # Claude
        with self._guardian("steps/toolCallRequest", result) as g:
            proc = subprocess.run(
                [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")],
                input=json.dumps({"session_id": "m-1", "cwd": "/tmp",
                                  "hook_event_name": "PreToolUse", "tool_name": "Bash",
                                  "tool_input": tool_input, "tool_use_id": "m1"}),
                capture_output=True, text=True, env=self._env(g), timeout=15)
        ui = (json.loads(proc.stdout).get("hookSpecificOutput", {}).get("updatedInput", {})
              if proc.stdout.strip() else {})
        self.assertEqual(ui, {"command": "echo safe", "timeout": 5},
            f"claude MODIFY must MERGE overrides onto the original input "
            f"(timeout must survive); got updatedInput={ui!r}")
        # Cursor
        with self._guardian("steps/toolCallRequest", result) as g:
            proc = subprocess.run(
                [sys.executable, str(HERE / "cursor" / "acs_adapter.py"), "preToolUse"],
                input=json.dumps({"conversation_id": "conv-m-1",
                                  "workspace_roots": ["/tmp"], "tool_name": "Bash",
                                  "tool_input": tool_input}),
                capture_output=True, text=True, env=self._env(g), timeout=15)
        ui = (json.loads(proc.stdout).get("updated_input", {})
              if proc.stdout.strip() else {})
        self.assertEqual(ui, {"command": "echo safe", "timeout": 5},
            f"cursor MODIFY must MERGE overrides onto the original input; "
            f"got updated_input={ui!r}")

    def test_disjoint_structured_targets_are_not_reported_as_overlap(self) -> None:
        """Prefix matching must not confuse sibling JSON Pointer paths."""
        mods = {
            "redactions": [{"path": "/options/token"}],
            "parameter_overrides": {"command": "echo safe"},
        }
        from jsonschema import Draft202012Validator
        schema = json.loads((SPEC_DIR / "modifications.json").read_text())
        Draft202012Validator(schema).validate(mods)
        self.assertIsNone(acs_common.modify_composition_violation(mods),
            "disjoint structured edits are valid; the overlap guard must not "
            "turn every combined MODIFY into DENY")

    def test_unapplied_redactions_cannot_be_half_applied_as_overrides(self) -> None:
        """A valid combined MODIFY is still all-or-nothing at the host edge.

        Claude and Cursor can replace tool input but do not expose a native
        JSON-Pointer redaction operation.  Applying only the override while
        silently ignoring the redaction changes the Guardian's decision.  The
        safe, honest translation is DENY until the complete edit can be
        realized.
        """
        mods = {
            "redactions": [{"path": "/secret", "replacement": "[REDACTED]"}],
            "parameter_overrides": {"command": "echo safe"},
        }
        from jsonschema import Draft202012Validator
        schema = json.loads((SPEC_DIR / "modifications.json").read_text())
        Draft202012Validator(schema).validate(mods)
        result = {"decision": "modify", "reasoning": "apply both edits",
                  "modifications": mods}
        tool_input = {"command": "unsafe", "secret": "do-not-forward"}

        with self._guardian("steps/toolCallRequest", result) as g:
            proc = subprocess.run(
                [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")],
                input=json.dumps({"session_id": "mr-1", "cwd": "/tmp",
                                  "hook_event_name": "PreToolUse",
                                  "tool_name": "Bash", "tool_input": tool_input}),
                capture_output=True, text=True, env=self._env(g), timeout=15)
        claude = json.loads(proc.stdout) if proc.stdout.strip() else {}
        self.assertEqual(
            claude.get("hookSpecificOutput", {}).get("permissionDecision"),
            "deny", f"Claude half-applied a combined MODIFY: {claude!r}")

        with self._guardian("steps/toolCallRequest", result) as g:
            proc = subprocess.run(
                [sys.executable, str(HERE / "cursor" / "acs_adapter.py"),
                 "preToolUse"],
                input=json.dumps({"conversation_id": "mr-2",
                                  "workspace_roots": ["/tmp"],
                                  "tool_name": "Bash", "tool_input": tool_input}),
                capture_output=True, text=True, env=self._env(g), timeout=15)
        cursor = json.loads(proc.stdout) if proc.stdout.strip() else {}
        self.assertEqual(cursor.get("permission"), "deny",
            f"Cursor half-applied a combined MODIFY: {cursor!r}")


# =============================================================================
# CORE-05 — SessionContext + chain head (conformance.md:21, §8)
# =============================================================================
#
# "session_id, chain_hash (rolling SHA-256), append-only ContextEntry chain,
#  with the Guardian publishing the chain head (chain_hash) on responses for
#  content-bearing steps"
# §8.2 — entry_hash = SHA-256(JCS(entry minus entry_hash/previous_hash) || prev_hash_bytes)
# =============================================================================

class Core05_SessionContext(CoreHarness):

    def test_response_carries_chain_hash(self) -> None:
        """conformance.md:21 — 'Guardian publishing the chain head
        (chain_hash) on responses for content-bearing steps'."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        self.assertIn("chain_hash", resp["result"],
            f"response missing chain_hash; got {resp['result']}")

    def test_chain_hash_is_lowercase_hex_sha256(self) -> None:
        """response-envelope.json:82-85 — chain_hash pattern
        ^[0-9a-f]{64}$ (lowercase hex SHA-256)."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        h = resp["result"]["chain_hash"]
        self.assertRegex(h, r"^[0-9a-f]{64}$",
            f"chain_hash must be lowercase 64-hex SHA-256; got {h!r}")

    def test_chain_links_consecutive_entries(self) -> None:
        """§8.2 normative — consecutive entries in a session must be
        chained, i.e. entry[i+1].previous_hash = entry[i].entry_hash."""
        sid = str(uuid.uuid4())
        h1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            session_id=sid))["result"]["chain_hash"]
        h2 = self._post(self._make_envelope(
            "steps/toolCallRequest",
            {"tool": {"name": "Read"},
             "arguments": {"file_path": {"value": "/tmp/x"}}},
            session_id=sid))["result"]["chain_hash"]
        self.assertNotEqual(h1, h2,
            "consecutive chain_hashes must differ — a fake chain reuses hashes")

    def test_distinct_sessions_have_distinct_chain_heads(self) -> None:
        """§8.2 — chain is per-session; two different sessions must
        produce different chain heads from the same first event."""
        h1 = self._post(self._make_envelope("steps/sessionStart", {}))["result"]["chain_hash"]
        h2 = self._post(self._make_envelope("steps/sessionStart", {}))["result"]["chain_hash"]
        self.assertNotEqual(h1, h2)

    def test_chain_externally_recomputable_across_3_entries(self) -> None:
        """§8.2 normative — entry_hash = SHA-256(JCS(entry minus
        entry_hash/previous_hash) || prev_hash_bytes). An external
        observer with the request stream MUST recompute the published
        chain head byte-for-byte across multiple entries; this is what
        catches a 'chain that doesn't actually chain' mutation.

        Testing 3 entries because a chain that returned sha256(entry)
        (ignoring previous_hash) would still produce the right value
        for the first entry (no previous_hash to ignore). The second
        and third entries are where the chain link is actually
        observable."""

        def expected(req: dict, prev_hash: str | None) -> str:
            params = req["params"]
            entry = {
                "entry_id": params["request_id"],
                "step_id": params["request_id"],
                "step_type": req["method"],
                "request_hash": hashlib.sha256(
                    acs_common.jcs_canonicalize(params)).hexdigest(),
                "timestamp": params["timestamp"],
            }
            content_bytes = acs_common.jcs_canonicalize(entry)
            prev_bytes = bytes.fromhex(prev_hash) if prev_hash else b""
            return hashlib.sha256(content_bytes + prev_bytes).hexdigest()

        sid = str(uuid.uuid4())
        req1 = self._make_envelope("steps/sessionStart", {}, session_id=sid)
        h1 = self._post(req1)["result"]["chain_hash"]
        self.assertEqual(h1, expected(req1, None),
            "entry 1 (root): published chain_hash != externally-computed hash")

        req2 = self._make_envelope("steps/userMessage",
            {"content": [{"type": "text", "value": "hi"}]}, session_id=sid)
        h2 = self._post(req2)["result"]["chain_hash"]
        self.assertEqual(h2, expected(req2, h1),
            "entry 2: published chain_hash != externally-computed hash. "
            "Either previous_hash is not folded in or JCS canonicalization differs.")
        # Falsifier: same h2 computed WITHOUT prev_hash MUST differ — i.e. chain
        # actually depends on the previous hash, not just the entry content.
        self.assertNotEqual(h2, expected(req2, None),
            "entry 2's hash matches the no-previous_hash computation — "
            "the chain is not actually chained, just hashed.")

        req3 = self._make_envelope("steps/toolCallRequest",
            {"tool": {"name": "Read"},
             "arguments": {"file_path": {"value": "/tmp/x"}}},
            session_id=sid)
        h3 = self._post(req3)["result"]["chain_hash"]
        self.assertEqual(h3, expected(req3, h2),
            "entry 3: chain breaks at depth 2 — not a transitive chain")


# =============================================================================
# CORE-06 — Replay protection (conformance.md:22, §10.3)
# =============================================================================
#
# "request_id (UUID) and timestamp on every request; Guardians MUST reject
#  replays per §10.3"
# §10.3: "Guardians MUST reject duplicate request_id values within the
#        session with REPLAY_DETECTED (-32005)"
# §10.3: "Guardians MUST reject requests whose timestamp is more than the
#        negotiated skew window in the past or future, returning
#        TIMESTAMP_OUT_OF_WINDOW (-32006)"
# =============================================================================

class Core06_ReplayProtection(CoreHarness):

    def test_duplicate_request_id_rejected_with_32005(self) -> None:
        """§10.3 — 'Guardians MUST reject duplicate request_id values
        within the session with REPLAY_DETECTED (-32005)'."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        r1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            session_id=sid, request_id=rid))
        self.assertIn("result", r1)
        r2 = self._post(self._make_envelope("steps/userMessage",
            {"content": [{"type": "text", "value": "hi"}]},
            session_id=sid, request_id=rid))
        self.assertIn("error", r2, f"replay must be rejected; got {r2}")
        self.assertEqual(r2["error"]["code"], -32005,
            f"§10.3 — code must be -32005 REPLAY_DETECTED; got {r2['error']}")

    def test_timestamp_outside_window_rejected_with_32006(self) -> None:
        """§10.3 — 'Guardians MUST reject requests whose timestamp is
        more than the negotiated skew window in the past or future,
        returning TIMESTAMP_OUT_OF_WINDOW (-32006)'. Tests BOTH
        directions: an ancient timestamp and a future one."""
        # Past
        ancient = datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc).isoformat()
        resp = self._post(self._make_envelope("steps/sessionStart", {},
                                              timestamp=ancient))
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32006,
            f"§10.3 — code must be -32006 TIMESTAMP_OUT_OF_WINDOW (past)")
        # Future
        future = (datetime.datetime.now(datetime.timezone.utc)
                  + datetime.timedelta(hours=1)).isoformat()
        resp = self._post(self._make_envelope("steps/sessionStart", {},
                                              timestamp=future))
        self.assertIn("error", resp,
            "§10.3 says 'past or future' — future-skewed timestamps must "
            "also be rejected, not silently accepted")
        self.assertEqual(resp["error"]["code"], -32006)

    def test_error_response_envelope_validates(self) -> None:
        """Every Guardian response — including ERROR responses — MUST
        validate against response-envelope.json. The disposition tests
        cover allow/deny envelopes; this one covers the error branch
        of the JSON-RPC oneOf (result OR error)."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        # First request: accepted
        self._post(self._make_envelope("steps/sessionStart", {},
                                        session_id=sid, request_id=rid))
        # Second request: same (sid, rid) → -32005 REPLAY_DETECTED error
        resp = self._post(self._make_envelope("steps/sessionStart", {},
                                              session_id=sid, request_id=rid))
        self.assertIn("error", resp)
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"Guardian error response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))

    def test_same_request_id_across_sessions_is_fine(self) -> None:
        """§10.3 — replay protection is PER-SESSION. The same
        request_id used in two different sessions MUST both be accepted."""
        rid = str(uuid.uuid4())
        r1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            request_id=rid))
        r2 = self._post(self._make_envelope("steps/sessionStart", {},
                                            request_id=rid))
        self.assertIn("result", r1)
        self.assertIn("result", r2,
            "cross-session same-request_id must be accepted; "
            "replay protection scope is per-session")


# =============================================================================
# CORE-07 — Baseline integrity (conformance.md:23, §10)
# =============================================================================
#
# "every request and response carries a signature over the canonical
#  envelope. HMAC-SHA256 with an HKDF-derived per-session key from
#  deployment-provided key material is the baseline"
# §10: "The signed input ... is the RFC 8785 (JCS) canonicalization of
#       the request or response envelope with the signature field removed"
# =============================================================================

class Core07_BaselineIntegrity(CoreHarness):

    def test_signed_request_accepted(self) -> None:
        """conformance.md:23 — signed request with HMAC-SHA256 baseline
        MUST be accepted by a Guardian that requires signing."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        self.assertIn("result", resp,
            f"signed request was rejected; got {resp}")

    def test_unsigned_request_rejected_when_secret_configured(self) -> None:
        """conformance.md:23 — when signing is required, an unsigned
        request MUST be rejected."""
        env = self._make_envelope("steps/sessionStart", {}, sign=False)
        resp = self._post(env)
        self.assertIn("error", resp,
            f"unsigned request was accepted; got {resp}")
        self.assertEqual(resp["error"]["code"], -32004,
            f"unsigned-request error must be -32004 SIGNATURE_INVALID")

    def test_tampered_request_signature_invalid(self) -> None:
        """§10 — 'signed input ... canonicalization of the envelope with
        the signature field removed' — any post-sign tamper MUST fail
        verification."""
        env = self._make_envelope("steps/sessionStart", {})
        # Tamper with method AFTER signing
        env["method"] = "steps/userMessage"
        resp = self._post(env)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)

    def test_response_is_signed_and_verifies(self) -> None:
        """conformance.md:23 — 'every request and response carries a
        signature'. The Guardian's response MUST be signed; a client
        MUST be able to verify it with the same HKDF-derived key."""
        sid = str(uuid.uuid4())
        env = self._make_envelope("steps/sessionStart", {}, session_id=sid)
        resp = self._post(env)
        self.assertIn("result", resp)
        # The result body must include signature, and signature must verify.
        sig = resp["result"].get("signature")
        self.assertIsNotNone(sig,
            "Guardian response missing `signature` field per §10")
        key = acs_common.derive_session_key(self.HMAC_SECRET.encode(), sid)
        self.assertTrue(acs_common.verify_signature(resp, key=key),
            "Guardian's response signature must verify with the "
            "HKDF-derived per-session key")

    def test_error_response_is_signed_and_verifies(self) -> None:
        """conformance.md:23 — 'every request and response carries a
        signature' includes ERROR responses (a spoofable unsigned error
        under fail-open is an allow). Elicit a real error (replay →
        -32005) and assert the error envelope carries a signature that
        verifies with the per-session key."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        env1 = self._make_envelope("steps/sessionStart", {},
                                    session_id=sid, request_id=rid)
        self.assertIn("result", self._post(env1))
        # Same request_id again → REPLAY_DETECTED (-32005)
        env2 = self._make_envelope("steps/sessionStart", {},
                                    session_id=sid, request_id=rid)
        resp = self._post(env2)
        self.assertIn("error", resp,
            f"replayed request_id must be refused; got {resp}")
        self.assertEqual(resp["error"].get("code"), -32005)
        sig = resp["error"].get("signature")
        self.assertIsNotNone(sig,
            "error response missing `signature` — errors are responses "
            "too; conformance.md:23 exempts only system/ping")
        key = acs_common.derive_session_key(self.HMAC_SECRET.encode(), sid)
        self.assertTrue(acs_common.verify_signature(resp, key=key),
            "error-response signature must verify with the per-session key")
        # And a tampered error must NOT verify (the check is real).
        tampered = json.loads(json.dumps(resp))
        tampered["error"]["message"] = "REPLAY_DETECTED but for a different action"
        self.assertFalse(acs_common.verify_signature(tampered, key=key),
            "tampered error envelope must fail verification")

    def test_per_session_key_derivation(self) -> None:
        """§10 — 'HKDF-derived per-session key from deployment-provided
        key material'. The derived key MUST differ between sessions
        with the same secret."""
        secret = self.HMAC_SECRET.encode()
        k1 = acs_common.derive_session_key(secret, "session-A")
        k2 = acs_common.derive_session_key(secret, "session-B")
        self.assertNotEqual(k1, k2,
            "per-session HKDF MUST produce distinct keys for distinct sessions")
        # Same session_id → same key
        k1b = acs_common.derive_session_key(secret, "session-A")
        self.assertEqual(k1, k1b,
            "HKDF must be deterministic for the same (secret, session_id)")

    def test_signature_covers_session_id(self) -> None:
        """§10 — 'binds the signature to the whole envelope, including
        method, metadata.session_id, request_id, and timestamp, so a
        captured signature cannot be lifted into a different envelope'.

        Verifies by: take a valid signed envelope, change session_id,
        Guardian MUST reject (the signature was over the old session_id)."""
        sid_a = str(uuid.uuid4())
        sid_b = str(uuid.uuid4())
        env = self._make_envelope("steps/sessionStart", {}, session_id=sid_a)
        # Lift signature to a different session
        env["params"]["metadata"]["session_id"] = sid_b
        resp = self._post(env)
        self.assertIn("error", resp,
            "signature lifted into a different session_id MUST be rejected")
        self.assertEqual(resp["error"]["code"], -32004)


# =============================================================================
# CORE-08 — Decision honoring (conformance.md:24, §6.4)
# =============================================================================
#
# Adapter-side property — covered end-to-end in the per-adapter test
# suites because it depends on how the framework (Claude Code, Cursor,
# NAT) routes the verdict. The wire-level property "Guardian responds
# in time" is covered here; "framework actually waits and applies" is
# covered in adapters/{claude-code,cursor,nat}/tests/.
# =============================================================================

class Core08_DecisionHonoringAdapter(unittest.TestCase):
    """§6.4 is an adapter-side property: 'the Observed Agent MUST wait
    for the Guardian's decision up to the negotiated timeout and apply
    it'. We falsify this by:

      1. The adapter MUST apply DENY when the Guardian returns DENY
         (positive: deny shows up as `permissionDecision: deny`).
      2. The adapter MUST wait for the response, not proceed before it
         arrives (a slow-but-responsive Guardian still gets honored).
      3. On no-response, the adapter MUST fall to its fail posture and
         emit an audit event (contradiction: silent bypass is a §6.4 violation).
    """

    def _run_claude_adapter(self, *, guardian_url: str,
                             env_overrides: dict | None = None,
                             timeout: float = 10.0) -> subprocess.CompletedProcess:
        adapter = HERE / "claude-code" / "acs_adapter.py"
        env = os.environ.copy()
        env["ACS_GUARDIAN_URL"] = guardian_url
        env["ACS_HANDSHAKE"] = "0"
        env.pop("ACS_DEFAULT_DENY", None)
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            [sys.executable, str(adapter)],
            input=json.dumps({
                "session_id": "00000000-0000-4000-8000-000000000001",
                "transcript_path": "/tmp/t", "cwd": "/tmp",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /home/u"},
            }),
            capture_output=True, text=True, env=env, timeout=timeout,
        )

    def test_adapter_waits_for_a_slow_guardian(self) -> None:
        """§6.4 — 'wait for the Guardian's decision up to the negotiated
        timeout'. The adapter MUST NOT proceed before the response
        arrives. We run a deliberately-slow Guardian (1s delay) and
        check the adapter took at least that long AND honored the result."""
        delay_s = 1.0

        class SlowGuardian(http.server.BaseHTTPRequestHandler):
            def do_POST(self_h):  # noqa: N802
                length = int(self_h.headers.get("Content-Length", "0"))
                body = json.loads(self_h.rfile.read(length).decode())
                time.sleep(delay_s)
                reply = json.dumps({
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "result": {"type": "final", "acs_version": "0.1.0",
                               "request_id": body.get("params", {}).get("request_id", ""),
                               "decision": "deny",
                               "reasoning": "slow guardian denied"},
                }).encode()
                self_h.send_response(200)
                self_h.send_header("Content-Length", str(len(reply)))
                self_h.send_header("Content-Type", "application/json")
                self_h.end_headers()
                self_h.wfile.write(reply)
            def log_message(self, *a, **kw): return

        srv = http.server.HTTPServer(("127.0.0.1", 0), SlowGuardian)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            start = time.monotonic()
            proc = self._run_claude_adapter(
                guardian_url=f"http://127.0.0.1:{port}/acs")
            elapsed = time.monotonic() - start
            self.assertGreaterEqual(elapsed, delay_s,
                f"adapter returned in {elapsed:.2f}s but Guardian deliberately "
                f"slept {delay_s}s — the adapter proceeded WITHOUT waiting. "
                f"§6.4 violated.")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny",
                "adapter waited but failed to apply the verdict")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_guardian_error_response_carries_distinct_cause(self) -> None:
        """A Guardian-returned JSON-RPC error must be distinguishable in
        the audit log from 'Guardian unreachable' — same §6.4 fail
        posture, but a signature error is a client bug while an
        unreachable Guardian is an ops issue.

        Setup: Guardian REQUIRES signing; the adapter runs WITHOUT a
        secret, so the Guardian responds -32004 SIGNATURE_INVALID.
        """
        adapter = HERE / "claude-code" / "acs_adapter.py"
        # Spin up a Guardian that requires signing
        env_g = os.environ.copy()
        env_g["ACS_HMAC_SECRET"] = "regression-test-secret"
        env_g.pop("ACS_DEV_MODE", None)
        env_g["ACS_GUARDIAN_STATE_DIR"] = tempfile.mkdtemp()
        guardian, port = launch_guardian(env=env_g)
        try:
            env_a = os.environ.copy()
            env_a["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{port}/acs"
            env_a["ACS_HANDSHAKE"] = "0"
            env_a.pop("ACS_HMAC_SECRET", None)
            env_a.pop("ACS_HMAC_SECRET_FILE", None)
            env_a.pop("ACS_DEFAULT_DENY", None)  # default fail-open

            proc = subprocess.run(
                [sys.executable, str(adapter)],
                input=json.dumps({
                    "session_id": "00000000-0000-4000-8000-000000000001",
                    "transcript_path": "/tmp/t", "cwd": "/tmp",
                    "permission_mode": "default",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "echo hi"},
                }),
                capture_output=True, text=True, env=env_a, timeout=10,
            )
            self.assertIn("ACS_AUDIT", proc.stderr,
                "refusal path must emit audit; stderr was:\n" + proc.stderr)
            # The unsigned adapter cannot verify the Guardian's signed
            # -32004 error, so the refusal surfaces one layer earlier —
            # still fail-closed, with the claimed code carried as
            # unverified triage metadata.
            self.assertIn("guardian_refusal_fail_closed", proc.stderr,
                "a Guardian refusal must fail closed even under "
                "DEFAULT_DENY=0 — fail-open here is a bypass primitive")
            self.assertIn('"permissionDecision": "deny"', proc.stdout,
                "the adapter must emit a real deny on the refusal path")
            # The audit carries the claimed -32004 /
            # signature_invalid_response, marked unverified, and never
            # collapses into the transport bucket.
            self.assertIn("signature_invalid_response", proc.stderr,
                "REGRESSION GAP: the audit must carry the claimed "
                "signature_invalid_response cause (unverified triage "
                "metadata) — without it operators can't grep for client "
                "bugs vs Guardian outages.")
            self.assertNotIn("cause\": \"transport_failure", proc.stderr,
                "Guardian-returned error must NOT be logged as transport_failure")
        finally:
            guardian.terminate()
            try: guardian.wait(timeout=2.0)
            except subprocess.TimeoutExpired: guardian.kill()

    def test_guardian_error_under_fail_closed_emits_deny(self) -> None:
        """Same unsigned-adapter setup with ACS_DEFAULT_DENY=1: the
        adapter MUST emit a deny AND audit the specific cause."""
        adapter = HERE / "claude-code" / "acs_adapter.py"
        env_g = os.environ.copy()
        env_g["ACS_HMAC_SECRET"] = "regression-test-secret-2"
        env_g.pop("ACS_DEV_MODE", None)
        env_g["ACS_GUARDIAN_STATE_DIR"] = tempfile.mkdtemp()
        guardian, port = launch_guardian(env=env_g)
        try:
            env_a = os.environ.copy()
            env_a["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{port}/acs"
            env_a["ACS_HANDSHAKE"] = "0"
            env_a["ACS_DEFAULT_DENY"] = "1"
            env_a.pop("ACS_HMAC_SECRET", None)
            env_a.pop("ACS_HMAC_SECRET_FILE", None)

            proc = subprocess.run(
                [sys.executable, str(adapter)],
                input=json.dumps({
                    "session_id": "00000000-0000-4000-8000-000000000002",
                    "transcript_path": "/tmp/t", "cwd": "/tmp",
                    "permission_mode": "default",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rm -rf /home/some-fake-path"},
                }),
                capture_output=True, text=True, env=env_a, timeout=10,
            )
            # With DEFAULT_DENY=1, the adapter MUST emit a deny on stdout.
            self.assertTrue(proc.stdout.strip(),
                "fail-closed mode must emit a deny on stdout, not be silent")
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError:
                self.fail(f"stdout was not JSON: {proc.stdout!r}")
            self.assertEqual(
                payload.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny",
                "PreToolUse adapter under DEFAULT_DENY=1 + Guardian rejects "
                "envelope must emit permissionDecision=deny."
            )
            # And the audit log must record the refusal class + cause.
            # SIGNATURE_INVALID is a refusal, so the audit type is
            # guardian_refusal_fail_closed (posture-independent), not the
            # posture-driven decision_failure_fail_closed (issue #32).
            self.assertIn("guardian_refusal_fail_closed", proc.stderr,
                "refusal audit type must appear")
            self.assertIn("signature_invalid_response", proc.stderr,
                "audit must carry cause=signature_invalid_response")
        finally:
            guardian.terminate()
            try: guardian.wait(timeout=2.0)
            except subprocess.TimeoutExpired: guardian.kill()

    def test_malformed_envelope_under_fail_closed_emits_deny(self) -> None:
        """A non-UUID session_id makes the Guardian return -32600
        Invalid Request; under DEFAULT_DENY=1 the adapter MUST emit a
        deny AND log cause=malformed_envelope_response."""
        adapter = HERE / "claude-code" / "acs_adapter.py"
        env_g = os.environ.copy()
        env_g["ACS_DEV_MODE"] = "1"  # no signing for this test
        env_g.pop("ACS_HMAC_SECRET", None)
        env_g.pop("ACS_HMAC_SECRET_FILE", None)
        env_g["ACS_GUARDIAN_STATE_DIR"] = tempfile.mkdtemp()
        guardian, port = launch_guardian(env=env_g)
        try:
            env_a = os.environ.copy()
            env_a["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{port}/acs"
            env_a["ACS_HANDSHAKE"] = "0"
            env_a["ACS_DEFAULT_DENY"] = "1"
            env_a.pop("ACS_HMAC_SECRET", None)
            env_a.pop("ACS_HMAC_SECRET_FILE", None)

            # Non-UUID session_id triggers -32600 from the Guardian's
            # request-envelope.json schema validation
            proc = subprocess.run(
                [sys.executable, str(adapter)],
                input=json.dumps({
                    "session_id": "test-sess",  # not a UUID — Guardian rejects
                    "transcript_path": "/tmp/t", "cwd": "/tmp",
                    "permission_mode": "default",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rm -rf /home/some-fake-path"},
                }),
                capture_output=True, text=True, env=env_a, timeout=10,
            )
            # Either the adapter refused to build the envelope at all
            # (adapter_build_failed) because session_id isn't a UUID,
            # OR the Guardian rejected with -32600. Both should result
            # in a deny under DEFAULT_DENY=1.
            self.assertTrue(proc.stdout.strip(),
                "fail-closed must emit a deny on stdout; stdout was empty. "
                "stderr: " + proc.stderr[:400])
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError:
                self.fail(f"stdout was not JSON: {proc.stdout!r}")
            self.assertEqual(
                payload.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny",
                "non-UUID session_id under DEFAULT_DENY=1 must produce deny, "
                "not silent proceed")
            # -32600 is a Guardian REFUSAL (alive-and-refused, and
            # attacker-reachable: oversize the body past the cap and the
            # envelope is rejected BEFORE policy runs), so the audit type
            # is guardian_refusal_fail_closed regardless of posture
            # (issue #32). adapter_build_failed (caught before the wire)
            # is a plain decision failure and keeps the posture-driven
            # type.
            self.assertTrue(
                "guardian_refusal_fail_closed" in proc.stderr
                or "decision_failure_fail_closed" in proc.stderr,
                f"a fail-closed audit type must appear; stderr: {proc.stderr[:400]}")
            # Cause is either adapter_build_failed (caught before the wire)
            # or malformed_envelope_response (caught by Guardian).
            self.assertTrue(
                "adapter_build_failed" in proc.stderr
                or "malformed_envelope_response" in proc.stderr,
                f"cause must distinguish the malformed-envelope case from "
                f"a transport failure; stderr was: {proc.stderr[:400]}")
        finally:
            guardian.terminate()
            try: guardian.wait(timeout=2.0)
            except subprocess.TimeoutExpired: guardian.kill()


class Core08b_NegotiatedDecisionTimeout(unittest.TestCase):
    """The signed ServerHello deadline, not a local constant, governs waits."""

    def _run_shell_adapter(self, platform: str, guardian,
                           cache_dir: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update({
            "ACS_GUARDIAN_URL": guardian.url(),
            "ACS_HMAC_SECRET": guardian.hmac_secret,
            "ACS_HANDSHAKE_CACHE": cache_dir,
        })
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env.pop("ACS_HANDSHAKE", None)
        env.pop("ACS_DEFAULT_DENY", None)
        if platform == "claude":
            command = [sys.executable, str(HERE / "claude-code" / "acs_adapter.py")]
            event = {
                "session_id": str(uuid.uuid4()), "cwd": "/tmp",
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": "echo hi"},
            }
        else:
            command = [sys.executable, str(HERE / "cursor" / "acs_adapter.py"),
                       "preToolUse"]
            event = {
                "conversation_id": str(uuid.uuid4()),
                "workspace_roots": ["/tmp"], "tool_name": "Bash",
                "tool_input": {"command": "echo hi"},
            }
        return subprocess.run(command, input=json.dumps(event),
                              capture_output=True, text=True, env=env,
                              timeout=5)

    def test_shell_adapters_apply_the_negotiated_deadline(self) -> None:
        """A DENY arriving after the negotiated 100 ms deadline is late:
        under the default fail-open posture the adapters must time out
        and audit, not apply it (the slow-Guardian test disables the
        handshake, so it cannot cover negotiation).
        """
        from test_harness import ProgrammableGuardian

        for platform in ("claude", "cursor"):
            with self.subTest(platform=platform):
                guardian = ProgrammableGuardian()

                def hello(req: dict) -> dict:
                    result = guardian._default_handshake(req)
                    result["payload"]["timeout_config"] = {"default_ms": 100}
                    return result

                def delayed_deny(req: dict) -> dict:
                    time.sleep(0.3)
                    return {
                        "type": "final", "acs_version": "0.1.0",
                        "request_id": req["params"]["request_id"],
                        "chain_hash": "0" * 64, "decision": "deny",
                        "reasoning": "arrived after negotiated deadline",
                    }

                guardian.handlers["handshake/hello"] = hello
                guardian.handlers["__default__"] = delayed_deny
                with tempfile.TemporaryDirectory() as cache_dir, guardian:
                    proc = self._run_shell_adapter(
                        platform, guardian, cache_dir)

                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn('"cause": "decision_timeout"', proc.stderr,
                    "the signed ServerHello timeout must control the real "
                    "Guardian round trip")
                self.assertNotIn('"permissionDecision": "deny"', proc.stdout)
                self.assertNotIn('"permission": "deny"', proc.stdout)


# =============================================================================
# CORE-09 — Liveness system/ping (conformance.md:25, §13)
# =============================================================================
#
# §13: "Guardians MUST always return decision: allow for system/ping
#       regardless of policy, signature, or session state."
# §13: "system/ping MUST NOT be written into SessionContext as a ContextEntry"
# §13: "system/ping MUST NOT require a signature even if the session
#       otherwise requires signatures"
# =============================================================================

class Core09_SystemPing(CoreHarness):

    def test_ping_returns_allow(self) -> None:
        """§13 — 'Guardians MUST always return decision: allow for
        system/ping regardless of policy, signature, or session state'.
        Also: the response envelope MUST validate against
        response-envelope.json."""
        env = self._make_envelope("system/ping", {"echo": "hi"}, sign=False)
        resp = self._post(env)
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["decision"], "allow")
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"ping response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))

    def test_ping_payload_includes_status_echo_timestamp(self) -> None:
        """§13 — 'response ... with decision: allow and a payload
        object carrying {status: ok, echo: <request.echo>,
        server_timestamp: <iso-8601>}'."""
        env = self._make_envelope("system/ping", {"echo": "ping-test"}, sign=False)
        result = self._post(env)["result"]
        payload = result.get("payload", {})
        self.assertEqual(payload.get("status"), "ok")
        self.assertEqual(payload.get("echo"), "ping-test")
        self.assertIn("server_timestamp", payload)

    def test_ping_does_not_consume_replay_slot(self) -> None:
        """§13 — 'system/ping MUST NOT be written into SessionContext
        as a ContextEntry; it does not participate in the chain hash'.
        Two pings with the same request_id must both succeed —
        otherwise ping is silently in the replay set."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        env1 = self._make_envelope("system/ping", {"echo": "1"},
                                    session_id=sid, request_id=rid, sign=False)
        env2 = self._make_envelope("system/ping", {"echo": "2"},
                                    session_id=sid, request_id=rid, sign=False)
        r1 = self._post(env1)
        r2 = self._post(env2)
        self.assertIn("result", r1)
        self.assertIn("result", r2,
            "second ping with same request_id was rejected — "
            "ping must not enter the replay set")


# =============================================================================
# CORE-10 — Wrapped MCP (conformance.md:26)
# =============================================================================
#
# "Wrapped MCP — protocols/MCP/*"
#
# Our example Guardian doesn't fully implement MCP wrapping (it falls
# through to unknown-method deny). But the method-namespace MUST accept
# protocols/MCP/* method names at the wire level — i.e., the envelope
# schema MUST validate such methods, and the Guardian MUST return
# either a valid result or a structured error (not crash).
# =============================================================================

class Core10_WrappedMcp(CoreHarness):

    def test_mcp_namespace_method_validates(self) -> None:
        """conformance.md:26 — the protocols/MCP/* namespace shape
        (an unconditional MUST on this branch's spec text; PR #21 —
        open, not in this branch — proposes MUST only for deployments
        whose sessions involve MCP. This reference stack exercises the
        shape either way). The envelope MUST
        be a valid wire-level form. request-envelope.json:13-14
        regex includes ^protocols/ so any protocols/MCP/* method
        passes schema validation."""
        env = self._make_envelope("protocols/MCP/tools/call", {})
        errors = _validate_request_envelope(env)
        self.assertEqual(errors, [],
            f"protocols/MCP/* method MUST be valid wire-format; got {errors}")

    def test_guardian_returns_structured_response_for_mcp(self) -> None:
        """The Guardian MUST not crash on a protocols/MCP/* method AND
        its response MUST validate against response-envelope.json (an
        empty-200 no-op fails this). Partial Core-10 verification —
        full wrapped-MCP semantics is a documented implementation gap
        (adapter READMEs)."""
        env = self._make_envelope("protocols/MCP/tools/call",
            {"name": "echo", "arguments": {"text": "hi"}})
        resp = self._post(env)
        # Must be a well-formed JSON-RPC envelope
        self.assertTrue("result" in resp or "error" in resp,
            f"Guardian response for MCP method lacks both result and error: {resp}")
        # ResponseEnvelope schema validates — including conditional fields
        # (deny -> reasoning required, etc.). A garbage response is rejected.
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"response to protocols/MCP/* envelope is malformed: {errors}")

class CitationGuard(unittest.TestCase):
    """Every conformance.md line this suite cites must still say what
    the citing test thinks it says."""

    # line number in docs/spec/conformance.md → fragment that must
    # appear on exactly that line. Update BOTH this table and the tests
    # citing the line when the spec text changes.
    CITED_LINES = {
        17: "Handshake",
        18: "Request/response envelope",
        19: "Hook taxonomy",
        20: "Dispositions",
        21: "SessionContext and Intent",
        22: "Replay protection",
        23: "Baseline integrity",
        24: "Decision honoring",
        25: "Liveness",
        26: "Wrapped MCP",
    }

    def test_cited_lines_still_carry_their_content(self) -> None:
        conformance = (Path(__file__).resolve().parents[1]
                       / "docs" / "spec" / "conformance.md")
        self.assertTrue(conformance.exists(),
            f"conformance.md not found at {conformance} — the suite's "
            "docstring citations have nothing to cite")
        lines = conformance.read_text().splitlines()
        for lineno, fragment in self.CITED_LINES.items():
            with self.subTest(line=lineno, expects=fragment):
                self.assertGreater(len(lines), lineno - 1,
                    f"conformance.md has no line {lineno}")
                actual = lines[lineno - 1]
                self.assertIn(fragment, actual,
                    f"conformance.md:{lineno} no longer contains "
                    f"{fragment!r} — it now reads:\n  {actual}\n"
                    f"A spec edit moved or rewrote a line this suite "
                    f"cites. Re-verify every test citing "
                    f"conformance.md:{lineno}, then update CITED_LINES.")


# =============================================================================
# Conformance summary — entry point.
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("ACS-Core conformance check (v0.1.0)")
    print("=" * 70)
    print("Spec source:", SPEC_DIR)
    print()
    unittest.main(verbosity=2)
