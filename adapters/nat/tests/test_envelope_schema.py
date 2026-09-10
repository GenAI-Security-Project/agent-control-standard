"""
Spec-validation tests for the NAT adapter.

Validates the adapter's `_build_request()` output against the
canonical v0.1.0 `request-envelope.json` and the corresponding
per-hook schemas. Does NOT require nvidia-nat-core to be installed
(the adapter's helpers are importable without NAT).
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.validators import RefResolver


# In-repo schemas by default (repo root is three levels up from tests/);
# override with ACS_SPEC_DIR to validate against an alternate checkout.
SPEC_DIR_DEFAULT = Path(__file__).resolve().parents[3] / "specification" / "v0.1.0"
SPEC_DIR = Path(os.environ.get("ACS_SPEC_DIR", str(SPEC_DIR_DEFAULT)))

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))

import acs_adapter  # noqa: E402


def _load_schema(name: str) -> dict:
    with open(SPEC_DIR / name) as f:
        return json.load(f)


def _validate(payload: dict, schema_name: str) -> list:
    schema = _load_schema(schema_name)
    resolver = RefResolver(
        base_uri=(SPEC_DIR.as_uri() + "/" + schema_name),
        referrer=schema,
    )
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(payload)
    ]


class _StubConfig:
    """Minimal stand-in for ACSMiddlewareConfig so the test runs without NAT installed."""
    guardian_url = "http://127.0.0.1:8787/acs"
    default_deny = True
    session_id = "00000000-0000-0000-0000-000000000001"
    timeout_s = 5.0
    target_function_or_group = "my_tools"
    target_location = "input"


class SpecValidationSetUp(unittest.TestCase):
    def setUp(self) -> None:
        if not SPEC_DIR.exists():
            self.fail(
                f"Canonical spec schemas not found at {SPEC_DIR}. "
                "Clone GenAI-Security-Project/agent-control-standard and set ACS_SPEC_DIR. "
                "Spec validation is non-negotiable; this is not a skip."
            )
        # Bypass FunctionMiddleware.__init__ when NAT isn't available; instantiate
        # the class directly with the stub config.
        try:
            self.mw = acs_adapter.ACSMiddleware(_StubConfig())
        except TypeError:
            # NAT base class accepts no args in some versions; retry with default ctor
            self.mw = object.__new__(acs_adapter.ACSMiddleware)
            self.mw.__init__(_StubConfig())


class EnvelopeMatchesV010Schema(SpecValidationSetUp):
    def test_toolcallrequest_envelope_validates(self) -> None:
        env = self.mw._build_request(
            method="steps/toolCallRequest",
            tool_name="search_web",
            tool_arguments={"query": "ACS spec"},
        )
        errors = _validate(env, "request-envelope.json")
        self.assertEqual(errors, [],
                         "envelope FAILS request-envelope.json:\n  - " + "\n  - ".join(errors))

    def test_toolcallresult_envelope_validates(self) -> None:
        env = self.mw._build_request(
            method="steps/toolCallResult",
            tool_name="search_web",
            tool_arguments={"query": "ACS spec"},
            result={"hits": 3},
        )
        errors = _validate(env, "request-envelope.json")
        self.assertEqual(errors, [],
                         "envelope FAILS request-envelope.json:\n  - " + "\n  - ".join(errors))

    def test_timestamp_is_iso8601(self) -> None:
        env = self.mw._build_request("steps/toolCallRequest", "x", {})
        ts = env["params"]["timestamp"]
        self.assertIsInstance(ts, str)
        import datetime as _dt
        _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_metadata_has_required_fields(self) -> None:
        env = self.mw._build_request("steps/toolCallRequest", "x", {})
        meta = env["params"]["metadata"]
        self.assertIn("agent_id", meta)
        self.assertIn("session_id", meta)
        self.assertTrue(meta["agent_id"])
        self.assertTrue(meta["session_id"])


class PayloadMatchesHookSchema(SpecValidationSetUp):
    def test_toolcallrequest_payload_validates(self) -> None:
        env = self.mw._build_request(
            method="steps/toolCallRequest",
            tool_name="search_web",
            tool_arguments={"query": "ACS", "limit": 10},
        )
        payload = env["params"]["payload"]
        errors = _validate(payload, "hooks/tool-call-request.json")
        self.assertEqual(errors, [],
                         "tool-call-request payload FAILS:\n  - " + "\n  - ".join(errors))
        for arg_name, arg_val in payload["arguments"].items():
            self.assertIn("value", arg_val,
                          f"argument '{arg_name}' missing 'value' wrapper")

    def test_toolcallresult_payload_validates(self) -> None:
        env = self.mw._build_request(
            method="steps/toolCallResult",
            tool_name="search_web",
            tool_arguments={"query": "ACS"},
            result={"hits": 3, "titles": ["spec", "core"]},
        )
        payload = env["params"]["payload"]
        errors = _validate(payload, "hooks/tool-call-result.json")
        self.assertEqual(errors, [],
                         "tool-call-result payload FAILS:\n  - " + "\n  - ".join(errors))
        self.assertIn(payload["exit_status"], {"success", "failure", "timeout", "blocked"})
        self.assertIsInstance(payload["outputs"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
