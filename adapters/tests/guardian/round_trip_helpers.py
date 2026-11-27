"""Steps and helpers the round-trip tests share: send one step through acs.client and read the verified result."""
from __future__ import annotations

import copy
import uuid

from acs.client import Decided, FailPosture, round_trip
from acs.core import request_envelope
from acs.testing.harness import validate_response_envelope

SESSION = "44444444-4444-4444-8444-444444444444"
METADATA = {"agent_id": "finbot", "session_id": SESSION, "platform": "lab"}
# The most permissive posture, so a deny or an ask in these tests comes from the Guardian, never from the client.
PROCEED = FailPosture(deny_on_failure=False, timeout_s=5.0)
VENDOR_RESULT = {"tool": {"name": "get_vendor_details"}, "exit_status": "success",
                 "request_id_ref": "33333333-3333-4333-8333-333333333333",
                 "outputs": [{"value": {"name": "Acme", "bank_account_number": "111-222"}},
                             {"value": {"name": "Beta", "bank_account_number": "333-444"}}]}
TRANSFER = {"tool": {"name": "finstripe__create_transfer", "version": "sha256:ab"},
            "arguments": {"amount": {"value": 9000}, "to": {"value": "acct-1"}}}


def send_step(url: str, method: str, payload: dict) -> tuple[dict, dict]:
    """Send one step and return the request as sent and the verified, schema-valid result."""
    request = request_envelope(method, request_id=str(uuid.uuid4()), metadata=METADATA, payload=payload)
    sent = copy.deepcopy(request)
    outcome = round_trip(request, guardian_url=url, posture=PROCEED, session_id=SESSION, gate=True)
    assert isinstance(outcome, Decided), outcome
    assert validate_response_envelope(outcome.response) == []
    return sent, outcome.response["result"]


def apply_redactions(payload: dict, redactions: list[dict]) -> dict:
    """What the lab gateway does with a verified MODIFY (BUILD_PLAN A.4). acs.client carries no applier."""
    redacted = copy.deepcopy(payload)
    for redaction in redactions:
        *parents, leaf = [t.replace("~1", "/").replace("~0", "~") for t in redaction["path"][1:].split("/")]
        node = redacted
        for token in parents:
            node = node[int(token)] if isinstance(node, list) else node[token]
        node[leaf] = redaction.get("replacement", "[REDACTED]")
    return redacted
