"""Reading a Guardian's decision safely, and the §6.3 MODIFY composition rules."""
from __future__ import annotations

import json
import re
from typing import Any


# ----- Safe decision normalization -----

# The five ACS dispositions (§6.3). Shared so every adapter classifies an
# arrived verdict against the same set.
KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def normalize_decision(result: Any) -> tuple[str, str, dict]:
    """Coerce a Guardian result's decision fields to safe types, never
    raising.

    Reading `decision`/`reasoning`/`modifications` must never throw:
    §6.3:146 requires failing closed on an undeterminable Guardian
    intent, and an uncaught AttributeError exits 1, which the shell
    hosts treat as proceed (fail-open).

    Returns (decision, reasoning, modifications):
      - decision: stripped, lower-cased str; "" when the field is not a
        usable string, which routes the caller to its unusable→DENY branch.
      - reasoning: always a str (JSON repr if the Guardian sent a
        non-string, so it can go into a `reason` field unchanged).
      - modifications: always a dict ({} when the Guardian sent a
        non-object, which makes a MODIFY with no usable mutation
        substitute to DENY per §6.3:146).
    """
    if not isinstance(result, dict):
        return "", "", {}
    raw_decision = result.get("decision")
    decision = raw_decision.strip().lower() if isinstance(raw_decision, str) else ""
    raw_reason = result.get("reasoning", "")
    reasoning = (raw_reason if isinstance(raw_reason, str)
                 else json.dumps(raw_reason, default=str))
    raw_mods = result.get("modifications", {})
    modifications = raw_mods if isinstance(raw_mods, dict) else {}
    return decision, reasoning, modifications


def modify_composition_violation(modifications: dict) -> str | None:
    """Return a reason string if a MODIFY's `modifications` object violates
    the §6.3 / modifications.json composition rules, else None.

    The two shapes are mutually exclusive (modifications.json `oneOf`):
    wholesale `modified_content`, OR structured edits (`redactions` and/or
    `parameter_overrides`) whose targets are DISJOINT — never both shapes,
    never overlapping structured targets. Per §6.3:146 the receiver MUST
    fail closed (DENY) rather than half-apply one branch."""
    if not isinstance(modifications, dict):
        return None  # caller treats empty/absent as no-usable-mutation
    has_content = "modified_content" in modifications
    has_redactions = "redactions" in modifications
    has_overrides = "parameter_overrides" in modifications
    redactions = modifications.get("redactions")
    overrides = modifications.get("parameter_overrides")
    if has_content and (has_redactions or has_overrides):
        return ("modifications combines wholesale modified_content with "
                "structured edits — the two shapes are mutually exclusive "
                "(§6.3)")
    if has_content and not isinstance(modifications.get("modified_content"), str):
        return "modified_content is not a string — Guardian intent is unusable (§6.3)"
    if has_redactions and not isinstance(redactions, list):
        return "redactions is not an array — Guardian intent is unusable (§6.3)"
    if has_overrides and not isinstance(overrides, dict):
        return ("parameter_overrides is not an object — Guardian intent is "
                "unusable (§6.3)")

    def _pointer_token(value: str) -> str:
        """Encode one object-member name as an RFC 6901 token."""
        return value.replace("~", "~0").replace("/", "~1")

    def _paths_overlap(left: str, right: str) -> bool:
        """True when equal paths or one JSON Pointer contains the other."""
        return (left == right or left == "" or right == ""
                or left.startswith(right + "/")
                or right.startswith(left + "/"))

    override_paths = {
        f"/{_pointer_token(key)}": key
        for key in (overrides or {})
        if isinstance(key, str)
    }
    if has_redactions:
        for r in redactions:
            if not isinstance(r, dict):
                return ("redactions contains a non-object item — Guardian "
                        "intent is unusable (§6.3)")
            path = r.get("path")
            if not isinstance(path, str) or (path and not path.startswith("/")):
                return (f"redaction path {path!r} is not an RFC 6901 JSON "
                        "Pointer — Guardian intent is unusable (§6.3)")
            # JSON Pointer permits only ~0 and ~1 escape sequences.  Reject a
            # malformed pointer rather than compare a different path from the
            # one the Guardian intended.
            if re.search(r"~(?:[^01]|$)", path):
                return (f"redaction path '{path}' has an invalid JSON Pointer "
                        "escape — Guardian intent is unusable (§6.3)")
            if has_overrides:
                for override_path, key in override_paths.items():
                    if _paths_overlap(path, override_path):
                        return (f"redaction path '{path}' overlaps "
                                f"parameter_override '{key}' — structured "
                                "targets MUST be disjoint (§6.3)")
    return None
