from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


@dataclass(frozen=True)
class Decision:
    """A Guardian result's decision fields coerced to safe types; disposition is "" when unusable."""

    disposition: str = ""
    reasoning: str = ""
    modifications: dict = field(default_factory=dict)

    @property
    def known(self) -> bool:
        return self.disposition in KNOWN_DECISIONS


def normalize_decision(result: Any) -> Decision:
    """Coerce a Guardian result's decision fields without raising: an exception exits 1, which the hosts treat as proceed."""
    if not isinstance(result, dict):
        return Decision()
    raw_decision = result.get("decision")
    decision = raw_decision.strip().lower() if isinstance(raw_decision, str) else ""
    raw_reason = result.get("reasoning", "")
    reasoning = (raw_reason if isinstance(raw_reason, str)
                 else json.dumps(raw_reason, default=str))
    raw_mods = result.get("modifications", {})
    modifications = raw_mods if isinstance(raw_mods, dict) else {}
    return Decision(decision, reasoning, modifications)


def modify_composition_violation(modifications: dict) -> str | None:
    """Why a MODIFY breaks the §6.3 composition rules (both shapes, or overlapping targets), or None."""
    if not isinstance(modifications, dict):
        return None
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
        return value.replace("~", "~0").replace("/", "~1")

    def _paths_overlap(left: str, right: str) -> bool:
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
            # RFC 6901 allows only the ~0 and ~1 escapes.
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
