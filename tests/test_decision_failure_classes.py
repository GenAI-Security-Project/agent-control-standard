"""The sessionEnd failure count and the Trace failure event name the same classes.

`summary.decision_failures` in hooks/session-end.json counts decision failures per
class, and `acs.failure.class` on the `acs.decision.failure` event names the class of
each one. A class added to one list and not the other would leave a failure that one
side can record and the other cannot count.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SESSION_END = ROOT / "specification" / "v0.1.0" / "hooks" / "session-end.json"
OTEL_MAPPING = ROOT / "specification" / "v0.1.0" / "trace" / "otel-mapping.json"


def test_session_end_counts_exactly_the_trace_failure_classes():
    session_end = json.loads(SESSION_END.read_text(encoding="utf-8"))
    counted = session_end["properties"]["summary"]["properties"]["decision_failures"]["propertyNames"]["enum"]

    mapping = json.loads(OTEL_MAPPING.read_text(encoding="utf-8"))
    failure_event = mapping["properties"].get("decision_failure_event")
    assert failure_event is not None, "otel-mapping.json defines no decision_failure_event"
    emitted = failure_event["properties"]["attribute_values"]["default"]["acs.failure.class"]

    assert sorted(counted) == sorted(emitted), (
        f"session-end.json counts {sorted(counted)}; acs.failure.class takes {sorted(emitted)}"
    )
