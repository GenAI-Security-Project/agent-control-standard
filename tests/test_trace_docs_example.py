"""The example span on the Trace with OpenTelemetry page is real exporter output.

The page shows one span from the committed sample trace
(reference-implementations/agt/samples/trace/acs-trace-sample.jsonl), so a
reader sees what the reference Guardian actually emits. An example copied by
hand drifts the first time the exporter or the mapping changes, so this test
requires it to match the sample's span with the same acs.request_id, once
the values that differ between runs (ids and timestamps) are set aside. When
the sample is regenerated, the example has to be updated with it.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "spec" / "trace" / "extend_opentelemetry.md"
SAMPLE = ROOT / "reference-implementations" / "agt" / "samples" / "trace" / "acs-trace-sample.jsonl"
HEADING = "## Example: a denied tool call"
VOLATILE = {"traceId", "spanId", "parentSpanId", "startTimeUnixNano", "endTimeUnixNano", "timeUnixNano"}


def _strip(value):
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def _request_id(span):
    for attribute in span.get("attributes", []):
        if attribute["key"] == "acs.request_id":
            return attribute["value"]["stringValue"]
    return None


def _sample_spans():
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            for resource in json.loads(line)["resourceSpans"]:
                for scope in resource["scopeSpans"]:
                    yield from scope["spans"]


def test_docs_example_span_matches_the_committed_sample():
    text = PAGE.read_text(encoding="utf-8")
    assert HEADING in text, f"{PAGE.name} has no '{HEADING}' section"
    block = re.search(r"```json\n(.*?)```", text[text.index(HEADING):], re.S)
    assert block, f"the '{HEADING}' section has no JSON example"
    example = json.loads(block.group(1))

    request_id = _request_id(example)
    matches = [span for span in _sample_spans() if _request_id(span) == request_id]
    assert len(matches) == 1, f"the sample has no single span with acs.request_id {request_id}"
    assert _strip(example) == _strip(matches[0]), "the docs example no longer matches the sample; copy the span from the regenerated sample"
