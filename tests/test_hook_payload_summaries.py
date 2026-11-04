"""Keep each payload summary on the Hooks page in step with its schema.

Implementers read the Hooks page first, and its one-line payload summaries
drifted from the schemas under `specification/v0.1.0/hooks/` (#389). Rows left
out required fields such as `toolCallResult`'s `tool`, listed three of four
`preCompact` triggers, and named fields no schema defines, such as
`knowledgeRetrieval`'s `keywords`. The schemas are the normative source, so
these checks read them. They cover the 19 `steps/*` hooks, whose sections have
bare names. Sections such as `agbom/snapshot` and `defer/subscribe` keep their
namespace in the name and are not checked here.

- every top-level payload field appears in the row, in backticks;
- every value of a top-level enum appears in the row, in backticks;
- every name the row puts in backticks is defined by that hook's schema, a
  schema it references, the request envelope's metadata, a ContextEntry, or
  is another hook's name.

Whether the row marks a field optional is not checked. Rows write "optionally"
before the fields the schema leaves out of `required`.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
PAGE = ROOT / "docs" / "spec" / "instrument" / "hooks.md"

# Names a row may put in backticks that its own schema does not define, each with its reason.
ALSO_NAMED = {
    "skillRegister": {"model": "the AgBOM component type a bundled model is inventoried as"},
}


def hook_sections(text):
    """Map each `## <hook>` section to its schema path and its payload row, or None without one."""
    found = {}
    for match in re.finditer(r"^## (\S+)\n(.*?)(?=^## |\Z)", text, re.M | re.S):
        schema = re.search(r"^Schema: \[`hooks/([a-z-]+\.json)`\]", match[2], re.M)
        if schema:
            payload = re.search(r"^\*\*Payload:\*\* (.+)$", match[2], re.M)
            found[match[1]] = (SPEC / "hooks" / schema[1], payload[1] if payload else None)
    return found


def steps_hooks(sections):
    """The `steps/*` hooks, whose sections have bare names, unlike `agbom/snapshot` or `defer/subscribe`."""
    return {hook: entry for hook, entry in sections.items() if "/" not in hook}


SECTIONS = hook_sections(PAGE.read_text(encoding="utf-8"))
STEPS = steps_hooks(SECTIONS)
ROWS = {hook: entry for hook, entry in STEPS.items() if entry[1] is not None}


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def resolve(node, document):
    while isinstance(node, dict) and node.get("$ref", "").startswith("#/"):
        for part in node["$ref"][2:].split("/"):
            document = document[part]
        node = document
    return node


def vocabulary(path, seen=None):
    """Every property name and string enum value in a schema and the schemas it references."""
    seen = set() if seen is None else seen
    if path in seen:
        return set()
    seen.add(path)
    names = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    names.update(value)
                elif key in ("enum", "const"):
                    names.update(v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str))
                elif key == "$ref" and isinstance(value, str) and not value.startswith("#"):
                    names.update(vocabulary((path.parent / value.split("#")[0]).resolve(), seen))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(load(path))
    return names


def shared_names():
    """Names any row may use: the request envelope's metadata fields and a ContextEntry's fields."""
    envelope = load(SPEC / "request-envelope.json")
    entry = load(SPEC / "context-entry.json")
    return set(envelope["$defs"]["Metadata"]["properties"]) | set(entry["properties"])


def named(row):
    """Identifiers the row puts in backticks; `composition.models` names both parts."""
    return {
        token
        for span in re.findall(r"`([^`]+)`", row)
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", span)
    }


def missing(path, row):
    """Top-level fields and top-level enum values the row leaves out."""
    schema = load(path)
    expected = set(schema["properties"])
    for prop in schema["properties"].values():
        expected.update(v for v in resolve(prop, schema).get("enum", []) if isinstance(v, str))
    return sorted(expected - named(row))


def undefined(hook, path, row):
    """Backticked names in the row that nothing the row may draw on defines."""
    allowed = vocabulary(path.resolve()) | shared_names() | set(SECTIONS) | set(ALSO_NAMED.get(hook, {}))
    return sorted(named(row) - allowed)


def test_every_steps_hook_has_a_payload_row():
    without = {hook for hook, (_, row) in STEPS.items() if row is None}
    assert not without, f"Hook sections with no **Payload:** row: {sorted(without)}"
    assert len(ROWS) == 19, f"Expected a payload row for each of the 19 steps/* hooks, found {len(ROWS)}"


def test_a_namespaced_section_with_a_payload_row_is_not_counted():
    """#496 adds `## defer/subscribe` with a schema link and a payload row; the steps/* checks must skip it."""
    page = PAGE.read_text(encoding="utf-8") + (
        "\n## defer/subscribe\n\n"
        "Schema: [`hooks/defer-subscribe.json`](https://example.com/defer-subscribe.json).\n\n"
        "**Payload:** `deferred_request_id`, the `request_id` of the deferred step.\n"
    )
    sections = hook_sections(page)
    assert "defer/subscribe" in sections
    assert steps_hooks(sections).keys() == STEPS.keys()


@pytest.mark.parametrize("hook", sorted(ROWS))
def test_payload_row_names_every_top_level_field_and_enum_value(hook):
    path, row = ROWS[hook]
    gaps = missing(path, row)
    assert not gaps, f"{hook}: the payload row leaves out {gaps}, which {path.name} defines"


@pytest.mark.parametrize("hook", sorted(ROWS))
def test_payload_row_names_only_what_the_schemas_define(hook):
    path, row = ROWS[hook]
    unknown = undefined(hook, path, row)
    assert not unknown, (
        f"{hook}: the payload row names {unknown}, which {path.name} does not define. "
        "If the name is deliberate, add it to ALSO_NAMED with its reason."
    )


def test_also_named_entries_are_still_needed():
    for hook, names in ALSO_NAMED.items():
        path, row = ROWS[hook]
        for name, reason in names.items():
            assert reason, f"ALSO_NAMED[{hook!r}][{name!r}] needs a reason"
            assert name in named(row), f"{hook}: the row no longer names {name!r}; remove it from ALSO_NAMED"
            assert name not in vocabulary(path.resolve()), f"{hook}: {path.name} now defines {name!r}; remove it from ALSO_NAMED"


# Rows as they read before #389, each with a gap the checks above must catch.
OLD_ROWS = [
    ("toolCallResult", "`request_id_ref` (the originating request), outputs, exit status, duration.",
     {"missing": {"tool", "exit_status", "outputs"}}),
    ("turnStart", "`turn_id`, `triggered_by` (`user_message`, `auto_continuation`, `agent_loop`, "
     "`subagent_return`), optional `parent_turn_id` for nested turns.",
     {"missing": {"scheduled", "external_event", "expected_inputs"}}),
    ("knowledgeRetrieval", "`query`, `keywords`, retrieved results (each with content, mime type, source id).",
     {"missing": {"results", "source"}, "undefined": {"keywords"}}),
    ("preCompact", "`entries_to_compact` (array of `step_id`s that will be summarized), pre-compaction "
     "`provenance_summary` (so the Guardian can see what it's about to lose), `triggered_by` "
     "(`size_threshold`, `manual`, `agent_initiated`).",
     {"missing": {"framework_initiated", "pre_compact_provenance_summary"}}),
    ("sessionEnd", "`reason` (`completed`, `cancelled`, `error`, `timeout`, `abandoned`), and an optional "
     "`summary` with the outcome, step count, errors, and `decision_failures`.",
     {"missing": {"final_chain_hash"}}),
]


@pytest.mark.parametrize("hook,row,gaps", OLD_ROWS, ids=[hook for hook, _, _ in OLD_ROWS])
def test_the_checks_catch_the_rows_issue_389_reported(hook, row, gaps):
    path, _ = ROWS[hook]
    assert gaps.get("missing", set()) <= set(missing(path, row))
    assert gaps.get("undefined", set()) <= set(undefined(hook, path, row))
