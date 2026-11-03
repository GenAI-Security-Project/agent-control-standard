"""Hook taxonomy guards for the Instrument pillar documents.

The hook set is stated in three places: the schemas under
`specification/v0.1.0/hooks/`, the overview table on the Hooks page, and the
taxonomy table in Specification section 5. The schemas are the normative
source; the two tables are readable views of the same set.

Nothing binds the views to the source. When the skill lifecycle hooks landed,
they reached the schemas and the Hooks page but not the taxonomy table, so the
specification page listed sixteen hooks while the Hooks page listed nineteen.
A reader treating the specification page as canonical never learned that skills
are governable, and the omission propagated into implementations. The build
stayed green throughout, so only a check that reads the schemas catches it.

The same drift reached the Trace pillar. The OpenTelemetry and OCSF mapping
tables under `specification/v0.1.0/trace/`, the two docs pages that render
them, and the overview on the ACS page each restate the set, and none of them
gained the skill hooks. A deployment emitting OTel or OCSF from the mapping
files had no span name and no event class for a skill event, so the one hook
that vets a whole skill left no trace. The guards below therefore reach every
surface that restates the set: a file naming eight or more hooks as
`steps/<name>` must name all of them, the mapping tables must key exactly the
schema set, and every hook count stated in the docs must match the schemas.

Two kinds of page trip those rules on purpose: one that names a hook proposed
for a later version, and one that lists a deliberate subset of eight or more
hooks. Each failure message names its escape hatch, and the two allowlists
below record every exemption with a reason, so a deliberate subset stays
distinguishable from a stale copy in review.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK_SCHEMAS = ROOT / "specification" / "v0.1.0" / "hooks"
SPECIFICATION = ROOT / "docs" / "spec" / "instrument" / "specification.md"
HOOKS_PAGE = ROOT / "docs" / "spec" / "instrument" / "hooks.md"
DOCS = ROOT / "docs"
TRACE_MAPPINGS = ROOT / "specification" / "v0.1.0" / "trace"
OTEL_MAPPING = TRACE_MAPPINGS / "otel-mapping.json"
OCSF_MAPPING = TRACE_MAPPINGS / "ocsf-mapping.json"

# A file that names this many distinct hooks as `steps/<name>` is restating
# the set rather than quoting an example. The Trace surfaces name fifteen or
# more; no example snippet in the docs names more than four.
RESTATING_THRESHOLD = 8

# Files that deliberately name a subset of RESTATING_THRESHOLD or more hooks as
# `steps/<name>`, such as a table of the hooks ACS-Core gates. Path relative to
# the repo root -> why the subset is intended. Empty by default: an entry lands
# in the same PR as the page that needs it, where a reviewer can judge it.
SUBSET_SURFACES = {}

# `steps/<name>` references that deliberately name no schema, such as a hook
# proposed for a later version. Path -> {name: reason}. Keyed by file so one
# page's exemption does not hide the same name on another page.
PROPOSED_HOOKS = {}

# Every place a new hook has to reach. Only some of them are checked below, so
# the omission messages print the whole list rather than only what failed.
NEW_HOOK_CHECKLIST = """
A new hook reaches all of these in the same PR:
  docs/spec/instrument/specification.md  section 5 taxonomy row
  docs/spec/instrument/hooks.md          overview row, `## <name>` section, count
  docs/spec/trace/events.md              OTel and OCSF tables
  docs/spec/trace/extend_ocsf.md         OCSF class table
  specification/v0.1.0/trace/*.json      step_to_span and step_to_class keys
  docs/spec/conformance.md, docs/acs.md  ACS-Core or additional-hooks list
  README.md                              native hook count"""

# `steps/skillRegister payload` -> "skillRegister". The profile variants title
# themselves `... payload (ACS-Provenance profile)` and are the same hook, so
# anchoring the end of the string collapses them to one entry.
SCHEMA_TITLE = re.compile(r"^steps/([A-Za-z][A-Za-z0-9]*) payload$")
# `| 15 | `skillRegister` | Skill enters ...` -> ("15", "skillRegister")
TAXONOMY_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*`([A-Za-z][A-Za-z0-9]*)`\s*\|")
# `| [`skillRegister`](#skillregister) | Skill enters ...` -> "skillRegister".
# Namespaced entries (`agbom/snapshot`, `system/ping`, `protocols/MCP/*`) carry
# a slash, so they do not match and stay out of the native set.
OVERVIEW_ROW = re.compile(r"^\|\s*\[?`([A-Za-z][A-Za-z0-9]*)`")
# `ACS v0.1.0 defines 19 native `steps/*` hooks` -> "19"
STATED_COUNT = re.compile(r"defines (\d+) native `steps/\*` hooks")
# `| `steps/skillRegister` | `acs.skill.register` |` -> "skillRegister".
# `steps/*` carries no name, so the wildcard on the Hooks page does not match.
# A glob (`steps/toolCall*`) names no single hook, and a path or anchor
# (`/docs/steps/x`, `#steps/x`) is not a method, so the lookarounds skip both.
STEPS_REFERENCE = re.compile(r"(?<![\w/#.-])steps/([A-Za-z][A-Za-z0-9]*)(?![\w*])")
# Spelled-out counts read like the digits and drifted the same way: README.md
# said "sixteen native lifecycle hooks" after the schemas reached nineteen.
NUMBER_WORDS = {
    word: value
    for value, word in enumerate(
        "sixteen seventeen eighteen nineteen twenty twenty-one twenty-two "
        "twenty-three twenty-four twenty-five".split(),
        start=16,
    )
}
# `16 native lifecycle hooks (` -> "16"; `sixteen native lifecycle hooks` ->
# "sixteen"; `19 native `steps/*` hooks` -> "19". "Native" is required, so the
# skill proposal's historical "Sixteen `steps/*` hooks" does not match.
STATED_COUNT_ANYWHERE = re.compile(
    r"\b(\d+|" + "|".join(NUMBER_WORDS) + r") native (?:lifecycle |`steps/\*` )?hooks",
    re.IGNORECASE,
)
# Where a native hook count may be stated. The proposals under
# `specification/proposals/` record the set as it stood and are left out.
COUNT_SURFACES = sorted(DOCS.rglob("*.md")) + [ROOT / "README.md"]


def native_hook_methods():
    """The normative hook set, read from the schemas' own declared titles."""
    methods = set()
    for path in sorted(HOOK_SCHEMAS.glob("*.json")):
        title = json.loads(path.read_text(encoding="utf-8")).get("title", "")
        match = SCHEMA_TITLE.match(title)
        if match:
            methods.add(match.group(1))
    return methods


def restating_surfaces():
    """Every file that may restate the hook set: docs pages and Trace mappings."""
    return sorted(DOCS.rglob("*.md")) + sorted(TRACE_MAPPINGS.glob("*.json"))


def steps_references(path):
    """Distinct hook names a file references as `steps/<name>`."""
    return set(STEPS_REFERENCE.findall(path.read_text(encoding="utf-8")))


def mapping_keys(path, table):
    """The `steps/*` keys of a Trace mapping's default table, prefix stripped.

    The tables also key `agbom/snapshot` and `agbom/changed`. Those are
    Inspect-pillar methods that share the request envelope, not hooks, so they
    sit outside the set the hook schemas define and are left out here.
    """
    mapping = json.loads(path.read_text(encoding="utf-8"))
    keys = mapping["properties"][table]["default"]
    return {key[len("steps/") :] for key in keys if key.startswith("steps/")}


def relative(path):
    return path.relative_to(ROOT).as_posix()


def section(path, heading):
    """Lines under a `## ` heading, stopping at the next one."""
    lines = path.read_text(encoding="utf-8").splitlines()
    # A bare next() raises StopIteration, which pytest prints with no hint of
    # which heading moved.
    start = next((i for i, line in enumerate(lines) if line.startswith(heading)), None)
    assert start is not None, (
        f"{relative(path)} has no heading starting {heading!r}. If it was renamed, "
        "update the heading this test reads."
    )
    for offset, line in enumerate(lines[start + 1 :], start=start + 1):
        if line.startswith("## "):
            return lines[start + 1 : offset]
    return lines[start + 1 :]


def test_specification_taxonomy_lists_every_native_hook():
    rows = [
        TAXONOMY_ROW.match(line)
        for line in section(SPECIFICATION, "## 5. Hook Taxonomy")
    ]
    listed = {match.group(2) for match in rows if match}
    expected = native_hook_methods()

    missing = sorted(expected - listed)
    unknown = sorted(listed - expected)
    assert not missing, (
        "Specification section 5 omits hooks the schemas define: "
        + ", ".join(missing)
        + NEW_HOOK_CHECKLIST
    )
    assert not unknown, (
        "Specification section 5 lists hooks with no schema: "
        + ", ".join(unknown)
        + ". Add the schema under specification/v0.1.0/hooks/ or drop the row."
    )


def test_specification_taxonomy_numbering_runs_without_gaps():
    numbers = [
        int(match.group(1))
        for line in section(SPECIFICATION, "## 5. Hook Taxonomy")
        if (match := TAXONOMY_ROW.match(line))
    ]
    assert numbers == list(range(1, len(numbers) + 1)), (
        f"Specification section 5 numbering is not 1..{len(numbers)}: {numbers}"
    )


def test_hooks_page_overview_lists_every_native_hook():
    rows = [OVERVIEW_ROW.match(line) for line in section(HOOKS_PAGE, "## Overview")]
    listed = {match.group(1) for match in rows if match}
    expected = native_hook_methods()

    missing = sorted(expected - listed)
    unknown = sorted(listed - expected)
    assert not missing, (
        "Hooks page overview omits hooks the schemas define: "
        + ", ".join(missing)
        + NEW_HOOK_CHECKLIST
    )
    assert not unknown, (
        "Hooks page overview lists hooks with no schema: "
        + ", ".join(unknown)
        + ". Add the schema under specification/v0.1.0/hooks/ or drop the row."
    )


def test_hooks_page_states_the_real_hook_count():
    match = STATED_COUNT.search(HOOKS_PAGE.read_text(encoding="utf-8"))
    assert match, "Hooks page no longer states a native `steps/*` hook count"
    expected = len(native_hook_methods())
    assert int(match.group(1)) == expected, (
        f"Hooks page claims {match.group(1)} native hooks; the schemas define "
        f"{expected}. Update the count on line 3 and in the diagram."
    )


def test_every_steps_reference_names_a_schema_hook():
    expected = native_hook_methods()
    unknown = {}
    for path in restating_surfaces():
        proposed = PROPOSED_HOOKS.get(relative(path), {})
        stray = sorted(steps_references(path) - expected - proposed.keys())
        if stray:
            unknown[relative(path)] = stray
    assert not unknown, (
        "Files reference `steps/` methods no schema defines:\n"
        + "\n".join(f"  {file}: {', '.join(hooks)}" for file, hooks in unknown.items())
        + "\nFix the typo, add the schema, or, for a hook proposed for a later "
        "version, add it to PROPOSED_HOOKS in this file with a reason."
    )


def test_restating_surfaces_list_every_native_hook():
    expected = native_hook_methods()
    missing = {}
    for path in restating_surfaces():
        if relative(path) in SUBSET_SURFACES:
            continue
        listed = steps_references(path)
        if len(listed) >= RESTATING_THRESHOLD and expected - listed:
            missing[relative(path)] = sorted(expected - listed)
    assert not missing, (
        f"Files naming {RESTATING_THRESHOLD} or more hooks as `steps/<name>` are "
        "treated as restating the set, and these omit hooks the schemas define:\n"
        + "\n".join(f"  {file}: {', '.join(hooks)}" for file, hooks in missing.items())
        + "\nAdd the missing hooks. If the file lists a subset on purpose, add it "
        "to SUBSET_SURFACES in this file with a reason, or write the subset "
        "without the `steps/` prefix."
        + NEW_HOOK_CHECKLIST
    )


def test_allowlist_entries_carry_a_reason_and_are_still_needed():
    expected = native_hook_methods()
    stale = []
    for file, reason in SUBSET_SURFACES.items():
        if not (ROOT / file).is_file() or not reason.strip():
            stale.append(f"SUBSET_SURFACES {file}: missing file or empty reason")
    for file, names in PROPOSED_HOOKS.items():
        path = ROOT / file
        for name, reason in names.items():
            if not path.is_file() or not reason.strip():
                stale.append(f"PROPOSED_HOOKS {file} {name}: missing file or empty reason")
            elif name in expected or name not in steps_references(path):
                # Once the hook ships, or the page drops it, the exemption only
                # hides the next mistake.
                stale.append(f"PROPOSED_HOOKS {file} {name}: no longer needed")
    assert not stale, "Remove or fix these allowlist entries:\n  " + "\n  ".join(stale)


@pytest.mark.parametrize(
    "path, table",
    [(OTEL_MAPPING, "step_to_span"), (OCSF_MAPPING, "step_to_class")],
    ids=["otel", "ocsf"],
)
def test_trace_mapping_keys_exactly_the_native_hooks(path, table):
    keyed = mapping_keys(path, table)
    expected = native_hook_methods()

    missing = sorted(expected - keyed)
    unknown = sorted(keyed - expected)
    assert not missing, (
        f"{path.name} {table} omits hooks the schemas define: "
        + ", ".join(missing)
        + NEW_HOOK_CHECKLIST
    )
    assert not unknown, (
        f"{path.name} {table} keys hooks with no schema: "
        + ", ".join(unknown)
        + ". Add the schema under specification/v0.1.0/hooks/ or drop the key."
    )


def test_every_docs_page_states_the_real_hook_count():
    expected = len(native_hook_methods())
    stated = 0
    wrong = {}
    for path in COUNT_SURFACES:
        for match in STATED_COUNT_ANYWHERE.finditer(path.read_text(encoding="utf-8")):
            word = match.group(1).lower()
            count = NUMBER_WORDS.get(word) or int(word)
            # "These 2 native hooks" counts a subset, never the whole set, which
            # has always held more than RESTATING_THRESHOLD hooks.
            if count < RESTATING_THRESHOLD:
                continue
            stated += 1
            if count != expected:
                wrong.setdefault(relative(path), []).append(match.group(1))
    assert stated, "No docs page states a native hook count; the prose has moved"
    assert not wrong, (
        f"Pages claim a native hook count other than the {expected} the schemas define:\n"
        + "\n".join(f"  {file}: {', '.join(counts)}" for file, counts in wrong.items())
        + f"\nUpdate the count. To count a subset, write it as \"9 of the {expected} "
        "native hooks\" so the total stays checked."
    )


def test_agbom_update_triggers_cover_every_component_type():
    """Every component type in agbom/component.json must have a bullet in
    docs/spec/inspect/README.md under '## Triggers for AgBOM updates' (#120)."""
    component_schema = json.loads(
        (ROOT / "specification" / "v0.1.0" / "agbom" / "component.json").read_text(
            encoding="utf-8"
        )
    )
    component_types = component_schema["properties"]["type"]["enum"]
    inspect_readme = DOCS / "spec" / "inspect" / "README.md"
    bullets = [
        line.strip()
        for line in section(inspect_readme, "## Triggers for AgBOM updates")
        if line.strip().startswith("- ")
    ]
    assert len(bullets) == len(component_types), (
        f"AgBOM update trigger list has {len(bullets)} bullets for "
        f"{len(component_types)} component types"
    )
    for comp_type in component_types:
        phrase = comp_type.replace("_", " ").lower()
        assert any(phrase in b.lower() for b in bullets), (
            f"AgBOM update triggers omit component type {comp_type!r}"
        )

