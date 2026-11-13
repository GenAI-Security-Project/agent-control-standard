"""Tests for the schema publisher.

The negative cases are the point. $id reaches this code from any pull request, including
a fork's, and it is used to build a filesystem path.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE, SchemaError, iter_refs, publish, resolve_pointer, target_for

REPO = Path(__file__).resolve().parents[1]


# --- $id validation -------------------------------------------------------

def test_target_for_strips_the_namespace_base():
    path = Path("v0.1.0/acs_schema.json")
    assert target_for({"$id": BASE + "v0.1.0/acs_schema.json"}, path, Path(".")) == \
        "v0.1.0/acs_schema.json"


def test_target_for_rejects_a_missing_id():
    with pytest.raises(SchemaError, match="no \\$id"):
        target_for({}, Path("broken.json"), Path("."))


def test_target_for_rejects_an_out_of_namespace_id():
    with pytest.raises(SchemaError, match="outside namespace"):
        target_for({"$id": "https://example.com/schema/v0.1.0/x.json"}, Path("broken.json"), Path("."))


@pytest.mark.parametrize(
    "tail",
    [
        "../index.html",
        "../../../../pwned.txt",
        "/etc/passwd",
        "v0.1.0/../../x.json",
        "v0.1.0/%2e%2e/x.json",
        "index.html",
        "v0.1.0/x.txt",
        "",
    ],
)
def test_target_for_rejects_unsafe_publish_paths(tail):
    """Each of these escapes the artifact or lands outside the versioned namespace."""
    with pytest.raises(SchemaError):
        target_for({"$id": BASE + tail}, Path("evil.json"), Path("."))


def test_a_percent_encoded_id_is_named_as_such(tmp_path):
    """SAFE_TAIL alone would reject this, with a message about the pattern.

    The percent-decode check exists to label the attempt, so a build log tells an
    operator someone tried something rather than that someone made a typo. Assert
    the specific message, or the check can be deleted with no test noticing.
    """
    with pytest.raises(SchemaError, match="must not be percent-encoded"):
        target_for({"$id": BASE + "v0.1.0/%2e%2e/x.json"}, Path("a.json"), Path("."))


def test_publish_refuses_an_id_that_escapes_the_output_root(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "../../../../pwned.txt")
    with pytest.raises(SchemaError):
        publish(src, out)
    assert not (tmp_path.parent / "pwned.txt").exists()


DRAFT_DIRS = [
    "proposals", "Proposals", "PROPOSALS", "proposal", "drafts", "draft",
    "_drafts", "draft-v2", "drafty", "wip", "experimental", "sandbox",
    "staging", "rc", "preview", "candidate", "unreleased", "incubator",
    "beta", "pending", "scratch", "playground", "prototype",
    "ｐｒｏｐｏｓａｌｓ",   # fullwidth
    "dra‍ft",                                               # zero-width joiner
    "prоposаls",                                       # Cyrillic homoglyphs
]


@pytest.mark.parametrize("directory", DRAFT_DIRS)
def test_no_directory_name_can_claim_the_normative_namespace(tmp_path, directory):
    """The old check was a name list, so it only refused names already on it.

    These are the complement the list could not cover, including three that render
    identically to a blocked word in a diff.
    """
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, f"{directory}/nested/sneak.json", BASE + "v0.1.0/sneak.json")
    with pytest.raises(SchemaError, match="but the file sits at"):
        publish(src, tmp_path / "out")


def test_a_draft_declaring_its_own_location_is_refused_by_the_tail_pattern(tmp_path):
    """The honest form fails too, so a draft has no way through at all."""
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, "proposals/honest.json", BASE + "proposals/honest.json")
    with pytest.raises(SchemaError, match="not a safe publish path"):
        publish(src, tmp_path / "out")


def test_publish_rejects_a_duplicate_id(tmp_path):
    """Two files, each honest about its own location, both claiming one $id."""
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    (src / "v0.1.0" / "b.json").write_text(
        json.dumps({"$id": BASE + "v0.1.0/a.json"}), encoding="utf-8"
    )
    with pytest.raises(SchemaError, match="but the file sits at"):
        publish(src, tmp_path / "out")


# --- placement ------------------------------------------------------------

def test_publish_places_files_at_their_declared_id_path(tmp_path):
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/acs_schema.json", BASE + "v0.1.0/acs_schema.json")
    assert publish(src, tmp_path / "out") == ["v0.1.0/acs_schema.json"]


def test_publish_skips_json_without_an_id(tmp_path):
    """An example payload beside a proposal must not stop the deploy."""
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    (src / "proposals").mkdir(parents=True, exist_ok=True)
    (src / "proposals" / "example.json").write_text('{"session_id": "abc"}', encoding="utf-8")
    assert publish(src, out) == ["v0.1.0/a.json"]


def test_publish_fails_on_invalid_json(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    (src / "v0.1.0").mkdir(parents=True)
    (src / "v0.1.0" / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(SchemaError, match="invalid JSON"):
        publish(src, out)


def test_publish_fails_when_no_schemas_are_found(tmp_path):
    with pytest.raises(SchemaError, match="no schemas found"):
        publish(tmp_path / "empty", tmp_path / "out")


def test_publish_handles_more_than_one_spec_version(tmp_path):
    """Old versions stay published so their $id URIs keep resolving."""
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    write_schema(src, "v0.2.0/a.json", BASE + "v0.2.0/a.json")
    assert publish(src, out) == ["v0.1.0/a.json", "v0.2.0/a.json"]


# --- reference closure ----------------------------------------------------

def test_iter_refs_finds_nested_and_listed_refs():
    doc = {"$ref": "a.json", "properties": {"x": {"$ref": "b.json"}}, "anyOf": [{"$ref": "c.json"}]}
    assert sorted(iter_refs(doc)) == ["a.json", "b.json", "c.json"]


def test_resolve_pointer_walks_objects_and_arrays():
    doc = {"$defs": {"S": {"type": "string"}}, "list": [{"a": 1}]}
    assert resolve_pointer(doc, "/$defs/S")
    assert resolve_pointer(doc, "/list/0/a")
    assert not resolve_pointer(doc, "/$defs/Missing")
    assert not resolve_pointer(doc, "/list/9")


def test_publish_resolves_a_parent_relative_ref(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/provenance.json", BASE + "v0.1.0/provenance.json")
    write_schema(
        src, "v0.1.0/hooks/session-start.json", BASE + "v0.1.0/hooks/session-start.json",
        {"properties": {"p": {"$ref": "../provenance.json"}}},
    )
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_dangling_ref(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "./missing.json"}}})
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)


def test_publish_fails_on_a_cross_file_fragment_that_does_not_exist(tmp_path):
    """Renaming a $defs entry another schema points at is the likeliest real breakage."""
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Renamed": {}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_accepts_a_cross_file_fragment_that_exists(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Sig": {"type": "string"}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_broken_self_fragment(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "#/$defs/Missing"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_ignores_an_external_ref(tmp_path):
    from conftest import write_schema

    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "https://json-schema.org/draft/2020-12/schema"}}})
    assert publish(src, out) == ["v0.1.0/a.json"]


# --- write safety -----------------------------------------------------------

def test_a_dangling_ref_leaves_no_output_directory(tmp_path):
    """Absence, not emptiness. An implementation that mkdirs first satisfies 'empty'."""
    from conftest import write_schema

    src = tmp_path / "spec"
    out = tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 body={"properties": {"x": {"$ref": BASE + "v0.1.0/gone.json"}}})
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)
    assert not out.exists()


def test_the_written_bytes_are_the_bytes_that_were_parsed(tmp_path, monkeypatch):
    """A second read at write time could substitute content nothing validated.

    Mutating the file the instant parsing finishes proves which read feeds the write.
    """
    import publish_schemas as ps
    from conftest import write_schema

    src = tmp_path / "spec"
    out = tmp_path / "out"
    target = write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    real_read = ps._read

    def read_then_tamper(source):
        parsed = real_read(source)
        target.write_bytes(b'{"$id": "tampered, never validated"}')
        return parsed

    monkeypatch.setattr(ps, "_read", read_then_tamper)
    ps.publish(src, out)
    written = json.loads((out / "v0.1.0/a.json").read_text())
    assert written["$id"] == BASE + "v0.1.0/a.json"


def test_a_symlink_out_of_the_source_tree_is_refused(tmp_path):
    """The symlink's own path satisfies every check while its target supplies bytes.

    Without resolving, any file on the runner becomes publishable as a schema by
    adding one three-line, self-consistent-looking entry under specification/.
    """
    src = tmp_path / "spec"
    (src / "v0.1.0").mkdir(parents=True)
    outside = tmp_path / "secret.json"
    outside.write_text(json.dumps({"$id": BASE + "v0.1.0/c.json", "token": "leak"}))
    (src / "v0.1.0" / "c.json").symlink_to(outside)
    with pytest.raises(SchemaError, match="resolves outside"):
        publish(src, tmp_path / "out")


def test_a_symlinked_directory_does_not_leak_its_contents(tmp_path):
    """rglob does not descend into a symlinked directory, so nothing under one is
    enumerated. That is behavior we depend on rather than check, so assert it here.
    If discovery ever moves to os.walk(followlinks=True), this fails instead of
    quietly publishing whatever the link points at.
    """
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "leak.json").write_text(
        json.dumps({"$id": BASE + "v0.1.0/leak.json", "secret": "x"}), encoding="utf-8"
    )
    (src / "v0.1.0" / "sub").symlink_to(outside, target_is_directory=True)

    published = publish(src, tmp_path / "out")
    assert published == ["v0.1.0/a.json"]
    assert not (tmp_path / "out" / "v0.1.0" / "leak.json").exists()


def test_two_paths_differing_only_by_case_are_refused(tmp_path):
    """A case-insensitive filesystem collapses these into one file.

    A Linux commit or the GitHub web editor can carry both. CI would publish two
    schemas while a maintainer's local checkout shows one, so the tree a human
    verifies is not the tree that deploys.
    """
    from conftest import write_schema

    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    upper = src / "v0.1.0" / "A.json"
    if upper.exists():
        pytest.skip("case-insensitive filesystem cannot hold both names")
    write_schema(src, "v0.1.0/A.json", BASE + "v0.1.0/A.json")
    with pytest.raises(SchemaError, match="differs from"):
        publish(src, tmp_path / "out")


# --- the real tree --------------------------------------------------------

def test_publish_handles_the_real_specification_tree(tmp_path):
    published = publish(REPO / "specification", tmp_path / "out")
    assert "v0.1.0/acs_schema.json" in published
    assert len(published) == len(set(published))
    # No magic count. A count assertion breaks on every legitimate schema addition,
    # and the first hand-bump after a collision would hide the collision.
    assert len(published) >= 44


def test_every_real_schema_is_a_valid_json_schema():
    """Ref closure is not validity. A closed package can still be unusable."""
    from jsonschema import Draft202012Validator

    for path in sorted((REPO / "specification").rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            Draft202012Validator.check_schema(doc)
