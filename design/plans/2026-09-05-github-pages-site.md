# GitHub Pages Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a landing page, the MkDocs specification site, and all 44 JSON schemas to GitHub Pages on every merge to `main`, so that schema `$id` URIs resolve for the first time.

**Architecture:** One workflow runs tests, assembles three parts into a single Pages artifact, deploys, then verifies the published bytes. Schema publish paths derive from each schema's own `$id`, validated and contained. Landing page content that varies with repository state is injected at build time and machine-checked.

**Tech Stack:** Python 3.11+, uv, MkDocs Material, pytest, GitHub Actions, hand-authored HTML and CSS with no JavaScript framework and no third-party runtime assets.

**Spec:** `design/2026-09-05-github-pages-landing.md`

**Revision:** 2.0. Version 1.0 went through a six-perspective adversarial premortem that returned 36 findings at Plausible or above, four Critical. Every fix below is verified by execution, not by reasoning. The premortem map at the end of this document ties each finding to the task that closes it.

## Global Constraints

- Python `>=3.11`, matching `pyproject.toml` `requires-python`.
- uv pinned to `0.9.9` in CI, matching `.github/workflows/sync_version.yml`.
- Every GitHub Action SHA-pinned with a trailing version comment. The five pins in this plan were each resolved from the action's tagged release and verified to point at that tag.
- Workflow-level `permissions: {}`. Jobs grant only what they need.
- Never interpolate `${{ }}` inside a `run:` block. Pass values through `env:` and reference the shell variable. `sync_version.yml` documents this rule and this plan follows it.
- Schema `$id` values must not change. `$id` is versioned by spec version (`v0.1.0`), not release version (`version.txt`, currently `0.1.1`).
- `$id` and `GOVERNANCE.md` are untrusted input. Both are writable by pull request and both reach a filesystem path or an HTML attribute. Validate accordingly.
- The landing page carries exactly one email address, `rock.lambros@owasp.org`. Example addresses in `docs/` keep using the RFC 2606 reserved domains, and the eleven that exist today stay as they are.
- The published site loads no third-party asset. No external font, script, stylesheet, or image.
- Landing page links must be relative (`docs/`), never root-relative (`/docs/`). A project Pages site serves from `/agent-control-standard/`.
- Prose follows `STYLE.md`. Avoid em dashes, semicolons, sentences starting with conjunctions, and filler words (just, very, really, actually, certainly, basically, literally, utilize, facilitate, leverage, robust, seamless, transformative, holistic, unlock, unleash, empower). This includes the HTML `<title>`.
- Every guard must run in CI. A test that only runs on a developer's laptop is not a control.
- Never credit an AI in commit messages, code comments, file headers, or documentation.
- All work lands on branch `feat/github-pages-site`.

---

## File Structure

| File | Responsibility |
|---|---|
| `tools/publish_schemas.py` | Place each schema at the validated path its `$id` declares. Verify every `$ref` resolves, fragment included. |
| `tools/render_landing.py` | Replace named placeholders in the landing page from repository state. Escape untrusted content. |
| `tools/verify_published.py` | Poll the deployed site and assert each schema serves its own `$id`. |
| `landing/index.html` | Landing page markup and copy. |
| `landing/assets/acs.css` | Design tokens, layout, light and dark themes. |
| `landing/assets/starburst.svg` | Hero diagram, injected at build time. |
| `landing/assets/icon.svg` | Favicon. |
| `landing/assets/fonts/` | Self-hosted Inter, so the page contacts no third party. |
| `tests/test_publish_schemas.py` | Publishing, containment, and ref-closure tests. |
| `tests/test_render_landing.py` | Injection, escaping, and parser-robustness tests. |
| `tests/test_landing_page.py` | Content guards, run against the **rendered** page. |
| `tests/test_site_config.py` | Regression test that no third-party request ships. |
| `.github/workflows/deploy-pages.yml` | Test, build, deploy, verify. |
| `.github/workflows/monitor-pages.yml` | Scheduled check that the published schemas still resolve. |
| `mkdocs.yml` | Modified: remove `extra.analytics`, set `font: false`. |
| `.gitignore` | Modified: add `_site/`. |
| `pyproject.toml` | Modified: add a `dev` group with pytest and jsonschema. |
| `CLAUDE.md`, `SECURITY.md`, `LICENSING.md`, `.github/CODEOWNERS` | Modified: policy and ownership catch up with the new hosting posture. |

---

## Task 1: Schema publisher

Publishes schemas to the validated paths their `$id` values declare and fails the build if the package does not resolve completely. `$id` is attacker-influenced input: a fork pull request reaches this code on the runner before any human review.

**Files:**
- Create: `tools/publish_schemas.py`, `tests/test_publish_schemas.py`
- Modify: `pyproject.toml`, `uv.lock`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `BASE: str`; `class SchemaError(Exception)`; `load_schemas(source: Path) -> dict[Path, dict]`; `target_for(doc: dict, path: Path) -> str`; `iter_refs(node: object) -> Iterator[str]`; `resolve_pointer(doc: dict, pointer: str) -> bool`; `publish(source: Path, out: Path) -> list[str]`. CLI: `python tools/publish_schemas.py <source> <out>`.

- [ ] **Step 1: Add the dev dependency group**

Append to `pyproject.toml`:

```toml
[dependency-groups]
dev = [ "pytest>=8.0", "jsonschema>=4.25.0",]
```

- [ ] **Step 2: Regenerate the lockfile**

Run: `uv lock`
Expected: `uv.lock` updates. Note the resolved pytest version; `>=8.0` resolves to a 9.x release, which is correct because the lockfile is the pin.

- [ ] **Step 3: Write the failing tests**

Create `tests/test_publish_schemas.py`:

```python
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


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --- $id validation -------------------------------------------------------

def test_target_for_strips_the_namespace_base():
    assert target_for({"$id": BASE + "v0.1.0/acs_schema.json"}, Path("a")) == "v0.1.0/acs_schema.json"


def test_target_for_rejects_a_missing_id():
    with pytest.raises(SchemaError, match="no \\$id"):
        target_for({}, Path("broken.json"))


def test_target_for_rejects_an_out_of_namespace_id():
    with pytest.raises(SchemaError, match="outside namespace"):
        target_for({"$id": "https://example.com/schema/v0.1.0/x.json"}, Path("broken.json"))


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
        target_for({"$id": BASE + tail}, Path("evil.json"))


def test_publish_refuses_an_id_that_escapes_the_output_root(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "../../../../pwned.txt")
    with pytest.raises(SchemaError):
        publish(src, out)
    assert not (tmp_path.parent / "pwned.txt").exists()


def test_publish_rejects_a_draft_claiming_the_normative_namespace(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    write_schema(src, "proposals/draft.json", BASE + "v0.1.0/draft.json")
    with pytest.raises(SchemaError, match="normative namespace"):
        publish(src, out)


def test_publish_rejects_a_duplicate_id(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/dup.json", {"x": 1})
    write_schema(src, "v0.1.0/b.json", BASE + "v0.1.0/dup.json", {"x": 2})
    with pytest.raises(SchemaError, match="duplicate \\$id"):
        publish(src, out)


# --- placement ------------------------------------------------------------

def test_publish_places_files_at_their_declared_id_path(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    # On-disk layout deliberately differs from the URI layout.
    write_schema(src, "ACS/acs_schema.json", BASE + "v0.1.0/acs_schema.json")
    assert publish(src, out) == ["v0.1.0/acs_schema.json"]
    assert (out / "v0.1.0" / "acs_schema.json").is_file()


def test_publish_skips_json_without_an_id(tmp_path):
    """An example payload beside a proposal must not stop the deploy."""
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
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/provenance.json", BASE + "v0.1.0/provenance.json")
    write_schema(
        src, "v0.1.0/hooks/session-start.json", BASE + "v0.1.0/hooks/session-start.json",
        {"properties": {"p": {"$ref": "../provenance.json"}}},
    )
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_dangling_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "./missing.json"}}})
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)


def test_publish_fails_on_a_cross_file_fragment_that_does_not_exist(tmp_path):
    """Renaming a $defs entry another schema points at is the likeliest real breakage."""
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Renamed": {}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_accepts_a_cross_file_fragment_that_exists(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Sig": {"type": "string"}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_broken_self_fragment(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "#/$defs/Missing"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_ignores_an_external_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "https://json-schema.org/draft/2020-12/schema"}}})
    assert publish(src, out) == ["v0.1.0/a.json"]


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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -v`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'publish_schemas'`

- [ ] **Step 5: Write the implementation**

Create `tools/publish_schemas.py`:

```python
#!/usr/bin/env python3
"""Publish JSON schemas to the paths their own $id values declare.

The on-disk layout does not match the URI layout. specification/ACS/acs_schema.json
declares an $id of .../schema/v0.1.0/acs_schema.json, so deriving the destination from
$id avoids a hardcoded special case and lets a new spec version publish untouched.

$id is attacker-influenced input, not trusted identity. Anyone who can land a file under
specification/ controls the string, and a fork pull request reaches this code on the
runner before review. Every path derived from it is validated and contained.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin

BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

# A publishable tail: version directory, then nested names, ending in .json.
SAFE_TAIL = re.compile(r"^v[0-9]+(?:\.[0-9]+)*/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.json$")

# Draft schemas live here. They must never publish to a normative URI.
NON_NORMATIVE = ("proposals",)


class SchemaError(Exception):
    """A schema has an unusable $id, an unsafe publish path, or an unresolvable $ref."""


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source that declares an $id.

    Files without an $id are skipped rather than fatal. Example payloads and fixtures
    live under specification/ too, and a contributor adding one must not stop the deploy.
    """
    schemas: dict[Path, dict] = {}
    for path in sorted(source.rglob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise SchemaError(f"{path}: invalid JSON: {error}") from error
        if not isinstance(doc, dict) or "$id" not in doc:
            continue
        schemas[path] = doc
    return schemas


def target_for(doc: dict, path: Path) -> str:
    """Return the validated publish path a document's $id declares.

    Rejects anything that would escape the output root or land outside the versioned
    namespace. The check runs on the decoded string so percent-encoded traversal
    cannot slip past it.
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
    if any(part in NON_NORMATIVE for part in path.parts):
        raise SchemaError(
            f"{path}: a file under {'/'.join(NON_NORMATIVE)}/ must not claim the "
            f"normative namespace ($id: {sid})"
        )
    return tail


def iter_refs(node: object) -> Iterator[str]:
    """Yield every $ref string anywhere in a parsed document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_refs(item)


def resolve_pointer(doc: dict, pointer: str) -> bool:
    """Return whether a JSON Pointer resolves inside doc. An empty pointer means the root."""
    if pointer in ("", "/"):
        return True
    node: object = doc
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                return False
            node = node[int(token)]
        else:
            return False
    return True


def verify_refs(docs: dict[Path, dict], by_id: dict[str, dict]) -> None:
    """Fail if a $ref inside our namespace does not resolve, fragment included.

    Checking only the file leaves the likeliest real breakage undetected: renaming a
    $defs entry another schema points at. The package holds one cross-file fragment
    reference and it targets the signature definition.
    """
    for path, doc in docs.items():
        sid = doc["$id"]
        for ref in iter_refs(doc):
            target, fragment = urldefrag(urljoin(sid, ref))
            if not target.startswith(BASE):
                continue  # external reference, not ours to publish
            if target not in by_id:
                raise SchemaError(
                    f"{path}: $ref {ref!r} resolves to {target}, which no $id publishes"
                )
            if fragment == "" or fragment.startswith("/"):
                if not resolve_pointer(by_id[target], fragment):
                    raise SchemaError(
                        f"{path}: $ref {ref!r} points at {fragment!r}, "
                        f"which does not exist in {target}"
                    )


def publish(source: Path, out: Path) -> list[str]:
    """Copy every schema to its $id-declared path. Return sorted relative paths."""
    docs = load_schemas(source)
    if not docs:
        raise SchemaError(f"no schemas found under {source}")

    out.mkdir(parents=True, exist_ok=True)
    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    published: list[str] = []

    for path, doc in docs.items():
        rel = target_for(doc, path)
        sid = doc["$id"]
        if sid in seen:
            raise SchemaError(f"{path}: duplicate $id {sid}, already declared by {seen[sid]}")
        seen[sid] = path

        destination = (out / rel).resolve()
        # Belt and braces. SAFE_TAIL should make this unreachable. If it ever is
        # reachable, the build stops rather than writing outside the artifact.
        if not destination.is_relative_to(out_root):
            raise SchemaError(f"{path}: $id escapes the output root: {sid}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        by_id[sid] = doc
        published.append(rel)

    verify_refs(docs, by_id)
    return sorted(published)


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else Path("specification")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site/schema")
    try:
        files = publish(source, out)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"published {len(files)} schemas to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_publish_schemas.py -v`
Expected: PASS, 29 tests (the parametrized case contributes 8)

- [ ] **Step 7: Run the publisher against the real tree**

Run: `uv run python tools/publish_schemas.py specification /tmp/schema-check`
Expected: `published 44 schemas to /tmp/schema-check`

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock tools/publish_schemas.py tests/test_publish_schemas.py
git commit -m "Publish schemas to validated paths derived from their \$id

Derives each destination from the schema's own \$id rather than from
hardcoded directory names, then asserts that every \$ref inside the
namespace resolves, fragment included.

Treats \$id as untrusted input. It is a pull-request-writable string used
to build a filesystem path, and a fork's copy reaches this code on the
runner before review. An \$id tail of ../index.html overwrote the
rendered landing page in the artifact, and an absolute tail wrote
outside the output tree entirely, because pathlib discards the left
operand when the right is absolute. Both are now rejected by pattern and
by a resolved-path containment check.

Also rejects a duplicate \$id, which previously collapsed two schemas
into one published file with no error, and a draft under proposals/
claiming the normative namespace. Verifying the fragment as well as the
file catches a renamed \$defs target, which the package depends on for
its signature definition."
```

---

## Task 2: Landing page, styles, and assets

Builds the static page. Every value that varies with repository state is a placeholder that Task 3 fills and machine-checks, including the hero diagram.

**Files:**
- Create: `landing/index.html`, `landing/assets/acs.css`, `landing/assets/starburst.svg`, `landing/assets/icon.svg`, `landing/assets/fonts/`
- This task ships no tests. Its guards live in `tests/test_landing_page.py`, which Task 3 creates, because they assert properties of the **rendered** page rather than this template.

**Interfaces:**
- Consumes: nothing.
- Produces: five placeholders, spelled exactly `<!--ACS:SPEC_VERSION-->`, `<!--ACS:SCHEMA_COUNT-->`, `<!--ACS:SCHEMA_HREF-->`, `<!--ACS:WORKSTREAMS-->`, `<!--ACS:STARBURST-->`.

- [ ] **Step 1: Vendor the Inter font**

The page must contact no third party, so the font ships with the site. Inter is licensed under the SIL Open Font License 1.1, which permits redistribution.

```bash
mkdir -p landing/assets/fonts
cd landing/assets/fonts
curl -sSLO https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip
unzip -j Inter-4.1.zip 'web/InterVariable.woff2' -d .
rm Inter-4.1.zip
shasum -a 256 InterVariable.woff2 | tee CHECKSUMS.txt
```

Record the printed checksum in `CHECKSUMS.txt` and commit it alongside the font. If the download fails or the release layout has changed, stop and use the system font stack instead by deleting the `@font-face` rule in Step 2; the stack in `--acs-font` already renders the page correctly without Inter.

- [ ] **Step 2: Write the design tokens and layout**

Create `landing/assets/acs.css`. Token values come from the live site, except the five that failed a measured contrast check. Each replacement is annotated with its computed ratio.

```css
/* ACS landing page. Tokens mirror agentcontrolstandard.org, except where the source
   value failed a WCAG contrast measurement. Those five carry their ratio inline. */

@font-face {
  font-family: "Inter";
  src: url("fonts/InterVariable.woff2") format("woff2");
  font-weight: 100 900;
  font-display: swap;
}

:root {
  --acs-page: #ffffff;
  --acs-surface: #f4f5f7;
  --acs-surface-2: #eef0f4;
  --acs-text: #121212;
  --acs-text-soft: #5f636d;
  --acs-text-muted: #6b7079;
  --acs-text-inverse: #f7f7f7;
  --acs-brand: #111111;
  --acs-accent-navy: #1b4f72;
  --acs-accent-teal: #17a2b8;
  --acs-border: #e5e7eb;
  --acs-border-strong: #d0d5dd;
  --acs-footer: #111111;
  /* Was hsla(0,0%,7%,.18), which composited to #d4d4d4 for 1.48:1 against the page.
     SC 1.4.11 needs 3:1. Solid navy measures 8.72:1. */
  --acs-focus-ring: #1b4f72;
  --acs-grid-line: hsla(0, 0%, 7%, 0.04);
  --acs-node-fill: #ffffff;
  --acs-node-stroke: #6b7079;   /* 4.98:1 on the page */
  --acs-spoke: #6b7079;
  --acs-hex-fill: #f4f5f7;
  /* Was #c4cdd8 for 1.47:1 against the hexagon fill. The center of the diagram was
     close to invisible. #7d8899 measures 3.29:1. */
  --acs-hex-stroke: #7d8899;
  --acs-tier-1: #0f7b3f;
  --acs-tier-2: #1b4f72;
  --acs-tier-3: #6b46c1;
  --acs-font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --acs-mono: ui-monospace, SFMono-Regular, "JetBrains Mono", "Fira Code", monospace;
}

/* Dark tokens are redefined in two places so the toggle wins in both directions. */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --acs-page: #0a0a0a;
    --acs-surface: #161616;
    --acs-surface-2: #202020;
    --acs-text: #ffffff;
    --acs-text-soft: #9ca3af;
    /* Was #6b7280 for 3.74:1 on the surface. SC 1.4.3 needs 4.5:1. This is 5.48:1. */
    --acs-text-muted: #868e9c;
    --acs-brand: #1b4f72;
    --acs-accent-navy: #2e86c1;
    --acs-accent-teal: #1abc9c;
    --acs-border: #2a2a2a;
    --acs-border-strong: #373737;
    --acs-footer: #0a0a0a;
    /* Was hsla(0,0%,100%,.2) for 1.77:1. Solid measures 8.67:1. */
    --acs-focus-ring: #63b3ed;
    --acs-grid-line: hsla(0, 0%, 100%, 0.04);
    --acs-node-fill: #111111;
    --acs-node-stroke: #a0aec0;
    /* Was #3d4f65 for 2.36:1 against the page. This is 8.78:1. */
    --acs-spoke: #a0aec0;
    --acs-hex-fill: #0d1117;
    --acs-hex-stroke: #63b3ed;
    --acs-tier-1: #48bb78;
    --acs-tier-2: #63b3ed;
    --acs-tier-3: #805ad5;
  }
}

:root[data-theme="dark"] {
  --acs-page: #0a0a0a;
  --acs-surface: #161616;
  --acs-surface-2: #202020;
  --acs-text: #ffffff;
  --acs-text-soft: #9ca3af;
  --acs-text-muted: #868e9c;
  --acs-brand: #1b4f72;
  --acs-accent-navy: #2e86c1;
  --acs-accent-teal: #1abc9c;
  --acs-border: #2a2a2a;
  --acs-border-strong: #373737;
  --acs-footer: #0a0a0a;
  --acs-focus-ring: #63b3ed;
  --acs-grid-line: hsla(0, 0%, 100%, 0.04);
  --acs-node-fill: #111111;
  --acs-node-stroke: #a0aec0;
  --acs-spoke: #a0aec0;
  --acs-hex-fill: #0d1117;
  --acs-hex-stroke: #63b3ed;
  --acs-tier-1: #48bb78;
  --acs-tier-2: #63b3ed;
  --acs-tier-3: #805ad5;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  font-family: var(--acs-font);
  color: var(--acs-text);
  background-color: var(--acs-page);
  background-image: linear-gradient(var(--acs-grid-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--acs-grid-line) 1px, transparent 1px);
  background-size: 64px 64px;
  line-height: 1.6;
}

a { color: inherit; }
a:focus-visible,
button:focus-visible { outline: 3px solid var(--acs-focus-ring); outline-offset: 2px; }

.layout { display: grid; grid-template-columns: 260px 1fr; }

.sidebar {
  position: sticky; top: 0; align-self: start; height: 100vh;
  padding: 2rem 1.5rem; border-right: 1px solid var(--acs-border);
  display: flex; flex-direction: column; gap: 1.5rem;
}
.wordmark { font-weight: 700; letter-spacing: 0.12em; font-size: 1.1rem; text-decoration: none; }
.sidebar nav { display: flex; flex-direction: column; gap: 0.6rem; }
.sidebar nav a { text-decoration: none; color: var(--acs-text-soft); }
.sidebar nav a:hover { color: var(--acs-text); }
.sidebar h2 { font-size: 0.75rem; text-transform: uppercase; color: var(--acs-text-muted); }

main { padding: 4rem 3rem; max-width: 1100px; }
section { padding-block: 3.5rem; border-top: 1px solid var(--acs-border); }
section:first-of-type { border-top: 0; }

.hero { display: grid; grid-template-columns: 1fr 1fr; gap: 3rem; align-items: center; }
.hero h1 { font-size: clamp(2.5rem, 6vw, 4.5rem); line-height: 1.02; letter-spacing: -0.03em; margin: 0; }
.hero p { font-size: 1.15rem; color: var(--acs-text-soft); }

.cta-row { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1.5rem; }
.cta {
  display: inline-flex; align-items: center; min-height: 50px; padding: 0.85rem 1.25rem;
  border: 1px solid var(--acs-border-strong); border-radius: 999px;
  font-weight: 600; text-decoration: none;
  transition: transform 0.15s ease, background-color 0.15s ease;
}
.cta:hover { background-color: var(--acs-surface); transform: translateY(-1px); }
.cta-primary { background-color: var(--acs-brand); color: var(--acs-text-inverse); border-color: var(--acs-brand); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.25rem; }
.card { padding: 1.5rem; border: 1px solid var(--acs-border); border-radius: 14px; background-color: var(--acs-surface); }
.card h3 { margin-top: 0; }

.tier { border-left: 4px solid var(--acs-border-strong); padding-left: 1rem; margin-bottom: 1.25rem; }
.tier-1 { border-left-color: var(--acs-tier-1); }
.tier-2 { border-left-color: var(--acs-tier-2); }
.tier-3 { border-left-color: var(--acs-tier-3); }

table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--acs-border); }
code { font-family: var(--acs-mono); background-color: var(--acs-surface-2); padding: 0.15em 0.4em; border-radius: 4px; }

footer { background-color: var(--acs-footer); color: var(--acs-text-inverse); padding: 3rem; }
footer a { color: var(--acs-text-inverse); }
footer nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 1rem; }

@media (max-width: 1024px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--acs-border); }
  .hero { grid-template-columns: 1fr; }
  main { padding: 2rem 1.25rem; }
}

/* Continuous motion is a vestibular trigger and a battery cost. CSS animation is
   stopped here. The SVG's SMIL elements carry their own guard, because
   `animation: none` does not reach them. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
```

- [ ] **Step 3: Write the starburst**

Create `landing/assets/starburst.svg`. Geometry comes from the live site: a `0 0 680 680` viewBox, center `(340, 340)`, six nodes of radius 48. Node centers clockwise from top: `(340, 80)` LLM agent, `(565.17, 210)` Tool call, `(565.17, 470)` Output guard, `(340, 600)` Sub agent, `(114.83, 470)` Memory store, `(114.83, 210)` Code exec.

SMIL animation ignores `animation: none`, so each animating element carries `systemLanguage`-independent guards through a CSS rule that sets `visibility` on a wrapper is not reliable either. The dependable approach is to gate the animation elements themselves with a media query in an internal stylesheet, which SVG honours.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 680 680" fill="none"
     class="starburst" role="img"
     aria-label="Six agent decision points routed through a central ACS control panel">
  <style>
    /* SMIL does not respond to `animation: none`. Disabling the elements is what works. */
    @media (prefers-reduced-motion: reduce) {
      animate, animateMotion, animateTransform { display: none; }
    }
  </style>
  <defs>
    <radialGradient id="acs-glow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="currentColor" stop-opacity="0.15"/>
      <stop offset="100%" stop-color="currentColor" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <circle cx="340" cy="340" r="150" fill="url(#acs-glow)" color="var(--acs-hex-stroke)">
    <animate attributeName="r" values="140;170;140" dur="8s" repeatCount="indefinite"/>
  </circle>

  <!-- Orbit rings expand outward on an eight second cycle, offset by half. -->
  <circle cx="340" cy="340" r="60" fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0">
    <animate attributeName="r" values="60;240" dur="8s" begin="0s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.2;0" dur="8s" begin="0s" repeatCount="indefinite"/>
  </circle>
  <circle cx="340" cy="340" r="60" fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0">
    <animate attributeName="r" values="60;240" dur="8s" begin="4s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.2;0" dur="8s" begin="4s" repeatCount="indefinite"/>
  </circle>

  <!-- One group per node: a dashed quadratic spoke, a particle traveling it, the node,
       and a two-line label. Particle begin times stagger by 1.5s so traffic reads as
       continuous rather than synchronized. -->
  <g>
    <path d="M340,340 Q356,197 340,80" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5s" begin="0s" repeatCount="indefinite" path="M340,340 Q356,197 340,80"/>
    </circle>
    <circle cx="340" cy="80" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="340" y="75" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">LLM</text>
    <text x="340" y="96" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">agent</text>
  </g>
  <g>
    <path d="M340,340 Q471.84,282.36 565.17,210" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.3s" begin="1.5s" repeatCount="indefinite" path="M340,340 Q471.84,282.36 565.17,210"/>
    </circle>
    <circle cx="565.17" cy="210" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="565.17" y="205" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Tool</text>
    <text x="565.17" y="226" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">call</text>
  </g>
  <g>
    <path d="M340,340 Q455.84,425.36 565.17,470" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.6s" begin="3s" repeatCount="indefinite" path="M340,340 Q455.84,425.36 565.17,470"/>
    </circle>
    <circle cx="565.17" cy="470" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="565.17" y="465" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Output</text>
    <text x="565.17" y="486" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">guard</text>
  </g>
  <g>
    <path d="M340,340 Q324,483 340,600" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.9s" begin="4.5s" repeatCount="indefinite" path="M340,340 Q324,483 340,600"/>
    </circle>
    <circle cx="340" cy="600" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="340" y="595" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Sub</text>
    <text x="340" y="616" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">agent</text>
  </g>
  <g>
    <path d="M340,340 Q208.16,397.64 114.83,470" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="6.2s" begin="6s" repeatCount="indefinite" path="M340,340 Q208.16,397.64 114.83,470"/>
    </circle>
    <circle cx="114.83" cy="470" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="114.83" y="465" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Memory</text>
    <text x="114.83" y="486" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">store</text>
  </g>
  <g>
    <path d="M340,340 Q224.16,254.64 114.83,210" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="6.5s" begin="7.5s" repeatCount="indefinite" path="M340,340 Q224.16,254.64 114.83,210"/>
    </circle>
    <circle cx="114.83" cy="210" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2"/>
    <text x="114.83" y="205" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Code</text>
    <text x="114.83" y="226" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">exec</text>
  </g>

  <g>
    <polygon points="340,272 398.89,306 398.89,374 340,408 281.11,374 281.11,306"
             fill="var(--acs-hex-fill)" stroke="var(--acs-hex-stroke)" stroke-width="2"/>
    <polygon points="340,291.04 382.4,315.52 382.4,364.48 340,388.96 297.6,364.48 297.6,315.52"
             fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0.4"/>
    <text x="340" y="326" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">ACS</text>
    <text x="340" y="346" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">control</text>
    <text x="340" y="366" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">panel</text>
  </g>
</svg>
```

- [ ] **Step 4: Write the favicon**

Create `landing/assets/icon.svg`, matching the live site's mark:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
  <rect width="32" height="32" rx="6" fill="#1B4F72"/>
  <text x="16" y="21.5" text-anchor="middle" font-family="Inter, system-ui, sans-serif"
        font-size="12" font-weight="700" letter-spacing="0.5" fill="#FFFFFF">ACS</text>
</svg>
```

- [ ] **Step 5: Write the page**

Create `landing/index.html`. The title carries no em dash. The contact list separates general contact from vulnerability reporting so the routing in `SECURITY.md` and `CODE_OF_CONDUCT.md` survives, and the footer links every governing document.

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACS Agent Control Standard</title>
<meta name="description" content="The open standard for runtime agent control. Declarative hooks, policy enforcement, and observability across AI agent frameworks.">
<link rel="icon" href="assets/icon.svg">
<link rel="stylesheet" href="assets/acs.css">
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <a class="wordmark" href=".">ACS</a>
    <nav aria-label="Sections">
      <a href="#problem">The problem</a>
      <a href="#solution">The solution</a>
      <a href="#architecture">How it works</a>
      <a href="#why-now">Why now</a>
      <a href="#status">Spec status</a>
      <a href="#workstreams">Workstreams</a>
      <a href="#contribute">Contribute</a>
    </nav>
    <div>
      <h2>External resources</h2>
      <nav aria-label="External resources">
        <a href="docs/">Specification</a>
        <a href="https://github.com/GenAI-Security-Project/agent-control-standard">GitHub</a>
        <a href="https://owasp.slack.com">Slack</a>
      </nav>
    </div>
    <button id="theme-toggle" type="button">Switch theme</button>
  </aside>

  <main>
    <section class="hero">
      <div>
        <h1>The runtime control plane for AI agents.</h1>
        <p>Agent Control Standard (ACS) is the open standard that defines how agent
        platforms expose middleware hooks and how open-source tooling enforces safety
        policy through those hooks. Declarative controls. Portable across frameworks.
        Enforced at runtime.</p>
        <div class="cta-row">
          <a class="cta cta-primary" href="docs/">Read the specification</a>
          <a class="cta" href="https://github.com/GenAI-Security-Project/agent-control-standard">View on GitHub</a>
          <a class="cta" href="https://owasp.slack.com">Join the conversation</a>
        </div>
      </div>
      <div><!--ACS:STARBURST--></div>
    </section>

    <section id="problem">
      <h2>Agents are shipping fast. Controls are not</h2>
      <p>AI agents act across organizational boundaries. The industry standardized how
      agents communicate through MCP and A2A, and documented the risks through the OWASP
      Agentic Top 10. Runtime control never got the same treatment.</p>
      <ul>
        <li>System prompts are not controls.</li>
        <li>Model improvements do not cover edge cases or adversarial inputs.</li>
        <li>Proprietary guardrails create vendor lock-in.</li>
      </ul>
    </section>

    <section id="solution">
      <h2>Three layers, one standard</h2>
      <div class="cards">
        <div class="card">
          <h3>Instrument</h3>
          <p>ACS defines standardized middleware hooks at every agent decision point. A
          Guardian Agent intercepts the action and returns a verdict: allow, deny, or
          modify.</p>
        </div>
        <div class="card">
          <h3>Trace</h3>
          <p>Agents emit structured trace data through OpenTelemetry, the pipeline your
          teams already run. ACS maps those traces to OCSF so security events land in the
          SIEM without a custom parser.</p>
        </div>
        <div class="card">
          <h3>Inspect</h3>
          <p>Enterprises cannot secure what they cannot inventory. AgBOM captures tools,
          models, and dependencies as the agent acquires them, which a static SBOM cannot
          do.</p>
        </div>
      </div>
    </section>

    <section id="architecture">
      <h2>How it works</h2>
      <div class="tier tier-1">
        <h3>Tier 1: Platform layer</h3>
        <p>Agent frameworks expose standardized middleware hooks.</p>
      </div>
      <div class="tier tier-2">
        <h3>Tier 2: Enforcement layer</h3>
        <p>An open-source SDK reads declarative policy and returns verdicts through those hooks.</p>
      </div>
      <div class="tier tier-3">
        <h3>Tier 3: Enterprise layer</h3>
        <p>Custom classifiers and domain-specific logic plug in behind the same interface.</p>
      </div>
    </section>

    <section id="why-now">
      <h2>Why now</h2>
      <p>The EU AI Act requires high-risk AI systems to be designed for effective human
      oversight, including the ability for a person to intervene in or interrupt the
      system (<a href="https://eur-lex.europa.eu/eli/reg/2024/1689/oj">Regulation (EU)
      2024/1689</a>, Article 14). The NIST AI Risk Management Framework, which is
      voluntary guidance rather than regulation, describes continuous monitoring and the
      ability to deactivate systems operating outside intended limits
      (<a href="https://doi.org/10.6028/NIST.AI.100-1">NIST AI 100-1</a>, MANAGE 2.4).</p>
      <p>Both describe controls that exist at runtime. Neither is satisfied by a system
      prompt.</p>
    </section>

    <section id="built-with">
      <h2>Built with the community</h2>
      <p>OWASP ASI, AIVSS, OpenTelemetry, CycloneDX, SPDX, MCP, and A2A.</p>
    </section>

    <section id="status">
      <h2>Spec status</h2>
      <table>
        <tbody>
          <tr><th>Specification version</th><td><code><!--ACS:SPEC_VERSION--></code></td></tr>
          <tr><th>Published schemas</th><td><!--ACS:SCHEMA_COUNT--></td></tr>
        </tbody>
      </table>
      <p>Every schema resolves at the URI its <code>$id</code> declares. Start at
      <a href="<!--ACS:SCHEMA_HREF-->">the root schema</a>.</p>
    </section>

    <section id="workstreams">
      <h2>Workstreams</h2>
      <p>Each workstream owns a slice of the standard and runs its own review.</p>
      <table>
        <thead><tr><th>Workstream</th><th>Leads</th></tr></thead>
        <tbody><!--ACS:WORKSTREAMS--></tbody>
      </table>
    </section>

    <section id="contribute">
      <h2>Contribute</h2>
      <p>ACS is an open specification. The fastest way to shape it is to use it and tell
      us what breaks.</p>
      <ul>
        <li>Join <a href="https://owasp.slack.com">owasp.slack.com</a> and the
        <code>#team-genai-asi-acs-general</code> channel.</li>
        <li>Open an issue or a discussion on
        <a href="https://github.com/GenAI-Security-Project/agent-control-standard">GitHub</a>.</li>
        <li>General questions about the project:
        <a href="mailto:rock.lambros@owasp.org">rock.lambros@owasp.org</a></li>
      </ul>
      <h3>Reporting a problem</h3>
      <p>Report a security vulnerability through
      <a href="https://github.com/GenAI-Security-Project/agent-control-standard/security/advisories/new">GitHub
      private vulnerability reporting</a>, which is the channel our
      <a href="https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/SECURITY.md">security
      policy</a> covers. Report a Code of Conduct concern through the
      <a href="https://owasp.org/www-policy/operational/code-of-conduct">OWASP Code of
      Conduct process</a>, which handles reports independently of this project's
      maintainers.</p>
    </section>
  </main>
</div>

<footer>
  <p>Copyright 2025-2026 The OWASP GenAI Security Project and the ACS contributors.
  Specification and code licensed under
  <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License 2.0</a>.
  Documentation licensed under
  <a href="https://creativecommons.org/licenses/by-sa/4.0/">CC BY-SA 4.0</a>.</p>
  <p>ACS is vendor neutral and community governed. A project of the OWASP GenAI Security
  Project.</p>
  <nav aria-label="Project documents">
    <a href="https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/GOVERNANCE.md">Governance</a>
    <a href="https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/SECURITY.md">Security</a>
    <a href="https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CODE_OF_CONDUCT.md">Code of Conduct</a>
    <a href="https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/LICENSING.md">Licensing</a>
  </nav>
</footer>

<script>
  // Theme toggle. The page renders correctly without this. It only overrides the
  // system preference and remembers the override.
  (function () {
    var root = document.documentElement;
    try {
      var saved = localStorage.getItem("acs-theme");
      if (saved) root.setAttribute("data-theme", saved);
    } catch (e) { /* private mode blocks storage, so the system preference still applies */ }
    document.getElementById("theme-toggle").addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("acs-theme", next); } catch (e) { /* ignore */ }
    });
  })();
</script>
</body>
</html>
```

- [ ] **Step 6: Commit**

```bash
git add landing/
git commit -m "Add the landing page, its design tokens, and the starburst diagram

Tokens mirror agentcontrolstandard.org, except five that failed a
measured contrast check and are annotated with their computed ratios.
The focus ring was a translucent overlay compositing to 1.48:1 against
the page where WCAG SC 1.4.11 requires 3:1, and the hexagon stroke at
the center of the diagram measured 1.47:1 against its own fill.

The hero is a machine-filled placeholder rather than a hand-applied
paste, so the renderer's placeholder check covers it. Inter ships with
the site so the page contacts no third party, which is the same
reasoning that removed analytics.

The contact section separates general questions from vulnerability
reporting and Code of Conduct reports, so publishing an address does not
route those away from the channels that handle them independently."
```

---

## Task 3: Build-time content injection and page guards

Fills placeholders from repository state, escapes untrusted content, and runs the page guards against the **rendered** output rather than the template.

**Files:**
- Create: `tools/render_landing.py`, `tests/test_render_landing.py`, `tests/test_landing_page.py`

**Interfaces:**
- Consumes: `publish_schemas.load_schemas`, `publish_schemas.target_for`, `publish_schemas.SchemaError`, and the five placeholders from Task 2.
- Produces: `class RenderError(Exception)`; `REQUIRED_PLACEHOLDERS: tuple[str, ...]`; `spec_version(source)`; `schema_count(source)`; `parse_workstreams(text)`; `render_workstreams(rows)`; `render(template, source, governance, starburst)`. CLI: `python tools/render_landing.py <landing_dir> <out_dir>`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_render_landing.py`:

```python
"""Tests for build-time content injection.

GOVERNANCE.md reaches an HTML attribute position, so the escaping cases are the point.
A roster pull request is reviewed for names and handles, not for quoting.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE
from render_landing import (
    RenderError, parse_workstreams, render, render_workstreams, schema_count, spec_version,
)

REPO = Path(__file__).resolve().parents[1]

GOVERNANCE = """# Governance

## Project lead

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |

## Workstream leads

Prose that must not be parsed as a row.

| Workstream | Leads |
| --- | --- |
| Identity | Eva Benn ([@evabenn](https://github.com/evabenn)) |
| Spec | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)) |

## Origins

Not a workstream.
"""

FULL_TEMPLATE = (
    "<!--ACS:SPEC_VERSION--><!--ACS:SCHEMA_COUNT--><!--ACS:SCHEMA_HREF-->"
    "<tbody><!--ACS:WORKSTREAMS--></tbody><div><!--ACS:STARBURST--></div>"
)


@pytest.fixture
def spec_tree(tmp_path: Path) -> Path:
    root = tmp_path / "specification"
    (root / "v0.1.0").mkdir(parents=True)
    for name in ("a.json", "b.json"):
        (root / "v0.1.0" / name).write_text(
            json.dumps({"$id": BASE + f"v0.1.0/{name}"}), encoding="utf-8")
    return root


def test_spec_version_reads_the_id_namespace(spec_tree):
    assert spec_version(spec_tree) == "v0.1.0"


def test_schema_count_counts_every_schema(spec_tree):
    assert schema_count(spec_tree) == 2


def test_spec_version_returns_the_highest_of_several(tmp_path):
    """Old versions stay published, so more than one is the steady state."""
    root = tmp_path / "specification"
    root.mkdir()
    for version in ("v0.1.0", "v0.2.0", "v0.10.0"):
        (root / f"{version}.json").write_text(
            json.dumps({"$id": BASE + f"{version}/x.json"}), encoding="utf-8")
    assert spec_version(root) == "v0.10.0"


# --- governance parsing ---------------------------------------------------

def test_parse_workstreams_reads_only_the_workstream_table():
    assert [name for name, _ in parse_workstreams(GOVERNANCE)] == ["Identity", "Spec"]


def test_parse_workstreams_accepts_heading_case_and_spacing():
    """A formatter or a title-case edit must not take the site down."""
    for heading in ("## Workstream Leads", "## Workstream leads ", "##  Workstream leads"):
        text = GOVERNANCE.replace("## Workstream leads", heading)
        assert len(parse_workstreams(text)) == 2


def test_parse_workstreams_stops_at_any_heading_level():
    text = GOVERNANCE.replace("## Origins", "### Emeritus\n\n| Old | Thing |\n| --- | --- |\n| A | B |\n\n## Origins")
    assert [name for name, _ in parse_workstreams(text)] == ["Identity", "Spec"]


def test_parse_workstreams_keeps_an_escaped_pipe():
    text = GOVERNANCE.replace("| Identity |", r"| Identity \| IAM |")
    assert [name for name, _ in parse_workstreams(text)] == ["Identity | IAM", "Spec"]


def test_parse_workstreams_raises_on_a_wrong_width_row():
    """A silently dropped workstream is worse than a loud failure."""
    text = GOVERNANCE.replace("| Spec |", "| Spec | extra |")
    with pytest.raises(RenderError, match="cells"):
        parse_workstreams(text)


def test_parse_workstreams_fails_without_the_section():
    with pytest.raises(RenderError, match="Workstream leads"):
        parse_workstreams("# Governance\n\nNothing here.\n")


def test_parse_workstreams_handles_the_real_file():
    assert len(parse_workstreams((REPO / "GOVERNANCE.md").read_text(encoding="utf-8"))) == 5


# --- escaping -------------------------------------------------------------

def test_render_workstreams_converts_markdown_links_to_html():
    html = render_workstreams([("Identity", "Eva Benn ([@evabenn](https://example.com))")])
    assert '<a href="https://example.com">@evabenn</a>' in html


def parse_attributes(markup: str) -> list[tuple[str, list[tuple[str, str | None]]]]:
    """Return (tag, attributes) for every start tag.

    String matching is the wrong tool here. A safely escaped payload still contains the
    literal text `onfocus=` inside an attribute value, so grepping for it reports a
    breakout that does not exist. Only a parser answers whether an attribute is real.
    """
    from html.parser import HTMLParser

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, attrs))

    collector = Collector()
    collector.feed(markup)
    return collector.tags


def test_render_workstreams_blocks_attribute_breakout():
    html = render_workstreams([("X", '[@ok](https://x" autofocus onfocus="alert(1))')])
    attributes = [name for _, attrs in parse_attributes(html) for name, _ in attrs]
    assert not [name for name in attributes if name.startswith("on")]
    assert "autofocus" not in attributes
    # The quote survives as an entity inside the value rather than as a delimiter.
    assert "&quot;" in html


def test_render_workstreams_drops_a_javascript_scheme():
    html = render_workstreams([("X", "[@x](javascript:alert(1))")])
    assert "javascript:" not in html
    assert "@x" in html  # the label survives, the link does not


def test_render_workstreams_escapes_raw_html():
    html = render_workstreams([("<script>alert(1)</script>", "safe")])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --- placeholders ---------------------------------------------------------

def test_render_fills_every_placeholder(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, GOVERNANCE, "<svg id='sb'/>")
    assert "v0.1.0" in out and "Identity" in out and "<svg id='sb'/>" in out


def test_render_derives_the_schema_href_from_the_version(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, GOVERNANCE, "<svg/>")
    assert "schema/v0.1.0/acs_schema.json" in out


def test_render_fails_when_the_template_drops_a_placeholder(spec_tree):
    """A template missing the hero would otherwise ship a blank div with no error."""
    without = FULL_TEMPLATE.replace("<!--ACS:STARBURST-->", "")
    with pytest.raises(RenderError, match="STARBURST"):
        render(without, spec_tree, GOVERNANCE, "<svg/>")


def test_render_fails_when_an_unknown_placeholder_survives(spec_tree):
    with pytest.raises(RenderError, match="unfilled placeholder"):
        render(FULL_TEMPLATE + "<!--ACS:UNKNOWN-->", spec_tree, GOVERNANCE, "<svg/>")
```

Create `tests/test_landing_page.py`. Every guard runs against the rendered page, because the injected content is the half no human reviews:

```python
"""Content guards on the page that ships.

These run against render() output, not the template. The template is hand-reviewed;
the injected sections are not.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from render_landing import render

REPO = Path(__file__).resolve().parents[1]
LANDING = REPO / "landing"


@pytest.fixture(scope="module")
def page() -> str:
    return render(
        (LANDING / "index.html").read_text(encoding="utf-8"),
        REPO / "specification",
        (REPO / "GOVERNANCE.md").read_text(encoding="utf-8"),
        (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8"),
    )


def test_the_hero_diagram_is_present(page):
    assert "<svg" in page
    for label in ["LLM", "Tool", "Output", "Sub", "Memory", "Code", "ACS"]:
        assert label in page


def test_no_root_relative_links(page):
    """A project Pages site serves from /agent-control-standard/, so /docs/ would 404."""
    assert not re.search(r"""(href|src)\s*=\s*['"]/(?!/)""", page)


def test_no_retired_project_links(page):
    assert "aos.owasp.org" not in page


def test_the_only_email_is_the_approved_one(page):
    found = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page))
    assert found == {"rock.lambros@owasp.org"}


def test_no_third_party_origin(page):
    """The page must contact nothing. Same reasoning that removed analytics."""
    hosts = set(re.findall(r"""(?:href|src)\s*=\s*['"]https?://([^/'"]+)""", page))
    allowed = {"github.com", "owasp.slack.com", "owasp.org", "www.apache.org",
               "creativecommons.org", "eur-lex.europa.eu", "doi.org"}
    assert hosts <= allowed, f"unexpected origins: {hosts - allowed}"


def test_no_inline_event_handlers(page):
    """Parsed, not grepped. An escaped payload contains the text `onfocus=` inside an
    attribute value while being entirely inert, so a regex reports a false positive."""
    from html.parser import HTMLParser

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.handlers: list[str] = []
            self.schemes: list[str] = []

        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if name.startswith("on"):
                    self.handlers.append(f"<{tag} {name}>")
                if name in ("href", "src") and value and value.lower().startswith("javascript:"):
                    self.schemes.append(f"<{tag} {name}={value[:40]}>")

    collector = Collector()
    collector.feed(page)
    assert not collector.handlers, collector.handlers
    assert not collector.schemes, collector.schemes


def test_no_em_dash(page):
    assert "—" not in page


def test_the_title_has_no_em_dash_and_is_present(page):
    match = re.search(r"<title>(.*?)</title>", page)
    assert match and "—" not in match.group(1)


def test_footer_links_the_governing_documents(page):
    for doc in ["GOVERNANCE.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSING.md"]:
        assert doc in page


def test_license_names_are_linked(page):
    assert "apache.org/licenses/LICENSE-2.0" in page
    assert "creativecommons.org/licenses/by-sa/4.0" in page


def test_dark_theme_and_reduced_motion_are_defined():
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")
    assert 'data-theme="dark"' in css
    assert "prefers-color-scheme: dark" in css
    assert "prefers-reduced-motion: reduce" in css
    svg = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    # `animation: none` does not reach SMIL, so the SVG carries its own guard.
    assert "prefers-reduced-motion: reduce" in svg


def test_focus_ring_and_muted_text_meet_contrast():
    """Encodes the measurements that four inherited token values failed."""
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")

    def luminance(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        channels = []
        for i in (0, 2, 4):
            c = int(h[i : i + 2], 16) / 255
            channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    def ratio(a: str, b: str) -> float:
        la, lb = luminance(a), luminance(b)
        hi, lo = max(la, lb), min(la, lb)
        return (hi + 0.05) / (lo + 0.05)

    def token(name: str, block: str) -> str:
        section = css.split(block, 1)[1]
        return re.search(rf"{name}:\s*(#[0-9a-fA-F]{{6}})", section).group(1)

    light_ring = token("--acs-focus-ring", ":root {")
    assert ratio(light_ring, "#ffffff") >= 3.0
    dark_ring = token("--acs-focus-ring", ':root[data-theme="dark"]')
    assert ratio(dark_ring, "#0a0a0a") >= 3.0
    dark_muted = token("--acs-text-muted", ':root[data-theme="dark"]')
    assert ratio(dark_muted, "#161616") >= 4.5
    light_hex = token("--acs-hex-stroke", ":root {")
    assert ratio(light_hex, "#f4f5f7") >= 3.0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_render_landing.py tests/test_landing_page.py -v`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'render_landing'`

- [ ] **Step 3: Write the implementation**

Create `tools/render_landing.py`:

```python
#!/usr/bin/env python3
"""Fill the landing page's placeholders from repository state.

Injection happens at build time, so the published page stays static and renders with
JavaScript disabled.

GOVERNANCE.md is a build input and its contents reach an HTML attribute position. Treat
every value from it as untrusted text, because a roster pull request is reviewed for
names and handles rather than for quoting.
"""
from __future__ import annotations

import html
import re
import shutil
import sys
from pathlib import Path

from publish_schemas import SchemaError, load_schemas, target_for

# Tolerant of case and spacing so a formatter cannot break the build.
WORKSTREAM_HEADING = re.compile(r"^##\s+workstream\s+leads\s*$", re.IGNORECASE)
ANY_HEADING = re.compile(r"^#{2,6}\s")
MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
PLACEHOLDER = re.compile(r"<!--ACS:[A-Z_]+-->")
SPLIT_CELLS = re.compile(r"(?<!\\)\|")
ALLOWED_SCHEMES = ("https://", "http://", "mailto:")

REQUIRED_PLACEHOLDERS = (
    "<!--ACS:SPEC_VERSION-->",
    "<!--ACS:SCHEMA_COUNT-->",
    "<!--ACS:SCHEMA_HREF-->",
    "<!--ACS:WORKSTREAMS-->",
    "<!--ACS:STARBURST-->",
)


class RenderError(Exception):
    """Repository state does not supply what the template asks for."""


def _versions(source: Path) -> set[str]:
    try:
        docs = load_schemas(source)
        return {target_for(doc, path).split("/")[0] for path, doc in docs.items()}
    except SchemaError as error:
        raise RenderError(str(error)) from error


def spec_version(source: Path) -> str:
    """Return the highest spec version present.

    Old versions stay published so their $id URIs keep resolving, so more than one
    version is the expected steady state rather than an error.
    """
    versions = _versions(source)
    if not versions:
        raise RenderError(f"no schemas found under {source}")
    return max(versions, key=lambda v: tuple(int(p) for p in v.lstrip("v").split(".")))


def schema_count(source: Path) -> int:
    try:
        return len(load_schemas(source))
    except SchemaError as error:
        raise RenderError(str(error)) from error


def parse_workstreams(text: str) -> list[tuple[str, str]]:
    """Read the two-column table under the Workstream leads heading."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if WORKSTREAM_HEADING.match(line)), None)
    if start is None:
        raise RenderError("GOVERNANCE.md: no '## Workstream leads' section")

    rows: list[tuple[str, str]] = []
    table_lines = 0
    for line in lines[start + 1 :]:
        if ANY_HEADING.match(line):
            break  # any heading level ends the section, not only level two
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        table_lines += 1
        cells = [cell.strip() for cell in SPLIT_CELLS.split(stripped.strip("|"))]
        if cells[0].lower() == "workstream" or set(cells[0]) <= set("-: "):
            continue
        if len(cells) != 2:
            raise RenderError(
                f"GOVERNANCE.md: workstream row has {len(cells)} cells, expected 2: {stripped!r}"
            )
        rows.append((cells[0].replace("\\|", "|"), cells[1].replace("\\|", "|")))

    if not rows:
        raise RenderError("GOVERNANCE.md: the workstream table is empty")
    # A silently dropped row is worse than a loud failure, so account for every line.
    if len(rows) != table_lines - 2:
        raise RenderError(
            f"GOVERNANCE.md: parsed {len(rows)} workstreams from {table_lines} table lines. "
            "Expected a header, a separator, then one line per workstream."
        )
    return rows


def _to_html(markdown: str) -> str:
    """Escape everything, then rebuild links from an allowlisted scheme."""

    def link(match: re.Match[str]) -> str:
        label, url = match.group(1), match.group(2)
        if not url.startswith(ALLOWED_SCHEMES):
            return label  # drop the link, keep the text
        return f'<a href="{url}">{label}</a>'

    # quote=True so a quote in the source cannot break out of the href attribute.
    return MD_LINK.sub(link, html.escape(markdown, quote=True))


def render_workstreams(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f"<tr><td>{_to_html(name)}</td><td>{_to_html(leads)}</td></tr>" for name, leads in rows
    )


def render(template: str, source: Path, governance: str, starburst: str) -> str:
    """Replace every placeholder. Fail if one is missing from the template or survives it.

    Both directions matter. A surviving token means the renderer did not know about it.
    A missing token means the template dropped a section, which would otherwise ship a
    page with a blank hero and no error anywhere.
    """
    missing = [token for token in REQUIRED_PLACEHOLDERS if token not in template]
    if missing:
        raise RenderError(f"template is missing placeholder: {', '.join(missing)}")

    version = spec_version(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(schema_count(source)))
    out = out.replace("<!--ACS:SCHEMA_HREF-->", html.escape(f"schema/{version}/acs_schema.json"))
    out = out.replace("<!--ACS:WORKSTREAMS-->", render_workstreams(parse_workstreams(governance)))
    # Inlining is required: an SVG loaded through <img> cannot read the page's CSS
    # custom properties, so the diagram would ignore the theme.
    out = out.replace("<!--ACS:STARBURST-->", starburst)

    survivors = PLACEHOLDER.findall(out)
    if survivors:
        raise RenderError(f"unfilled placeholder: {', '.join(sorted(set(survivors)))}")
    return out


def main(argv: list[str]) -> int:
    landing = Path(argv[1]) if len(argv) > 1 else Path("landing")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site")
    repo = Path(__file__).resolve().parents[1]
    try:
        page = render(
            (landing / "index.html").read_text(encoding="utf-8"),
            repo / "specification",
            (repo / "GOVERNANCE.md").read_text(encoding="utf-8"),
            (landing / "assets" / "starburst.svg").read_text(encoding="utf-8"),
        )
    except (RenderError, SchemaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"error: cannot read a landing page source: {error}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page, encoding="utf-8")
    shutil.copytree(landing / "assets", out / "assets", dirs_exist_ok=True)
    print(f"rendered landing page to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_render_landing.py tests/test_landing_page.py -v`
Expected: PASS, 30 tests

- [ ] **Step 5: Render the page and check it by eye**

Run: `uv run python tools/render_landing.py landing /tmp/landing-check && open /tmp/landing-check/index.html`
Expected: the hero diagram renders, the status table shows `v0.1.0` and `44`, five workstream rows appear. Toggle the theme and confirm the diagram follows it. Tab through the page and confirm the focus ring is clearly visible in both themes.

- [ ] **Step 6: Commit**

```bash
git add tools/render_landing.py tests/test_render_landing.py tests/test_landing_page.py
git commit -m "Inject page content at build time and guard the rendered output

Reads the version from the schema \$id namespace and the roster from
GOVERNANCE.md, so neither can drift. The hero diagram is injected the
same way, because a hand-applied paste was invisible to the placeholder
check and shipped a blank hero with a green suite.

Escapes GOVERNANCE.md content with quote=True and rebuilds links only
from an allowlisted scheme. The previous quote=False left a double quote
intact while interpolating the URL into an href attribute, so a roster
row could add an event handler or a javascript: target to the published
page.

The parser now tolerates heading case and spacing, keeps escaped pipes,
stops at any heading level, and fails loudly on a wrong-width row rather
than dropping a workstream in silence.

Page guards now run against render() output. Running them against the
template left the injected sections, the only part no human reviews,
outside every check."
```

---

## Task 4: Site configuration

Removes every third-party request from the documentation site.

The gate that runs these tests is Task 5's `test` job, which `build` depends on. Writing a test is not a control and running it on every pull request is, so this task supplies the guard and Task 5 supplies the enforcement.

**Files:**
- Modify: `mkdocs.yml`, `.gitignore`
- Create: `tests/test_site_config.py`

`pyproject.toml` already carries the `dev` dependency group from Task 1. It needs no change here.

- [ ] **Step 1: Write the failing test**

Create `tests/test_site_config.py`:

```python
"""Regression guard on the built documentation site.

Verified before this change: with GOOGLE_ANALYTICS_KEY empty, and also with the variable
unset entirely, Material emitted <script src=".../gtag/js?id=">. No env value suppressed
it, so the analytics block had to be removed. Removing it alone was not enough: the theme
also fetched Roboto from fonts.googleapis.com on all 37 pages.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Anchor links are prose and fetch nothing. Only resource loads reach a third party,
# so the guard matches loading constructs rather than every href on the page.
RESOURCE_TAG = re.compile(
    r"""<(?:script|link|img|iframe|source|audio|video|embed|object)\b[^>]*?"""
    r"""(?:src|href|data)\s*=\s*['"](?:https?:)?//([^/'"]+)""",
    re.I,
)
IMPORT_RULE = re.compile(r"""@import\s+(?:url\()?['"]?(?:https?:)?//([^/'"]+)""", re.I)

# The canonical URL the test build is given. Anything else is a third party.
SELF_HOSTS = {"example.org"}


@pytest.fixture(scope="module")
def built_site(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site")
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = "https://example.org/"
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


def test_mkdocs_config_declares_no_analytics():
    assert "analytics" not in (REPO / "mkdocs.yml").read_text(encoding="utf-8")


def test_mkdocs_config_disables_theme_fonts():
    """Material fetches Roboto from Google unless font is false."""
    assert re.search(r"^\s*font:\s*false\s*$", (REPO / "mkdocs.yml").read_text(encoding="utf-8"), re.M)


def test_built_site_loads_nothing_from_google(built_site):
    for page in built_site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        assert "googletagmanager" not in text
        assert "fonts.googleapis.com" not in text
        assert "fonts.gstatic.com" not in text


def test_built_site_loads_no_third_party_resource(built_site):
    """The site must fetch nothing it does not serve itself.

    Measured before this guard existed: the built site had zero third-party resource
    loads once analytics and theme fonts were off. An empty result is the correct
    result, so any host appearing here is a regression.
    """
    offenders: dict[str, str] = {}
    for page in built_site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        for match in list(RESOURCE_TAG.finditer(text)) + list(IMPORT_RULE.finditer(text)):
            host = match.group(1)
            if host not in SELF_HOSTS:
                offenders.setdefault(host, page.name)
    assert not offenders, f"third-party resource loads: {offenders}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_site_config.py -v`
Expected: FAIL on all four tests.

- [ ] **Step 3: Remove analytics and the theme fonts**

In `mkdocs.yml`, delete these four lines from the `extra:` block:

```yaml
  analytics:
    provider: google
    property: !ENV GOOGLE_ANALYTICS_KEY
```

Then replace the `font:` block under `theme:`:

```yaml
  font: false
```

Verified: `material/templates/base.html:65` guards the font links with
`{% if config.theme.font != false %}`, and a build with both changes produced zero
`googletagmanager` and zero `fonts.googleapis` references across all 37 pages.

- [ ] **Step 4: Ignore local build output**

Append to `.gitignore`:

```gitignore
_site/
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest -v`
Expected: PASS, 63 tests

- [ ] **Step 6: Commit**

```bash
git add mkdocs.yml .gitignore tests/test_site_config.py
git commit -m "Stop the documentation site contacting Google

Material emits a googletagmanager script tag whenever the analytics
block exists, including when GOOGLE_ANALYTICS_KEY is unset entirely, and
separately fetches Roboto from fonts.googleapis.com on every page.
Publishing as configured would have sent two third-party requests
carrying the referrer and client IP of every documentation reader, one
of them for no analytics data at all.

No environment value suppresses either, so the analytics block is gone
and theme fonts are off. The guard now asserts that no page fetches an
unexpected origin, rather than grepping for one vendor string."
```

---

## Task 5: Workflows

Runs the guards as a merge gate, builds the artifact, deploys only from `main`, and verifies the published bytes rather than a status code.

**Files:**
- Create: `.github/workflows/deploy-pages.yml`, `.github/workflows/monitor-pages.yml`, `tools/verify_published.py`

- [ ] **Step 1: Write the verifier**

Create `tools/verify_published.py`. A separate script keeps `${{ }}` out of `run:` and makes the check testable:

```python
#!/usr/bin/env python3
"""Assert that the deployed site serves each schema at the URI its $id declares.

A status code is not the property worth checking. A traversal that overwrites the root
schema still returns 200, and so does a truncated or stale document.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

# Pages fronts content through a CDN, so a fresh deployment can 404 briefly. curl's
# --retry does not cover a 404, which is why this polls explicitly.
ATTEMPTS = 6
DELAY_SECONDS = 10


def fetch(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            time.sleep(DELAY_SECONDS)
            continue
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: verify_published.py <base-url> <path> [<path> ...]", file=sys.stderr)
        return 2
    for path in argv[2:]:
        check(argv[1], path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 2: Write the deploy workflow**

Create `.github/workflows/deploy-pages.yml`:

```yaml
# Builds and publishes the landing page, the documentation site, and the JSON schemas.
# Pull requests test and build without deploying. Merge to main publishes with no human
# in the loop, so every guard runs here rather than on a contributor's laptop.
name: Deploy Pages

on:
  push:
    branches: ["main"]
  pull_request:
  workflow_dispatch:

# Deny by default. Each job grants itself only what it needs.
permissions: {}

# One group for every deploy so they serialize on the single Pages site they share.
# Pull request builds group per ref and cancel stale runs. Keying everything on ref
# would let a dispatch on a branch deploy alongside a push to main.
concurrency:
  group: pages-${{ github.event_name == 'pull_request' && github.ref || 'deploy' }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install uv
        uses: astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0
        with:
          version: "0.9.9"

      - name: Install dependencies from the lockfile
        run: uv sync --locked

      - name: Run the guards
        run: uv run pytest -v

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # configure-pages calls GET /repos/{owner}/{repo}/pages, which needs this.
      pages: read
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install uv
        uses: astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0
        with:
          version: "0.9.9"

      - name: Install dependencies from the lockfile
        run: uv sync --locked --no-dev

      - name: Configure Pages
        id: pages
        # Skipped on pull requests. The action fails when Pages is not yet enabled, and
        # a fork's token cannot read the Pages API at all. Pull requests only need a
        # site_url, and the constant below is correct for them.
        if: github.event_name != 'pull_request'
        uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6.0.0

      - name: Build the documentation site
        env:
          # mkdocs.yml reads site_url from this. Unset produces no canonical URL.
          GITHUB_PAGES_URL: ${{ steps.pages.outputs.base_url || 'https://genai-security-project.github.io/agent-control-standard' }}
        run: uv run --no-dev mkdocs build --strict -d _site/docs

      - name: Render the landing page
        run: uv run --no-dev python tools/render_landing.py landing _site

      - name: Publish the schemas
        # Fails when any $id is unsafe or duplicated, or any $ref does not resolve.
        run: uv run --no-dev python tools/publish_schemas.py specification _site/schema

      - name: Upload the artifact
        if: github.event_name != 'pull_request'
        uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        with:
          path: _site
          # The default is one day, which would expire the fastest rollback path:
          # re-running the deploy job of the last good run.
          retention-days: 30

  deploy:
    # event_name alone is not enough. workflow_dispatch can target any ref, so without
    # the branch check a feature branch could publish to the production site.
    if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'
    needs: build
    runs-on: ubuntu-latest
    permissions:
      # The job checks out the repository so the verify step can reach
      # tools/verify_published.py. A job that declares its own block gets none for
      # every scope it omits, so this has to be restated here.
      contents: read
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Deploy to Pages
        id: deployment
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1

      - name: Verify the published schemas
        # Through env, never interpolated into the shell. sync_version.yml documents why.
        env:
          PAGE_URL: ${{ steps.deployment.outputs.page_url }}
        run: |
          python3 tools/verify_published.py "$PAGE_URL" \
            schema/v0.1.0/acs_schema.json \
            schema/v0.1.0/hooks/session-start.json
```

- [ ] **Step 3: Write the monitor**

Create `.github/workflows/monitor-pages.yml`. Nothing else watches the site between merges, and a spec repository can go weeks without one:

```yaml
# The published $id URIs are a machine-consumed contract. Between merges nothing else
# checks that they still resolve, so this does.
name: Monitor Pages

on:
  schedule:
    - cron: "17 */6 * * *"
  workflow_dispatch:

permissions: {}

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Verify the published schemas still resolve
        env:
          PAGE_URL: https://genai-security-project.github.io/agent-control-standard/
        run: |
          python3 tools/verify_published.py "$PAGE_URL" \
            schema/v0.1.0/acs_schema.json \
            schema/v0.1.0/hooks/session-start.json
```

- [ ] **Step 4: Validate both workflows parse**

Run:
```bash
uv run python -c "
import yaml, pathlib
for f in ['deploy-pages.yml', 'monitor-pages.yml']:
    yaml.safe_load(pathlib.Path('.github/workflows', f).read_text())
    print(f, 'ok')
"
```
Expected: both print `ok`.

- [ ] **Step 5: Reproduce the build locally**

```bash
rm -rf _site
GITHUB_PAGES_URL="https://genai-security-project.github.io/agent-control-standard" \
  uv run mkdocs build --strict -d _site/docs
uv run python tools/render_landing.py landing _site
uv run python tools/publish_schemas.py specification _site/schema
uv run pytest -v
```

Expected: `published 44 schemas`, `_site` contains `index.html`, `docs/index.html`, and
`schema/v0.1.0/acs_schema.json`, and the suite passes.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/deploy-pages.yml .github/workflows/monitor-pages.yml tools/verify_published.py
git commit -m "Test, build, deploy, then verify the published bytes

Adds a test job so the guards run on every pull request. Without it the
suite only ran when a developer remembered to, and the deploy job
installs with --no-dev, which excludes the group pytest lives in.

The deploy job now also checks the ref. workflow_dispatch can target any
branch, and gating on event name alone let a feature branch publish to
the production site. Concurrency groups every deploy together so they
serialize on the one Pages site, while pull request builds group per ref
and cancel stale runs.

Verification fetches and parses each document and asserts it serves its
own \$id. The previous check read a status code with the body discarded,
so a file overwritten with different content still passed, and its
retry flags were inert: curl does not retry a 404 without --fail, which
is exactly how CDN propagation lag presents.

configure-pages is skipped on pull requests. It fails when Pages is not
enabled and a fork's token cannot read the Pages API. Artifact retention
goes to 30 days so re-running the last good deploy stays available as a
rollback."
```

---

## Task 6: Policy and ownership catch up with hosting

This repository is about to operate a public website. Four documents currently say it does not.

**Files:**
- Modify: `CLAUDE.md`, `SECURITY.md`, `LICENSING.md`, `.github/CODEOWNERS`

- [ ] **Step 1: Fix the contact policy without contradicting it**

In `CLAUDE.md`, replace the **entire** "Contact channels" paragraph. Replacing only its first sentence leaves the later sentence "Do not add a contact address to documentation" in place, which forbids the exception the first half granted, and dropping the whole paragraph would delete the RFC 2606 rule that licenses eleven example addresses in `docs/`.

```markdown
### Contact channels
The repository carries one contact address and no others. `rock.lambros@owasp.org`
appears on the landing page for general questions about the project. Do not add any
other contact address to documentation, `project.owasp.yaml`, or the site config.

Routing is unchanged. Community contact is GitHub Discussions and the
`#team-genai-asi-acs-general` channel on `owasp.slack.com`. Security reporting is GitHub
private vulnerability reporting, which is the channel `SECURITY.md` covers. Code of
Conduct enforcement routes to the OWASP CoC process so that a report about a maintainer
does not land with the maintainers. The landing page links both, so publishing an
address does not pull reports out of the processes that handle them independently.

Example addresses in specification documents must use the RFC 2606 reserved domains
(`example.com`, `example.net`, `example.org`). Eleven of these exist in `docs/` today
and are correct.
```

- [ ] **Step 2: Record the new hosting posture**

In `CLAUDE.md`, replace the body of "Hosting (decoupled from this repo)":

```markdown
This repository is the source of truth for the ACS spec, and it now carries the workflow
that publishes the site. Once Pages is enabled, `.github/workflows/deploy-pages.yml`
builds three things on every merge to `main`: the landing page from `landing/`, the
MkDocs documentation under `/docs/`, and the JSON schemas under `/schema/<spec-version>/`.

Schema publish paths derive from each schema's own `$id`, which is validated and
contained because `$id` is a pull-request-writable string used to build a filesystem
path. The build fails on an unsafe or duplicated `$id` and on any `$ref` that does not
resolve, fragment included.

`GOVERNANCE.md` is a build input. Its workstream table renders into the published page,
so a change to its shape can fail the deploy, and its contents are escaped as untrusted
text.

The marketing site at **agentcontrolstandard.org** is still built and deployed from a
separate repository. It will redirect here later. Adding the custom domain makes GitHub
301 the `github.io` URIs to it, which schema tooling follows. Do not rebase `$id` onto
the marketing domain during that cutover. A `CNAME` must be written into `_site` by the
build; placing one in `landing/` does not reach the artifact.
```

- [ ] **Step 3: Bring the site into disclosure scope**

In `SECURITY.md`, the out-of-scope column currently reads "The documentation site at
agentcontrolstandard.ai, which is built from a separate repository". That names the wrong
domain, and it stops being true when this workflow ships. Replace that cell with:

```markdown
| The marketing site at agentcontrolstandard.org, which is built and deployed from a separate repository |
```

Then add these rows to the in-scope column:

```markdown
| The published site at genai-security-project.github.io/agent-control-standard, including the landing page, the documentation, and the schema endpoints |
| The build and publish tooling in `tools/` and `.github/workflows/` |
```

Leave "Missing security headers on sites we do not operate" as it is. GitHub Pages does
not let us set response headers on the site we now operate, so add one more out-of-scope
row making that explicit:

```markdown
| Missing security response headers on the Pages site, which GitHub Pages does not allow us to set |
```

- [ ] **Step 4: Give the new directories a license**

`LICENSING.md` maps `specification/**`, `.github/**`, `docs/**`, and a fixed list of root
Markdown files. It covers none of `landing/`, `tools/`, `tests/`, or `design/`, so the
footer's license claim currently describes files the scope map does not reach. Add to the
scope table:

```markdown
| `landing/**`, `tools/**`, `tests/**` | Apache License 2.0 | `Apache-2.0` |
| `design/**` | CC BY-SA 4.0 | `CC-BY-SA-4.0` |
| `landing/assets/fonts/**` | SIL Open Font License 1.1 | `OFL-1.1` |
```

- [ ] **Step 5: Record the provenance of the reused design**

The tokens, the diagram geometry, and the favicon come from agentcontrolstandard.org,
whose source this project has said it cannot read. Add to `LICENSING.md`:

```markdown
## Provenance of the landing page design

The design tokens in `landing/assets/acs.css`, the diagram geometry in
`landing/assets/starburst.svg`, and the mark in `landing/assets/icon.svg` derive from
agentcontrolstandard.org, which the OWASP GenAI Security Project operates and which is
built from a separate repository. They are used here as the project's own work.

If any part of that site was produced by a party outside the project, confirm in writing
who holds the rights before the next release.
```

Open a tracking issue for that confirmation and reference it in the pull request. This
is the one item in the plan that a code change cannot close.

- [ ] **Step 6: Extend ownership to the code that publishes**

`.github/CODEOWNERS` restricts `/.github/` to five admins with the reasoning that CI is a
privilege-escalation surface. The same reasoning applies to the code that decides what
lands on the public origin, and to the governance file that now renders into it. Add:

```
# These generate and publish the public site. A change here alters what the front door
# says, which is the same class of privilege the /.github/ rule below protects.
/tools/        @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
/landing/      @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
/GOVERNANCE.md @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
```

- [ ] **Step 7: Verify the policy files are consistent**

```bash
grep -c "agentcontrolstandard.ai" SECURITY.md          # expect 0
grep -c "carries no email addresses" CLAUDE.md          # expect 0
grep -rlE "[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" --include='*.md' . \
  | grep -v -e docs/ -e design/ -e CLAUDE.md            # expect no output
uv run pytest -v                                        # expect 63 passed
```

- [ ] **Step 8: Commit**

```bash
git add CLAUDE.md SECURITY.md LICENSING.md .github/CODEOWNERS
git commit -m "Bring policy and ownership in line with operating a site

SECURITY.md put the documentation site out of scope and named the wrong
domain. Once this workflow ships the project operates a site, so a
researcher reading the policy would have been told not to report a
finding against it.

The contact-channels paragraph is replaced whole. Replacing only its
first sentence would have left a later sentence forbidding the exception
the first half grants, and dropping the paragraph would have deleted the
RFC 2606 rule that licenses eleven example addresses in docs/.

LICENSING.md covered none of landing/, tools/, tests/, or design/, so
the footer named licenses for files the scope map did not reach. It also
now records where the reused design tokens and diagram came from.

CODEOWNERS gated the workflow file and left the code that workflow runs
under the widest rule in the file. tools/, landing/, and GOVERNANCE.md
now carry the same admin review as the CI surface, because all three
decide what the public front door says."
```

---

## Task 7: Enable Pages, deploy, and verify

The only steps that change state outside the repository.

- [ ] **Step 1: Open the pull request**

```bash
git push -u origin feat/github-pages-site
gh pr create --title "Publish the ACS site and schemas from this repository" \
  --body "Enables GitHub Pages and publishes three things on every merge to main: a landing page matching the agentcontrolstandard.org design, the existing MkDocs specification site, and all 44 JSON schemas at the URIs their \$id values declare.

Design: design/2026-09-05-github-pages-landing.md
Plan: design/plans/2026-09-05-github-pages-site.md

The plan went through a six-perspective adversarial premortem. The four Critical findings it closed: \$id was an unvalidated filesystem write primitive, GOVERNANCE.md could inject HTML into the published page, the test suite never ran in CI, and the enablement runbook could not pass its own second step."
```

- [ ] **Step 2: Confirm the pull request checks pass**

Run: `gh pr checks --watch`
Expected: `test` and `build` pass. No `deploy` job runs. `configure-pages` is skipped, so
this succeeds before Pages exists.

- [ ] **Step 3: Enable Pages**

This publishes a public website. Confirm with the project lead before running it.

```bash
gh api -X POST repos/GenAI-Security-Project/agent-control-standard/pages \
  -f 'build_type=workflow'
```

Expected: JSON describing the new Pages site. On `409 Conflict` Pages already exists, so
switch the build type instead:

```bash
gh api -X PUT repos/GenAI-Security-Project/agent-control-standard/pages \
  -f 'build_type=workflow'
```

- [ ] **Step 4: Restrict the environment to the default branch**

The workflow's `github.ref` check is the control that matters, and this is the second
layer. Without it, an admin editing the workflow later removes the only guard.

In the repository settings, open **Environments**, select `github-pages`, and set
**Deployment branches** to **Selected branches** with a single rule for `main`. Verify:

```bash
gh api repos/GenAI-Security-Project/agent-control-standard/environments/github-pages \
  --jq '.deployment_branch_policy'
```

Expected: a policy object rather than `null`.

- [ ] **Step 5: Merge**

```bash
gh pr merge --squash
```

- [ ] **Step 6: Watch the deploy**

Run: `gh run watch`
Expected: `test`, `build`, then `deploy` pass, including the schema verification step.

- [ ] **Step 7: Verify the three surfaces by hand**

```bash
BASE="https://genai-security-project.github.io/agent-control-standard"
for path in "" "docs/" "schema/v0.1.0/acs_schema.json" "schema/v0.1.0/hooks/session-start.json"; do
  printf '%s -> %s\n' "${path:-/}" "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/$path")"
done
uv run python tools/verify_published.py "$BASE/" \
  schema/v0.1.0/acs_schema.json schema/v0.1.0/hooks/session-start.json
```

Expected: `200` for all four, then `ok:` for both schemas, each serving its own `$id`.
This is the outcome the whole plan exists to produce.

- [ ] **Step 8: Confirm the page ships whole**

Open the site. Confirm the hero diagram renders, the status table reads `v0.1.0` and
`44`, five workstream rows appear, the theme toggle works, and tabbing shows a clearly
visible focus ring. Then confirm the page contacts nothing:

```bash
curl -sS "$BASE/" | grep -oE 'https?://[^"/]+' | sort -u
```

Expected: only github.com, owasp.slack.com, owasp.org, apache.org, creativecommons.org,
eur-lex.europa.eu, and doi.org. No Google host.

- [ ] **Step 9: Record the rollback procedure**

Add to `design/2026-09-05-github-pages-landing.md` under "Risks accepted":

```markdown
## Rollback

A build failure needs no rollback. Pages keeps serving the last successful deployment.

A successful deploy of wrong content does. In order of speed:

1. Re-run the deploy job of the last good workflow run. Artifact retention is 30 days,
   so this stays available for a month.
2. `git revert` the offending commit, then merge. This takes a full pipeline run.

Both are exercised from the Actions tab by anyone with write access. The scheduled
monitor in `.github/workflows/monitor-pages.yml` checks every six hours that the schema
endpoints still serve their own `$id`.
```

Commit and push that change.

- [ ] **Step 10: Retire the note that says the namespace is not served**

`CLAUDE.md` records under Schema namespace: "The base is not yet served: GitHub Pages is
not enabled on this repo, so remote retrieval 404s." That sentence is accurate until
Step 3 and false immediately after. Replace it with:

```markdown
The base is served from this repository. `.github/workflows/deploy-pages.yml` publishes
every schema at the path its `$id` declares, and the deploy fails if any of them does not
resolve. `.github/workflows/monitor-pages.yml` rechecks that every six hours.
```

In the same edit, change the Hosting section's "Once Pages is enabled" back to the
present tense, because at that point it is.

Do both only after Step 7 confirms the URIs resolve. Writing either earlier would trade
one false statement for another.

---

## Premortem remediation map

| Finding | Closed by |
|---|---|
| F1 `$id` write primitive (Critical) | Task 1: `SAFE_TAIL` pattern, percent-encoding rejection, resolved-path containment, 8 parametrized negative cases |
| F3 tests never run in CI (Critical) | Task 5: `test` job that `build` depends on |
| F8 runbook cannot pass its own step 2 (Critical) | Task 5: `configure-pages` skipped on pull requests. Task 7: enablement before merge, environment branch policy |
| F4 starburst ships blank (High) | Tasks 2 and 3: `<!--ACS:STARBURST-->` is machine-filled, and `render` fails when it is missing or survives |
| F2 HTML injection via `GOVERNANCE.md` (High) | Task 3: `quote=True` plus scheme allowlist, four escaping tests |
| F7 smoke test retries nothing, checks status only (High) | Task 5: `tools/verify_published.py` polls explicitly and asserts the served `$id` |
| F9 second spec version fails the deploy (High) | Task 3: `spec_version` returns the highest. Task 1 test for multi-version publish |
| F10 fragment refs unverified (High) | Task 1: `resolve_pointer`, fragment checked in `verify_refs` |
| F24 guards test the template (High) | Task 3: `tests/test_landing_page.py` runs against `render()` output |
| F5 `workflow_dispatch` deploys any branch (High) | Task 5: `github.ref == 'refs/heads/main'`. Task 7: environment branch policy |
| F11 duplicate `$id` (Medium) | Task 1: `seen` map raises |
| F12 non-schema JSON fails deploy (Medium) | Task 1: files without `$id` skipped; `proposals/` cannot claim the namespace |
| F13 `GOVERNANCE.md` brittleness (Medium) | Task 3: case-insensitive heading, escaped pipes, any-heading stop, row-count reconciliation |
| F14 Google Fonts (Medium) | Task 2: self-hosted Inter. Task 4: `font: false` and an origin allowlist test |
| F15 WCAG contrast (Medium) | Task 2: five measured token replacements. Task 3: a test that computes the ratios |
| F16 CLAUDE.md self-contradiction (Medium) | Task 6 Step 1: whole-paragraph replacement |
| F17 `SECURITY.md` scope and domain (Medium) | Task 6 Step 3 |
| F18 CODEOWNERS coverage (Medium) | Task 6 Step 6 |
| F19 no rollback, 1-day retention (Medium) | Task 5: `retention-days: 30`. Task 7 Step 9: written procedure |
| F20 no monitoring (Medium) | Task 5: `monitor-pages.yml` every six hours |
| F22 no meta-validation (Medium) | Task 1: `Draft202012Validator.check_schema` over the real tree |
| F23 `${{ }}` in `run:` (Low) | Task 5: `env:` plus a script |
| F25 provenance and license scope (Medium) | Task 6 Steps 4 and 5, plus a tracking issue |
| F26 footer links no license (Low) | Task 2: linked licenses, copyright line, document nav |
| F27 email routing (Medium) | Task 2: contact split from reporting, both processes linked |
| F28 uncited regulatory claims (Low) | Task 2: cited to Article 14 and MANAGE 2.4, NIST described as voluntary |
| F29 em dash in `<title>` (Low) | Task 2, guarded by a test |
| F30 dead error handler (Low) | Task 3: `_versions` wraps the call that raises; `main` catches both types |
| F31 weak link regex, magic count (Low) | Task 3: quote-and-space tolerant pattern. Task 1: `>= 44` with a uniqueness check |
| F6 concurrency races (Medium) | Task 5: one group for all deploys |
| F36 `CNAME` cannot reach `_site` (Medium) | Task 6 Step 2: recorded in `CLAUDE.md` for the cutover |

**Not closed, carried forward.** F21, published schemas are mutable in place with no hash
record (Impact High, Confidence Plausible). A `specification/schema.lock` of sha256 per
`$id`, failing the build when a released version's hash changes without a lockfile
update, is the fix. It is a separate change with its own release-process implications and
does not belong in the pull request that turns the site on.

**Parked tail risk.** After the domain cutover every `$id` resolves through a 301 into a
domain governed outside this repository. Registrar compromise or a lapsed renewal
redirects the ecosystem's schema fetches, and consumers who cache carry it forward.
Remote today because no cutover has happened. The trigger that raises it is the `CNAME`
pull request being opened. Record registrar lock, DNSSEC, and named renewal ownership as
preconditions before that change.

**Dropped, retrievable.** Typosquatted lookalike GitHub orgs (Unlikely, no base rate,
mitigation sits with org governance). Bandwidth exhaustion from third-party validator
traffic (Unlikely, unquantified, enforcement is a notice). Fork-runner compromise as
independent harm (Unlikely; read-only token, no secrets, counted instead as F1's
reachability vector).

## Self-Review

**Spec coverage.** Every section of `design/2026-09-05-github-pages-landing.md` maps to a
task. Two design statements were falsified by the premortem and the design needs updating
alongside Task 7 Step 9: the claim that ref closure means "the package either resolves
completely or the build stops" was untrue for fragments until Task 1, and the concurrency
description no longer matches the workflow.

**Type consistency.** `render_landing` imports `load_schemas`, `target_for`, and
`SchemaError` from `publish_schemas`, all defined in Task 1 with matching signatures.
`render()` takes four arguments in Task 3's implementation, its tests, and
`tests/test_landing_page.py`. The five placeholder spellings match across Task 2's HTML,
`REQUIRED_PLACEHOLDERS`, and both test files. All three CLIs take positional arguments in
the order the workflow passes them.

**Test counts.** 29 + 30 + 4 = 63. Task 4 Step 5 and Task 6 Step 7 both expect 63.

**Known gap, out of scope.** Seven A2A hook pages under `docs/spec/instrument/a2a/hooks/`
are absent from the `mkdocs.yml` navigation and publish as orphans reachable only by
direct URL. `--strict` reports this at INFO and does not fail. Fix separately.
