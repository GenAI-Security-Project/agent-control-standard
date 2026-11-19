"""Guards against dead and off-namespace links inside the published docs.

Nothing else in the repository checks a doc link. `mkdocs build --strict` validates
internal references only, and CI runs no link checker at all. `tests/conftest.py`
deliberately treats `("a", "href")` as non-fetching, correctly, because that guard is
about resources a browser fetches on load rather than links a human clicks.

Those three true facts left a hole, and something fell through it: 44 links across 9
files under `docs/spec/` pointed at `github.com/afogel/ACS_official`, a maintainer's
personal fork of this project from before the OWASP donation. The fork has no `dev`
branch, so every one of the 44 returned HTTP 404, 25 of them on the published Hooks
page, until the donation commit that carried them in was traced and fixed.

Guard A is a positive allowlist rather than a blocklist of known-bad hosts, because a
blocklist only catches repositories someone has already flagged as a problem. The dead
links here were never flagged. A positive allowlist fails closed on any new foreign
repository, including one nobody has looked at yet, which is the property this defect
proves the repository needs.

Guard B checks the other direction: a link into the schema's own published namespace
must still point at a schema that exists, under the exact URL the schema's own $id
declares. That catches drift from a rename or move as readily as it catches a typo.

The scan originally covered `docs/` only, which is exactly why the 44 dead links above
lived undetected: root files ship straight to readers too, README.md most of all, and
carried zero coverage. `ROOT_MARKDOWN_FILES` below adds the front-door files this repo
actually renders for humans. `CONTRIBUTING.md` is deliberately absent from that list: a
pull request open at the time this guard was extended rewrites it, and adding it here
would race that rewrite rather than protect it.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SPECIFICATION = ROOT / "specification"

# Repository-root markdown files that ship to readers the same way docs/ does, so they
# get the same two guards. CONTRIBUTING.md is excluded on purpose; see the module
# docstring.
ROOT_MARKDOWN_FILES = (
    "README.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "LICENSING.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTORS.md",
    "STYLE.md",
    "reference-implementations/README.md",
)

# The only GitHub repositories any doc may link to. Add an entry here only as a
# deliberate decision: the point of a positive allowlist is that a new foreign
# repository fails until someone does that on purpose.
ALLOWED_GITHUB_REPOS = frozenset({
    "GenAI-Security-Project/agent-control-standard",  # this project
    "prowler-cloud/py-ocsf-models",                   # OCSF Python models, cited in extend_ocsf.md
    "ocsf/examples",                                  # OCSF example events, cited in extend_ocsf.md
    "orgs/GenAI-Security-Project",                     # the org's project board, not a repo; same regex shape
    "microsoft/agent-governance-toolkit",             # upstream policy engine the AGT reference implementation governs, cited in README.md
})

# The namespace every published schema's $id is served from. See tools/publish_schemas.py.
SCHEMA_BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

GITHUB_REPO = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
# Stops at markdown link/prose delimiters rather than at a fixed extension, so a
# directory link or a link with a query string is still captured whole.
SCHEMA_LINK = re.compile(re.escape(SCHEMA_BASE) + r"([^\s)\]]+)")


def _scanned_paths():
    """Every markdown file this guard covers: all of docs/, plus the named root files."""
    paths = list(DOCS.rglob("*.md"))
    paths.extend(ROOT / name for name in ROOT_MARKDOWN_FILES)
    return sorted(paths)


def _doc_lines():
    """Yield (path, line number, line text) for every line of every scanned doc."""
    for path in _scanned_paths():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            yield path, lineno, line


def test_no_doc_links_to_a_github_repository_outside_the_allowlist():
    violations = []
    for path, lineno, line in _doc_lines():
        for match in GITHUB_REPO.finditer(line):
            repo = f"{match.group(1)}/{match.group(2)}"
            if repo not in ALLOWED_GITHUB_REPOS:
                violations.append(
                    f"{path.relative_to(ROOT)}:{lineno}: links to {repo}, "
                    f"not on the allowlist ({match.group(0)})"
                )
    assert not violations, "Foreign GitHub repository links found:\n" + "\n".join(violations)


def test_schema_namespace_links_match_a_published_id():
    violations = []
    for path, lineno, line in _doc_lines():
        for match in SCHEMA_LINK.finditer(line):
            url = match.group(0)
            tail = match.group(1)
            schema_path = SPECIFICATION / tail
            if not schema_path.is_file():
                violations.append(f"{path.relative_to(ROOT)}:{lineno}: {url} has no schema at {tail}")
                continue
            try:
                declared = json.loads(schema_path.read_text(encoding="utf-8")).get("$id")
            except json.JSONDecodeError as exc:
                violations.append(f"{path.relative_to(ROOT)}:{lineno}: {url} schema is invalid JSON ({exc})")
                continue
            if declared != url:
                violations.append(
                    f"{path.relative_to(ROOT)}:{lineno}: {url} does not match "
                    f"the schema's own $id ({declared!r})"
                )
    assert not violations, "Schema links that do not match a published $id:\n" + "\n".join(violations)


def test_root_markdown_files_are_scanned():
    """Prove the guard covers the root files, not just docs/.

    A silent path-list typo (a missing file, a wrong name) would otherwise leave a root
    file unguarded while this suite still reports green, which is exactly how the 44
    dead links in docs/spec/ went unnoticed for as long as they did.
    """
    scanned = _scanned_paths()
    for name in ROOT_MARKDOWN_FILES:
        path = ROOT / name
        assert path.is_file(), f"{name} does not exist at the repository root"
        assert path in scanned, f"{name} is not included in the scan"


MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING_LINE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
INLINE_CODE = re.compile(r"`[^`]*`")


def _heading_slug(text: str) -> str:
    """Compute a GitHub-compatible heading anchor slug."""
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    cleaned = cleaned.replace("`", "").replace("*", "").replace("_", "")
    cleaned = cleaned.strip().lower()
    cleaned = re.sub(r"[^\w\s-]", "", cleaned, flags=re.UNICODE)
    return re.sub(r"\s", "-", cleaned)


def _headings_in_markdown(path: Path) -> set[str]:
    """Return every heading anchor slug (GitHub and MkDocs forms) in a markdown file."""
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_LINE.match(line)
        if not match:
            continue
        base = _heading_slug(match.group(2))
        idx = counts.get(base, 0)
        counts[base] = idx + 1
        slug = base if idx == 0 else f"{base}-{idx}"
        slugs.add(slug)
        slugs.add(re.sub(r"-+", "-", slug).strip("-"))
    return slugs


def _validate_relative_links(path: Path, text: str | None = None) -> list[str]:
    """Validate relative file links and markdown heading anchors inside `path`."""
    content = path.read_text(encoding="utf-8") if text is None else text
    violations: list[str] = []
    in_fence = False
    rel_source = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    for lineno, line in enumerate(content.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        scrubbed = INLINE_CODE.sub("", line)
        for match in MARKDOWN_LINK.finditer(scrubbed):
            raw_target = match.group(1).strip()
            target = raw_target.split()[0] if " " in raw_target else raw_target
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            path_part, _, fragment = target.partition("#")
            resolved = (path.parent / path_part).resolve() if path_part else path.resolve()
            if not resolved.exists():
                violations.append(
                    f"{rel_source}:{lineno}: relative link {target!r} does not exist"
                )
                continue
            if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
                slugs = _headings_in_markdown(resolved)
                if fragment not in slugs:
                    violations.append(
                        f"{rel_source}:{lineno}: anchor #{fragment} not found in "
                        f"{resolved.relative_to(ROOT)}"
                    )
    return violations


def test_relative_links_and_anchors_resolve():
    """Check relative file links and heading anchors across scanned docs and reference-implementations READMEs."""
    ref_readmes = sorted((ROOT / "reference-implementations").rglob("README.md"))
    candidates = sorted(set(_scanned_paths()) | set(ref_readmes))
    violations: list[str] = []
    for path in candidates:
        violations.extend(_validate_relative_links(path))
    assert not violations, "Broken relative links or heading anchors:\n" + "\n".join(violations)


def test_reference_implementations_readme_key_links_resolve():
    """Ensure reference-implementations/README.md is scanned and its key links and anchors resolve."""
    readme = ROOT / "reference-implementations" / "README.md"
    assert readme in _scanned_paths()
    text = readme.read_text(encoding="utf-8")
    assert "(../docs/spec/instrument/specification.md#10-cryptographic-signatures)" in text
    assert "(agt/agt.lock)" in text
    assert _validate_relative_links(readme) == []

    broken_anchor = (
        "[sig](../docs/spec/instrument/specification.md#10-renamed-signatures)\n"
    )
    assert _validate_relative_links(readme, broken_anchor) != []

    broken_path = "[lock](agt/missing-agt.lock)\n"
    assert _validate_relative_links(readme, broken_path) != []

