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
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SPECIFICATION = ROOT / "specification"

# The only GitHub repositories any doc may link to. Add an entry here only as a
# deliberate decision: the point of a positive allowlist is that a new foreign
# repository fails until someone does that on purpose.
ALLOWED_GITHUB_REPOS = frozenset({
    "GenAI-Security-Project/agent-control-standard",  # this project
    "prowler-cloud/py-ocsf-models",                   # OCSF Python models, cited in extend_ocsf.md
    "ocsf/examples",                                  # OCSF example events, cited in extend_ocsf.md
})

# The namespace every published schema's $id is served from. See tools/publish_schemas.py.
SCHEMA_BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

GITHUB_REPO = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
# Stops at markdown link/prose delimiters rather than at a fixed extension, so a
# directory link or a link with a query string is still captured whole.
SCHEMA_LINK = re.compile(re.escape(SCHEMA_BASE) + r"([^\s)\]]+)")


def _doc_lines():
    """Yield (path, line number, line text) for every line of every doc under docs/."""
    for path in sorted(DOCS.rglob("*.md")):
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
