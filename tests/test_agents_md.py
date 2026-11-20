"""AGENTS.md must name only things that exist and state no version that can drift.

Coding agents read AGENTS.md as fact, and CLAUDE.md imports it whole, so a stale path or
a dead anchor there sends every agent to the wrong place with full confidence. The
strict docs build never sees AGENTS.md, and tests/test_doc_links.py checks neither
relative links nor anchors, so nothing else catches that drift.

Three checks run on the real file:

- Every repository path AGENTS.md names, in backticks or as a relative link, exists.
- Every `#anchor` in a relative link resolves to a heading in its target, using GitHub's
  heading rule, because GitHub is where the file is read.
- The prose states no bare version such as v0.1 or 0.1.4. The README, the spec, the
  decision log, version.txt, and the schema $id own those, and a copy here goes stale.

The helper tests below plant a bad path, a dead anchor, and a bare version, so a change
that blinds a detector fails here rather than passing quietly on the real file.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "AGENTS.md"

# A backticked token counts as a repository path when it contains a slash or ends in one
# of these extensions. A bare host such as `owaspacs.org` matches neither, so it is left
# alone. A token that starts with a slash is a published site path, not a repository one.
PATH_EXTENSIONS = (".md", ".yml", ".yaml", ".toml", ".json", ".py", ".txt", ".lock", ".html", ".ts")
# Characters that mark a token as a command, label, URL, address, or placeholder.
NOT_A_PATH = re.compile(r"[\s:@$<>*?]")
FENCE = re.compile(r"^(```|~~~)")
CODE_SPAN = re.compile(r"`([^`\n]+)`")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
BARE_URL = re.compile(r"https?://\S+")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
HTML_ID = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")
# v0.1, v0.1.0, V2, or a dotted release such as 0.1.4. A two-part number without a v,
# such as the DCO's 1.1, is a document title rather than a project version.
VERSION = re.compile(r"(?<![\w.])(?:[vV]\d+(?:\.\d+)*|\d+\.\d+\.\d+)(?![\w.])")


def prose_lines(text: str) -> list[str]:
    """Return the lines outside fenced code blocks."""
    lines, fenced = [], False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return lines


def named_paths(text: str) -> set[str]:
    """Return the repository paths named in code spans and relative links."""
    found = set()
    for line in prose_lines(text):
        for token in CODE_SPAN.findall(line):
            if token.startswith("/") or NOT_A_PATH.search(token):
                continue
            if "/" in token or token.endswith(PATH_EXTENSIONS):
                found.add(token.rstrip("/"))
        for target in LINK.findall(line):
            path = target.partition("#")[0]
            if path and not SCHEME.match(path):
                found.add(path.rstrip("/"))
    return found


def missing_paths(text: str, root: Path) -> list[str]:
    return sorted(p for p in named_paths(text) if not (root / p).exists())


def slug(heading: str) -> str:
    """Return the anchor GitHub gives a heading."""
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    plain = plain.replace("`", "").lower()
    plain = re.sub(r"[^\w\- ]", "", plain)
    return plain.replace(" ", "-")


def anchors(text: str) -> set[str]:
    """Return every anchor a markdown file defines, numbering repeated headings as GitHub does."""
    found, seen = set(), {}
    for line in prose_lines(text):
        found.update(HTML_ID.findall(line))
        match = HEADING.match(line)
        if not match:
            continue
        base = slug(match.group(1))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def dead_anchors(text: str, source: Path, root: Path) -> list[str]:
    """Return each relative link whose #anchor its target file does not define."""
    dead = []
    for line in prose_lines(text):
        for target in LINK.findall(line):
            if SCHEME.match(target) or "#" not in target:
                continue
            path, _, fragment = target.partition("#")
            file = source if not path else root / path
            if not file.is_file() or fragment not in anchors(file.read_text(encoding="utf-8")):
                dead.append(target)
    return dead


def bare_versions(text: str) -> list[str]:
    """Return version numbers stated in prose, ignoring code, link targets, and URLs."""
    found = []
    for line in prose_lines(text):
        line = CODE_SPAN.sub("", line)
        # Drop link targets but keep link text, which is prose a reader sees.
        line = re.sub(r"\]\([^)]*\)", "]", line)
        line = BARE_URL.sub("", line)
        found.extend(VERSION.findall(line))
    return found


# The real file.


def test_every_path_agents_md_names_exists():
    missing = missing_paths(AGENTS.read_text(encoding="utf-8"), ROOT)
    assert not missing, f"AGENTS.md names paths that do not exist: {missing}"


def test_every_anchor_in_agents_md_resolves():
    dead = dead_anchors(AGENTS.read_text(encoding="utf-8"), AGENTS, ROOT)
    assert not dead, f"AGENTS.md links anchors its targets do not define: {dead}"


def test_agents_md_states_no_bare_version():
    found = bare_versions(AGENTS.read_text(encoding="utf-8"))
    assert not found, (
        f"AGENTS.md states versions {found}. Point to version.txt or the schema $id instead, "
        "and name release and spec versions separately if one is needed."
    )


# The detectors, against planted input.


def test_a_planted_missing_path_is_caught():
    text = "Run `tools/no_such_file.py`, read [this](./docs/no-such-page.md), and keep `mkdocs.yml`."
    assert missing_paths(text, ROOT) == ["./docs/no-such-page.md", "tools/no_such_file.py"]


def test_hosts_commands_labels_and_site_paths_are_not_paths():
    text = "`owaspacs.org` `git commit -s` `status:accepted` `/docs/` `$id` `you@example.com` `integration`"
    assert named_paths(text) == set()


def test_paths_inside_a_fenced_block_are_ignored():
    assert named_paths("```bash\ncat `tools/no_such_file.py`\n```\n") == set()


def test_a_planted_dead_anchor_is_caught():
    text = "[Ok](./CONTRIBUTING.md#how-work-gets-accepted) and [Dead](./CONTRIBUTING.md#no-such-section)."
    assert dead_anchors(text, AGENTS, ROOT) == ["./CONTRIBUTING.md#no-such-section"]


def test_slug_follows_githubs_heading_rule():
    assert slug("Developer's Certificate of Origin 1.1") == "developers-certificate-of-origin-11"
    assert slug("Part 2: How Work Enters the Repository") == "part-2-how-work-enters-the-repository"
    assert slug("Review When Asked, and Show Your Work") == "review-when-asked-and-show-your-work"


def test_a_repeated_heading_gets_a_numbered_anchor():
    assert anchors("## Notes\n\n## Notes\n") == {"notes", "notes-1"}


def test_a_planted_bare_version_is_caught():
    assert bare_versions("ACS v0.1 ships today, and release 0.1.4 is tagged.") == ["v0.1", "0.1.4"]


def test_versions_in_code_links_and_titles_are_not_flagged():
    text = (
        "See `specification/v0.1.0/` and [the schema](./specification/v0.1.0/acs_schema.json), "
        "the [Developer's Certificate of Origin 1.1](./CONTRIBUTING.md), and "
        "https://example.com/v2/page."
    )
    assert bare_versions(text) == []
