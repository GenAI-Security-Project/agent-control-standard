"""Heading structure guards for the specification documents.

A subsection renders under whichever heading precedes it. When a numbered
subsection has no parent heading, its prose silently joins the previous
section, the section gets no anchor, and it never appears in the page table of
contents. Nothing fails the build, so only a structural check catches it.
"""

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"

# `### 9.1 Intent extension via ASK (normative)` -> ("9", "1")
SUBSECTION = re.compile(r"^#{3,6}\s+(\d+)\.(\d+)\b")
# `## 9. Approver Model` -> "9"
SECTION = re.compile(r"^##\s+(\d+)\.")


def numbered_spec_documents():
    """Every docs page that numbers its sections, so the rule stays scoped."""
    for path in sorted(DOCS.rglob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        if any(SECTION.match(line) for line in lines):
            yield path


def test_every_numbered_subsection_has_a_parent_section():
    orphans = []
    for path in numbered_spec_documents():
        lines = path.read_text(encoding="utf-8").splitlines()
        parents = {SECTION.match(line).group(1) for line in lines if SECTION.match(line)}
        for number, line in enumerate(lines, start=1):
            match = SUBSECTION.match(line)
            if match and match.group(1) not in parents:
                orphans.append(
                    f"{path.relative_to(DOCS.parent)}:{number} "
                    f"'{line.strip()}' has no '## {match.group(1)}.' parent"
                )
    assert not orphans, "Numbered subsections with no parent section:\n" + "\n".join(orphans)


def test_numbered_sections_run_without_gaps():
    """A missing parent heading also shows up as a gap in the section sequence."""
    gaps = []
    for path in numbered_spec_documents():
        lines = path.read_text(encoding="utf-8").splitlines()
        found = [int(SECTION.match(line).group(1)) for line in lines if SECTION.match(line)]
        if not found:
            continue
        missing = sorted(set(range(min(found), max(found) + 1)) - set(found))
        if missing:
            gaps.append(f"{path.relative_to(DOCS.parent)} skips section(s) {missing}")
    assert not gaps, "Numbered section sequences with gaps:\n" + "\n".join(gaps)
