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

    version, count = _schema_facts(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(count))
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
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(page, encoding="utf-8")
        shutil.copytree(
            landing / "assets",
            out / "assets",
            dirs_exist_ok=True,
            # The diagram is inlined into the page, so publishing it again would ship a
            # second copy that nothing references and that can drift from the inlined one.
            ignore=shutil.ignore_patterns("starburst.svg"),
        )
    except OSError as error:
        print(f"error: cannot write the rendered site: {error}", file=sys.stderr)
        return 1
    print(f"rendered landing page to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
