"""Walk either surface's left navigation pane into rows, and hold the shared patterns.

The landing page and the docs site render one pane from `mkdocs.yml` through two
different templates. A test holds the two panes equal and a live check compares three
served pages, so both need the same reading of the markup. That reading lives here.

A row is `(depth, label, url, is_group, is_section)`. Depth counts the `ul` elements
that enclose the row inside the pane, so the two surfaces agree on depth even though
their wrapper elements differ.

This module runs on the deploy runner's bare interpreter (`python -I -S`), so it imports
the standard library only. The parser builds a small tree with `html.parser` because no
third-party HTML parser is a dependency of this project.

The patterns are defined once here so the renderer, the nav test, and the live check
cannot drift apart on what a title, an anchor, or an allowed URL is.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

Row = tuple[int, str, str | None, bool, bool]

# These gate pull-request-writable values from mkdocs.yml on their way into HTML, so
# they anchor with \A and \Z. A `$` also matches before a final newline, which would let
# "problem\n" pass under match(). Anchoring here keeps them safe under match() or
# fullmatch() alike, so no caller has to remember which one is safe.
TITLE = re.compile(r"\A[^<>&\n]+\Z")
ANCHOR = re.compile(r"\A[A-Za-z][A-Za-z0-9_-]*\Z")
# A value is external when it matches: any scheme, or a path rooted at the host.
EXTERNAL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:|^/")
# A prefix check by design: the host is fixed and any path under it is allowed.
EXTERNAL_URL = re.compile(r"\Ahttps://(github\.com|owasp\.slack\.com)(/|\Z)")
DOC_PATH = re.compile(r"\A(?!/)(?!.*(^|/)\.\.(/|$))[A-Za-z0-9_./-]+\.md\Z")
REPO_URL = "https://github.com/GenAI-Security-Project/agent-control-standard"

PANE_LABEL = "Navigation"
_VOID = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
    "track", "wbr",
})
_HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_SNIPPET = 80


class WalkError(ValueError):
    """The pane's markup does not have the shape the walkers read."""


class _Node:
    __slots__ = ("tag", "attrs", "children", "parent")

    def __init__(self, tag: str, attrs: dict[str, str | None], parent: _Node | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.children: list[_Node | str] = []
        self.parent = parent

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def elements(self) -> list[_Node]:
        return [child for child in self.children if isinstance(child, _Node)]

    def descendants(self, prune=lambda node: False):
        """Yield every element below this one in document order, skipping pruned subtrees."""
        for child in self.elements():
            if prune(child):
                continue
            yield child
            yield from child.descendants(prune)

    def text(self) -> str:
        """Join the text nodes as a browser lays out inline text, then collapse whitespace."""
        parts: list[str] = []
        stack: list[_Node | str] = [self]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                parts.append(item)
            else:
                stack.extend(reversed(item.children))
        return " ".join("".join(parts).split())


class _TreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document", {}, None)
        self._open = self.root

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, dict(attrs), self._open)
        self._open.children.append(node)
        if tag not in _VOID:
            self._open = node

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open.children.append(_Node(tag, dict(attrs), self._open))

    def handle_endtag(self, tag: str) -> None:
        # Close back to the matching open element. A stray end tag with no open match
        # is ignored rather than allowed to unwind the whole tree.
        node: _Node | None = self._open
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self._open = node.parent

    def handle_data(self, data: str) -> None:
        self._open.children.append(data)


def _pane(markup: str) -> _Node:
    builder = _TreeBuilder()
    builder.feed(markup)
    builder.close()
    panes = [node for node in builder.root.descendants() if node.attrs.get("aria-label") == PANE_LABEL]
    if len(panes) != 1:
        raise WalkError(f'expected one element with aria-label="{PANE_LABEL}", found {len(panes)}')
    return panes[0]


def _depth(node: _Node, pane: _Node) -> int:
    depth = 0
    current = node.parent
    while current is not None and current is not pane:
        if current.tag == "ul":
            depth += 1
        current = current.parent
    return depth


def _is_toc(node: _Node) -> bool:
    return node.tag == "nav" and "md-nav--secondary" in node.classes


def _docs_pick(item: _Node, depth: int) -> _Node:
    candidates: list[_Node] = []
    for child in item.elements():
        if child.tag == "div" and "md-nav__container" in child.classes:
            candidates.extend(child.elements())
        else:
            candidates.append(child)
    # The active page's row repeats its own title in a label that opens the table of
    # contents. It is not a navigation row, so it must not compete with the page link.
    candidates = [node for node in candidates if not (node.tag == "label" and node.attrs.get("for") == "__toc")]
    links = [node for node in candidates if node.tag == "a" and "md-nav__link" in node.classes]
    labels = [node for node in candidates
              if node.tag == "label" and "md-nav__link" in node.classes and node.attrs.get("for") is not None]
    # A container row holds both its page link and its toggle label. The link names the
    # row, so it wins over the label whenever one exists.
    if len(links) == 1:
        return links[0]
    if not links and len(labels) == 1:
        return labels[0]
    raise WalkError(
        f"docs row at depth {depth} has {len(links)} links and {len(labels)} labels: "
        f"{item.text()[:_SNIPPET]!r}"
    )


def _row(pick: _Node, depth: int, base: str, is_group: bool, is_section: bool) -> Row:
    href = pick.attrs.get("href") if pick.tag == "a" else None
    url = urljoin(base, href) if href is not None else None
    return (depth, pick.text(), url, is_group, is_section)


def _docs_items(markup: str, base: str) -> list[tuple[_Node, Row]]:
    pane = _pane(markup)
    found: list[tuple[_Node, Row]] = []
    for node in pane.descendants(prune=_is_toc):
        if node.tag != "li" or "md-nav__item" not in node.classes:
            continue
        if node.parent is None or node.parent.tag != "ul" or "md-nav__list" not in node.parent.classes:
            continue
        depth = _depth(node, pane)
        is_section = "md-nav__item--section" in node.classes
        is_group = "md-nav__item--nested" in node.classes and not is_section
        found.append((node, _row(_docs_pick(node, depth), depth, base, is_group, is_section)))
    return found


def walk_docs(markup: str, base: str) -> list[Row]:
    """Read a Material docs page's primary pane into rows, with URLs resolved against base."""
    return [row for _node, row in _docs_items(markup, base)]


def _direct(node: _Node, tags: frozenset[str] | set[str]) -> _Node | None:
    return next((child for child in node.elements() if child.tag in tags), None)


def _landing_items(markup: str, base: str) -> list[tuple[_Node, Row]]:
    pane = _pane(markup)
    found: list[tuple[_Node, Row]] = []
    for node in pane.descendants():
        if node.tag != "li" or node.parent is None or node.parent.tag != "ul":
            continue
        depth = _depth(node, pane)
        details = _direct(node, {"details"})
        if details is not None:
            summary = _direct(details, {"summary"})
            pick = None if summary is None else (_direct(summary, {"a"}) or summary)
        else:
            pick = _direct(node, {"a"}) or _direct(node, _HEADINGS)
        if pick is None:
            raise WalkError(f"landing row at depth {depth} has nothing to name it: {node.text()[:_SNIPPET]!r}")
        found.append((node, _row(pick, depth, base, details is not None, "nav-section" in node.classes)))
    return found


def walk_landing(markup: str, base: str) -> list[Row]:
    """Read the landing page's pane into rows, with URLs resolved against base."""
    return [row for _node, row in _landing_items(markup, base)]


def _toggle(item: _Node) -> _Node | None:
    return next((child for child in item.elements()
                 if child.tag == "input" and "md-nav__toggle" in child.classes
                 and child.attrs.get("id") != "__toc"), None)


def docs_open_labels(markup: str) -> frozenset[str]:
    """Labels of docs rows whose toggle the page renders checked."""
    opened = set()
    for node, row in _docs_items(markup, ""):
        toggle = _toggle(node)
        if toggle is not None and "checked" in toggle.attrs:
            opened.add(row[1])
    return frozenset(opened)


def landing_open_labels(markup: str) -> frozenset[str]:
    """Labels of landing rows whose `details` the page renders open."""
    opened = set()
    for node, row in _landing_items(markup, ""):
        details = _direct(node, {"details"})
        if details is not None and "open" in details.attrs:
            opened.add(row[1])
    return frozenset(opened)


def aria_current_links(markup: str) -> list[tuple[str, str]]:
    """Every element in the pane that carries aria-current, as (tag, raw href)."""
    return [(node.tag, node.attrs.get("href") or "")
            for node in _pane(markup).descendants() if "aria-current" in node.attrs]


def ancestor_labels(rows: list[Row], index: int) -> list[str]:
    """Labels of the groups and sections that hold rows[index], nearest first.

    Rows are in document order, so the nearest earlier row at a smaller depth is the
    parent. A section counts as an ancestor too. Skipping it would hand a section's
    children to whatever group closed before the section, and that group's state would
    decide their visibility.
    """
    limit = rows[index][0]
    found: list[str] = []
    for depth, label, _url, is_group, is_section in reversed(rows[:index]):
        if (is_group or is_section) and depth < limit:
            found.append(label)
            limit = depth
            if depth == 1:
                break
    return found


def docs_expanded_mismatch(markup: str) -> list[str]:
    """Report each docs group whose nested nav's aria-expanded is missing, invalid, or
    disagrees with its toggle, plus "indeterminate" when any toggle is in that state.

    Material sets aria-expanded from the same state that checks the toggle. A mismatch
    means a screen reader announces a group as open or closed when it is not.
    """
    problems: list[str] = []
    for node, (_depth_, label, _url, is_group, _section) in _docs_items(markup, ""):
        if not is_group:
            continue
        nested = next((child for child in node.elements()
                       if child.tag == "nav" and "md-nav" in child.classes and not _is_toc(child)), None)
        if nested is None:
            continue
        expanded = nested.attrs.get("aria-expanded")
        if expanded is None:
            problems.append(f"{label}: nested nav has no aria-expanded")
            continue
        if expanded not in ("true", "false"):
            problems.append(f"{label}: aria-expanded is {expanded!r}")
            continue
        toggle = _toggle(node)
        checked = toggle is not None and "checked" in toggle.attrs
        if (expanded == "true") != checked:
            state = "checked" if checked else "unchecked"
            problems.append(f"{label}: aria-expanded is {expanded!r} but the toggle is {state}")
    if any("md-toggle--indeterminate" in node.classes for node in _pane(markup).descendants()):
        problems.append("indeterminate")
    return problems
