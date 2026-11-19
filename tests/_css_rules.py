"""CSS rule walker and Material 9.8.0 wide-viewport fixture for the navigation tests."""
from __future__ import annotations

from conftest import _strip_css_comments

WIDE = "@media screen and (min-width:76.25em)"

# The one `min-width:76.25em` block that holds the section rules, copied verbatim from
# the mkdocs-material 9.8.0 wheel, material/templates/assets/stylesheets/main.57a0d79d.min.css.
MATERIAL_980_WIDE_BLOCK = (
    '@media screen and (min-width:76.25em){.md-nav{margin-bottom:-.4rem;transition:max-he'
    'ight .25s cubic-bezier(.86,0,.07,1)}.md-nav--primary .md-nav__title{position:sticky;'
    'top:0;z-index:1;background:var(--md-default-bg-color);box-shadow:0 0 .4rem .4rem var'
    '(--md-default-bg-color)}.md-nav--primary .md-nav__title[for=__drawer]{scroll-snap-al'
    'ign:start}.md-nav--primary .md-nav__title .md-nav__icon{display:none}[dir=ltr] .md-n'
    'av--primary .md-nav__list{padding-left:.6rem}[dir=rtl] .md-nav--primary .md-nav__lis'
    't{padding-right:.6rem}.md-nav--primary .md-nav__list{padding-bottom:.4rem}[dir=ltr] '
    '.md-nav--primary .md-nav__item>.md-nav__link{margin-right:.4rem}[dir=rtl] .md-nav--p'
    'rimary .md-nav__item>.md-nav__link{margin-left:.4rem}.md-nav__toggle~.md-nav{display'
    ':grid;grid-template-rows:minmax(.4rem,0fr);visibility:collapse;opacity:0;transition:'
    'grid-template-rows .25s cubic-bezier(.86,0,.07,1),opacity .25s,visibility 0s .25s}.m'
    'd-nav__toggle~.md-nav>.md-nav__list{overflow:hidden}.md-nav__toggle.md-toggle--indet'
    'erminate~.md-nav,.md-nav__toggle:checked~.md-nav{grid-template-rows:minmax(.4rem,1fr'
    ');visibility:visible;opacity:1;transition:grid-template-rows .25s cubic-bezier(.86,0'
    ',.07,1),opacity .15s .1s,visibility}.md-nav__toggle.md-toggle--indeterminate~.md-nav'
    '{transition:none}.md-nav__item--nested>.md-nav>.md-nav__title{display:none}.md-nav__'
    'item--section{display:block;margin:1.25em 0}.md-nav__item--section:last-child{margin'
    '-bottom:0}.md-nav__item--section>.md-nav__link{font-weight:700}.md-nav--lifted>.md-n'
    'av__list>.md-nav__item>[for],.md-nav__item--section>.md-nav__link[for]{color:var(--m'
    'd-default-fg-color--light)}.md-nav--lifted>.md-nav__list>.md-nav__item--active>.md-n'
    'av__link:not(.md-nav__container),.md-nav__item--section>.md-nav__link:not(.md-nav__c'
    'ontainer){pointer-events:none}.md-nav__item--section>.md-nav__link .md-icon,.md-nav_'
    '_item--section>.md-nav__link>[for]{display:none}[dir=ltr] .md-nav__item--section>.md'
    '-nav{margin-left:-.6rem}[dir=rtl] .md-nav__item--section>.md-nav{margin-right:-.6rem'
    '}.md-nav__item--section>.md-nav{display:block;visibility:visible;opacity:1}.md-nav__'
    'item--section>.md-nav>.md-nav__list>.md-nav__item{padding:0}.md-nav__icon{width:.9re'
    'm;height:.9rem;border-radius:100%;transition:background-color .25s}.md-nav__icon:hov'
    'er{background-color:var(--md-accent-fg-color--transparent)}.md-nav__icon:after{displ'
    'ay:inline-block;width:100%;height:100%;vertical-align:-.1rem;content:"";background-c'
    'olor:currentcolor;border-radius:100%;-webkit-mask-image:var(--md-nav-icon--next);mas'
    'k-image:var(--md-nav-icon--next);-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat'
    ';-webkit-mask-position:center;mask-position:center;-webkit-mask-size:contain;mask-si'
    'ze:contain;transition:transform .25s}[dir=rtl] .md-nav__icon:after{transform:rotate('
    '180deg)}.md-nav__item--nested .md-nav__toggle:checked~.md-nav__link .md-nav__icon:af'
    'ter,.md-nav__item--nested .md-toggle--indeterminate~.md-nav__link .md-nav__icon:afte'
    'r{transform:rotate(90deg)}.md-nav--lifted>.md-nav__list>.md-nav__item,.md-nav--lifte'
    'd>.md-nav__title{display:none}.md-nav--lifted>.md-nav__list>.md-nav__item--active{di'
    'splay:block}.md-nav--lifted>.md-nav__list>.md-nav__item--active>.md-nav__link{positi'
    'on:sticky;top:0;z-index:1;margin-top:0;background:var(--md-default-bg-color);box-sha'
    'dow:0 0 .4rem .4rem var(--md-default-bg-color)}.md-nav--lifted>.md-nav__list>.md-nav'
    '__item--active.md-nav__item--section{margin:0}[dir=ltr] .md-nav--lifted>.md-nav__lis'
    't>.md-nav__item>.md-nav:not(.md-nav--secondary){margin-left:-.6rem}[dir=rtl] .md-nav'
    '--lifted>.md-nav__list>.md-nav__item>.md-nav:not(.md-nav--secondary){margin-right:-.'
    '6rem}.md-nav--lifted .md-nav[data-md-level="1"]{grid-template-rows:minmax(.4rem,1fr)'
    ';visibility:visible;opacity:1}[dir=ltr] .md-nav--integrated>.md-nav__list>.md-nav__i'
    'tem--active .md-nav--secondary{border-left:.05rem solid var(--md-primary-fg-color)}['
    'dir=rtl] .md-nav--integrated>.md-nav__list>.md-nav__item--active .md-nav--secondary{'
    'border-right:.05rem solid var(--md-primary-fg-color)}.md-nav--integrated>.md-nav__li'
    'st>.md-nav__item--active .md-nav--secondary{display:block;margin-bottom:1.25em;visib'
    'ility:visible;opacity:1}.md-nav--integrated>.md-nav__list>.md-nav__item--active .md-'
    'nav--secondary>.md-nav__list{padding-bottom:0;overflow:visible}.md-nav--integrated>.'
    'md-nav__list>.md-nav__item--active .md-nav--secondary>.md-nav__title{display:none}}'
)


def _skip_string(css: str, index: int) -> int:
    """Return the offset past the string that opens at index."""
    quote = css[index]
    index += 1
    while index < len(css) and css[index] != quote:
        index += 2 if css[index] == "\\" else 1
    return index + 1


def _split_top(text: str, separator: str) -> list[str]:
    """Split on separator outside strings, parentheses, brackets, and backslash escapes."""
    parts, depth, start, index = [], 0, 0, 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "\"'":
            index = _skip_string(text, index)
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def _block_end(css: str, opening: int) -> int:
    """Return the offset of the brace that closes the one at opening."""
    depth, index = 0, opening
    while index < len(css):
        char = css[index]
        if char == "\\":
            index += 2
            continue
        if char in "\"'":
            index = _skip_string(css, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError(f"unclosed block at offset {opening}")


def _walk_css(css: str, header: str, out: list) -> None:
    index = 0
    while True:
        # A prelude runs to the next brace or semicolon outside strings and parentheses.
        depth, cursor = 0, index
        while cursor < len(css):
            char = css[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char in "\"'":
                cursor = _skip_string(css, cursor)
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char in "{;" and depth == 0:
                break
            cursor += 1
        if cursor >= len(css):
            return
        prelude = css[index:cursor].strip()
        if css[cursor] == ";":
            # A statement at-rule such as @charset or @import carries no rules.
            index = cursor + 1
            continue
        end = _block_end(css, cursor)
        body = css[cursor + 1:end]
        if prelude.startswith("@") and "{" in body:
            # A conditional group rule nests rules. Its headers join outermost first.
            _walk_css(body, f"{header} {prelude}".strip(), out)
        elif not prelude.startswith("@"):
            declarations = frozenset(
                f"{name.strip().lower()}:{value.strip()}"
                for name, _colon, value in (part.partition(":") for part in _split_top(body, ";"))
            )
            out.extend((header, selector, declarations) for selector in _split_top(prelude, ","))
        index = end + 1


def _css_rules(css: str) -> list[tuple[str, str, frozenset[str]]]:
    """Return (media header or "", member selector, declarations) for every style rule.

    A selector list yields one tuple per member, because the 9.8.0 theme merged the
    pointer-events rule into a two-member list. Lookups match a member exactly.
    """
    out: list[tuple[str, str, frozenset[str]]] = []
    _walk_css(_strip_css_comments(css), "", out)
    return out


def _wide_rule_problems(rules) -> list[str]:
    """Name each rule the External resources section needs that the wide block lacks."""
    wide = [(index, selector, declarations)
            for index, (header, selector, declarations) in enumerate(rules) if header == WIDE]

    def last(selector: str, needed: set[str]) -> int | None:
        found = [index for index, member, declarations in wide
                 if member == selector and needed <= declarations]
        return found[-1] if found else None

    problems = []
    section = last(".md-nav__item--section>.md-nav", {"display:block", "visibility:visible"})
    collapse = last(".md-nav__toggle~.md-nav", {"visibility:collapse"})
    if section is None:
        problems.append("shows .md-nav__item--section>.md-nav with display:block and visibility:visible")
    if collapse is None:
        problems.append("collapses .md-nav__toggle~.md-nav with visibility:collapse")
    if section is not None and collapse is not None and section < collapse:
        # Equal specificity, so source order decides which rule a section obeys.
        problems.append("places the section display rule after the collapse rule")
    if last(".md-nav__item--section>.md-nav__link:not(.md-nav__container)", {"pointer-events:none"}) is None:
        problems.append("makes the section label inert with pointer-events:none")
    if last(".md-nav__item--nested>.md-nav>.md-nav__title", {"display:none"}) is None:
        problems.append("hides the nested nav title with display:none")
    return problems
