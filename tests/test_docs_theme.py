"""Guards on the documentation site's theme and its published URLs.

The canonical bug these cover was invisible to every earlier test, because none of them
compared the URL a page declares against the path it is published at.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _docs_build import DOCS_BASE

REPO = Path(__file__).resolve().parents[1]


def test_every_canonical_matches_the_page_path(built_docs):
    """A canonical that omits /docs/ names a URL that does not exist."""
    wrong = []
    for page in built_docs.rglob("index.html"):
        match = re.search(r'rel="canonical" href="([^"]+)"', page.read_text(encoding="utf-8"))
        if not match:
            continue
        relative = page.parent.relative_to(built_docs).as_posix()
        expected = DOCS_BASE if relative == "." else f"{DOCS_BASE}{relative}/"
        if match.group(1) != expected:
            wrong.append((relative, match.group(1)))
    assert not wrong, f"canonical does not match publish path: {wrong[:5]}"


def test_sitemap_urls_sit_under_the_docs_path(built_docs):
    sitemap = built_docs / "sitemap.xml"
    if not sitemap.exists():
        import gzip
        text = gzip.open(built_docs / "sitemap.xml.gz", "rt").read()
    else:
        text = sitemap.read_text(encoding="utf-8")
    urls = re.findall(r"<loc>([^<]+)</loc>", text)
    assert urls, "sitemap has no entries"
    assert all(u.startswith(DOCS_BASE) for u in urls), [u for u in urls if not u.startswith(DOCS_BASE)][:5]


def test_docs_stylesheet_declares_the_acs_tokens():
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    for token in ['[data-md-color-scheme="default"]', '[data-md-color-scheme="slate"]',
                  "--md-text-font", "--md-typeset-a-color"]:
        assert token in css


def test_docs_use_the_same_mark_as_the_landing_page():
    config = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "logo: assets/icon.svg" in config
    assert "favicon: assets/icon.svg" in config
    assert (REPO / "docs" / "assets" / "icon.svg").is_file()


def test_the_two_copies_of_the_mark_stay_identical():
    """MkDocs needs the logo inside docs_dir, so the file exists twice. Nothing else
    keeps the copies in step."""
    assert (REPO / "docs" / "assets" / "icon.svg").read_bytes() == \
        (REPO / "landing" / "assets" / "icon.svg").read_bytes()


def test_docs_do_not_call_the_github_api_at_runtime(built_docs):
    """Material fetches star counts from api.github.com when this hook is present.

    A runtime fetch is invisible to the markup-scanning guards, so this asserts the
    trigger is absent rather than trying to find the request.
    """
    for page in built_docs.rglob("*.html"):
        assert 'data-md-component="source"' not in page.read_text(encoding="utf-8")


def test_repository_link_survives_the_override(built_docs):
    """Dropping the fetch must not drop the link it decorated."""
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert 'class="md-source"' in index
    assert "github.com/GenAI-Security-Project/agent-control-standard" in index


def test_the_header_keeps_its_repository_icon(built_docs):
    """The icon vanished once when this partial was rewritten and a person had to catch it.

    Asserting the mark is inlined turns a silent regression into a failing build. The
    fetch hook staying absent is covered separately, and both have to hold together.
    """
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    match = re.search(r'class="md-source__icon md-icon">\s*(<svg.*?</svg>)', index, re.S)
    assert match, "the repository icon is not inlined in the header"
    assert "viewBox" in match.group(1)
    assert 'data-md-component="source"' not in index


def test_the_theme_still_styles_the_override():
    """The override uses the theme's class names, which the theme's stylesheet supplies.

    Writing the partial for this project means nothing tracks upstream markup. What still
    has to hold is that these classes exist, because a rename upstream would leave the
    header rendering unstyled with every other test passing.
    """
    import material

    stylesheets = Path(material.__file__).parent / "templates" / "assets" / "stylesheets"
    css = "".join(p.read_text(encoding="utf-8") for p in stylesheets.glob("main.*.css"))
    if not css:
        pytest.skip("installed Material layout differs, nothing to compare")
    for klass in [".md-source", ".md-source__repository", ".md-nav__container", ".md-nav__toggle",
                  ".md-nav__item--section"]:
        assert klass in css, f"{klass} is gone from the installed theme"


def test_docs_palette_is_a_two_state_sun_and_moon_toggle():
    """Three states and a switch glyph did not match the landing page's control."""
    config = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "material/weather-night" in config
    assert "material/weather-sunny" in config
    assert "toggle-switch" not in config
    assert config.count("media: \"(prefers-color-scheme") == 2


def test_link_colour_survives_the_theme_default_palette(built_docs):
    """Material's palette sets --md-typeset-a-color from its default indigo primary.

    The scheme rules alone tie with it at equal specificity, so the ACS value only wins
    when the selector also matches the primary attribute the built pages always carry.
    """
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    assert '[data-md-color-scheme="slate"][data-md-color-primary]' in css
    assert '[data-md-color-scheme="default"][data-md-color-primary]' in css
    # The pages must still carry the attribute the fix depends on.
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert "data-md-color-primary=" in index


def test_docs_contrast_tokens_meet_wcag_aa():
    """Verify light syntax tokens, footer tokens, and search status bar all meet 4.5:1."""
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")

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

    def block(selector: str) -> str:
        start = css.index(selector)
        return css[start : css.index("}", start)]

    def token(section: str, name: str) -> str:
        match = re.search(rf"(?<![-\w]){re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})", section)
        assert match, f"missing {name} in {section!r}"
        return match.group(1)

    light = block('[data-md-color-scheme="default"] {')
    code_bg = token(light, "--md-code-bg-color")
    for name in (
        "--md-code-hl-number-color",
        "--md-code-hl-special-color",
        "--md-code-hl-function-color",
        "--md-code-hl-constant-color",
        "--md-code-hl-keyword-color",
        "--md-code-hl-string-color",
        "--md-code-hl-comment-color",
        "--md-default-fg-color--lighter",
    ):
        color = token(light, name)
        assert ratio(color, code_bg) >= 4.5, f"{name} ({color}) on {code_bg} < 4.5:1"

    for scheme in ('[data-md-color-scheme="default"] {', '[data-md-color-scheme="slate"] {'):
        sec = block(scheme)
        bg_dark = token(sec, "--md-footer-bg-color--dark")
        for fg_name in ("--md-footer-fg-color", "--md-footer-fg-color--light", "--md-footer-fg-color--lighter"):
            fg = token(sec, fg_name)
            assert ratio(fg, bg_dark) >= 4.5, f"{scheme} {fg_name} ({fg}) on {bg_dark} < 4.5:1"

    light_meta = block('[data-md-color-scheme="default"] .md-search-result__meta')
    assert ratio(token(light_meta, "color"), token(light_meta, "background-color")) >= 4.5
    dark_meta = block('[data-md-color-scheme="slate"] .md-search-result__meta')
    assert ratio(token(dark_meta, "color"), token(dark_meta, "background-color")) >= 4.5


def _extract_balanced_block(css: str, header: str) -> str:
    """Return the body between `{` and its matching `}` for the first block starting with `header`."""
    start = css.index(header)
    brace = css.index("{", start)
    depth = 0
    for idx in range(brace, len(css)):
        if css[idx] == "{":
            depth += 1
        elif css[idx] == "}":
            depth -= 1
            if depth == 0:
                return css[brace + 1 : idx]
    raise AssertionError(f"unbalanced block for {header!r}")


def test_docs_accessibility_rules_and_keyboard_controls(built_docs):
    """Pin prose underlines, scoped mobile drawer/search visibility, search wrapping, and JS-free controls."""
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    assert "text-decoration: underline;" in css

    # Scope visibility assertions to each rule inside its own media query so another rule cannot satisfy them.
    drawer_mq = _extract_balanced_block(css, "@media screen and (max-width: 76.234375em)")
    sidebar_closed = _extract_balanced_block(drawer_mq, ".md-sidebar--primary")
    sidebar_open = _extract_balanced_block(
        drawer_mq, '[data-md-toggle="drawer"]:checked ~ .md-container .md-sidebar--primary'
    )
    assert "visibility: hidden;" in sidebar_closed
    assert "visibility: visible;" in sidebar_open

    search_mq = _extract_balanced_block(css, "@media screen and (max-width: 59.984375em)")
    search_closed = _extract_balanced_block(search_mq, ".md-search__inner")
    search_open = _extract_balanced_block(
        search_mq, '[data-md-toggle="search"]:checked ~ .md-header .md-search__inner'
    )
    assert "visibility: hidden;" in search_closed
    assert "visibility: visible;" in search_open

    # Focus ring for the dark header bar must stay off light-mode search inputs/results inside .md-header.
    assert ".md-header :focus-visible" not in css
    assert ".md-header__button:focus-visible" in css
    assert ".md-header__ellipsis:focus-visible" in css
    assert ".md-header__option:focus-visible" in css
    assert ".md-search__input:focus-visible" in css

    assert ".md-search-result__article pre > code" in css and "white-space: pre-wrap;" in css

    # Static HTML keeps <label for="__drawer"> so the menu stays usable when JS is blocked.
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert '<label class="md-header__button md-icon acs-drawer-toggle" for="__drawer" aria-label="Menu">' in index
    assert 'for="__search" role="button" tabindex="0" aria-label="Search"' in index

    mermaid_init = (REPO / "docs" / "assets" / "javascripts" / "mermaid-init.js").read_text(encoding="utf-8")
    assert 'edgeLabelBackground: "#161616"' in mermaid_init
    assert 'textColor: "#f7f7f7"' in mermaid_init


def test_a11y_js_drawer_inert_search_shortcuts_and_focus():
    """Execute docs/assets/javascripts/a11y.js to catch regressions in drawer inert, focus return, and /, s, f."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not available on PATH")

    script_path = REPO / "docs" / "assets" / "javascripts" / "a11y.js"
    harness = r"""
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

class FakeEvent {
  constructor(type, opts = {}) {
    this.type = type;
    this.bubbles = !!opts.bubbles;
    this.key = opts.key || "";
    this.metaKey = !!opts.metaKey;
    this.ctrlKey = !!opts.ctrlKey;
    this.altKey = !!opts.altKey;
    this.target = opts.target || null;
    this.defaultPrevented = false;
    this.immediateStopped = false;
  }
  preventDefault() { this.defaultPrevented = true; }
  stopImmediatePropagation() { this.immediateStopped = true; }
}

class FakeEl {
  constructor(tag, { id = "", className = "", attrs = {}, children = [], doc = null } = {}) {
    this.tagName = tag.toUpperCase();
    this.nodeType = 1;
    this.id = id;
    this.className = className;
    this._attrs = Object.assign({}, attrs);
    this.dataset = {};
    this.children = [];
    this.parentNode = null;
    this.checked = false;
    this.inert = false;
    this.isContentEditable = false;
    this.scrollWidth = 100;
    this.clientWidth = 100;
    this.scrollHeight = 100;
    this.clientHeight = 100;
    this._listeners = [];
    this._doc = doc;
    for (const c of children) this.appendChild(c);
  }
  get firstChild() { return this.children[0] || null; }
  appendChild(child) {
    if (child.parentNode) {
      const idx = child.parentNode.children.indexOf(child);
      if (idx >= 0) child.parentNode.children.splice(idx, 1);
    }
    child.parentNode = this;
    child._doc = this._doc;
    this.children.push(child);
    return child;
  }
  replaceChild(next, prev) {
    const idx = this.children.indexOf(prev);
    assert(idx >= 0, "prev not a child");
    next.parentNode = this;
    next._doc = this._doc;
    prev.parentNode = null;
    this.children[idx] = next;
    return prev;
  }
  setAttribute(k, v) { this._attrs[k] = String(v); if (k === "id") this.id = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k); }
  removeAttribute(k) { delete this._attrs[k]; }
  addEventListener(type, fn, capture = false) { this._listeners.push({ type, fn, capture: !!capture }); }
  dispatchEvent(ev) {
    if (!ev.target) ev.target = this;
    for (const l of this._listeners.filter((x) => x.type === ev.type && x.capture)) {
      l.fn.call(this, ev);
      if (ev.immediateStopped) return !ev.defaultPrevented;
    }
    for (const l of this._listeners.filter((x) => x.type === ev.type && !x.capture)) {
      l.fn.call(this, ev);
      if (ev.immediateStopped) return !ev.defaultPrevented;
    }
    return !ev.defaultPrevented;
  }
  click() {
    this.dispatchEvent(new FakeEvent("click", { bubbles: true, target: this }));
  }
  focus() {
    if (this._doc) this._doc.activeElement = this;
  }
  contains(node) {
    let cur = node;
    while (cur) {
      if (cur === this) return true;
      cur = cur.parentNode;
    }
    return false;
  }
  matches(sel) {
    return sel.split(",").some((part) => {
      let s = part.trim();
      const tagMatch = s.match(/^([a-zA-Z0-9-]+)/);
      if (tagMatch) {
        if (this.tagName !== tagMatch[1].toUpperCase()) return false;
        s = s.slice(tagMatch[0].length);
      }
      for (const m of s.matchAll(/\.([a-zA-Z0-9_-]+)/g)) {
        if (!this.className.split(/\s+/).includes(m[1])) return false;
      }
      for (const m of s.matchAll(/\[([a-zA-Z0-9_-]+)(?:="([^"]*)")?\]/g)) {
        if (m[1] === "inert") {
          if (!this.inert) return false;
        } else if (m[2] !== undefined) {
          if (this.getAttribute(m[1]) !== m[2]) return false;
        } else if (!this.hasAttribute(m[1])) {
          return false;
        }
      }
      return true;
    });
  }
  closest(sel) {
    let cur = this;
    while (cur) {
      if (cur.matches(sel)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }
  querySelector(sel) {
    if (sel.includes("a[href]")) return this._firstFocusable || null;
    if (sel === "input.md-nav__toggle") return this._toggle || null;
    if (sel === "nav.md-nav[data-md-level]") return this._childNav || null;
    if (sel.includes("label.md-nav__link")) return this._groupLabel || null;
    return null;
  }
  querySelectorAll(sel) {
    if (sel.includes("md-nav__link")) return this._navItems || [];
    return [];
  }
}

const doc = {
  readyState: "complete",
  _listeners: [],
  addEventListener(type, fn, capture = false) { this._listeners.push({ type, fn, capture: !!capture }); },
  dispatchEvent(ev) {
    for (const l of this._listeners.filter((x) => x.type === ev.type && x.capture)) {
      l.fn.call(doc, ev);
      if (ev.immediateStopped) return !ev.defaultPrevented;
    }
    for (const l of this._listeners.filter((x) => x.type === ev.type && !x.capture)) {
      l.fn.call(doc, ev);
      if (ev.immediateStopped) return !ev.defaultPrevented;
    }
    return !ev.defaultPrevented;
  },
  createElement(tag) { return new FakeEl(tag, { doc }); },
};

const body = new FakeEl("body", { doc });
doc.body = body;
doc.activeElement = body;

const drawerCheckbox = new FakeEl("input", { id: "__drawer", doc });
const searchCheckbox = new FakeEl("input", { id: "__search", doc });
const headerNav = new FakeEl("nav", { doc });
const svg = new FakeEl("svg", { doc });
const drawerLabel = new FakeEl("label", {
  className: "md-header__button md-icon acs-drawer-toggle",
  attrs: { for: "__drawer", "aria-label": "Menu" },
  children: [svg],
  doc,
});
headerNav.appendChild(drawerLabel);

const searchTrigger = new FakeEl("label", {
  className: "md-header__button md-icon",
  attrs: { for: "__search", role: "button", tabindex: "0", "aria-label": "Search" },
  doc,
});
const searchInput = new FakeEl("input", { className: "md-search__input", doc });
const searchInner = new FakeEl("div", { className: "md-search__inner", children: [searchInput], doc });

const navLink = new FakeEl("a", { className: "md-nav__link", attrs: { href: "/docs/" }, doc });
const groupToggle = new FakeEl("input", { id: "__nav_5", className: "md-nav__toggle", doc });
const groupLabel = new FakeEl("label", {
  className: "md-nav__link",
  attrs: { for: "__nav_5", tabindex: "0" },
  doc,
});
const childLink = new FakeEl("a", { className: "md-nav__link", attrs: { href: "/docs/concepts/" }, doc });
const childNav = new FakeEl("nav", { className: "md-nav", attrs: { "data-md-level": "1", "aria-expanded": "false" }, children: [childLink], doc });
const groupLi = new FakeEl("li", { className: "md-nav__item md-nav__item--nested", children: [groupToggle, groupLabel, childNav], doc });
groupLi._toggle = groupToggle;
groupLi._childNav = childNav;
groupLi._groupLabel = groupLabel;
childNav._navItems = [childLink];

const sidebar = new FakeEl("div", { className: "md-sidebar--primary", children: [navLink, groupLi], doc });
sidebar._firstFocusable = navLink;
sidebar._navItems = [navLink, groupLabel, childLink];
const content = new FakeEl("div", { className: "md-content", doc });
const footer = new FakeEl("footer", { className: "md-footer", doc });

const scrollTable = new FakeEl("div", { className: "md-typeset__scrollwrap", doc });
scrollTable.scrollWidth = 600;
scrollTable.clientWidth = 300;
const preCode = new FakeEl("code", { doc });
preCode.scrollWidth = 600;
preCode.clientWidth = 300;

doc.getElementById = (id) => ({ __drawer: drawerCheckbox, __search: searchCheckbox, __nav_5: groupToggle }[id] || null);
doc.querySelector = (sel) => ({
  ".acs-drawer-toggle": headerNav.children.find((c) => c.className.includes("acs-drawer-toggle")) || null,
  ".md-sidebar--primary": sidebar,
  ".md-content": content,
  ".md-sidebar--secondary": null,
  ".md-footer": footer,
  'header label.md-header__button[for="__search"]': searchTrigger,
  ".md-search__inner": searchInner,
  ".md-search__input": searchInput,
}[sel] || null);
doc.querySelectorAll = (sel) => {
  if (sel.includes(".md-typeset__scrollwrap")) return [scrollTable];
  return [];
};

const rafQueue = [];
const mql = { matches: true, addEventListener() {} };
const win = {
  matchMedia: () => mql,
  requestAnimationFrame: (cb) => rafQueue.push(cb),
  addEventListener() {},
};

const code = fs.readFileSync(process.argv[1], "utf8");
vm.runInNewContext(code, { window: win, document: doc, Event: FakeEvent });

// 1. Progressive upgrade from <label> to <button> with aria-controls + initial inert states.
const button = headerNav.children[0];
assert.strictEqual(button.tagName, "BUTTON", "drawer label must upgrade to <button> when JS runs");
assert.strictEqual(button.getAttribute("aria-expanded"), "false");
assert.strictEqual(button.getAttribute("aria-controls"), sidebar.id);
assert.strictEqual(sidebar.inert, true, "closed mobile drawer must be inert");
assert.strictEqual(searchInner.inert, true, "closed mobile search must be inert");

// 2. Opening drawer clears sidebar.inert, marks background inert, and moves focus in.
button.click();
while (rafQueue.length) rafQueue.shift()();
assert.strictEqual(drawerCheckbox.checked, true);
assert.strictEqual(button.getAttribute("aria-expanded"), "true");
assert.strictEqual(sidebar.inert, false);
assert.strictEqual(content.inert, true);
assert.strictEqual(doc.activeElement, navLink);

// 3. Closing drawer from overlay / in-pane title label while focus is inside sidebar returns focus to button.
drawerCheckbox.checked = false;
drawerCheckbox.dispatchEvent(new FakeEvent("change", { bubbles: true }));
assert.strictEqual(sidebar.inert, true);
assert.strictEqual(content.inert, false);
assert.strictEqual(doc.activeElement, button, "closing drawer must restore focus to toggle button");

// 4. `/`, `s`, and `f` shortcuts open mobile search, clear inert, focus input, and close an open drawer.
for (const key of ["/", "s", "f"]) {
  button.click();
  assert.strictEqual(drawerCheckbox.checked, true);
  doc.activeElement = body;
  const ev = new FakeEvent("keydown", { key, target: body });
  doc.dispatchEvent(ev);
  assert.strictEqual(ev.defaultPrevented, true, `shortcut ${key} must call preventDefault`);
  assert.strictEqual(searchCheckbox.checked, true, `shortcut ${key} must check __search`);
  assert.strictEqual(searchInner.inert, false, `shortcut ${key} must clear searchInner.inert`);
  assert.strictEqual(doc.activeElement, searchInput, `shortcut ${key} must focus search input`);
  assert.strictEqual(drawerCheckbox.checked, false, `opening search via ${key} must close open drawer`);
  // Close search and verify inert restored.
  searchCheckbox.checked = false;
  searchCheckbox.dispatchEvent(new FakeEvent("change", { bubbles: true }));
  assert.strictEqual(searchInner.inert, true);
}

// 5. Typing `/`, `s`, or `f` inside an editable input must NOT trigger the shortcut.
const textInput = new FakeEl("input", { doc });
doc.activeElement = textInput;
const typingEv = new FakeEvent("keydown", { key: "s", target: textInput });
doc.dispatchEvent(typingEv);
assert.strictEqual(typingEv.defaultPrevented, false);
assert.strictEqual(searchCheckbox.checked, false);

// 6. Sidebar arrow keys, Home/End, and Space expand/collapse navigation.
sidebar.inert = false;
navLink.focus();
sidebar.dispatchEvent(new FakeEvent("keydown", { key: "ArrowDown", target: navLink }));
assert.strictEqual(doc.activeElement, groupLabel, "ArrowDown must move to next visible sidebar item");
// Space toggles collapsed group open.
sidebar.dispatchEvent(new FakeEvent("keydown", { key: " ", target: groupLabel }));
assert.strictEqual(groupToggle.checked, true, "Space must expand collapsed group");
// ArrowRight on open group enters first child; ArrowLeft returns to group label, then collapses.
sidebar.dispatchEvent(new FakeEvent("keydown", { key: "ArrowRight", target: groupLabel }));
assert.strictEqual(doc.activeElement, childLink, "ArrowRight on open group must focus first child");
sidebar.dispatchEvent(new FakeEvent("keydown", { key: "ArrowLeft", target: childLink }));
assert.strictEqual(doc.activeElement, groupLabel, "ArrowLeft on child must focus parent group label");
sidebar.dispatchEvent(new FakeEvent("keydown", { key: "ArrowLeft", target: groupLabel }));
assert.strictEqual(groupToggle.checked, false, "ArrowLeft on open group label must collapse it");
// ArrowDown skips collapsed child; Home returns to top.
sidebar.dispatchEvent(new FakeEvent("keydown", { key: "Home", target: groupLabel }));
assert.strictEqual(doc.activeElement, navLink, "Home must focus first visible sidebar item");

// 7. Scrollable tables get tabindex/role/label; pre > code is left to Material.
assert.strictEqual(scrollTable.getAttribute("tabindex"), "0");
assert.strictEqual(scrollTable.getAttribute("role"), "region");
assert.strictEqual(scrollTable.getAttribute("aria-label"), "Scrollable table");
assert.strictEqual(preCode.hasAttribute("role"), false);
"""
    completed = subprocess.run(
        [node, "-e", harness, str(script_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, (
        f"a11y.js runtime check failed:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
    )
