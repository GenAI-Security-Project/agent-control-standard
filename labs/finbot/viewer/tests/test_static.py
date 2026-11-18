"""Static checks on the page: text only, no motion, large type, nothing from another origin, a label per beat."""
from __future__ import annotations

import re

from beats import BEATS
from conftest import VIEWER_DIR

STATIC = VIEWER_DIR / "static"


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_no_inner_html():
    script = read("app.js")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                   "setTimeout(\"", "setInterval("):
        assert banned not in script, banned
    assert "textContent" in script


def test_no_animation_or_transition():
    style = read("style.css")
    for banned in ("animation", "transition", "@keyframes", "smooth"):
        assert banned not in style, banned
    assert "smooth" not in read("app.js")


def test_root_font_is_large():
    match = re.search(r"html\s*\{[^}]*font-size:\s*(\d+)px", read("style.css"))
    assert match and int(match.group(1)) >= 20


def test_no_external_fetch():
    for name in ("index.html", "app.js", "style.css"):
        text = read(name)
        assert "http://" not in text and "https://" not in text and "//" + "cdn" not in text, name


def test_every_beat_has_a_label():
    script = read("app.js")
    for beat in BEATS:
        assert re.search(rf"\b{beat}:\s*\"[^\"]+\"", script), beat
    # The page indexes beats in A.12 order, the order the paint log's step numbers use.
    listed = re.search(r"const BEATS = \[([^\]]*)\]", script)
    assert listed and [b.strip().strip('"') for b in listed.group(1).split(",") if b.strip()] == list(BEATS)


def test_page_loads_only_its_own_files():
    page = read("index.html")
    assert re.findall(r'(?:src|href)="([^"]+)"', page) == ["/static/style.css", "/static/app.js"]
    assert "<script>" not in page and "style=" not in page


def test_decision_class_comes_from_a_fixed_set():
    # M6: a decision string from a log never becomes part of a class name as it is.
    script = read("app.js")
    assert '"d-" + row.decision' not in script and "'d-' + row.decision" not in script
    assert re.search(r"const DECISION_CLASSES = \{[^}]*allow: \"d-allow\"", script)


def test_page_caps_its_rows():
    match = re.search(r"const MAX_DOM_ROWS = (\d+);", read("app.js"))
    assert match and 0 < int(match.group(1)) <= 2000


def test_page_shows_the_applied_decision_beside_the_signed_one():
    script = read("app.js")
    assert "row.applied" in script and "row.conflict" in script
