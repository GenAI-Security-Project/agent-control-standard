"""Guards on the two theme partial overrides that put the shared pane on the docs site.

Each override is a copy of an installed Material partial plus a small change. The
installed copy, the override, and the unified diff between them are all committed, so
a theme bump can replay the change onto the new partial instead of a person redoing it
by eye. These tests hold the three in step and pin the tool that replays the diff.

The two rows the nav override emits by hand must equal the byte contract in
tests/test_site_nav_walk.py, because the pane walkers were written against it.
"""
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tests"))

import rederive_overrides  # noqa: E402
import site_nav  # noqa: E402
from rederive_overrides import PARTIALS, UPSTREAM, apply_diff, installed_partial, record_diff  # noqa: E402
from _docs_build import DOCS_BASE  # noqa: E402
from render_landing import read_nav_config  # noqa: E402
from test_site_nav_walk import EXTERNAL_SECTION_ROW, HOME_CONTAINER_ROW  # noqa: E402

FIXTURE_ROOT = "https://example.org/agent-control-standard/"
OVERRIDES = REPO / "overrides" / "partials"
NAV = read_nav_config(REPO / "mkdocs.yml")


def _collapse(markup: str) -> str:
    return " ".join(markup.split())


def _li_block(markup: str, toggle_id: str) -> str:
    """Return the whole li element whose own toggle input carries toggle_id."""
    toggle = markup.index(f'id="{toggle_id}"')
    start = markup.rindex("<li ", 0, toggle)
    depth = 0
    for match in re.compile(r"<li[\s>]|</li>").finditer(markup, start):
        depth += 1 if match.group(0).startswith("<li") else -1
        if depth == 0:
            return markup[start:match.end()]
    raise AssertionError(f"li for {toggle_id} never closes")


def _expand_children(fixture: str, entries: list[tuple[str, str]]) -> str:
    """Swap the fixture's single child row for one row per configured entry."""
    child = next(line for line in fixture.splitlines() if line.lstrip().startswith('<li class="md-nav__item"><a'))
    href = re.search(r'href="([^"]+)"', child).group(1)
    title = re.search(r'<span class="md-ellipsis">([^<]+)</span>', child).group(1)
    rows = [child.replace(f'href="{href}"', f'href="{url}"').replace(f">{title}<", f">{label}<")
            for label, url in entries]
    return fixture.replace(child, "\n".join(rows))


@pytest.mark.parametrize(("page", "root"), [
    ("index.html", "./.."),
    ("concepts/agents/index.html", "../../.."),
    ("404.html", "/agent-control-standard/docs/.."),
])
def test_override_rows_equal_the_task_1_fixtures(built_docs, page, root):
    markup = (built_docs / page).read_text(encoding="utf-8")

    home = _expand_children(HOME_CONTAINER_ROW, [(s["title"], f"{root}#{s['anchor']}") for s in NAV.landing_sections])
    home = home.replace(f'href="{FIXTURE_ROOT}"', f'href="{root}"')
    external = _expand_children(EXTERNAL_SECTION_ROW, [(r["title"], r["url"]) for r in NAV.external_resources])

    assert _collapse(_li_block(markup, "__nav_home")) == _collapse(home)
    assert _collapse(_li_block(markup, "__nav_ext")) == _collapse(external)


def test_only_the_current_page_link_is_marked_current(built_docs):
    page = built_docs / "concepts" / "agents" / "index.html"
    marked = site_nav.aria_current_links(page.read_text(encoding="utf-8"))
    assert marked == [("a", "./")], marked


def test_upstream_copies_equal_the_installed_partials():
    for name in PARTIALS:
        committed = (REPO / UPSTREAM / name).read_text(encoding="utf-8")
        installed = installed_partial(name).read_text(encoding="utf-8")
        delta = record_diff(committed, installed, name)
        assert not delta, (
            f"The installed Material {name} differs from overrides/.upstream/partials/{name}:\n"
            f"{delta}\nRun `uv run python tools/rederive_overrides.py`, read the delta it prints, "
            f"then run `uv run python tools/rederive_overrides.py --accept-delta <hex>`."
        )


def test_recorded_diffs_equal_difflib_of_upstream_and_override():
    for name in PARTIALS:
        upstream = (REPO / UPSTREAM / name).read_text(encoding="utf-8")
        override = (OVERRIDES / name).read_text(encoding="utf-8")
        recorded = (REPO / UPSTREAM / f"{name}.diff").read_text(encoding="utf-8")
        assert recorded == record_diff(upstream, override, name), (
            f"{name} was edited without re-recording. Run `uv run python tools/rederive_overrides.py --record`."
        )
        assert recorded, f"{name} override is identical to upstream, so it overrides nothing"


def test_override_source_has_no_nav_literals():
    """The pane's content lives in mkdocs.yml. A copy in a template drifts silently."""
    for name in PARTIALS:
        source = (OVERRIDES / name).read_text(encoding="utf-8")
        for literal in ("#problem", "owasp.slack.com", "Roadmap"):
            assert literal not in source, f"{literal} is hard-coded in overrides/partials/{name}"


def test_override_jinja_uses_no_python_method_call():
    """A Python method call renders under Jinja2 but not under MiniJinja, which Zensical
    uses. The added lines are what this project wrote, so they are what is checked."""
    for name in PARTIALS:
        diff = (REPO / UPSTREAM / f"{name}.diff").read_text(encoding="utf-8")
        added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
        for line in added:
            for expression in re.findall(r"\{\{.*?\}\}|\{%.*?%\}", line):
                assert not re.search(r"\.\w+\s*\(", expression), f"{name}: {expression}"


def _scratch_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    shutil.copytree(REPO / "overrides", root / "overrides")
    return root


def _fake_installed(tmp_path: Path) -> Path:
    installed = tmp_path / "installed"
    installed.mkdir()
    for name in PARTIALS:
        shutil.copyfile(installed_partial(name), installed / name)
    return installed


def _run(root: Path, *extra: str, installed: Path | None = None) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(REPO / "tools" / "rederive_overrides.py"), "--root", str(root)]
    if installed is not None:
        argv += ["--installed", str(installed)]
    return subprocess.run([*argv, *extra], capture_output=True, text=True, timeout=120)


def _snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_rederive_record_writes_the_copies_and_diffs(tmp_path):
    root = _scratch_root(tmp_path)
    shutil.rmtree(root / UPSTREAM)
    result = _run(root, "--record")
    assert result.returncode == 0, result.stderr
    for name in PARTIALS:
        assert (root / UPSTREAM / name).read_bytes() == installed_partial(name).read_bytes()
        assert (root / UPSTREAM / f"{name}.diff").read_bytes() == (REPO / UPSTREAM / f"{name}.diff").read_bytes()


def test_record_refuses_to_rebaseline_a_changed_upstream(tmp_path):
    root = _scratch_root(tmp_path)
    installed = _fake_installed(tmp_path)
    nav = installed / "nav.html"
    nav.write_text(nav.read_text(encoding="utf-8") + "{#- an upstream change -#}\n", encoding="utf-8")
    # A hand edit too, so a write of either the copy or the diff would show.
    override = root / "overrides" / "partials" / "nav-item.html"
    override.write_text(override.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    before = _snapshot(root)

    result = _run(root, "--record", installed=installed)
    assert result.returncode == 1
    assert "nav.html" in result.stderr
    assert "--accept-delta" in result.stderr
    assert _snapshot(root) == before


def test_record_rerecords_the_diff_from_the_committed_copy(tmp_path):
    root = _scratch_root(tmp_path)
    installed = _fake_installed(tmp_path)
    override = root / "overrides" / "partials" / "nav-item.html"
    edited = override.read_text(encoding="utf-8") + "{#- a hand edit -#}\n"
    override.write_text(edited, encoding="utf-8")
    copies = {name: (root / UPSTREAM / name).read_bytes() for name in PARTIALS}

    result = _run(root, "--record", installed=installed)
    assert result.returncode == 0, result.stderr
    for name in PARTIALS:
        assert (root / UPSTREAM / name).read_bytes() == copies[name]
    upstream = (root / UPSTREAM / "nav-item.html").read_text(encoding="utf-8")
    assert (root / UPSTREAM / "nav-item.html.diff").read_text(encoding="utf-8") == record_diff(
        upstream, edited, "nav-item.html")
    assert "+{#- a hand edit -#}" in (root / UPSTREAM / "nav-item.html.diff").read_text(encoding="utf-8")


def test_rederive_reproduces_the_override(tmp_path):
    assert not tmp_path.resolve().is_relative_to(REPO)
    for name in PARTIALS:
        out = tmp_path / name
        apply_diff(REPO / UPSTREAM / name, REPO / UPSTREAM / f"{name}.diff", out)
        assert out.read_bytes() == (OVERRIDES / name).read_bytes()


def test_rederive_ignores_an_inherited_git_dir(tmp_path, monkeypatch):
    """A git hook exports GIT_DIR. Inherited, it points git apply at another repository
    and loads that repository's config. The config here is broken on purpose, so git
    exits fatally if it reads it, which proves the scratch run never looked there."""
    other = tmp_path / "other"
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    with open(other / ".git" / "config", "a", encoding="utf-8") as config:
        config.write("[core\n")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_INDEX_FILE", str(other / ".git" / "index"))
    for name in PARTIALS:
        out = tmp_path / "out" / name
        apply_diff(REPO / UPSTREAM / name, REPO / UPSTREAM / f"{name}.diff", out)
        assert out.read_bytes() == (OVERRIDES / name).read_bytes()
    assert [path.name for path in other.iterdir()] == [".git"]


def _accept_hex(result: subprocess.CompletedProcess) -> str:
    match = re.search(r"--accept-delta ([0-9a-f]{64})", result.stdout)
    assert match, result.stdout
    return match.group(1)


def test_rederive_refuses_a_context_change(tmp_path):
    root = _scratch_root(tmp_path)
    installed = _fake_installed(tmp_path)
    # A line the nav.html hunk carries as context, edited in place, so the hunk cannot
    # find its anchor anywhere in the file.
    nav = installed / "nav.html"
    text = nav.read_text(encoding="utf-8")
    assert text.count("{% for nav_item in nav.items %}") == 1
    nav.write_text(text.replace("{% for nav_item in nav.items %}", "{% for nav_item in nav.children %}"), encoding="utf-8")

    first = _run(root, installed=installed)
    assert first.returncode == 2, first.stdout + first.stderr
    before = _snapshot(root)
    second = _run(root, "--accept-delta", _accept_hex(first), installed=installed)
    assert second.returncode != 0
    assert "nav.html" in second.stderr
    assert _snapshot(root) == before


def test_rederive_applies_an_offset_only_change(tmp_path):
    root = _scratch_root(tmp_path)
    installed = _fake_installed(tmp_path)
    # A line inserted between two hunks shifts the later one without touching any
    # line a hunk carries. git apply finds it at the new offset. A line above the first
    # hunk would not do, because a hunk that starts at line 1 is anchored there.
    gap = '  </label>\n  {% if config.repo_url %}\n'
    shifted = '  </label>\n  {#- an upstream comment line -#}\n  {% if config.repo_url %}\n'
    nav = installed / "nav.html"
    text = nav.read_text(encoding="utf-8")
    assert text.count(gap) == 1
    nav.write_text(text.replace(gap, shifted), encoding="utf-8")

    first = _run(root, installed=installed)
    assert first.returncode == 2
    second = _run(root, "--accept-delta", _accept_hex(first), installed=installed)
    assert second.returncode == 0, second.stderr
    override = (root / "overrides" / "partials" / "nav.html").read_text(encoding="utf-8")
    assert override == (OVERRIDES / "nav.html").read_text(encoding="utf-8").replace(gap, shifted)
    assert (root / UPSTREAM / "nav.html").read_bytes() == nav.read_bytes()
    assert (root / UPSTREAM / "nav.html.delta").read_text(encoding="utf-8")
    assert (root / UPSTREAM / "nav.html.diff").read_text(encoding="utf-8") == record_diff(
        nav.read_text(encoding="utf-8"), override, "nav.html")


def test_rederive_refuses_an_unaccepted_delta_and_writes_nothing(tmp_path):
    root = _scratch_root(tmp_path)
    installed = _fake_installed(tmp_path)
    item = installed / "nav-item.html"
    item.write_text(item.read_text(encoding="utf-8") + "{#- appended upstream -#}\n", encoding="utf-8")
    before = _snapshot(root)

    absent = _run(root, installed=installed)
    assert absent.returncode == 2
    assert "+{#- appended upstream -#}" in absent.stdout
    expected = hashlib.sha256(rederive_overrides.render_deltas(
        {"nav-item.html": record_diff((REPO / UPSTREAM / "nav-item.html").read_text(encoding="utf-8"),
                                      item.read_text(encoding="utf-8"), "nav-item.html")}).encode()).hexdigest()
    assert _accept_hex(absent) == expected

    wrong = _run(root, "--accept-delta", "0" * 64, installed=installed)
    assert wrong.returncode == 2
    assert _snapshot(root) == before


def test_rederive_exits_one_when_nothing_changed(tmp_path):
    root = _scratch_root(tmp_path)
    before = _snapshot(root)
    result = _run(root, installed=_fake_installed(tmp_path))
    assert result.returncode == 1
    assert "installed partials equal the committed copies, nothing to re-derive" in result.stdout + result.stderr
    assert _snapshot(root) == before
