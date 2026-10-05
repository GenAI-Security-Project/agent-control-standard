"""Tests for the roadmap.json build step and its failure table.

The rule under test: the roadmap never stops a schema from publishing or a pull request
from merging. Only a pull request whose committed fixture breaks, or a nightly refresh that
would replace the page the site already serves for this commit, may fail the build.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from build_roadmap_data import published_commit, run  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "roadmap-data.json"
NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def args(tmp_path, **kw) -> argparse.Namespace:
    data = tmp_path / "data.json"
    if "data" in kw:
        data.write_text(kw.pop("data"))
    base = dict(
        data=str(data), fixture=str(FIXTURE), out=str(tmp_path / "site" / "roadmap" / "roadmap.json"),
        repo_root=str(REPO_ROOT), event="push", source="", preview="", render_enabled="true",
        commit="abc", run="1", published_url="https://example.invalid/roadmap/roadmap.json", summary=None,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def out(ns) -> dict:
    return json.loads(Path(ns.out).read_text())


def opener_returning(commit):
    def opener(request, timeout):
        if commit is None:
            raise urllib.error.HTTPError(request.full_url, 404, "nf", {}, None)
        return io.BytesIO(json.dumps({"commit": commit}).encode())
    return opener


def test_pull_request_renders_the_fixture(tmp_path):
    ns = args(tmp_path, event="pull_request", render_enabled="false")
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    doc = out(ns)
    assert doc["status"] == "ok"
    states = {m["number"]: m["state"] for m in doc["milestones"]}
    assert states == {1: "in_progress", 2: "ongoing", 3: "deferred", 4: "withdrawn", 5: "planning"}
    reasons = {m["number"]: m["unverified_reasons"] for m in doc["milestones"]}
    assert reasons[5] == {"200": "untrusted_closer", "201": "not_on_main"}
    assert reasons[1] == {}


def test_switch_off_writes_disabled(tmp_path):
    ns = args(tmp_path, render_enabled="false")
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "disabled" and out(ns)["milestones"] == []


def test_preview_overrides_the_switch(tmp_path):
    ns = args(tmp_path, render_enabled="false", preview="true", data=FIXTURE.read_text())
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "ok"


@pytest.mark.parametrize("source", ["", "manual"])
def test_data_failure_degrades_outside_nightly(tmp_path, source):
    ns = args(tmp_path, source=source, data=json.dumps({"status": "failed", "class": "rate_limit"}))
    assert run(ns, opener=opener_returning("abc"), now=NOW) == 0
    assert out(ns)["status"] == "unavailable" and out(ns)["reason"] == "rate_limit"


def test_nightly_fails_when_site_already_serves_this_commit(tmp_path):
    ns = args(tmp_path, source="nightly", data=json.dumps({"status": "failed", "class": "server"}))
    assert run(ns, opener=opener_returning("abc"), now=NOW) == 1


@pytest.mark.parametrize("published", [None, "older"])
def test_nightly_degrades_when_site_is_behind_or_unreadable(tmp_path, published):
    ns = args(tmp_path, source="nightly", data=json.dumps({"status": "failed", "class": "server"}))
    assert run(ns, opener=opener_returning(published), now=NOW) == 0
    assert out(ns)["status"] == "unavailable"


def test_missing_data_file_is_a_data_failure(tmp_path):
    ns = args(tmp_path)
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "unavailable" and out(ns)["reason"] == "missing"


def test_published_commit_tolerates_html_and_errors():
    url = "https://example.invalid/roadmap/roadmap.json"
    assert published_commit(url, opener=lambda r, timeout: io.BytesIO(b"<html>")) is None
    assert published_commit(url, opener=opener_returning(None)) is None
    assert published_commit(url, opener=opener_returning("x")) == "x"
    assert published_commit("not a url", opener=opener_returning("x")) is None


def test_odd_switch_value_warns(tmp_path, capsys):
    ns = args(tmp_path, render_enabled="yes")
    run(ns, opener=opener_returning(None), now=NOW)
    assert "::warning::" in capsys.readouterr().out


def test_data_path_that_is_a_directory_degrades(tmp_path):
    (tmp_path / "data.json").mkdir()
    ns = args(tmp_path)
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "unavailable"


def test_invalid_json_in_data_file_degrades(tmp_path):
    ns = args(tmp_path, data="{not json")
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "unavailable" and out(ns)["reason"] == "code_defect"


def test_governance_parse_failure_on_push_degrades(tmp_path, monkeypatch):
    import roadmap_model

    def boom(_text):
        raise ValueError("bad roster")

    monkeypatch.setattr(roadmap_model, "parse_governance", boom)
    ns = args(tmp_path, data=FIXTURE.read_text())
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["reason"] == "code_defect"


def test_unwritable_roadmap_json_returns_zero(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("file")
    for kw in ({"data": FIXTURE.read_text()}, {"render_enabled": "false"},
               {"data": json.dumps({"status": "failed", "class": "server"})}):
        ns = args(tmp_path, out=str(blocker / "roadmap.json"), **kw)
        assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert "::warning::Could not write roadmap.json (" in capsys.readouterr().out


def test_unwritable_summary_returns_zero(tmp_path, capsys):
    ns = args(tmp_path, data=FIXTURE.read_text(), summary=str(tmp_path / "no" / "such" / "summary.md"))
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["status"] == "ok"
    assert "::warning::Could not write the run summary" in capsys.readouterr().out


def test_pull_request_with_broken_fixture_fails(tmp_path):
    broken = tmp_path / "fixture.json"
    broken.write_text("{}")
    ns = args(tmp_path, event="pull_request", fixture=str(broken))
    with pytest.raises(Exception):
        run(ns, opener=opener_returning(None), now=NOW)


def test_nightly_code_defect_with_matching_commit_fails(tmp_path):
    ns = args(tmp_path, source="nightly", data="{not json")
    assert run(ns, opener=opener_returning("abc"), now=NOW) == 1


def test_summary_holds_only_integers_and_state_names(tmp_path):
    summary = tmp_path / "summary.md"
    ns = args(tmp_path, data=FIXTURE.read_text(), summary=str(summary))
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    rows = [l for l in summary.read_text().splitlines() if l.startswith("| ")][2:]
    assert len(rows) == 5
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[0].isdigit() and cells[1].replace("_", "").isalpha()
        assert all(c.isdigit() for c in cells[2:])


def test_unlisted_failure_class_becomes_unknown(tmp_path, capsys):
    evil = "server\n::error::injected"
    ns = args(tmp_path, data=json.dumps({"status": "failed", "class": evil}))
    assert run(ns, opener=opener_returning(None), now=NOW) == 0
    assert out(ns)["reason"] == "unknown"
    assert "injected" not in capsys.readouterr().out
