"""The module had no test file, so three of its defects shipped unnoticed."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import verify_published as vp


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    """Six attempts at ten seconds each would make this suite a minute slower."""
    calls = []
    monkeypatch.setattr(vp.time, "sleep", lambda seconds: calls.append(seconds))
    return calls


def test_a_non_object_body_is_not_retried(monkeypatch, no_sleeping):
    """It parsed and it is wrong. Waiting cannot change that, and .get would raise."""
    monkeypatch.setattr(vp, "fetch", lambda url: ["not", "an", "object"])
    with pytest.raises(SystemExit, match="not a JSON object"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert no_sleeping == []


def test_a_decoding_failure_is_retried(monkeypatch, no_sleeping):
    def boom(url):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(vp, "fetch", boom)
    with pytest.raises(SystemExit, match="never became available"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert len(no_sleeping) == vp.ATTEMPTS - 1, "no sleep after the final attempt"


def test_a_wrong_id_reports_what_was_served(monkeypatch, no_sleeping):
    monkeypatch.setattr(vp, "fetch", lambda url: {"$id": "https://elsewhere/x.json"})
    with pytest.raises(SystemExit, match="serves \\$id"):
        vp.check("https://example.com", "v0.1.0/a.json")


def test_paths_come_from_the_schema_tree(tmp_path):
    """Two hardcoded paths in two workflows left 42 of 44 URIs unchecked."""
    base = "https://genai-security-project.github.io/agent-control-standard/schema/"
    src = tmp_path / "spec"
    (src / "v0.1.0" / "hooks").mkdir(parents=True)
    for rel in ("v0.1.0/a.json", "v0.1.0/hooks/b.json"):
        (src / rel).write_text(json.dumps({"$id": base + rel}))
    assert vp.paths_from(src) == ["v0.1.0/a.json", "v0.1.0/hooks/b.json"]
