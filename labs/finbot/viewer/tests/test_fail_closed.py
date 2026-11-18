"""Final-review fix round: an error anywhere in a poll never leaves a verified mark standing (R1), and the four
minors M-1, M-3, M-4 and M-5 the final code review found."""
from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa",
                    reason="the pqc extra is not installed: uv run --extra pqc")

import beats  # noqa: E402
import model as model_module  # noqa: E402
from lab_lines import SESSION_A, SESSION_B, LabLogs, answer, decision_key, tool_request  # noqa: E402
from model import Model  # noqa: E402
from test_verify import flip_deny  # noqa: E402
from verify import KeySource  # noqa: E402


@pytest.fixture
def key(tmp_path):
    return decision_key(tmp_path / "decision-keys")


@pytest.fixture
def keys(key):
    return KeySource({"ACS_GUARDIAN_KEYS": str(key.document_path)})


def signed_session(logs, key, session_id=SESSION_A):
    a, b = tool_request("echo", session_id=session_id), tool_request("rm", session_id=session_id)
    logs.pair(a, key.sign(answer(a, "allow"), a))
    logs.pair(b, key.sign(answer(b, "deny"), b))


def marks(model, session_id=SESSION_A):
    return {r.tool: (r.decision, r.verify) for r in model.rows_after(0) if r.session_id == session_id}


def test_a_result_file_past_year_9999_never_stops_judging(tmp_path, key, keys, monkeypatch):
    # R1, the review's trigger. APFS can't hold such an mtime, so the listing hands result_row one, through the real
    # result_row path that raised ValueError: year 33658 is out of range.
    logs = LabLogs(tmp_path)
    signed_session(logs, key)
    model = Model(logs.transcript_dir, None, keys, verify_dir=logs.verify_dir)
    model.refresh()
    assert marks(model) == {"echo": ("allow", "verified"), "rm": ("deny", "verified")}
    record = {"kind": "forge", "algorithm": "ML-DSA-65", "result": "broken", "entry": 1, "detail": "x"}
    monkeypatch.setattr(beats, "result_files", lambda directory: [("far.json", (10**21, 10), record)])
    flip_deny(logs.transcript())
    model.refresh()
    assert marks(model) == {"echo": ("allow", "not_checked"), "rm": ("DENY", "failed")}
    assert model.paused is None


def test_a_failing_poll_drops_every_mark_until_a_poll_succeeds(tmp_path, key, keys, monkeypatch):
    # R1: when a poll fails as a whole, every mark drops to not checked, and the page says checks are paused and why.
    logs = LabLogs(tmp_path)
    signed_session(logs, key)
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()

    def broken(self):
        raise RuntimeError("disk\x1b[2J gone")

    monkeypatch.setattr(Model, "_judge", broken)
    model.refresh()
    assert {verify for _, verify in marks(model).values()} == {"not_checked"}
    assert model.paused == "checks paused: RuntimeError: disk\\x1b[2J gone"
    monkeypatch.undo()
    model.refresh()
    assert {verify for _, verify in marks(model).values()} == {"verified"}
    assert model.paused is None


def test_one_failing_session_affects_only_itself(tmp_path, key, keys, monkeypatch):
    # R1: a session whose read raises loses its marks, and every other session is still read and judged that poll.
    logs = LabLogs(tmp_path)
    signed_session(logs, key, SESSION_A)
    signed_session(logs, key, SESSION_B)
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    real = model_module.LogTail.read_new

    def read_new(self):
        if self.path.stem == SESSION_B:
            raise OSError("bad sector")
        return real(self)

    monkeypatch.setattr(model_module.LogTail, "read_new", read_new)
    os.utime(logs.transcript(SESSION_B), ns=(5, 5))
    flip_deny(logs.transcript(SESSION_A))
    model.refresh()
    assert marks(model, SESSION_A) == {"echo": ("allow", "not_checked"), "rm": ("DENY", "failed")}
    assert {verify for _, verify in marks(model, SESSION_B).values()} == {"not_checked"}
    assert model.paused is None


class _VanishedEntry:
    """A listing entry whose file is deleted between scandir and its stat (review M-1, probe p1)."""

    name = "vanished.jsonl"
    path = "/nonexistent/vanished.jsonl"

    def is_file(self, follow_symlinks=True):
        return True

    def stat(self, follow_symlinks=True):
        raise FileNotFoundError(self.path)


def test_a_file_vanishing_during_the_listing_drops_nothing_else(tmp_path, key, keys, monkeypatch):
    logs = LabLogs(tmp_path)
    signed_session(logs, key)
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()
    ids = sorted(r.id for r in model.rows_after(0))
    real = os.scandir
    monkeypatch.setattr(model_module.os, "scandir", lambda path: list(real(path)) + [_VanishedEntry()])
    model.refresh()
    assert sorted(r.id for r in model.rows_after(0)) == ids
    assert model.drops() == []


def test_an_unreadable_directory_forgets_nothing(tmp_path, key, keys, monkeypatch):
    logs = LabLogs(tmp_path)
    signed_session(logs, key)
    model = Model(logs.transcript_dir, None, keys)
    model.refresh()

    def denied(path):
        raise PermissionError(path)

    monkeypatch.setattr(model_module.os, "scandir", denied)
    model.refresh()
    assert len(model.rows_after(0)) == 2 and model.drops() == []


def test_a_replaced_audit_log_does_not_add_its_rows_twice(tmp_path):
    # Review M-3, probe p5: the audit tail restarts, so the rows it made go, and the log is read again once.
    logs = LabLogs(tmp_path)
    logs.audit("ask_pending", session_id=SESSION_A, request_id="r1", tool="pay", approver="lab-approver")
    logs.audit("replay_miss", cause="no_recording", step=1, branch="main", stream=False)
    model = Model(logs.transcript_dir, logs.audit_file, None)
    model.refresh()
    assert sorted(r.method for r in model.rows_after(0)) == ["ask_pending", "model call"]
    copy = logs.audit_file.with_suffix(".new")
    copy.write_bytes(logs.audit_file.read_bytes())
    os.replace(copy, logs.audit_file)
    model.refresh()
    assert sorted(r.method for r in model.rows_after(0)) == ["ask_pending", "model call"]
    drop = model.drops()[-1]
    assert (drop["source"], drop["session_id"]) == ("audit", None)
    assert drop["why"] == "the audit log was replaced or cut shorter, so it is read again"
