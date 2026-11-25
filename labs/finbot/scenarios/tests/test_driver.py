"""Tests for the scenario driver behind lab run and lab record (issue #589, LAB-16 Task 4). Run with:

    uv run --project adapters --locked --group test python -m pytest labs/finbot/scenarios/tests/test_driver.py -v

The driver runs in-process against fake_finbot: a fake FinBot, the gateway's admin port and its approver page, each on
a free loopback port. The fake writes the gateway's audit and model input lines through the gateway's own writers, and
each run record is read back through evidence.py, the reader every module check uses, so the record's shape is held to
that reader's contract here.
"""
from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fake_finbot import BUNDLE, FakeLab, FakeServers  # noqa: I001  (puts the driver, cli and checks on sys.path)

import driver  # noqa: E402
import evidence  # noqa: E402

SCENARIOS = BUNDLE / "scenarios"
RESULT_LINE = re.compile(r"^(DONE|NOT YET:)")


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.bundle = tmp_path / "bundle"
        for sub in ("state/secrets", "state/runs", "state/transcripts", "policy"):
            (self.bundle / sub).mkdir(parents=True)
        (self.bundle / ".env").write_text("ACS_LAB_MODE=enforce\nACS_UPSTREAM=replay\nACS_RESPONSE_SIGNING=ML-DSA-65\n"
                                          "LAB_PORT_VIEWER=18095\nLAB_PORT_APPROVER=18090\n", encoding="utf-8")
        (self.bundle / "policy" / "outbound_email.rego").write_text("package finbot\n", encoding="utf-8")
        (self.bundle / "policy" / "data.json").write_text('{"finbot_lab": {"vendor_domains": []}}\n',
                                                          encoding="utf-8")
        self.lab = FakeLab(self.bundle)
        (self.bundle / "state/secrets/admin.token").write_text(self.lab.admin_token + "\n", encoding="utf-8")
        (self.bundle / "state/secrets/approver.token").write_text(self.lab.approver_token + "\n", encoding="utf-8")
        self.servers = FakeServers(self.lab)
        monkeypatch.setenv("LAB_BUNDLE", str(self.bundle))
        monkeypatch.setenv("ACS_GATEWAY_ADMIN_HOST", "127.0.0.1")
        monkeypatch.setenv("ACS_GATEWAY_ADMIN_PORT", str(self.servers.port("admin")))
        monkeypatch.setenv("ACS_GATEWAY_ADMIN_TOKEN_FILE", str(self.bundle / "state/secrets/admin.token"))
        self.settings = driver.Settings(
            finbot_url=f"http://127.0.0.1:{self.servers.port('finbot')}",
            approver_port=self.servers.port("approver"),
            quiet_s=0.3, poll_s=0.05, done_timeout_s=10.0, end_wait_s=3.0, approver_wait_s=5.0,
            scenarios_dir=SCENARIOS)

    def run(self, capsys: pytest.CaptureFixture[str], *argv: str, **settings: Any) -> tuple[int, list[str]]:
        code = driver.main(list(argv), settings=replace(self.settings, **settings))
        out = capsys.readouterr().out
        return code, out.splitlines()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((self.bundle / "state/runs").glob("*.json"))]

    def runs(self) -> list[evidence.Run]:
        return evidence.Evidence(self.bundle).runs()


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = Harness(tmp_path, monkeypatch)
    yield h
    h.servers.close()


def _one_result_line(lines: list[str]) -> str:
    results = [line for line in lines if RESULT_LINE.match(line)]
    assert len(results) == 1, lines
    return results[0]


def test_driver_rule_runs_before_the_first_chat(harness, capsys):
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    lab = harness.lab
    register = lab.index("finbot", "POST", "/vendor/api/v1/vendors/register")
    chat = lab.index("finbot", "POST", "/vendor/api/v1/chat")
    clear = lab.index("finbot", "DELETE", "/vendor/api/v1/chat/history")
    first_epoch = lab.index("admin", "POST", "/epoch")
    assert -1 < first_epoch < chat and -1 < clear < chat
    # Ruling I1: setup, then quiet, then a fresh epoch, then the history clear, and only then the chat (P10).
    epochs = [i for i, s in enumerate(lab.seen) if s.server == "admin"]
    assert any(register < i < clear for i in epochs)
    after_register = [s.at for s in lab.seen if s.server == "admin"
                      and s.at > lab.seen[register].at]
    assert after_register and after_register[0] >= lab.seen[register].at + lab.background_s


def test_epoch_bumped_after_the_run(harness, capsys):
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    lab = harness.lab
    last_epoch = lab.index("admin", "POST", "/epoch", last=True)
    last_finbot = max(i for i, s in enumerate(lab.seen) if s.server == "finbot")
    assert last_epoch > last_finbot
    (record,) = harness.records()
    before, after = record["epoch"]
    assert after == lab.epoch and before < after
    # R9: the final bump ends the chat's session, and the run's window holds that session_ended line.
    (run,) = harness.runs()
    ended = [e["session_id"] for e in harness_audit(harness, run) if e["acs_audit_event"] == "session_ended"]
    assert lab.chat_sessions[0] in ended


def harness_audit(harness: Harness, run: evidence.Run) -> list[dict[str, Any]]:
    return evidence.Evidence(harness.bundle).audit(run)


def test_csrf_on_every_post_and_put(harness, capsys):
    code, lines = harness.run(capsys, "s6")
    assert code == 0, lines
    unsafe = [s for s in harness.lab.finbot_requests() if s.method in ("POST", "PUT", "DELETE", "PATCH")]
    assert {s.method for s in unsafe} >= {"POST", "PUT", "DELETE"}
    assert all(s.headers.get("x-csrf-token") == harness.lab.csrf for s in unsafe)
    assert all(s.status != 403 for s in harness.lab.finbot_requests())


def test_cookie_kept_across_calls(harness, capsys):
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    requests = harness.lab.finbot_requests()
    assert requests[0].path == "/api/session/status" and "cookie" not in requests[0].headers
    cookies = {s.headers.get("cookie") for s in requests[1:]}
    assert len(cookies) == 1 and None not in cookies
    # The fingerprint pin: the same three headers on every request, or FinBot swaps the namespace.
    fingerprints = {tuple(s.headers.get(h) for h in ("user-agent", "accept-language", "accept-encoding"))
                    for s in requests}
    assert len(fingerprints) == 1 and None not in next(iter(fingerprints))
    assert harness.lab.hijacks == 0
    (record,) = harness.records()
    assert record["finbot"]["namespace"] in harness.lab.namespaces.values()


def test_copilot_history_cleared_for_s6(harness, capsys):
    code, lines = harness.run(capsys, "s6")
    assert code == 0, lines
    lab = harness.lab
    clear = lab.index("finbot", "DELETE", "/admin/api/v1/copilot/history")
    chat = lab.index("finbot", "POST", "/admin/api/v1/copilot/chat")
    assert -1 < clear < chat
    assert lab.index("finbot", "DELETE", "/vendor/api/v1/chat/history") == -1
    # A fresh namespace has no server row, so the GET that creates it comes before the PUT (darklab api.py:87-95).
    get = lab.index("finbot", "GET", "/darklab/api/v1/supply-chain/servers/finmail")
    put = lab.index("finbot", "PUT", "/darklab/api/v1/supply-chain/servers/finmail/tools")
    assert -1 < get < put < chat
    assert "collector@exfil.example" in lab.overrides["finmail"]["send_email"]["description"]


def test_clean_skips_the_override(harness, capsys):
    code, lines = harness.run(capsys, "s6", "--clean")
    assert code == 0, lines
    assert harness.lab.index("finbot", "PUT", "/darklab/api/v1/supply-chain/servers/finmail/tools") == -1
    assert harness.lab.index("finbot", "POST", "/admin/api/v1/copilot/chat") > -1
    (record,) = harness.records()
    assert record["flags"] == {"answer": None, "clean": True}
    # A scenario with nothing to skip refuses --clean rather than run as if it had been clean.
    code, lines = harness.run(capsys, "s1", "--clean")
    assert code == 2 and _one_result_line(lines).startswith("NOT YET:")


def test_poisoned_run_records_its_model_input_span(harness, capsys):
    # lab pins keeps a poisoned run's lines out of the registry, so the record names them, setup included.
    code, lines = harness.run(capsys, "s6")
    assert code == 0, lines
    code, lines = harness.run(capsys, "s6", "--clean")
    assert code == 0, lines
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    poisoned, clean, benign = sorted(harness.records(), key=lambda r: r["model_input_span"][0])
    assert (poisoned["poisoned"], clean["poisoned"], benign["poisoned"]) == (True, False, False)
    log = (harness.bundle / "state" / "model-inputs.jsonl").read_bytes()
    for record in (poisoned, clean, benign):
        start, end = record["model_input_span"]
        assert start <= record["model_inputs"][0] and end == record["model_inputs"][1]
    # Each span starts where the run before it ended, so it holds setup's onboarding lines and the chat.
    assert poisoned["model_input_span"][0] == 0
    assert clean["model_input_span"][0] == poisoned["model_input_span"][1]
    start, end = poisoned["model_input_span"]
    held = [json.loads(line) for line in log[start:end].decode().splitlines()]
    assert any(b.get("agent") == "onboarding" for b in held) and any("message" in b for b in held)


def test_offsets_snap_to_the_last_complete_line(tmp_path):
    # The gateway may be mid-write when the driver reads a size. A span cut inside a line would hand pins half a
    # request, so each offset stops after the last newline.
    state = tmp_path / "state"
    state.mkdir()
    logs = driver.Logs(state)
    assert logs.offsets() == (0, 0)
    first = b'{"tools": []}\n'
    (state / "model-inputs.jsonl").write_bytes(first + b'{"tools": [{"type": "fun')
    (state / "audit.log").write_bytes(b"ACS_AUDIT {}\nACS_AUDIT {\"a\"")
    assert logs.offsets() == (len(b"ACS_AUDIT {}\n"), len(first))
    # A partial first line snaps to 0, and a line longer than one read chunk still snaps right.
    (state / "audit.log").write_bytes(b"ACS_AUDIT {")
    long = b'{"x": "' + b"y" * 200_000 + b'"}\n'
    (state / "model-inputs.jsonl").write_bytes(long + b'{"x": "' + b"z" * 150_000)
    assert logs.offsets() == (0, len(long))


def test_waits_for_done_and_times_out_as_not_yet(harness, capsys):
    harness.lab.background_s = 1.0
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines
    probe = harness.lab.index("finbot", "GET", "/vendor/api/v1/messages")
    # Quiet means no new model input line for quiet_s, so no probe runs while the onboarding agent still talks.
    assert harness.lab.seen[probe].at >= harness.lab.last_model_input + 0.3 - 0.05

    harness.lab.background_s = 30.0
    code, lines = harness.run(capsys, "s1", done_timeout_s=1.0)
    assert code == 1
    assert _one_result_line(lines).startswith("NOT YET:")
    newest = harness.runs()[0]
    assert newest.result == "timed_out"


def test_run_record_windows_cover_the_run(harness, capsys):
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    (run,) = harness.runs()
    assert run.scenario == "s3" and run.mode == "enforce" and run.signing == "ML-DSA-65" and run.upstream == "replay"
    assert run.result == "completed" and run.started <= run.ended
    assert run.policy_sha256 == evidence.policy_sha256(harness.bundle / "policy")
    ev = evidence.Evidence(harness.bundle)
    opened = [e["session_id"] for e in ev.audit(run) if e["acs_audit_event"] == "session_opened"]
    # The chat's session is the run's. The onboarding session from setup was closed before the window opened.
    assert opened == harness.lab.chat_sessions
    assert list(run.sessions) == harness.lab.chat_sessions
    inputs = ev.model_inputs(run)
    assert [i.get("message") for i in inputs if "message" in i] == [
        json.loads((SCENARIOS / "s3.json").read_text())["steps"][0]["message"]]
    assert not any(i.get("agent") == "onboarding" for i in inputs)


def test_evidence_snapshot_written(harness, capsys):
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines
    (record,) = harness.records()
    finbot = record["finbot"]
    assert finbot["vendor"]["id"] == 1
    assert finbot["evidence"]["inbox"] == harness.lab.inbox
    # The module 2 and 3 checks read the dead drop as the route's messages list, each message whole.
    assert finbot["evidence"]["dead_drop"] == harness.lab.dead_drop
    for message in finbot["evidence"]["dead_drop"]:
        assert {"to_addresses", "cc_addresses", "bcc_addresses", "created_at"} <= set(message)

    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    record = harness.records()[-1] if harness.records()[-1]["scenario"] == "s3" else harness.records()[0]
    assert record["finbot"]["evidence"]["reply"] == harness.lab.reply


def test_answer_answers_each_held_call_once(harness, capsys):
    """FinBot retried the rejected transfer in the s4a__reject recording, so a second call was held. --answer reject
    answers that one too, and it does not time out (2026-11-24, m4 took 4 min 41 s on the 240 s ask deadline)."""
    harness.lab.ask_on_invoice = True
    harness.lab.ask_again_on_reject = True
    code, lines = harness.run(capsys, "s4a", "--answer", "reject")
    assert code == 0, lines
    assert [a["choice"] for a in harness.lab.answers] == ["reject", "reject"]
    assert len({a["id"] for a in harness.lab.answers}) == 2
    assert all(choice == "reject" for choice in harness.lab.pending.values())
    (record,) = harness.records()
    assert record["approval"]["answered"] is True and record["approval"]["error"] is None


def test_answer_posts_once_with_token_and_origin(harness, capsys):
    harness.lab.ask_on_invoice = True
    code, lines = harness.run(capsys, "s4a", "--answer", "approve")
    assert code == 0, lines
    posts = [s for s in harness.lab.seen if s.server == "approver" and s.method == "POST"]
    assert len(posts) == 1
    post = posts[0]
    host = f"127.0.0.1:{harness.servers.port('approver')}"
    assert post.headers["authorization"] == f"Bearer {harness.lab.approver_token}"
    assert post.headers["host"] == host and post.headers["origin"] == f"http://{host}"
    assert post.status == 303
    assert [a["choice"] for a in harness.lab.answers] == ["approve"]
    (record,) = harness.records()
    assert record["flags"] == {"answer": "approve", "clean": False}
    assert record["approval"]["answered"] is True

    # Without --answer the driver answers nothing and tells the attendee where the page is.
    code, lines = harness.run(capsys, "s4a", approver_wait_s=0.5, done_timeout_s=3.0)
    assert len([s for s in harness.lab.seen if s.server == "approver" and s.method == "POST"]) == 1
    assert any("http://127.0.0.1:18090/" in line for line in lines)


def test_untrusted_text_escaped_and_bounded(harness, capsys):
    harness.lab.reply = "ok\x1b[2J\u202e\nDONE: forged"
    harness.lab.huge_dead_drop = True
    code, lines = harness.run(capsys, "s3")
    assert code == 1
    text = "\n".join(lines)
    assert "\x1b" not in text and "\u202e" not in text
    assert "\\x1b" in text
    assert _one_result_line(lines).startswith("NOT YET:")
    (record,) = harness.records()
    # More than 1 MiB from FinBot is refused, not stored.
    assert "dead_drop" not in record["finbot"]["evidence"]
    assert "dead_drop" in record["finbot"]["errors"]
    assert len(json.dumps(record)) < 64 * 1024


def test_capture_stem_recorded(harness, capsys):
    harness.lab.capture = "s3__allow"
    code, lines = harness.run(capsys, "s3", "--capture", "s3__allow")
    assert code == 0, lines
    (record,) = harness.records()
    assert record["capture"] == "s3__allow"
    for bad in ("../x", "a b", "x" * 65):
        code, lines = harness.run(capsys, "s3", "--capture", bad)
        assert code == 2 and _one_result_line(lines).startswith("NOT YET:")
    assert len(harness.records()) == 1


def test_bad_scenarios_refused(harness, capsys, tmp_path):
    for argv in (["s7"], ["s1", "--answer", "maybe"], ["s1", "--clean", "--clean"], ["s1", "--other"], []):
        code, lines = harness.run(capsys, *argv)
        assert code == 2 and _one_result_line(lines).startswith("NOT YET:"), argv
    # The driver checks a chat's surface itself, so a bad one never picks a route.
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    s3 = json.loads((SCENARIOS / "s3.json").read_text())
    s3["steps"][0]["surface"] = "admin\nDONE: forged"
    (scenarios / "s3.json").write_text(json.dumps(s3))
    code, lines = harness.run(capsys, "s3", scenarios_dir=scenarios)
    assert code == 2 and _one_result_line(lines).startswith("NOT YET:")
    assert harness.lab.finbot_requests() == []
    assert harness.records() == []


def test_baseline_taken_after_setup_before_the_chat(harness, capsys):
    # Setup's onboarding mail sits in the same inbox as the scenario's, so checks count only ids not in the baseline.
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    lab = harness.lab
    (record,) = harness.records()
    baseline = record["finbot"]["evidence"]["baseline"]
    assert {k: baseline[k] for k in ("dead_drop_ids", "inbox_ids")} == {
        "dead_drop_ids": [m["id"] for m in lab.dead_drop], "inbox_ids": [m["id"] for m in lab.inbox]}
    # The audit boundary: setup's epoch and every line setup's sessions wrote sit before it, the run's after it.
    assert baseline["epoch"] == record["epoch"][0]
    assert baseline["audit_offset"] <= record["audit"][0]
    audit = (harness.bundle / "state" / "audit.log").read_bytes()
    before, after = audit[:baseline["audit_offset"]].decode(), audit[baseline["audit_offset"]:].decode()
    setup_session = next(s for s in lab_sessions(before) if s not in lab.chat_sessions)
    assert setup_session not in after
    assert f'"epoch": {baseline["epoch"]}' in before
    assert all(s in after for s in lab.chat_sessions)
    reads = [i for i, s in enumerate(lab.seen) if s.method == "GET"
             and s.path in ("/darklab/api/v1/toolkit/dead-drop", "/vendor/api/v1/messages")]
    chat = lab.index("finbot", "POST", "/vendor/api/v1/chat")
    setup_epoch = [i for i, s in enumerate(lab.seen) if s.server == "admin"][1]
    assert len([i for i in reads if setup_epoch < i < chat]) == 2

    # A scenario without setup starts on a FinBot reset to empty volumes, so its baseline is empty by construction.
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines
    s1 = next(r for r in harness.records() if r["scenario"] == "s1")
    s1_baseline = s1["finbot"]["evidence"]["baseline"]
    assert (s1_baseline["dead_drop_ids"], s1_baseline["inbox_ids"]) == ([], [])
    assert s1_baseline["epoch"] == s1["epoch"][0] and s1_baseline["audit_offset"] <= s1["audit"][0]


def lab_sessions(audit_text: str) -> list[str]:
    ids = []
    for line in audit_text.splitlines():
        if line.startswith("ACS_AUDIT "):
            event = json.loads(line[len("ACS_AUDIT "):])
            if event["acs_audit_event"] == "session_opened":
                ids.append(event["session_id"])
    return ids


def test_transcript_sizes_recorded_at_start_and_end(harness, capsys):
    # Module 1 compares these two maps to show an off run changed no transcript, so they carry names and sizes only.
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    (record,) = harness.records()
    evidence_ = record["finbot"]["evidence"]
    before, after = evidence_["transcripts_before"], evidence_["transcripts_after"]
    directory = harness.bundle / "state" / "transcripts"
    assert after == {p.name: p.stat().st_size for p in directory.glob("*.jsonl")}
    chat = f"{harness.lab.chat_sessions[0]}.jsonl"
    assert chat not in before and chat in after
    setup = next(name for name in before)
    # Setup's session ended before the run started, so its transcript doesn't change during the run.
    assert after[setup] == before[setup]
    assert all(isinstance(v, int) for v in {**before, **after}.values())


def test_approver_watched_only_in_enforce(harness, capsys):
    # The gateway builds the approver page only in enforce mode (acs_gateway/app.py:155), so off and shadow runs
    # never call it, and its absence there isn't an error.
    env = harness.bundle / ".env"
    env.write_text(env.read_text().replace("ACS_LAB_MODE=enforce", "ACS_LAB_MODE=off"))
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines
    assert not [s for s in harness.lab.seen if s.server == "approver"]
    (record,) = harness.records()
    assert record["mode"] == "off" and record["approval"]["error"] is None
    code, lines = harness.run(capsys, "s4a", "--answer", "approve")
    assert code == 1
    assert "enforce" in _one_result_line(lines)


# ---------------------------------------------------------------------------------------------------------------------
# Fix round 1: the stored result agrees with the printed line, the quiet window, the watch, the end time
# ---------------------------------------------------------------------------------------------------------------------

def _set_env(harness: Harness, old: str, new: str) -> None:
    env = harness.bundle / ".env"
    env.write_text(env.read_text().replace(old, new))


NOT_YET_PATHS = {
    # path: (scenario and flags, the fake's switch, a word the error names)
    "replay miss": (["s3"], "replay_miss_on_chat", "recording"),
    "probe FinBot couldn't answer": (["s3"], "huge_dead_drop", "dead_drop"),
    "namespace moved": (["s3"], "move_namespace_after_chat", "namespace"),
    "no assistant reply": (["s3"], "no_assistant_reply", "reply"),
    "answer not posted": (["s4a", "--answer", "approve"], "approver_fails", "approver"),
    "approver watch failed": (["s1"], "approver_fails", "approver"),
}


@pytest.mark.parametrize("path", NOT_YET_PATHS)
def test_result_is_not_yet_when_the_driver_says_not_yet(harness, capsys, path):
    # Checks read the record, not the exit code, so a NOT YET run never stores completed (review C1).
    argv, switch, word = NOT_YET_PATHS[path]
    setattr(harness.lab, switch, True)
    harness.lab.ask_on_invoice = argv[0] == "s4a"
    code, lines = harness.run(capsys, *argv)
    assert code == 1, lines
    line = _one_result_line(lines)
    assert line.startswith("NOT YET:")
    (record,) = harness.records()
    assert record["result"] == "not_yet"
    assert isinstance(record["error"], str) and "\n" not in record["error"] and word in record["error"]
    assert record["error"] in line


def test_result_is_completed_only_on_done(harness, capsys):
    code, lines = harness.run(capsys, "s3")
    assert code == 0 and _one_result_line(lines).startswith("DONE")
    (record,) = harness.records()
    assert record["result"] == "completed" and record["error"] is None


def test_unreadable_approver_token_is_not_yet_in_enforce(harness, capsys):
    # Without the token a held call would read as quiet, so the run can't be called complete (review I1).
    (harness.bundle / "state/secrets/approver.token").unlink()
    code, lines = harness.run(capsys, "s1")
    assert code == 1
    (record,) = harness.records()
    assert record["result"] == "not_yet" and "approver token" in record["error"]


def test_watch_keeps_polling_through_a_failed_poll(harness, capsys):
    import threading
    harness.lab.approver_fails = True

    def recover() -> None:
        harness.lab.approver_fails = False

    threading.Timer(0.3, recover).start()
    code, lines = harness.run(capsys, "s1", done_timeout_s=3.0)
    approver_gets = [s for s in harness.lab.seen if s.server == "approver"]
    # It polled again after the failures, and the failure still makes the run NOT YET.
    assert any(s.status == 200 for s in approver_gets) and any(s.status == 500 for s in approver_gets)
    assert code == 1 and harness.records()[0]["result"] == "not_yet"


def test_quiet_window_follows_the_upstream(harness, capsys):
    # Ruling 2026-11-19 (review C2): replay gets the short window, live and capture runs the long one, and the
    # after-setup baseline waits on the same window.
    settings = {"quiet_s": None, "quiet_replay_s": 0.3, "quiet_live_s": 1.5}
    harness.lab.gap_s = 0.8
    harness.lab.background_s = 0.1
    _set_env(harness, "ACS_UPSTREAM=replay", "ACS_UPSTREAM=openai")
    code, lines = harness.run(capsys, "s3", **settings)
    assert code == 0, lines
    (record,) = harness.records()
    assert record["quiet_s"] == 1.5
    baseline_read = harness.lab.seen[harness.lab.index("finbot", "GET", "/darklab/api/v1/toolkit/dead-drop")].at
    assert baseline_read >= harness.lab.agent_done["onboarding"]

    _set_env(harness, "ACS_UPSTREAM=openai", "ACS_UPSTREAM=replay")
    harness.run(capsys, "s1", **settings)
    harness.lab.capture = "s1__off"
    harness.run(capsys, "s1", "--capture", "s1__off", **settings)
    by_capture = {r["capture"]: r["quiet_s"] for r in harness.records() if r["scenario"] == "s1"}
    assert by_capture == {None: 0.3, "s1__off": 1.5}


def test_held_call_keeps_the_run_open(harness, capsys):
    import threading
    import time
    harness.lab.ask_on_invoice = True
    answered: list[float] = []

    def person() -> None:
        # A person answers on the page after a while. The driver must not snapshot before that.
        time.sleep(1.2)
        for ask in list(harness.lab.pending):
            harness.lab.pending[ask] = "approve"
        answered.append(time.monotonic())

    threading.Thread(target=person, daemon=True).start()
    code, lines = harness.run(capsys, "s4a")
    probe = harness.lab.seen[harness.lab.index("finbot", "GET", "/vendor/api/v1/invoices/1")]
    assert answered and probe.at > answered[0]


@pytest.mark.parametrize("timed_out", [False, True])
def test_ended_recorded_after_the_snapshot(harness, capsys, timed_out):
    from datetime import datetime
    if timed_out:
        harness.lab.background_s = 30.0
    code, lines = harness.run(capsys, "s1", done_timeout_s=1.0 if timed_out else 10.0)
    (record,) = harness.records()
    assert record["result"] == ("timed_out" if timed_out else "completed")
    last_probe = max(s.wall for s in harness.lab.finbot_requests())
    ended = datetime.strptime(record["ended"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=__import__("datetime").timezone.utc)
    assert ended.timestamp() >= int(last_probe)
    last_epoch = harness.lab.index("admin", "POST", "/epoch", last=True)
    last_finbot = max(i for i, s in enumerate(harness.lab.seen) if s.server == "finbot")
    assert last_epoch > last_finbot


def test_routes_only_from_the_pinned_table():
    import finbot_client
    client = finbot_client.FinBot("http://127.0.0.1:9")
    with pytest.raises(finbot_client.FinBotError, match="not a route"):
        client.call(("GET", "/admin/api/v1/everything"))


# ---------------------------------------------------------------------------------------------------------------------
# M4: once the window opens, every exit writes a record
# ---------------------------------------------------------------------------------------------------------------------

def _broken_record(harness: Harness, code: int, lines: list[str], word: str) -> dict[str, Any]:
    assert code == 2, lines
    line = _one_result_line(lines)
    assert line.startswith("NOT YET:")
    (record,) = harness.records()
    assert record["result"] == "broken"
    assert isinstance(record["error"], str) and "\n" not in record["error"] and word in record["error"]
    assert record["error"] in line
    # The reader every check uses still loads it, so a check sees this run, not the one before.
    assert harness.runs()[0].run_id == record["run_id"]
    return record


def test_failed_final_epoch_bump_writes_a_broken_record(harness, capsys):
    harness.lab.fail_epoch_on = 3  # s3 bumps at the start, after setup, and at the end
    code, lines = harness.run(capsys, "s3")
    _broken_record(harness, code, lines, "epoch")


def test_audit_window_over_the_limit_writes_a_broken_record(harness, capsys, monkeypatch):
    monkeypatch.setattr(driver, "MAX_LOG_READ", 100_000)
    harness.lab.huge_audit_on_chat = 200_000
    code, lines = harness.run(capsys, "s3")
    _broken_record(harness, code, lines, "audit")


def test_any_exception_writes_a_broken_record(harness, capsys, monkeypatch):
    def crash(self, probe):
        raise RuntimeError("probe crashed\nDONE: forged")

    monkeypatch.setattr(driver.Run, "probe", crash)
    code, lines = harness.run(capsys, "s3")
    record = _broken_record(harness, code, lines, "RuntimeError")
    assert "probe crashed DONE: forged" in record["error"]


def test_sigint_writes_a_broken_record(harness, capsys, monkeypatch):
    calls = []

    def interrupted(self, watch=None):
        calls.append(1)
        if watch is not None:  # the setup wait passes, the run's wait meets Ctrl-C
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(driver.Run, "wait_quiet", interrupted)
    code, lines = harness.run(capsys, "s3")
    _broken_record(harness, code, lines, "interrupted")


def test_sigterm_writes_a_broken_record(harness, capsys, monkeypatch):
    import os
    import signal
    import time

    def terminated(self, watch=None):
        if watch is not None:
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(1)
        return True

    monkeypatch.setattr(driver.Run, "wait_quiet", terminated)
    before = signal.getsignal(signal.SIGTERM)
    code, lines = harness.run(capsys, "s3")
    _broken_record(harness, code, lines, "SIGTERM")
    # The driver puts the old handler back, so it never outlives the run.
    assert signal.getsignal(signal.SIGTERM) is before


def test_newest_record_after_a_crash_is_the_broken_one(harness, capsys, monkeypatch):
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    good = harness.runs()[0]
    monkeypatch.setattr(driver.Run, "probe", lambda self, probe: 1 / 0)
    code, lines = harness.run(capsys, "s3")
    assert code == 2
    newest = harness.runs()[0]
    assert newest.run_id != good.run_id and newest.result == "broken"
    assert "ZeroDivisionError" in newest.record["error"]


def test_record_written_atomically(harness, capsys, monkeypatch):
    import os
    synced = []
    real = os.fsync
    monkeypatch.setattr(driver.os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines
    # The file and its directory are both synced, and no temporary file is left beside the record.
    assert len(synced) >= 2
    assert [p.name for p in (harness.bundle / "state/runs").iterdir() if not p.name.endswith(".json")] == []


# ---------------------------------------------------------------------------------------------------------------------
# Fix round 2: a slow poll and a watch that outlives finish() (re-review I-R1, I-R2)
# ---------------------------------------------------------------------------------------------------------------------

def test_slow_approver_poll_never_lets_a_held_call_read_as_quiet(harness, capsys):
    # P7: once a call is held, the page answers after 1 s, past the quiet window, with no error. Each poll has a total
    # deadline under the quiet window, and a poll past it is a failed poll, so the run can't be called complete.
    harness.lab.ask_on_invoice = True
    harness.lab.approver_delay_s = 1.0
    code, lines = harness.run(capsys, "s4a", done_timeout_s=4.0)
    (record,) = harness.records()
    assert not (code == 0 or record["result"] == "completed"), lines
    # Polls that keep missing their deadline also keep the watch busy, so the run may time out rather than go quiet.
    # Either way it is short of complete, and the record names the approver page that missed its deadline.
    assert code == 1 and record["result"] in ("not_yet", "timed_out")
    assert "approver page" in record["approval"]["error"]


def test_watch_busy_while_a_poll_is_in_flight(harness):
    import threading
    watch = driver.ApprovalWatch(None, None, harness.settings)
    watch._poll_started()
    assert watch.busy()
    watch._poll_ended()
    assert not watch.busy()
    assert threading.active_count() >= 1


def test_watch_outliving_finish_is_not_yet(harness, capsys, monkeypatch):
    # P6: the page hangs past finish()'s join. The record must not say completed for an --answer never posted.
    import approver_client
    import time

    def hang(self):
        time.sleep(3.0)
        return []

    monkeypatch.setattr(approver_client.Approver, "waiting", hang)
    harness.lab.ask_on_invoice = True
    harness.lab.background_s = 0.1
    code, lines = harness.run(capsys, "s4a", "--answer", "approve", done_timeout_s=2.0)
    (record,) = harness.records()
    assert code == 1 and record["result"] in ("not_yet", "timed_out")
    assert record["approval"]["error"] and "didn't stop" in record["approval"]["error"]


def test_judge_flags_an_unposted_answer_without_an_error_string():
    record = {"result": "completed", "error": None, "replay_misses": 0, "sessions_unended": [],
              "finbot": {"errors": {}},
              "approval": {"answer": "approve", "answered": False, "error": None, "status": None}}
    code, _ = driver.judge(record)
    assert code == 1 and record["result"] == "not_yet" and "--answer" in record["error"]


# 2026-11-23 live sitting: a capture take ended while a slow live call had no recording line yet, so its replay ran
# short. A capture now stays open while a call it sent is unrecorded, up to inflight_max_s.

def _quiet_run(tmp_path, capture: bool, inflight, **settings):
    import types
    state = tmp_path / "state"
    state.mkdir()
    (state / "model-inputs.jsonl").write_text("", encoding="utf-8")
    run = types.SimpleNamespace(
        settings=driver.Settings(finbot_url="http://127.0.0.1:1", approver_port=1, quiet_s=0.2, poll_s=0.02,
                                 done_timeout_s=3.0, **settings),
        logs=driver.Logs(state), quiet_s=0.2)
    run.calls_in_flight = inflight
    return run


def test_a_capture_with_a_call_in_flight_is_not_quiet_until_it_is_recorded(tmp_path):
    import time
    started = time.monotonic()
    run = _quiet_run(tmp_path, True, lambda: 1 if time.monotonic() - started < 0.8 else 0, inflight_max_s=5.0)
    assert driver.Run.wait_quiet(run) is True
    assert time.monotonic() - started >= 0.8


def test_an_unrecorded_call_holds_a_capture_only_up_to_the_bound(tmp_path):
    import time
    started = time.monotonic()
    run = _quiet_run(tmp_path, True, lambda: 1, inflight_max_s=0.6)
    assert driver.Run.wait_quiet(run) is True
    assert 0.6 <= time.monotonic() - started < 2.0


def test_calls_in_flight_counts_input_lines_since_the_take_less_recording_lines(tmp_path):
    import types
    state = tmp_path / "state"
    state.mkdir()
    inputs = state / "model-inputs.jsonl"
    inputs.write_text('{"before": 1}\n', encoding="utf-8")
    start = inputs.stat().st_size
    with inputs.open("a", encoding="utf-8") as f:
        f.write('{"a": 1}\n{"b": 2}\n{"c": 3}\n')
    recording = tmp_path / "s1__off.jsonl"
    run = types.SimpleNamespace(logs=driver.Logs(state), capture_path=recording, capture_inputs_start=start)
    assert driver.Run.calls_in_flight(run) == 3                 # no recording file yet
    recording.write_text('{"x": 1}\n{"y": 2}\n', encoding="utf-8")
    assert driver.Run.calls_in_flight(run) == 1
    recording.write_text('{"x": 1}\n{"y": 2}\n{"z": 3}\n{"w": 4}\n', encoding="utf-8")
    assert driver.Run.calls_in_flight(run) == 0                 # a retried key never goes negative
    run.capture_path = None
    assert driver.Run.calls_in_flight(run) == 0                 # outside a capture nothing is in flight


# 2026-11-24 owner sitting: s1__off and s1__enforce share their first keys, so an off run replayed the enforce take's
# first answer. The driver now picks each replay run's recording from the manifest and the live policies.

def _policy_pack(harness: Harness, **variants: str) -> None:
    """The real policy pack in the harness bundle, with each named module's live file set to that variant."""
    import shutil
    policy = harness.bundle / "policy"
    shutil.copytree(SCENARIOS.parent / "policy", policy, dirs_exist_ok=True)
    modules = {m["id"]: m for m in json.loads((policy / "tools" / "modules.json").read_text())["modules"]}
    for module, variant in {"m3": "starter", "m4": "starter", "m5": "starter", "m6": "starter", **variants}.items():
        entry = modules[module]
        source = entry["variants"].get(variant, {}).get("file")
        if source:
            shutil.copyfile(policy / source, policy / entry["live"])


@pytest.mark.parametrize("argv, mode, policies, want", [
    (["s1"], "off", {}, "s1__off"),
    (["s1"], "enforce", {}, "s1__enforce"),
    (["s2"], "shadow", {}, "s2__off"),
    (["s3"], "enforce", {}, "s3__deny"),
    (["s3"], "enforce", {"m3": "solution"}, "s3__allow"),
    (["s2"], "enforce", {}, "s2__enforce"),
    (["s2"], "enforce", {"m3": "solution"}, "s2__fixed"),
    (["s2"], "enforce", {"m3": "solution", "m4": "solution", "m5": "solution", "m6": "solution"}, "s2__solutions"),
    (["s4a", "--answer", "approve"], "enforce", {"m3": "solution", "m4": "solution"}, "s4a__approve"),
])
def test_a_replay_run_selects_the_recording_its_manifest_row_names(harness, capsys, argv, mode, policies, want):
    _policy_pack(harness, **policies)
    _set_env(harness, "ACS_LAB_MODE=enforce", f"ACS_LAB_MODE={mode}")
    harness.lab.chat_done = True
    harness.run(capsys, *argv)
    assert harness.lab.replay_selected[0] == want and harness.lab.replay_selected[-1] is None
    assert harness.records()[-1]["replay"] == want


def test_a_run_no_row_settles_replays_from_its_own_scenarios_takes(harness, capsys):
    # No guide row runs s1 with an answer, so the gateway draws on s1's takes only, never another scenario's
    # (2026-11-24 premortem, C-08), and the selection is cleared after the run.
    code, lines = harness.run(capsys, "s1", "--answer", "approve")
    assert harness.lab.replay_selected == ["s1", None]
    assert any("replay draws on s1's recordings" in line for line in lines)
    assert harness.records()[-1]["replay"] is None


def test_a_capture_selects_no_replay(harness, capsys):
    harness.lab.capture = "s3__allow"
    harness.run(capsys, "s3", "--capture", "s3__allow")
    assert harness.lab.replay_selected == []


def test_a_learners_own_policy_still_settles_a_run_whose_recording_does_not_turn_on_policy(harness, capsys):
    # Review M1: a correct module 3 policy that is not the shipped solution byte for byte.
    _policy_pack(harness, m3="solution")
    live = harness.bundle / "policy" / "outbound_email.rego"
    live.write_text(live.read_text() + "\n# my own fix\n")
    harness.run(capsys, "s1")
    assert harness.lab.replay_selected[0] == "s1__enforce"


def test_s2_under_an_unknown_module_3_policy_replays_from_its_own_takes(harness, capsys):
    # s2 has a take per policy set (starter, module 3 fixed, every solution), so an unknown policy can't pick one.
    _policy_pack(harness, m3="solution")
    live = harness.bundle / "policy" / "outbound_email.rego"
    live.write_text(live.read_text() + "\n# my own fix\n")
    harness.run(capsys, "s2")
    assert harness.lab.replay_selected == ["s2", None]


def test_s3_with_an_unknown_policy_replays_from_its_own_takes(harness, capsys):
    # s3's deny and allow takes turn on module 3's policy, so an unknown policy can't pick one.
    _policy_pack(harness)
    live = harness.bundle / "policy" / "outbound_email.rego"
    live.write_text(live.read_text() + "\n# my own fix\n")
    harness.run(capsys, "s3")
    assert harness.lab.replay_selected == ["s3", None]


def test_a_gateway_with_no_replay_route_still_runs_every_recording(harness, capsys, monkeypatch):
    # Review M2: an older gateway answers 404 to /replay. A null selection changes nothing there.
    monkeypatch.setattr(harness.lab, "admin_token", harness.lab.admin_token)
    original = driver.Admin.select_replay

    def no_route(self, recording, pace=None):
        if recording is None:
            import io
            import urllib.error
            raise_404 = urllib.error.HTTPError(self.url, 404, "not found", {}, io.BytesIO(b""))
            monkeypatch.setattr(self._opener, "open", lambda *a, **k: (_ for _ in ()).throw(raise_404))
        return original(self, recording, pace)
    monkeypatch.setattr(driver.Admin, "select_replay", no_route)
    code, lines = harness.run(capsys, "s1")
    assert code == 0, lines


def _typist(harness: Harness, stop: Any, sent: list[dict[str, Any]]) -> None:
    """Stands in for the recording toolkit: reads each chat cue and posts it as FinBot's page would, with the cue's
    cookie and the driver's fingerprint headers, which ui/proxy.py adds for a browser."""
    import urllib.request

    import finbot_client
    cue_path = harness.bundle / "state" / "ui" / driver.CHAT_CUE
    done: tuple = ()
    while not stop.is_set():
        try:
            cue = json.loads(cue_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cue = None
        if cue and (cue["run"], cue["seq"]) != done:
            done = (cue["run"], cue["seq"])
            sent.append(cue)
            if cue.get("view"):
                # A view cue opens a page and types nothing, as acsrec.typist does.
                stop.wait(0.05)
                continue
            if cue.get("form"):
                # A form cue posts what FinBot's own form would: the onboarding form adds nothing the cue lacks, the
                # invoice form adds attachments (static/js/vendor/invoice.js:260-267).
                path = "/vendor/api/v1/vendors/register" if cue["form"] == "onboarding" else "/vendor/api/v1/invoices"
                body = dict(cue["fields"]) if cue["form"] == "onboarding" else {**cue["fields"], "attachments": []}
                headers = {**finbot_client.FINGERPRINT_HEADERS, "Content-Type": "application/json",
                           "X-CSRF-Token": harness.lab.csrf,
                           "Cookie": "; ".join(f"{c['name']}={c['value']}" for c in cue["cookies"])}
                request = urllib.request.Request(harness.settings.finbot_url + path, method="POST", headers=headers,
                                                 data=json.dumps(body).encode())
                with urllib.request.urlopen(request, timeout=10) as response:
                    response.read()
                stop.wait(0.05)
                continue
            path = "/vendor/api/v1/chat" if cue["surface"] == "vendor" else "/admin/api/v1/copilot/chat"
            headers = {**finbot_client.FINGERPRINT_HEADERS, "Content-Type": "application/json",
                       "X-CSRF-Token": harness.lab.csrf, "Cookie": "; ".join(f"{c['name']}={c['value']}" for c in cue["cookies"])}
            request = urllib.request.Request(harness.settings.finbot_url + path, method="POST", headers=headers,
                                             data=json.dumps({"message": cue["message"]}).encode())
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
        stop.wait(0.05)


def test_browser_chat_mode_cues_the_page_and_reads_the_reply(harness, capsys, monkeypatch):
    """2026-11-24 lab videos: with LAB_CHAT_IN_BROWSER=1 the message is typed into FinBot's page, so the driver cues it
    and never posts the chat itself. The run still completes on the reply FinBot's history holds."""
    import threading
    monkeypatch.setenv("LAB_CHAT_IN_BROWSER", "1")
    stop, sent = threading.Event(), []
    typist = threading.Thread(target=_typist, args=(harness, stop, sent), daemon=True)
    typist.start()
    try:
        code, lines = harness.run(capsys, "s3")
    finally:
        stop.set()
        typist.join(5)
    assert code == 0, lines
    # Setup's onboarding cues a view of the vendor dashboard, then the chat cues its page (2026-11-25).
    # Setup's onboarding is filled into FinBot's form, then the chat cues its page (2026-11-25).
    assert [(c["page"], c.get("form")) for c in sent] == [("/vendor/onboarding", "onboarding"),
                                                          ("/vendor/assistant", None)]
    assert sent[0]["message"] == "" and [c["name"] for c in sent[1]["cookies"]] == ["finbot_session", "agreedToRules"]
    assert harness.lab.registered_bodies[0]["phone"] == "" and "company_name" in harness.lab.registered_bodies[0]
    assert sent[1]["url"] == "http://localhost:8097"
    assert any("Type the message into FinBot's chat at http://localhost:8097/vendor/assistant" in line for line in lines)
    # One chat, the typist's, and the session never moved (a fingerprint mismatch would start a new namespace).
    assert sum(1 for s in harness.lab.seen if s.method == "POST" and s.path == "/vendor/api/v1/chat") == 1
    assert harness.lab.hijacks == 0
    cue_file = harness.bundle / "state" / "ui" / driver.CHAT_CUE
    assert cue_file.stat().st_mode & 0o077 == 0


def test_browser_chat_mode_with_no_typist_runs_short(harness, capsys, monkeypatch):
    monkeypatch.setenv("LAB_CHAT_IN_BROWSER", "1")
    code, lines = harness.run(capsys, "s3", done_timeout_s=1.0)
    assert code != 0, lines
    assert not any(s.method == "POST" and s.path == "/vendor/api/v1/chat" for s in harness.lab.seen)


def test_each_run_names_its_cues(harness, capsys, monkeypatch):
    """Two runs both cue seq 1. The run id tells them apart, so a typist types the second run's chat too."""
    import threading
    monkeypatch.setenv("LAB_CHAT_IN_BROWSER", "1")
    stop, sent = threading.Event(), []
    typist = threading.Thread(target=_typist, args=(harness, stop, sent), daemon=True)
    typist.start()
    try:
        first, _ = harness.run(capsys, "s3")
        second, _ = harness.run(capsys, "s3")
    finally:
        stop.set()
        typist.join(5)
    assert (first, second) == (0, 0)
    assert [c["seq"] for c in sent] == [1, 2, 1, 2] and len({c["run"] for c in sent}) == 2


def test_a_finbot_stall_after_setup_is_waited_out_once(harness, capsys, monkeypatch):
    """2026-11-24 intro take: FinBot's database locked after setup and a baseline read timed out. The driver waits
    for quiet again and retries once, and the run completes. Setup's vendor registration is not repeated."""
    import functools
    import finbot_client
    monkeypatch.setattr(driver.finbot_client, "FinBot", functools.partial(finbot_client.FinBot, timeout=0.5))
    harness.lab.stall_first_dead_drop_s = 1.5
    code, lines = harness.run(capsys, "s3")
    assert code == 0, lines
    assert any("waits for quiet again" in line for line in lines)
    assert sum(1 for s in harness.lab.seen if s.path == "/vendor/api/v1/vendors/register") == 1


def test_a_recording_with_a_pinned_pace_is_selected_with_it(harness, tmp_path):
    """2026-11-24 m4 takes: s4a's reject recording replays only at pace 0, which the manifest pins."""
    import shutil
    scen = tmp_path / "scen"
    shutil.copytree(SCENARIOS, scen, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    doc = json.loads((scen / "manifest.json").read_text(encoding="utf-8"))
    doc["replayPace"] = {"s4a__reject": 0, "bad": 3}
    (scen / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    run = driver.Run(driver.Args("s4a", "reject", False, None), {}, replace(harness.settings, scenarios_dir=scen),
                     harness.bundle)
    assert run.replay_pace("s4a__reject") == 0.0
    assert run.replay_pace("bad") is None and run.replay_pace("s1__off") is None and run.replay_pace(None) is None



def test_a_replay_miss_during_setup_fails_the_run(harness, capsys):
    """2026-11-24 premortem: m7's setup missed its recording on paced replay while the run read completed, because only
    the run's own window counted misses. A setup that got neutral replies is not the recorded run."""
    harness.lab.replay_miss_on_register = True
    code, lines = harness.run(capsys, "s3")
    assert code != 0, lines
    record = harness.records()[-1]
    assert record["setup_replay_misses"] == 1 and record["replay_misses"] == 0
    assert "had no recording in replay" in record["error"]


def _judged(**fields):
    record = {"result": "completed", "error": None, "replay_misses": 0, "setup_replay_misses": 0,
              "finbot": {"errors": {}}, "approval": {"answer": None, "answered": False, "error": None},
              "sessions_unended": [], **fields}
    return driver.judge(record), record


def test_setup_misses_pass_only_at_the_count_the_manifest_expects():
    """2026-11-24 m4 takes: s4a__reject was captured after FinBot's vendor onboarding, so every run of it misses the
    same 4 setup calls while its steps replay whole. Exactly that count passes. Any other fails, as before."""
    (code, _), record = _judged(setup_replay_misses=4, setup_replay_misses_expected=4)
    assert code == 0 and record["error"] is None
    for setup, expected in ((5, 4), (3, 4), (4, 0), (1, 0)):
        (code, _), record = _judged(setup_replay_misses=setup, setup_replay_misses_expected=expected)
        assert code != 0 and "had no recording in replay" in record["error"], (setup, expected)
    # A step miss always fails, whatever setup expects.
    (code, _), record = _judged(replay_misses=1, setup_replay_misses=4, setup_replay_misses_expected=4)
    assert code != 0


def test_the_manifest_names_expected_setup_misses_for_s4a_reject_only(harness, tmp_path):
    import shutil
    run = driver.Run(driver.Args("s4a", "reject", False, None), {}, harness.settings, harness.bundle)
    assert run.setup_misses_expected("s4a__reject") == 4
    assert run.setup_misses_expected("s4a__approve") == 0 and run.setup_misses_expected(None) == 0
    scen = tmp_path / "scenarios"
    shutil.copytree(SCENARIOS, scen, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    doc = json.loads((scen / "manifest.json").read_text(encoding="utf-8"))
    doc["setupMissesExpected"] = {"a": True, "b": -2, "c": "4", "d": 2.5}
    (scen / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    run = driver.Run(driver.Args("s4a", "reject", False, None), {}, replace(harness.settings, scenarios_dir=scen),
                     harness.bundle)
    assert [run.setup_misses_expected(k) for k in "abcd"] == [0, 0, 0, 0]


def test_an_invoice_run_in_browser_mode_fills_finbots_forms(harness, capsys, monkeypatch):
    """2026-11-25: s4a makes its invoice through FinBot's API, so with nothing typed FinBot's pane sat on its portal
    page through m4. The driver now cues a view of the vendor's invoices page after the invoice, and the dashboard
    after onboarding, so the video shows FinBot act."""
    import threading
    monkeypatch.setenv("LAB_CHAT_IN_BROWSER", "1")
    harness.lab.ask_on_invoice = True
    stop, sent = threading.Event(), []
    typist = threading.Thread(target=_typist, args=(harness, stop, sent), daemon=True)
    typist.start()
    try:
        code, lines = harness.run(capsys, "s4a", "--answer", "approve")
    finally:
        stop.set()
        typist.join(5)
    assert code == 0, lines
    assert [(c["page"], c.get("form")) for c in sent] == [("/vendor/onboarding", "onboarding"),
                                                          ("/vendor/invoices", "invoice")]
    assert all(c["message"] == "" for c in sent)
    assert harness.lab.invoice_bodies[0]["attachments"] == [] and harness.lab.invoice_bodies[0]["invoice_number"]
