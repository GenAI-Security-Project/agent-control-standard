"""The run record reader every module check reads through (issue #589, LAB-16).

Runs in the adapters environment with the pqc extra, since the fixtures write real audit, transcript and model input
lines and sign answers with a real ML-DSA-65 decision key:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_evidence.py -v
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import subprocess
import sys
import tokenize

import pytest

import fixtures
from fixtures import SESSION_A, SESSION_B, LabState, answer, sign_hmac, tool_request

import evidence  # noqa: E402  (fixtures put the checks directory on sys.path)
from evidence import Evidence, EvidenceError

FINGERPRINT = "sha256:" + "ef" * 32


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


def test_audit_window_bounds_reads(lab):
    lab.audit("session_opened", session_id=SESSION_B, epoch=0)
    start = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id=SESSION_A, epoch=1)
    lab.audit("decision", session_id=SESSION_A, decision="deny")
    end = lab.size(lab.audit_file)
    lab.audit("session_opened", session_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc", epoch=2)
    lab.model_input({"model": "before"})
    m_start = lab.size(lab.model_input_file)
    lab.model_input({"model": "inside"})
    m_end = lab.size(lab.model_input_file)
    lab.model_input({"model": "after"})
    lab.run_record("20261125T101500Z-s2", scenario="s2", audit=(start, end), model_inputs=(m_start, m_end))

    ev = Evidence(lab.root)
    run = ev.runs()[0]
    assert [(e["acs_audit_event"], e["session_id"]) for e in ev.audit(run)] == [
        ("session_opened", SESSION_A), ("decision", SESSION_A)]
    assert ev.model_inputs(run) == [{"model": "inside"}]

    # A window wider than the bound is refused rather than cut short, so a check never judges half a run.
    small = Evidence(lab.root, max_read=end - start - 1)
    with pytest.raises(EvidenceError, match="larger than"):
        small.audit(run)
    assert evidence.MAX_READ_BYTES == 8 * 1024 * 1024

    # A window the log no longer reaches, after lab reset, reads as empty rather than as some other run's lines.
    lab.run_record("20261125T101600Z-s2", scenario="s2", started="2026-11-25T10:16:00Z",
                   audit=(end * 10, end * 10 + 5))
    assert ev.audit(ev.runs()[0]) == []
    for bad in ([5, 1], [-1, 3], ["0", 3], [0], [True, 3]):
        lab.run_record("20261125T101700Z-s2", scenario="s2", started="2026-11-25T10:17:00Z", audit=bad)
        assert "20261125T101700Z-s2" not in [r.run_id for r in ev.runs()], bad


def test_torn_last_line_ignored(lab):
    lab.audit("session_opened", session_id=SESSION_A, epoch=1)
    lab.model_input({"model": "whole"})
    req = tool_request("send_email")
    lab.pair(req, sign_hmac(answer(req, "deny")))
    # A writer caught mid-line by the read: no newline yet, and the JSON cut short.
    for path, torn in ((lab.audit_file, 'ACS_AUDIT {"acs_audit_event": "decis'), (lab.model_input_file, '{"mod'),
                       (lab.transcript_path(), '{"dir":"req","env')):
        with path.open("a", encoding="utf-8") as f:
            f.write(torn)
    lab.run_record("20261125T101500Z-s1", audit=(0, lab.size(lab.audit_file)),
                   model_inputs=(0, lab.size(lab.model_input_file)))
    ev = Evidence(lab.root)
    run = ev.runs()[0]
    assert [e["acs_audit_event"] for e in ev.audit(run)] == ["session_opened"]
    assert ev.model_inputs(run) == [{"model": "whole"}]
    assert [line["dir"] for line in ev.transcript(SESSION_A)] == ["req", "resp"]
    # Only gateway session ids name a transcript file, so no argument walks out of state/transcripts.
    for bad in ("../secrets/hmac", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", ""):
        with pytest.raises(EvidenceError):
            ev.transcript(bad)
    assert ev.transcript(SESSION_B) == []


def test_runs_newest_first(lab):
    lab.run_record("20261125T101500Z-s2", scenario="s2", mode="off", started="2026-11-25T10:15:00Z")
    lab.run_record("20261125T111500Z-s2", scenario="s2", mode="enforce", started="2026-11-25T11:15:00Z")
    lab.run_record("20261125T103000Z-s3", scenario="s3", mode="enforce", started="2026-11-25T10:30:00Z")
    (lab.state / "runs" / "20261125T120000Z-s1.json").write_text("{not json", encoding="utf-8")
    (lab.state / "runs" / "20261125T120001Z-s1.json").write_text(json.dumps({"format": "other/1"}), encoding="utf-8")
    # A record whose run_id doesn't match its file name was copied or edited, so it isn't read as that run.
    lab.run_record("20261125T090000Z-s1", started="2026-11-25T13:00:00Z").rename(
        lab.state / "runs" / "20261125T130000Z-s1.json")
    ev = Evidence(lab.root)
    assert [r.run_id for r in ev.runs()] == ["20261125T111500Z-s2", "20261125T103000Z-s3", "20261125T101500Z-s2"]
    assert [r.run_id for r in ev.runs(scenario="s2")] == ["20261125T111500Z-s2", "20261125T101500Z-s2"]
    assert [r.run_id for r in ev.runs(scenario="s2", mode="off")] == ["20261125T101500Z-s2"]
    assert ev.runs(scenario="s9") == []
    run = ev.runs(scenario="s3")[0]
    assert (run.scenario, run.mode, run.sessions, run.audit) == ("s3", "enforce", (SESSION_A,), (0, 0))
    assert run.finbot["namespace"] == "ns_user_test"
    assert Evidence(lab.root / "nowhere").runs() == []
    # Review M4: a link in state/runs/ or state/transcripts/ points somewhere the driver and gateway never wrote.
    elsewhere = lab.root / "planted.json"
    lab.run_record("20261125T140000Z-s2", scenario="s2", started="2026-11-25T14:00:00Z").rename(elsewhere)
    (lab.state / "runs" / "20261125T140000Z-s2.json").symlink_to(elsewhere)
    assert "20261125T140000Z-s2" not in [r.run_id for r in ev.runs()]
    (lab.state / "transcripts" / f"{SESSION_B}.jsonl").symlink_to(elsewhere)
    with pytest.raises(EvidenceError, match="link"):
        ev.transcript(SESSION_B)


def _recording_runner(calls: list[list[str]], stdout: str, code: int = 0):
    def run(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr="")
    return run


def test_verify_passes_the_fingerprint(lab, tmp_path):
    lab.write_env(LAB_CLIENT_TOKEN="x" * 64, LAB_GUARDIAN_FINGERPRINT=FINGERPRINT)
    req = tool_request("send_email")
    lab.pair(req, sign_hmac(answer(req, "deny")))
    calls: list[list[str]] = []
    ev = Evidence(lab.root, runner=_recording_runner(calls, json.dumps({"result": "pass", "complete": True})))
    assert ev.fingerprint() == FINGERPRINT
    result = ev.verify(SESSION_A)
    assert result.outcome == "verified" and result.ok and result.report["complete"] is True
    keys = str(lab.state / "keys" / "guardian-keys.json")
    transcript = str(lab.transcript_path())
    assert calls[0] == [sys.executable, "-m", "acs.testing.verify", "--json", transcript, "--keys", keys,
                        "--expect-fingerprint", FINGERPRINT]
    ev.verify(SESSION_A, keys_only=True)
    assert calls[1][-1] == "--keys-only" and calls[1][:-1] == calls[0]
    ev.verify(SESSION_A, hmac=True)
    assert calls[2] == [sys.executable, "-m", "acs.testing.verify", "--json", transcript, "--hmac-secret",
                        str(lab.state / "secrets" / "hmac.key")]

    # Exit 1 is a transcript that fails verification. Exit 2, or output that isn't the JSON report, is an error.
    failing = Evidence(lab.root, runner=_recording_runner([], json.dumps(
        {"result": "fail", "failure": {"line": 2, "code": "bad_signature", "reason": "r"}}), code=1))
    assert failing.verify(SESSION_A).outcome == "broken"
    assert Evidence(lab.root, runner=_recording_runner([], "Traceback", code=2)).verify(SESSION_A).outcome == "error"


def test_verify_against_real_acs_verify(lab):
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")
    # The key document lands at state/keys/guardian-keys.json, where lab init puts it.
    key = fixtures.decision_key(lab.state / "keys")
    lab.write_hmac_secret()
    a, b = tool_request("get_vendor"), tool_request("send_email")
    lab.pair(a, key.sign(answer(a, "allow"), a))
    lab.pair(b, key.sign(answer(b, "deny"), b))
    hmac_req = tool_request("send_email", session_id=SESSION_B)
    lab.pair(hmac_req, sign_hmac(answer(hmac_req, "allow"), SESSION_B))

    lab.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    ev = Evidence(lab.root)
    result = ev.verify(SESSION_A, keys_only=True)
    assert result.outcome == "verified", result.detail
    assert result.report["response_algorithm"] == "ML-DSA-65"
    # The same session against a fingerprint the attendee never saw fails, because the pin comes from .env.
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=FINGERPRINT)
    assert Evidence(lab.root).verify(SESSION_A, keys_only=True).outcome == "broken"
    # Under HMAC the forger's own secret is all it takes (specification section 8.6).
    assert ev.verify(SESSION_B, keys_only=True, hmac=True).outcome == "verified"


def test_verify_without_fingerprint_is_not_yet(lab):
    req = tool_request("send_email")
    lab.pair(req, sign_hmac(answer(req, "deny")))
    calls: list[list[str]] = []
    runner = _recording_runner(calls, json.dumps({"result": "pass"}))
    # No .env, then a .env without the pin, then a pin that isn't a fingerprint, then one only os.environ holds.
    assert Evidence(lab.root, runner=runner).verify(SESSION_A).outcome == "not_yet"
    lab.write_env(LAB_CLIENT_TOKEN="x" * 64)
    assert Evidence(lab.root, runner=runner).verify(SESSION_A).outcome == "not_yet"
    lab.write_env(LAB_GUARDIAN_FINGERPRINT="sha256:" + "ef" * 31)
    assert Evidence(lab.root, runner=runner).fingerprint() is None
    assert Evidence(lab.root, runner=runner).verify(SESSION_A).outcome == "not_yet"
    lab.write_env()
    os.environ["LAB_GUARDIAN_FINGERPRINT"] = FINGERPRINT
    try:
        result = Evidence(lab.root, runner=runner).verify(SESSION_A)
    finally:
        del os.environ["LAB_GUARDIAN_FINGERPRINT"]
    assert result.outcome == "not_yet" and "init" in result.detail
    assert calls == []
    # A session with no transcript is not yet too, and acs-verify never runs.
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=FINGERPRINT)
    assert Evidence(lab.root, runner=runner).verify(SESSION_B).outcome == "not_yet"
    assert calls == []


# Review I3 and re-review N4: the trace view's names and ports, matched in code only. The leading \b keeps hotel_ and
# motel_ out, and jaeger has no trailing \b, so JAEGER_ENDPOINT and jaeger_query match. 16686 is the trace UI,
# 4317 and 4318 the OTLP collector, 14268 the Jaeger collector.
TRACE_ENDPOINT = re.compile(r"\bjaeger|\b(?:16686|4317|4318|14268)\b|\botel_[a-z]", re.IGNORECASE)
# A check reads files only. A network module beside the checks could reach the trace view through a URL built at run
# time. The guard catches mistakes, not deliberate evasion: __import__("socket") or importlib gets past any static scan.
NETWORK_MODULES = frozenset({"socket", "http", "urllib", "requests", "httpx"})
# A port is often a bare number. From Python 3.12, tokenize splits an f-string into FSTRING_START, FSTRING_MIDDLE and
# FSTRING_END, so the middle pieces are kept too (re-review N1).
TEXT_TOKENS = frozenset({tokenize.NAME, tokenize.NUMBER, tokenize.STRING,
                         getattr(tokenize, "FSTRING_MIDDLE", tokenize.STRING)})


def _code_text(source: str) -> str:
    """The identifiers and string constants in source, without comments or docstrings."""
    docstrings = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add((first.value.lineno, first.value.col_offset))
    kept = [tok.string for tok in tokenize.generate_tokens(io.StringIO(source).readline)
            if tok.type in TEXT_TOKENS and tok.start not in docstrings]
    return "\n".join(kept)


def _network_imports(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        found += [name for name in names if name.split(".")[0] in NETWORK_MODULES]
    return found


def _bans_network(path) -> bool:
    """Every file under modules/checks/ outside tests/ is held to the import ban, helpers included (re-review N1).
    The driver under scenarios/ talks to FinBot, so it isn't."""
    try:
        parts = path.relative_to(fixtures.CHECKS_DIR).parts
    except ValueError:
        return False
    return "tests" not in parts


def _trace_problems(label: str, source: str, *, is_check: bool) -> list[str]:
    problems = [f"{label}: {m.group(0)}" for m in TRACE_ENDPOINT.finditer(_code_text(source))]
    if is_check:
        problems += [f"{label}: imports {name}" for name in _network_imports(source)]
    return problems


CLEAN_SOURCE = '''"""No check reads Jaeger. It is an optional view."""
# never port 16686 or OTEL_ settings
def f():
    """Not jaeger either."""
    hotel_room = "motel_sign"
    return hotel_room
'''


def test_trace_guard_catches_what_it_should():
    # The guard below passes on an empty tree, so its rules are shown to bite here first.
    assert _trace_problems("a", 'URL = "http://jaeger:16686/api"\n', is_check=False) == ["a: jaeger", "a: 16686"]
    assert _trace_problems("a", 'import os\nX = os.environ["OTEL_EXPORTER"]\n', is_check=False) == ["a: OTEL_E"]
    assert _trace_problems("a", "import urllib.request\nfrom http import client\n", is_check=True) == [
        "a: imports urllib.request", "a: imports http"]
    assert _trace_problems("a", "import socket\n", is_check=False) == []
    assert _trace_problems("a", CLEAN_SOURCE, is_check=True) == []
    # Re-review N1: from Python 3.12, an f-string tokenizes as FSTRING_MIDDLE pieces, not one STRING.
    assert _trace_problems("a", 'h = "x"\nURL = f"http://{h}:16686/api"\n', is_check=False) == ["a: 16686"]
    assert _trace_problems("a", 'h = 1\nURL = f"http://jaeger:{h}/api"\n', is_check=False) == ["a: jaeger"]
    # Re-review N4: names and environment settings, and the collector ports.
    assert _trace_problems("a", 'JAEGER_ENDPOINT = "x:4317"\nP = 14268\nQ = "4318"\n', is_check=False) == [
        "a: JAEGER", "a: 4317", "a: 14268", "a: 4318"]
    # Re-review N1: a helper beside the checks is held to the import ban, since any check can call it.
    helper = fixtures.CHECKS_DIR / "traces.py"
    assert _bans_network(helper) and _bans_network(fixtures.CHECKS_DIR / "m3.py")
    assert _bans_network(fixtures.CHECKS_DIR / "evidence.py")
    assert not _bans_network(fixtures.CHECKS_DIR / "tests" / "fixtures.py")
    assert not _bans_network(fixtures.BUNDLE / "scenarios" / "driver.py")


def test_no_check_reads_jaeger():
    """Python code under modules/ and scenarios/ names no trace endpoint, and nothing under modules/checks/ imports a
    network module.
    Guides and other prose may name the trace view as an optional extra that no check reads."""
    scanned, problems = [], []
    for top in ("modules", "scenarios"):
        root = fixtures.BUNDLE / top
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            if "tests" in path.relative_to(root).parts:
                continue
            scanned.append(path)
            is_check = _bans_network(path)
            problems += _trace_problems(str(path.relative_to(fixtures.BUNDLE)), path.read_text(encoding="utf-8"),
                                        is_check=is_check)
    assert fixtures.CHECKS_DIR / "evidence.py" in scanned
    assert problems == []


def test_policy_sha256_covers_the_live_pack(lab):
    policy = lab.root / "policy"
    policy.mkdir()
    (policy / "base.rego").write_text("package a\n", encoding="utf-8")
    (policy / "data.json").write_text("{}\n", encoding="utf-8")
    (policy / "starters").mkdir()
    (policy / "starters" / "x.rego").write_text("package s\n", encoding="utf-8")
    ev = Evidence(lab.root)
    first = ev.policy_sha256()
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    # A starter or solution file isn't live, so changing it leaves the hash alone.
    (policy / "starters" / "x.rego").write_text("package t\n", encoding="utf-8")
    assert ev.policy_sha256() == first
    (policy / "data.json").write_text('{"a": 1}\n', encoding="utf-8")
    assert ev.policy_sha256() != first
