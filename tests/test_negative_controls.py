"""Negative controls for the conformance runner, one group per #53 requirement it can test.

Issue #53 lists what a v0.2 suite has to get right. Seven of those requirements are about
the gate itself rather than any one Guardian, so each is tested here by handing the runner
in `tests/negative_controls_runner.py` a subject or a corpus it must refuse:

- 2, the gate has negative controls of its own: every runner mutant below is caught.
- 3, structural rules have a mirror: an allow-everything Guardian fails, and a suite with
  only positive controls is refused.
- 4, the runner owns its process: every run is a child process, and a child that exits 0
  without a report is not read as a pass.
- 5, a constant cannot be measured: a Guardian that skips signature checks fails exactly
  the signature vectors, and a suite whose signatures never change is refused. The same
  holds across a sequence: a Guardian that answers a byte-identical resend with its first
  decision, as an idempotent retry, fails exactly the resend vector, and a suite that never
  resends a request is refused.
- 7, codes, never prose: the right message with the wrong code fails, and the right code
  with other wording passes.
- 9, a run that scores nothing does not exit 0.
- 11, CI reads the report: `read_report` fails a run whose exit code disagrees with it.

The last group runs the same vectors against the reference Guardian in
`reference-implementations/agt`. Its four known gaps are strict expected failures, so the
day the Guardian closes one, this file fails until the marker is removed.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "tests" / "negative_controls_runner.py"
AGT = ROOT / "reference-implementations" / "agt"

_spec = importlib.util.spec_from_file_location("negative_controls_runner", RUNNER)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

VECTOR_IDS = [vector["id"] for vector in runner.VECTORS]
NEGATIVE_IDS = {v["id"] for v in runner.VECTORS if v["kind"] == "negative"}
POSITIVE_IDS = set(VECTOR_IDS) - NEGATIVE_IDS
SIGNATURE_IDS = {"signature-invalid", "signature-missing"}
RESEND_IDS = {"request-resent-after-lost-response"}


# --- reading a run --------------------------------------------------------------------


@dataclass
class Report:
    returncode: int
    verdicts: dict
    counts: dict
    stdout: str


def read_report(proc: subprocess.CompletedProcess) -> Report:
    """Score a run from its report, and fail when the exit code disagrees (requirement 11)."""
    lines = proc.stdout.splitlines()
    results = [line for line in lines if line.startswith("RESULT ")]
    assert len(results) == 1 and lines[-1] == results[0], (
        "no closing RESULT line; exit %d, stdout %r" % (proc.returncode, proc.stdout[-500:]))
    counts = {k: int(v) for k, v in (item.split("=") for item in results[0].split()[1:])}
    verdicts = {}
    for line in lines:
        word, _, rest = line.partition(" ")
        if word in ("PASS", "FAIL", "NOT-RUN"):
            verdicts[rest.split(" ")[0]] = word
    tally = {"pass": "PASS", "fail": "FAIL", "not_run": "NOT-RUN"}
    invalid = any(line.startswith("SUITE-INVALID ") for line in lines)
    if not invalid:
        for key, word in tally.items():
            assert counts[key] == list(verdicts.values()).count(word), (
                "RESULT says %s=%d but the report lists %d" % (key, counts[key], list(verdicts.values()).count(word)))
    if invalid or counts["pass"] + counts["fail"] == 0:
        expected = 2
    elif counts["fail"] or counts["not_run"]:
        expected = 1
    else:
        expected = 0
    assert proc.returncode == expected, (
        "exit code %d disagrees with the report, which implies %d" % (proc.returncode, expected))
    return Report(proc.returncode, verdicts, counts, proc.stdout)


def run_runner(url: str, tmp_path: Path, vectors: list | None = None, script: Path = RUNNER) -> Report:
    """One child process per run, isolated from this interpreter (requirement 4)."""
    args = [sys.executable, "-I", str(script), "--guardian", url]
    if vectors is not None:
        path = tmp_path / ("vectors-%d.json" % time.monotonic_ns())
        path.write_text(json.dumps(vectors))
        args += ["--vectors", str(path)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    return read_report(proc)


# --- stub Guardians -------------------------------------------------------------------


def _error(body: dict, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": code, "message": message}}


def _allow(body: dict) -> dict:
    return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"decision": "allow"}}


class Conformant:
    """Checks the three properties the vectors vary, the way sections 10 and 10.3 say."""

    def __init__(self, check_signature: bool = True, codes: dict | None = None, wording: str = "plain",
                 idempotent_resend: bool = False):
        self.check_signature = check_signature
        self.codes = codes or {}
        self.wording = wording
        self.idempotent_resend = idempotent_resend
        self.seen: dict = {}
        self.lock = threading.Lock()

    def refuse(self, body: dict, code: int, name: str) -> dict:
        message = {"plain": name, "other": "request refused, see code"}[self.wording]
        return _error(body, self.codes.get(code, code), message)

    def __call__(self, body: dict) -> dict:
        params = body.get("params", {})
        sent = params.get("signature")
        if self.check_signature:
            unsigned = json.loads(json.dumps(body))
            unsigned["params"].pop("signature", None)
            if not sent or sent != runner.sign(unsigned, runner.DEFAULT_PSK):
                return self.refuse(body, -32004, "SIGNATURE_INVALID: signature invalid")
        stamp = datetime.datetime.fromisoformat(params["timestamp"].replace("Z", "+00:00"))
        if abs((runner.now() - stamp).total_seconds()) > 300:
            return self.refuse(body, -32006, "TIMESTAMP_OUT_OF_WINDOW: timestamp outside window")
        key = (params["metadata"]["session_id"], params["request_id"])
        with self.lock:
            if key in self.seen:
                if self.idempotent_resend and self.seen[key] == body:
                    return _allow(body)
                return self.refuse(body, -32005, "REPLAY_DETECTED: duplicate request_id")
            self.seen[key] = body
        return _allow(body)


def allow_all(body: dict) -> dict:
    return _allow(body)


def deny_all(body: dict) -> dict:
    return _error(body, -32004, "SIGNATURE_INVALID")


def drop(body: dict) -> None:
    return None


class Stub:
    """Serve a policy on a loopback port; a policy returning None closes the connection unanswered."""

    def __init__(self, policy):
        policy_ref = policy

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                answer = policy_ref(body)
                if answer is None:
                    self.close_connection = True
                    return
                data = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d/acs" % self.server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.url

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def vectors_where(predicate) -> list:
    return [json.loads(json.dumps(v)) for v in runner.VECTORS if predicate(v)]


# --- controls, as functions of a runner script so the mutants can reuse them ----------


def control_conformant_passes(script: Path, tmp_path: Path) -> None:
    with Stub(Conformant()) as url:
        report = run_runner(url, tmp_path, script=script)
    assert report.returncode == 0 and set(report.verdicts.values()) == {"PASS"}, report.stdout


def control_allow_all_fails(script: Path, tmp_path: Path) -> None:
    with Stub(allow_all) as url:
        report = run_runner(url, tmp_path, script=script)
    assert report.returncode == 1, report.stdout
    assert {i for i, v in report.verdicts.items() if v == "FAIL"} == NEGATIVE_IDS, report.stdout


def control_deny_all_fails(script: Path, tmp_path: Path) -> None:
    with Stub(deny_all) as url:
        report = run_runner(url, tmp_path, script=script)
    assert report.returncode == 1, report.stdout
    assert POSITIVE_IDS <= {i for i, v in report.verdicts.items() if v == "FAIL"}, report.stdout


def control_positives_only_refused(script: Path, tmp_path: Path) -> None:
    with Stub(allow_all) as url:
        report = run_runner(url, tmp_path, vectors_where(lambda v: v["kind"] == "positive"), script=script)
    assert report.returncode == 2 and "needs a positive and a negative control" in report.stdout, report.stdout


def control_constant_signature_refused(script: Path, tmp_path: Path) -> None:
    vectors = vectors_where(lambda v: True)
    for vector in vectors:
        for step in vector["steps"]:
            step.pop("signature", None)
    with Stub(allow_all) as url:
        report = run_runner(url, tmp_path, vectors, script=script)
    assert report.returncode == 2 and "no vector changes signature" in report.stdout, report.stdout


def control_unchecked_signature_fails(script: Path, tmp_path: Path) -> None:
    with Stub(Conformant(check_signature=False)) as url:
        report = run_runner(url, tmp_path, script=script)
    assert {i for i, v in report.verdicts.items() if v == "FAIL"} == SIGNATURE_IDS, report.stdout


def control_idempotent_resend_fails(script: Path, tmp_path: Path) -> None:
    with Stub(Conformant(idempotent_resend=True)) as url:
        report = run_runner(url, tmp_path, script=script)
    assert {i for i, v in report.verdicts.items() if v == "FAIL"} == RESEND_IDS, report.stdout


def control_no_resend_refused(script: Path, tmp_path: Path) -> None:
    vectors = vectors_where(lambda v: v["id"] not in RESEND_IDS)
    with Stub(Conformant()) as url:
        report = run_runner(url, tmp_path, vectors, script=script)
    assert report.returncode == 2 and "no vector changes resend" in report.stdout, report.stdout


def control_wrong_code_fails(script: Path, tmp_path: Path) -> None:
    wrong = {code: -32603 for code in (-32004, -32005, -32006)}
    with Stub(Conformant(codes=wrong)) as url:
        report = run_runner(url, tmp_path, script=script)
    assert {i for i, v in report.verdicts.items() if v == "FAIL"} == NEGATIVE_IDS, report.stdout


def control_empty_suite_exits_2(script: Path, tmp_path: Path) -> None:
    with Stub(allow_all) as url:
        report = run_runner(url, tmp_path, [], script=script)
    assert report.returncode == 2 and report.counts == {"pass": 0, "fail": 0, "not_run": 0}, report.stdout


def control_unanswered_scores_nothing(script: Path, tmp_path: Path) -> None:
    with Stub(drop) as url:
        report = run_runner(url, tmp_path, script=script)
    assert report.returncode == 2 and set(report.verdicts.values()) == {"NOT-RUN"}, report.stdout


# Requirement 2: each mutant weakens one guard in the runner, and at least one control
# above must fail against it. A mutant whose source line is not found fails the test,
# so a rewrite of the runner cannot quietly turn a mutant into a copy of the original.
MUTANTS = [
    ("the error code is not compared",
     'ok = last.get("error") == expect["error"]', 'ok = "error" in last',
     control_wrong_code_fails),
    ("an allow expectation is not checked",
     'ok = all(o.get("decision") == expect["decision"] for o in observations)', "ok = True",
     control_deny_all_fails),
    ("the positive and negative mirror rule is dropped",
     'if kinds != {"positive", "negative"}:', "if not kinds:",
     control_positives_only_refused),
    ("the rule that a suite varies each property is dropped",
     "if steps and not any(", "if False and not any(",
     control_constant_signature_refused),
    ("an empty run exits 0",
     'if counts["PASS"] + counts["FAIL"] == 0:\n        return 2', 'if False:\n        return 2',
     control_empty_suite_exits_2),
    ("a transport failure is scored as a pass",
     'counts["NOT-RUN"] += 1\n            print("NOT-RUN %s %s" % (vector["id"], type(exc).__name__))',
     'counts["PASS"] += 1\n            print("PASS " + vector["id"])',
     control_unanswered_scores_nothing),
    ("a resend step sends a fresh request",
     'if step.get("resend") == "identical" and sent is not None:', "if False:",
     control_conformant_passes),
    ("every run exits 0",
     'return 1 if counts["FAIL"] or counts["NOT-RUN"] else 0', "return 0",
     control_allow_all_fails),
]


# --- requirement 3 ----------------------------------------------------------------------


def test_a_conformant_guardian_passes(tmp_path):
    """The positive control for the gate itself: a strict runner that fails everything is no gate."""
    control_conformant_passes(RUNNER, tmp_path)


def test_an_allow_everything_guardian_fails_every_negative(tmp_path):
    control_allow_all_fails(RUNNER, tmp_path)


def test_a_deny_everything_guardian_fails_every_positive(tmp_path):
    control_deny_all_fails(RUNNER, tmp_path)


def test_a_suite_of_positive_controls_alone_is_refused(tmp_path):
    control_positives_only_refused(RUNNER, tmp_path)


# --- requirement 5 ----------------------------------------------------------------------


def test_a_guardian_that_skips_signatures_fails_the_signature_vectors(tmp_path):
    control_unchecked_signature_fails(RUNNER, tmp_path)


def test_a_suite_whose_signatures_never_change_is_refused(tmp_path):
    control_constant_signature_refused(RUNNER, tmp_path)


def test_a_guardian_that_answers_a_resend_as_an_idempotent_retry_fails_it(tmp_path):
    control_idempotent_resend_fails(RUNNER, tmp_path)


def test_a_suite_that_never_resends_a_request_is_refused(tmp_path):
    control_no_resend_refused(RUNNER, tmp_path)


# --- requirement 7 ----------------------------------------------------------------------


def test_the_right_message_with_the_wrong_code_fails(tmp_path):
    control_wrong_code_fails(RUNNER, tmp_path)


def test_the_right_code_with_other_wording_passes(tmp_path):
    with Stub(Conformant(wording="other")) as url:
        report = run_runner(url, tmp_path)
    assert report.returncode == 0, report.stdout


# --- requirement 9 ----------------------------------------------------------------------


def test_an_empty_suite_does_not_exit_0(tmp_path):
    control_empty_suite_exits_2(RUNNER, tmp_path)


def test_a_guardian_that_never_answers_scores_nothing(tmp_path):
    control_unanswered_scores_nothing(RUNNER, tmp_path)


def test_a_closed_port_scores_nothing(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    report = run_runner("http://127.0.0.1:%d/acs" % port, tmp_path)
    assert report.returncode == 2, report.stdout


# --- requirements 4 and 11 --------------------------------------------------------------


def test_a_child_that_exits_0_without_a_report_is_not_a_pass(tmp_path):
    silent = tmp_path / "silent.py"
    silent.write_text("import sys\nsys.exit(0)\n")
    with pytest.raises(AssertionError, match="no closing RESULT line"):
        run_runner("http://127.0.0.1:9/acs", tmp_path, script=silent)


def test_an_exit_code_that_disagrees_with_the_report_fails(tmp_path):
    proc = subprocess.CompletedProcess([], 0, stdout="FAIL x expected\nRESULT pass=0 fail=1 not_run=0\n", stderr="")
    with pytest.raises(AssertionError, match="disagrees with the report"):
        read_report(proc)


# --- requirement 2 ----------------------------------------------------------------------


@pytest.mark.parametrize("name, old, new, control", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_every_runner_mutant_is_caught(tmp_path, name, old, new, control):
    source = RUNNER.read_text()
    assert source.count(old) == 1, "mutant %r no longer matches the runner" % name
    mutant = tmp_path / "mutant_runner.py"
    mutant.write_text(source.replace(old, new))
    with pytest.raises(AssertionError):
        control(mutant, tmp_path)


# --- the reference Guardian ---------------------------------------------------------------

# Each is a MUST the reference Guardian fails, not an optional case and not a defect in the
# vector. The strict marker turns a fix into a failing run, so the list cannot go stale.
REFERENCE_GAPS = {
    "signature-invalid": "a section 10 MUST the reference Guardian fails today: it does not verify signatures (#184)",
    "signature-missing": "a section 10 MUST the reference Guardian fails today: it accepts an unsigned request (#184)",
    "request-id-repeated": "a section 10.3 MUST the reference Guardian fails today: it does not track request_id (#184)",
    "request-resent-after-lost-response": "a section 10.3 MUST the reference Guardian fails today: it does not track request_id (#184)",
    "timestamp-outside-window": "a section 10.3 MUST the reference Guardian fails today: it does not check the skew window (#184)",
}


@pytest.fixture(scope="module")
def reference_report(tmp_path_factory):
    bun = shutil.which("bun")
    if bun is None or not (AGT / "node_modules").is_dir():
        reason = ("the reference Guardian needs Bun and `bun install` in %s; the Reference "
                  "implementation workflow runs this group with both" % AGT.relative_to(ROOT))
        if os.environ.get("ACS_REQUIRE_REFERENCE_GUARDIAN"):
            pytest.fail(reason)
        pytest.skip(reason)
    work = tmp_path_factory.mktemp("reference-guardian")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, ACS_GUARDIAN_PORT=str(port), ACS_GUARDIAN_HOST="127.0.0.1",
               ACS_ENVELOPE_LOG=str(work / "envelopes.jsonl"),
               ACS_SESSION_CONTEXT_LOG=str(work / "session-context.jsonl"))
    log = work / "guardian.log"
    with open(log, "w") as out:
        guardian = subprocess.Popen([bun, "run", "guardian"], cwd=AGT, env=env, stdout=out,
                                    stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while "Guardian listening" not in log.read_text():
            assert guardian.poll() is None and time.monotonic() < deadline, log.read_text()
            time.sleep(0.2)
        yield run_runner("http://127.0.0.1:%d/acs" % port, work)
    finally:
        os.killpg(guardian.pid, signal.SIGTERM)
        guardian.wait(timeout=30)


@pytest.mark.parametrize("vector_id", [
    pytest.param(i, marks=pytest.mark.xfail(strict=True, reason=REFERENCE_GAPS[i])) if i in REFERENCE_GAPS else i
    for i in VECTOR_IDS
])
def test_the_reference_guardian(reference_report, vector_id):
    assert reference_report.verdicts.get(vector_id) == "PASS", reference_report.stdout
