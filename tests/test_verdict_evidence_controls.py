"""Executable controls for the draft verdict evidence predicate (docs/predicates, #297).

The draft says two things in prose. A `witness_scope` above SELF must come from a
statement the peer authored and signed, naming the requirement it checked and the
artifact it used, never from a field the runner writes. A quarantine record must be
bound, and `review_by` must have an outcome. These tests run a pinned corpus of
signed records against a reference reader. Each refused case is one change from an
accepted twin: a wrong peer key, a peer statement the runner signed, the wrong vector,
the wrong requirement, an absent peer artifact, a different transcript, altered
quarantine fields and an overdue `review_by`.

The corpus and the reader come from the `verdict-evidence` dependency group, pinned in
uv.lock. The guard job does not install that group, so there the module is skipped.
The verdict-evidence-controls workflow installs it and sets
ACS_REQUIRE_VERDICT_EVIDENCE=1, which turns a missing package into a failure.

To run a verifier of your own against the same cases, set
ACS_VERDICT_EVIDENCE_VERIFIER to its command line. It is called as
`<verifier> <case-dir>/case.json --json`, prints one JSON object with `decision` and
`reason`, and exits 0 for supported, 1 for contradicted or not_established, 2 for no
verdict.
"""
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REQUIRED = os.environ.get("ACS_REQUIRE_VERDICT_EVIDENCE") == "1"
MODULE = "agent_evidence_vectors.verdict_evidence"

if importlib.util.find_spec("agent_evidence_vectors") is None or (
        importlib.util.find_spec(MODULE) is None):
    if REQUIRED:
        raise RuntimeError(
            f"{MODULE} is not installed; run `uv sync --locked --group verdict-evidence`")
    pytest.skip("the verdict-evidence dependency group is not installed",
                allow_module_level=True)

from agent_evidence_vectors.verdict_evidence import run as controls  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PREDICATE_DOC = ROOT / "docs" / "predicates" / "acs-verdict-evidence-v1.md"
MANIFEST = json.loads((controls.PACKAGED_CORPUS / "MANIFEST.json").read_text())
CASES = MANIFEST["cases"]
RUN = [sys.executable, "-m", f"{MODULE}.run"]

# One refusal for each rule the draft states in prose.
DRAFT_RULES = {
    "peer_artifact_unverified:untrusted_key": "wrong peer key, or the runner's own key",
    "peer_artifact_unverified:wrong_vector": "the peer checked another vector",
    "peer_artifact_unverified:wrong_requirement": "the peer checked another requirement",
    "peer_artifact_unverified:not_supplied": "the record names a peer artifact nobody holds",
    "peer_artifact_unverified:transcript_digest_mismatch": "the retained transcript differs",
    "witness_scope_misderived": "PEER or EXTERNAL with no peer statement behind it",
    "field_invalid:provenance.lift_state": "a lift field written by the runner",
    "peer_disagrees": "the peer saw another result, or its statement is reused for another verdict",
    "payload_digest_fields_incomplete": "a digest that leaves out a field, such as expiry_disposition",
    "quarantine_digest_mismatch": "a quarantine field edited after the digest",
    "quarantine_overdue": "review_by has passed",
}


def _report(tmp_path, *extra):
    out = tmp_path / "out"
    done = subprocess.run([*RUN, "--output", str(out), *extra], capture_output=True,
                          text=True, check=False)
    report = json.loads((out / "report.json").read_text()) if out.exists() else None
    return done, report


def test_the_reference_reader_answers_every_case_as_expected(tmp_path):
    done, report = _report(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    assert report["answered"] == report["total"] == len(CASES)
    assert report["failures"] == []


@pytest.mark.parametrize("reason", sorted(DRAFT_RULES))
def test_each_rule_in_the_draft_has_a_refused_case_with_an_accepted_twin(reason):
    by_id = {c["id"]: c for c in CASES}
    refused = [c for c in CASES if c["expected"]["reason"] == reason]
    assert refused, f"no case for: {DRAFT_RULES[reason]}"
    for case in refused:
        assert by_id[case["twin"]]["expected"]["decision"] == "supported"


def test_no_accepted_scope_lift_rests_on_a_runner_key():
    for case in CASES:
        if case["expected"]["reason"] in ("verdict_verified_peer", "verdict_verified_external"):
            spec = json.loads((controls.PACKAGED_CORPUS / "cases" / case["id"] /
                               "case.json").read_text())
            assert "peer_statement" in spec["supplied"]
            assert not set(spec["policy"]["peer_keys"]) & set(spec["policy"]["trusted_keys"])


@pytest.mark.skipif(not PREDICATE_DOC.exists(), reason="the predicate document lands with #297")
def test_the_corpus_uses_the_predicate_type_the_document_states():
    uris = re.findall(r"`(https://[^`]+acs-verdict-evidence-v1\.md)`", PREDICATE_DOC.read_text())
    assert MANIFEST["verdictPredicate"] in uris


def _stub(tmp_path, decision, code):
    script = tmp_path / f"stub_{decision}.py"
    script.write_text("import json, sys\n"
                      f"print(json.dumps({{'decision': {decision!r}, 'reason': 'stub'}}))\n"
                      f"sys.exit({code})\n")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}"


@pytest.mark.parametrize(("decision", "code"), [("supported", 0), ("contradicted", 1)])
def test_a_verifier_that_answers_one_way_fails_the_run(tmp_path, decision, code):
    done, report = _report(tmp_path, "--verifier", _stub(tmp_path, decision, code))
    assert done.returncode == 1, done.stdout + done.stderr
    assert report["failures"], "a constant verifier must fail some case"


@pytest.mark.skipif("ACS_VERDICT_EVIDENCE_VERIFIER" not in os.environ,
                    reason="no verifier under test named")
def test_the_named_verifier_answers_every_case_as_expected(tmp_path):
    done, report = _report(tmp_path, "--verifier", os.environ["ACS_VERDICT_EVIDENCE_VERIFIER"])
    assert done.returncode == 0, done.stdout + done.stderr
    assert report["answered"] == report["total"]
