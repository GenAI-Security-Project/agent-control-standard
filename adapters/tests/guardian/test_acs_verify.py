"""acs-verify against sessions the real example Guardian signed (issue #584).

Every transcript here comes from the example Guardian over HTTP, in ML-DSA-65 response mode or today's HMAC mode,
recorded through acs.client's on_wire the way the lab gateway records it. Tampered copies are made from those
lines. The key document, the request hash, and the response algorithm offer are lab conventions (issues #460, #13,
#316).
"""
from __future__ import annotations

import json

import pytest

from decision_signing_helpers import require_pqc

require_pqc()

from acs_verify_helpers import record_session, start_guardian, stop_guardian  # noqa: E402
from acs.core import iso8601_now  # noqa: E402
from acs.testing.verify import verify_transcript  # noqa: E402


@pytest.fixture
def mldsa_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=True)
    yield run
    stop_guardian(run)


@pytest.fixture
def hmac_run(tmp_path, monkeypatch):
    run = start_guardian(tmp_path, monkeypatch, mldsa=False)
    yield run
    stop_guardian(run)


def records(lines):
    return [json.loads(line) for line in lines]


def line_of(lines, predicate) -> int:
    """The 1-based line number of the first record the predicate accepts."""
    for number, record in enumerate(records(lines), start=1):
        if predicate(record):
            return number
    raise AssertionError("no such line")


def test_clean_mldsa_session_passes(mldsa_run):
    lines = record_session(mldsa_run)
    report = verify_transcript(lines, key_document=mldsa_run.key_document(), hmac_secret=None)
    assert report.ok, report.to_text()
    assert report.complete
    assert report.chain_checked
    assert report.response_algorithm == "ML-DSA-65"
    assert report.lines == len(lines)
    assert report.session_id == mldsa_run.session_id


def test_clean_hmac_session_passes_with_the_secret(hmac_run):
    lines = record_session(hmac_run)
    report = verify_transcript(lines, key_document=None, hmac_secret=hmac_run.hmac_secret)
    assert report.ok, report.to_text()
    assert report.complete
    assert report.response_algorithm == "HMAC-SHA256"


def test_the_recomputed_chain_matches_the_guardians_chain_hash(mldsa_run):
    lines = record_session(mldsa_run)
    report = verify_transcript(lines, key_document=mldsa_run.key_document(), hmac_secret=None)
    guardian_heads = [r["envelope"]["result"]["chain_hash"] for r in records(lines)
                      if r["dir"] == "resp" and "chain_hash" in (r["envelope"].get("result") or {})]
    assert len(guardian_heads) == 4  # sessionStart, allow, deny, sessionEnd
    assert report.chain_heads == guardian_heads
