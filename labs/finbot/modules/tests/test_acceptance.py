"""acceptance.py's parts that need no live lab: the Docker shim, the audit scan, the run record rules, and the guide
preflight (issue #589, LAB-16 Task 16). Standard library and pytest only.

Run from the repository root:
    uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/modules/tests -v
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import acceptance  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the lab runs on macOS and Linux only (Rock, 2026-11-17)")

NAMESPACE = "ns_0f3a9c"
GOOD = {"result": "completed", "replay_misses": 0, "upstream": "replay", "finbot": {"namespace": NAMESPACE}}


@pytest.fixture
def shim(tmp_path: Path) -> Path:
    real = tmp_path / "real docker"
    real.write_text('#!/bin/sh\nprintf "%s|" "$@"\n', encoding="utf-8")
    real.chmod(0o755)
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    return acceptance.write_docker_shim(shim_dir, str(real), Path("/lab bundle/compose.offline.yaml"))


def _call(shim: Path, *args: str) -> list[str]:
    out = subprocess.run([str(shim), *args], capture_output=True, text=True, check=True).stdout
    return out.split("|")[:-1]


@pytest.mark.parametrize("extra", [[], ["-f", "compose.openai.yaml"],
                                   ["-f", "compose.openai.yaml", "-f", "replay/compose.capture.yaml"]])
def test_shim_adds_the_override_after_the_base_file(shim, extra):
    # Each of lab.sh's three compose() forms gets the override right after compose.yaml, the rest kept in order.
    got = _call(shim, "compose", "-f", "compose.yaml", *extra, "run", "--rm", "lab", "two words")
    assert got == ["compose", "-f", "compose.yaml", "-f", "/lab bundle/compose.offline.yaml", *extra, "run", "--rm",
                   "lab", "two words"]


@pytest.mark.parametrize("args", [["compose", "version", "--short"], ["volume", "rm", "--force", "x"],
                                  ["compose", "-f", "other.yaml", "ps"]])
def test_shim_passes_every_other_call_through(shim, args):
    assert _call(shim, *args) == args


def test_audit_scan_reads_only_new_lines_and_restarts_after_a_wipe(tmp_path):
    log = tmp_path / "audit.log"
    assert acceptance.new_audit_misses(log, 0) == (0, [])
    miss = 'ACS_AUDIT {"acs_audit_event": "replay_miss", "cause": "no_recording"}\n'
    log.write_text('ACS_AUDIT {"acs_audit_event": "epoch_bumped"}\n' + miss, encoding="utf-8")
    offset, misses = acceptance.new_audit_misses(log, 0)
    assert len(misses) == 1 and offset == log.stat().st_size
    assert acceptance.new_audit_misses(log, offset) == (offset, [])
    # A reset wipes state/, so a shorter log is new from its first byte.
    log.write_text(miss, encoding="utf-8")
    assert acceptance.new_audit_misses(log, offset)[1] == [miss.strip()]


def test_a_good_record_passes():
    assert acceptance.record_problems("r.json", GOOD, {"s1__enforce.jsonl": '{"scenario": "s1__enforce"}'}) == []


@pytest.mark.parametrize(("change", "words"), [
    ({"result": "not_yet", "error": "2 model calls had no recording"}, "says 'not_yet'"),
    ({"replay_misses": 2}, "counts 2 replay misses"),
    ({"replay_misses": None}, "counts None replay misses"),
    ({"upstream": "openai"}, "'openai' upstream"),
    ({"finbot": {}}, "no FinBot namespace"),
    ({"finbot": "x"}, "no FinBot namespace"),
])
def test_each_record_rule_fails_alone(change, words):
    problems = acceptance.record_problems("r.json", {**GOOD, **change}, {})
    assert len(problems) == 1 and words in problems[0], problems


def test_a_run_in_a_recordings_namespace_fails():
    recordings = {"s2__enforce.jsonl": f'{{"input": "vendor in {NAMESPACE}"}}', "s1__off.jsonl": "{}"}
    problems = acceptance.record_problems("r.json", GOOD, recordings)
    assert problems == [f"run record r.json ran in FinBot namespace {NAMESPACE}, which recording "
                        f"s2__enforce.jsonl holds"]


def test_a_record_that_isnt_an_object_fails():
    assert acceptance.record_problems("r.json", [], {}) == ["run record r.json isn't a JSON object"]


def test_missing_guides_fail_before_docker(tmp_path, monkeypatch):
    def no_docker(*args, **kwargs):
        raise AssertionError("Docker was called before the guides passed")

    monkeypatch.setattr(acceptance, "_run", no_docker)
    monkeypatch.setattr(acceptance, "_docker", no_docker)
    run = acceptance.Acceptance([1, 2], tmp_path, {})
    with pytest.raises(acceptance.NotYet, match=r"no guide yet at modules/1\.md, modules/2\.md"):
        run.play()


def test_a_broken_guide_fails_before_docker(tmp_path, monkeypatch):
    monkeypatch.setattr(acceptance, "_run", lambda *a, **k: pytest.fail("Docker was called"))
    (tmp_path / "1.md").write_text("# Module 1\n\n```sh\n./lab.sh run s1; rm -rf state\n```\n", encoding="utf-8")
    with pytest.raises(acceptance.NotYet, match="don't pass the simulator"):
        acceptance.Acceptance([1], tmp_path, {}).play()


@pytest.mark.parametrize("text", ["0", "8", "1,x", ""])
def test_modules_flag_takes_only_module_numbers(text):
    with pytest.raises(SystemExit):
        acceptance.main(["--modules", text])


def test_modules_flag_sorts_and_dedupes():
    assert acceptance._modules("7,1,3,1") == [1, 3, 7]
