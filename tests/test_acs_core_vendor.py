"""Refuse altered imports and exercise the local report without a vectors package."""

import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGT = ROOT / "reference-implementations/agt"
RUNNER = AGT / "conformance/heldout-runner/agent_evidence_vectors/heldout.py"
AUDIT_FIXTURES = ["va0ee5d0830b0490b", "vfdd68340c2094962"]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, AGT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_complete_original_import():
    assert load_script("check-acs-core-vendor").check(AGT) == 43


@pytest.mark.parametrize("mutation", ["expectation", "normative-text", "license", "missing", "unrecorded",
                                      "runner", "runner-unrecorded"])
def test_refuse_changed_import(tmp_path, mutation):
    shutil.copytree(AGT / "conformance", tmp_path / "conformance")
    corpus = tmp_path / "conformance/vectors-acs-core"
    manifest = json.loads((corpus / "MANIFEST.json").read_text())
    member = corpus / manifest["vectors"][0]["file"]
    if mutation == "expectation":
        data = json.loads(member.read_text())
        data["expected"]["verdict"] = "mutated"
        member.write_text(json.dumps(data))
    elif mutation == "normative-text":
        path = corpus / manifest["specVendored"]["specification"]["path"]
        path.write_bytes(path.read_bytes() + b"\nChanged requirement.\n")
    elif mutation == "license":
        (tmp_path / "conformance/acs-core-source/LICENSE").write_text("replacement")
    elif mutation == "missing":
        member.unlink()
    elif mutation == "runner":
        runner = tmp_path / RUNNER.relative_to(AGT)
        runner.write_bytes(runner.read_bytes().replace(b"verdict-differs", b"matched"))
    elif mutation == "runner-unrecorded":
        (tmp_path / RUNNER.relative_to(AGT)).with_name("extra.py").write_text("")
    else:
        (corpus / "vectors/unrecorded.json").write_text("{}")
    with pytest.raises((ValueError, FileNotFoundError)):
        load_script("check-acs-core-vendor").check(tmp_path)


def test_runner_default_and_override_work_without_package(tmp_path):
    # -I -S excludes caller paths and installed packages. Use a missing
    # Guardian to exercise every retained member while keeping network scope local.
    script = AGT / "scripts/run-acs-core-vectors.py"
    results = []
    for index, extra in enumerate([[], ["--vectors", str(AGT / "conformance/vectors-acs-core")]]):
        output = tmp_path / f"result-{index}.jsonl"
        process = subprocess.run(
            [sys.executable, "-I", "-S", str(script), "--guardian", "http://127.0.0.1:1/acs",
             "--out", str(output), *extra], cwd=tmp_path, capture_output=True, text=True,
        )
        assert process.returncode == 2
        assert "Guardian answered no request" in process.stderr
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        assert len(rows) == 43
        assert all(row["adapted"]["status"] in {"transport-failure", "not-on-the-wire"} for row in rows)
        results.append({row["id"] for row in rows})
    assert results[0] == results[1]


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_constant_guardian_cannot_claim_full_evidence(tmp_path, decision):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = json.dumps({"result": {"decision": decision}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = tmp_path / "results.jsonl"
    try:
        process = subprocess.run(
            [sys.executable, "-I", "-S", str(AGT / "scripts/run-acs-core-vectors.py"),
             "--guardian", f"http://127.0.0.1:{server.server_port}/acs", "--out", str(output)],
            cwd=tmp_path, capture_output=True, text=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert process.returncode == 0
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(rows) == 43 and requests
    selected = {row["id"]: row for row in rows}
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    sessions = {request["params"]["metadata"]["session_id"] for request in requests}
    for identity in ["va0ee5d0830b0490b", "vfdd68340c2094962"]:
        for column in ["raw", "adapted"]:
            assert selected[identity][column]["status"] == "not-on-the-wire"
            assert "deployment audit observations" in selected[identity][column]["reason"]
            assert selected[identity][column + "_score"] == "NOT RUN"
            assert str(uuid.uuid5(namespace, identity + ":" + column + ":s-0001")) not in sessions
    if decision == "allow":
        assert any(row["expected"]["verdict"] == "allow" and row["adapted_score"] == "PASS" for row in rows)
        assert any(row["expected"]["verdict"] == "deny" and row["adapted_score"] == "FAIL" for row in rows)
    else:
        assert any(row["expected"]["verdict"] == "allow" and row["adapted_score"] == "FAIL" for row in rows)
        assert any(row["adapted_score"] == "FAIL-CODE" for row in rows)


class ConstantGuardian:
    """A local Guardian that answers every request with one decision and keeps what it saw."""

    def __init__(self, decision):
        self.requests = []
        seen = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({"result": {"decision": decision}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/acs"

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def heldout(*args, cwd):
    return subprocess.run([sys.executable, "-I", "-S", str(RUNNER), *args],
                          cwd=cwd, capture_output=True, text=True)


def test_retained_runner_refuses_its_own_controls(tmp_path):
    process = heldout("self-test", cwd=tmp_path)
    assert process.returncode == 0, process.stderr
    assert "9 controls, 0 failed" in process.stdout


def test_sealed_run_through_the_adapter_verifies_and_leaves_audit_fixtures_unmeasured(tmp_path):
    seed = tmp_path / "seed"
    seed.write_bytes(b"a test seed that is long enough and public on purpose")
    sealing = heldout("seal", "--seed-file", str(seed), "--out", str(tmp_path / "held"), cwd=tmp_path)
    assert sealing.returncode == 0, sealing.stderr
    record, transcript = tmp_path / "run.json", tmp_path / "run.transcript"
    with ConstantGuardian("allow") as guardian:
        process = heldout(
            "run", "--sealed", str(tmp_path / "held/SEALED.json"),
            "--record", str(record), "--transcript", str(transcript), "--",
            sys.executable, "-I", "-S", str(AGT / "scripts/acs-core-heldout-adapter.py"),
            "--guardian", guardian.url, cwd=tmp_path,
        )
    # A constant allow fails the deny members: exit 1 is a measured result, 2 would be a refusal.
    assert process.returncode == 1, process.stderr
    run = json.loads(record.read_text())
    assert run["totals"]["public"]["of"] == 43 and run["totals"]["sealed"]["of"] > 0
    assert run["corpusDigest"] == json.loads(
        (AGT / "conformance/acs-core-source.json").read_text())["runner"]["corpusDigest"]
    rows = {row["id"]: row for row in run["rows"]}
    for identity in AUDIT_FIXTURES:
        assert rows[identity]["verdict"] == "unmeasurable"
    assert any(row["partition"] == "sealed" and row["pass"] for row in run["rows"])
    assert guardian.requests
    verified = heldout("verify", str(record), "--transcript", str(transcript), cwd=tmp_path)
    assert verified.returncode == 0 and "record verifies" in verified.stdout
