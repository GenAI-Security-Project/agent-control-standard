"""Refuse altered imports and exercise the local report without a vectors package."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGT = ROOT / "reference-implementations/agt"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, AGT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_complete_original_import():
    assert load_script("check-acs-core-vendor").check(AGT) == 43


@pytest.mark.parametrize("mutation", ["expectation", "normative-text", "license", "missing", "unrecorded"])
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
