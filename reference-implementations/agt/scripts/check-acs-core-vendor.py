#!/usr/bin/env python3
"""Check the retained ACS-Core source before the local Guardian report runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


RUNNER_DIR = "conformance/heldout-runner/"


def check_files(root: Path, entries: list[dict], paths: set[str]) -> None:
    """Refuse an entry whose bytes differ from the recorded length and digest."""
    for entry in entries:
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or entry["path"] in paths:
            raise ValueError("import path escapes the source or repeats")
        paths.add(entry["path"])
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("retained source differs: " + entry["path"])


def check_complete(root: Path, directory: str, paths: set[str], what: str) -> None:
    """Refuse a retained directory holding a file the record does not name."""
    actual = {
        str(path.relative_to(root)) for path in (root / directory).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual != {path for path in paths if path.startswith(directory)}:
        raise ValueError(f"retained {what} has missing or unrecorded files")


def check(root: Path) -> int:
    """Refuse missing or changed imported files without fetching any source."""
    root = root.resolve()
    record = json.loads((root / "conformance/acs-core-source.json").read_text())
    paths: set[str] = set()
    check_files(root, record["files"], paths)
    check_files(root, record["runner"]["files"], paths)
    check_complete(root, "conformance/vectors-acs-core/", paths, "corpus")
    check_complete(root, RUNNER_DIR, paths, "runner")
    manifest = json.loads((root / "conformance/vectors-acs-core/MANIFEST.json").read_text())
    if len(manifest["vectors"]) != record["memberCount"]:
        raise ValueError("retained member count differs")
    if manifest["corpusDigest"] != record["corpusDigest"] or manifest["counts"] != record["counts"]:
        raise ValueError("retained corpus declaration differs")
    if record["runner"]["corpusDigest"] != record["corpusDigest"]:
        raise ValueError("the retained runner is recorded against a different corpus")
    return len(manifest["vectors"])


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"ACS-Core retained source: every imported file, the held-out runner and all {count} members match")
