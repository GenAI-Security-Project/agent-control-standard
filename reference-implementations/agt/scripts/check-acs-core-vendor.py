#!/usr/bin/env python3
"""Check the retained ACS-Core source before the local Guardian report runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def check(root: Path) -> int:
    """Refuse missing or changed imported files without fetching any source."""
    root = root.resolve()
    record = json.loads((root / "conformance/acs-core-source.json").read_text())
    paths = set()
    for entry in record["files"]:
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or entry["path"] in paths:
            raise ValueError("import path escapes the source or repeats")
        paths.add(entry["path"])
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("retained source differs: " + entry["path"])
    corpus = root / "conformance/vectors-acs-core"
    actual = {str(path.relative_to(root)) for path in corpus.rglob("*") if path.is_file()}
    expected = {path for path in paths if path.startswith("conformance/vectors-acs-core/")}
    if actual != expected:
        raise ValueError("retained corpus has missing or unrecorded files")
    manifest = json.loads((corpus / "MANIFEST.json").read_text())
    if len(manifest["vectors"]) != record["memberCount"]:
        raise ValueError("retained member count differs")
    if manifest["corpusDigest"] != record["corpusDigest"] or manifest["counts"] != record["counts"]:
        raise ValueError("retained corpus declaration differs")
    return len(manifest["vectors"])


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"ACS-Core retained source: every imported file and all {count} members match")
