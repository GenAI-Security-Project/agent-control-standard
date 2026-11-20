"""The module 7 kit's result files, in the shape LAB-13's viewer reads (issue #589, LAB-16 Task 12).

Version 1.1.0. Owner: Rock Lambros. Standard library only.

acs-verify's verdicts reach no log, so lab forge, lab verify and lab downgrade each leave one JSON file in
state/verify/, named <kind>-<algorithm>-<session>.json, and the viewer paints a beat from it (viewer/beats.py):

    {"kind": "forge" | "keys_only" | "downgrade", "algorithm": "HMAC-SHA256" | "ML-DSA-65",
     "result": "verified" | "broken" | "refused", "entry": <int> | null, "detail": <str>,
     "fingerprint": "sha256:<64 hex>"}

fingerprint is optional, and only lab downgrade writes it: the pin its refusal verified under, so check 7 can tell a
refusal under the current key from one recorded before a fresh lab init. The viewer reads the other fields only.

The shape is a lab convention the coordinator accepted for LAB-16 (plan LAB-13, open question 1). Each file goes
through a temporary file and one rename, so the viewer, which polls the directory, never reads half of one. The
temporary name doesn't end in .json, so the viewer's directory scan skips it.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from pathlib import Path

KINDS = ("forge", "keys_only", "downgrade")
ALGORITHMS = ("HMAC-SHA256", "ML-DSA-65")
RESULTS = ("verified", "broken", "refused")
# The viewer reads 64 KiB of a result at most. A detail this long is a bug, not a verdict.
MAX_DETAIL = 2000
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")


def write(state: Path, *, kind: str, algorithm: str, session_id: str, result: str, entry: int | None,
          detail: str, fingerprint: str | None = None) -> Path:
    """state/verify/<kind>-<algorithm>-<session_id>.json holding one result. Raises ValueError for a value outside
    the shape, so a file the viewer would drop is never written."""
    if kind not in KINDS or algorithm not in ALGORITHMS or result not in RESULTS:
        raise ValueError(f"no result shape for {kind!r}, {algorithm!r}, {result!r}")
    if entry is not None and (isinstance(entry, bool) or not isinstance(entry, int) or entry < 1):
        raise ValueError(f"entry must be a line number or None, got {entry!r}")
    if fingerprint is not None and not (isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint)):
        raise ValueError(f"fingerprint must be sha256: and 64 hex digits, got {fingerprint!r}")
    # The session id names the file, so only a canonical UUID may, as for the gateway's transcripts.
    if str(uuid.UUID(session_id)) != session_id:
        raise ValueError(f"{session_id!r} is not a session id")
    record = {"kind": kind, "algorithm": algorithm, "result": result, "entry": entry,
              "detail": " ".join(str(detail).split())[:MAX_DETAIL]}
    if fingerprint is not None:
        record["fingerprint"] = fingerprint
    directory = state / "verify"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kind}-{algorithm}-{session_id}.json"
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(record, indent=2) + "\n")
        # The viewer reads this directory as another service, and a verdict holds nothing secret.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
