"""The A.12 beats: which named moment of the lab a viewer row paints (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.12).

Most beats come from the gateway's rows. The three module 7 beats are acs-verify results, which no log holds, so
LAB-16's lab forge, lab verify and lab downgrade each write one JSON result file into the verify directory:

    {"kind": "forge" | "keys_only" | "downgrade", "algorithm": "HMAC-SHA256" | "ML-DSA-65",
     "result": "verified" | "broken" | "refused", "entry": <int> | null, "detail": <str>}

That file shape is a lab convention the coordinator accepted for LAB-16 (plan LAB-13, open question 1). A file that
doesn't match it adds nothing.
"""
from __future__ import annotations

import dataclasses
import datetime
import json
import os
import stat
from pathlib import Path
from typing import Any

from model import HANDSHAKE_METHOD, Row

BEATS = ("handshake", "first_allow", "shadow_decision", "deny", "allow_after_fix", "ask_pending", "ask_resolved",
         "modify", "digest_mismatch", "forge_passes_hmac", "forge_fails_mldsa", "keys_only_verify",
         "downgrade_refused")
NO_RECORD_TEXT = "no ACS record"
# The Guardian's refusal of a ClientHello offering no algorithm it signs with (example_guardian
# UNSUPPORTED_SIGNATURE_ALGORITHM, a lab convention until issue #316). The error table has no closer code.
DOWNGRADE_CODE = -32000
DOWNGRADE_REASON = "unsupported_signature_algorithm"
# The reason code a changed tool declaration gets (A.10, a lab convention until issue #38).
DIGEST_MISMATCH = "tool_content_hash_mismatch"
ASK_PENDING, ASK_RESOLVED = "ask_pending", "ask_resolved"

RESULT_KINDS = ("forge", "keys_only", "downgrade")
RESULT_ALGORITHMS = ("HMAC-SHA256", "ML-DSA-65")
RESULT_VALUES = ("verified", "broken", "refused")
_RESULT_BEATS = {
    ("forge", "HMAC-SHA256", "verified"): "forge_passes_hmac",
    ("forge", "ML-DSA-65", "broken"): "forge_fails_mldsa",
    ("keys_only", "ML-DSA-65", "verified"): "keys_only_verify",
    ("downgrade", "HMAC-SHA256", "refused"): "downgrade_refused",
    ("downgrade", "ML-DSA-65", "refused"): "downgrade_refused",
}
# A result file is a few hundred bytes. The bound keeps a wrong file in the directory from being read whole.
MAX_RESULT_BYTES = 64 * 1024


@dataclasses.dataclass
class BeatHistory:
    """What earlier rows showed: the row that took each session's first allow, and the sessions that denied each
    tool. allow_after_fix reads it, and it lasts until the viewer restarts (plan LAB-13, open question 3)."""

    first_allow: dict[str, int] = dataclasses.field(default_factory=dict)
    denials: dict[str, set[str]] = dataclasses.field(default_factory=dict)


def classify(row: Row, history: BeatHistory) -> str | None:
    """The beat this row paints, or None. Called again each time the row changes, so it must give the same answer
    for the same row and history."""
    if history.first_allow.get(row.session_id) == row.id and not (row.decision == "allow" and row.tool):
        # The row that took the first allow is no longer an allow, such as an answer the gateway withheld.
        del history.first_allow[row.session_id]
    if row.kind is not None:
        return _RESULT_BEATS.get((row.kind, row.algorithm, row.decision))
    if row.error_code == DOWNGRADE_CODE and row.error_reason == DOWNGRADE_REASON:
        return "downgrade_refused"
    if row.method == HANDSHAKE_METHOD:
        ok = row.verify in ("verified", "not_checked") and row.error_code is None
        return "handshake" if ok else None
    if row.method in (ASK_PENDING, ASK_RESOLVED):
        return row.method
    if row.decision == "deny":
        if row.mode == "shadow":
            return "shadow_decision"
        if row.tool:
            history.denials.setdefault(row.tool, set()).add(row.session_id)
        return "digest_mismatch" if DIGEST_MISMATCH in row.reason_codes else "deny"
    if row.decision == "modify":
        return "modify"
    if row.decision == "allow" and row.tool:
        if history.denials.get(row.tool, set()) - {row.session_id}:
            return "allow_after_fix"
        if history.first_allow.setdefault(row.session_id, row.id) == row.id:
            return "first_allow"
    return None


def read_result(path: Path) -> dict[str, Any] | None:
    """One result file, or None when it can't be read or isn't the shape above."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = os.read(fd, MAX_RESULT_BYTES + 1)
        finally:
            os.close(fd)
        record = json.loads(data.decode("utf-8")) if len(data) <= MAX_RESULT_BYTES else None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(record, dict):
        return None
    entry = record.get("entry")
    if (record.get("kind") not in RESULT_KINDS or record.get("algorithm") not in RESULT_ALGORITHMS
            or record.get("result") not in RESULT_VALUES or not isinstance(record.get("detail"), str)
            or not (entry is None or (isinstance(entry, int) and not isinstance(entry, bool)))):
        return None
    return record


def result_row(record: dict[str, Any], mtime_ns: int) -> Row:
    """The row for one result. The decision column holds acs-verify's verdict. The verify column stays
    not_checked, since that column is only ever the viewer's own check."""
    moment = datetime.datetime.fromtimestamp(mtime_ns / 1e9, datetime.timezone.utc)
    entry = record.get("entry")
    note = record["detail"] + (f" (entry {entry})" if entry is not None else "")
    return Row(0, 0, moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z", "",
               f"lab {record['kind'].replace('_', '-')}", decision=record["result"], algorithm=record["algorithm"],
               note=note, source="verify", kind=record["kind"])


def result_files(directory: Path | None) -> list[tuple[str, tuple[int, int], dict[str, Any]]]:
    """(name, (mtime_ns, size), record) for every usable *.json result in the directory, by name."""
    if directory is None:
        return []
    try:
        entries = sorted((e for e in os.scandir(directory) if e.name.endswith(".json")), key=lambda e: e.name)
    except OSError:
        return []
    out = []
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        record = read_result(Path(entry.path))
        if record is not None:
            out.append((entry.name, (info.st_mtime_ns, info.st_size), record))
    return out


def verify_dir_beats(directory: Path) -> list[Row]:
    """One row per usable result file in the directory, each with the beat it paints."""
    history = BeatHistory()
    rows = []
    for _, (mtime_ns, _), record in result_files(directory):
        row = result_row(record, mtime_ns)
        row.beat = classify(row, history)
        rows.append(row)
    return rows
