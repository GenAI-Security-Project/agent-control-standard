"""What the module 7 kit reads from the gateway's transcripts (issue #589, LAB-16 Task 12).

Version 1.2.0. Owner: Rock Lambros. Standard library only, plus the run record reader beside the checks.

lab forge and lab verify both need a session's response algorithm, which only its ServerHello names, and both pick
the newest session that fits. The reading goes through evidence.Evidence, so the kit refuses the same things a check
refuses: a session id that isn't the gateway's canonical UUID, a transcript that is a link, and a file larger than
evidence.MAX_READ_BYTES. acs-verify on a forged copy goes through Evidence.verify too, with directory="forged", so
the rule that ML-DSA-65 is always checked against the fingerprint in .env exists once (ledger ruling 2026-11-17).

Lab conventions: the x_acs_lab_response_algorithm ServerHello field and ML-DSA-65 response signing (issue #316).
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CHECKS_DIR = Path(__file__).resolve().parents[1] / "checks"
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

# Imported under its own name, as lab_modules registers it, so lab_modules' _call recognizes its EvidenceError.
import evidence  # noqa: E402
import report  # noqa: E402  (the CLI's directory, on sys.path wherever lab.py runs)

HMAC = "HMAC-SHA256"
MLDSA = "ML-DSA-65"
HANDSHAKE_METHOD = "handshake/hello"
TOOL_CALL_METHOD = "steps/toolCallRequest"
RESPONSE_ALGORITHM_FIELD = "x_acs_lab_response_algorithm"


def _folded(message: str) -> str:
    # acs-verify's reasons and a Guardian's error text can hold newlines, and every kit verdict is one line.
    return " ".join(str(message).split())


def done(message: str) -> int:
    report.done(_folded(message))
    return report.EXIT_PASS


def not_yet(message: str, code: int = report.EXIT_NOT_YET) -> int:
    report.not_yet(_folded(message))
    return code


def broken(message: str) -> int:
    """A lab that can't give a verdict: one NOT YET line and exit 2."""
    return not_yet(message, report.EXIT_BROKEN)


def session_argument(value: str) -> str:
    """value when it is a gateway session id, the canonical UUID the gateway names each transcript with, or
    ValueError. The kit's parsers call it, so a guide line such as --session <id> fails the guide checks, not the
    attendee who copies it (Task 13 review M6)."""
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        canonical = None
    if canonical != value:
        raise ValueError(f"--session takes a gateway session id, such as {uuid.UUID(int=0)}, not {value!r}")
    return value


def bundle_root(root: Path | str | None = None) -> Path:
    """The bundle: root when given, else LAB_BUNDLE (/lab in the container), else the directory above modules/."""
    if root is not None:
        return Path(root)
    return Path(os.environ.get("LAB_BUNDLE") or Path(__file__).resolve().parents[2])


@dataclass(frozen=True)
class Transcript:
    """One session's transcript as whole lines, each kept byte for byte, and each parsed where it parses."""

    session_id: str
    lines: tuple[bytes, ...]
    records: tuple[dict[str, Any] | None, ...]

    def _pairs(self) -> list[tuple[int, dict[str, Any], dict[str, Any]]]:
        """(response line number, request, response) for each request line answered by the next line, from 1."""
        pairs = []
        for i in range(len(self.records) - 1):
            req, resp = self.records[i], self.records[i + 1]
            if (req is not None and resp is not None and req.get("dir") == "req" and resp.get("dir") == "resp"
                    and isinstance(req.get("envelope"), dict) and isinstance(resp.get("envelope"), dict)):
                pairs.append((i + 2, req["envelope"], resp["envelope"]))
        return pairs

    @property
    def algorithm(self) -> str | None:
        """The response algorithm the ServerHello negotiated, or None when the transcript holds no ServerHello.

        The Guardian names ML-DSA-65 in the ServerHello and names nothing under HMAC. The forger can rewrite this
        field, which is why acs-verify takes the algorithm from its flags and never from the transcript (PREMORTEM
        P5). lab forge reads it to pick the flags an attendee would pick. lab verify never chooses a session by it, and
        reads it only to explain a failure (review I1)."""
        for _, req, resp in self._pairs():
            result = resp.get("result")
            if req.get("method") == HANDSHAKE_METHOD and isinstance(result, dict):
                return MLDSA if result.get(RESPONSE_ALGORITHM_FIELD) == MLDSA else HMAC
        return None

    @property
    def denied_line(self) -> int | None:
        """The line number of the first signed deny answering a tool call, or None.

        A line with a cause is one the gateway marked, such as an answer that came back late, so it is left alone."""
        for number, req, resp in self._pairs():
            result = resp.get("result")
            if (req.get("method") == TOOL_CALL_METHOD and isinstance(result, dict) and result.get("decision") == "deny"
                    and isinstance(result.get("signature"), dict) and "cause" not in self.records[number - 1]):
                return number
        return None


def _parse(line: bytes) -> dict[str, Any] | None:
    try:
        record = json.loads(line)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def read(ev: evidence.Evidence, session_id: str) -> Transcript | None:
    """The session's transcript, or None when it wrote none. Raises evidence.EvidenceError as Evidence does."""
    path = ev.transcript_path(session_id)
    if not path.is_file():
        return None
    data = ev.read_bounded(path)
    end = data.rfind(b"\n")
    # Bytes after the last newline are a write still in progress, as evidence reads them.
    lines = tuple(data[:end].split(b"\n")) if end >= 0 else ()
    return Transcript(session_id, lines, tuple(_parse(line) for line in lines))


def newest(ev: evidence.Evidence, fits: Callable[[Transcript], bool]) -> Transcript | None:
    """The most recently written transcript that fits, or None. Files the gateway couldn't have named are skipped."""
    directory = ev.state / "transcripts"
    if not directory.is_dir():
        return None
    candidates = []
    for path in directory.glob("*.jsonl"):
        try:
            canonical = str(uuid.UUID(path.stem)) == path.stem
        except ValueError:
            canonical = False
        if canonical and not path.is_symlink() and path.is_file():
            candidates.append((path.stat().st_mtime_ns, path.stem))
    for _, session_id in sorted(candidates, reverse=True):
        transcript = read(ev, session_id)
        if transcript is not None and fits(transcript):
            return transcript
    return None
