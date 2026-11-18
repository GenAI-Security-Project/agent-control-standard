"""Read the lab gateway's transcripts and audit log, as they grow, into one row per governed step (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.7 and A.12).

The viewer only reads. Each log is reopened read only on every poll and followed from a byte offset, so it never
writes, renames, truncates or locks a file the gateway writes. Everything it shows comes from those files, which an
attacker who reaches the model or the Guardian can fill with terminal escapes and bidi overrides (issue #468), so
every string leaves this module through escape_text.

Inputs, as the gateway writes them (adapters/gateway/README.md, "Records"):

- ACS_TRANSCRIPT_DIR/<session_id>.jsonl: {"dir": "req" | "resp", "envelope": {...}} per line. A response line can
  carry "cause" (a gap line with a null envelope, a body that is no JSON-RPC answer, or an answer that came late),
  and a discards line {"dir": "resp", "envelope": null, "cause": "decision_timeout", "discards": <request_id>}
  marks the answer before it as withheld (a lab convention until issue #577 settles it).
- ACS_AUDIT_FILE: "ACS_AUDIT {json}" per line, the event named by acs_audit_event.
"""
from __future__ import annotations

import collections
import dataclasses
import datetime
import json
import os
import stat
import unicodedata
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

HANDSHAKE_METHOD = "handshake/hello"
ML_DSA_65 = "ML-DSA-65"
AUDIT_PREFIX = b"ACS_AUDIT "
# The one cause the gateway puts on an answer it withheld for coming late, and on a discards line.
LATE_CAUSE = "decision_timeout"
# Events that report on a step the transcript already holds, joined to its row by request_id.
STEP_EVENTS = ("decision_applied", "shadow_decision")
# A read takes at most this much of a log, so one poll stays short however far behind the viewer is. The next poll
# carries on from the offset.
MAX_READ_BYTES = 4 * 1024 * 1024
# A line longer than this is shown as one unreadable row, cut short, and the rest of it up to its newline is dropped.
# The gateway's own lines are far smaller. Without the bound a line that never ends would grow without limit.
MAX_LINE_BYTES = 1024 * 1024
# The longest text a row carries for an unreadable line or a note.
MAX_TEXT_CHARS = 400
# Audit lines for a step whose transcript line hasn't been read yet wait here. The bound keeps a flood of audit lines
# naming steps that never appear from growing memory.
MAX_WAITING_AUDIT = 10_000

# Characters a terminal or a browser can't show as themselves, or that reorder what is shown: controls (Cc), format
# characters such as bidi overrides, isolates and zero-width marks (Cf), surrogates (Cs), and line and paragraph
# separators (Zl, Zp). The test goes by Unicode category, as acs-verify's does, so a character Unicode adds later to
# one of these categories is escaped without a change here.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_SHORT_ESCAPES = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\\": "\\\\"}

Verifier = Callable[[Mapping[str, Any], "Mapping[str, Any] | None", bool], "tuple[str, str | None]"]


def escape_text(value: str) -> str:
    """value with every character a reader can't see as itself written as a visible escape.

    \\n, \\t and \\r keep their usual spelling, other controls up to U+00FF read \\x1b, and anything else unsafe reads
    \\u{202e}. A backslash doubles, so no log text can print something that reads as one of these escapes.
    """
    out = []
    for char in value:
        if char in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[char])
        elif unicodedata.category(char) in _UNSAFE_CATEGORIES:
            code = ord(char)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{{{code:x}}}")
        else:
            out.append(char)
    return "".join(out)


def escape_bytes(raw: bytes) -> str:
    """A line that may not be UTF-8, shown with each byte that doesn't decode as \\xNN and the rest escaped."""
    text = raw.decode("utf-8", errors="surrogateescape")
    # surrogateescape maps each undecodable byte to U+DC80 to U+DCFF, which gives the byte back exactly.
    return "".join(f"\\x{ord(c) - 0xDC00:02x}" if 0xDC80 <= ord(c) <= 0xDCFF else escape_text(c) for c in text)


def _clip(text: str) -> str:
    return text if len(text) <= MAX_TEXT_CHARS else text[:MAX_TEXT_CHARS] + "..."


def receipt_time() -> str:
    """Now, as RFC 3339 UTC with milliseconds, the form every time the viewer stamps takes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class LogTail:
    """One log file followed from a byte offset. Each read returns the complete lines added since the last one.

    A last line with no newline yet is held back until its newline arrives, so a line the gateway is still writing is
    never shown half written and never shown twice. The file is reopened on every read, so a file replaced under the
    same name, or cut shorter, is read again from its start.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._offset = 0
        self._partial = b""
        self._identity: tuple[int, int] | None = None
        self._dropping = False

    def read_new(self) -> list[bytes]:
        data = self._read()
        if not data:
            return []
        pieces = (self._partial + data).split(b"\n")
        self._partial = pieces.pop()
        lines: list[bytes] = []
        for piece in pieces:
            if self._dropping:
                # The rest of a line already shown cut short.
                self._dropping = False
                continue
            if piece:
                lines.append(piece)
        if len(self._partial) > MAX_LINE_BYTES:
            if not self._dropping:
                lines.append(self._partial[:MAX_LINE_BYTES])
            self._partial = b""
            self._dropping = True
        return lines

    def _read(self) -> bytes:
        # O_NONBLOCK and the regular-file check keep a FIFO planted under a log's name from hanging the viewer, and
        # O_NOFOLLOW keeps a symlink from pointing it at a file the gateway never wrote.
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError:
            return b""
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return b""
            identity = (info.st_dev, info.st_ino)
            if identity != self._identity or info.st_size < self._offset:
                self._identity, self._offset, self._partial, self._dropping = identity, 0, b"", False
            if info.st_size == self._offset:
                return b""
            os.lseek(fd, self._offset, os.SEEK_SET)
            data = os.read(fd, MAX_READ_BYTES)
        except OSError:
            return b""
        finally:
            os.close(fd)
        self._offset += len(data)
        return data


@dataclasses.dataclass
class Row:
    """One line of the viewer's table. id stays fixed and seq grows each time the row changes, so a poll for every
    seq after the last one seen returns new rows and changed rows alike."""

    id: int
    seq: int
    t: str
    session_id: str
    method: str
    tool: str | None = None
    decision: str | None = None
    reason_codes: list[str] = dataclasses.field(default_factory=list)
    algorithm: str | None = None
    verify: str = "not_checked"
    note: str | None = None
    beat: str | None = None
    # What the classifier reads. Never served.
    request_id: str | None = None
    mode: str | None = None
    error_code: int | None = None
    error_reason: str | None = None
    source: str = "transcript"
    kind: str | None = None
    # An unreadable line's note is escaped from its bytes when read, so it is not escaped a second time.
    note_escaped: bool = False

    PUBLIC = ("id", "seq", "t", "session_id", "method", "tool", "decision", "reason_codes", "algorithm", "verify",
              "note", "beat")

    def escaped(self) -> Row:
        def clean(value: Any) -> Any:
            if isinstance(value, str):
                return escape_text(value)
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        changes = {f.name: clean(getattr(self, f.name)) for f in dataclasses.fields(self)}
        if self.note_escaped:
            changes["note"] = self.note
        return dataclasses.replace(self, **changes)

    def public(self) -> dict[str, Any]:
        """The served fields, every string escaped."""
        row = self.escaped()
        return {name: getattr(row, name) for name in self.PUBLIC}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def signature_algorithm(response: Mapping[str, Any] | None) -> str | None:
    """The algorithm the answer's signature names, in result or in error, or None for an unsigned answer."""
    if not isinstance(response, Mapping):
        return None
    container = response.get("result") if "result" in response else response.get("error")
    signature = _mapping(container).get("signature")
    if not isinstance(signature, Mapping):
        return None
    return _text(signature.get("algorithm")) or "unnamed"


def unchecked(request: Mapping[str, Any], response: Mapping[str, Any] | None, mldsa_session: bool) -> tuple[str, str | None]:
    """The mark when no verifier is wired in: nothing is checked, and an unsigned answer says so."""
    if response is None:
        return "no_answer", None
    algorithm = signature_algorithm(response)
    return ("unsigned", None) if algorithm is None else ("not_checked", algorithm)


@dataclasses.dataclass
class _Session:
    tail: LogTail
    open_request: dict[str, Any] | None = None
    by_request: dict[str, Row] = dataclasses.field(default_factory=dict)
    # Whether this session's ServerHello verified under ML-DSA-65, which makes any later HMAC answer a downgrade.
    mldsa: bool = False


class Model:
    """Every row read so far. refresh() reads what the logs gained, and rows_after() hands out what changed."""

    def __init__(self, transcript_dir: Path, audit_file: Path | None, verifier: Verifier | None) -> None:
        self.transcript_dir = Path(transcript_dir)
        self.audit_tail = LogTail(Path(audit_file)) if audit_file else None
        self.verifier: Verifier = verifier or unchecked
        self._sessions: dict[str, _Session] = {}
        self._rows: dict[int, Row] = {}
        self._next_id = 1
        self._seq = 0
        self._waiting: collections.OrderedDict[str, Mapping[str, Any]] = collections.OrderedDict()

    # Reading

    def refresh(self) -> None:
        for path in self._transcript_files():
            session_id = path.stem
            session = self._sessions.get(session_id)
            if session is None:
                session = self._sessions[session_id] = _Session(LogTail(path))
            for raw in session.tail.read_new():
                self._transcript_line(session_id, session, raw)
        if self.audit_tail is not None:
            for raw in self.audit_tail.read_new():
                self._audit_line(raw)

    def rows_after(self, seq: int) -> list[Row]:
        """Every row new or changed after seq, oldest change first, with every string escaped."""
        return [row.escaped() for row in sorted(self._rows.values(), key=lambda r: r.seq) if row.seq > seq]

    @property
    def last_seq(self) -> int:
        return self._seq

    def _transcript_files(self) -> list[Path]:
        try:
            names = sorted(entry.name for entry in os.scandir(self.transcript_dir)
                           if entry.name.endswith(".jsonl"))
        except OSError:
            return []
        return [self.transcript_dir / name for name in names]

    # Rows

    def _add(self, row: Row) -> Row:
        row.id = self._next_id
        self._next_id += 1
        self._touch(row)
        self._rows[row.id] = row
        return row

    def _touch(self, row: Row) -> None:
        self._seq += 1
        row.seq = self._seq

    def _unreadable(self, raw: bytes, session_id: str, source: str, why: str | None = None) -> None:
        self._add(Row(0, 0, receipt_time(), session_id, "unreadable", note=why or _clip(escape_bytes(raw)),
                      source=source, note_escaped=why is None))

    # The transcript

    def _transcript_line(self, session_id: str, session: _Session, raw: bytes) -> None:
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._unreadable(raw, session_id, "transcript")
            return
        if not isinstance(record, dict) or record.get("dir") not in ("req", "resp"):
            self._unreadable(raw, session_id, "transcript")
            return
        envelope = record.get("envelope")
        if record["dir"] == "req":
            if not isinstance(envelope, dict):
                self._unreadable(raw, session_id, "transcript")
                return
            if session.open_request is not None:
                # A request followed by another request got no answer line at all.
                self._step_row(session_id, session, session.open_request, None, None)
            session.open_request = envelope
            return
        if "discards" in record:
            self._discard(session, record.get("discards"))
            return
        if session.open_request is None:
            self._unreadable(raw, session_id, "transcript", "a response line with no request before it")
            return
        request, session.open_request = session.open_request, None
        cause = _text(record.get("cause"))
        response = envelope if isinstance(envelope, dict) and ("result" in envelope or "error" in envelope) else None
        self._step_row(session_id, session, request, response, cause)

    def _step_row(self, session_id: str, session: _Session, request: dict[str, Any],
                  response: dict[str, Any] | None, cause: str | None) -> None:
        params = _mapping(request.get("params"))
        payload = _mapping(params.get("payload"))
        request_id = _text(params.get("request_id"))
        row = Row(0, 0, _text(params.get("timestamp")) or receipt_time(), session_id,
                  _text(request.get("method")) or "unnamed", tool=_text(_mapping(payload.get("tool")).get("name")),
                  request_id=request_id)
        if response is None:
            row.verify, row.note = "no_answer", cause
        else:
            if "result" in response:
                result = _mapping(response.get("result"))
                row.decision = _text(result.get("decision"))
                row.reason_codes = _strings(result.get("reason_codes"))
            else:
                error = _mapping(response.get("error"))
                data = _mapping(error.get("data"))
                code = error.get("code")
                row.error_code = code if isinstance(code, int) and not isinstance(code, bool) else None
                row.error_reason = _text(data.get("reason"))
                row.reason_codes = [row.error_reason] if row.error_reason else []
                row.note = f"error {code}: {_text(error.get('message')) or ''}".rstrip(": ")
            if cause == LATE_CAUSE:
                row.note = "the answer came late and the gateway withheld it (decision_timeout)"
            try:
                row.verify, row.algorithm = self.verifier(request, response, session.mldsa)
            except Exception:  # noqa: BLE001
                # A check that breaks never reads as a pass.
                row.verify, row.algorithm = "failed", signature_algorithm(response)
            if row.method == HANDSHAKE_METHOD and row.verify == "verified" and row.algorithm == ML_DSA_65:
                session.mldsa = True
        self._add(row)
        if request_id is not None:
            session.by_request[request_id] = row
            waiting = self._waiting.pop(request_id, None)
            if waiting is not None:
                self._join(row, waiting)

    def _discard(self, session: _Session, request_id: Any) -> None:
        row = session.by_request.get(request_id) if isinstance(request_id, str) else None
        if row is not None:
            row.note = "the gateway withheld this answer and denied the step (decision_timeout)"
            self._touch(row)

    # The audit log

    def _audit_line(self, raw: bytes) -> None:
        if not raw.startswith(AUDIT_PREFIX):
            self._unreadable(raw, "", "audit")
            return
        try:
            event = json.loads(raw[len(AUDIT_PREFIX):].decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._unreadable(raw, "", "audit")
            return
        if not isinstance(event, dict):
            self._unreadable(raw, "", "audit")
            return
        name = event.get("acs_audit_event")
        if name in STEP_EVENTS:
            request_id = _text(event.get("request_id"))
            session = self._sessions.get(_text(event.get("session_id")) or "")
            row = session.by_request.get(request_id) if session and request_id else None
            if row is not None:
                self._join(row, event)
            elif request_id is not None:
                self._waiting[request_id] = event
                while len(self._waiting) > MAX_WAITING_AUDIT:
                    self._waiting.popitem(last=False)

    def _join(self, row: Row, event: Mapping[str, Any]) -> None:
        applied = _text(event.get("decision"))
        said = _text(event.get("guardian_decision"))
        cause = _text(event.get("cause"))
        if not row.reason_codes:
            row.reason_codes = _strings(event.get("reason_codes"))
        if event.get("acs_audit_event") == "shadow_decision":
            # Shadow forwards every call unchanged, so the decision worth showing is the one the Guardian made.
            row.mode, row.note = "shadow", "shadow"
            row.decision = said or row.decision
        else:
            row.mode = "enforce"
            if applied is not None and (applied != said or cause):
                detail = f" ({cause})" if cause else ""
                row.note = f"gateway applied {applied}{detail}" + (f", Guardian said {said}" if said else "")
            row.decision = applied or row.decision
        self._touch(row)

