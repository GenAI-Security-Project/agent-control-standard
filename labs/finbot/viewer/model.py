"""Read the lab gateway's transcripts and audit log, as they grow, into one row per governed step (issue #586).

Owner: Rock Lambros. Lab code for the FinBot lab (BUILD_PLAN A.7 and A.12).

The viewer only reads. Each log is reopened read only on every poll and followed from a byte offset, so it never
writes, renames, truncates or locks a file the gateway writes. Everything it shows comes from those files, which an
attacker who reaches the model or the Guardian can fill with terminal escapes and bidi overrides (issue #468), so
every string leaves this module through escape_text, exactly once.

Three sources, and what each may say:

- The transcript holds the signed answers. A row's decision is the signed answer's decision and nothing else.
- acs-verify (acs.testing.verify), run over a session's whole transcript, is the one source of the verify mark. A row
  reads verified only when acs-verify accepts the session and the row's answer carries a signature it checked.
- The audit log is the gateway's unsigned word on what it did. It fills the applied column and never changes the
  decision. Where it disagrees with the signed answer the row says so (fix round 1, I3).

Inputs, as the gateway writes them (adapters/gateway/README.md, "Records"):

- ACS_TRANSCRIPT_DIR/<session_id>.jsonl: {"dir": "req" | "resp", "envelope": {...}} per line. A response line can
  carry "cause" (a gap line with a null envelope, a body that is no JSON-RPC answer, or an answer that came late),
  and a discards line {"dir": "resp", "envelope": null, "cause": "decision_timeout", "discards": <request_id>}
  marks the answer before it as withheld (a lab convention until issue #577 settles it).
- ACS_AUDIT_FILE: "ACS_AUDIT {json}" per line, the event named by acs_audit_event.

Every store here is bounded (fix round 1, I5), so a junk or endless log costs bounded memory and bounded time per
poll. The bounds are the MAX_ constants below, and the README states them.
"""
from __future__ import annotations

import collections
import dataclasses
import datetime
import json
import os
import stat
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HANDSHAKE_METHOD = "handshake/hello"
ML_DSA_65 = "ML-DSA-65"
AUDIT_PREFIX = b"ACS_AUDIT "
# The one cause the gateway puts on an answer it withheld for coming late, and on a discards line.
LATE_CAUSE = "decision_timeout"
# Events that report on a step the transcript already holds, joined to its row by session_id and request_id.
STEP_EVENTS = ("decision_applied", "shadow_decision")
# Events that are rows of their own: an ASK held for the approver and its outcome (LAB-08), and a replay miss, which
# names no session or request (LAB-06).
ASK_EVENTS = ("ask_pending", "ask_resolved")
REPLAY_MISS = "replay_miss"
REPLAY_MISS_NOTE = "replay miss: recorded neutral reply"
# The epoch moves on lab mode, lab sign and a policy reload. Rows from before it are not the current run's record.
EPOCH_BUMPED = "epoch_bumped"

# Bounds (I5). A read takes at most MAX_READ_BYTES of a log, so one poll stays short however far behind the viewer
# is, and the next poll carries on from the offset. 256 KiB of junk lines costs about 0.2 seconds under the lock,
# and holds a few hundred gateway lines.
MAX_READ_BYTES = 256 * 1024
# A line longer than this is one unreadable row, cut short, and the rest of it up to its newline is dropped.
MAX_LINE_BYTES = 1024 * 1024
# Rows kept. Past it the oldest rows go, and the page has them already or never needed them.
MAX_ROWS = 5000
# Rows in one answer to the page. The page asks again at once while an answer says there is more.
MAX_ROWS_PER_ANSWER = 500
# Session files followed, the most recently changed first.
MAX_SESSIONS = 200
# A session longer than this is not judged here, since acs-verify reads the whole session on every change. Its rows
# read not checked and say to run lab verify. 4000 lines is about 2000 steps, far past a lab scenario, and acs-verify
# reads that many in well under a second.
MAX_SESSION_LINES = 4000
MAX_SESSION_BYTES = 32 * 1024 * 1024
# The longest text a row carries for an unreadable line or a note.
MAX_TEXT_CHARS = 400
# Audit lines for a step whose transcript line hasn't been read yet wait here.
MAX_WAITING_AUDIT = 10_000

TOO_LONG_NOTE = "this session is too long for the viewer to judge. Run lab verify on it"

# Characters a terminal or a browser can't show as themselves, or that reorder what is shown: controls (Cc), format
# characters such as bidi overrides, isolates and zero-width marks (Cf), surrogates (Cs), and line and paragraph
# separators (Zl, Zp). The test goes by Unicode category, as acs-verify's does, so a character Unicode adds later to
# one of these categories is escaped without a change here.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_SHORT_ESCAPES = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\\": "\\\\"}


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


def _moment(value: str) -> datetime.datetime | None:
    try:
        moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def receipt_time() -> str:
    """Now, as RFC 3339 UTC with milliseconds, the form every time the viewer stamps takes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class LogTail:
    """One log file followed from a byte offset. Each read returns the complete lines added since the last one.

    A last line with no newline yet is held back until its newline arrives, so a line the gateway is still writing is
    never shown half written and never shown twice. The file is reopened on every read, so a file replaced under the
    same name, or cut shorter, is read again from its start, and restarts counts that.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.restarts = 0
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
                if self._identity is not None:
                    self.restarts += 1
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
    seq after the last one seen returns new rows and changed rows alike.

    decision is the signed answer's decision. applied is what the audit log says the gateway did. note joins what the
    transcript, the audit log and acs-verify said about the row.
    """

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
    applied: str | None = None
    conflict: bool = False
    # What the model and the classifier read. Never served.
    request_id: str | None = None
    mode: str | None = None
    error_code: int | None = None
    error_reason: str | None = None
    source: str = "transcript"
    kind: str | None = None
    signed: bool = False
    answered: bool = False
    lines: tuple[int, ...] = ()
    gateway_note: str | None = None
    check_note: str | None = None
    unreadable_count: int = 0
    # An unreadable line's note is escaped from its bytes when read, so it is not escaped a second time.
    note_escaped: bool = False

    PUBLIC = ("id", "seq", "t", "session_id", "method", "tool", "decision", "applied", "conflict", "reason_codes",
              "algorithm", "verify", "note", "beat")

    def escaped(self) -> Row:
        """A copy with every string escaped once, and note holding everything said about the row."""
        def clean(value: Any) -> Any:
            if isinstance(value, str):
                return escape_text(value)
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        changes = {f.name: clean(getattr(self, f.name)) for f in dataclasses.fields(self)}
        own = self.note if self.note_escaped else escape_text(self.note) if self.note else None
        if self.unreadable_count > 1:
            own = f"{own} ({self.unreadable_count} unreadable lines)"
        parts = [p for p in (own, changes["gateway_note"], changes["check_note"]) if p]
        changes.update(note=" | ".join(parts) or None, gateway_note=None, check_note=None, unreadable_count=0,
                       note_escaped=True)
        return dataclasses.replace(self, **changes)

    def public(self) -> dict[str, Any]:
        """The served fields of a row escaped() returned. It escapes nothing itself, so nothing is escaped twice."""
        return {name: getattr(self, name) for name in self.PUBLIC}


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


@dataclasses.dataclass
class _Session:
    session_id: str
    tail: LogTail
    restarts: int = 0
    lines: list[bytes] = dataclasses.field(default_factory=list)
    line_count: int = 0
    size: int = 0
    too_long: bool = False
    open_request: tuple[int, dict[str, Any]] | None = None
    by_request: dict[str, Row] = dataclasses.field(default_factory=dict)
    by_line: dict[int, Row] = dataclasses.field(default_factory=dict)
    rows: list[Row] = dataclasses.field(default_factory=list)
    # The algorithm the session's first signed answer names. Not ML-DSA-65 means an HMAC session, which nothing here
    # can check, so its rows read not checked and never verified.
    first_algorithm: str | None = None
    last_unreadable: Row | None = None
    dirty: bool = False
    judged_with: int = -1

    def reset(self) -> None:
        """The file was replaced or cut shorter. Its old rows stay as history, and the new content starts over."""
        self.lines, self.line_count, self.size, self.too_long = [], 0, 0, False
        self.open_request, self.by_request, self.by_line, self.rows = None, {}, {}, []
        self.first_algorithm, self.last_unreadable, self.dirty = None, None, True


class Model:
    """Every row read so far, within the bounds. refresh() reads what the logs gained and judges every session that
    changed, and page() hands out what changed."""

    def __init__(self, transcript_dir: Path, audit_file: Path | None, keys: Any | None, *,
                 verify_dir: Path | None = None) -> None:
        # Imported here: beats builds on Row, defined above.
        import beats

        self._beats = beats
        self._history = beats.BeatHistory()
        # keys is a verify.KeySource, or None for a viewer with no key document.
        self.keys = keys
        self.verify_dir = Path(verify_dir) if verify_dir else None
        self.transcript_dir = Path(transcript_dir)
        self.audit_tail = LogTail(Path(audit_file)) if audit_file else None
        self._results: dict[str, tuple[tuple[int, int], Row]] = {}
        self._epoch_at: datetime.datetime | None = None
        self._sessions: dict[str, _Session] = {}
        # Rows in seq order: a change moves its row to the end, so the rows after any seq are a walk from the end.
        self._rows: collections.OrderedDict[int, Row] = collections.OrderedDict()
        self._next_id = 1
        self._seq = 0
        self._waiting: collections.OrderedDict[tuple[str, str], Mapping[str, Any]] = collections.OrderedDict()
        self._audit_unreadable: Row | None = None

    # Reading

    def refresh(self) -> None:
        for path in self._transcript_files():
            session = self._sessions.get(path.stem)
            if session is None:
                session = self._sessions[path.stem] = _Session(path.stem, LogTail(path))
            raws = session.tail.read_new()
            if session.tail.restarts != session.restarts:
                session.restarts = session.tail.restarts
                session.reset()
            for raw in raws:
                self._transcript_line(session, raw)
        if self.audit_tail is not None:
            for raw in self.audit_tail.read_new():
                self._audit_line(raw)
        self._read_results()
        self._judge()

    def rows_after(self, seq: int) -> list[Row]:
        """Every row new or changed after seq, oldest change first, escaped once."""
        return [row.escaped() for row in self._changed_after(seq)]

    def page(self, seq: int) -> tuple[list[Row], int, bool]:
        """(rows, next, more): at most MAX_ROWS_PER_ANSWER rows changed after seq, escaped once, the seq to ask from
        next, and whether more rows wait past this page."""
        changed = self._changed_after(seq)
        if len(changed) > MAX_ROWS_PER_ANSWER:
            changed = changed[:MAX_ROWS_PER_ANSWER]
            return [row.escaped() for row in changed], changed[-1].seq, True
        return [row.escaped() for row in changed], self._seq, False

    def _changed_after(self, seq: int) -> list[Row]:
        changed = []
        for row in reversed(self._rows.values()):
            if row.seq <= seq:
                break
            changed.append(row)
        changed.reverse()
        return changed

    @property
    def last_seq(self) -> int:
        return self._seq

    @property
    def no_record(self) -> bool:
        """True while no ACS row has come since the viewer started or since the last epoch bump. With ACS off the
        gateway writes no transcript, so the page shows "no ACS record", the module 1 and module 2 beat (A.12)."""
        return not any(self._is_record(row) for row in self._rows.values())

    def _is_record(self, row: Row) -> bool:
        governed = (row.source == "transcript" and row.method != "unreadable") or row.method in ASK_EVENTS
        if not governed:
            return False
        if self._epoch_at is None:
            return True
        moment = _moment(row.t)
        # A time that can't be read counts as current, so a row is never hidden for its timestamp.
        return moment is None or moment > self._epoch_at

    def _transcript_files(self) -> list[Path]:
        try:
            found = []
            for entry in os.scandir(self.transcript_dir):
                if entry.name.endswith(".jsonl") and entry.is_file(follow_symlinks=False):
                    found.append((entry.stat(follow_symlinks=False).st_mtime_ns, entry.name))
        except OSError:
            return []
        newest = sorted(found, reverse=True)[:MAX_SESSIONS]
        return [self.transcript_dir / name for _, name in sorted(newest, key=lambda item: item[1])]

    # Rows

    def _add(self, row: Row) -> Row:
        row.id = self._next_id
        self._next_id += 1
        self._rows[row.id] = row
        self._touch(row)
        while len(self._rows) > MAX_ROWS:
            self._drop(min(self._rows))
        return row

    def _drop(self, row_id: int) -> None:
        row = self._rows.pop(row_id)
        session = self._sessions.get(row.session_id)
        if session is not None:
            if row.request_id is not None and session.by_request.get(row.request_id) is row:
                del session.by_request[row.request_id]
            for line in row.lines:
                if session.by_line.get(line) is row:
                    del session.by_line[line]

    def _touch(self, row: Row) -> None:
        if row.id not in self._rows:
            return
        self._seq += 1
        row.seq = self._seq
        self._rows.move_to_end(row.id)
        row.beat = self._beats.classify(row, self._history)

    def _unreadable(self, raw: bytes, session: _Session | None, why: str | None = None,
                    number: int | None = None) -> None:
        last = session.last_unreadable if session is not None else self._audit_unreadable
        if why is None and last is not None and last.id in self._rows:
            # A run of unreadable lines is one row with a count, so junk can't become a row per line. acs-verify
            # stops at the run's first line, which the row already holds.
            last.unreadable_count += 1
            self._touch(last)
            return
        row = self._add(Row(0, 0, receipt_time(), session.session_id if session else "", "unreadable",
                            note=why or _clip(escape_bytes(raw)), source="transcript" if session else "audit",
                            note_escaped=why is None, unreadable_count=1,
                            lines=(number,) if number is not None else ()))
        if session is not None:
            session.rows.append(row)
            if number is not None:
                session.by_line[number] = row
        if why is None:
            if session is not None:
                session.last_unreadable = row
            else:
                self._audit_unreadable = row

    # The transcript

    def _record_line(self, session: _Session, raw: bytes) -> int:
        """Keep the line for acs-verify and give its 1-based number in the session."""
        session.line_count += 1
        session.size += len(raw)
        session.dirty = True
        if session.too_long:
            return session.line_count
        if session.line_count > MAX_SESSION_LINES or session.size > MAX_SESSION_BYTES:
            # Stop holding the session's lines. Its rows read not checked from here on.
            session.too_long, session.lines = True, []
        else:
            session.lines.append(raw)
        return session.line_count

    def _transcript_line(self, session: _Session, raw: bytes) -> None:
        number = self._record_line(session, raw)
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            record = None
        envelope = record.get("envelope") if isinstance(record, dict) else None
        if (not isinstance(record, dict) or record.get("dir") not in ("req", "resp")
                or (record["dir"] == "req" and not isinstance(envelope, dict))):
            self._unreadable(raw, session, number=number)
            return
        session.last_unreadable = None
        if record["dir"] == "req":
            if session.open_request is not None:
                # A request followed by another request got no answer line at all.
                self._step_row(session, session.open_request, None, None, None)
            session.open_request = (number, envelope)
            return
        if "discards" in record:
            self._discard(session, record.get("discards"), number)
            return
        if session.open_request is None:
            self._unreadable(raw, session, "a response line with no request before it", number)
            return
        request, session.open_request = session.open_request, None
        cause = _text(record.get("cause"))
        response = envelope if isinstance(envelope, dict) and ("result" in envelope or "error" in envelope) else None
        self._step_row(session, request, (number, response), cause, record)

    def _step_row(self, session: _Session, request: tuple[int, dict[str, Any]],
                  response: tuple[int, dict[str, Any] | None] | None, cause: str | None,
                  record: dict[str, Any] | None) -> None:
        req_line, envelope = request
        params = _mapping(envelope.get("params"))
        payload = _mapping(params.get("payload"))
        request_id = _text(params.get("request_id"))
        row = Row(0, 0, _text(params.get("timestamp")) or receipt_time(), session.session_id,
                  _text(envelope.get("method")) or "unnamed", tool=_text(_mapping(payload.get("tool")).get("name")),
                  request_id=request_id, lines=(req_line,) if response is None else (req_line, response[0]))
        answer = response[1] if response is not None else None
        if answer is None:
            row.verify, row.note = "no_answer", cause
        else:
            row.answered = True
            if "result" in answer:
                result = _mapping(answer.get("result"))
                row.decision = _text(result.get("decision"))
                row.reason_codes = _strings(result.get("reason_codes"))
            else:
                error = _mapping(answer.get("error"))
                data = _mapping(error.get("data"))
                code = error.get("code")
                row.error_code = code if isinstance(code, int) and not isinstance(code, bool) else None
                row.error_reason = _text(data.get("reason"))
                row.reason_codes = [row.error_reason] if row.error_reason else []
                row.note = f"error {code}: {_text(error.get('message')) or ''}".rstrip(": ")
            if cause == LATE_CAUSE:
                row.note = "the answer came late and the gateway withheld it (decision_timeout)"
            row.algorithm = signature_algorithm(answer)
            row.signed = row.algorithm is not None
            if row.signed and session.first_algorithm is None:
                session.first_algorithm = row.algorithm
            row.verify = "not_checked" if row.signed else "unsigned"
        self._add(row)
        session.rows.append(row)
        for line in row.lines:
            session.by_line[line] = row
        if request_id is not None:
            session.by_request[request_id] = row
            waiting = self._waiting.pop((session.session_id, request_id), None)
            if waiting is not None:
                self._join(row, waiting)

    def _discard(self, session: _Session, request_id: Any, number: int) -> None:
        row = session.by_request.get(request_id) if isinstance(request_id, str) else None
        if row is not None:
            row.note = "the gateway withheld this answer and denied the step (decision_timeout)"
            session.by_line[number] = row
            self._touch(row)

    # acs-verify

    def _judge(self) -> None:
        """Run acs-verify over every session that changed, or every session when the key document changed."""
        keys = self.keys.current() if self.keys is not None else None
        generation = self.keys.generation if self.keys is not None else 0
        for session in self._sessions.values():
            if session.dirty or session.judged_with != generation:
                session.dirty, session.judged_with = False, generation
                self._judge_session(session, keys)

    def _judge_session(self, session: _Session, keys: Any | None) -> None:
        from verify import verify_session

        session.rows = [row for row in session.rows if row.id in self._rows]
        if session.too_long:
            verdict = None
            marks = {row.id: ("not_checked" if row.answered else "no_answer", TOO_LONG_NOTE) for row in session.rows}
        elif keys is None or (session.first_algorithm not in (None, ML_DSA_65)):
            # No key document, or an HMAC session: nothing here can check it, so no row reads verified (I2).
            verdict = None
            marks = {row.id: (self._unchecked(row), None) for row in session.rows}
        else:
            verdict = verify_session(session.lines, keys)
            marks = {row.id: self._mark(row, session, verdict) for row in session.rows}
        for row in session.rows:
            mark, note = marks[row.id]
            if (row.verify, row.check_note) != (mark, note):
                row.verify, row.check_note = mark, note
                self._touch(row)

    @staticmethod
    def _unchecked(row: Row) -> str:
        if row.method == "unreadable":
            return "not_checked"
        if not row.answered:
            return "no_answer"
        return "not_checked" if row.signed else "unsigned"

    def _mark(self, row: Row, session: _Session, verdict: Any) -> tuple[str, str | None]:
        if not verdict.ok and verdict.failure_line is None:
            # The key document itself failed, such as a fingerprint the settings pin that it doesn't hold, so no
            # signed answer in the session can verify.
            reason = _clip(f"acs-verify: {verdict.failure_code}: {verdict.failure_reason}")
            return ("failed", reason) if row.signed and row.answered else (self._unchecked(row), reason)
        if not verdict.ok:
            failed = session.by_line.get(verdict.failure_line)
            if failed is row:
                return "failed", _clip(f"acs-verify: {verdict.failure_code}: {verdict.failure_reason}")
            stopped = f"the session failed acs-verify at line {verdict.failure_line} ({verdict.failure_code})"
            return ("no_answer" if not row.answered and row.method != "unreadable" else "not_checked"), stopped
        if row.method == "unreadable" or not row.answered:
            return self._unchecked(row), None
        if not row.signed:
            # acs-verify passed the session, so this unsigned answer is one section 10 allows: ping, or the -32004 for
            # a key_id the Guardian holds no secret for.
            return "unsigned", None
        if verdict.warnings:
            return "warning", _clip(verdict.warnings[0])
        return "verified", None

    # The audit log

    def _audit_line(self, raw: bytes) -> None:
        event = None
        if raw.startswith(AUDIT_PREFIX):
            try:
                event = json.loads(raw[len(AUDIT_PREFIX):].decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                event = None
        if not isinstance(event, dict):
            self._unreadable(raw, None)
            return
        self._audit_unreadable = None
        name = event.get("acs_audit_event")
        session_id = _text(event.get("session_id")) or ""
        when = _text(event.get("timestamp")) or receipt_time()
        if name == EPOCH_BUMPED:
            self._epoch_at = _moment(when) or datetime.datetime.now(datetime.timezone.utc)
        elif name == REPLAY_MISS:
            cause = _text(event.get("cause"))
            self._add(Row(0, 0, when, session_id, "model call", note=REPLAY_MISS_NOTE,
                          reason_codes=[cause] if cause else [], source="audit"))
        elif name == "ask_pending":
            approver = _text(event.get("approver"))
            self._add(Row(0, 0, when, session_id, name, tool=_text(event.get("tool")), decision="ask",
                          note=f"held for {approver}" if approver else "held for the approver", source="audit",
                          request_id=_text(event.get("request_id"))))
        elif name == "ask_resolved":
            cause = _text(event.get("cause"))
            outcome = _text(event.get("outcome")) or ""
            self._add(Row(0, 0, when, session_id, name, tool=_text(event.get("tool")),
                          decision=_text(event.get("decision")), note=f"ask {outcome}".strip(),
                          reason_codes=[cause] if cause else [], source="audit",
                          request_id=_text(event.get("ask_request_id"))))
        elif name in STEP_EVENTS:
            request_id = _text(event.get("request_id"))
            if request_id is None:
                return
            session = self._sessions.get(session_id)
            row = session.by_request.get(request_id) if session is not None else None
            if row is not None:
                self._join(row, event)
                return
            # A request_id is unique within its session only, so the wait is keyed by both (M8).
            self._waiting[(session_id, request_id)] = event
            while len(self._waiting) > MAX_WAITING_AUDIT:
                self._waiting.popitem(last=False)

    def _join(self, row: Row, event: Mapping[str, Any]) -> None:
        """Record what the gateway says it did. The signed decision stays as it is (I3)."""
        applied = _text(event.get("decision"))
        said = _text(event.get("guardian_decision"))
        cause = _text(event.get("cause"))
        signed = row.decision
        row.applied = applied
        if event.get("acs_audit_event") == "shadow_decision":
            row.mode, note = "shadow", "shadow: the gateway forwarded the call"
        else:
            row.mode, note = "enforce", None
            if applied is not None and applied != signed:
                note = f"gateway applied {applied}" + (f" ({cause})" if cause else "")
        row.conflict = False
        if said is not None and signed is not None and said != signed:
            row.conflict = True
            note = f"conflict: the audit line says the Guardian said {said}, the signed answer says {signed}"
        elif row.mode == "enforce" and applied == "allow" and signed not in (None, "allow"):
            # The gateway's unsigned word is that it allowed a call the signed answer did not allow.
            row.conflict = True
            note = f"conflict: the gateway applied allow, the signed answer says {signed}"
        row.gateway_note = note
        self._touch(row)

    # The module 7 result files

    def _read_results(self) -> None:
        for name, key, record in self._beats.result_files(self.verify_dir):
            known = self._results.get(name)
            if known is not None and known[0] == key:
                continue
            fresh = self._beats.result_row(record, key[0])
            if known is None or known[1].id not in self._rows:
                self._results[name] = (key, self._add(fresh))
                continue
            row = known[1]
            for field in ("t", "decision", "algorithm", "note", "kind"):
                setattr(row, field, getattr(fresh, field))
            self._results[name] = (key, row)
            self._touch(row)
