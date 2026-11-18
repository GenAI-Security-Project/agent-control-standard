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
import hashlib
import json
import os
import re
import stat
import sys
import time
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HANDSHAKE_METHOD = "handshake/hello"
PING_METHOD = "system/ping"
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
# read not checked and say to run lab verify. 2000 lines is about 1000 steps, far past a lab scenario, and 2000 lines
# of typical gateway lines come to 5 MiB. Measured in round 3, one judge at the cap, which reads the file from disk,
# hashes it and runs acs-verify, took 0.19 seconds on typical lines and 0.24 seconds on lines filling 7.8 MiB.
MAX_SESSION_LINES = 2000
MAX_SESSION_BYTES = 8 * 1024 * 1024
# The longest text a row carries for an unreadable line or a note.
MAX_TEXT_CHARS = 400
# Audit lines for a step whose transcript line hasn't been read yet wait here.
MAX_WAITING_AUDIT = 10_000

# One poll spends at most this long judging sessions, and leaves the rest for the next poll (round 2, M4). A poll
# always judges at least one session, so every session is judged in the end. The worst poll judges for the budget plus
# one session at the cap, about 0.5 seconds measured. The disk read and hash count inside the budget.
JUDGE_BUDGET_S = 0.25

TOO_LONG_NOTE = "this session is too long for the viewer to judge. Run lab verify on it"
CHANGING_NOTE = "the file changed while it was read. Judging it again"
# Why a session's rows were dropped, as the page says it (round 4).
DROP_LEFT = "the file left the transcript directory"
DROP_UNLISTED = "the file is no longer among the newest followed"
DROP_REPLACED = "the file was replaced or cut shorter, so it is read again"
DROP_EDITED = "the file no longer holds the bytes read before, so it is read again"
DROP_AUDIT = "the audit log was replaced or cut shorter, so it is read again"
# Drops the page can name. The newest win.
MAX_DROPS = 20
# The gateway names each transcript str(uuid.UUID(session_id)), so a drop names a file only when its stem has that
# shape. Any other name could carry text that reads as another session or reason on the page (round 5, M-B).
_SESSION_FILE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
REJUDGE_NOTE = "judging again under the changed key document"
WITHHELD_NOTE = "the gateway withheld this answer and denied the step (decision_timeout)"
CLAIM_NOTE = "the gateway says it withheld the answer above and denied the step (decision_timeout)"
STRAY_DISCARDS_NOTE = "a discards line that does not follow the answer it names"

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
        # A hash of every byte read so far, so the bytes on disk can be checked against what was read (round 3, F1).
        self._hash = hashlib.sha256()

    def restart(self) -> None:
        """Read the file again from its start, as for a replaced file. The next read takes the file's identity
        afresh, so it doesn't count the same restart twice."""
        self.restarts += 1
        self._offset, self._partial, self._dropping, self._hash = 0, b"", False, hashlib.sha256()
        self._identity = None

    def outgrown(self, inode: int, size: int) -> bool:
        """Whether a stat shows a replaced file or one cut shorter, the check _read makes, without reading."""
        return self._identity is not None and (inode != self._identity[1] or size < self._offset)

    def disk_lines(self) -> list[bytes] | None:
        """The complete lines read so far, as the file holds them now, or None when the file no longer holds the
        bytes read so far: replaced, cut shorter, edited in place, or gone. Read from disk on every call, so a judge
        sees only bytes that are on disk when it runs, whatever the file's inode, size or times say."""
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self._identity:
                return None
            data = os.pread(fd, self._offset, 0) if self._offset else b""
        except OSError:
            return None
        finally:
            os.close(fd)
        if len(data) != self._offset or hashlib.sha256(data).digest() != self._hash.digest():
            return None
        complete = data[:self._offset - len(self._partial)]
        # The same split read_new makes, so line numbers match the rows'. A line read_new cut short is whole here, so
        # acs-verify, which has no line limit, may pass it while the viewer's row for it reads unreadable and not
        # checked. That row never reads verified, so no mark overclaims.
        return [line for line in complete.split(b"\n") if line]

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
                self._hash = hashlib.sha256()
            if info.st_size == self._offset:
                return b""
            os.lseek(fd, self._offset, os.SEEK_SET)
            data = os.read(fd, MAX_READ_BYTES)
        except OSError:
            return b""
        finally:
            os.close(fd)
        self._offset += len(data)
        self._hash.update(data)
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
    # A row the file no longer holds. It goes to the page once more, as gone, and the page drops it.
    gone: bool = False
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
        if self.gone:
            return {"id": self.id, "seq": self.seq, "gone": True}
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
    # The file's (inode, size, mtime, ctime) at the last poll. Any change queues the session for judging, and the
    # judge reads the file from disk. An ordinary write moves ctime, and no caller can set ctime back. A write through a
    # memory map held open moves neither mtime nor ctime on macOS until the map closes (round 4 review, probe p9), so
    # such an edit is caught only when the file next grows or is judged for another reason.
    stamp: tuple[int, ...] | None = None
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
    # The row whose answer is on the line just read, the only answer a discards line may mark.
    just_answered: Row | None = None
    # The line and session_id of the first request naming a session, checked against the file's name (M2).
    named: tuple[int, str] | None = None
    dirty: bool = False
    # Set when this poll's read of the session failed, so it isn't judged until a read succeeds.
    failed: bool = False
    judged_with: int = -1
    judged_at: float = 0.0

    def reset(self) -> None:
        """The file was replaced or cut shorter, so the new content starts over. The caller retires the old rows."""
        self.line_count, self.size, self.too_long = 0, 0, False
        self.open_request, self.by_request, self.by_line, self.rows = None, {}, {}, []
        self.first_algorithm, self.last_unreadable, self.just_answered, self.named = None, None, None, None
        self.dirty = True


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
        self._generation_seen: int | None = None
        self._drops: collections.deque[dict[str, str]] = collections.deque(maxlen=MAX_DROPS)
        # Every drop since the viewer started, so the page can count those since it loaded (round 5, M-C).
        self.drop_count = 0
        # Why the last poll failed as a whole, escaped, or None while polls succeed (final review R1).
        self.paused: str | None = None
        self._audit_restarts = 0

    # Reading

    def refresh(self) -> None:
        """Read what the logs gained and judge what changed, failing closed (final review R1).

        Each session, the audit log and each result file is read in a step of its own, so one that fails affects
        only itself and every other session is still judged that poll. If the poll fails as a whole, every mark drops
        to not checked and paused says why, until a poll succeeds.
        """
        try:
            listing_error = self._refresh()
        except Exception as e:  # noqa: BLE001
            self.fail_closed(e)
            return
        if listing_error is not None:
            self.fail_closed(listing_error)
        else:
            self.paused = None

    def fail_closed(self, error: BaseException) -> None:
        """Drop every mark to not checked and say why, so no mark stands that this poll couldn't check."""
        reason = f"checks paused: {type(error).__name__}: {error}"
        # paused goes to the page as it is, so it is escaped here. The row note is escaped on its way out.
        self.paused = _clip(escape_text(reason))
        for row in list(self._rows.values()):
            if not row.gone and row.verify in ("verified", "warning", "failed"):
                row.verify, row.check_note = "not_checked", _clip(reason)
                self._touch(row)
        for session in self._sessions.values():
            # Judged again in full at the next poll that succeeds.
            session.dirty, session.judged_with = True, -1

    def _refresh(self) -> OSError | None:
        """One poll. Returns the listing error when the transcript directory can't be listed or is gone. Then no
        session is read or judged, since nothing can say what the files hold, and the caller pauses every mark (fix
        round 2, R4). The audit log and the result files carry no mark, so they are still read."""
        try:
            listed = self._transcript_files()
        except OSError as e:
            self._read_audit_safely()
            self._read_results()
            return e
        names = {path.stem for path in listed}
        for session in [s for s in self._sessions.values() if s.session_id not in names]:
            # A file no longer listed, deleted or past the newest MAX_SESSIONS, is no longer stat'ed or judged, so
            # its rows go from the table and the beat history rather than keep marks nothing checks (round 4, I-2a).
            gone = not os.path.lexists(session.tail.path)
            self._forget(session, DROP_LEFT if gone else DROP_UNLISTED)
        for path in listed:
            session = self._sessions.get(path.stem)
            if session is None:
                session = self._sessions[path.stem] = _Session(path.stem, LogTail(path))
            try:
                self._poll_session(session, path)
            except Exception as e:  # noqa: BLE001
                self._session_failed(session, e)
        self._read_audit_safely()
        self._read_results()
        self._judge()
        return None

    def _read_audit_safely(self) -> None:
        if self.audit_tail is None:
            return
        try:
            self._read_audit()
        except Exception as e:  # noqa: BLE001
            # The audit log fills the applied column and its own rows, never a verify mark, so a failure here stops
            # only that.
            sys.stderr.write(f"acs-viewer: reading the audit log failed: {escape_text(type(e).__name__)}\n")

    def _poll_session(self, session: _Session, path: Path) -> None:
        session.failed = False
        try:
            info = os.stat(path, follow_symlinks=False)
            stamp = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except OSError:
            stamp = None
        if stamp != session.stamp:
            session.stamp, session.dirty = stamp, True
        if session.too_long:
            # Past the cap the tail stops and nothing is read or hashed again, so the session costs one stat a
            # poll however large the file grows (round 4, I-1). A replaced or shortened file starts over.
            if stamp is None or not session.tail.outgrown(stamp[0], stamp[1]):
                return
            self._start_over(session, DROP_REPLACED)
        self._read_session(session)

    def _session_failed(self, session: _Session, error: BaseException) -> None:
        """One session failed to read or judge. Its marks drop to not checked, and it is judged again next poll."""
        note = _clip(f"checks paused for this file: {type(error).__name__}: {error}")
        for row in session.rows:
            if row.id in self._rows and not row.gone and row.verify in ("verified", "warning", "failed"):
                row.verify, row.check_note = "not_checked", note
                self._touch(row)
        # Not judged again this poll, since what it gained is unknown. The next poll reads and judges it afresh.
        session.dirty, session.failed = True, True

    def _read_audit(self) -> None:
        assert self.audit_tail is not None
        raws = self.audit_tail.read_new()
        if self.audit_tail.restarts != self._audit_restarts:
            # Replaced or cut shorter: drop the rows the old log made and read it again once (final review M-3).
            self._audit_restarts = self.audit_tail.restarts
            self._drop_audit_rows()
        for raw in raws:
            self._audit_line(raw)

    def _drop_audit_rows(self) -> None:
        dropped = False
        for row in list(self._rows.values()):
            if row.source == "audit" and not row.gone:
                self._gone(row)
                dropped = True
            elif not row.gone and (row.applied or row.mode or row.conflict or row.gateway_note):
                # What the old log joined onto a transcript row goes with it. The new log joins again if it says the
                # same (fix round 2, R7).
                row.applied, row.mode, row.conflict, row.gateway_note = None, None, False, None
                self._touch(row)
        self._epoch_at, self._audit_unreadable = None, None
        self._waiting.clear()
        if dropped:
            self._drops.append({"t": receipt_time(), "session_id": "", "why": DROP_AUDIT, "source": "audit"})
            self.drop_count += 1

    def rows_after(self, seq: int) -> list[Row]:
        """Every row still held that is new or changed after seq, oldest change first, escaped once."""
        return [row.escaped() for row in self._changed_after(seq) if not row.gone]

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
        return not any(self._is_record(row) for row in self._rows.values() if not row.gone)

    def _is_record(self, row: Row) -> bool:
        governed = (row.source == "transcript" and row.method != "unreadable") or row.method in ASK_EVENTS
        if not governed:
            return False
        if self._epoch_at is None:
            return True
        moment = _moment(row.t)
        # A time that can't be read counts as current, so a row is never hidden for its timestamp.
        return moment is None or moment > self._epoch_at

    def _read_session(self, session: _Session) -> None:
        raws = session.tail.read_new()
        if session.tail.restarts != session.restarts:
            # Replaced or cut shorter, the fast path. A same-size edit is caught when the session is judged.
            session.restarts = session.tail.restarts
            self._drop_session_rows(session, DROP_REPLACED)
            session.reset()
        for raw in raws:
            self._transcript_line(session, raw)

    def _start_over(self, session: _Session, why: str) -> None:
        """Drop the session's rows and read its file again from the start."""
        self._drop_session_rows(session, why)
        session.reset()
        session.tail.restart()
        session.restarts = session.tail.restarts

    def _drop_session_rows(self, session: _Session, why: str) -> None:
        """Drop every row the session holds, from the table and the beat history, and say so on the page. A file
        read again from the start brings back each row it still holds, judged from the bytes on disk."""
        dropped = False
        for row in session.rows:
            if row.id in self._rows and not row.gone:
                self._gone(row)
                dropped = True
        self._history.forget(session.session_id)
        if dropped:
            self._drops.append({"t": receipt_time(), "session_id": session.session_id, "why": why,
                                "source": "transcript"})
            self.drop_count += 1

    def drops(self) -> list[dict[str, str | None]]:
        """The latest drops, oldest first, each with why its rows went. session_id is the file's session when the
        name has the gateway's shape, else None, which the page reads as a transcript file. Escaped once."""
        out: list[dict[str, str | None]] = []
        for drop in self._drops:
            named = drop["session_id"] if _SESSION_FILE.fullmatch(drop["session_id"]) else None
            out.append({"t": drop["t"], "session_id": named, "why": escape_text(drop["why"]), "source": drop["source"]})
        return out

    def _forget(self, session: _Session, why: str) -> None:
        self._drop_session_rows(session, why)
        del self._sessions[session.session_id]

    def _gone(self, row: Row) -> None:
        row.gone = True
        self._touch(row)

    def _transcript_files(self) -> list[Path]:
        """The newest MAX_SESSIONS transcript files. A file that goes between the listing and its stat is skipped
        alone, so it never empties the listing (final review M-1). A directory that can't be listed, or is gone,
        raises, and the poll fails closed: the rows stay, since the failure says nothing about them, and every mark
        drops to not checked with the cause on the page until a listing succeeds (fix round 2, R4)."""
        entries = list(os.scandir(self.transcript_dir))
        found = []
        for entry in entries:
            try:
                if entry.name.endswith(".jsonl") and entry.is_file(follow_symlinks=False):
                    found.append((entry.stat(follow_symlinks=False).st_mtime_ns, entry.name))
            except OSError:
                continue
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
        if not row.gone:
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
        if session.line_count > MAX_SESSION_LINES or session.size > MAX_SESSION_BYTES:
            # Past the cap the session is no longer judged. Its rows read not checked from here on.
            session.too_long = True
        return session.line_count

    def _transcript_line(self, session: _Session, raw: bytes) -> None:
        number = self._record_line(session, raw)
        just_answered, session.just_answered = session.just_answered, None
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
            self._discard(session, record.get("discards"), number, just_answered)
            return
        if session.open_request is None:
            self._unreadable(raw, session, "a response line with no request before it", number)
            return
        request, session.open_request = session.open_request, None
        cause = _text(record.get("cause"))
        response = envelope if isinstance(envelope, dict) and ("result" in envelope or "error" in envelope) else None
        row = self._step_row(session, request, (number, response), cause, record)
        # Only a signed answer to a step, with no cause, can be withheld, acs-verify's rule (round 3, N2).
        if response is not None and row.signed and cause is None and row.method not in (HANDSHAKE_METHOD, PING_METHOD):
            session.just_answered = row

    def _step_row(self, session: _Session, request: tuple[int, dict[str, Any]],
                  response: tuple[int, dict[str, Any] | None] | None, cause: str | None,
                  record: dict[str, Any] | None) -> Row:
        req_line, envelope = request
        params = _mapping(envelope.get("params"))
        named = _text(_mapping(params.get("metadata")).get("session_id"))
        if session.named is None and named:
            session.named = (req_line, named)
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
        return row

    def _discard(self, session: _Session, request_id: Any, number: int, just_answered: Row | None) -> None:
        """A discards line is the gateway's unsigned claim, a row of its own, so acs-verify failing it fails that row
        and never the answer it names (round 2, M3). Only the answer on the line just before may be marked withheld,
        acs-verify's adjacency rule."""
        adjacent = just_answered is not None and isinstance(request_id, str) and just_answered.request_id == request_id
        claim = Row(0, 0, just_answered.t if adjacent else receipt_time(), session.session_id, "withheld",
                    note=CLAIM_NOTE if adjacent else STRAY_DISCARDS_NOTE, answered=True, lines=(number,))
        self._add(claim)
        session.rows.append(claim)
        session.by_line[number] = claim
        if adjacent:
            just_answered.note = WITHHELD_NOTE
            self._touch(just_answered)

    # acs-verify

    def _judge(self) -> None:
        """Run acs-verify over sessions that changed, or over every session when the key document changed, within the
        poll's budget. The longest-waiting session goes first, and the rest wait for the next poll (round 2, M4)."""
        keys = self.keys.current() if self.keys is not None else None
        generation = self.keys.generation if self.keys is not None else 0
        if self._generation_seen is not None and generation != self._generation_seen:
            # A mark judged under the old document says nothing under the new one, so it goes until judged again.
            for session in self._sessions.values():
                for row in session.rows:
                    if row.id in self._rows and row.verify in ("verified", "warning", "failed"):
                        row.verify, row.check_note = "not_checked", REJUDGE_NOTE
                        self._touch(row)
        self._generation_seen = generation
        waiting = sorted((s for s in self._sessions.values()
                          if (s.dirty or s.judged_with != generation) and not s.failed),
                         key=lambda s: s.judged_at)
        started = time.monotonic()
        for number, session in enumerate(waiting):
            if number and time.monotonic() - started >= JUDGE_BUDGET_S:
                break
            session.dirty, session.judged_with, session.judged_at = False, generation, time.monotonic()
            try:
                self._judge_session(session, keys)
            except Exception as e:  # noqa: BLE001
                self._session_failed(session, e)

    def _judge_session(self, session: _Session, keys: Any | None) -> None:
        from verify import verify_session

        session.rows = [row for row in session.rows if row.id in self._rows and not row.gone]
        if session.too_long:
            # Checked before any disk read, so a session past the cap costs nothing more to judge (round 4, I-1). The
            # file name check needs no disk read, so it still fails a copied file.
            name = self._name_problem(session)
            marks = ({row.id: self._mark(row, session, name) for row in session.rows} if name is not None else
                     {row.id: ("not_checked" if row.answered else "no_answer", TOO_LONG_NOTE) for row in session.rows})
            self._apply_marks(session, marks)
            return
        lines = session.tail.disk_lines()
        if lines is None:
            # The file no longer holds the bytes its rows came from. Drop them and read it again from the start, so
            # every mark below comes from bytes on disk now (round 3, F1).
            self._start_over(session, DROP_EDITED)
            self._read_session(session)
            lines = None if session.too_long else session.tail.disk_lines()
        session.rows = [row for row in session.rows if row.id in self._rows and not row.gone]
        name = self._name_problem(session)
        if lines is None and session.too_long:
            marks = {row.id: ("not_checked" if row.answered else "no_answer", TOO_LONG_NOTE) for row in session.rows}
        elif lines is None:
            # Still changing under the reader. Nothing is judged, and the next poll tries again.
            session.dirty = True
            marks = {row.id: (self._unchecked(row), CHANGING_NOTE) for row in session.rows}
        elif name is not None:
            # A file holding another session's requests fails whatever the session's mode (round 3, N1).
            marks = {row.id: self._mark(row, session, name) for row in session.rows}
        elif keys is None or (session.first_algorithm not in (None, ML_DSA_65)):
            # No key document, or an HMAC session: nothing here can check it, so no row reads verified (I2).
            marks = {row.id: (self._unchecked(row), None) for row in session.rows}
        else:
            verdict = verify_session(lines, keys)
            marks = {row.id: self._mark(row, session, verdict) for row in session.rows}
        self._apply_marks(session, marks)

    def _apply_marks(self, session: _Session, marks: dict[int, tuple[str, str | None]]) -> None:
        for row in session.rows:
            mark, note = marks[row.id]
            if (row.verify, row.check_note) != (mark, note):
                row.verify, row.check_note = mark, note
                self._touch(row)

    @staticmethod
    def _name_problem(session: _Session) -> Any | None:
        """The gateway names each file for its session, so a file whose requests name another session holds lines
        copied from elsewhere, each of which may verify on its own (round 2, M2)."""
        from verify import SessionVerdict

        if session.named is None or session.named[1] == session.session_id:
            return None
        return SessionVerdict(ok=False, failure_line=session.named[0], failure_code="session_file_mismatch",
                              failure_reason=f"the file is named for session {session.session_id}, and its requests "
                                             f"name session {session.named[1]}")

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
                # The file name check is the viewer's own. Every other code is acs-verify's.
                source = "viewer" if verdict.failure_code == "session_file_mismatch" else "acs-verify"
                return "failed", _clip(f"{source}: {verdict.failure_code}: {verdict.failure_reason}")
            stopped = f"the session failed at line {verdict.failure_line} ({verdict.failure_code})"
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
        try:
            results = self._beats.result_files(self.verify_dir)
        except Exception:  # noqa: BLE001
            # The result files make module 7 rows only, never a verify mark, so a failed listing skips them alone.
            return
        for name, key, record in results:
            try:
                self._read_result(name, key, record)
            except (ValueError, OverflowError, OSError):
                # One result file the viewer can't use, such as an mtime past year 9999, skips that file alone.
                continue

    def _read_result(self, name: str, key: tuple[int, int], record: dict[str, Any]) -> None:
        known = self._results.get(name)
        if known is not None and known[0] == key:
            return
        fresh = self._beats.result_row(record, key[0])
        if known is None or known[1].id not in self._rows:
            self._results[name] = (key, self._add(fresh))
            return
        row = known[1]
        for field in ("t", "decision", "algorithm", "note", "kind"):
            setattr(row, field, getattr(fresh, field))
        self._results[name] = (key, row)
        self._touch(row)
