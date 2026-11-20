"""The one reader every module check reads the lab's evidence through (issue #589, LAB-16, BUILD_PLAN A.11).

Version 1.1.0. Owner: Rock Lambros. Standard library only, so it loads in the lab container and in the cli tests.

A check sees five sources and nothing else: the run records the scenario driver writes under state/runs/, the
gateway's audit log, its model input log, its per-session transcripts, and the FinBot evidence the driver copied into
each run record. acs-verify, run as a subprocess, judges a transcript's signatures.

Each run record names byte offsets into the audit log and the model input log, so a check reads only its own run's
lines. A window wider than MAX_READ_BYTES is refused rather than cut short, because a check that saw half a run could
pass a run it should fail. A last line with no newline is a write still in progress and is skipped.

The fingerprint acs-verify pins comes from .env alone, never from state/ and never from the process environment.
The gateway mounts state/ with write access, so in module 7 a forger holding the gateway's files could otherwise
choose the key the verifier trusts (LAB-16 review focus 2). Lab conventions: the key document format acs-lab-keys/1
(issue #460) and ML-DSA-65 response signing (issue #316).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RUN_FORMAT = "acs-lab-run/1"
MAX_READ_BYTES = 8 * 1024 * 1024
AUDIT_PREFIX = "ACS_AUDIT "
FINGERPRINT_KEY = "LAB_GUARDIAN_FINGERPRINT"
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
# acs-verify on one session is well under a second. The bound only stops a hung run from hanging a check.
VERIFY_TIMEOUT_S = 120
VERIFY_OUTCOMES = ("verified", "broken", "not_yet", "error")
TRANSCRIPTS = "transcripts"
# The gateway's transcripts, and the copies lab forge writes in module 7. A copy is judged by the same rules.
TRANSCRIPT_DIRECTORIES = (TRANSCRIPTS, "forged")

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class EvidenceError(Exception):
    """Evidence that can't be read as the run describes it. lab check prints it as one line and exits 2."""


@dataclass(frozen=True)
class Run:
    """One state/runs/<run_id>.json, the plan's acs-lab-run/1 record, with its windows checked."""

    run_id: str
    scenario: str
    mode: str
    signing: str
    upstream: str
    flags: dict[str, Any]
    policy_sha256: str
    started: str
    ended: str
    result: str
    audit: tuple[int, int]
    model_inputs: tuple[int, int]
    sessions: tuple[str, ...]
    epoch: tuple[Any, ...]
    finbot: dict[str, Any]
    record: dict[str, Any]


@dataclass(frozen=True)
class VerifyResult:
    """acs-verify's verdict on one transcript.

    outcome is verified (exit 0), broken (exit 1, the transcript fails verification), not_yet (no pin in .env or no
    transcript, so acs-verify never ran), or error (exit 2 or output that isn't its JSON report).
    """

    outcome: str
    detail: str
    report: dict[str, Any] | None = None
    argv: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.outcome == "verified"


def _window(value: Any) -> tuple[int, int] | None:
    # bool is an int to Python, and a record saying [true, 3] wasn't written by the driver.
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value)
            and value[0] <= value[1]):
        return value[0], value[1]
    return None


def _run_from(record: Any, stem: str) -> Run | None:
    """The record as a Run, or None when it isn't one the driver wrote for this file name."""
    if not isinstance(record, dict) or record.get("format") != RUN_FORMAT or record.get("run_id") != stem:
        return None
    audit, model_inputs = _window(record.get("audit")), _window(record.get("model_inputs"))
    sessions = record.get("sessions")
    text = ("scenario", "mode", "started")
    if (audit is None or model_inputs is None or not isinstance(sessions, list)
            or not all(isinstance(s, str) for s in sessions)
            or not all(isinstance(record.get(k), str) for k in text)):
        return None
    epoch = record.get("epoch")
    finbot = record.get("finbot")
    flags = record.get("flags")
    return Run(run_id=stem, scenario=record["scenario"], mode=record["mode"],
               signing=str(record.get("signing", "")), upstream=str(record.get("upstream", "")),
               flags=flags if isinstance(flags, dict) else {}, policy_sha256=str(record.get("policy_sha256", "")),
               started=record["started"], ended=str(record.get("ended", "")), result=str(record.get("result", "")),
               audit=audit, model_inputs=model_inputs, sessions=tuple(sessions),
               epoch=tuple(epoch) if isinstance(epoch, list) else (),
               finbot=finbot if isinstance(finbot, dict) else {}, record=record)


def _whole_lines(data: bytes) -> list[str]:
    """Complete lines only. Bytes after the last newline belong to a write still in progress."""
    end = data.rfind(b"\n")
    if end < 0:
        return []
    return data[:end].decode("utf-8", errors="replace").split("\n")


def _json_lines(lines: list[str]) -> list[Any]:
    out = []
    for line in lines:
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            # One unreadable line, such as a write cut by a crash, doesn't hide the lines after it.
            continue
    return out


def policy_sha256(policy_dir: Path) -> str:
    """sha256 over the live policy: every top-level .rego file and data.json, sorted by name.

    Each file contributes its name, a NUL, its length in decimal, a NUL, then its bytes, so moving bytes from one file
    to the next changes the hash. Starters, solutions and tests aren't live and stay out. The driver records this in
    each run record and a check compares it with the pack in place now.
    """
    digest = hashlib.sha256()
    files = sorted([*policy_dir.glob("*.rego"), policy_dir / "data.json"], key=lambda p: p.name)
    for path in files:
        if not path.is_file():
            continue
        data = path.read_bytes()
        digest.update(f"{path.name}\0{len(data)}\0".encode())
        digest.update(data)
    return digest.hexdigest()


class Evidence:
    """The lab's evidence under one bundle directory (/lab in the container)."""

    def __init__(self, root: Path | str | None = None, *, runner: Runner | None = None,
                 python: str = sys.executable, max_read: int = MAX_READ_BYTES) -> None:
        self.root = Path(root if root is not None else os.environ.get("LAB_BUNDLE") or Path(__file__).parents[2])
        self.state = self.root / "state"
        self._runner = runner or subprocess.run
        self._python = python
        self._max_read = max_read

    # run records ------------------------------------------------------------------------------------------------

    def runs(self, scenario: str | None = None, mode: str | None = None) -> list[Run]:
        """Every run record the driver wrote, newest first, filtered by scenario and mode. Unreadable records and
        records whose run_id doesn't match the file name are left out."""
        directory = self.state / "runs"
        if not directory.is_dir():
            return []
        found = []
        for path in directory.glob("*.json"):
            # The driver writes plain files. A link points at something it never wrote.
            if path.is_symlink():
                continue
            try:
                record = json.loads(self.read_bounded(path))
            except (OSError, ValueError, EvidenceError):
                continue
            run = _run_from(record, path.stem)
            if run and (scenario is None or run.scenario == scenario) and (mode is None or run.mode == mode):
                found.append(run)
        return sorted(found, key=lambda r: (r.started, r.run_id), reverse=True)

    # logs -------------------------------------------------------------------------------------------------------

    def audit(self, run: Run) -> list[dict[str, Any]]:
        """The ACS_AUDIT lines inside the run's audit window, parsed. Other lines in the log are skipped."""
        lines = self._window_lines(self.state / "audit.log", run.audit, "audit")
        payloads = _json_lines([line[len(AUDIT_PREFIX):] for line in lines if line.startswith(AUDIT_PREFIX)])
        return [p for p in payloads if isinstance(p, dict)]

    def model_inputs(self, run: Run) -> list[dict[str, Any]]:
        """The request bodies the gateway forwarded to the model inside the run's window. A body that wasn't JSON
        was logged as a string and comes back as {"raw": text}."""
        lines = self._window_lines(self.state / "model-inputs.jsonl", run.model_inputs, "model input")
        return [b if isinstance(b, dict) else {"raw": b} for b in _json_lines(lines)]

    def transcript(self, session_id: str) -> list[dict[str, Any]]:
        """Every line of state/transcripts/<session_id>.jsonl, or [] when the session wrote none."""
        path = self.transcript_path(session_id)
        if not path.is_file():
            return []
        return [line for line in _json_lines(_whole_lines(self.read_bounded(path))) if isinstance(line, dict)]

    # acs-verify -------------------------------------------------------------------------------------------------

    def fingerprint(self) -> str | None:
        """LAB_GUARDIAN_FINGERPRINT from .env, the value lab init printed, or None when it's missing or malformed."""
        try:
            data = self.read_bounded(self.root / ".env")
        except (OSError, EvidenceError):
            return None
        value = None
        for line in data.decode("utf-8", errors="replace").splitlines():
            key, sep, rest = line.partition("=")
            if sep and key.strip() == FINGERPRINT_KEY:
                value = rest.strip()
        return value if value and FINGERPRINT.fullmatch(value) else None

    def verify(self, session_id: str, *, keys_only: bool = False, hmac: bool = False,
               directory: str = TRANSCRIPTS) -> VerifyResult:
        """acs-verify --json on one session's transcript.

        Under ML-DSA-65 it always passes --keys and --expect-fingerprint with the pin from .env, and refuses to run
        without one (ledger ruling 2026-11-17, LAB-11). hmac=True checks under the shared HMAC secret instead, which
        anyone holding that secret can satisfy (specification section 8.6). directory names the copy under state/ to
        judge, as transcript_path takes it. The module 7 kit passes forged for its forged copies.
        """
        transcript = self.transcript_path(session_id, directory)
        if not transcript.is_file():
            return VerifyResult("not_yet", f"session {session_id} has no transcript yet. Run the scenario first")
        argv = [self._python, "-m", "acs.testing.verify", "--json", str(transcript)]
        if hmac:
            argv += ["--hmac-secret", str(self.state / "secrets" / "hmac.key")]
        else:
            fingerprint = self.fingerprint()
            if fingerprint is None:
                return VerifyResult("not_yet", f"{FINGERPRINT_KEY} isn't in .env. Run ./lab.sh init, which writes "
                                    "the fingerprint it prints there")
            argv += ["--keys", str(self.state / "keys" / "guardian-keys.json"), "--expect-fingerprint", fingerprint]
        if keys_only:
            argv.append("--keys-only")
        try:
            completed = self._runner(argv, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_S, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            return VerifyResult("error", f"acs-verify couldn't run: {e}", argv=tuple(argv))
        try:
            report = json.loads(completed.stdout)
        except (TypeError, ValueError):
            report = None
        if not isinstance(report, dict) or completed.returncode not in (0, 1):
            detail = report.get("error") if isinstance(report, dict) else (completed.stderr or completed.stdout)
            return VerifyResult("error", f"acs-verify exited {completed.returncode}: {str(detail).strip()[:500]}",
                                report if isinstance(report, dict) else None, tuple(argv))
        if completed.returncode == 0:
            return VerifyResult("verified", "acs-verify passed", report, tuple(argv))
        failure = report.get("failure") or {}
        return VerifyResult("broken", f"acs-verify failed at line {failure.get('line')} ({failure.get('code')}): "
                            f"{failure.get('reason')}", report, tuple(argv))

    def policy_sha256(self) -> str:
        return policy_sha256(self.root / "policy")

    # reading ----------------------------------------------------------------------------------------------------

    def transcript_path(self, session_id: str, directory: str = TRANSCRIPTS) -> Path:
        """state/<directory>/<session_id>.jsonl, refused unless session_id is a canonical UUID and the file is no link.

        directory is transcripts, the gateway's own record, or forged, the module 7 kit's copies, and nothing else.
        """
        if directory not in TRANSCRIPT_DIRECTORIES:
            raise EvidenceError(f"{directory!r} is not a transcript directory")
        # The gateway names each file with str(uuid.UUID(session_id)), so only that spelling names a file, and no
        # argument can walk out of the directory.
        try:
            canonical = str(uuid.UUID(session_id))
        except (ValueError, TypeError, AttributeError):
            canonical = None
        if canonical != session_id:
            raise EvidenceError(f"{session_id!r} is not a gateway session id")
        path = self.state / directory / f"{canonical}.jsonl"
        # The gateway writes plain files. A link would make another file read as this session's record.
        if path.is_symlink():
            raise EvidenceError(f"the {directory} file for {session_id} is a link, not a plain file")
        return path

    def read_bounded(self, path: Path) -> bytes:
        """The whole file, refused when it is larger than the reader's bound rather than cut short."""
        with path.open("rb") as f:
            data = f.read(self._max_read + 1)
        if len(data) > self._max_read:
            raise EvidenceError(f"{path.name} is larger than {self._max_read} bytes")
        return data

    def _window_lines(self, path: Path, window: tuple[int, int], label: str) -> list[str]:
        start, end = window
        if end - start > self._max_read:
            raise EvidenceError(f"the run's {label} window is larger than {self._max_read} bytes")
        try:
            with path.open("rb") as f:
                size = os.fstat(f.fileno()).st_size
                # A log shorter than the window's start was reset since the run, so none of its lines are this run's.
                if start >= size:
                    return []
                f.seek(start)
                data = f.read(min(end, size) - start)
        except FileNotFoundError:
            return []
        return _whole_lines(data)
