"""Module 7's check, Forge a decision (issue #589, LAB-16 Task 13). lab check 7 runs it.

Version 1.2.0. Owner: Rock Lambros. Standard library only. Reads every file through evidence.py, opens no socket,
and writes nothing.

Module 7 passes when four things hold. The three forgery halves are recomputed here with acs-verify, and the kit's
forge and keys_only result files are never read, since a file saying a forgery failed is not a forgery that failed.

1. HMAC. The newest s2 run under HMAC-SHA256 completed, and one of its sessions holds a signed deny on a tool call
   whose forged copy in state/forged/ is lab forge's copy: every line the gateway wrote, except that deny now says
   allow. acs-verify passes that copy under the shared HMAC secret, because anyone holding the secret can sign.
2. ML-DSA-65. The newest s2 run under ML-DSA-65 completed, and one of its sessions holds both of the next two.
   Its forged copy, built the same way, fails acs-verify under the pinned key at the forged line.
3. The same genuine session passes acs-verify keys only, with the key document and the fingerprint from .env.
4. The Guardian signs with ML-DSA-65 now, by ACS_RESPONSE_SIGNING in .env, the value compose passes it, and
   state/verify/ holds a downgrade result that says refused under the pin in .env right now. lab downgrade writes one
   only after it checked that the Guardian signed the refusal with that pinned key and bound it to the ClientHello,
   and it records the pin. A refusal from before a fresh lab init, or from before signing went back to HMAC, says
   nothing about the Guardian now (Task 13 review C1). A check never touches the network or changes lab state, so it
   reads that result rather than probing again (coordinator ruling, 2026-11-19). The result sits under state/,
   inside the trust boundary every check documents.

Without a pin in .env nothing can be judged under ML-DSA-65, so the check exits 2 before reading anything else.
Sessions come from the driver's run records, never from file times. Lab conventions: ML-DSA-65 response signing and
the refusal reason (issue #316), the key document and its fingerprint (issue #460).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import report
from evidence import FINGERPRINT_KEY, Evidence, EvidenceError, Run

SCENARIO = "s2"
HMAC = "HMAC-SHA256"
MLDSA = "ML-DSA-65"
TOOL_CALL = "steps/toolCallRequest"
# The file lab downgrade writes (kit/results.py): downgrade-<algorithm>-<fresh session>.json.
DOWNGRADE_GLOB = f"downgrade-{MLDSA}-*.json"
SIGNING_KEY = "ACS_RESPONSE_SIGNING"
# compose.yaml and commands.DEFAULTS both give the Guardian ML-DSA-65 when .env names no signing.
DEFAULT_SIGNING = MLDSA
SET_UP = {HMAC: "./lab.sh sign hmac, then ./lab.sh run s2", MLDSA: "./lab.sh sign mldsa, then ./lab.sh run s2"}
MAKE_DENY = "./lab.sh policy 3 solution, then ./lab.sh run s2"


class _NotYet(Exception):
    """One NOT YET line and its exit code: 1 for a step still to do, 2 for a lab that can't judge it."""

    def __init__(self, message: str, code: int = report.EXIT_NOT_YET) -> None:
        super().__init__(message)
        self.code = code


def check(ev: Evidence) -> int:
    try:
        fingerprint = ev.fingerprint()
        if fingerprint is None:
            raise _NotYet(f"{FINGERPRINT_KEY} isn't in .env, so nothing can be checked under {MLDSA}. Run "
                          "./lab.sh init, which writes the fingerprint it prints there", report.EXIT_BROKEN)
        hmac_session, hmac_line = _judge_hmac(ev)
        mldsa_session, mldsa_line = _judge_mldsa(ev)
        refusal = _judge_downgrade(ev, fingerprint)
    except _NotYet as e:
        report.not_yet(str(e))
        return e.code
    report.done(f"module 7. The forged allow at line {hmac_line} of session {hmac_session} verifies under {HMAC}, "
                f"so anyone holding the shared key could have written it. The forged allow at line {mldsa_line} of "
                f"session {mldsa_session} fails under {MLDSA}, while the session itself verifies with the key "
                f"{fingerprint}. {refusal}")
    return report.EXIT_PASS


# ---------------------------------------------------------------------------------------------------------------------
# runs and transcripts
# ---------------------------------------------------------------------------------------------------------------------

def _newest_run(ev: Evidence, signing: str) -> Run:
    runs = [r for r in ev.runs(SCENARIO) if r.signing == signing]
    if not runs:
        raise _NotYet(f"module 7 needs a run of {SCENARIO} under {signing}, and there isn't one yet. Run "
                      f"{SET_UP[signing]}")
    run = runs[0]
    if run.result != "completed":
        raise _NotYet(f"the newest {signing} run of {SCENARIO}, {run.run_id}, ended {run.result}, not completed. Run "
                      f"{SET_UP[signing]}")
    return run


def _lines(ev: Evidence, path: Path) -> list[bytes] | None:
    """The file's whole lines, byte for byte, or None when it isn't there."""
    if not path.is_file():
        return None
    data = ev.read_bounded(path)
    end = data.rfind(b"\n")
    return data[:end].split(b"\n") if end >= 0 else []


def _parse(line: bytes) -> dict[str, Any]:
    try:
        record = json.loads(line)
    except ValueError:
        return {}
    return record if isinstance(record, dict) else {}


def _envelope(line: bytes) -> dict[str, Any]:
    envelope = _parse(line).get("envelope")
    return envelope if isinstance(envelope, dict) else {}


def _decision(line: bytes) -> str | None:
    result = _envelope(line).get("result")
    return result.get("decision") if isinstance(result, dict) else None


def _denies(lines: list[bytes]) -> list[int]:
    """Line numbers, from 1, of each signed deny that answers a tool call on the line before it."""
    found = []
    for i in range(1, len(lines)):
        req, resp = _parse(lines[i - 1]), _parse(lines[i])
        result = _envelope(lines[i]).get("result")
        if (req.get("dir") == "req" and resp.get("dir") == "resp" and _envelope(lines[i - 1]).get("method") == TOOL_CALL
                and isinstance(result, dict) and result.get("decision") == "deny"
                and isinstance(result.get("signature"), dict)):
            found.append(i + 1)
    return found


def _forged_line(ev: Evidence, session_id: str) -> int:
    """The line lab forge rewrote in this session's copy, after checking the copy is lab forge's copy.

    A copy counts only when it has the gateway's lines byte for byte except one, and that one is a signed deny on a
    tool call in the transcript and an allow in the copy. A whole copy of the transcript forges nothing, yet it would
    pass under HMAC."""
    genuine = _lines(ev, ev.transcript_path(session_id))
    if not genuine or not _denies(genuine):
        raise _NotYet(f"session {session_id} holds no tool call the Guardian denied. Run {MAKE_DENY}")
    forged = _lines(ev, ev.transcript_path(session_id, "forged"))
    redo = f"Run ./lab.sh forge --session {session_id}"
    if forged is None:
        raise _NotYet(f"session {session_id} has no forged copy in state/forged/ yet. {redo}")
    changed = [i + 1 for i, (a, b) in enumerate(zip(genuine, forged)) if a != b]
    if (len(forged) != len(genuine) or len(changed) != 1 or changed[0] not in _denies(genuine)
            or _decision(forged[changed[0] - 1]) != "allow"):
        raise _NotYet(f"the copy of session {session_id} in state/forged/ isn't lab forge's copy, one deny turned "
                      f"into an allow with every other line kept. {redo}")
    return changed[0]


def _failure_line(report_: dict[str, Any] | None) -> int | None:
    line = ((report_ or {}).get("failure") or {}).get("line")
    return line if isinstance(line, int) and not isinstance(line, bool) else None


def _verdict(outcome: Any) -> None:
    # acs-verify that couldn't run, or the pin vanishing between reads, is a lab that can't give a verdict.
    if outcome.outcome not in ("verified", "broken"):
        raise _NotYet(outcome.detail, report.EXIT_BROKEN)


# ---------------------------------------------------------------------------------------------------------------------
# the four halves
# ---------------------------------------------------------------------------------------------------------------------

def _first_pass(ev: Evidence, run: Run, judge: Any) -> tuple[str, int]:
    """The first session in run that judge passes, as (session, forged line). Judged one session at a time, and the
    first session's NOT YET is the one shown when none passes."""
    if not run.sessions:
        raise _NotYet(f"run {run.run_id} opened no ACS session. Run ./lab.sh mode enforce, then ./lab.sh run s2")
    problems: list[_NotYet] = []
    for session_id in run.sessions:
        try:
            return session_id, judge(session_id)
        except _NotYet as e:
            if e.code == report.EXIT_BROKEN:
                raise
            problems.append(e)
    # run.sessions isn't empty here, so every session left a NOT YET.
    raise problems[0]


def _judge_hmac(ev: Evidence) -> tuple[str, int]:
    def judge(session_id: str) -> int:
        line = _forged_line(ev, session_id)
        outcome = ev.verify(session_id, hmac=True, directory="forged")
        _verdict(outcome)
        if outcome.outcome != "verified":
            raise _NotYet(f"the forged copy of session {session_id} doesn't verify under {HMAC}, so the session "
                          f"wasn't signed with the lab's shared key. {outcome.detail}. Run {SET_UP[HMAC]}")
        return line

    return _first_pass(ev, _newest_run(ev, HMAC), judge)


def _judge_mldsa(ev: Evidence) -> tuple[str, int]:
    def judge(session_id: str) -> int:
        line = _forged_line(ev, session_id)
        genuine = ev.verify(session_id, keys_only=True)
        _verdict(genuine)
        if genuine.outcome != "verified":
            raise _NotYet(f"session {session_id} doesn't verify keys only under the pinned key. {genuine.detail}. "
                          f"Run {SET_UP[MLDSA]}")
        forged = ev.verify(session_id, directory="forged")
        _verdict(forged)
        if forged.outcome == "verified":
            raise _NotYet(f"the forged copy of session {session_id} verifies under {MLDSA}, so whoever signed it "
                          f"holds the Guardian's key. Run ./lab.sh forge --session {session_id}")
        failed_at = _failure_line(forged.report)
        if failed_at != line:
            raise _NotYet(f"the forged copy of session {session_id} fails at line {failed_at}, not at the forged "
                          f"line {line}. {forged.detail}. Run ./lab.sh forge --session {session_id}")
        return line

    return _first_pass(ev, _newest_run(ev, MLDSA), judge)


def _signing(ev: Evidence) -> str:
    """ACS_RESPONSE_SIGNING from .env, the last line naming it, as Evidence reads the pin. Absent means the default."""
    try:
        data = ev.read_bounded(ev.root / ".env")
    except (OSError, EvidenceError):
        return DEFAULT_SIGNING
    value = None
    for line in data.decode("utf-8", errors="replace").splitlines():
        key, sep, rest = line.partition("=")
        if sep and key.strip() == SIGNING_KEY:
            value = rest.strip()
    return value or DEFAULT_SIGNING


def _refusals(ev: Evidence) -> list[tuple[str, Any]]:
    """(file name, recorded fingerprint) for each refused ML-DSA-65 downgrade result. A link or a file that isn't the
    kit's shape is skipped, as runs() skips one. The probe opens a fresh session, so no run record names it."""
    directory = ev.state / "verify"
    found = []
    for path in sorted(directory.glob(DOWNGRADE_GLOB)) if directory.is_dir() else []:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            record = json.loads(ev.read_bounded(path))
        except (OSError, ValueError, EvidenceError):
            continue
        if (isinstance(record, dict) and record.get("kind") == "downgrade" and record.get("algorithm") == MLDSA
                and record.get("result") == "refused"):
            found.append((path.name, record.get("fingerprint")))
    return found


def _judge_downgrade(ev: Evidence, pin: str) -> str:
    """The refusal lab downgrade recorded under the current pin, while the Guardian signs with ML-DSA-65.

    Any refused result under the current pin counts, with no reading of file times. lab init makes a new key each
    time, so a matching pin means a refusal from this key's life, and the signing setting says the Guardian is still
    on ML-DSA-65."""
    signing = _signing(ev)
    if signing != MLDSA:
        raise _NotYet(f"the Guardian signs decisions with {signing} now, so it would open a session for a client "
                      f"that can check only {HMAC}. Run ./lab.sh sign mldsa, then ./lab.sh downgrade")
    refusals = _refusals(ev)
    if not refusals:
        raise _NotYet(f"no downgrade result says the Guardian refused to fall back to {HMAC}. With signing on "
                      f"{MLDSA}, run ./lab.sh downgrade")
    for name, fingerprint in refusals:
        if fingerprint == pin:
            return f"lab downgrade recorded the Guardian's signed refusal of an HMAC only ClientHello ({name})"
    if all(fingerprint is None for _, fingerprint in refusals):
        raise _NotYet("the downgrade result names no Guardian fingerprint, so it can't show the refusal came from "
                      "the key lab init pinned. Run ./lab.sh downgrade")
    raise _NotYet(f"the downgrade result was recorded under another Guardian key, not the pin {pin} in .env. A "
                  "fresh lab init changes the key, so run ./lab.sh downgrade again")
