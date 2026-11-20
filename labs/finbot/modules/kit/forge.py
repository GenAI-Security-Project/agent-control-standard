"""lab forge [--session ID]: a Guardian deny rewritten to allow in a copy of the transcript (issue #589, LAB-16).

Version 1.3.0. Owner: Rock Lambros. Runs in the lab container, with acs from the image's adapters environment.

Module 7 plays the gateway turned forger. It holds the gateway's files, so it holds the shared HMAC secret, and it
wants the record to say the Guardian allowed a tool call the Guardian denied. lab forge takes the newest transcript
with a denied steps/toolCallRequest, or the one named, and writes state/forged/<session>.jsonl: every line as the
gateway wrote it except that one answer, which says allow, drops its reason codes, and is signed the only way the
forger can sign, with HMAC under the session key derive_session_key(state/secrets/hmac.key, session_id), the way the
Guardian signs under HMAC-SHA256. The chain head stays, because the chain hashes requests only (example_guardian
compute_entry_hash and append_to_chain), and the request binding stays too.

Then acs-verify judges the copy, with --hmac-secret for a session that negotiated HMAC and with the key document and
the fingerprint from .env for one that negotiated ML-DSA-65. Under HMAC the forgery verifies: HMAC shows that nobody
without the secret edited the log, and can't say which side wrote an entry (specification section 8.6). Under
ML-DSA-65 it fails at the forged line, because only the Guardian holds the decision key.

lab forge writes only under state/forged/ and state/verify/. The gateway's transcripts are evidence the checks read,
so they are never touched. Lab conventions: ML-DSA-65 response signing (issue #316), the key document (issue #460),
the result file shape (plan LAB-13, open question 1).
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import results
import sessions
from sessions import HMAC, MLDSA, evidence

from acs.core import derive_session_key, sign_with_key

USAGE = "lab forge takes --session <session id>, nothing else"
NO_DENY = ("no transcript holds a tool call the Guardian denied. Make one with module 3's attack run: "
           "./lab.sh policy 3 solution, then ./lab.sh run s2")
# The label the lab gives its HMAC secret (compose.yaml ACS_HMAC_KEY_ID), for a request that names none.
LAB_HMAC_KEY_ID = "lab"
# The secret is a line of hex. The bound keeps a wrong file from being read whole.
MAX_SECRET_BYTES = 4096


def parse_arguments(argv: list[str]) -> str | None:
    """The session id argv names, None for the newest, or ValueError with USAGE. guide_sim.py reads the guides'
    forge flags here, so this parser is the one place they are stated."""
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == "--session":
        return sessions.session_argument(argv[1])
    raise ValueError(USAGE)


def _secret(path: Path) -> bytes:
    with path.open("rb") as f:
        data = f.read(MAX_SECRET_BYTES + 1)
    secret = data.rstrip(b"\r\n\t ")
    if not secret or len(data) > MAX_SECRET_BYTES:
        raise ValueError(f"{path.name} doesn't hold an HMAC secret")
    return secret


def forged_record(transcript: sessions.Transcript, line: int, secret: bytes) -> dict[str, Any]:
    """The answer at line, rewritten to allow and HMAC-signed under the session key.

    Every field but the decision, the reason codes and the signature is kept, chain_hash, request_id and an
    ML-DSA-65 answer's request hash included, so the forgery fails, where it fails, on its signature alone.
    Raises ValueError when line isn't a request's answer, which denied_line never returns."""
    record = transcript.records[line - 1]
    request = transcript.records[line - 2] if line >= 2 else None
    # Checked rather than asserted, so python -O can't turn a bad line into a traceback (review M3).
    if record is None or request is None or not isinstance(record.get("envelope"), dict):
        raise ValueError(f"line {line} of session {transcript.session_id} is not a request's answer")
    envelope = copy.deepcopy(record["envelope"])
    result = {k: v for k, v in envelope["result"].items() if k not in ("reason_codes", "signature")}
    result["decision"] = "allow"
    envelope["result"] = result
    signature = (request["envelope"].get("params") or {}).get("signature")
    key_id = signature.get("key_id") if isinstance(signature, dict) else None
    # The request's own label, the one the Guardian signs HMAC answers under, so the copy looks like its answer.
    sign_with_key(envelope, derive_session_key(secret, transcript.session_id),
                  key_id=key_id if isinstance(key_id, str) and key_id else LAB_HMAC_KEY_ID)
    return {**record, "envelope": envelope}


def _write_copy(path: Path, lines: list[bytes]) -> None:
    """The copy through a temporary file and one rename, owner-only like the transcripts it copies."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b"".join(line + b"\n" for line in lines))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _failure_line(outcome: evidence.VerifyResult) -> int | None:
    line = ((outcome.report or {}).get("failure") or {}).get("line")
    return line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None


def main(argv: list[str], *, root: Path | str | None = None, runner: evidence.Runner | None = None) -> int:
    try:
        session_id = parse_arguments(argv)
    except ValueError as e:
        return sessions.broken(str(e))
    ev = evidence.Evidence(sessions.bundle_root(root), runner=runner)
    if session_id is not None:
        transcript = sessions.read(ev, session_id)
        if transcript is None:
            return sessions.not_yet(f"session {session_id} has no transcript yet. {NO_DENY}")
        if transcript.denied_line is None:
            return sessions.not_yet(f"session {session_id} holds no tool call the Guardian denied. {NO_DENY}")
    else:
        transcript = sessions.newest(ev, lambda t: t.denied_line is not None and t.algorithm is not None)
        if transcript is None:
            return sessions.not_yet(NO_DENY)
    session_id, line, algorithm = transcript.session_id, transcript.denied_line, transcript.algorithm
    if line is None:
        return sessions.not_yet(NO_DENY)
    if algorithm is None:
        return sessions.broken(f"session {session_id} holds no ServerHello, so its response algorithm is unknown")
    if algorithm == MLDSA and ev.fingerprint() is None:
        return sessions.broken(f"{evidence.FINGERPRINT_KEY} isn't in .env. Run ./lab.sh init, which writes the "
                               "fingerprint it prints there")
    try:
        secret = _secret(ev.state / "secrets" / "hmac.key")
    except (OSError, ValueError) as e:
        return sessions.broken(f"the lab's HMAC secret can't be read ({e}). Run ./lab.sh init")

    lines = list(transcript.lines)
    try:
        record = forged_record(transcript, line, secret)
    except ValueError as e:
        return sessions.broken(str(e))
    lines[line - 1] = json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    copy_path = ev.state / "forged" / f"{session_id}.jsonl"
    _write_copy(copy_path, lines)

    outcome = ev.verify(session_id, hmac=algorithm == HMAC, directory="forged")
    # Under HMAC the genuine transcript passes too, so a verdict on any other file would let the DONE line describe
    # a forgery nobody checked. The verdict counts only when acs-verify read the copy (review M1).
    if str(copy_path) not in outcome.argv:
        return sessions.broken(f"acs-verify didn't read the forged copy of session {session_id}, so its verdict "
                               "says nothing about the forgery")
    if outcome.outcome not in ("verified", "broken"):
        return sessions.broken(outcome.detail)
    failed_at = _failure_line(outcome)
    failure_code = ((outcome.report or {}).get("failure") or {}).get("code")
    if algorithm == HMAC and outcome.outcome == "verified":
        results.write(ev.state, kind="forge", algorithm=HMAC, session_id=session_id, result="verified", entry=line,
                      detail=f"the forged allow at line {line} verifies under HMAC")
        return sessions.done(f"the forged allow at line {line} verifies under HMAC. Anyone holding the shared key "
                             "could have written it")
    if algorithm == MLDSA and outcome.outcome == "broken" and failed_at == line:
        results.write(ev.state, kind="forge", algorithm=MLDSA, session_id=session_id, result="broken", entry=line,
                      detail=f"the forged allow fails at line {line} under ML-DSA-65. {outcome.detail}")
        return sessions.done(f"the forged allow fails at line {line} under ML-DSA-65")
    # Anything else means the session itself doesn't verify, so the copy shows nothing about the forgery.
    if failure_code == "fingerprint_mismatch":
        # acs-verify refused the key document before reading a line (review M2).
        return sessions.not_yet("the key document in state/keys doesn't hold the key with the fingerprint lab init "
                                "pinned, so no ML-DSA-65 answer can verify. Run ./lab.sh verify to see the mismatch")
    if outcome.outcome == "verified":
        return sessions.not_yet(f"the forged copy of session {session_id} verified under {algorithm}, which it "
                                "shouldn't. Run ./lab.sh verify to check the session itself")
    return sessions.not_yet(f"the forged copy of session {session_id} fails at line {failed_at}, not at the forged "
                            f"line {line}, so the session doesn't verify as the gateway wrote it. {outcome.detail}")
