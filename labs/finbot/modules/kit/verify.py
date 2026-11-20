"""lab verify [--keys-only] [--session ID]: acs-verify over an ML-DSA-65 session (issue #589, LAB-16 Task 12).

Version 1.3.0. Owner: Rock Lambros. Standard library only, plus the kit's sessions and results.

It checks the newest session the gateway wrote, or the one named, and always passes --keys
state/keys/guardian-keys.json with --expect-fingerprint set to LAB_GUARDIAN_FINGERPRINT from .env (ledger ruling
2026-11-17). The session is chosen without reading its ServerHello. The forger can edit that field, and a session
picked by it lets a forged newest session drop out of view while an older genuine one prints DONE (review I1). A
session that ran under HMAC fails under the pinned key, and the NOT YET line names it. The gateway can write state/, so a forger holding its files could swap the key document. The pin
from .env, which no service mounts, is what catches that, so without it lab verify refuses to run and exits 2.

--keys-only checks the signatures, bindings and key validity without the chain, and writes the keys_only result the
viewer paints. Lab conventions: the key document (issue #460) and ML-DSA-65 response signing (issue #316).
"""
from __future__ import annotations

from pathlib import Path

import results
import sessions
from sessions import MLDSA, evidence

USAGE = "lab verify takes --keys-only and --session <session id>, nothing else"


def parse_arguments(argv: list[str]) -> tuple[bool, str | None]:
    """(keys_only, session_id) from argv, or ValueError with USAGE. guide_sim.py reads the guides' verify flags here,
    so this parser is the one place they are stated."""
    keys_only, session_id, rest = False, None, list(argv)
    while rest:
        arg = rest.pop(0)
        if arg == "--keys-only" and not keys_only:
            keys_only = True
        elif arg == "--session" and session_id is None and rest:
            session_id = sessions.session_argument(rest.pop(0))
        else:
            raise ValueError(USAGE)
    return keys_only, session_id


def main(argv: list[str], *, root: Path | str | None = None, runner: evidence.Runner | None = None) -> int:
    try:
        keys_only, session_id = parse_arguments(argv)
    except ValueError as e:
        return sessions.broken(str(e))
    ev = evidence.Evidence(sessions.bundle_root(root), runner=runner)
    if ev.fingerprint() is None:
        return sessions.broken(f"{evidence.FINGERPRINT_KEY} isn't in .env. Run ./lab.sh init, which writes the "
                               "fingerprint it prints there")
    if session_id is not None:
        transcript = sessions.read(ev, session_id)
        if transcript is None:
            return sessions.not_yet(f"session {session_id} has no transcript yet. Run ./lab.sh run s2 first")
    else:
        transcript = sessions.newest(ev, lambda _: True)
        if transcript is None:
            return sessions.not_yet("no session has run yet. Run ./lab.sh sign mldsa, then ./lab.sh run s2")
    session_id = transcript.session_id
    outcome = ev.verify(session_id, keys_only=keys_only)
    if outcome.outcome not in ("verified", "broken"):
        return sessions.broken(outcome.detail)
    entry = None
    if outcome.outcome == "broken":
        line = ((outcome.report or {}).get("failure") or {}).get("line")
        entry = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
    if keys_only:
        results.write(ev.state, kind="keys_only", algorithm=MLDSA, session_id=session_id, result=outcome.outcome,
                      entry=entry, detail=outcome.detail)
    what = "every signature in" if keys_only else "the whole of"
    if outcome.outcome == "verified":
        return sessions.done(f"{what} session {session_id} verifies under ML-DSA-65 with the key lab init pinned")
    # The ServerHello is only a hint here, read after the verdict: a session it says ran under HMAC fails for that
    # reason, and one that claims ML-DSA-65 failed on something in the record.
    hint = ("" if transcript.algorithm == MLDSA else " Its ServerHello names no ML-DSA-65, so it ran under HMAC or was "
            "edited. To make an ML-DSA-65 session, run ./lab.sh sign mldsa, then ./lab.sh run s2.")
    detail = outcome.detail.rstrip(".")
    return sessions.not_yet(f"session {session_id} doesn't verify under the pinned key. {detail}.{hint}")
