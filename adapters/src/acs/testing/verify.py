"""acs-verify: check a Guardian session transcript offline, its audit chain and every decision signature (issue #584).

    python -m acs.testing.verify TRANSCRIPT --keys KEY_DOCUMENT [--expect-fingerprint FP] [--hmac-secret FILE]
    python -m acs.testing.verify TRANSCRIPT --hmac-secret FILE

The transcript is the lab gateway's JSONL (A.7): one {"dir": "req" | "resp", "envelope": {...}} object per line,
in send order, and {"dir": "resp", "envelope": null, "cause": "..."} when a request got no usable answer. Each
response line answers the request line before it.

Four checks run on every pair, and the first failure is reported with its line number:

- The response signature. With --keys, every response must verify under ML-DSA-65 with the key its key_id names in
  the key document, and must carry the hash of the request it answers. With --hmac-secret alone, every response must
  verify under the HMAC session key. The flags choose the algorithm. Nothing in the transcript does, so rewriting a
  ServerHello can't switch a check to HMAC (PREMORTEM P5).
- The request binding: the JSON-RPC id, the request_id, and under ML-DSA-65 x_acs_lab_request_sha256, the
  SHA-256 of the request's section 10 signed input.
- Key validity: the key must be live, and not revoked, at the request's timestamp (PREMORTEM P25).
- The audit chain, recomputed exactly as the example Guardian's compute_entry_hash and append_to_chain build it,
  for exactly the methods the Guardian chains (acs.guardian._chain), against every chain_hash it signed.

A pass claims only what a signature covers. Every request line no signed decision covers is listed: a request with
a null or missing answer, a step answered without a chain head, and a ping. While that list is not empty, or the
transcript ends without a verified sessionEnd, the report says the transcript is not complete and never says the
whole log verified (PREMORTEM P31). The exit code stays 0 for such a pass.

Three gateway lines are unsigned claims, reported and never read as decisions, and a transcript carrying one is never
complete (fix rounds 4 and 5). A gap line, or a JSON object that is no JSON-RPC answer written with the cause
acs.client gave, is a recorded failure. A discards line, and an answer written with the cause decision_timeout, say
the gateway withheld a verified answer. An unsigned -32004 answering a request that names a key_id is the one unsigned
error specification section 10 allows. Any other unsigned answer still fails.

Lab conventions: the key document format acs-lab-keys/1 (issue #460), the request hash (issue #576, closest
tracking issue #13), and ML-DSA-65 response signing (issue #316). This module imports acs.core, acs.client and the
Guardian's chain predicate, and loads cryptography only when a key document is given, so the HMAC mode needs no
pqc extra.

Exit codes: 0 pass, 1 verification failure, 2 usage error or unreadable input.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import itertools
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from acs.client import (
    KeyDocumentError,
    ResponseKeys,
    not_writable_by_others,
    owner_only,
    parse_key_document,
    read_trusted_file,
)
from acs.core import (
    BINDING_ID,
    BINDING_REQUEST,
    BINDING_RESULT,
    BINDING_SHAPE,
    derive_session_key,
    jcs_canonicalize,
    parse_iso8601,
    response_binding_problem,
    response_names_request,
    response_shape_problem,
    server_hello_problem,
    verify_with_key,
)
from acs.core._canonical import CANONICALIZATION_ERRORS
from acs.guardian._chain import HANDSHAKE_METHOD, PING_METHOD, chains_method

ML_DSA_65 = "ML-DSA-65"
HMAC_SHA256 = "HMAC-SHA256"
SESSION_END = "steps/sessionEnd"
# A request whose answer carries no chain_hash may or may not have advanced the chain (PREMORTEM P6). The next
# checkpoint settles it by trying each such request in and out, 2**n candidates, so n is bounded. 20 keeps a lab
# segment with the Guardian down from failing a genuine transcript as tampered, at about a second of hashing.
MAX_UNSETTLED = 20
# Causes acs.client gives only when a request failed before post(), so it never left the client: a Guardian URL it
# refused, an envelope it couldn't sign, a request that can't bind an answer, and a body over the cap. Such a
# request is listed but not held for the chain. Every other cause is held, because it can follow a send the Guardian
# chained: transport_failure covers a reply lost after the answer was written, adapter_exception can come from either
# side of the send, and on_wire_failed names a callback failure on "req" or on "resp" alike (fix round 3, F1).
NEVER_SENT_CAUSES = frozenset({"guardian_url_rejected", "envelope_not_signable", "request_envelope_invalid",
                               "request_exceeds_max_payload"})
# Section 10 names the one error a Guardian sends unsigned: SIGNATURE_INVALID for a key_id it holds no secret for
# (specification section 10, "key_id for HMAC", and decision D-039). acs.client reads it the same way (key_id_rejected).
SIGNATURE_INVALID = -32004
# The one cause the gateway writes on a discards line and on a signed answer: the answer came after the deadline.
LATE_CAUSE = "decision_timeout"
UNSIGNED_TEXT = ("the response carries no signature. Only system/ping and the -32004 a Guardian sends for a key_id it "
                 "holds no secret for may go unsigned (specification section 10, decision D-039)")
# Section 10 asks for at least 32 bytes of secret, the bound acs.client applies.
MIN_SECRET_BYTES = 32
# A secret file is a few dozen bytes. The bound keeps a wrong path, such as a log, from being read whole.
MAX_SECRET_BYTES = 4096
# The cap acs.client puts on a key document.
MAX_KEY_DOCUMENT_BYTES = 1 << 20
DEFAULT_MAX_TRANSCRIPT_BYTES = 256 * 1024 * 1024
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
# Stands in for every revoked key_id in the load check, so the revoked list's shape is checked without revoking.
_PROBE_KEY_ID = "\u0000acs-verify-load-check"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

HMAC_TRUST_NOTE = ("HMAC-SHA256 proves only that someone holding the shared secret wrote each response. It can't "
                   "say whether the Guardian or the agent side did (specification section 8.6).")

_BINDING_TEXT = {
    BINDING_REQUEST: "the request is not an envelope any answer can bind to",
    BINDING_SHAPE: "the answer is not a JSON-RPC 2.0 response with exactly one result or error",
    BINDING_ID: "the answer carries a different JSON-RPC id",
    BINDING_RESULT: "the result carries a different request_id, or this request can't bind a result",
}


class UsageError(Exception):
    """Bad flags or input that can't be read. The command exits 2."""


@dataclass(frozen=True)
class Failure:
    """The first entry that failed: its 1-based line (0 for the key document itself), a stable code, and why."""

    line: int
    code: str
    reason: str


@dataclass
class Report:
    ok: bool = False
    complete: bool = False
    failure: Failure | None = None
    lines: int = 0
    entries: int = 0
    checkpoint_line: int | None = None
    checkpoint_method: str | None = None
    unverified_lines: list[int] = field(default_factory=list)
    unsigned_lines: list[int] = field(default_factory=list)
    discarded_lines: list[int] = field(default_factory=list)
    recorded_failures: list[dict[str, Any]] = field(default_factory=list)
    unsigned_errors: list[dict[str, Any]] = field(default_factory=list)
    response_algorithm: str = ""
    chain_checked: bool = True
    session_id: str | None = None
    chain_heads: list[str] = field(default_factory=list)
    keys_used: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "result": "pass" if self.ok else "fail",
            "complete": self.complete,
            "failure": None if self.failure is None else {"line": self.failure.line, "code": self.failure.code,
                                                          "reason": self.failure.reason},
            "lines": self.lines,
            "entries": self.entries,
            "checkpoint_line": self.checkpoint_line,
            "checkpoint_method": self.checkpoint_method,
            "unverified_lines": self.unverified_lines,
            "unsigned_lines": self.unsigned_lines,
            "discarded_lines": self.discarded_lines,
            "recorded_failures": self.recorded_failures,
            "unsigned_errors": self.unsigned_errors,
            "response_algorithm": self.response_algorithm,
            "chain_checked": self.chain_checked,
            "session_id": self.session_id,
            "chain_heads": self.chain_heads,
            "keys_used": self.keys_used,
            "warnings": self.warnings,
            "notes": self.notes,
        }

    def to_text(self) -> str:
        out: list[str] = []
        if self.failure is not None:
            where = "the key document" if self.failure.line == 0 else f"line {self.failure.line}"
            out.append(f"acs-verify: FAIL at {where} ({self.failure.code})")
            out.append(f"  {self.failure.reason}")
            if self.failure.line > 1:
                out.append(f"  Lines 1 to {self.failure.line - 1} checked before it. Nothing after it was checked.")
        elif self.complete:
            out.append("acs-verify: PASS")
        elif not self.chain_checked:
            out.append("acs-verify: PASS, signatures only")
        elif self.unverified_lines:
            out.append("acs-verify: PASS, tail unverified")
        else:
            out.append("acs-verify: PASS, not complete")
        out.append(f"  transcript: {self.lines} lines, {self.entries} requests, session {self.session_id or 'unknown'}")
        if self.response_algorithm:
            keys = ", ".join(f"{kid} ({fp})" for kid, fp in self.keys_used.items())
            out.append(f"  responses: {self.response_algorithm}" + (f", key {keys}" if keys else ""))
        if self.failure is None:
            out.append(self._chain_line())
            if self.unsigned_lines:
                out.append(f"  no signed decision: {_request_lines(self.unsigned_lines)}. No signature covers "
                           "what was decided for them.")
            if self.discarded_lines:
                out.append(f"  withheld by the gateway: {_request_lines(self.discarded_lines)}. The gateway's unsigned "
                           "line says it withheld the answer and denied the step as decision_timeout. No signature "
                           "covers that claim.")
            if self.recorded_failures:
                failures = ", ".join(f"{f['line']} ({f['cause']})" for f in self.recorded_failures)
                out.append(f"  recorded failures: {_noun(self.recorded_failures)} {failures}. No usable answer came "
                           "back, as the gateway recorded.")
            if self.unsigned_errors:
                out.append(f"  unsigned -32004 for an unknown key_id: "
                           f"{_request_lines([e['line'] for e in self.unsigned_errors])}. The Guardian refused the "
                           "request's key, so it decided nothing (specification section 10).")
        out.extend(f"  warning: {warning}" for warning in self.warnings)
        out.extend(f"  note: {note}" for note in self.notes)
        return "\n".join(out)

    def _chain_line(self) -> str:
        if not self.chain_checked:
            return "  chain: not checked (--keys-only). Signatures, bindings and key validity only."
        if self.complete:
            return (f"  chain: verified through line {self.checkpoint_line} ({SESSION_END}). "
                    "The whole transcript verified.")
        through = (f"verified through line {self.checkpoint_line} ({self.checkpoint_method})"
                   if self.checkpoint_line else "no checkpoint verified")
        if not self.unverified_lines and self.checkpoint_method == SESSION_END:
            return f"  chain: {through}. Not complete, since some requests have no signed decision."
        tail = _ranges(self.unverified_lines)
        lines = "Line" if len(self.unverified_lines) == 1 else "Lines"
        verb = "is" if len(self.unverified_lines) == 1 else "are"
        tail_text = f" {lines} {tail} {verb} not covered by any signed chain_hash." if tail else ""
        return (f"  chain: {through}. tail unverified: no {SESSION_END}.{tail_text} Entries cut from the end "
                "of the transcript can't be detected.")


def _noun(items: Sequence[Any]) -> str:
    return "request line" if len(items) == 1 else "request lines"


def _request_lines(numbers: Sequence[int]) -> str:
    return f"{_noun(numbers)} {_ranges(numbers)}"


def _ranges(numbers: Sequence[int]) -> str:
    if not numbers:
        return ""
    spans, start, prev = [], numbers[0], numbers[0]
    for n in list(numbers[1:]) + [None]:
        if n is not None and n == prev + 1:
            prev = n
            continue
        spans.append(str(start) if start == prev else f"{start} to {prev}")
        if n is not None:
            start = prev = n
    return ", ".join(spans)


class _Fail(Exception):
    def __init__(self, line: int, code: str, reason: str) -> None:
        super().__init__(reason)
        self.failure = Failure(line, code, reason)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Two parsers that keep different copies of a repeated key read one line two ways, so a repeat is refused.
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"the key {key!r} appears twice in one object")
        out[key] = value
    return out


def _no_constants(name: str) -> Any:
    # NaN and the infinities aren't JSON, and RFC 8785 has no form for them, so no signature could cover one.
    raise ValueError(f"{name} is not JSON")


def _strict_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants)


def _parse_line(raw: str | bytes, number: int) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        record = _strict_loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _Fail(number, "line_invalid", f"the line is not one strict JSON object: {exc}") from exc
    if not isinstance(record, dict) or record.get("dir") not in ("req", "resp"):
        raise _Fail(number, "line_invalid", 'the line is not a {"dir": "req" or "resp", "envelope": ...} record')
    envelope = record.get("envelope")
    if record["dir"] == "req" and not isinstance(envelope, dict):
        raise _Fail(number, "line_invalid", "a request line must carry its envelope as an object")
    if record["dir"] == "resp" and envelope is not None and not isinstance(envelope, dict):
        raise _Fail(number, "line_invalid", "a response line carries an envelope object, or null with a cause")
    if "discards" in record:
        # The gateway's discards line, a lab convention until issue #577 settles it: {"dir": "resp", "envelope":
        # null, "cause": "decision_timeout", "discards": <request_id>}.
        discards = record["discards"]
        if (record["dir"] != "resp" or envelope is not None or not isinstance(discards, str) or not discards
                or record.get("cause") != LATE_CAUSE):
            raise _Fail(number, "line_invalid", "a discards line is a response line with a null envelope, the cause "
                                                f"{LATE_CAUSE} and one request_id")
    return record


def _params(request: Mapping[str, Any]) -> Mapping[str, Any]:
    params = request.get("params")
    return params if isinstance(params, Mapping) else {}


def _request_key_id(request: Mapping[str, Any]) -> str | None:
    signature = _params(request).get("signature")
    key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
    return key_id if isinstance(key_id, str) else None


def _timestamp(request: Mapping[str, Any]) -> str | None:
    value = _params(request).get("timestamp")
    return value if isinstance(value, str) and value else None


def _moment(request: Mapping[str, Any], line: int) -> datetime.datetime:
    """The request's own timestamp, the time a key must be live at. It sits inside the signed request hash."""
    value = _timestamp(request)
    if value is None:
        raise _Fail(line, "no_timestamp", "the request has no timestamp, so key validity can't be checked")
    try:
        moment = parse_iso8601(value)
    except (ValueError, TypeError) as exc:
        raise _Fail(line, "no_timestamp", f"the request timestamp {value!r} is not RFC 3339") from exc
    if moment.tzinfo is None:
        raise _Fail(line, "no_timestamp", f"the request timestamp {value!r} names no time zone")
    return moment


def chain_entry(request: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ContextEntry the example Guardian appends for this request, without its hashes, or None without a timestamp.

    Mirrors example_guardian.append_to_chain: the entry and step ids are params.request_id, step_type is the method,
    request_hash is the SHA-256 of JCS(params) with the signature inside, and the timestamp is the request's own.
    A request with no timestamp gets the Guardian's clock, which no reader can recompute. Raises one of
    acs.core's canonicalization errors when RFC 8785 has no form for params.
    """
    params = _params(request)
    timestamp = _timestamp(request)
    if timestamp is None:
        return None
    request_id = params.get("request_id")
    request_id = "" if request_id is None else request_id
    return {
        "entry_id": request_id,
        "step_id": request_id,
        "step_type": request.get("method"),
        "request_hash": hashlib.sha256(jcs_canonicalize(dict(params))).hexdigest(),
        "timestamp": timestamp,
    }


def _entry_bytes(entry: Mapping[str, Any]) -> bytes:
    """JCS of the entry without its own hashes, the part of section 8.2's input that never changes."""
    return jcs_canonicalize({k: v for k, v in entry.items() if k not in ("entry_hash", "previous_hash")})


def _head(content: bytes, previous_hash: str | None) -> str:
    previous = bytes.fromhex(previous_hash) if previous_hash else b""
    return hashlib.sha256(content + previous).hexdigest()


def entry_hash(entry: Mapping[str, Any], previous_hash: str | None) -> str:
    """Section 8.2, as example_guardian.compute_entry_hash: SHA-256 of JCS(entry) and the previous head's raw bytes.

    The entry is hashed without its own hashes, so previous_hash enters only as the trailing raw bytes.
    """
    return _head(_entry_bytes(entry), previous_hash)


def _probe_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """The document with every well-formed revocation renamed to a key_id no key has, so nothing is revoked.

    A malformed revoked list or a bad revoked_at stays as it is, so parsing the probe still refuses it.
    """
    revoked = document.get("revoked", [])
    if isinstance(revoked, list):
        revoked = [{**entry, "key_id": _PROBE_KEY_ID}
                   if isinstance(entry, Mapping) and isinstance(entry.get("key_id"), str) and entry["key_id"]
                   else entry for entry in revoked]
    return {**document, "revoked": revoked}


class _KeyDocument:
    """The key document, parsed once: each key_id's keys and validity, and the fingerprints an operator pinned."""

    def __init__(self, document: Mapping[str, Any], *, key_id: str | None, fingerprints: Sequence[str]) -> None:
        self.pin = key_id
        self.fingerprints = tuple(fingerprints)
        keys = document.get("keys") if isinstance(document, Mapping) else None
        if not isinstance(keys, list) or not keys:
            raise UsageError("the key document holds no keys list")
        probe = _probe_document(document)
        # parse_key_document checks every entry, the revoked list included, whatever the time, so the first parse
        # that succeeds proves the whole document well formed. Revocations are neutralized for that check only.
        self.keys: dict[str, ResponseKeys | None] = {}
        self.fingerprint_by_id: dict[str, str] = {}
        problem = "no key entry names a key_id and a not_before"
        for entry in keys:
            entry_id = entry.get("key_id") if isinstance(entry, Mapping) else None
            not_before = entry.get("not_before") if isinstance(entry, Mapping) else None
            if not isinstance(entry_id, str) or not isinstance(not_before, str):
                continue
            try:
                moment = datetime.datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                unrevoked = parse_key_document(probe, key_id=entry_id, now=moment)
            except (KeyDocumentError, ValueError, TypeError) as exc:
                problem = str(exc)
                continue
            self.fingerprint_by_id[entry_id] = unrevoked.fingerprint
            try:
                # The real document gives the key's revoked_at. A key revoked at or before its own not_before is
                # never live, so it verifies nothing.
                self.keys[entry_id] = parse_key_document(document, key_id=entry_id, now=moment)
            except KeyDocumentError:
                self.keys[entry_id] = None
        if not self.fingerprint_by_id:
            raise UsageError(f"the key document can't be used: {problem}")
        if key_id is not None and key_id not in self.fingerprint_by_id:
            raise UsageError(f"--key-id {key_id!r} names no key in the key document. It holds "
                             f"{', '.join(sorted(self.fingerprint_by_id))}")

    def pinned_fingerprint_problem(self) -> str | None:
        if self.fingerprints and not set(self.fingerprints) & set(self.fingerprint_by_id.values()):
            return (f"the key document holds no key with fingerprint {', '.join(self.fingerprints)}. It has "
                    f"{', '.join(sorted(self.fingerprint_by_id.values()))}, so it is not the Guardian's document")
        return None


@dataclass
class _Held:
    """A chained-method request no chain head has covered yet, with its entry encoded once."""

    line: int
    content: bytes | None


class _Verifier:
    def __init__(self, *, keys: _KeyDocument | None, hmac_secret: bytes | None, keys_only: bool) -> None:
        self.keys = keys
        self.hmac_secret = hmac_secret
        self.report = Report(response_algorithm=ML_DSA_65 if keys is not None else HMAC_SHA256,
                             chain_checked=not keys_only)
        self.head: str | None = None
        self.held: list[_Held] = []
        # Lines left out of the chain since the last checkpoint because their cause shows they were never sent.
        self.dropped: list[int] = []
        self.session_key: bytes | None = None
        self.request_ids: set[str] = set()
        self.content: dict[int, bytes | None] = {}
        self.warned: set[str] = set()
        # A request whose signature failed under the HMAC session key. It fails unless its answer is the unsigned
        # -32004, since a request under a key the Guardian doesn't hold can't verify under the Guardian's secret.
        self.pending: _Fail | None = None
        # Request key_ids the Guardian answered with a verified signature, and those it refused with the unsigned
        # -32004, each with the first line that showed it. One key_id can't be both in one transcript.
        self.accepted_key_ids: dict[str, int] = {}
        self.rejected_key_ids: dict[str, int] = {}

    # Requests

    def request(self, line: int, request: dict[str, Any]) -> None:
        self.report.entries += 1
        method = request.get("method")
        if not isinstance(method, str):
            raise _Fail(line, "line_invalid", "the request names no method")
        try:
            jcs_canonicalize(request)
            entry = chain_entry(request)
            self.content[line] = None if entry is None else _entry_bytes(entry)
        except CANONICALIZATION_ERRORS as exc:
            raise _Fail(line, "not_canonical", "the request holds a value RFC 8785 (JCS) can't encode, such as an "
                                               "integer beyond 2**53 or a number too large for a double, so no "
                                               f"signature or chain entry can cover it ({type(exc).__name__})")
        request_id = _params(request).get("request_id")
        if isinstance(request_id, str) and request_id:
            if request_id in self.request_ids:
                raise _Fail(line, "duplicate_request_id", f"request_id {request_id!r} appears earlier in the "
                                                          "transcript. A request is sent once")
            self.request_ids.add(request_id)
        if method == PING_METHOD:
            return
        metadata = _params(request).get("metadata")
        session_id = metadata.get("session_id") if isinstance(metadata, Mapping) else None
        if not isinstance(session_id, str) or not session_id:
            raise _Fail(line, "line_invalid", "the request names no session_id")
        if self.report.session_id is None:
            self.report.session_id = session_id
            if self.hmac_secret is not None:
                self.session_key = derive_session_key(self.hmac_secret, session_id)
        elif session_id != self.report.session_id:
            raise _Fail(line, "session_mismatch", f"the request names session {session_id}, but the transcript "
                                                  f"began with session {self.report.session_id}")
        if self.session_key is not None and not verify_with_key(request, self.session_key):
            self.pending = _Fail(line, "request_signature_invalid",
                                 "the request signature does not verify under the HMAC session key")

    def raise_pending(self) -> None:
        if self.pending is not None:
            raise self.pending

    # Responses

    def response(self, req_line: int, request: dict[str, Any], resp_line: int, response: dict[str, Any]) -> bool:
        """Check one answer. True when it is a verified answer to a step, the only answer the gateway can withhold."""
        method = request.get("method")
        if method == PING_METHOD:
            # Section 13 leaves ping unsigned, so nothing covers it and nothing is chained.
            self.report.unsigned_lines.append(req_line)
            return False
        container = response.get("result") if "result" in response else response.get("error")
        signature = container.get("signature") if isinstance(container, Mapping) else None
        if not isinstance(signature, Mapping):
            if self._key_id_rejected(response):
                self._unsigned_error(req_line, request, resp_line, response)
                return False
            self.raise_pending()
            raise _Fail(resp_line, "unsigned_response", UNSIGNED_TEXT)
        self.raise_pending()
        self._check_binding(req_line, request, resp_line, response)
        if self.keys is not None:
            self._verify_mldsa(req_line, request, resp_line, response, signature)
        else:
            self._verify_hmac(resp_line, response)
        key_id = _request_key_id(request)
        if key_id is not None:
            if key_id in self.rejected_key_ids:
                raise _Fail(resp_line, "unsigned_response",
                            f"this signed answer accepts key_id {key_id!r}, which the unsigned -32004 at line "
                            f"{self.rejected_key_ids[key_id]} said the Guardian holds no secret for. That -32004 is "
                            "not the section 10 exemption, so it is an unsigned answer")
            self.accepted_key_ids.setdefault(key_id, resp_line)
        if method == HANDSHAKE_METHOD:
            self._check_server_hello(request, resp_line, response)
            return False
        result = response.get("result")
        chain_hash = result.get("chain_hash") if isinstance(result, Mapping) else None
        if isinstance(chain_hash, str):
            if self.report.chain_checked:
                self._checkpoint(req_line, request, resp_line, chain_hash)
        else:
            self.unanswered(req_line, request, None)
        return True

    def _check_binding(self, req_line: int, request: dict, resp_line: int, response: dict) -> None:
        problem = response_binding_problem(request, response)
        if problem is not None:
            reason = _BINDING_TEXT.get(problem, f"binding problem {problem!r}")
            raise _Fail(req_line, "binding", f"the response at line {resp_line} does not answer this request: "
                                             f"{reason}")

    @staticmethod
    def _key_id_rejected(response: Mapping[str, Any]) -> bool:
        """The unsigned -32004, by acs.client's own key_id_rejected rule: an error with that code and no signature."""
        error = response.get("error") if "result" not in response else None
        return isinstance(error, Mapping) and error.get("code") == SIGNATURE_INVALID and "signature" not in error

    def _unsigned_error(self, req_line: int, request: dict, resp_line: int, response: dict) -> None:
        """Accept the section 10 exemption, an unsigned -32004 for a key_id the Guardian holds no secret for.

        Nothing signs it, so it is listed and held like an unanswered request. Two checks keep it to the exemption:
        the request must name a key_id, as the Guardian answers this only to a readable signature object, and no
        verified answer in this transcript may accept that key_id.
        """
        self._check_binding(req_line, request, resp_line, response)
        key_id = _request_key_id(request)
        if key_id is None:
            raise _Fail(resp_line, "unsigned_response", "an unsigned -32004 answers a request that names no key_id, "
                                                        f"so it is not the section 10 exemption. {UNSIGNED_TEXT}")
        if key_id in self.accepted_key_ids:
            raise _Fail(resp_line, "unsigned_response",
                        f"an unsigned -32004 refuses key_id {key_id!r}, which the Guardian accepted with the signed "
                        f"answer at line {self.accepted_key_ids[key_id]}, so it is not the section 10 exemption")
        self.rejected_key_ids.setdefault(key_id, resp_line)
        # The Guardian refused this key, so the request's own signature couldn't verify under the Guardian's secret.
        self.pending = None
        self.report.unsigned_errors.append({"line": req_line, "code": SIGNATURE_INVALID})
        self.unanswered(req_line, request, None)

    def recorded_failure(self, req_line: int, request: dict[str, Any], cause: str) -> None:
        """A gap line or a verbatim non-answer body with the cause acs.client gave: no usable answer came back."""
        self.raise_pending()
        self.report.recorded_failures.append({"line": req_line, "cause": cause})
        self.unanswered(req_line, request, cause)

    def discard(self, line: int, request_id: str, answered: tuple[int, str | None] | None) -> None:
        """The gateway's discards line: the signed answer on the line before was withheld (lab convention, #577)."""
        if request_id not in self.request_ids:
            raise _Fail(line, "discards_invalid", f"the discards line names request_id {request_id!r}, which the "
                                                  "transcript has not seen")
        if answered is None or answered[1] != request_id:
            raise _Fail(line, "discards_invalid", f"the discards line names request_id {request_id!r}, but the line "
                                                  "before it is not that request's answer")
        self.report.discarded_lines.append(answered[0])

    def _check_server_hello(self, request: dict, resp_line: int, response: dict) -> None:
        """A verified ServerHello must also be one acs.client would negotiate on, by the same rule it applies."""
        hello = response.get("result")
        if not isinstance(hello, Mapping):
            return  # A signed refusal is an error, which the signature and binding checks already covered.
        if "negotiated_version" not in hello:
            raise _Fail(resp_line, "server_hello_invalid", "the ServerHello carries no negotiated_version, so no "
                                                           "client would negotiate on it")
        offered = _params(request).get("payload")
        problem = server_hello_problem(hello, offered if isinstance(offered, Mapping) else {})
        if problem is not None:
            raise _Fail(resp_line, "server_hello_invalid", f"the ServerHello does not answer its ClientHello: "
                                                           f"{problem}")

    def _verify_mldsa(self, req_line: int, request: dict, resp_line: int, response: dict,
                      signature: Mapping) -> None:
        import acs.core
        assert self.keys is not None
        key_id = signature.get("key_id")
        if not isinstance(key_id, str) or key_id not in self.keys.keys or (
                self.keys.pin is not None and key_id != self.keys.pin):
            raise _Fail(resp_line, "key_unknown", f"the response names key_id {key_id!r}, which the key document "
                                                  f"does not hold{' under the pin' if self.keys.pin else ''}. "
                                                  "It can't verify under ML-DSA-65")
        moment = _moment(request, req_line)
        keys = self.keys.keys[key_id]
        # verify_with_keyring never checks the validity window, so it is checked here, at this entry's own time.
        if keys is None or not keys.is_live(moment):
            raise _Fail(resp_line, "key_not_valid", f"key {key_id!r} was not live at the request's timestamp "
                                                    f"{_timestamp(request)}")
        if self.keys.fingerprints and keys.fingerprint not in self.keys.fingerprints:
            raise _Fail(resp_line, "fingerprint_mismatch", f"key {key_id!r} has fingerprint {keys.fingerprint}, "
                                                           "not the expected fingerprint")
        if not response_names_request(response, request):
            raise _Fail(req_line, "request_digest_mismatch",
                        f"the response at line {resp_line} names a different request: its x_acs_lab_request_sha256 "
                        "is missing or is not the hash of this request's signed input")
        # require_request_digest stays True, or a response relayed from another session that copied these ids
        # would verify (adapters/docs/signing.md, the relay limit).
        if not acs.core.verify_with_keyring(response, keys.keyring, expected_key_id=key_id, request=request,
                                            require_request_digest=True):
            raise _Fail(resp_line, "signature_invalid",
                        f"the response does not verify under {ML_DSA_65} key {key_id!r}")
        self.report.keys_used[key_id] = keys.fingerprint
        if keys.revoked_at is not None and key_id not in self.warned:
            self.warned.add(key_id)
            # Offline, validity can only be judged at the signed request timestamp, and whoever holds the private
            # key chooses that timestamp.
            self.report.warnings.append(
                f"key {key_id!r} signed entries here and the key document revokes it as of "
                f"{keys.revoked_at.isoformat().replace('+00:00', 'Z')}. Validity is checked at each request's signed "
                "timestamp, which anyone holding the stolen key can backdate, so these entries prove less than "
                "they seem")

    def _verify_hmac(self, resp_line: int, response: dict) -> None:
        assert self.session_key is not None
        if not verify_with_key(response, self.session_key):
            raise _Fail(resp_line, "signature_invalid", "the response does not verify under the HMAC session key")

    # The chain

    def unanswered(self, req_line: int, request: dict[str, Any], cause: object) -> None:
        """A request no signed decision covers. A chained method is held until the next checkpoint settles it."""
        method = request.get("method")
        self.report.unsigned_lines.append(req_line)
        if not self.report.chain_checked or not chains_method(method):
            return
        if cause in NEVER_SENT_CAUSES:
            self.dropped.append(req_line)
            return
        self.held.append(_Held(req_line, self.content.get(req_line)))

    def _checkpoint(self, req_line: int, request: dict, resp_line: int, chain_hash: str) -> None:
        content = self.content.get(req_line)
        if content is None:
            raise _Fail(req_line, "no_timestamp", "the request has no timestamp, so its chain entry can't be "
                                                  "recomputed")
        if len(self.held) > MAX_UNSETTLED:
            raise _Fail(req_line, "chain_unsettled", f"{len(self.held)} requests before this one got no chain "
                                                     f"head, more than the {MAX_UNSETTLED} acs-verify settles")
        # Fewest held entries first, so a request the Guardian refused before chaining is left out.
        candidates = [h.content for h in self.held if h.content is not None]
        for size in range(len(candidates) + 1):
            for chosen in itertools.combinations(candidates, size):
                head = self.head
                for item in (*chosen, content):
                    head = _head(item, head)
                if head == chain_hash:
                    self._settle(resp_line, request, chain_hash)
                    return
        unsettled = f" with {len(self.held)} unsettled requests before it tried in and out" if self.held else ""
        dropped = (f" Request line {_ranges(self.dropped)} was left out because its cause says it was never sent."
                   if len(self.dropped) == 1 else
                   f" Request lines {_ranges(self.dropped)} were left out because their causes say they were never "
                   "sent." if self.dropped else "")
        raise _Fail(req_line, "chain_mismatch", f"the chain_hash signed at line {resp_line} is not the head the "
                                                f"transcript builds here{unsettled}. An entry was edited, removed, "
                                                f"inserted or moved at or before this line.{dropped}")

    def _settle(self, resp_line: int, request: dict, chain_hash: str) -> None:
        self.head = chain_hash
        self.held.clear()
        self.dropped.clear()
        self.report.chain_heads.append(chain_hash)
        self.report.checkpoint_line = resp_line
        self.report.checkpoint_method = request.get("method")


def verify_transcript(lines: Iterable[str | bytes], *, key_document: Mapping[str, Any] | None,
                      hmac_secret: bytes | None, expect_fingerprints: Sequence[str] = (), key_id: str | None = None,
                      keys_only: bool = False) -> Report:
    """Check a transcript and return the report. Raises UsageError for bad flags or an unusable key document.

    key_document selects ML-DSA-65 for every response. hmac_secret alone selects HMAC-SHA256. With both, the secret
    checks request signatures and responses stay on ML-DSA-65, so an HMAC-signed response never passes beside a key
    document.
    """
    if key_document is None and hmac_secret is None:
        raise UsageError("give --keys (the Guardian's key document) or --hmac-secret")
    for fingerprint in expect_fingerprints:
        if not _FINGERPRINT.fullmatch(fingerprint):
            raise UsageError(f"--expect-fingerprint {fingerprint!r} must be sha256: and 64 lowercase hex characters")
    if expect_fingerprints and key_document is None:
        raise UsageError("--expect-fingerprint needs --keys")
    if key_id is not None and key_document is None:
        raise UsageError("--key-id needs --keys")
    keys = None if key_document is None else _KeyDocument(key_document, key_id=key_id,
                                                          fingerprints=expect_fingerprints)
    verifier = _Verifier(keys=keys, hmac_secret=hmac_secret, keys_only=keys_only)
    report = verifier.report
    if keys is None:
        report.notes.append(HMAC_TRUST_NOTE)
    try:
        if keys is not None:
            problem = keys.pinned_fingerprint_problem()
            if problem is not None:
                raise _Fail(0, "fingerprint_mismatch", problem)
        _walk(verifier, lines)
    except _Fail as fail:
        report.failure = fail.failure
        report.ok = False
        report.complete = False
        return report
    report.ok = True
    report.unsigned_lines.sort()
    after = report.checkpoint_line or 0
    report.unverified_lines = list(range(after + 1, report.lines + 1)) if report.chain_checked else []
    # A withheld answer rests on an unsigned gateway line anyone who can edit the file can add or remove, and a
    # complete pass rests on signatures alone (fix round 5, coordinator ruling on I1).
    report.complete = (report.chain_checked and report.checkpoint_method == SESSION_END
                       and not report.unverified_lines and not report.unsigned_lines and not report.discarded_lines)
    return report


def _walk(verifier: _Verifier, lines: Iterable[str | bytes]) -> None:
    report = verifier.report
    open_request: tuple[int, dict[str, Any]] | None = None
    # The request line and request_id of the answer on the line just read, the only answer a discards line can mark.
    answered: tuple[int, str | None] | None = None
    for number, raw in enumerate(lines, start=1):
        report.lines = number
        record = _parse_line(raw, number)
        envelope = record.get("envelope")
        just_answered, answered = answered, None
        if "discards" in record:
            if open_request is not None:
                raise _Fail(number, "discards_invalid", f"a discards line follows the answer it marks, but request "
                                                        f"line {open_request[0]} has no answer before it")
            verifier.discard(number, record["discards"], just_answered)
            continue
        if record["dir"] == "req":
            if open_request is not None:
                verifier.raise_pending()
                verifier.unanswered(*open_request, None)
            verifier.request(number, envelope)
            open_request = (number, envelope)
            continue
        if open_request is None:
            raise _Fail(number, "order", "a response line with no unanswered request line before it")
        req_line, request = open_request
        open_request = None
        cause = record.get("cause")
        if envelope is None:
            if isinstance(cause, str) and cause:
                verifier.recorded_failure(req_line, request, cause)
            else:
                verifier.raise_pending()
                verifier.unanswered(req_line, request, cause)
        elif response_shape_problem(envelope) is not None and isinstance(cause, str) and cause:
            # The gateway writes any JSON object that is no JSON-RPC answer verbatim with the cause acs.client gave,
            # such as a 429's {"detail": ...}. Without a cause it is not a line the gateway writes, so it is read as
            # an answer and fails unsigned.
            if cause in NEVER_SENT_CAUSES:
                raise _Fail(number, "line_invalid", f"a body came back with the cause {cause}, which says the request "
                                                    "was never sent. A request that got a body was sent")
            verifier.recorded_failure(req_line, request, cause)
        else:
            if "cause" in record and cause != LATE_CAUSE:
                raise _Fail(number, "line_invalid", f"a JSON-RPC answer carries a cause only when it came back late, "
                                                    f"as {LATE_CAUSE}, not {cause!r}")
            step_answer = verifier.response(req_line, request, number, envelope)
            request_id = _params(request).get("request_id")
            if "cause" in record:
                # Late on arrival, so the gateway withheld it. The cause is the gateway's unsigned claim.
                report.discarded_lines.append(req_line)
            elif step_answer:
                answered = (req_line, request_id if isinstance(request_id, str) else None)
    if open_request is not None:
        verifier.raise_pending()
        verifier.unanswered(*open_request, None)
    if report.lines == 0:
        raise _Fail(1, "empty", "the transcript holds no lines")


def _read_secret(path: str) -> bytes:
    try:
        # The same owner-only, no-symlink rule every other reader of a secret file applies, checked on the
        # descriptor that reads it.
        secret = read_trusted_file(path, setting="--hmac-secret", max_bytes=MAX_SECRET_BYTES, mode_rule=owner_only,
                                   refused=UsageError).rstrip(b"\r\n\t ")
    except UsageError:
        raise
    except (OSError, RuntimeError) as exc:
        raise UsageError(f"--hmac-secret {path!r} can't be read: {exc}") from exc
    if len(secret) < MIN_SECRET_BYTES:
        raise UsageError(f"--hmac-secret {path!r} holds {len(secret)} bytes, under the {MIN_SECRET_BYTES} section "
                         "10 requires")
    return secret


def _read_key_document(path: str) -> Mapping[str, Any]:
    # The document decides which key verifies every decision, so it goes through the one reader for trusted files,
    # with the rule acs.client's load_response_keys applies to it: no symlink, no FIFO, no group or other write. It is
    # public and the Guardian owns it, so a verifier running as another user must still read it, and no owner is
    # checked. --expect-fingerprint covers an owner swap.
    data = read_trusted_file(path, setting="--keys", max_bytes=MAX_KEY_DOCUMENT_BYTES,
                             mode_rule=not_writable_by_others, refused=UsageError, require_owner=False)
    try:
        document = _strict_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise UsageError(f"--keys {path!r} can't be read as JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise UsageError(f"--keys {path!r} is not a JSON object")
    return document


def _read_transcript(path: str, max_bytes: int) -> list[bytes]:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError as exc:
        raise UsageError(f"the transcript {path!r} can't be read: {exc}") from exc
    if len(data) > max_bytes:
        raise UsageError(f"the transcript {path!r} is larger than {max_bytes} bytes. Raise --max-bytes to read it")
    # Lines are split on bytes, so a line that isn't UTF-8 fails at its own number instead of failing the file.
    return data.splitlines() if data else []


def _error(message: str, as_json: bool) -> int:
    if as_json:
        sys.stdout.write(json.dumps({"result": "error", "error": message}) + "\n")
    else:
        sys.stderr.write(f"acs-verify: {message}\n")
    return EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="acs-verify",
        description="Check a Guardian session transcript offline: the audit chain, every decision signature, the "
                    "request binding, and key validity. Exit 0 pass, 1 verification failure, 2 usage or "
                    "unreadable input. Lab conventions: issues #460, #576, #316.")
    parser.add_argument("transcript", help="the gateway's <session_id>.jsonl transcript")
    parser.add_argument("--keys", metavar="KEY_DOCUMENT",
                        help="the Guardian's acs-lab-keys/1 key document. Every response must verify under ML-DSA-65")
    parser.add_argument("--expect-fingerprint", action="append", default=[], metavar="FINGERPRINT",
                        help="the fingerprint the Guardian printed at startup. Every verifying key must match one")
    parser.add_argument("--key-id", help="accept only this key_id from the key document")
    parser.add_argument("--hmac-secret", metavar="FILE",
                        help="the shared HMAC secret file. Checks request signatures. Without --keys it also makes "
                             "HMAC-SHA256 the response algorithm")
    parser.add_argument("--keys-only", action="store_true", help="check signatures without the chain")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_TRANSCRIPT_BYTES,
                        help=f"refuse a transcript larger than this (default {DEFAULT_MAX_TRANSCRIPT_BYTES})")
    parser.add_argument("--json", action="store_true", help="print one JSON object instead of text")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_PASS if exc.code == 0 else EXIT_USAGE
    try:
        if args.max_bytes <= 0:
            raise UsageError("--max-bytes must be positive")
        if args.key_id is not None and args.keys is None:
            raise UsageError("--key-id needs --keys")
        document = _read_key_document(args.keys) if args.keys else None
        secret = _read_secret(args.hmac_secret) if args.hmac_secret else None
        lines = _read_transcript(args.transcript, args.max_bytes)
        report = verify_transcript(lines, key_document=document, hmac_secret=secret,
                                   expect_fingerprints=args.expect_fingerprint, key_id=args.key_id,
                                   keys_only=args.keys_only)
    except UsageError as exc:
        return _error(str(exc), args.json)
    except ImportError as exc:
        # The key document needs the pqc extra. Without it nothing can be checked, which is a setup problem.
        return _error(str(exc), args.json)
    if args.json:
        sys.stdout.write(json.dumps(report.to_json(), sort_keys=True) + "\n")
    else:
        sys.stdout.write(report.to_text() + "\n")
    return EXIT_PASS if report.ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
