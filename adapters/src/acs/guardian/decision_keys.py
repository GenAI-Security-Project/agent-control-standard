"""The example Guardian's ML-DSA-65 decision key: written owner-only, loaded only when its key document vouches for it.

Lab convention until issue #460 settles key publication. The key file holds the 32 byte FIPS 204 seed as 64
lowercase hex characters and a newline, mode 0600, and is mounted only into the Guardian. The key document
(acs-lab-keys/1, see acs.client._key_document) is public and is what GET /keys serves.

    python -m acs.guardian.decision_keys --out-dir DIR --key-id ID --guardian-id GID [--days N]

writes DIR/guardian.key and DIR/guardian-keys.json (creating DIR as 0700 if missing) and prints the fingerprint an
operator compares out of band, then the three settings to export: the key file, the key id, and the key document.
It never overwrites either file. This module needs the pqc extra, and the example Guardian imports it only when
ACS_RESPONSE_SIGNING=ML-DSA-65.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from acs.client import KeyDocumentError, ResponseKeys, load_response_keys, owner_only, read_trusted_file
from acs.client._key_document import KEY_DOCUMENT_ENV, KEY_ID_ENV, SIGNING_KEY_FILE_ENV, utcnow
from acs.core import MLDSA65SigningKey

DEFAULT_VALIDITY_DAYS = 90
# Ten years. A lab key lives 90 days, and the cap keeps not_after far inside what datetime can represent.
MAX_VALIDITY_DAYS = 3650
KEY_FILE_NAME = "guardian.key"
KEY_DOCUMENT_NAME = "guardian-keys.json"
_SEED_HEX = re.compile(r"[0-9a-f]{64}\n?")


class DecisionKeyError(RuntimeError):
    """The decision key or its key document can't be used, so the Guardian must not start."""


@dataclass(frozen=True)
class DecisionSigner:
    """The key the Guardian signs every response with, and the key document pinned to it."""

    signing_key: MLDSA65SigningKey
    keys: ResponseKeys

    @property
    def fingerprint(self) -> str:
        return self.keys.fingerprint


def _stamp(moment: datetime.datetime) -> str:
    # RFC 3339 UTC with a Z suffix, the form acs.client's key document parser requires.
    return moment.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def key_document(signing_key: MLDSA65SigningKey, *, guardian_id: str, not_before: datetime.datetime,
                 not_after: datetime.datetime) -> dict:
    """The acs-lab-keys/1 document that publishes one signing key."""
    verification_key = signing_key.verification_key()
    return {"format": "acs-lab-keys/1", "guardian_id": guardian_id,
            "keys": [{"key_id": signing_key.key_id, "algorithm": signing_key.algorithm,
                      "public_key": base64.b64encode(verification_key.public_key).decode("ascii"),
                      "fingerprint": verification_key.fingerprint,
                      "not_before": _stamp(not_before), "not_after": _stamp(not_after)}],
            "revoked": []}


def _write_new(path: Path, data: bytes, mode: int) -> None:
    # O_EXCL: a second run fails instead of replacing a key that a published document already names.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def write_key_files(directory: Path, *, key_id: str, guardian_id: str, now: datetime.datetime | None = None,
                    days: int = DEFAULT_VALIDITY_DAYS) -> tuple[Path, Path]:
    """Generate a key and write its seed (0600) and its key document (0644). Raises FileExistsError for either.

    A missing directory is created with mode 0700.

    Every argument is checked before anything is written, so a bad one leaves no file behind (review CR7).
    """
    if not isinstance(guardian_id, str) or not guardian_id.strip():
        raise ValueError("guardian_id must be a non-empty string")
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"days must be a whole number from 1 to {MAX_VALIDITY_DAYS}, got {days!r}")
    directory = Path(directory)
    key_path, doc_path = directory / KEY_FILE_NAME, directory / KEY_DOCUMENT_NAME
    if key_path.exists() or doc_path.exists():
        raise FileExistsError(f"{key_path if key_path.exists() else doc_path} already exists")
    start = (now or utcnow()).replace(microsecond=0)
    signing_key = MLDSA65SigningKey.generate(key_id)
    document = key_document(signing_key, guardian_id=guardian_id, not_before=start,
                            not_after=start + datetime.timedelta(days=days))
    if not directory.exists():
        # A directory this run creates holds a private key, so it is owner-only whatever the umask says. Missing
        # parents keep the default mode. An existing directory is the operator's and is never chmodded.
        directory.parent.mkdir(parents=True, exist_ok=True)
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    _write_new(key_path, (signing_key.seed().hex() + "\n").encode("ascii"), 0o600)
    _write_new(doc_path, (json.dumps(document, indent=2) + "\n").encode("utf-8"), 0o644)
    return key_path, doc_path


def load_signing_key(path: str, key_id: str) -> MLDSA65SigningKey:
    """The signing key in an owner-only, non-symlink seed file. Every refusal names ACS_GUARDIAN_SIGNING_KEY_FILE."""
    # The one reader every secret goes through: opened once, never through a symlink or a FIFO, and checked through
    # that descriptor (reviews R-M2, CR3-2).
    # The cap leaves room past the 65 valid bytes, so a seed with a CRLF ending reaches the content checks and is
    # refused for its line ending, not for its size (final review M1).
    raw = read_trusted_file(path, setting=SIGNING_KEY_FILE_ENV, max_bytes=128, mode_rule=owner_only,
                            refused=DecisionKeyError)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    if "\r" in text:
        raise DecisionKeyError(f"{SIGNING_KEY_FILE_ENV} {path!r} has a CRLF line ending. It must hold 64 lowercase "
                               "hex characters and at most one LF. Fix: remove the carriage return, as with "
                               f"dos2unix {path}")
    if not _SEED_HEX.fullmatch(text):
        # The content is the private key, so no part of it reaches the message.
        raise DecisionKeyError(f"{SIGNING_KEY_FILE_ENV} {path!r} must hold 64 lowercase hex characters, "
                               "the 32 byte ML-DSA-65 seed")
    return MLDSA65SigningKey.from_seed(bytes.fromhex(text.strip()), key_id)


def load_decision_signer(env: Mapping[str, str], *, now: datetime.datetime | None = None) -> DecisionSigner:
    """The signer the Guardian starts with, refused unless the seed's key is the live key its document names."""
    settings = {}
    for name in (SIGNING_KEY_FILE_ENV, KEY_ID_ENV, KEY_DOCUMENT_ENV):
        value = env.get(name, "").strip()
        if not value:
            raise DecisionKeyError(f"{name} is not set. ACS_RESPONSE_SIGNING=ML-DSA-65 needs "
                                   f"{SIGNING_KEY_FILE_ENV}, {KEY_ID_ENV} and {KEY_DOCUMENT_ENV}")
        settings[name] = value
    key_id = settings[KEY_ID_ENV]
    signing_key = load_signing_key(settings[SIGNING_KEY_FILE_ENV], key_id)
    # The seed's own fingerprint is the pin. A regenerated seed beside a stale document would sign responses no client
    # can verify, so the pin refuses that, and a pinned document needs no owner check, so a document another user
    # owns, as in a container layout, never stops the Guardian (final review round 2 R3b).
    fingerprint = signing_key.verification_key().fingerprint
    try:
        keys = load_response_keys(settings[KEY_DOCUMENT_ENV], key_id=key_id, now=now, fingerprint=fingerprint)
    except KeyDocumentError as exc:
        raise DecisionKeyError(f"{exc}. The Guardian pins {KEY_DOCUMENT_ENV} to the key in {SIGNING_KEY_FILE_ENV}, "
                               f"fingerprint {fingerprint}") from exc
    return DecisionSigner(signing_key=signing_key, keys=keys)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m acs.guardian.decision_keys",
                                     description="Write the example Guardian's ML-DSA-65 decision key and its "
                                                 "key document (lab convention, issue #460).")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--guardian-id", required=True)
    parser.add_argument("--days", type=int, default=DEFAULT_VALIDITY_DAYS)
    args = parser.parse_args(argv)
    try:
        key_path, doc_path = write_key_files(args.out_dir, key_id=args.key_id, guardian_id=args.guardian_id,
                                             days=args.days)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"decision_keys: {exc}\n")
        return 1
    document = json.loads(doc_path.read_text(encoding="utf-8"))
    sys.stdout.write(f"fingerprint={document['keys'][0]['fingerprint']}\n"
                     f"{SIGNING_KEY_FILE_ENV}={key_path}\n{KEY_ID_ENV}={args.key_id}\n"
                     f"{KEY_DOCUMENT_ENV}={doc_path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
