"""The Guardian's ML-DSA-65 decision key: written owner-only, loaded only when it matches its key document (issue #576)."""
from __future__ import annotations

import datetime
import json
import os
import re
import stat

import pytest

from decision_signing_helpers import require_pqc

require_pqc()

from acs.core import MLDSA65SigningKey  # noqa: E402
from acs.guardian import decision_keys  # noqa: E402
from acs.guardian.decision_keys import (  # noqa: E402
    DecisionKeyError,
    load_decision_signer,
    load_signing_key,
    write_key_files,
)

UTC = datetime.timezone.utc
KEY_ID = "lab-guardian-1"


@pytest.fixture
def files(tmp_path):
    key_path, doc_path = write_key_files(tmp_path, key_id=KEY_ID, guardian_id="lab-guardian")
    return key_path, doc_path


def _env(key_path, doc_path, **extra: str) -> dict[str, str]:
    return {"ACS_GUARDIAN_SIGNING_KEY_FILE": str(key_path), "ACS_GUARDIAN_KEY_ID": KEY_ID,
            "ACS_GUARDIAN_KEYS": str(doc_path), **extra}


def test_write_key_files_makes_an_owner_only_seed(files):
    key_path, doc_path = files
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    text = key_path.read_text()
    assert re.fullmatch(r"[0-9a-f]{64}\n", text)
    fingerprint = MLDSA65SigningKey.from_seed(bytes.fromhex(text.strip()), KEY_ID).verification_key().fingerprint
    document = json.loads(doc_path.read_text())
    assert document["format"] == "acs-lab-keys/1"
    assert document["revoked"] == []
    assert document["keys"][0]["fingerprint"] == fingerprint


def test_write_key_files_sets_a_90_day_window(tmp_path):
    now = datetime.datetime(2026, 12, 9, 12, 0, 0, tzinfo=UTC)
    _, doc_path = write_key_files(tmp_path, key_id=KEY_ID, guardian_id="lab-guardian", now=now)
    entry = json.loads(doc_path.read_text())["keys"][0]
    assert entry["not_before"] == "2026-12-09T12:00:00Z"
    assert entry["not_after"] == "2027-03-09T12:00:00Z"


def test_write_key_files_never_overwrites(files, tmp_path):
    with pytest.raises(FileExistsError):
        write_key_files(tmp_path, key_id=KEY_ID, guardian_id="lab-guardian")


def test_load_signing_key_refuses_loose_modes(files):
    key_path, _ = files
    os.chmod(key_path, 0o644)
    with pytest.raises(DecisionKeyError, match="ACS_GUARDIAN_SIGNING_KEY_FILE"):
        load_signing_key(str(key_path), KEY_ID)


def test_load_signing_key_refuses_a_symlink(files, tmp_path):
    key_path, _ = files
    link = tmp_path / "linked.key"
    link.symlink_to(key_path)
    with pytest.raises(DecisionKeyError, match="ACS_GUARDIAN_SIGNING_KEY_FILE"):
        load_signing_key(str(link), KEY_ID)


@pytest.mark.parametrize("content", [b"a" * 63 + b"\n", b"z" * 64 + b"\n", os.urandom(32), b""],
                         ids=["63 characters", "non-hex", "32 raw bytes", "empty"])
def test_load_signing_key_refuses_bad_hex(tmp_path, content):
    path = tmp_path / "bad.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    with pytest.raises(DecisionKeyError, match="ACS_GUARDIAN_SIGNING_KEY_FILE"):
        load_signing_key(str(path), KEY_ID)


def test_load_signing_key_refuses_a_missing_file(tmp_path):
    with pytest.raises(DecisionKeyError, match="ACS_GUARDIAN_SIGNING_KEY_FILE"):
        load_signing_key(str(tmp_path / "absent.key"), KEY_ID)


@pytest.mark.parametrize("name", ["ACS_GUARDIAN_SIGNING_KEY_FILE", "ACS_GUARDIAN_KEY_ID", "ACS_GUARDIAN_KEYS"])
def test_each_setting_is_required(files, name):
    env = _env(*files)
    env[name] = "  "
    with pytest.raises(DecisionKeyError, match=name):
        load_decision_signer(env)
    del env[name]
    with pytest.raises(DecisionKeyError, match=name):
        load_decision_signer(env)


def test_a_seed_missing_from_the_document_refuses(files):
    key_path, doc_path = files
    os.chmod(key_path, 0o600)
    key_path.unlink()
    fresh = MLDSA65SigningKey.generate(KEY_ID)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(fresh.seed().hex() + "\n")
    with pytest.raises(DecisionKeyError, match="fingerprint"):
        load_decision_signer(_env(key_path, doc_path))


def test_an_expired_or_revoked_key_refuses(files):
    key_path, doc_path = files
    later = datetime.datetime.now(UTC) + datetime.timedelta(days=91)
    with pytest.raises(DecisionKeyError):
        load_decision_signer(_env(key_path, doc_path), now=later)
    document = json.loads(doc_path.read_text())
    document["revoked"] = [{"key_id": KEY_ID, "revoked_at": document["keys"][0]["not_before"]}]
    doc_path.write_text(json.dumps(document))
    with pytest.raises(DecisionKeyError):
        load_decision_signer(_env(key_path, doc_path))


def test_load_decision_signer_pins_its_own_key_id(tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    key_path, doc_path = write_key_files(first, key_id=KEY_ID, guardian_id="lab-guardian")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    _, other_doc = write_key_files(other_dir, key_id="lab-guardian-2", guardian_id="lab-guardian")
    document = json.loads(doc_path.read_text())
    document["keys"] += json.loads(other_doc.read_text())["keys"]
    doc_path.write_text(json.dumps(document))
    signer = load_decision_signer(_env(key_path, doc_path))
    assert signer.keys.key_id == KEY_ID
    assert signer.keys.keyring.key_ids == (KEY_ID,)
    assert signer.signing_key.key_id == KEY_ID
    assert signer.fingerprint == signer.signing_key.verification_key().fingerprint
    with pytest.raises(DecisionKeyError):
        load_decision_signer(_env(key_path, doc_path, ACS_GUARDIAN_KEY_ID="lab-guardian-2"))


def test_main_writes_both_files_and_prints_the_fingerprint(tmp_path, capsys):
    assert decision_keys.main(["--out-dir", str(tmp_path), "--key-id", KEY_ID,
                               "--guardian-id", "lab-guardian", "--days", "30"]) == 0
    out = capsys.readouterr().out
    document = json.loads((tmp_path / "guardian-keys.json").read_text())
    assert f"fingerprint={document['keys'][0]['fingerprint']}" in out
    assert str(tmp_path / "guardian.key") in out
    assert str(tmp_path / "guardian-keys.json") in out
    assert decision_keys.main(["--out-dir", str(tmp_path), "--key-id", KEY_ID,
                               "--guardian-id", "lab-guardian"]) == 1


@pytest.mark.parametrize("kwargs", [{"guardian_id": ""}, {"guardian_id": "   "}, {"days": 0}, {"days": -1},
                                    {"days": 3651}, {"days": 10**12}],
                         ids=["empty guardian id", "blank guardian id", "zero days", "negative days",
                              "past the cap", "overflow"])
def test_write_key_files_validates_before_writing(tmp_path, kwargs):
    # Review CR7: refused with ValueError and nothing written, never an empty id or an OverflowError traceback.
    with pytest.raises(ValueError):
        write_key_files(tmp_path, **{"key_id": KEY_ID, "guardian_id": "lab-guardian", **kwargs})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("args", [["--guardian-id", ""], ["--guardian-id", "g", "--days", "99999999999"],
                                  ["--guardian-id", "g", "--days", "0"]])
def test_main_refuses_bad_arguments_without_writing(tmp_path, capsys, args):
    assert decision_keys.main(["--out-dir", str(tmp_path), "--key-id", KEY_ID, *args]) == 1
    assert list(tmp_path.iterdir()) == []
    assert "decision_keys:" in capsys.readouterr().err


def test_a_fifo_at_the_key_path_is_refused_without_blocking(tmp_path):
    # Review CR3-2: the seed goes through the one reader, which opens with O_NONBLOCK.
    fifo = tmp_path / "guardian.key"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(DecisionKeyError, match="regular file"):
        load_signing_key(str(fifo), KEY_ID)


def test_a_key_in_a_directory_others_can_write_is_refused(files):
    key_path, _ = files
    os.chmod(key_path.parent, 0o770)
    try:
        with pytest.raises(DecisionKeyError, match="writable by group or other"):
            load_signing_key(str(key_path), KEY_ID)
    finally:
        os.chmod(key_path.parent, 0o700)
