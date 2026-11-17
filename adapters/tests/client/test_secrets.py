"""The secret file check must fail closed on every platform.

Windows has no owner/group/other bits (stat() reports 0o666 for ordinary files), so the POSIX
0600 rule cannot be evaluated there. The equivalent control is the NTFS ACL, which stat() does
not expose, so the check refuses by default and needs an explicit, logged opt-in to skip.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from acs.client import _secrets
from acs.client._secrets import SecretFilePermissionsError


def _fake_stat(mode: int, uid: int = 0):
    def _stat(_path):
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    return _stat


@pytest.fixture
def key_file(tmp_path):
    p = tmp_path / "hmac.key"
    p.write_text("a" * 64)
    return str(p)


def test_windows_refuses_without_opt_in(monkeypatch, key_file):
    monkeypatch.setattr(_secrets, "_IS_WINDOWS", True)
    monkeypatch.delenv(_secrets._ALLOW_UNCHECKED_ENV, raising=False)
    with pytest.raises(SecretFilePermissionsError) as err:
        _secrets._check_secret_file_perms(key_file)
    assert _secrets._ALLOW_UNCHECKED_ENV in str(err.value)


def test_windows_opt_in_warns_but_proceeds(monkeypatch, key_file, capsys):
    monkeypatch.setattr(_secrets, "_IS_WINDOWS", True)
    monkeypatch.setenv(_secrets._ALLOW_UNCHECKED_ENV, "1")
    _secrets._check_secret_file_perms(key_file)
    assert "WARNING" in capsys.readouterr().err


def test_posix_still_refuses_group_or_other_access(monkeypatch, key_file):
    monkeypatch.setattr(_secrets, "_IS_WINDOWS", False)
    monkeypatch.setattr(_secrets.os.path, "islink", lambda _p: False)
    monkeypatch.setattr(_secrets.os, "stat", _fake_stat(0o100644))
    with pytest.raises(SecretFilePermissionsError) as err:
        _secrets._check_secret_file_perms(key_file)
    assert "too permissive" in str(err.value)


@pytest.mark.parametrize("mode", [0o100600, 0o100400])
def test_posix_owner_only_modes_pass(monkeypatch, key_file, mode):
    monkeypatch.setattr(_secrets, "_IS_WINDOWS", False)
    monkeypatch.setattr(_secrets.os.path, "islink", lambda _p: False)
    uid = getattr(os, "geteuid", lambda: 0)()
    monkeypatch.setattr(_secrets.os, "stat", _fake_stat(mode, uid))
    _secrets._check_secret_file_perms(key_file)


def test_symlink_is_refused(monkeypatch, key_file):
    monkeypatch.setattr(_secrets.os.path, "islink", lambda _p: True)
    with pytest.raises(SecretFilePermissionsError) as err:
        _secrets._check_secret_file_perms(key_file)
    assert "symlink" in str(err.value)


def test_the_setting_name_appears_in_the_message(monkeypatch, key_file):
    # The Guardian checks its ML-DSA-65 key file with the same rule, under its own setting name (issue #576).
    from acs.client import check_secret_file_perms
    monkeypatch.setattr(_secrets, "_IS_WINDOWS", False)
    monkeypatch.setattr(_secrets.os.path, "islink", lambda _p: False)
    monkeypatch.setattr(_secrets.os, "stat", _fake_stat(0o100644))
    with pytest.raises(SecretFilePermissionsError) as named:
        check_secret_file_perms(key_file, setting="ACS_GUARDIAN_SIGNING_KEY_FILE")
    assert str(named.value).startswith(f"ACS_GUARDIAN_SIGNING_KEY_FILE {key_file!r} mode 0o644")
    with pytest.raises(SecretFilePermissionsError) as default:
        _secrets._check_secret_file_perms(key_file)
    assert str(default.value) == (f"ACS_HMAC_SECRET_FILE {key_file!r} mode 0o644 is too permissive; "
                                  f"must be 0600 or 0400 (no group/other access). Fix: chmod 600 {key_file}")
