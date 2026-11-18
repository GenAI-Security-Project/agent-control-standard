"""The CLI's configuration rules, where #118's key_id requirement lands."""

from __future__ import annotations

import argparse

import pytest

from acs_guardian import main as cli
from helpers import KEY_ID, SECRET


def _args(tmp_path, *, key_id=None):
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(SECRET)
    return argparse.Namespace(
        secret_file=str(secret_file),
        key_id=key_id,
        posture=None,
        timeout_ms=5000,
        skew_window_ms=300_000,
        require_provenance=False,
        spec_root=None,
        host=None,
        port=None,
    )


def test_serve_requires_a_key_id(monkeypatch, tmp_path) -> None:
    """#118: key_id comes from config, with no default."""
    monkeypatch.delenv("ACS_GUARDIAN_KEY_ID", raising=False)
    with pytest.raises(SystemExit) as caught:
        cli._build_config(_args(tmp_path))
    assert "key_id" in str(caught.value)


def test_the_configured_key_id_reaches_the_config(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("ACS_GUARDIAN_KEY_ID", raising=False)
    config = cli._build_config(_args(tmp_path, key_id="2026-10"))
    assert config.key_id == "2026-10"


def test_the_environment_supplies_the_key_id(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ACS_GUARDIAN_KEY_ID", KEY_ID)
    config = cli._build_config(_args(tmp_path))
    assert config.key_id == KEY_ID
