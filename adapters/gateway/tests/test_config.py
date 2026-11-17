from pathlib import Path

import pytest

from acs_gateway.config import GatewayConfig, prepare_state_dirs


def test_unset_mode_is_off(tmp_path):
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path)})
    assert config.mode == "off"


def test_unknown_mode_is_refused(tmp_path):
    with pytest.raises(ValueError, match="ACS_LAB_MODE"):
        GatewayConfig.from_env({"ACS_LAB_MODE": "loud", "ACS_GATEWAY_STATE_DIR": str(tmp_path)})


def test_decision_timeout_reads_milliseconds(tmp_path):
    config = GatewayConfig.from_env({"ACS_DECISION_TIMEOUT_MS": "500", "ACS_GATEWAY_STATE_DIR": str(tmp_path)})
    assert config.decision_timeout_s == 0.5


def test_transcript_dir_defaults_under_state_dir(tmp_path):
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path)})
    assert config.transcript_dir == tmp_path / "transcripts"


def test_prepare_state_dirs_points_acs_client_at_gateway_state(tmp_path):
    env = {"ACS_GATEWAY_STATE_DIR": str(tmp_path)}
    prepare_state_dirs(env)
    assert env["ACS_SESSION_STATE_DIR"] == str(tmp_path / "sessions")
    assert env["ACS_HANDSHAKE_CACHE"] == str(tmp_path / "handshakes")


def test_prepare_state_dirs_refuses_the_home_directory(tmp_path):
    env = {"ACS_GATEWAY_STATE_DIR": str(tmp_path),
           "ACS_HANDSHAKE_CACHE": str(Path.home() / ".cache" / "acs-adapter-handshake")}
    with pytest.raises(ValueError, match="home"):
        prepare_state_dirs(env)


def test_prepare_state_dirs_without_a_state_dir_uses_a_private_temp_dir():
    env: dict[str, str] = {}
    state = prepare_state_dirs(env)
    assert state.name.startswith("acs-gateway-")
    assert env["ACS_GATEWAY_STATE_DIR"] == str(state)
    assert (state.stat().st_mode & 0o777) == 0o700
