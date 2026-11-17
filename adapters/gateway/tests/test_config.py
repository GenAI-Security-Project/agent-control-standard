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


@pytest.mark.parametrize("name", ["ACS_GATEWAY_WORKERS", "ACS_GATEWAY_MAX_SESSIONS", "ACS_GATEWAY_MAX_BODY_BYTES"])
@pytest.mark.parametrize("value", ["0.5", "1.5", "0", "-3", "ten", "1e3"])
def test_integer_settings_refuse_anything_but_a_whole_number_of_at_least_one(tmp_path, name, value):
    with pytest.raises(ValueError, match=name):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), name: value})


def test_integer_settings_read_whole_numbers(tmp_path):
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_WORKERS": "3",
                                     "ACS_GATEWAY_MAX_SESSIONS": "7", "ACS_GATEWAY_MAX_BODY_BYTES": "1024"})
    assert (config.workers, config.max_sessions, config.max_body_bytes) == (3, 7, 1024)


@pytest.mark.parametrize("value", ["١٢", "８", "8e6"])
def test_integer_settings_take_plain_ascii_digits_only(tmp_path, value):
    with pytest.raises(ValueError, match="ACS_GATEWAY_WORKERS must be plain ASCII digits"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_WORKERS": value})


def test_the_stream_idle_timeout_defaults_to_60_seconds_and_reads_seconds(tmp_path):
    assert GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path)}).stream_idle_timeout_s == 60.0
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path),
                                     "ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S": "2.5"})
    assert config.stream_idle_timeout_s == 2.5
    with pytest.raises(ValueError, match="ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S": "0"})


def test_the_stream_deadline_defaults_to_600_seconds(tmp_path):
    assert GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path)}).stream_deadline_s == 600.0
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_STREAM_DEADLINE_S": "30"})
    assert config.stream_deadline_s == 30.0


def test_approver_is_off_by_default_and_binds_loopback(tmp_path):
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path)})
    assert config.approver_port is None
    assert config.approver_host == "127.0.0.1"
    assert config.ask_max_s == 240.0


def test_approver_port_and_ask_cap_are_read(tmp_path):
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_APPROVER_PORT": "8090",
                                     "ACS_GATEWAY_ASK_MAX_S": "0.5"})
    assert config.approver_port == 8090
    assert config.ask_max_s == 0.5


def test_ask_cap_above_240_seconds_is_refused(tmp_path):
    # FinBot's LLM_TIMEOUT is 360 s, so a hold longer than 240 s would outlive the client's own wait (A.3).
    with pytest.raises(ValueError, match="ACS_GATEWAY_ASK_MAX_S"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_GATEWAY_ASK_MAX_S": "241"})
