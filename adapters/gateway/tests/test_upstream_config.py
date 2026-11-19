"""Upstream mode configuration and the model key file (issue #579)."""
from pathlib import Path

import pytest

from acs_gateway.config import GatewayConfig

KEY = "sk-test-" + "k" * 40


def config(tmp_path, **env):
    return GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), **env})


# A key file needs the model port's client token (final review R8). Config records only the path.
TOKEN_ENV = {"ACS_GATEWAY_CLIENT_TOKEN_FILE": "/run/acs/client.token"}


def key_file(tmp_path: Path, text: str = KEY, mode: int = 0o600) -> Path:
    path = tmp_path / "keys" / "openai.key"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text + "\n")
    path.chmod(mode)
    return path


def test_unset_upstream_is_live_with_nothing_else(tmp_path):
    c = config(tmp_path)
    assert (c.upstream_mode, c.upstream_key_file, c.recordings_dir, c.capture_scenario) == ("live", None, None, "capture")


def test_openai_is_live_and_capture_flag_makes_capture(tmp_path):
    assert config(tmp_path, ACS_UPSTREAM="openai").upstream_mode == "live"
    c = config(tmp_path, ACS_UPSTREAM="openai", ACS_CAPTURE="1", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    assert c.upstream_mode == "capture"
    assert c.recordings_dir == tmp_path / "rec"


def test_unknown_upstream_is_refused(tmp_path):
    with pytest.raises(ValueError, match="ACS_UPSTREAM"):
        config(tmp_path, ACS_UPSTREAM="ollama")


@pytest.mark.parametrize("mode", ["capture", "replay"])
def test_capture_and_replay_need_a_recordings_dir(tmp_path, mode):
    with pytest.raises(ValueError, match="ACS_RECORDINGS_DIR"):
        config(tmp_path, ACS_UPSTREAM=mode)


def test_replay_refuses_the_capture_flag_and_a_key(tmp_path):
    rec = str(tmp_path / "rec")
    with pytest.raises(ValueError, match="ACS_CAPTURE"):
        config(tmp_path, ACS_UPSTREAM="replay", ACS_CAPTURE="1", ACS_RECORDINGS_DIR=rec)
    with pytest.raises(ValueError, match="ACS_UPSTREAM_KEY_FILE"):
        config(tmp_path, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=rec, ACS_UPSTREAM_KEY_FILE="/run/acs/openai.key")


@pytest.mark.parametrize("scenario", ["../x", "a/b", "-x", "x" * 65])
def test_a_bad_scenario_name_is_refused(tmp_path, scenario):
    with pytest.raises(ValueError, match="ACS_CAPTURE_SCENARIO"):
        config(tmp_path, ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path), ACS_CAPTURE_SCENARIO=scenario)


def test_a_good_key_file_is_read_and_stripped(tmp_path):
    from acs_gateway.upstream import read_key_file

    assert read_key_file(key_file(tmp_path)) == KEY


@pytest.mark.parametrize("problem", ["mode", "symlink", "empty", "spaces", "in_repo", "missing"])
def test_a_bad_key_file_is_refused_without_showing_the_key(tmp_path, problem):
    from acs_gateway.upstream import read_key_file

    path = key_file(tmp_path)
    if problem == "mode":
        path.chmod(0o644)
    elif problem == "symlink":
        link = tmp_path / "link.key"
        link.symlink_to(path)
        path = link
    elif problem == "empty":
        path.write_text("\n")
    elif problem == "spaces":
        path.write_text(KEY + " second\n")
    elif problem == "in_repo":
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / "secrets").mkdir()
        path = key_file(repo / "secrets")
    elif problem == "missing":
        path = tmp_path / "nope.key"
    with pytest.raises(ValueError, match="ACS_UPSTREAM_KEY_FILE") as raised:
        read_key_file(path)
    assert KEY not in str(raised.value)


@pytest.mark.parametrize("mode", ["live", "replay"])
def test_an_empty_or_odd_scenario_matters_only_to_capture(tmp_path, mode):
    rec = str(tmp_path)
    for scenario in ("", "../x"):
        c = config(tmp_path, ACS_UPSTREAM=mode, ACS_RECORDINGS_DIR=rec, ACS_CAPTURE_SCENARIO=scenario)
        assert c.upstream_mode == mode


def test_an_empty_scenario_means_the_default_in_capture(tmp_path):
    c = config(tmp_path, ACS_UPSTREAM="capture", ACS_RECORDINGS_DIR=str(tmp_path), ACS_CAPTURE_SCENARIO="  ")
    assert c.capture_scenario == "capture"


def test_replay_scenario_is_read_and_checked_only_in_replay(tmp_path):
    rec = str(tmp_path)
    assert config(tmp_path, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=rec).replay_scenario is None
    assert config(tmp_path, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=rec,
                  ACS_REPLAY_SCENARIO="s2").replay_scenario == "s2"
    with pytest.raises(ValueError, match="ACS_REPLAY_SCENARIO"):
        config(tmp_path, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=rec, ACS_REPLAY_SCENARIO="../s2")
    assert config(tmp_path, ACS_REPLAY_SCENARIO="../s2").upstream_mode == "live"


def test_capture_off_contradicting_capture_mode_is_refused(tmp_path):
    """Final review M-1: ACS_CAPTURE=0 says do not capture, so ACS_UPSTREAM=capture with it is a contradiction."""
    with pytest.raises(ValueError, match="ACS_CAPTURE=0"):
        config(tmp_path, ACS_UPSTREAM="capture", ACS_CAPTURE="0", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    assert config(tmp_path, ACS_UPSTREAM="live", ACS_CAPTURE="0").upstream_mode == "live"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20", "gateway.lab"])
def test_a_key_file_refuses_a_model_port_off_loopback(tmp_path, host):
    """Security scan F1 and F2: the model port takes no client credential, so with a key file anyone who reaches it
    spends the operator's key. The key file is allowed only on a loopback listener."""
    with pytest.raises(ValueError, match="ACS_GATEWAY_HOST"):
        config(tmp_path, ACS_UPSTREAM_KEY_FILE=str(key_file(tmp_path)), ACS_GATEWAY_HOST=host)


@pytest.mark.parametrize("host", ["", "127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_a_key_file_is_accepted_on_a_loopback_model_port(tmp_path, host):
    assert config(tmp_path, ACS_UPSTREAM_KEY_FILE=str(key_file(tmp_path)), ACS_GATEWAY_HOST=host,
                  **TOKEN_ENV).upstream_key_file


def test_a_model_port_off_loopback_without_a_key_file_is_unchanged(tmp_path):
    assert config(tmp_path, ACS_GATEWAY_HOST="0.0.0.0").listen_host == "0.0.0.0"


def test_the_shared_key_opt_in_allows_a_model_port_off_loopback(tmp_path):
    """Round 2, R4b: the lab bundle binds 0.0.0.0 on a container network that only the lab's containers and the host
    itself can reach, so an explicit ACS_UPSTREAM_KEY_SHARED=1 lifts the loopback rule. Without it the refusal
    stands."""
    path = str(key_file(tmp_path))
    with pytest.raises(ValueError, match="ACS_UPSTREAM_KEY_SHARED"):
        config(tmp_path, ACS_UPSTREAM_KEY_FILE=path, ACS_GATEWAY_HOST="0.0.0.0")
    with pytest.raises(ValueError, match="ACS_GATEWAY_HOST"):
        config(tmp_path, ACS_UPSTREAM_KEY_FILE=path, ACS_GATEWAY_HOST="0.0.0.0", ACS_UPSTREAM_KEY_SHARED="0")
    c = config(tmp_path, ACS_UPSTREAM_KEY_FILE=path, ACS_GATEWAY_HOST="0.0.0.0", ACS_UPSTREAM_KEY_SHARED="1", **TOKEN_ENV)
    assert (c.listen_host, c.upstream_key_shared) == ("0.0.0.0", True)


@pytest.mark.parametrize("value", ["yes", "true", "2"])
def test_the_shared_key_opt_in_takes_only_0_or_1(tmp_path, value):
    with pytest.raises(ValueError, match="ACS_UPSTREAM_KEY_SHARED must be 0 or 1"):
        config(tmp_path, ACS_UPSTREAM_KEY_SHARED=value)


def test_a_shared_key_says_so_once_at_startup(tmp_path, capfd):
    from acs_gateway.upstream import UpstreamSource

    path = str(key_file(tmp_path))
    UpstreamSource(config(tmp_path, ACS_UPSTREAM_KEY_FILE=path, ACS_GATEWAY_HOST="0.0.0.0",
                          ACS_UPSTREAM_KEY_SHARED="1", **TOKEN_ENV))
    err = capfd.readouterr().err
    assert err.count("\n") == 1
    assert "every client that can reach the model port" in err and KEY not in err
    UpstreamSource(config(tmp_path, ACS_UPSTREAM_KEY_FILE=path, **TOKEN_ENV))
    assert capfd.readouterr().err == ""
