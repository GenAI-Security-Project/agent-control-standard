"""Upstream mode configuration and the model key file (issue #579)."""
from pathlib import Path

import pytest

from acs_gateway.config import GatewayConfig

KEY = "sk-test-" + "k" * 40


def config(tmp_path, **env):
    return GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), **env})


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


@pytest.mark.parametrize("scenario", ["", "../x", "a/b", "-x", "x" * 65])
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
