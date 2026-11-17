"""Clean startup errors (fix round 2, CR2), one secret file reader (CR9), and one rule for reading a request (CR10)."""
import os

import pytest

from acs_gateway import cli


def run_main(monkeypatch, capsys, **env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    code = cli.main()
    return code, capsys.readouterr().err


def test_missing_recordings_exit_2_naming_the_directory(monkeypatch, capsys, tmp_path):
    missing = tmp_path / "no-recordings"
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(missing))
    assert code == 2
    assert str(missing) in err and "Traceback" not in err


def test_a_bad_recording_exits_2_naming_the_line(monkeypatch, capsys, tmp_path):
    (tmp_path / "rec").mkdir()
    (tmp_path / "rec" / "s1.jsonl").write_text("not json\n")
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"))
    assert code == 2
    assert "s1.jsonl:1" in err


def test_a_bad_key_file_exits_2_naming_the_file(monkeypatch, capsys, tmp_path):
    key = tmp_path / "keys" / "openai.key"
    key.parent.mkdir()
    key.write_text("sk-test-" + "k" * 40)
    key.chmod(0o644)
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM_KEY_FILE=str(key))
    assert code == 2
    assert str(key) in err and "sk-test-" not in err


def test_one_reader_serves_the_admin_token_and_the_model_key(tmp_path, monkeypatch):
    from acs_gateway import app, secretfile, upstream

    seen = []
    real = secretfile.load_secret_file

    def spy(path, name):
        seen.append(name)
        return real(path, name)

    monkeypatch.setattr(secretfile, "load_secret_file", spy)
    token = tmp_path / "admin.token"
    token.write_text("t" * 40)
    token.chmod(0o600)
    key = tmp_path / "openai.key"
    key.write_text("sk-" + "k" * 40)
    key.chmod(0o600)
    app.load_admin_token(token)
    upstream.read_key_file(key)
    assert seen == ["ACS_GATEWAY_ADMIN_TOKEN_FILE", "ACS_UPSTREAM_KEY_FILE"]


def test_a_fifo_key_file_is_refused(tmp_path):
    from acs_gateway.upstream import read_key_file

    fifo = tmp_path / "openai.key"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="regular file"):
        read_key_file(fifo)


def test_replay_reads_a_request_by_the_session_rules():
    from acs_gateway import app, sessions
    from acs_gateway.upstream import placeholder_map, replay_key

    body = {"input": [{"role": "developer", "content": [{"type": "input_text", "text": "You are FinBot."}]},
                      {"role": "user", "type": "message",
                       "content": [{"type": "input_text", "text": "Pay "}, {"type": "input_text", "text": "vendor 7"}]},
                      {"role": "user", "content": "Again"}]}
    system, first_user = sessions.conversation_parts(body)
    assert replay_key(body, placeholder_map(body))[:2] == (first_user, 2)
    assert app.is_stream is sessions.is_stream
