"""The containerized lab CLI (issue #588, LAB-15), run against a temporary bundle with the standard library only.

The Guardian key generator needs the adapters with the pqc extra, which the CI runner for this suite doesn't have, so
it is stubbed here with a script that prints what acs.guardian.decision_keys prints. The image tests run the real one.
Run from the repository root: python3 -m pytest labs/finbot/cli/tests/test_cli.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1]
LAB_PY = CLI / "lab.py"
sys.path.insert(0, str(CLI))

import commands  # noqa: E402
import report  # noqa: E402

# Prints the lines decision_keys prints and writes the two files it writes, so init runs end to end without pqc.
STUB = """
import json, os, sys
args = sys.argv[1:]
out = args[args.index("--out-dir") + 1]
os.makedirs(out, mode=0o700)
fd = os.open(os.path.join(out, "guardian.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, b"%s\\n" % (b"ab" * 32)); os.close(fd)
with open(os.path.join(out, "guardian-keys.json"), "w") as f:
    json.dump({"format": "acs-lab-keys/1", "keys": [{"fingerprint": "sha256:" + "cd" * 32}]}, f)
print("fingerprint=sha256:" + "cd" * 32)
print("ACS_GUARDIAN_SIGNING_KEY_FILE=" + os.path.join(out, "guardian.key"))
"""


@pytest.fixture
def bundle(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    stub = tmp_path / "decision_keys_stub.py"
    stub.write_text(STUB, encoding="utf-8")
    monkeypatch.setenv("LAB_BUNDLE", str(root))
    monkeypatch.setattr(commands, "DECISION_KEYS", [sys.executable, str(stub)])
    return root


def lab(*args: str, capsys) -> tuple[int, str]:
    code = commands.dispatch(list(args))
    return code, capsys.readouterr().out


def env_file(root: Path) -> dict[str, str]:
    lines = (root / ".env").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_init_writes_owner_only_secrets(bundle, capsys):
    code, _ = lab("init", capsys=capsys)
    assert code == report.EXIT_PASS
    secrets = bundle / "state" / "secrets"
    for name in ("hmac.key", "guardian.key", "admin.token", "approver.token"):
        path = secrets / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, name
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o700
    # acs.client wants at least 32 bytes in the HMAC secret, and the gateway the same in the admin token.
    assert len((secrets / "hmac.key").read_text(encoding="utf-8").strip()) == 64
    assert len((secrets / "admin.token").read_text(encoding="utf-8").strip()) == 64
    assert (bundle / "state" / "keys" / "guardian-keys.json").is_file()
    for name in ("transcripts", "guardian", "verify"):
        assert (bundle / "state" / name).is_dir(), name
    assert (bundle / "replay" / "recordings").is_dir()
    assert not list(secrets.glob(".keygen*"))


def test_init_refuses_to_overwrite_keys(bundle, capsys):
    assert lab("init", capsys=capsys)[0] == 0
    before = (bundle / "state" / "secrets" / "hmac.key").read_bytes()
    code, out = lab("init", capsys=capsys)
    assert code == report.EXIT_NOT_YET
    assert out.startswith("NOT YET:") and "--force" in out
    assert (bundle / "state" / "secrets" / "hmac.key").read_bytes() == before
    code, _ = lab("init", "--force", capsys=capsys)
    assert code == 0
    assert (bundle / "state" / "secrets" / "hmac.key").read_bytes() != before


def test_init_prints_fingerprint(bundle, capsys):
    code, out = lab("init", capsys=capsys)
    assert code == 0
    assert f"sha256:{'cd' * 32}" in out


def test_init_writes_defaults_and_keeps_overrides(bundle, capsys):
    (bundle / ".env").write_text("LAB_PORT_FINBOT=8001\n", encoding="utf-8")
    assert lab("init", capsys=capsys)[0] == 0
    values = env_file(bundle)
    token = values.pop("LAB_CLIENT_TOKEN")
    assert token == (bundle / "state" / "secrets" / "client.token").read_text(encoding="utf-8").strip()
    assert values == {"LAB_PORT_FINBOT": "8001", "ACS_LAB_MODE": "enforce", "ACS_UPSTREAM": "replay",
                      "ACS_RESPONSE_SIGNING": "ML-DSA-65", "ACS_RESPONSE_ALGORITHMS": "ML-DSA-65"}


def test_init_key_generator_failure_exits_2(bundle, capsys, monkeypatch):
    monkeypatch.setattr(commands, "DECISION_KEYS", [sys.executable, "-c", "import sys; sys.exit(1)"])
    code, out = lab("init", capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out.startswith("NOT YET:")


@pytest.mark.parametrize("args", [["mode", "loud"], ["upstream", "ollama"], ["sign", "rsa"], ["traces", "maybe"],
                                  ["colour", "red"], ["mode"]])
def test_set_rejects_unknown_values(bundle, capsys, args):
    code, out = lab("_set", *args, capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out.startswith("NOT YET:")
    assert not (bundle / ".env").exists()


def test_sign_writes_both_settings(bundle, capsys):
    assert lab("_set", "sign", "hmac", capsys=capsys)[0] == 0
    env = env_file(bundle)
    assert env["ACS_RESPONSE_SIGNING"] == "HMAC-SHA256" and env["ACS_RESPONSE_ALGORITHMS"] == "HMAC-SHA256"
    assert lab("_set", "sign", "mldsa", capsys=capsys)[0] == 0
    env = env_file(bundle)
    assert env["ACS_RESPONSE_SIGNING"] == "ML-DSA-65" and env["ACS_RESPONSE_ALGORITHMS"] == "ML-DSA-65"


def test_set_mode_upstream_and_traces(bundle, capsys):
    (bundle / ".env").write_text("# kept\nLAB_PORT_VIEWER=9095\nACS_LAB_MODE=enforce\n", encoding="utf-8")
    assert lab("_set", "mode", "shadow", capsys=capsys)[0] == 0
    assert lab("_set", "upstream", "openai", capsys=capsys)[0] == 0
    assert lab("_set", "traces", "on", capsys=capsys)[0] == 0
    text = (bundle / ".env").read_text(encoding="utf-8")
    assert text.startswith("# kept\n")
    assert env_file(bundle) == {"LAB_PORT_VIEWER": "9095", "ACS_LAB_MODE": "shadow", "ACS_UPSTREAM": "openai",
                                "COMPOSE_PROFILES": "traces", "LAB_OTLP_ENDPOINT": "http://jaeger:4318"}
    assert lab("_set", "traces", "off", capsys=capsys)[0] == 0
    assert "COMPOSE_PROFILES" not in env_file(bundle) and "LAB_OTLP_ENDPOINT" not in env_file(bundle)


def test_wipe_refuses_outside_state(bundle, tmp_path, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    # state/ itself a link elsewhere: refused, nothing touched.
    (bundle / "state").symlink_to(outside, target_is_directory=True)
    code, out = lab("_wipe", capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:")
    assert (outside / "keep.txt").exists()
    (bundle / "state").unlink()
    # A link inside state/ is removed as a link, and its target survives.
    state = bundle / "state"
    (state / "transcripts").mkdir(parents=True)
    (state / "transcripts" / "s.jsonl").write_text("{}", encoding="utf-8")
    (state / "escape").symlink_to(outside, target_is_directory=True)
    (bundle / ".env").write_text("ACS_LAB_MODE=off\n", encoding="utf-8")
    code, out = lab("_wipe", capsys=capsys)
    assert code == 0 and out.startswith("DONE")
    assert state.is_dir() and list(state.iterdir()) == []
    assert (outside / "keep.txt").exists()
    assert (bundle / ".env").exists()


def test_model_log_escapes_control_bytes(bundle, capsys):
    state = bundle / "state"
    state.mkdir()
    body = {"input": [{"role": "user", "content": "hi\x1b[2J\x07 \u202e"}]}
    (state / "model-inputs.jsonl").write_text('{"first": 1}\n' + json.dumps(body) + "\nnot json \x1b[31m\n",
                                              encoding="utf-8")
    code, out = lab("model-log", capsys=capsys)
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out and "\u202e" not in out
    assert "not json \\x1b[31m" in out
    (state / "model-inputs.jsonl").write_text('{"first": 1}\n' + json.dumps(body) + "\n", encoding="utf-8")
    code, out = lab("model-log", capsys=capsys)
    assert code == 0
    assert "\x1b" not in out and "\\u001b[2J" in out and '"first"' not in out


def test_model_log_missing_is_not_yet(bundle, capsys):
    code, out = lab("model-log", capsys=capsys)
    assert code == report.EXIT_NOT_YET and out.startswith("NOT YET:")


def test_unknown_command_exits_2(bundle, capsys):
    code, out = lab("frobnicate", capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out.startswith("NOT YET: unknown command")


class _Admin(BaseHTTPRequestHandler):
    seen: list[tuple[str, str | None]] = []

    def do_POST(self):  # noqa: N802
        _Admin.seen.append((self.path, self.headers.get("Authorization")))
        body = b'{"epoch": 7}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def test_epoch_posts_with_the_bearer_token(bundle, capsys, monkeypatch, tmp_path):
    server = HTTPServer(("127.0.0.1", 0), _Admin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token = tmp_path / "admin.token"
    token.write_text("t" * 64 + "\n", encoding="utf-8")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_HOST", "127.0.0.1")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_PORT", str(server.server_address[1]))
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_TOKEN_FILE", str(token))
    try:
        code, out = lab("_epoch", capsys=capsys)
    finally:
        server.shutdown()
    assert code == 0 and out.startswith("DONE") and "7" in out
    assert _Admin.seen == [("/epoch", "Bearer " + "t" * 64)]


def test_epoch_gateway_down_is_not_yet(bundle, capsys, monkeypatch, tmp_path):
    token = tmp_path / "admin.token"
    token.write_text("t" * 64, encoding="utf-8")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_HOST", "127.0.0.1")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_PORT", "9")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_TOKEN_FILE", str(token))
    code, out = lab("_epoch", capsys=capsys)
    assert code == report.EXIT_NOT_YET and out.startswith("NOT YET:")
    assert "t" * 64 not in out


def test_pins_runs_lab_12_tool_then_bumps_epoch(bundle, capsys, monkeypatch, tmp_path):
    # Interface pin: LAB-12's pins.py takes --model-log and --data and exits 0 or 2.
    calls = []
    monkeypatch.setattr(commands, "_run_tool", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(commands, "cmd_epoch", lambda args: calls.append(["_epoch"]) or 0)
    code, out = lab("pins", capsys=capsys)
    assert code == 0, out
    assert calls[0][1:] == [str(bundle / "policy" / "tools" / "pins.py"), "--model-log",
                            str(bundle / "state" / "model-inputs.jsonl"), "--data",
                            str(bundle / "policy" / "data.json")]
    assert calls[0][0] == commands.GATEWAY_PYTHON
    assert calls[1] == ["_epoch"]


def test_claims_passes_the_path_and_the_bundle_ledger(bundle, capsys, monkeypatch):
    seen = []

    class FakeClaims:
        @staticmethod
        def main(argv):
            seen.append(argv)
            return 0

    monkeypatch.setitem(sys.modules, "lab_claims", FakeClaims)
    assert lab("claims", "check", "/scan", capsys=capsys)[0] == 0
    assert lab("claims", "check", capsys=capsys)[0] == 0
    assert seen == [["/scan", "--ledger", str(bundle / "CLAIMS.md")],
                    [str(bundle), "--ledger", str(bundle / "CLAIMS.md")]]


def test_bench_show_prints_the_table(bundle, capsys, monkeypatch, tmp_path):
    table = tmp_path / "signature-benchmark.md"
    table.write_text("| alg | ms |\n|---|---|\n| ML-DSA-65 | 1.2 \x1b[0m |\n", encoding="utf-8")
    monkeypatch.setattr(commands, "BENCH_FILE", table)
    code, out = lab("bench", "--show", capsys=capsys)
    assert code == 0 and "ML-DSA-65" in out and "\x1b" not in out


def test_every_check_line_starts_done_or_not_yet(bundle, capsys):
    for args in (["init"], ["init"], ["_set", "mode", "off"], ["_set", "mode", "x"], ["model-log"], ["viewer"],
                 ["approver"], ["_wipe"], ["nope"]):
        code = commands.dispatch(args)
        lines = capsys.readouterr().out.splitlines()
        assert lines and lines[0].startswith(("DONE", "NOT YET:")), (args, lines)
        assert code in (0, 1, 2)


def test_lab_py_runs_by_path(bundle, tmp_path):
    env = {**os.environ, "LAB_BUNDLE": str(bundle)}
    result = subprocess.run([sys.executable, str(LAB_PY), "nope"], capture_output=True, text=True, env=env)
    assert result.returncode == 2 and result.stdout.startswith("NOT YET: unknown command")
    result = subprocess.run([sys.executable, str(LAB_PY)], capture_output=True, text=True, env=env)
    assert result.returncode == 0 and "init" in result.stdout


def _state_with_model_key(bundle: Path) -> Path:
    secrets = bundle / "state" / "secrets"
    secrets.mkdir(parents=True)
    for name in ("hmac.key", "openai.key"):
        (secrets / name).write_text("x\n", encoding="utf-8")
    (bundle / "state" / "audit.log").write_text("{}\n", encoding="utf-8")
    return secrets


def test_wipe_keeps_the_model_key_by_default(bundle, capsys):
    # The attendee pasted that key in by hand, and lab init can't make it again. Only an explicit flag deletes it.
    secrets = _state_with_model_key(bundle)
    code, out = lab("_wipe", capsys=capsys)
    assert code == 0 and out.startswith("DONE")
    assert [p.name for p in (bundle / "state").iterdir()] == ["secrets"]
    assert [p.name for p in secrets.iterdir()] == ["openai.key"]
    assert "openai.key" in out


def test_wipe_deletes_the_model_key_when_told(bundle, capsys):
    _state_with_model_key(bundle)
    code, out = lab("_wipe", "--delete-model-key", capsys=capsys)
    assert code == 0 and out.startswith("DONE")
    assert list((bundle / "state").iterdir()) == []


def test_wipe_rejects_unknown_arguments(bundle, capsys):
    secrets = _state_with_model_key(bundle)
    code, out = lab("_wipe", "--everything", capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:")
    assert (secrets / "hmac.key").exists() and (secrets / "openai.key").exists()



# ---------------------------------------------------------------------------------------------------------------------
# Final review R8: the model port's per-lab client token
# ---------------------------------------------------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_init_writes_the_client_token_owner_only_and_hands_it_to_finbot(bundle, capsys):
    assert lab("init", capsys=capsys)[0] == 0
    path = bundle / "state" / "secrets" / "client.token"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    token = path.read_text(encoding="utf-8").strip()
    # 256 random bits as hex, the gateway's minimum of 32 bytes for a listener secret.
    assert len(token) == 64 and int(token, 16) >= 0
    # FinBot's OPENAI_API_KEY comes from .env, which now holds a secret, so .env is owner-only too.
    assert env_file(bundle)["LAB_CLIENT_TOKEN"] == token
    assert stat.S_IMODE((bundle / ".env").stat().st_mode) == 0o600


def test_every_init_makes_a_new_client_token(bundle, capsys):
    # reset wipes state/ but keeps .env, so the next init must replace the token .env still holds.
    assert lab("init", capsys=capsys)[0] == 0
    first = env_file(bundle)["LAB_CLIENT_TOKEN"]
    shutil.rmtree(bundle / "state")
    assert lab("init", capsys=capsys)[0] == 0
    second = env_file(bundle)["LAB_CLIENT_TOKEN"]
    assert second != first
    assert second == (bundle / "state" / "secrets" / "client.token").read_text(encoding="utf-8").strip()
    assert lab("init", "--force", capsys=capsys)[0] == 0
    assert env_file(bundle)["LAB_CLIENT_TOKEN"] not in (first, second)


def test_init_refuses_when_only_the_client_token_exists(bundle, capsys):
    assert lab("init", capsys=capsys)[0] == 0
    for name in ("hmac.key", "guardian.key", "admin.token", "approver.token"):
        (bundle / "state" / "secrets" / name).unlink()
    code, out = lab("init", capsys=capsys)
    assert code == report.EXIT_NOT_YET and "client.token" in out
