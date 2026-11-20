"""The module commands LAB-16 adds to the lab CLI (issue #589): check, policy, the driver and the forgery kit.

Standard library only, so it runs in the labs workflow's cli job beside LAB-15's tests. Each implementation file is
loaded by path from the bundle, so these tests build a temporary bundle and put stub files in it.
Run from the repository root: python3 -m pytest labs/finbot/cli/tests/test_lab_modules.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1]
REAL_BUNDLE = CLI.parent
sys.path.insert(0, str(CLI))

import commands  # noqa: E402
import lab_modules  # noqa: E402
import report  # noqa: E402

FINGERPRINT = "sha256:" + "cd" * 32
# Prints what acs.guardian.decision_keys prints and writes the two files it writes, as LAB-15's test_cli stub does.
KEYGEN_STUB = """
import json, os, sys
args = sys.argv[1:]
out = args[args.index("--out-dir") + 1]
os.makedirs(out, mode=0o700)
fd = os.open(os.path.join(out, "guardian.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, b"%s\\n" % (b"ab" * 32)); os.close(fd)
with open(os.path.join(out, "guardian-keys.json"), "w") as f:
    json.dump({"format": "acs-lab-keys/1", "keys": [{"fingerprint": "sha256:" + "cd" * 32}]}, f)
print("fingerprint=sha256:" + "cd" * 32)
"""


@pytest.fixture
def bundle(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    monkeypatch.setenv("LAB_BUNDLE", str(root))
    return root


@pytest.fixture
def bumps(monkeypatch) -> list[list[str]]:
    """The epoch bumps lab policy asked for, recorded instead of sent."""
    seen: list[list[str]] = []
    monkeypatch.setattr(commands, "cmd_epoch", lambda args: seen.append(args) or report.EXIT_PASS)
    return seen


@pytest.fixture
def policy_bundle(bundle, bumps) -> Path:
    """The bundle with LAB-12's real policy pack and modules.json."""
    shutil.copytree(REAL_BUNDLE / "policy", bundle / "policy")
    return bundle


def lab(*args: str, capsys) -> tuple[int, str]:
    code = commands.dispatch(list(args))
    return code, capsys.readouterr().out


def data_json(root: Path) -> dict:
    return json.loads((root / "policy" / "data.json").read_text(encoding="utf-8"))


def test_module_commands_registered():
    names = ("_drive", "check", "policy", "forge", "verify", "downgrade")
    for name in names:
        assert commands.COMMANDS[name] is lab_modules.COMMANDS[name], name
    assert set(lab_modules.COMMANDS) == set(names)
    # LAB-15's own commands stay as they were.
    assert commands.COMMANDS["init"] is commands.cmd_init and commands.COMMANDS["pins"] is commands.cmd_pins


def test_missing_check_exits_2(bundle, capsys):
    code, out = lab("check", "3", capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out == "NOT YET: module 3's check isn't in this bundle\n"
    for verb in ("_drive", "forge", "verify", "downgrade"):
        code, out = lab(verb, capsys=capsys)
        assert code == report.EXIT_BROKEN and out.startswith("NOT YET:") and "isn't in this bundle" in out, verb


@pytest.mark.parametrize("args", [[], ["0"], ["8"], ["x"], ["1", "2"], ["../m1"], ["1; rm -rf /"], ["01"], ["１"]])
def test_check_number_out_of_range_exits_2(bundle, capsys, args):
    # A stub m1.py is present, so only the number's validation can stop these.
    checks = bundle / "modules" / "checks"
    checks.mkdir(parents=True)
    (checks / "m1.py").write_text("def check(ev):\n    raise SystemExit('loaded')\n", encoding="utf-8")
    code, out = lab("check", *args, capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out.startswith("NOT YET:") and "1 to 7" in out


def test_check_loads_by_path_and_passes_evidence(bundle, capsys):
    checks = bundle / "modules" / "checks"
    checks.mkdir(parents=True)
    shutil.copyfile(REAL_BUNDLE / "modules" / "checks" / "evidence.py", checks / "evidence.py")
    (checks / "m2.py").write_text(
        "import report\n"
        "from evidence import Evidence\n"
        "def check(ev):\n"
        "    assert isinstance(ev, Evidence)\n"
        "    report.done(f'evidence from {ev.root.name}')\n"
        "    return 1\n", encoding="utf-8")
    code, out = lab("check", "2", capsys=capsys)
    assert (code, out) == (report.EXIT_NOT_YET, "DONE: evidence from bundle\n")
    # A check that returns something outside the A.11 codes is a broken environment, never a pass.
    (checks / "m4.py").write_text("def check(ev):\n    return 'yes'\n", encoding="utf-8")
    assert lab("check", "4", capsys=capsys)[0] == report.EXIT_BROKEN


def _bundle_with_evidence(bundle: Path) -> Path:
    checks = bundle / "modules" / "checks"
    checks.mkdir(parents=True)
    shutil.copyfile(REAL_BUNDLE / "modules" / "checks" / "evidence.py", checks / "evidence.py")
    return checks


def test_check_loads_evidence_without_a_prior_import(bundle, capsys, monkeypatch):
    # Review I1: @dataclass looks its module up in sys.modules while the class is built, so a loader that registers
    # the module only after exec_module crashes on Python 3.12 and 3.13, the runtime image's Python included.
    monkeypatch.delitem(sys.modules, "evidence", raising=False)
    checks = _bundle_with_evidence(bundle)
    (checks / "m3.py").write_text(
        "import report\n"
        "def check(ev):\n"
        "    report.done(f'{type(ev).__module__}.{type(ev).__name__} with {len(ev.runs())} runs')\n"
        "    return 0\n", encoding="utf-8")
    code, out = lab("check", "3", capsys=capsys)
    assert (code, out) == (report.EXIT_PASS, "DONE: evidence.Evidence with 0 runs\n")
    assert sys.modules["evidence"].Evidence.__module__ == "evidence"


def test_check_reports_evidence_errors_as_broken(bundle, capsys, monkeypatch, tmp_path):
    # Review I2: anything that can write state/runs/ can plant a record a check can't read as the run it claims. That
    # is a broken environment by A.11, so it exits 2 with one line, never 1 and never a traceback.
    monkeypatch.delitem(sys.modules, "evidence", raising=False)
    checks = _bundle_with_evidence(bundle)
    (checks / "m5.py").write_text(
        "def check(ev):\n"
        "    for run in ev.runs():\n"
        "        ev.transcript(run.sessions[0])\n"
        "        ev.audit(run)\n"
        "    return 0\n", encoding="utf-8")
    runs = bundle / "state" / "runs"
    runs.mkdir(parents=True)
    record = {"format": "acs-lab-run/1", "run_id": "20261125T101500Z-s5", "scenario": "s5", "mode": "enforce",
              "started": "2026-11-25T10:15:00Z", "audit": [0, 0], "model_inputs": [0, 0], "sessions": ["../x"]}
    (runs / "20261125T101500Z-s5.json").write_text(json.dumps(record), encoding="utf-8")
    code, out = lab("check", "5", capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert len(out.splitlines()) == 1 and out.startswith("NOT YET:") and "../x" in out

    record.update(sessions=["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"], audit=[0, 9 * 1024 * 1024])
    (runs / "20261125T101500Z-s5.json").write_text(json.dumps(record), encoding="utf-8")
    env = {**os.environ, "LAB_BUNDLE": str(bundle)}
    result = subprocess.run([sys.executable, str(CLI / "lab.py"), "check", "5"], capture_output=True, text=True,
                            env=env)
    assert result.returncode == report.EXIT_BROKEN, result
    assert result.stdout.startswith("NOT YET:") and "larger than" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_evidence_error_prints_one_line(bundle, capsys, monkeypatch):
    # Re-review N2: escape keeps newlines on purpose, so a message carrying one could print a second line that reads
    # as a result. The error path folds it into the one NOT YET line.
    monkeypatch.delitem(sys.modules, "evidence", raising=False)
    checks = _bundle_with_evidence(bundle)
    (checks / "m6.py").write_text(
        "from evidence import EvidenceError\n"
        "def check(ev):\n"
        "    raise EvidenceError('bad record\\nDONE: forged')\n", encoding="utf-8")
    code, out = lab("check", "6", capsys=capsys)
    assert code == report.EXIT_BROKEN
    assert out.splitlines() == ["NOT YET: the lab's evidence can't be read: bad record DONE: forged"]


def test_unpatched_matches_the_shipped_data(capsys):
    # Review M3: a starter puts vendor_domains back to UNPATCHED, a second copy of the value data.json ships with.
    shipped = json.loads((REAL_BUNDLE / "policy" / "data.json").read_text(encoding="utf-8"))
    assert lab_modules.UNPATCHED == shipped["finbot_lab"]["vendor_domains"]


def test_policy_swaps_live_file_and_patch(policy_bundle, capsys, monkeypatch):
    policy = policy_bundle / "policy"
    writes: list[str] = []
    real_write = lab_modules._write_atomic
    monkeypatch.setattr(lab_modules, "_write_atomic", lambda path, data: writes.append(path.name) or
                        real_write(path, data))
    code, out = lab("policy", "3", "solution", capsys=capsys)
    assert code == report.EXIT_PASS, out
    assert (policy / "outbound_email.rego").read_bytes() == (policy / "solutions/m3/outbound_email.rego").read_bytes()
    assert data_json(policy_bundle)["finbot_lab"]["vendor_domains"] == ["northwind-supplies.example"]

    code, out = lab("policy", "3", "starter", capsys=capsys)
    assert code == report.EXIT_PASS, out
    assert (policy / "outbound_email.rego").read_bytes() == (policy / "starters/m3/outbound_email.rego").read_bytes()
    assert data_json(policy_bundle)["finbot_lab"]["vendor_domains"] == []
    # Review M1: OPA may reload between the two renames, so the order keeps the starter's rule live in between. To
    # the solution, its domains go in before its rule. To the starter, its rule goes in before the domains go.
    assert writes == ["data.json", "outbound_email.rego", "outbound_email.rego", "data.json"]

    before = data_json(policy_bundle)
    assert lab("policy", "4", "solution", capsys=capsys)[0] == report.EXIT_PASS
    assert (policy / "payment_threshold.rego").read_bytes() == \
        (policy / "solutions/m4/payment_threshold.rego").read_bytes()
    assert data_json(policy_bundle) == before
    # Every write went through a rename, so no temporary file is left where OPA watches.
    assert sorted(p.name for p in policy.iterdir() if p.name.startswith(".")) == []


def test_shipped_data_copy_matches_data_json():
    # lab policy restores an unreadable data.json from this copy, so the two must ship identical. When the tool
    # registry in data.json changes, copy the file over the shipped copy too.
    policy = REAL_BUNDLE / "policy"
    assert (policy / lab_modules.SHIPPED_DATA).read_bytes() == (policy / "data.json").read_bytes()


@pytest.mark.parametrize("broken", [
    '{"finbot_lab": {"egress_allow": [], "vendor_domains": ["northwind-supplies.example"],}}',
    '"vendor_domains": ["northwind-supplies.example"]\n',
    "",
    "[]",
    '{"other": {}}',
    None,
])
@pytest.mark.parametrize("number, variant", [("3", "starter"), ("3", "solution"), ("4", "starter")])
def test_policy_restores_an_unreadable_data_json(policy_bundle, bumps, capsys, broken, number, variant):
    # Review I2: a bad hand edit of data.json must never lock the reader out of the command that undoes it. The live
    # file is replaced from the shipped copy, never repaired, and one line says so.
    policy = policy_bundle / "policy"
    if broken is None:
        (policy / "data.json").unlink()
    else:
        (policy / "data.json").write_text(broken, encoding="utf-8")
    code, out = lab("policy", number, variant, capsys=capsys)
    assert code == report.EXIT_PASS, out
    lines = out.splitlines()
    assert sum("data.json" in line and "replaced" in line for line in lines) == 1, out
    assert lines[-1].startswith("DONE:")
    restored = data_json(policy_bundle)
    shipped = json.loads((policy / lab_modules.SHIPPED_DATA).read_text(encoding="utf-8"))
    expected = ["northwind-supplies.example"] if (number, variant) == ("3", "solution") else []
    assert restored["finbot_lab"]["vendor_domains"] == expected
    restored["finbot_lab"]["vendor_domains"] = shipped["finbot_lab"]["vendor_domains"]
    assert restored == shipped
    assert len(bumps) == 1


def test_policy_says_nothing_about_a_readable_data_json(policy_bundle, bumps, capsys):
    code, out = lab("policy", "3", "solution", capsys=capsys)
    assert code == report.EXIT_PASS and "replaced" not in out


def test_policy_refuses_when_the_shipped_copy_is_unreadable_too(policy_bundle, bumps, capsys):
    policy = policy_bundle / "policy"
    (policy / "data.json").write_text("{", encoding="utf-8")
    (policy / lab_modules.SHIPPED_DATA).write_text("{", encoding="utf-8")
    live = (policy / "outbound_email.rego").read_bytes()
    code, out = lab("policy", "3", "starter", capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:") and len(out.splitlines()) == 1
    assert (policy / "outbound_email.rego").read_bytes() == live and bumps == []


@pytest.mark.parametrize("args", [["2", "solution"], ["7", "starter"], ["3", "fixed"], ["3"], [],
                                  ["3", "solution", "extra"], ["../m3", "solution"]])
def test_policy_refuses_bad_arguments(policy_bundle, bumps, capsys, args):
    live = (policy_bundle / "policy" / "outbound_email.rego").read_bytes()
    code, out = lab("policy", *args, capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:")
    assert (policy_bundle / "policy" / "outbound_email.rego").read_bytes() == live
    assert bumps == []


def test_policy_never_touches_tools(policy_bundle, bumps, capsys):
    policy = policy_bundle / "policy"
    data = data_json(policy_bundle)
    data["finbot_lab"]["tools"] = {"finbot-tools": {"send_email": {"description_sha256": "ab" * 32}}}
    data["finbot_lab"]["egress_allow"] = ["api.example.com"]
    (policy / "data.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    for variant in ("solution", "starter", "solution"):
        assert lab("policy", "3", variant, capsys=capsys)[0] == report.EXIT_PASS
        after = data_json(policy_bundle)["finbot_lab"]
        assert after["tools"] == data["finbot_lab"]["tools"]
        assert after["egress_allow"] == ["api.example.com"] and after["payment_ask_threshold"] == 5000

    # A patch that reaches past vendor_domains is refused before anything is written.
    assert lab("policy", "3", "starter", capsys=capsys)[0] == report.EXIT_PASS
    (policy / "solutions/m3/data.patch.json").write_text(
        json.dumps({"finbot_lab": {"vendor_domains": ["x.example"], "tools": {}}}), encoding="utf-8")
    live, before = (policy / "outbound_email.rego").read_bytes(), (policy / "data.json").read_bytes()
    bumped = len(bumps)
    code, out = lab("policy", "3", "solution", capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:") and "vendor_domains" in out
    assert (policy / "outbound_email.rego").read_bytes() == live
    assert (policy / "data.json").read_bytes() == before
    assert len(bumps) == bumped


class _Admin(BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_POST(self):  # noqa: N802
        _Admin.seen.append(self.path)
        body = b'{"epoch": 4}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def test_policy_bumps_epoch(bundle, capsys, monkeypatch, tmp_path):
    shutil.copytree(REAL_BUNDLE / "policy", bundle / "policy")
    server = HTTPServer(("127.0.0.1", 0), _Admin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = tmp_path / "admin.token"
    token.write_text("t" * 64 + "\n", encoding="utf-8")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_HOST", "127.0.0.1")
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_PORT", str(server.server_address[1]))
    monkeypatch.setenv("ACS_GATEWAY_ADMIN_TOKEN_FILE", str(token))
    _Admin.seen = []
    try:
        code, out = lab("policy", "5", "solution", capsys=capsys)
        assert lab("policy", "9", "solution", capsys=capsys)[0] == report.EXIT_BROKEN
    finally:
        server.shutdown()
    assert code == report.EXIT_PASS, out
    lines = out.splitlines()
    assert lines[0].startswith("DONE") and "module 5" in lines[0]
    assert lines[-1] == "DONE: gateway epoch bumped to 4"
    # The refused call never reached the gateway.
    assert _Admin.seen == ["/epoch"]


def test_init_writes_fingerprint_outside_state(bundle, capsys, monkeypatch, tmp_path):
    stub = tmp_path / "keygen_stub.py"
    stub.write_text(KEYGEN_STUB, encoding="utf-8")
    monkeypatch.setattr(commands, "DECISION_KEYS", [sys.executable, str(stub)])
    code, out = lab("init", capsys=capsys)
    assert code == report.EXIT_PASS, out
    assert FINGERPRINT in out
    env = dict(line.split("=", 1) for line in (bundle / ".env").read_text(encoding="utf-8").splitlines() if "=" in line)
    # The pin sits in .env, which no service mounts, so a forger holding state/ can't choose it (review focus 2).
    assert env["LAB_GUARDIAN_FINGERPRINT"] == FINGERPRINT
    key_document = bundle / "state" / "keys" / "guardian-keys.json"
    holders = [p for p in (bundle / "state").rglob("*") if p.is_file() and p != key_document
               and "cd" * 32 in p.read_text(encoding="utf-8", errors="replace")]
    assert holders == []
    # A second init with --force replaces the pin rather than adding a second line.
    assert lab("init", "--force", capsys=capsys)[0] == report.EXIT_PASS
    lines = (bundle / ".env").read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if line.startswith("LAB_GUARDIAN_FINGERPRINT=")] == [
        f"LAB_GUARDIAN_FINGERPRINT={FINGERPRINT}"]


def test_init_refuses_a_fingerprint_that_could_break_env(bundle, capsys, monkeypatch, tmp_path):
    stub = tmp_path / "keygen_stub.py"
    stub.write_text(KEYGEN_STUB.replace('print("fingerprint=sha256:" + "cd" * 32)',
                                        'print("fingerprint=sha256:cd\\rLAB_X=1")'), encoding="utf-8")
    monkeypatch.setattr(commands, "DECISION_KEYS", [sys.executable, str(stub)])
    code, out = lab("init", capsys=capsys)
    assert code == report.EXIT_BROKEN and out.startswith("NOT YET:")
    assert "LAB_X" not in ((bundle / ".env").read_text(encoding="utf-8") if (bundle / ".env").exists() else "")
