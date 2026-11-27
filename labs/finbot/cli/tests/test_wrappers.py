"""lab.sh, the host wrapper (issue #588, LAB-15), driven against a fake docker that logs every call.

Each test copies lab.sh into a temporary bundle, so nothing here touches the real labs/finbot/state or .env.
Run from the repository root: python3 -m pytest labs/finbot/cli/tests/test_wrappers.py -v
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

BUNDLE = Path(__file__).resolve().parents[2]
LAB_SH = BUNDLE / "lab.sh"
FAKE = Path(__file__).resolve().parent / "fake_docker"
# The utilities lab.sh may call, linked into a bin directory of their own so a test can leave docker out.
TOOLS = ("sh", "dirname", "id", "grep", "sed", "cat", "mkdir", "pwd", "printf", "tr", "rm", "head", "tail", "basename")

pytestmark = pytest.mark.skipif(os.name == "nt", reason="lab.sh runs on macOS and Linux only (Rock, 2026-11-17)")


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    shutil.copy2(LAB_SH, root / "lab.sh")
    for name in ("compose.yaml", "compose.openai.yaml"):
        (root / name).write_text("services: {}\n", encoding="utf-8")
    secrets = root / "state" / "secrets"
    secrets.mkdir(parents=True)
    for name in ("hmac.key", "guardian.key", "admin.token", "approver.token", "client.token"):
        (secrets / name).write_text("x\n", encoding="utf-8")
    (root / ".env").write_text("LAB_CLIENT_TOKEN=x\n", encoding="utf-8")
    (root / "state" / "image-source").write_text("pulled\n", encoding="utf-8")
    return root


def _bin(tmp_path: Path, with_docker: bool) -> Path:
    path = tmp_path / "bin"
    path.mkdir(exist_ok=True)
    for tool in TOOLS:
        found = shutil.which(tool)
        if found and not (path / tool).exists():
            (path / tool).symlink_to(found)
    if with_docker and not (path / "docker").exists():
        (path / "docker").symlink_to(FAKE / "docker")
    return path


def run(bundle: Path, *args: str, cwd: Path | None = None, docker: bool = True,
        env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    full = {"PATH": str(_bin(bundle.parent, docker)), "FAKE_DOCKER_LOG": str(log), "HOME": str(bundle.parent)}
    full.update(env or {})
    result = subprocess.run(["sh", str(bundle / "lab.sh"), *args], cwd=cwd or bundle, env=full,
                            capture_output=True, text=True)
    return result, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def argv(line: str) -> str:
    return line.split(" | ", 1)[1]


def compose_calls(lines: list[str]) -> list[str]:
    return [argv(line) for line in lines if argv(line).startswith("compose ")]


def test_mode_sets_then_recreates_gateway_only(bundle):
    result, lines = run(bundle, "mode", "shadow")
    assert result.returncode == 0, result.stderr
    calls = compose_calls(lines)
    assert calls == ["compose -f compose.yaml run --rm lab _set mode shadow",
                     "compose -f compose.yaml up -d --wait --no-deps acs-gateway",
                     "compose -f compose.yaml run --rm lab _epoch"]


def test_sign_recreates_guardian_and_gateway_then_bumps_epoch(bundle):
    result, lines = run(bundle, "sign", "hmac")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml run --rm lab _set sign hmac",
                                    "compose -f compose.yaml up -d --wait --no-deps acs-guardian acs-gateway",
                                    "compose -f compose.yaml run --rm lab _epoch"]


def test_upstream_openai_needs_key_file(bundle):
    result, lines = run(bundle, "upstream", "openai")
    assert result.returncode == 2
    assert "NOT YET:" in result.stdout and "state/secrets/openai.key" in result.stdout
    assert compose_calls(lines) == []


def test_upstream_openai_adds_the_override(bundle):
    (bundle / "state" / "secrets" / "openai.key").write_text("sk\n", encoding="utf-8")
    # The fake can't run _set, so .env is written here as the container would have written it.
    (bundle / ".env").write_text("ACS_UPSTREAM=openai\n", encoding="utf-8")
    result, lines = run(bundle, "upstream", "openai")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[1] == ("compose -f compose.yaml -f compose.openai.yaml up -d --wait --no-deps "
                                       "acs-gateway")


def test_claims_path_mounted_read_only(bundle, tmp_path):
    scan = tmp_path / "recording"
    scan.mkdir()
    result, lines = run(bundle, "claims", "check", str(scan))
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == [f"compose -f compose.yaml run --rm -v {scan}:/scan:ro lab claims check /scan"]


def test_claims_relative_path_resolves_from_the_callers_directory(bundle, tmp_path):
    scan = tmp_path / "rel"
    scan.mkdir()
    result, lines = run(bundle, "claims", "check", "rel", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == [f"compose -f compose.yaml run --rm -v {scan}:/scan:ro lab claims check /scan"]


def test_claims_missing_path_exits_2(bundle, tmp_path):
    result, lines = run(bundle, "claims", "check", str(tmp_path / "absent"))
    assert result.returncode == 2
    assert compose_calls(lines) == []


def test_unknown_verb_goes_to_the_container(bundle):
    result, lines = run(bundle, "check", "1")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml run --rm lab check 1"]


def test_doctor_names_the_variable(bundle):
    result, _ = run(bundle, "doctor", env={"FAKE_DOCKER_FAIL_PORTS": "8090"})
    assert result.returncode == 1
    assert "NOT YET: port 8090 is in use. Set LAB_PORT_APPROVER in labs/finbot/.env" in result.stdout
    assert "DONE: port 8095 is free" in result.stdout
    # FinBot joins only internal networks and publishes no port, so doctor doesn't check one for it (C-17).
    assert "8000" not in result.stdout and "LAB_PORT_FINBOT" not in result.stdout


def test_doctor_reads_port_overrides_from_env_file(bundle):
    (bundle / ".env").write_text("LAB_PORT_VIEWER=9095\n", encoding="utf-8")
    result, _ = run(bundle, "doctor", env={"FAKE_DOCKER_FAIL_PORTS": "9095"})
    assert result.returncode == 1
    assert "NOT YET: port 9095 is in use. Set LAB_PORT_VIEWER in labs/finbot/.env" in result.stdout


def test_doctor_passes_and_every_line_is_done_or_not_yet(bundle):
    result, _ = run(bundle, "doctor")
    assert result.returncode == 0, result.stdout
    lines = [line for line in result.stdout.splitlines() if line]
    assert lines and all(line.startswith(("DONE", "NOT YET:")) for line in lines)
    assert any("images came from" in line and "pulled" in line for line in lines)


def test_doctor_low_memory_and_odd_architecture(bundle):
    result, _ = run(bundle, "doctor", env={"FAKE_DOCKER_MEM": str(4 * 1024 ** 3), "FAKE_DOCKER_ARCH": "s390x"})
    assert result.returncode == 1
    assert "NOT YET: Docker has 4 GiB of memory" in result.stdout
    assert "NOT YET: architecture s390x" in result.stdout


def test_doctor_daemon_down_exits_2(bundle):
    result, _ = run(bundle, "doctor", env={"FAKE_DOCKER_DOWN": "1"})
    assert result.returncode == 2
    assert "NOT YET: Docker isn't running" in result.stdout


def test_lab_sh_exports_host_uid(bundle):
    _, lines = run(bundle, "check", "1")
    expected = f"LAB_UID={os.getuid()} LAB_GID={os.getgid()} "
    if os.getuid() == 0:
        # Root on the host keeps the image's default user, so the services never run as root.
        expected = "LAB_UID= LAB_GID= "
    assert lines and all(line.startswith(expected) for line in lines)


def test_runs_from_any_directory(bundle, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    result, lines = run(bundle, "check", "1", cwd=elsewhere)
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml run --rm lab check 1"]


def test_no_docker_exits_2(bundle):
    result, _ = run(bundle, "check", "1", docker=False)
    assert result.returncode == 2
    assert result.stdout.startswith("NOT YET: Docker isn't installed")


def test_up_refuses_before_init(bundle):
    shutil.rmtree(bundle / "state" / "secrets")
    result, lines = run(bundle, "up")
    assert result.returncode == 1
    assert "NOT YET: run ./lab.sh init first" in result.stdout
    assert not any(" up " in call for call in compose_calls(lines))


def test_up_waits_for_healthy(bundle):
    result, lines = run(bundle, "up")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[-1] == "compose -f compose.yaml up -d --wait"


def test_first_run_pulls_then_builds_on_failure(bundle):
    (bundle / "state" / "image-source").unlink()
    result, lines = run(bundle, "up", env={"FAKE_DOCKER_PULL_FAIL": "1"})
    assert result.returncode == 0, result.stderr
    calls = compose_calls(lines)
    assert calls[0] == "compose -f compose.yaml --profile cli pull"
    assert calls[1] == "compose -f compose.yaml --profile cli build"
    built = [line for line in lines if argv(line) == calls[1]][0]
    assert "LAB_RUNTIME_IMAGE=acs-lab-runtime:local" in built
    assert (bundle / "state" / "image-source").read_text(encoding="utf-8").strip() == "built"
    # Every later call uses the local tags too.
    _, later = run(bundle, "check", "1")
    assert all("LAB_RUNTIME_IMAGE=acs-lab-runtime:local" in line for line in later)


def test_first_run_pull_success_records_pulled(bundle):
    (bundle / "state" / "image-source").unlink()
    result, lines = run(bundle, "init")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml --profile cli pull",
                                    "compose -f compose.yaml run --rm lab init"]
    assert (bundle / "state" / "image-source").read_text(encoding="utf-8").strip() == "pulled"


def test_reset_stops_then_wipes(bundle):
    result, lines = run(bundle, "reset")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml --profile traces --profile cli down --volumes",
                                    "compose -f compose.yaml run --rm lab _wipe"]


def test_traces_on_starts_jaeger_with_the_gateway(bundle):
    result, lines = run(bundle, "traces", "on")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml run --rm lab _set traces on",
                                    "compose -f compose.yaml up -d --wait --no-deps jaeger acs-gateway"]


def test_bad_setting_value_never_reaches_compose_up(bundle):
    result, lines = run(bundle, "mode")
    assert result.returncode == 2
    assert compose_calls(lines) == []


def test_up_rebuilds_local_images(bundle):
    (bundle / "state" / "image-source").write_text("built\n", encoding="utf-8")
    result, lines = run(bundle, "up")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml --profile cli build",
                                    "compose -f compose.yaml up -d --wait"]
    assert all("LAB_RUNTIME_IMAGE=acs-lab-runtime:local" in line for line in lines)


def _with_model_key(bundle: Path) -> None:
    (bundle / "state" / "secrets" / "openai.key").write_text("sk-x\n", encoding="utf-8")


def test_reset_without_a_terminal_keeps_the_model_key(bundle):
    _with_model_key(bundle)
    result, lines = run(bundle, "reset")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[-1] == "compose -f compose.yaml run --rm lab _wipe"
    assert "openai.key" in result.stdout and "--delete-model-key" in result.stdout


def test_reset_deletes_the_model_key_only_with_the_flag(bundle):
    _with_model_key(bundle)
    result, lines = run(bundle, "reset", "--delete-model-key")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[-1] == "compose -f compose.yaml run --rm lab _wipe --delete-model-key"


def test_reset_rejects_unknown_arguments_before_stopping_anything(bundle):
    result, lines = run(bundle, "reset", "--all")
    assert result.returncode == 2
    assert compose_calls(lines) == []


def _run_on_a_terminal(bundle: Path, answer: str) -> tuple[subprocess.CompletedProcess, list[str]]:
    # stdin on a pseudo-terminal, so lab.sh sees an attendee at the keyboard. The answer waits in the terminal's
    # input queue until lab.sh reads it.
    import pty

    leader, follower = pty.openpty()
    try:
        os.write(leader, answer.encode() + b"\n")
        log = bundle.parent / "docker.log"
        log.write_text("", encoding="utf-8")
        env = {"PATH": str(_bin(bundle.parent, True)), "FAKE_DOCKER_LOG": str(log), "HOME": str(bundle.parent)}
        result = subprocess.run(["sh", str(bundle / "lab.sh"), "reset"], cwd=bundle, env=env, stdin=follower,
                                capture_output=True, text=True, timeout=30)
    finally:
        os.close(follower)
        os.close(leader)
    return result, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.parametrize(("answer", "deletes"), [("y", True), ("yes", True), ("n", False), ("", False)])
def test_reset_on_a_terminal_warns_and_asks(bundle, answer, deletes):
    _with_model_key(bundle)
    result, lines = _run_on_a_terminal(bundle, answer)
    assert result.returncode == 0, result.stderr
    assert "openai.key" in result.stdout
    calls = compose_calls(lines)
    expected = "compose -f compose.yaml run --rm lab _wipe" + (" --delete-model-key" if deletes else "")
    assert calls[-1] == expected
    # The question comes before anything stops, so Ctrl-C at the prompt leaves the lab as it was.
    assert calls[0].endswith("down --volumes")


def test_reset_on_a_terminal_without_a_model_key_asks_nothing(bundle):
    result, lines = _run_on_a_terminal(bundle, "y")
    assert result.returncode == 0, result.stderr
    assert "openai.key" not in result.stdout
    assert compose_calls(lines)[-1] == "compose -f compose.yaml run --rm lab _wipe"


# ---------------------------------------------------------------------------------------------------------------------
# Final review: claims flags pass through, and the openai upstream never outlives its key
# ---------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("order", ["flag_last", "flag_first"])
def test_claims_path_keeps_require_signed_in_any_position(bundle, tmp_path, order):
    # Dropping the flag would turn the signing gate into an unsigned check that can still print DONE.
    scan = tmp_path / "recording"
    scan.mkdir()
    args = [str(scan), "--require-signed"] if order == "flag_last" else ["--require-signed", str(scan)]
    result, lines = run(bundle, "claims", "check", *args)
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == [
        f"compose -f compose.yaml run --rm -v {scan}:/scan:ro lab claims check /scan --require-signed"]


def test_claims_flags_pass_through_without_a_path(bundle):
    result, lines = run(bundle, "claims", "check", "--require-signed", "--digest")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines) == ["compose -f compose.yaml run --rm lab claims check --require-signed --digest"]


@pytest.mark.parametrize("bad", [["--ledger", "x"], ["--require-signd"], ["-s"], ["a", "b"]])
def test_claims_refuses_what_it_cannot_pass_through(bundle, tmp_path, bad):
    # --ledger names a host path the container can't see, a typo would vanish, and a second path has nowhere to go.
    for name in ("a", "b", "x"):
        (tmp_path / name).mkdir(exist_ok=True)
    result, lines = run(bundle, "claims", "check", *bad, cwd=tmp_path)
    assert result.returncode == 2, result.stdout
    assert result.stdout.startswith("NOT YET:")
    assert compose_calls(lines) == []


def test_claims_refuses_a_path_with_a_colon(bundle, tmp_path):
    # docker's -v splits on the colon, so the mount would name another path.
    scan = tmp_path / "a:b"
    scan.mkdir()
    result, lines = run(bundle, "claims", "check", str(scan))
    assert result.returncode == 2
    assert compose_calls(lines) == []


def test_up_refuses_the_openai_upstream_without_the_key(bundle):
    (bundle / ".env").write_text("LAB_CLIENT_TOKEN=x\nACS_UPSTREAM=openai\n", encoding="utf-8")
    result, lines = run(bundle, "up")
    assert result.returncode == 2
    assert "NOT YET:" in result.stdout and "./lab.sh upstream replay" in result.stdout
    assert compose_calls(lines) == []


def test_reset_deleting_the_key_sets_the_upstream_back_to_replay(bundle):
    _with_model_key(bundle)
    (bundle / ".env").write_text("ACS_UPSTREAM=openai\n", encoding="utf-8")
    result, lines = run(bundle, "reset", "--delete-model-key")
    assert result.returncode == 0, result.stderr
    calls = compose_calls(lines)
    assert calls[0] == "compose -f compose.yaml -f compose.openai.yaml run --rm lab _set upstream replay"
    assert calls[-1].endswith("run --rm lab _wipe --delete-model-key")


def test_reset_keeping_the_key_keeps_the_upstream(bundle):
    _with_model_key(bundle)
    (bundle / ".env").write_text("ACS_UPSTREAM=openai\n", encoding="utf-8")
    result, lines = run(bundle, "reset")
    assert result.returncode == 0, result.stderr
    assert not [c for c in compose_calls(lines) if "_set" in c]


@pytest.mark.parametrize("lose", ["env line", "empty value", "token file"])
def test_up_refuses_without_the_client_token(bundle, lose):
    # Without it FinBot starts with an empty key and every model call gets a 401, so up says so before starting.
    if lose == "env line":
        (bundle / ".env").write_text("ACS_MODE=enforce\n", encoding="utf-8")
    elif lose == "empty value":
        (bundle / ".env").write_text("LAB_CLIENT_TOKEN=\n", encoding="utf-8")
    else:
        (bundle / "state" / "secrets" / "client.token").unlink()
    result, lines = run(bundle, "up")
    assert result.returncode == 1
    assert "NOT YET:" in result.stdout and "./lab.sh init --force" in result.stdout
    assert compose_calls(lines) == []


# ---------------------------------------------------------------------------------------------------------------------
# LAB-16 (issue #589): lab run and lab record reset FinBot first, and capture never stays on
# ---------------------------------------------------------------------------------------------------------------------

FINBOT_VOLUMES = ("acs-finbot-lab_finbot-data", "acs-finbot-lab_finbot-uploads", "acs-finbot-lab_finbot-cache",
                  "acs-finbot-lab_redis-data")
CAPTURE_FILES = "compose -f compose.yaml -f compose.openai.yaml -f replay/compose.capture.yaml"


def _volume_rm(call: str) -> list[str]:
    words = call.split()
    assert words[:2] == ["volume", "rm"], call
    return [w for w in words[2:] if not w.startswith("-")]


def test_run_resets_finbot_before_driving(bundle):
    # FinBot's integer vendor and invoice ids reach the model, and replay matches exact text, so every run starts
    # FinBot from empty volumes and the ids repeat (LAB-16 open question 2).
    result, lines = run(bundle, "run", "s2")
    assert result.returncode == 0, result.stderr
    calls = [argv(line) for line in lines if argv(line).startswith(("compose ", "volume "))]
    assert calls[0] == "compose -f compose.yaml rm --stop --force finbot redis"
    assert sorted(_volume_rm(calls[1])) == sorted(FINBOT_VOLUMES)
    assert calls[2] == "compose -f compose.yaml up -d --wait finbot"
    assert calls[3] == "compose -f compose.yaml run --rm lab _drive s2"
    assert len(calls) == 4


def test_run_passes_only_allowlisted_flags(bundle):
    result, lines = run(bundle, "run", "s4a", "--answer", "reject")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[-1] == "compose -f compose.yaml run --rm lab _drive s4a --answer reject"
    result, lines = run(bundle, "run", "s6", "--clean")
    assert result.returncode == 0, result.stderr
    assert compose_calls(lines)[-1] == "compose -f compose.yaml run --rm lab _drive s6 --clean"


@pytest.mark.parametrize("args", [["s9"], ["s2;id"], ["s2", "--foo"], [], ["s7"], ["s1c"], ["S2"], ["s2", "s3"],
                                  ["s4a", "--answer"], ["s4a", "--answer", "maybe"], ["s2", "--clean", "--clean"],
                                  ["s4a", "--answer", "approve", "--answer", "reject"], ["s2 "], ["../s2"]])
def test_run_refuses_unknown_scenario_and_flags(bundle, args):
    result, lines = run(bundle, "run", *args)
    assert result.returncode == 2, result.stdout
    assert result.stdout.startswith("NOT YET:")
    # Refused before Docker runs, so attendee text never reaches a docker argument.
    assert lines == []


@pytest.mark.parametrize("verb", ["_drive", "_epoch", "_set", "_wipe", "_anything"])
def test_underscore_verbs_refused_from_the_host(bundle, verb):
    # Only lab run reaches the driver, because only run resets FinBot first. The CLI's internal verbs stay inside
    # lab.sh, which calls them through its lab function and never through this table.
    result, lines = run(bundle, verb, "s1")
    assert result.returncode == 2
    assert result.stdout.splitlines() == [
        "NOT YET: verbs that start with _ are the lab's own. To run a scenario, use ./lab.sh run <scenario>."]
    assert lines == []


def test_run_refuses_without_the_client_token(bundle):
    # The reset starts FinBot, so it needs what up needs: without the token every model call gets a 401.
    (bundle / ".env").write_text("ACS_LAB_MODE=enforce\n", encoding="utf-8")
    result, lines = run(bundle, "run", "s1")
    assert result.returncode == 1
    assert "./lab.sh init --force" in result.stdout
    assert compose_calls(lines) == []


# Rock 2026-11-19: the OpenAI key lives in pass as openai/api-key. A fake pass stands in for it, and PATH holds only
# the test's bin directory, so the real pass is never reachable from these tests. The fake is a sh script, so under
# an exported SHELLOPTS=xtrace it traces its own key to stderr, as the real pass, a bash script, would.
FAKE_KEY = "sk-fake-lab16-test-0000"
FAKE_PASS = f"""#!/bin/sh
printf '%s\\n' "$*" >> "${{FAKE_PASS_LOG:?}}"
key="{FAKE_KEY}"
case "${{FAKE_PASS_MODE:-}}" in
    fail) echo "Error: openai/api-key is not in the password store." >&2; exit 1 ;;
    tree) printf '%s\\n' "openai/api-key" "|-- one" "\\`-- two"; exit 0 ;;
    spaces) printf '%s\\n' "sk-has a space"; exit 0 ;;
    other) printf '%s\\n' "ghp_not_an_openai_key"; exit 0 ;;
esac
[ "$*" = "show openai/api-key" ] || exit 1
printf '%s\\n' "$key" "url: platform.openai.example"
"""
# A docker that logs the take's variables with each call, which the shared fake doesn't, answers `ps -q acs-gateway`
# as a running lab would when FAKE_GATEWAY_UP=1, and notes the key file while `lab _drive` runs.
SPY_DOCKER = """#!/bin/sh
printf '%s | %s | %s\\n' "${{LAB_CAPTURE_SCENARIO:-}}" "${{LAB_CAPTURE_KEY_FILE:-}}" "$*" >> "{spy}.env"
"{fake}" "$@" || exit $?
case "$*" in
    *" ps -q acs-gateway")
        [ "${{FAKE_PS_FAIL:-}}" = 1 ] && exit 1
        [ "${{FAKE_GATEWAY_UP:-}}" = 1 ] && echo 0123456789ab ;;
    *" lab _wipe"*) rm -f state/capture-take ;;
    *" _drive "*)
        key=${{LAB_CAPTURE_KEY_FILE:-/absent}}
        if [ -f "$key" ]; then
            {{ ls -l "$key" | cut -c1-10; ls -ld "${{key%/*}}" | cut -c1-10; }} > "{spy}"
        else
            echo absent > "{spy}"
        fi
        {extra} ;;
esac
exit 0
"""
SHELL_TOOLS = ("ls", "cut", "chmod", "sleep", "mktemp", "rmdir", "cp", "date", "bash", "dash")


def _recorder(bundle: Path, extra: str = ":", with_pass: bool = True) -> Path:
    bin_dir = _bin(bundle.parent, False)
    for tool in SHELL_TOOLS:
        found = shutil.which(tool)
        if found and not (bin_dir / tool).exists():
            (bin_dir / tool).symlink_to(found)
    spy = bundle.parent / "spy"
    (bin_dir / "docker").write_text(SPY_DOCKER.format(fake=FAKE / "docker", spy=spy, extra=extra), encoding="utf-8")
    (bin_dir / "docker").chmod(0o755)
    if with_pass:
        (bin_dir / "pass").write_text(FAKE_PASS, encoding="utf-8")
        (bin_dir / "pass").chmod(0o755)
    elif (bin_dir / "pass").exists():
        (bin_dir / "pass").unlink()
    (bundle.parent / "tmp").mkdir(exist_ok=True)
    return spy


def _record_env(bundle: Path, env: dict[str, str] | None = None) -> dict[str, str]:
    # TMPDIR inside the test's own directory, so a take's key directory never lands in the real temp directory.
    full = {"FAKE_PASS_LOG": str(bundle.parent / "pass.log"), "TMPDIR": str(bundle.parent / "tmp") + "/"}
    full.update(env or {})
    return full


def record(bundle: Path, *args: str, env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess,
                                                                                 list[str]]:
    return run(bundle, "record", *args, docker=False, env=_record_env(bundle, env))


def _invoke(bundle: Path, shell: list[str], *args: str, env: dict[str, str] | None = None
            ) -> tuple[subprocess.CompletedProcess, list[str]]:
    # As run(), with the shell and its options chosen by the test.
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    full = {"PATH": str(bundle.parent / "bin"), "FAKE_DOCKER_LOG": str(log), "HOME": str(bundle.parent),
            **_record_env(bundle, env)}
    result = subprocess.run([*shell, str(bundle / "lab.sh"), *args], cwd=bundle, env=full, capture_output=True,
                            text=True, timeout=60)
    return result, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def _spy_calls(spy: Path) -> list[list[str]]:
    return [line.split(" | ", 2) for line in Path(f"{spy}.env").read_text(encoding="utf-8").splitlines()]


def _key_file(bundle: Path) -> Path:
    return bundle / "state" / "secrets" / "openai.key"


def _take_dirs(bundle: Path) -> list[Path]:
    return sorted((bundle.parent / "tmp").glob("acs-lab-take.*"))


def _marker(bundle: Path) -> Path:
    return bundle / "state" / "capture-take"


def _never_shown(result: subprocess.CompletedProcess, lines: list[str]) -> None:
    for text in (result.stdout, result.stderr, "\n".join(lines)):
        assert FAKE_KEY not in text


def _nothing_left(bundle: Path) -> None:
    assert _take_dirs(bundle) == [] and not _marker(bundle).exists() and not _key_file(bundle).exists()


def test_record_needs_openai_key_and_a_new_stem(bundle):
    # The key comes from pass. With no pass, or a pass that can't give it, nothing starts and no key is left.
    _recorder(bundle, with_pass=False)
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 2 and result.stdout.startswith("NOT YET:") and "pass" in result.stdout
    assert lines == []
    _nothing_left(bundle)
    _recorder(bundle)
    result, lines = record(bundle, "s2__off", "s2", env={"FAKE_PASS_MODE": "fail"})
    assert result.returncode == 2 and "openai/api-key" in result.stdout
    assert lines == []
    _nothing_left(bundle)
    # A recording by that name already exists, and capture never writes over one. pass is never asked.
    recordings = bundle / "replay" / "recordings"
    recordings.mkdir(parents=True, exist_ok=True)
    (recordings / "s2__off.jsonl").write_text("{}\n", encoding="utf-8")
    (bundle.parent / "pass.log").unlink(missing_ok=True)
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 2 and "replay/recordings/s2__off.jsonl" in result.stdout
    assert lines == [] and not (bundle.parent / "pass.log").exists()


@pytest.mark.parametrize("mode", ["tree", "spaces", "other"])
def test_record_refuses_a_pass_entry_that_is_not_a_key(bundle, mode):
    # `pass show` on a folder prints a tree and exits 0. Its first line must never become the key (review M4).
    _recorder(bundle)
    result, lines = record(bundle, "s2__off", "s2", env={"FAKE_PASS_MODE": mode})
    assert result.returncode == 2 and result.stdout.startswith("NOT YET:") and "sk-" in result.stdout
    assert compose_calls(lines) == []
    _nothing_left(bundle)


def test_record_refuses_a_standing_model_key_file(bundle):
    # The key's home is pass, so a plaintext copy in state/ is one to delete, not to move or keep (review I4).
    _recorder(bundle)
    _with_model_key(bundle)
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 2 and "state/secrets/openai.key" in result.stdout
    assert "Delete it" in result.stdout and "Move" not in result.stdout
    assert lines == [] and _key_file(bundle).read_text(encoding="utf-8") == "sk-x\n"


def test_record_refuses_the_standing_openai_upstream(bundle):
    # The take's key exists only during the take, so a gateway left on the openai upstream couldn't be recreated
    # after it, and capture would stay on. record turns openai on for the take only.
    _recorder(bundle)
    (bundle / ".env").write_text("LAB_CLIENT_TOKEN=x\nACS_UPSTREAM=openai\n", encoding="utf-8")
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 2 and "./lab.sh upstream replay" in result.stdout
    assert lines == []


@pytest.mark.parametrize("args", [["s2__off"], ["../x", "s2"], ["a b", "s2"], ["x" * 65, "s2"], ["", "s2"],
                                  ["s2__off", "s9"], ["s2__off", "s2", "--foo"], ["s2__off", "s2", "--capture", "y"]])
def test_record_refuses_bad_stems_scenarios_and_flags(bundle, args):
    _recorder(bundle)
    result, lines = record(bundle, *args)
    assert result.returncode == 2, result.stdout
    assert result.stdout.startswith("NOT YET:")
    assert lines == [] and not (bundle.parent / "pass.log").exists()


@pytest.mark.parametrize("verb", [["run", "s2"], ["record", "s2__off", "s2"]])
def test_reset_refuses_another_compose_project_name(bundle, verb):
    # The volume names follow the project name. Under another one the reset would remove nothing, FinBot would
    # keep its ids, and replay would miss with no error (review M1).
    _recorder(bundle)
    result, lines = run(bundle, *verb, docker=False, env=_record_env(bundle, {"COMPOSE_PROJECT_NAME": "other"}))
    assert result.returncode == 2 and "COMPOSE_PROJECT_NAME" in result.stdout
    assert lines == []
    result, _ = run(bundle, *verb, docker=False,
                    env=_record_env(bundle, {"COMPOSE_PROJECT_NAME": "acs-finbot-lab"}))
    assert result.returncode == 0, result.stdout


def test_record_captures_then_turns_capture_off(bundle):
    spy = _recorder(bundle)
    result, lines = record(bundle, "s6__clean", "s6", "--clean")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [argv(line) for line in lines if argv(line).startswith(("compose ", "volume "))]
    assert calls[0] == f"{CAPTURE_FILES} up -d --wait --no-deps acs-gateway"
    assert calls[1] == f"{CAPTURE_FILES} rm --stop --force finbot redis"
    assert sorted(_volume_rm(calls[2])) == sorted(FINBOT_VOLUMES)
    # Every call in the capture window names the overlay, so starting FinBot can't recreate the gateway without it.
    assert calls[3] == f"{CAPTURE_FILES} up -d --wait finbot"
    assert calls[4] == f"{CAPTURE_FILES} run --rm lab _drive s6 --clean --capture s6__clean"
    # Back on the replay upstream, which holds no key.
    assert calls[5] == "compose -f compose.yaml up -d --wait --no-deps acs-gateway"
    assert len(calls) == 6
    seen = _spy_calls(spy)
    window = [(stem, key) for stem, key, call in seen if call.startswith(CAPTURE_FILES)]
    assert len(window) == 4 and {stem for stem, _ in window} == {"s6__clean"}
    # The take's key sits in its own owner-only directory outside the bundle, which the lab container mounts whole,
    # so the driver can't read it (review I3).
    keys = {key for _, key in window}
    assert len(keys) == 1
    key = Path(keys.pop())
    assert key.name == "openai.key" and key.parent.name.startswith("acs-lab-take.")
    assert key.parent.parent == bundle.parent / "tmp"
    assert bundle not in key.parents
    assert seen[-1] == ["", "", "compose -f compose.yaml up -d --wait --no-deps acs-gateway"]
    assert spy.read_text(encoding="utf-8").split() == ["-rw-------", "drwx------"]
    # The recordings directory exists before the gateway mounts it, so Docker never makes it as root.
    assert (bundle / "replay" / "recordings").is_dir()
    _nothing_left(bundle)
    assert (bundle.parent / "pass.log").read_text(encoding="utf-8") == "show openai/api-key\n"
    _never_shown(result, lines)


def test_record_writes_only_the_first_line_of_the_pass_entry(bundle):
    # pass entries often carry a URL or notes after the password line, which the gateway would read as the key.
    _recorder(bundle, extra=f'cp "$key" "{bundle.parent}/seen"')
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (bundle.parent / "seen").read_text(encoding="utf-8") == FAKE_KEY + "\n"
    _never_shown(result, lines)


SHELLS = [name for name in ("sh", "bash", "dash") if shutil.which(name)]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("trace", ["-x", "SHELLOPTS"])
def test_record_never_traces_the_key(bundle, shell, trace):
    # Review I1: under xtrace a shell prints every assignment and argument it expands, so the key never sits in a
    # shell variable or an argument, and pass's own stderr, which would carry its trace, never reaches the terminal.
    _recorder(bundle)
    if trace == "-x":
        result, lines = _invoke(bundle, [shell, "-x"], "record", "s2__off", "s2")
    else:
        result, lines = _invoke(bundle, [shell], "record", "s2__off", "s2", env={"SHELLOPTS": "xtrace"})
    assert result.returncode == 0, result.stdout + result.stderr
    if trace == "-x":
        assert "+ " in result.stderr, "xtrace was not on, so this run proves nothing"
    _never_shown(result, lines)
    _nothing_left(bundle)


def test_record_turns_capture_off_on_every_exit(bundle):
    # A run that breaks halfway through a capture still turns capture off and deletes the key.
    spy = _recorder(bundle, extra="exit 7")
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode == 7, result.stdout
    calls = compose_calls(lines)
    assert calls[-2] == f"{CAPTURE_FILES} run --rm lab _drive s2 --capture s2__off"
    assert calls[-1] == "compose -f compose.yaml up -d --wait --no-deps acs-gateway"
    assert _spy_calls(spy)[-1] == ["", "", "compose -f compose.yaml up -d --wait --no-deps acs-gateway"]
    _nothing_left(bundle)
    _never_shown(result, lines)


def test_record_deletes_the_key_when_the_gateway_never_starts(bundle):
    _recorder(bundle)
    bin_dir = bundle.parent / "bin"
    spy = (bin_dir / "docker").read_text(encoding="utf-8")
    (bin_dir / "docker").write_text(spy.replace('"$@" || exit $?\n',
                                                '"$@" || exit $?\ncase "$*" in *capture.yaml*"--no-deps acs-gateway"*) exit 1 ;; esac\n',
                                                1), encoding="utf-8")
    result, lines = record(bundle, "s2__off", "s2")
    assert result.returncode != 0
    assert compose_calls(lines)[-1] == "compose -f compose.yaml up -d --wait --no-deps acs-gateway"
    _nothing_left(bundle)


def _start_take(bundle: Path, shell: str) -> tuple[subprocess.Popen, Path]:
    marker = bundle.parent / "driving"
    _recorder(bundle, extra=f': > "{marker}"; sleep 30')
    log = bundle.parent / "docker.log"
    log.write_text("", encoding="utf-8")
    env = {"PATH": str(bundle.parent / "bin"), "FAKE_DOCKER_LOG": str(log), "HOME": str(bundle.parent),
           **_record_env(bundle)}
    proc = subprocess.Popen([shell, str(bundle / "lab.sh"), "record", "s2__off", "s2"], cwd=bundle, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    import time

    deadline = time.monotonic() + 20
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert marker.exists(), "the driver never started"
    return proc, log


@pytest.mark.parametrize("shell", [name for name in ("sh", "dash") if shutil.which(name)])
@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_record_turns_capture_off_on_a_signal(bundle, shell, signame):
    # Ctrl-C, a kill and a closed terminal are the likeliest ends of a take. dash skips the EXIT trap on a signal it
    # has no trap for, so each one gets its own (review I2).
    import signal

    proc, log = _start_take(bundle, shell)
    os.killpg(proc.pid, getattr(signal, signame))
    out, err = proc.communicate(timeout=30)
    assert proc.returncode != 0
    lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    assert compose_calls(lines)[-1] == "compose -f compose.yaml up -d --wait --no-deps acs-gateway"
    _nothing_left(bundle)
    assert FAKE_KEY not in out + err


CLEANED = "Cleaned up an interrupted capture take"


def _leftover_take(bundle: Path) -> Path:
    # What a take killed with SIGKILL, or cut off by a crash or power loss, leaves behind.
    take = bundle.parent / "tmp" / "acs-lab-take.AbC123"
    take.mkdir(parents=True, mode=0o700)
    (take / "openai.key").write_text(FAKE_KEY + "\n", encoding="utf-8")
    _marker(bundle).write_text(f"{take}\n", encoding="utf-8")
    return take


# Every verb in lab.sh's dispatch table but help, so a verb added later is covered by the one call in the dispatch.
DISPATCH_VERBS = [["init"], ["up"], ["down"], ["reset"], ["doctor"], ["logs"], ["mode", "off"],
                  ["upstream", "replay"], ["sign", "hmac"], ["traces", "off"], ["claims", "check"], ["run", "s1"],
                  ["record", "s2__new", "s2"], ["check", "1"]]
STOPPING = (["down"], ["reset"])


def test_the_dispatch_table_is_covered(bundle):
    # The verbs the case statement names, so a new one fails here until DISPATCH_VERBS lists it.
    text = (bundle / "lab.sh").read_text(encoding="utf-8")
    table = text[text.index('case $verb in'):]
    named = set(re.findall(r"(?m)^    ([a-z][a-z |_-]*)\)", table))
    verbs = {v.strip() for group in named for v in group.split("|")} - {"help", "-h", "--help"}
    # init and check go through the table's catch-all branch, which DISPATCH_VERBS covers with both.
    assert verbs == {v[0] for v in DISPATCH_VERBS} - {"init", "check"}


@pytest.mark.parametrize("verb", DISPATCH_VERBS, ids=lambda v: v[0])
def test_every_verb_cleans_up_an_interrupted_take(bundle, verb):
    # Review I4 and R1: nothing can trap SIGKILL, so lab.sh's dispatch finds the take's marker before any verb runs,
    # deletes its key and puts the gateway back on replay. The spy's _wipe erases the marker as the real one does,
    # so reset proves the cleanup runs before the wipe.
    _recorder(bundle)
    take = _leftover_take(bundle)
    result, lines = run(bundle, *verb, docker=False, env=_record_env(bundle, {"FAKE_GATEWAY_UP": "1"}))
    assert result.stdout.splitlines()[0].startswith(CLEANED), result.stdout + result.stderr
    assert not (take / "openai.key").exists() and not take.exists()
    calls = compose_calls(lines)
    if verb in STOPPING:
        assert "ps -q acs-gateway" not in " ".join(calls)
        assert "put the gateway back" not in result.stdout
    else:
        assert calls[:2] == ["compose -f compose.yaml ps -q acs-gateway",
                             "compose -f compose.yaml up -d --wait --no-deps acs-gateway"]
        assert result.stdout.splitlines()[0] == (f"{CLEANED}: deleted its model key and put the gateway back on "
                                                 "replay.")
    _nothing_left(bundle)
    _never_shown(result, lines)


@pytest.mark.parametrize("verb", [[], ["help"], ["--help"]])
def test_help_leaves_a_take_for_the_next_real_command(bundle, verb):
    _recorder(bundle)
    take = _leftover_take(bundle)
    result, lines = run(bundle, *verb, docker=False, env=_record_env(bundle))
    assert result.returncode == 0 and CLEANED not in result.stdout
    assert lines == [] and (take / "openai.key").exists()


def test_cleanup_says_what_it_did_when_docker_is_down(bundle):
    # Review m3: after a power cut Docker may not answer yet. The key is gone either way, and a gateway that comes
    # back can't find its key's bind source, so it goes back on replay at the next up.
    _recorder(bundle)
    _leftover_take(bundle)
    result, lines = run(bundle, "logs", docker=False, env=_record_env(bundle, {"FAKE_PS_FAIL": "1"}))
    first = result.stdout.splitlines()[0]
    assert first == (f"{CLEANED}: deleted its model key. Docker isn't answering, so the gateway goes back on replay "
                     "at the next ./lab.sh up.")
    assert "up -d --wait --no-deps acs-gateway" not in " ".join(compose_calls(lines))
    _nothing_left(bundle)


def test_cleanup_says_so_when_the_key_was_already_gone(bundle):
    _recorder(bundle)
    take = _leftover_take(bundle)
    (take / "openai.key").unlink()
    take.rmdir()
    result, _ = run(bundle, "logs", docker=False, env=_record_env(bundle))
    assert result.stdout.splitlines()[0] == f"{CLEANED}: its model key was already gone, and the gateway wasn't running."
    _nothing_left(bundle)


@pytest.mark.parametrize("tmpdir", ["relative", "in-bundle", "in-state"])
def test_record_refuses_a_temp_dir_in_the_cli_containers_reach(bundle, tmpdir):
    # Review m1: the lab container mounts the bundle whole, so a take directory under it would put the key in the
    # driver's reach, and under state/ in the Guardian's and the viewer's too.
    _recorder(bundle)
    (bundle / "state" / "tmp").mkdir()
    (bundle / "tmpx").mkdir()
    value = {"relative": "tmpx", "in-bundle": str(bundle / "tmpx") + "/",
             "in-state": str(bundle / "replay" / ".." / "state" / "tmp")}[tmpdir]
    result, lines = record(bundle, "s2__off", "s2", env={"TMPDIR": value})
    assert result.returncode == 2 and result.stdout.startswith("NOT YET:") and "TMPDIR" in result.stdout
    assert lines == [] and not _marker(bundle).exists()
    assert not list(bundle.rglob("acs-lab-take.*"))
    assert not (bundle.parent / "pass.log").exists()


def test_record_falls_back_to_tmp_without_tmpdir(bundle):
    spy = _recorder(bundle)
    env = _record_env(bundle)
    del env["TMPDIR"]
    result, lines = run(bundle, "record", "s2__off", "s2", docker=False, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    keys = {key for _, key, call in _spy_calls(spy) if key}
    assert len(keys) == 1
    key = Path(keys.pop())
    assert key.parent.parent == Path("/tmp").resolve() and key.parent.name.startswith("acs-lab-take.")
    assert not key.parent.exists()
    _never_shown(result, lines)


def test_record_refuses_a_planted_marker_symlink(bundle, tmp_path):
    # Review m2: the gateway, the Guardian and the CLI can all write to state/, so a dangling link planted at the
    # marker's path is refused, and nothing is written through it.
    _recorder(bundle)
    target = tmp_path / "written-through"
    _marker(bundle).symlink_to(target)
    for verb in (["record", "s2__off", "s2"], ["up"]):
        result, lines = run(bundle, *verb, docker=False, env=_record_env(bundle))
        assert result.returncode == 2 and result.stdout.startswith("NOT YET:"), result.stdout
        assert "state/capture-take" in result.stdout and "Delete" in result.stdout
        assert lines == []
    assert not target.exists()
    assert _take_dirs(bundle) == []


def test_record_writes_the_marker_with_no_clobber(bundle):
    # A marker that appears between the cleanup and the write is refused, never overwritten.
    _recorder(bundle, extra=":")
    lab_sh = (bundle / "lab.sh").read_text(encoding="utf-8")
    assert "set -C" in lab_sh[lab_sh.index("TAKE_DIR=$(mktemp"):lab_sh.index("write_model_key\n    CAPTURE")]


def test_cleanup_refuses_a_take_dir_that_is_a_symlink(bundle, tmp_path):
    # Following a linked take directory would delete openai.key in whatever the link points at.
    _recorder(bundle)
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "openai.key").write_text("keep\n", encoding="utf-8")
    link = bundle.parent / "tmp" / "acs-lab-take.LnK123"
    link.symlink_to(real)
    _marker(bundle).write_text(f"{link}\n", encoding="utf-8")
    result, lines = run(bundle, "up", docker=False, env=_record_env(bundle))
    assert result.returncode == 2 and result.stdout.startswith("NOT YET:")
    assert str(link) in result.stdout and "Delete" in result.stdout
    assert lines == []
    assert (real / "openai.key").read_text(encoding="utf-8") == "keep\n"


def test_cleanup_leaves_a_stopped_lab_stopped(bundle):
    # With no gateway running there is no capture to turn off, so cleanup starts nothing of its own.
    _recorder(bundle)
    _leftover_take(bundle)
    result, lines = run(bundle, "mode", "off", docker=False, env=_record_env(bundle))
    assert result.returncode == 0, result.stdout
    assert compose_calls(lines)[:2] == ["compose -f compose.yaml ps -q acs-gateway",
                                        "compose -f compose.yaml run --rm lab _set mode off"]
    _nothing_left(bundle)


@pytest.mark.parametrize("target", ["other-parent", "wrong-name", "relative"])
def test_cleanup_deletes_only_a_take_directory(bundle, tmp_path, target):
    # state/ is writable by the gateway, so a marker naming any path but a take directory in the temp directory is
    # refused, never followed.
    _recorder(bundle)
    other = {"other-parent": tmp_path / "elsewhere" / "acs-lab-take.AbC123",
             "wrong-name": bundle.parent / "tmp" / "keep",
             "relative": Path("acs-lab-take.AbC123")}[target]
    if other.is_absolute():
        other.mkdir(parents=True)
        (other / "openai.key").write_text("keep\n", encoding="utf-8")
    _marker(bundle).write_text(f"{other}\n", encoding="utf-8")
    result, lines = run(bundle, "up", docker=False, env=_record_env(bundle))
    assert result.returncode == 2 and result.stdout.startswith("NOT YET:")
    assert "state/capture-take" in result.stdout
    assert lines == []
    if other.is_absolute():
        assert (other / "openai.key").read_text(encoding="utf-8") == "keep\n"


def test_a_killed_take_is_cleaned_up_by_the_next_command(bundle):
    import signal

    proc, _ = _start_take(bundle, "sh")
    os.killpg(proc.pid, signal.SIGKILL)
    proc.communicate(timeout=30)
    assert _marker(bundle).exists() and len(_take_dirs(bundle)) == 1
    result, lines = run(bundle, "up", docker=False, env=_record_env(bundle, {"FAKE_GATEWAY_UP": "1"}))
    assert result.returncode == 0, result.stdout
    assert result.stdout.startswith(CLEANED)
    _nothing_left(bundle)


def test_command_table_lists_module_verbs(bundle):
    result, lines = run(bundle, "help")
    assert result.returncode == 0, result.stderr
    table = result.stdout
    for verb in ("run", "record", "check", "policy", "forge", "verify", "downgrade"):
        assert re.search(rf"(?m)^  {verb}\b", table), verb
    assert compose_calls(lines) == []
