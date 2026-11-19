"""lab.sh, the host wrapper (issue #588, LAB-15), driven against a fake docker that logs every call.

Each test copies lab.sh into a temporary bundle, so nothing here touches the real labs/finbot/state or .env.
Run from the repository root: python3 -m pytest labs/finbot/cli/tests/test_wrappers.py -v
"""
from __future__ import annotations

import os
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
    result, _ = run(bundle, "doctor", env={"FAKE_DOCKER_FAIL_PORTS": "8000"})
    assert result.returncode == 1
    assert "NOT YET: port 8000 is in use. Set LAB_PORT_FINBOT in labs/finbot/.env" in result.stdout
    assert "DONE: port 8090 is free" in result.stdout


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
