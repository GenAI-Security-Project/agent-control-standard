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
    for name in ("hmac.key", "guardian.key", "admin.token", "approver.token"):
        (secrets / name).write_text("x\n", encoding="utf-8")
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
