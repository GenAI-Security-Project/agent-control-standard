"""The ACS runtime image and its entrypoint (issue #588, LAB-15).

These tests build labs/finbot/images/acs.Dockerfile and run it, so they need Docker. Without Docker they skip, unless
LAB_REQUIRE_DOCKER=1, which the labs workflow sets so a runner with no Docker fails instead of passing quietly.

Run from the repository root: LAB_REQUIRE_DOCKER=1 python3 -m pytest labs/finbot/images/tests -v
"""
from __future__ import annotations

import fnmatch
import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
IMAGES = ROOT / "labs" / "finbot" / "images"
DOCKERFILE = IMAGES / "acs.Dockerfile"
ENTRYPOINT = IMAGES / "entrypoint.sh"
TAG = os.environ.get("LAB_TEST_IMAGE", "acs-lab-runtime:test")
# Files the build must never carry, whatever sits in the checkout when it runs.
FORBIDDEN = ("*.key", "*.token", ".env", "guardian-keys.json", "*/state/*", "state/*")
ADAPTERS_PY = "/opt/acs/adapters/.venv/bin/python"
GATEWAY_PY = "/opt/acs/gateway/.venv/bin/python"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.fixture(scope="session")
def image() -> str:
    if not _docker_ready():
        if os.environ.get("LAB_REQUIRE_DOCKER") == "1":
            pytest.fail("LAB_REQUIRE_DOCKER=1 and Docker is not available")
        pytest.skip("Docker is not available")
    # Canaries a careless build context would copy in. Each is created only when absent and always removed.
    canaries = [ROOT / "labs" / "finbot" / "state" / "lab-canary.key", ROOT / "labs" / "finbot" / "lab-canary.token"]
    planted = []
    for path in canaries:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("canary\n", encoding="utf-8")
            planted.append(path)
    try:
        if os.environ.get("LAB_TEST_IMAGE_PREBUILT") != "1":
            subprocess.run(["docker", "build", "-f", str(DOCKERFILE), "-t", TAG, str(ROOT)], check=True)
    finally:
        for path in planted:
            path.unlink()
    return TAG


def _run(image: str, *args: str, env: dict[str, str] | None = None, mounts: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm"]
    for key, value in (env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    for mount in mounts:
        cmd += ["-v", mount]
    return subprocess.run([*cmd, image, *args], capture_output=True, text=True)


def test_entrypoint_has_no_cr():
    # A CRLF checkout would break the shebang inside the container. The image build refuses one too.
    assert b"\r" not in ENTRYPOINT.read_bytes()
    assert ENTRYPOINT.read_bytes().startswith(b"#!/bin/sh\n")


def test_entrypoint_copies_and_drops(image, tmp_path):
    secret = tmp_path / "hmac"
    secret.write_text("a" * 64 + "\n", encoding="utf-8")
    secret.chmod(0o644)
    result = _run(image, "sh", "-c", "stat -c '%a %u %g' /run/acs/hmac.key; id -u; id -g; id -G",
                  env={"LAB_UID": "4321", "LAB_GID": "4322", "LAB_SECRETS": "acs-hmac:hmac.key"},
                  mounts=(f"{secret}:/run/secrets/acs-hmac:ro",))
    assert result.returncode == 0, result.stderr
    assert result.stdout.split("\n")[:4] == ["600 4321 4322", "4321", "4322", "4322"]


def test_entrypoint_owns_state_dirs(image):
    # The gateway chmods its tmpfs state root at startup, which only its owner may do.
    result = _run(image, "sh", "-c", "stat -c '%a %u' /run/acs-state",
                  env={"LAB_UID": "4321", "LAB_GID": "4321", "LAB_STATE_DIRS": "/run/acs-state"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "700 4321"


def test_missing_secret_exits_2(image):
    result = _run(image, "true", env={"LAB_SECRETS": "acs-guardian-key:guardian.key"})
    assert result.returncode == 2
    assert "lab-entrypoint: missing secret acs-guardian-key" in result.stderr


@pytest.mark.parametrize("value", ["0", "abc", "-1", ""])
def test_bad_lab_uid_exits_2(image, value):
    # Root as the service user would undo the privilege drop, and a name instead of a number would let setpriv look
    # up an account the image never meant to use.
    result = _run(image, "true", env={"LAB_UID": value})
    assert result.returncode == 2, result.stdout + result.stderr


def test_unsafe_secret_name_exits_2(image):
    result = _run(image, "true", env={"LAB_SECRETS": "../etc/passwd:x"})
    assert result.returncode == 2
    assert "lab-entrypoint:" in result.stderr


def test_non_root_without_secrets_runs(image):
    # The viewer and the lab CLI start as the attendee's uid and hold no secret.
    result = subprocess.run(["docker", "run", "--rm", "--user", "4321:4321", image, "id", "-u"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "4321"


def test_no_secret_in_any_layer(image, tmp_path):
    archive = tmp_path / "image.tar"
    subprocess.run(["docker", "save", "-o", str(archive), image], check=True)
    found = []
    with tarfile.open(archive) as outer:
        for member in outer.getmembers():
            if not member.isfile():
                continue
            data = outer.extractfile(member).read()
            try:
                layer = tarfile.open(fileobj=io.BytesIO(data))
            except tarfile.TarError:
                continue
            with layer:
                for name in layer.getnames():
                    base = name.rsplit("/", 1)[-1]
                    if any(fnmatch.fnmatch(base, p) or fnmatch.fnmatch(name, p) for p in FORBIDDEN):
                        found.append(name)
    assert found == []


def test_guardian_starts_with_pqc(image):
    result = _run(image, "/opt/acs/adapters/.venv/bin/acs-example-guardian", "--help")
    assert result.returncode == 0, result.stderr
    for python in (ADAPTERS_PY, GATEWAY_PY):
        check = _run(image, python, "-c", "import acs.core; acs.core.ML_DSA_65; assert acs.core.ml_dsa_available()")
        assert check.returncode == 0, f"{python}: {check.stderr}"


def test_gateway_and_lab_tools_present(image):
    # acs-gateway takes no flags and would start serving, so only its presence is checked.
    result = _run(image, "sh", "-c", "test -x /opt/acs/gateway/.venv/bin/acs-gateway "
                  "&& test -f /opt/lab/docs/signature-benchmark.md && command -v setpriv")
    assert result.returncode == 0, result.stdout + result.stderr
