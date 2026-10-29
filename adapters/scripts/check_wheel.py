"""Install a built acs-adapters wheel outside the repository and check what users depend on.

Usage: python scripts/check_wheel.py dist/acs_adapters-<version>-py3-none-any.whl

Needs `uv` on PATH. Each check runs in a fresh virtual environment in a
temporary directory, with that directory as the working directory, so
nothing resolves from the source tree.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_SCHEMAS = Path(__file__).resolve().parents[2] / "specification" / "v0.1.0"
SCRIPTS = ("acs-claude-code-hook", "acs-claude-code-wire", "acs-cursor-hook",
           "acs-cursor-wire", "acs-nat-wire", "acs-example-guardian")
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def venv(root: Path, wheel: Path, extras: str) -> Path:
    env_dir = root / f"venv{extras or '-base'}"
    subprocess.run(["uv", "venv", "-q", "--python", sys.executable, str(env_dir)], check=True)
    py = env_dir / "bin" / "python"
    subprocess.run(["uv", "pip", "install", "-q", "--python", str(py), f"{wheel}{extras}"], check=True)
    return env_dir


def run(cmd: list[str], cwd: Path, **kw) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("ACS_SPEC_DIR", "PYTHONPATH", "VIRTUAL_ENV")}
    env.update(kw.pop("env", {}))
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=120, **kw)


def base_checks(env_dir: Path, wheel_version: str, cwd: Path) -> None:
    py, bindir = str(env_dir / "bin" / "python"), env_dir / "bin"
    p = run([py, "-c", "import acs; print(acs.__version__)"], cwd)
    check("package version matches the wheel", p.stdout.strip() == wheel_version, p.stdout + p.stderr)

    p = run([py, "-c", "from acs.core import schemas_dir; print(schemas_dir())"], cwd)
    bundled = Path(p.stdout.strip()) if p.returncode == 0 else None
    check("schemas resolve from the installed package",
          bundled is not None and env_dir.resolve() in bundled.resolve().parents, p.stdout + p.stderr)
    if bundled is not None:
        want = {f.relative_to(REPO_SCHEMAS): f.read_bytes() for f in REPO_SCHEMAS.rglob("*") if f.is_file()}
        got = {f.relative_to(bundled): f.read_bytes() for f in bundled.rglob("*") if f.is_file()}
        check("bundled schemas are byte-identical to specification/v0.1.0", want == got,
              f"{len(got)} bundled, {len(want)} in the repository")

    p = run([py, "-c", "import json; from importlib.metadata import entry_points as e; "
             "print(json.dumps(sorted(x.name for x in e(group='acs.integrations'))))"], cwd)
    check("acs.integrations lists claude_code, cursor and nat",
          p.returncode == 0 and json.loads(p.stdout) == ["claude_code", "cursor", "nat"], p.stdout + p.stderr)

    for script in SCRIPTS:
        check(f"{script} is installed", (bindir / script).is_file())
    for script, label in (("acs-claude-code-hook", "claude-code"), ("acs-cursor-hook", "cursor")):
        p = run([str(bindir / script), "--version"], cwd)
        check(f"{script} --version", p.returncode == 0 and f"({label}) {wheel_version}" in p.stdout, p.stdout + p.stderr)
    for script in ("acs-claude-code-wire", "acs-cursor-wire"):
        p = run([str(bindir / script), "--help"], cwd)
        check(f"{script} --help", p.returncode == 0, p.stderr[-300:])

    event = json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                        "tool_input": {"command": "ls"}})
    p = run([str(bindir / "acs-claude-code-hook")], cwd, input=event, env={"ACS_DISABLED": "1"})
    check("the kill switch runs and leaves an audit line",
          p.returncode == 0 and "acs_disabled_bypass" in p.stderr, p.stdout + p.stderr)

    p = run([str(bindir / "acs-example-guardian"), "--port", "0"], cwd)
    check("acs-example-guardian refuses to start without a signing secret",
          p.returncode != 0 and "REFUSING TO START" in p.stderr, p.stderr[-300:])

    guardian_env = {k: v for k, v in os.environ.items() if k != "ACS_SPEC_DIR"}
    guardian_env["ACS_HMAC_SECRET"] = "ab" * 32
    guardian = subprocess.Popen([str(bindir / "acs-example-guardian"), "--port", "0"], cwd=cwd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=guardian_env)
    announced = False
    try:
        line = guardian.stdout.readline()
        time.sleep(0.2)
        announced = re.match(r"ACS_GUARDIAN_LISTENING port=\d+", line) is not None
        check("acs-example-guardian starts and announces its port", announced, line)
    finally:
        guardian.terminate()
        _, err = guardian.communicate(timeout=10)
    # Only meaningful once the Guardian actually started and loaded its schemas.
    check("the example Guardian validates envelopes against the bundled schemas",
          announced and "validation DISABLED" not in err, err[-300:])


def nat_checks(env_dir: Path, cwd: Path) -> None:
    code = ("from nat.runtime.loader import PluginTypes, discover_and_register_plugins\n"
            "from nat.cli.type_registry import GlobalTypeRegistry\n"
            "discover_and_register_plugins(PluginTypes.COMPONENT)\n"
            "print('acs_guardian' in [r.local_name for r in GlobalTypeRegistry.get().get_registered_middleware()])\n")
    p = run([str(env_dir / "bin" / "python"), "-c", code], cwd)
    check("NAT discovers `_type: acs_guardian` from the [nat] extra",
          p.stdout.strip().splitlines()[-1:] == ["True"], p.stderr[-400:])
    p = run([str(env_dir / "bin" / "acs-nat-wire"), "--help"], cwd)
    check("acs-nat-wire --help with the [nat] extra", p.returncode == 0, p.stderr[-300:])


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    wheel = Path(argv[1]).resolve()
    wheel_version = wheel.name.split("-")[1]
    with tempfile.TemporaryDirectory(prefix="acs-wheel-check-") as tmp:
        root = Path(tmp)
        # The base install is exactly what the quickstarts install: no extras.
        base_checks(venv(root, wheel, ""), wheel_version, root)
        nat_checks(venv(root, wheel, "[nat]"), root)
    print(f"\n{'OK' if not failures else 'FAILED'}: {len(failures)} failed check(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
