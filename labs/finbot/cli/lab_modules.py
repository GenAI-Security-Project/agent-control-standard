"""The lab CLI's module commands (issue #589, LAB-16, Appendix A.4 and A.11). Standard library only.

Version 1.0.0. Owner: Rock Lambros.

check, the scenario driver and the module 7 kit each live in their own file in the bundle, and this module loads
that file by path with importlib, the way lab pins runs policy/tools/pins.py. The path is built from a fixed table and
a validated module number, never from a name on the command line, and must resolve inside the bundle. A bundle
without the file says so and exits 2, so a lane that hasn't landed yet reads as missing rather than as a crash.

    lab check <1-7>                    modules/checks/m<n>.py check(Evidence) -> exit code
    lab policy <3-6> starter|solution  swaps the live policy file and its data patch, then bumps the epoch
    lab _drive ...                     scenarios/driver.py main(argv), handed off by lab.sh run and record
    lab forge|verify|downgrade ...     modules/kit/<name>.py main(argv)
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import report

CHECK_NUMBER = re.compile(r"[1-7]")
POLICY_MODULES = ("3", "4", "5", "6")
POLICY_VARIANTS = ("starter", "solution")
# A policy variant may set only this list in data.json. The tool registry is lab pins' to write (Task 14), and a patch
# that reached it could unpin a tool the module 6 policy checks.
PATCHABLE = ("finbot_lab", "vendor_domains")
# The value data.json ships with, which a variant without a patch puts back. LAB-12's starters assume it.
UNPATCHED: list[str] = []
# A byte copy of data.json as it ships, under tools/, which OPA ignores. A reader who breaks data.json by hand can still
# run lab policy, which puts this copy back (LAB-16 Task 8 review I2). A test holds the two files identical.
SHIPPED_DATA = "tools/data.shipped.json"
LIVE_NAME = re.compile(r"[A-Za-z0-9_]+\.rego")


def _commands() -> ModuleType:
    # Imported here, not at the top, because commands imports this module to merge COMMANDS.
    import commands
    return commands


def _load(relative: str, what: str, name: str | None = None) -> ModuleType | None:
    """The bundle file at relative, executed as a module, or None after a NOT YET line when it isn't there."""
    root = _commands().bundle().resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        report.not_yet(f"{what} isn't in this bundle")
        return None
    # Sibling files (evidence.py beside the checks, the FinBot clients beside the driver) import by name.
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    module_name = name or f"lab_bundle_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        report.not_yet(f"{what} can't be loaded from {relative}")
        return None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs, as import does. @dataclass looks the module up in sys.modules while it builds a
    # class, and on Python 3.12, the runtime image's, an unregistered module fails there (review I1).
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _broken_evidence() -> tuple[type[BaseException], ...]:
    """The errors that mean the lab's files can't be read as a run describes them, which A.11 calls broken."""
    loaded = sys.modules.get("evidence")
    error = getattr(loaded, "EvidenceError", None)
    return (OSError, error) if isinstance(error, type) else (OSError,)


def _call(fn: Callable[[], Any]) -> int:
    try:
        return _exit_code(fn())
    except _broken_evidence() as e:
        # escape keeps newlines on purpose, so the message is folded here to keep one result line (re-review N2).
        message = " ".join(str(e).splitlines())
        report.not_yet(f"the lab's evidence can't be read: {message}")
        return report.EXIT_BROKEN


def _exit_code(value: Any) -> int:
    # Anything but an A.11 code is a broken environment, never a pass.
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1, 2):
        return value
    report.not_yet(f"the command returned {value!r}, not an exit code")
    return report.EXIT_BROKEN


# ---------------------------------------------------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------------------------------------------------

def _evidence() -> Any:
    """evidence.Evidence over the bundle. Registered as the module evidence, so each check imports the same one."""
    loaded = sys.modules.get("evidence") or _load("modules/checks/evidence.py", "the run record reader", "evidence")
    return None if loaded is None else loaded.Evidence(_commands().bundle())


def cmd_check(args: list[str]) -> int:
    """check <1-7>: runs module n's check over the lab's evidence."""
    if len(args) != 1 or not CHECK_NUMBER.fullmatch(args[0]):
        report.not_yet("lab check takes one module number from 1 to 7")
        return report.EXIT_BROKEN
    number = args[0]
    module = _load(f"modules/checks/m{number}.py", f"module {number}'s check")
    if module is None:
        return report.EXIT_BROKEN
    ev = _evidence()
    if ev is None:
        return report.EXIT_BROKEN
    return _call(lambda: module.check(ev))


# ---------------------------------------------------------------------------------------------------------------------
# the driver and the kit
# ---------------------------------------------------------------------------------------------------------------------

def _runs_main(relative: str, what: str) -> Callable[[list[str]], int]:
    def run(args: list[str]) -> int:
        module = _load(relative, what)
        if module is None:
            return report.EXIT_BROKEN
        return _call(lambda: module.main(args))
    run.__doc__ = f"{what}: {relative} main(argv)."
    return run


# ---------------------------------------------------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------------------------------------------------

def _write_atomic(path: Path, data: bytes) -> None:
    """data into path through a temporary file and one rename, keeping path's mode.

    The temporary name starts with a dot and ends in .tmp, so OPA, which watches this directory for .rego and .json,
    never loads a half-written file.
    """
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _vendor_domains(patch: Any) -> list[str] | None:
    """The vendor_domains list when patch sets that and nothing else, as RFC 7386 would apply it."""
    outer, inner = PATCHABLE
    if not (isinstance(patch, dict) and list(patch) == [outer] and isinstance(patch[outer], dict)
            and list(patch[outer]) == [inner]):
        return None
    value = patch[outer][inner]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None


def _usable(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get(PATCHABLE[0]), dict)


def _live_data(policy: Path) -> tuple[dict[str, Any], bool]:
    """The live data.json, or the shipped copy when the live one is missing or isn't a finbot_lab object. The second
    value says the copy replaced it. Nothing from an unusable file is kept, since a half-right registry would deny
    tools without saying why."""
    try:
        data = json.loads((policy / "data.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if _usable(data):
        return data, False
    shipped = json.loads((policy / SHIPPED_DATA).read_text(encoding="utf-8"))
    if not _usable(shipped):
        raise ValueError(f"policy/{SHIPPED_DATA} has no finbot_lab object")
    return shipped, True


def cmd_policy(args: list[str]) -> int:
    """policy <3-6> starter|solution: puts module n's variant in place as the live policy file, applies the variant's
    data patch or puts vendor_domains back without one, then bumps the gateway epoch, since a policy reload starts the
    sessions over (A.4). Everything is checked before the first write."""
    if len(args) != 2 or args[0] not in POLICY_MODULES or args[1] not in POLICY_VARIANTS:
        report.not_yet(f"lab policy takes a module from {POLICY_MODULES[0]} to {POLICY_MODULES[-1]} and "
                       f"{' or '.join(POLICY_VARIANTS)}")
        return report.EXIT_BROKEN
    number, variant_name = args
    policy = (_commands().bundle() / "policy").resolve()
    try:
        modules = json.loads((policy / "tools" / "modules.json").read_text(encoding="utf-8"))["modules"]
        module = next(m for m in modules if m.get("id") == f"m{number}")
        variant = module["variants"][variant_name]
        live_name = module["live"]
        if not LIVE_NAME.fullmatch(live_name):
            raise ValueError(f"live file {live_name!r} is not a policy file name")
        source = (policy / variant["file"]).resolve()
        if not source.is_relative_to(policy):
            raise ValueError(f"{variant['file']} is outside the policy pack")
        rego = source.read_bytes()
        data, replaced = _live_data(policy)
        if "data_patch" in variant:
            patch_path = (policy / variant["data_patch"]).resolve()
            if not patch_path.is_relative_to(policy):
                raise ValueError(f"{variant['data_patch']} is outside the policy pack")
            domains = _vendor_domains(json.loads(patch_path.read_text(encoding="utf-8")))
            if domains is None:
                raise ValueError(f"{variant['data_patch']} may set only finbot_lab.vendor_domains, a list of names")
        else:
            domains = None
        patched_module = any("data_patch" in v for v in module["variants"].values())
        settings = data[PATCHABLE[0]]
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as e:
        report.not_yet(f"the policy pack can't switch module {number} to its {variant_name}: {e}")
        return report.EXIT_BROKEN

    # OPA may reload between the two renames, and the epoch bump follows both. The order keeps the starter's rule,
    # which reads no vendor_domains, live in between: a solution's domains go in before its rule, and a starter's
    # rule goes in before the domains go (review M1).
    writes = [(policy / live_name, rego)]
    if domains is not None or patched_module or replaced:
        if domains is not None or patched_module:
            settings[PATCHABLE[1]] = domains if domains is not None else list(UNPATCHED)
        data_write = (policy / "data.json", (json.dumps(data, indent=2) + "\n").encode("utf-8"))
        writes = [data_write, *writes] if domains is not None else [*writes, data_write]
    for path, content in writes:
        _write_atomic(path, content)
    if replaced:
        report.info("policy/data.json couldn't be read, so the lab replaced it with the copy the lab ships with")
    report.done(f"module {number} now runs its {variant_name} policy ({live_name}). OPA reloads it on its own")
    return _commands().cmd_epoch([])


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "_drive": _runs_main("scenarios/driver.py", "the scenario driver"),
    "check": cmd_check,
    "policy": cmd_policy,
    "forge": _runs_main("modules/kit/forge.py", "lab forge"),
    "verify": _runs_main("modules/kit/verify.py", "lab verify"),
    "downgrade": _runs_main("modules/kit/downgrade.py", "lab downgrade"),
}
