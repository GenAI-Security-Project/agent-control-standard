"""Check the FinBot lab policy pack against tools/modules.json with real OPA.

For each module and variant, the check copies the pack's top-level policy, data.json and tests into a temporary
directory, swaps the variant in for the live module file, applies the variant's data patch (an RFC 7386 merge
patch), runs that module's test package, and compares the failing tests with the manifest's "fails" list as a set.
The guides quote those lists, so a starter that fails a different test than they say is a mismatch too. One more
check runs every test package against all solutions together, so the solutions also compose.

--verdicts also evaluates data.finbot.verdict for each scenario in tools/inputs with all solutions in place and the
registry in tools/fixtures/registry.json, then runs the example Guardian's verdict_problem on each verdict, which
needs acs-adapters:

    uv run --project adapters --locked python labs/finbot/policy/tools/check_pack.py --verdicts

Prints one DONE or NOT YET line per check. Exit 0 when every check passes, 1 on any mismatch, 2 when OPA is missing
or fails to run. The input and verdict shape are a lab convention until issue #531.
Owner: the ACS lab maintainers (issue #585).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

PACK = Path(__file__).resolve().parent.parent
TOOLS = PACK / "tools"
# Each OPA run is a few hundred milliseconds. The bound only stops a hung binary from hanging CI.
OPA_TIMEOUT_S = 120


class OpaError(RuntimeError):
    """OPA is missing, failed to run, or printed something that isn't its JSON report."""


def merge_patch(target: Any, patch: Any) -> Any:
    """RFC 7386: an object patch merges key by key, null removes a key, and anything else replaces the target."""
    if not isinstance(patch, dict):
        return patch
    merged = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = merge_patch(merged.get(key), value)
    return merged


def load_manifest() -> list[dict[str, Any]]:
    return json.loads((TOOLS / "modules.json").read_text(encoding="utf-8"))["modules"]


def assemble(directory: Path, swaps: dict[str, str], patches: list[dict[str, Any]]) -> None:
    """Copy the pack the OPA server loads, plus its tests, with each live file in swaps replaced by its variant."""
    for source in sorted(PACK.glob("*.rego")):
        variant = swaps.get(source.name)
        shutil.copyfile(PACK / variant if variant else source, directory / source.name)
    (directory / "tests").mkdir()
    for source in sorted((PACK / "tests").glob("*.rego")):
        shutil.copyfile(source, directory / "tests" / source.name)
    data = json.loads((PACK / "data.json").read_text(encoding="utf-8"))
    for patch in patches:
        data = merge_patch(data, patch)
    (directory / "data.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_opa(opa: str, args: list[str]) -> Any:
    try:
        completed = subprocess.run([opa, *args], capture_output=True, text=True, timeout=OPA_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OpaError(f"{opa} {args[0]} could not run: {e}") from None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        raise OpaError(f"{opa} {args[0]} exited {completed.returncode}: {detail[-1] if detail else 'no output'}") \
            from None


def failing_tests(opa: str, directory: Path, package: str | None) -> set[str]:
    """The names of the tests that failed or raised an error, in one package or in all of them."""
    args = ["test", str(directory), "--format", "json"]
    if package:
        args += ["--run", "^data\\." + package.replace(".", "\\.") + "\\."]
    report = run_opa(opa, args)
    if not isinstance(report, list) or not report:
        # An empty report means the package matched no test, which would pass any starter silently.
        raise OpaError(f"opa test found no tests for {package or 'the pack'}")
    prefix = "data." + package if package else ""
    return {result["name"] if package else f"{result['package']}.{result['name']}" for result in report
            if (result.get("fail") or result.get("error")) and result.get("package", "").startswith(prefix)}


def variant_swaps(modules: list[dict[str, Any]], pick: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    swaps, patches = {}, []
    for module in modules:
        variant = module["variants"].get(pick)
        if "live" in module and variant and "file" in variant:
            swaps[module["live"]] = variant["file"]
        if variant and "data_patch" in variant:
            patches.append(json.loads((PACK / variant["data_patch"]).read_text(encoding="utf-8")))
    return swaps, patches


def check_modules(opa: str, modules: list[dict[str, Any]]) -> bool:
    ok = True
    for module in modules:
        for name, variant in module["variants"].items():
            swaps = {module["live"]: variant["file"]} if "file" in variant else {}
            patches = [json.loads((PACK / variant["data_patch"]).read_text(encoding="utf-8"))] \
                if "data_patch" in variant else []
            with tempfile.TemporaryDirectory(prefix="finbot-policy-") as tmp:
                assemble(Path(tmp), swaps, patches)
                got = failing_tests(opa, Path(tmp), module["test_package"])
            want = set(variant["fails"])
            label = f"{module['id']} {name}"
            if got == want:
                print(f"DONE: {label}")
            else:
                ok = False
                print(f"NOT YET: {label} (expected failing {sorted(want)}, got {sorted(got)})")
    swaps, patches = variant_swaps(modules, "solution")
    with tempfile.TemporaryDirectory(prefix="finbot-policy-") as tmp:
        assemble(Path(tmp), swaps, patches)
        got = failing_tests(opa, Path(tmp), None)
    if got:
        ok = False
        print(f"NOT YET: all solutions together (failing {sorted(got)})")
    else:
        print("DONE: all solutions together")
    return ok


def check_verdicts(opa: str, modules: list[dict[str, Any]]) -> bool:
    from acs.core import ACS_VERSION
    from acs.guardian.opa_backend import verdict_problem

    swaps, patches = variant_swaps(modules, "solution")
    registry = json.loads((TOOLS / "fixtures" / "registry.json").read_text(encoding="utf-8"))
    patches.append({"finbot_lab": {"tools": registry}})
    ok = True
    with tempfile.TemporaryDirectory(prefix="finbot-policy-") as tmp:
        directory = Path(tmp)
        assemble(directory, swaps, patches)
        shutil.rmtree(directory / "tests")
        for path in sorted((TOOLS / "inputs").glob("*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            document = case["input"]
            input_path = directory.parent / f"{directory.name}-input.json"
            input_path.write_text(json.dumps(document), encoding="utf-8")
            try:
                answer = run_opa(opa, ["eval", "--format", "json", "-d", str(directory), "-i", str(input_path),
                                       "data.finbot.verdict"])
            finally:
                input_path.unlink(missing_ok=True)
            results = answer.get("result") if isinstance(answer, dict) else None
            verdict = results[0]["expressions"][0]["value"] if results else None
            # The base evaluate_step builds before it calls the backend, with fresh values in the same shapes.
            base = {"type": "final", "acs_version": ACS_VERSION, "request_id": str(uuid.uuid4()),
                    "chain_hash": uuid.uuid4().hex + uuid.uuid4().hex}
            problem = "the verdict is undefined" if verdict is None else \
                verdict_problem(verdict, document["method"], document["payload"], base)
            expect = case["expect"]
            if problem is None:
                wrong = {key: verdict.get(key) for key, value in expect.items() if verdict.get(key) != value}
                problem = f"expected {expect}, got {wrong}" if wrong else None
            if problem:
                ok = False
                print(f"NOT YET: verdict {path.stem} ({problem})")
            else:
                print(f"DONE: verdict {path.stem} ({verdict['decision']})")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the FinBot lab policy pack against tools/modules.json.")
    parser.add_argument("--opa", default="opa", help="the OPA binary (default: opa on PATH)")
    parser.add_argument("--verdicts", action="store_true",
                        help="also validate each scenario's verdict with the example Guardian's verdict_problem")
    args = parser.parse_args(argv)
    opa = shutil.which(args.opa)
    if opa is None:
        print(f"check_pack: OPA not found at {args.opa}", file=sys.stderr)
        return 2
    modules = load_manifest()
    try:
        ok = check_modules(opa, modules)
        if args.verdicts:
            ok = check_verdicts(opa, modules) and ok
    except OpaError as e:
        print(f"check_pack: {e}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
