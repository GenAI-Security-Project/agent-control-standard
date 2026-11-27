"""Checks that a module guide's Rego compiles once pasted into its starter (issue #589, LAB-16).

Version 1.0.0. Owner: Rock Lambros. Standard library only.

A guide shows one rego block for the reader to paste over the starter's rule. One live policy file that won't
compile stops OPA deciding for every module, so each module whose guide carries Rego tests it two ways. The static
check runs everywhere: every name the snippet uses must be a keyword, a built-in, a name the snippet binds, or a rule
the pasted pack defines. When opa is on PATH, opa_check also runs `opa check` over a copy of the pack.

Module 5's test (Task 10) holds the first copy of this logic. This file generalizes it so modules 5 and 6 can share
one helper once both lanes merge.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

POLICY = Path(__file__).resolve().parents[3] / "policy"
REGO_FENCE = re.compile(r"^```rego\n(.*?)^```", re.M | re.S)
HEAD = re.compile(r"^([a-z_][a-z0-9_]*)\b", re.M)
TOKEN = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`')
KEYWORDS = {"package", "import", "if", "contains", "not", "in", "some", "every", "else", "default", "input", "data",
            "true", "false", "null", "with", "as", "_"}
# The OPA built-ins a lab module's rule reasonably calls. A dotted built-in counts by its first part.
BUILTINS = {"walk", "count", "concat", "array", "replace", "format_int", "is_string", "is_number", "is_array",
            "is_object", "split", "sprintf", "object", "startswith", "endswith", "lower", "upper", "regex", "strings",
            "to_number", "trim"}
# The partial sets base.rego declares. A snippet adds to them, so naming one isn't a clash.
PARTIAL_SETS = {"deny_codes", "ask_requests", "redaction_paths", "package"}
OPA_TIMEOUT_S = 120


def guide_rego(guide: Path) -> str:
    """The guide's one rego block. More than one leaves the reader guessing which to paste."""
    blocks = REGO_FENCE.findall(guide.read_text(encoding="utf-8"))
    if len(blocks) != 1:
        raise AssertionError(f"{guide.name} should show exactly one rego block, the one the reader pastes")
    return blocks[0]


def pasted(starter: Path, rule: re.Pattern[str], snippet: str) -> str:
    """The starter as the guide says to edit it: its one rule, matched by rule, replaced by the snippet."""
    text = starter.read_text(encoding="utf-8")
    if len(rule.findall(text)) != 1:
        raise AssertionError(f"{starter} should hold exactly one rule the guide replaces")
    return rule.sub(lambda _: snippet, text)


def code(text: str) -> str:
    """Rego with comments cut and string contents emptied, so neither reads as a name."""
    return STRING.sub('""', "\n".join(line.split("#", 1)[0] for line in text.splitlines()))


def bound(rego: str) -> set[str]:
    """Names a rule binds for itself: function parameters, := and = targets, some and walk bindings."""
    found: set[str] = set()
    for params in re.findall(r"^[a-z_]\w*\(([^)]*)\)", rego, re.M):
        found.update(p.strip() for p in params.split(","))
    found.update(re.findall(r"\b(\w+)\s*:?=(?!=)", rego))
    found.update(re.findall(r"\bsome\s+(\w+)", rego))
    for pair in re.findall(r"\[(\w+),\s*(\w+)\]", rego):
        found.update(pair)
    return found


def problems(snippet: str, pasted_text: str, live_file: str, policy: Path = POLICY) -> list[str]:
    """Why the pasted file wouldn't compile: names nothing defines, and helpers that redefine another file's rule."""
    others = {p.name: code(p.read_text(encoding="utf-8")) for p in policy.glob("*.rego") if p.name != live_file}
    snippet_code = code(snippet)
    defined = set(HEAD.findall(code(pasted_text))) | {h for text in others.values() for h in HEAD.findall(text)}
    unknown = set(TOKEN.findall(snippet_code)) - KEYWORDS - BUILTINS - bound(snippet_code) - defined
    out = [f"uses names nothing defines once pasted: {sorted(unknown)}"] if unknown else []
    added = set(HEAD.findall(snippet_code)) - PARTIAL_SETS
    clashes = sorted(name for name in added for text in others.values() if name in HEAD.findall(text))
    if clashes:
        out.append(f"redefines rules another live file defines: {clashes}")
    return out


def opa_check(pasted_text: str, live_file: str, directory: Path, policy: Path = POLICY) -> subprocess.CompletedProcess:
    """`opa check` over a copy of the live pack with live_file replaced by pasted_text. Needs opa on PATH."""
    for path in policy.glob("*.rego"):
        shutil.copy(path, directory / path.name)
    shutil.copy(policy / "data.json", directory / "data.json")
    (directory / live_file).write_text(pasted_text, encoding="utf-8")
    return subprocess.run(["opa", "check", str(directory)], capture_output=True, text=True, timeout=OPA_TIMEOUT_S,
                          check=False)
