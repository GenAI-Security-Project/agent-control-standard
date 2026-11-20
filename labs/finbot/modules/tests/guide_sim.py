"""Follows the attendee guides the way an attendee would, and lists the runs they make (issue #589, LAB-16 Task 5).

Version 1.3.0. Owner: Rock Lambros. Standard library only.

A guide passes only when every command a reader could copy is one the lab takes, with arguments it accepts, in an
order the lab accepts. The simulator reads modules/1.md to 7.md in order and works in three steps.

Find. Commands live in one place: lines in `sh`, `bash` or `console` fences, at any indent, so a fence nested in a
list item counts. Those are the lines the simulator walks. Everywhere else (inline code, other fences, indented
blocks, HTML, tables, blockquotes and prose) any text that reads as a lab or Docker command once folded is refused
with "put this command in a sh block". Folding decodes HTML entities, applies NFKC, maps lookalike letters to ASCII,
drops invisible marks and strips a leading `$ `, `bash ` or `sh `. What reads as a command: `./lab` or `./lab.sh`
followed by anything, `lab.sh` followed by a lab verb or an option, inline code starting `lab` and a lab verb, and
`docker` followed by a subcommand. The script named alone, such as `./lab.sh`, and the word lab in prose pass. Fence
tags come from an allowlist: sh, bash and console, plus untagged, text, json and rego fences, which are scanned.

Parse. Each command goes through one grammar per verb (GRAMMAR). A command is one `./lab.sh` call on one line in plain
ASCII, so a prompt, a lookalike or invisible character, any shell operator, substitution or line continuation is
refused. Internal verbs (a leading underscore), owner-only verbs (lab.sh's command table marks them) and the verbs in
REFUSED are refused with their reason. Every verb the lab takes must sit in GRAMMAR or REFUSED, which
test_every_lab_verb_has_a_grammar_or_a_refusal holds.

Follow. Every command changes the simulated lab, in order: mode, signing and policy settings, whether the lab is set
up, and the runs on disk. Each `run` becomes a Run, which test_guides.py compares with scenarios/manifest.json.

Order rules, each for a command an attendee would see fail:
- `init`, `up`, `doctor` and `reset` only open a guide, before any other step. `reset` wipes state/, so the runs and
  the setup go with it, and `init` refuses a lab that is already set up.
- The verbs that run lab.sh's need_init (read from lab.sh: up, run and record) come after `init` when the guide runs
  `init`, and never straight after `reset`.
- `check N` names the guide's own module, comes only after every scenario the guide runs, and follows the last run.
- `down` stops the lab, so nothing but `help` comes after it.
- `upstream openai` is refused, because attendees run on replay with no model key.

Where the rules come from, so nothing is copied: the verbs come from lab.sh's dispatch table, the one `case $verb in`
whose catch-all hands the verb to the CLI, plus the CLI's public COMMANDS. Setting values and the fresh bundle's
defaults come from commands.SETTINGS and DEFAULTS. Policy arguments come from lab_modules.POLICY_MODULES and
POLICY_VARIANTS, and the check number from lab_modules.CHECK_NUMBER. Scenarios are the files in scenarios/ whose names
fit lab.sh's drive_args patterns. Services come from compose.yaml. Two rules live here because no source states them
yet: the run flags, which mirror lab.sh's drive_args (`--answer approve|reject` and `--clean`, each once). The forge and
verify flags come from the module 7 kit's own parsers, parse_arguments in modules/kit/forge.py and verify.py. Loading
forge.py needs acs, so these checks run in the adapters environment, as the documented test command does.

A guide whose attendee edits a policy by hand also carries the command that writes the answer, as a
`./lab.sh policy <n> solution` line under the heading "Or let the lab write the answer", so the simulator sees the fix.

When a guide is missing or broken, the settings after it are unknown, and a later run that depends on one fails,
naming that guide. A guide that sets mode, signing and all four policies under "Before you start" stands on its own.
"""
from __future__ import annotations

import fnmatch
import html
import importlib.util
import re
import shlex
import sys
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar

MODULES_DIR = Path(__file__).resolve().parents[1]
BUNDLE = MODULES_DIR.parent
CLI_DIR = BUNDLE / "cli"
KIT_DIR = MODULES_DIR / "kit"
MODULES = range(1, 8)
LAB = "./lab.sh"
# Fence tags that hold commands, and the ones that hold text a reader only reads. Any other tag is refused, so a
# command can't sit in a block the checks skip.
SHELL = {"sh", "bash", "console"}
SHOWN = {"", "text", "json", "rego"}
# Lookalikes NFKC leaves alone, folded to the ASCII letter a reader takes them for. Pasting from a rich-text draft
# brings these in, and a command spelled with one looks right and fails when copied.
LOOKALIKES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0455": "s", "\u0458": "j", "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u0131": "i",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0425": "X", "\u0405": "S",
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c1": "p",
    "\u03c4": "t", "\u2215": "/", "\u2044": "/", "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
})
# A prompt or an interpreter in front of a command still leaves a command a reader copies.
PROMPT = re.compile(r"^\s*(?:\$\s+|(?:ba)?sh\s+)")
SH_BLOCK = "Only sh, bash and console fences hold commands, so put this command in a sh block"
# Docker subcommands an attendee could be told to run. The lab's own Docker steps live in lab.sh.
DOCKER = re.compile(r"\bdocker[ \t]+(?:compose|run|exec|ps|logs|rm|rmi|stop|start|restart|kill|volume|image|"
                    r"images|pull|push|build|system|network|inspect|container|cp|info|version|login|up|down)\b")
ANSWERS = ("approve", "reject")
# One command per line, so any of these means a second command, a redirect, a substitution or a variable.
OPERATOR = re.compile(r"[;&|<>`$()]")
FENCE = re.compile(r"(\s*)(`{3,}|~{3,})\s*([^`\s]*)[^`]*")
INLINE_CODE = re.compile(r"(`+)(.+?)\1")
COMMENT = re.compile(r"<!--.*?-->", re.S)
# Verbs that open a guide. They set the lab up or wipe it, so they make no sense between a guide's steps.
SETUP = {"init", "up", "doctor", "reset"}

if str(CLI_DIR) not in sys.path:
    sys.path.insert(0, str(CLI_DIR))

import commands as lab_commands  # noqa: E402
import lab_modules  # noqa: E402


class GuideError(ValueError):
    """A guide line the lab would refuse, or a run the simulator can't place. module names the guide."""

    def __init__(self, message: str, module: int | None = None) -> None:
        super().__init__(message)
        self.module = module


@dataclass(frozen=True)
class Command:
    path: Path
    line: int
    argv: tuple[str, ...]


@dataclass
class State:
    mode: str | None
    signing: str | None
    policy: dict[str, str | None] = field(default_factory=dict)
    # True set up, False wiped by reset, None unknown (a setup page may have run init).
    initialized: bool | None = None


@dataclass(frozen=True)
class Run:
    module: int
    scenario: str
    mode: str
    signing: str
    policy: tuple[tuple[str, str], ...]
    answer: str | None
    clean: bool
    command: str
    path: Path
    line: int

    MANIFEST_KEYS: ClassVar[tuple[str, ...]] = ("module", "scenario", "mode", "signing", "policy", "answer", "clean",
                                                "command")

    def as_manifest(self) -> dict[str, Any]:
        return {"module": self.module, "scenario": self.scenario, "mode": self.mode, "signing": self.signing,
                "policy": dict(self.policy), "answer": self.answer, "clean": self.clean, "command": self.command}


# ---------------------------------------------------------------------------------------------------------------------
# The lab's own rules
# ---------------------------------------------------------------------------------------------------------------------

def _lab_sh(bundle: Path = BUNDLE) -> str:
    return (bundle / "lab.sh").read_text(encoding="utf-8")


def dispatch_arms(lab_sh: str) -> list[tuple[set[str], str]]:
    """Each arm of lab.sh's dispatch table, the one `case $verb in` whose catch-all hands the verb to the CLI, as its
    verbs and its body. The catch-all is left out."""
    tables = []
    for m in re.finditer(r"^([ \t]*)case \$verb in\n(.*?)^\1esac\b", lab_sh, re.M | re.S):
        body = m.group(2)
        if 'lab "$verb" "$@"' in body:
            tables.append(body)
    if len(tables) != 1:
        raise GuideError(f"lab.sh has {len(tables)} `case $verb in` tables that hand a verb to the CLI, not one")
    body = tables[0]
    indent = re.match(r"([ \t]*)", next(line for line in body.splitlines() if line.strip())).group(1)
    heads = list(re.finditer(rf"^{indent}(\S[^)\n]*)\)", body, re.M))
    arms = []
    for i, head in enumerate(heads):
        verbs = {p.strip() for p in head.group(1).split("|")} - {"*"}
        if verbs:
            arms.append((verbs, body[head.end():heads[i + 1].start() if i + 1 < len(heads) else len(body)]))
    return arms


def host_verbs(lab_sh: str) -> set[str]:
    """The verbs in lab.sh's dispatch table."""
    return {verb for verbs, _ in dispatch_arms(lab_sh) for verb in verbs}


def need_init_verbs(lab_sh: str | None = None) -> set[str]:
    """The dispatch verbs that run lab.sh's need_init, in their own arm or in a function the arm calls."""
    text = _lab_sh() if lab_sh is None else lab_sh
    functions = dict(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{\n(.*?)^\}", text, re.M | re.S))
    needing = {name for name, body in functions.items() if re.search(r"\bneed_init\b", body)}
    found = set()
    for verbs, body in dispatch_arms(text):
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))
        if "need_init" in words or words & needing:
            found |= verbs
    return found


def owner_only_verbs(lab_sh: str | None = None) -> set[str]:
    """The verbs lab.sh's command table marks "owner only"."""
    text = _lab_sh() if lab_sh is None else lab_sh
    table = re.search(r"^# Command table:\n(.*?)^# Exit 0", text, re.M | re.S)
    if table is None:
        raise GuideError("lab.sh has no command table")
    return {m.group(1) for m in re.finditer(r"^#\s+(\S+) .*owner only", table.group(1), re.M)}


def known_verbs(bundle: Path = BUNDLE) -> frozenset[str]:
    cli = {name for name in lab_commands.COMMANDS if not name.startswith("_")}
    return frozenset(host_verbs(_lab_sh(bundle)) | cli)


def mode_values() -> tuple[str, ...]:
    return tuple(lab_commands.SETTINGS["mode"])


def signing_values() -> dict[str, str]:
    """Each `./lab.sh sign` value and the response algorithm it sets."""
    return {name: env["ACS_RESPONSE_SIGNING"] for name, env in lab_commands.SETTINGS["sign"].items()}


def policy_keys() -> tuple[str, ...]:
    return tuple(f"m{n}" for n in lab_modules.POLICY_MODULES)


def scenario_patterns(bundle: Path = BUNDLE) -> list[str]:
    """The scenario patterns lab.sh's drive_args accepts, such as s[1-6]."""
    function = re.search(r"^drive_args\(\) \{\n(.*?)^\}", _lab_sh(bundle), re.M | re.S)
    arm = function and re.search(r"^\s*(s\[[^)\n]*)\)", function.group(1), re.M)
    if not arm:
        raise GuideError("lab.sh's drive_args has no scenario pattern")
    return [p.strip() for p in arm.group(1).split("|")]


def scenario_ids(bundle: Path = BUNDLE) -> set[str]:
    patterns = scenario_patterns(bundle)
    return {p.stem for p in (bundle / "scenarios").glob("s*.json")
            if any(fnmatch.fnmatchcase(p.stem, pattern) for pattern in patterns)}


def service_names(bundle: Path = BUNDLE) -> set[str]:
    """The service names under compose.yaml's services key."""
    text = (bundle / "compose.yaml").read_text(encoding="utf-8")
    block = re.search(r"^services:\n(.*?)(?=^\S)", text, re.M | re.S)
    if block is None:
        raise GuideError("compose.yaml has no services")
    return set(re.findall(r"^  ([A-Za-z0-9][A-Za-z0-9_.-]*):\s*$", block.group(1), re.M))


def shipped_state() -> State:
    return State(mode=lab_commands.DEFAULTS["ACS_LAB_MODE"], signing=lab_commands.DEFAULTS["ACS_RESPONSE_SIGNING"],
                 policy={key: "starter" for key in policy_keys()})


def unknown_state() -> State:
    return State(mode=None, signing=None, policy={key: None for key in policy_keys()})


# ---------------------------------------------------------------------------------------------------------------------
# The grammar: one parser per verb a guide may use, each returning the error text or None
# ---------------------------------------------------------------------------------------------------------------------

Grammar = Callable[[list[str], int], str | None]


def _no_args(verb: str) -> Grammar:
    return lambda args, module: None if not args else f"{verb} takes no arguments"


def _one_of(verb: str, values: Callable[[], Iterable[str]]) -> Grammar:
    def parse(args: list[str], module: int) -> str | None:
        choices = list(values())
        return None if len(args) == 1 and args[0] in choices else f"{verb} takes one of {', '.join(choices)}"
    return parse


def _upstream(args: list[str], module: int) -> str | None:
    if args == ["openai"]:
        return "upstream openai needs a model key, and attendees run on replay"
    return _one_of("upstream", lambda: lab_commands.SETTINGS["upstream"])(args, module)


def _policy(args: list[str], module: int) -> str | None:
    if len(args) == 2 and args[0] in lab_modules.POLICY_MODULES and args[1] in lab_modules.POLICY_VARIANTS:
        return None
    return (f"policy takes a module from {', '.join(lab_modules.POLICY_MODULES)} and "
            f"{' or '.join(lab_modules.POLICY_VARIANTS)}")


def _check(args: list[str], module: int) -> str | None:
    if len(args) == 1 and lab_modules.CHECK_NUMBER.fullmatch(args[0]) and args[0] == str(module):
        return None
    return f"this guide's check is ./lab.sh check {module}"


def _run(args: list[str], module: int) -> str | None:
    scenarios = scenario_ids()
    if not args or args[0] not in scenarios:
        return f"run takes a scenario from {', '.join(sorted(scenarios))}"
    rest, answer, clean = args[1:], None, False
    while rest:
        flag = rest.pop(0)
        if flag == "--answer" and answer is None and rest and rest[0] in ANSWERS:
            answer = rest.pop(0)
        elif flag == "--clean" and not clean:
            clean = True
        else:
            return "run takes only --answer approve, --answer reject or --clean, each once"
    return None


def _logs(args: list[str], module: int) -> str | None:
    services = service_names()
    unknown = [a for a in args if a not in services]
    return f"logs takes service names from {', '.join(sorted(services))}" if unknown else None


def kit_parser(name: str) -> ModuleType:
    """modules/kit/<name>.py, loaded by path under the name lab_modules gives it, lab_bundle_<name>. The simulator and
    the CLI then share one module, and the kit's verify never shadows the viewer's verify on a shared sys.path. Its
    parse_arguments is the flag rule for that verb."""
    module_name = f"lab_bundle_{name}"
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        return loaded
    # The kit imports its siblings (results, sessions) by name.
    if str(KIT_DIR) not in sys.path:
        sys.path.insert(0, str(KIT_DIR))
    path = KIT_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise GuideError(f"the module 7 kit's {name} can't be loaded from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _kit_flags(verb: str) -> Grammar:
    def parse(args: list[str], module: int) -> str | None:
        try:
            kit_parser(verb).parse_arguments(list(args))
        except ValueError as e:
            return str(e)
        return None
    return parse


GRAMMAR: dict[str, Grammar] = {
    "mode": _one_of("mode", mode_values),
    "sign": _one_of("sign", signing_values),
    "upstream": _upstream,
    "traces": _one_of("traces", lambda: lab_commands.SETTINGS["traces"]),
    "policy": _policy,
    "run": _run,
    "check": _check,
    "logs": _logs,
    "forge": _kit_flags("forge"),
    "verify": _kit_flags("verify"),
    **{verb: _no_args(verb) for verb in ("init", "up", "down", "reset", "doctor", "help", "viewer", "approver",
                                         "model-log", "downgrade", "bench")},
}

REFUSED: dict[str, str] = {
    **{verb: f"{verb} is owner only, so an attendee guide never runs it" for verb in owner_only_verbs()},
    "pins": "pins rewrites the shipped tool registry, which the module 6 policy reads",
    "claims": "claims checks the lab's own text. It isn't an attendee step",
    "-h": "write ./lab.sh help",
    "--help": "write ./lab.sh help",
}


def parse(raw: str, module: int) -> tuple[str, ...]:
    """raw as one checked `./lab.sh` call, or a GuideError naming why the lab would refuse it."""
    text = raw.strip()
    if text.endswith("\\"):
        raise GuideError("a line continuation splits one command over lines. Put it on one line", module)
    if text.startswith("$"):
        raise GuideError(f"{text!r} starts with a prompt. Write the command alone, starting ./lab.sh", module)
    if not text.isascii() or any(unicodedata.category(ch) == "Cf" for ch in text):
        raise GuideError(f"{text!r} holds a lookalike or invisible character. Type the command in plain ASCII",
                         module)
    if OPERATOR.search(text):
        raise GuideError(f"{text!r} holds a shell operator, substitution or variable. A guide command is one "
                         f"./lab.sh call on its own line", module)
    try:
        argv = tuple(shlex.split(text))
    except ValueError as e:
        raise GuideError(f"{text!r} can't be read as one command ({e})", module) from None
    if not argv or argv[0] != LAB:
        hint = f" Write it as ./lab.sh {' '.join(argv[1:])}" if argv and argv[0] == "lab" else ""
        raise GuideError(f"{text!r} isn't a ./lab.sh command.{hint} Tag output and file contents with text, json or "
                         f"rego instead", module)
    if len(argv) < 2:
        raise GuideError("./lab.sh needs a verb", module)
    verb, args = argv[1], list(argv[2:])
    if verb.startswith("_"):
        raise GuideError(f"{verb} is internal to the lab, so a guide never runs it", module)
    if verb in REFUSED:
        raise GuideError(REFUSED[verb], module)
    if verb not in known_verbs() or verb not in GRAMMAR:
        raise GuideError(f"{verb} isn't a lab verb a guide can use", module)
    problem = GRAMMAR[verb](args, module)
    if problem:
        raise GuideError(problem, module)
    return argv


# ---------------------------------------------------------------------------------------------------------------------
# Finding every command a reader could copy
# ---------------------------------------------------------------------------------------------------------------------

def fences(text: str) -> list[tuple[int, str, list[str]]]:
    """Each fenced block as (line of the opening fence, tag, body lines). A fence may be indented, as one nested in a
    list item is. An unclosed fence runs to the end, as CommonMark reads it."""
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE.fullmatch(lines[i])
        if m is None:
            i += 1
            continue
        indent, marker, tag = m.groups()
        close = re.compile(rf"\s*{re.escape(marker[0])}{{{len(marker)},}}\s*")
        body = []
        j = i + 1
        while j < len(lines) and not close.fullmatch(lines[j]):
            # CommonMark strips up to the opening fence's indent from each body line.
            body.append(re.sub(rf"^[ \t]{{0,{len(indent)}}}", "", lines[j]))
            j += 1
        out.append((i + 1, tag.lower(), body))
        i = j + 1
    return out


def fold(text: str) -> str:
    """text as a reader sees it: HTML entities decoded, NFKC, lookalikes folded to ASCII, invisible marks dropped, and a
    leading prompt or interpreter stripped."""
    text = unicodedata.normalize("NFKC", html.unescape(text)).translate(LOOKALIKES)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return PROMPT.sub("", text)


def _verb_words() -> str:
    words = sorted(set(known_verbs()) | set(GRAMMAR) | set(REFUSED) - {"-h", "--help"}, key=len, reverse=True)
    return "|".join(map(re.escape, words)) + r"|_\w+|-"


def _reads_as_command(text: str) -> str | None:
    """The part of text, already folded, that reads as a lab or Docker command, or None."""
    verbs = _verb_words()
    patterns = [
        # ./lab or ./lab.sh followed by anything: a reader copies it as a command. Alone it only names the script.
        re.compile(r"\./lab(?:\.sh)?(?=[ \t]+[^\s`<|])", re.I),
        # lab.sh without ./, followed by a lab verb or an option.
        re.compile(rf"(?<![\w./-])lab\.sh(?=[ \t]+(?:{verbs})(?![\w-]))", re.I),
        DOCKER,
    ]
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return text[m.start():m.start() + 60].strip()
    return None


def find_commands(path: Path, module: int) -> list[Command]:
    """The commands in path's sh, bash and console fences, in reading order. Anything outside one that reads as a lab
    or Docker command, once folded, is a GuideError, as is a fence tag outside the allowlist."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    where = f"modules/{path.name}"
    found: list[tuple[int, str]] = []
    for start, tag, body in fences(text):
        if tag not in SHELL | SHOWN:
            raise GuideError(f"{where}:{start}: the fence tag {tag} isn't one the checks read. Use sh for commands, "
                             f"or text, json or rego", module)
        if tag in SHELL:
            found.extend((start + offset, raw.strip()) for offset, raw in enumerate(body, start=1)
                         if raw.strip() and not raw.strip().startswith("#"))
            # Only a command fence leaves the scan. Every other fence is read below like the rest of the page.
            for k in range(start - 1, min(start + len(body) + 1, len(lines))):
                lines[k] = ""
    visible = COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), "\n".join(lines)).split("\n")
    verbs = _verb_words()
    for number, line in enumerate(visible, start=1):
        spans = [fold(m.group(2)) for m in INLINE_CODE.finditer(line)]
        hit = _reads_as_command(fold(line)) or next(
            (span for span in spans if re.match(rf"lab[ \t]+(?:{verbs})(?![\w-])", span)), None)
        if hit:
            raise GuideError(f"{where}:{number}: {hit!r} reads as a command outside a sh block. {SH_BLOCK}", module)
    commands = []
    for number, raw in found:
        try:
            argv = parse(raw, module)
        except GuideError as e:
            raise GuideError(f"{where}:{number}: {e}", module) from None
        commands.append(Command(path, number, argv))
    return commands


# ---------------------------------------------------------------------------------------------------------------------
# Following a guide
# ---------------------------------------------------------------------------------------------------------------------

def _guide(path: Path, module: int, state: State, gaps: list[int]) -> list[Run]:
    """The runs one guide makes, changing state as the lab would."""
    commands = find_commands(path, module)
    needs_init = need_init_verbs()
    init_at = next((i for i, c in enumerate(commands) if c.argv[1] == "init"), None)
    scenarios = {c.argv[2] for c in commands if c.argv[1] == "run"}
    runs: list[Run] = []
    ran: set[str] = set()
    started = stopped = False
    checked_since_run = False
    for i, c in enumerate(commands):
        where = f"modules/{path.name}:{c.line}"
        verb, args = c.argv[1], list(c.argv[2:])
        # lab.sh's need_init: these verbs stop with "run ./lab.sh init first" on a lab that isn't set up.
        if verb in needs_init and state.initialized is False:
            raise GuideError(f"{where}: the lab was reset, so ./lab.sh init comes before ./lab.sh {verb}", module)
        if verb in needs_init and init_at is not None and i < init_at:
            raise GuideError(f"{where}: ./lab.sh {verb} needs the lab set up, so ./lab.sh init comes first", module)
        if stopped and verb != "help":
            raise GuideError(f"{where}: ./lab.sh {verb} comes after ./lab.sh down, which stops the lab. Put down last",
                             module)
        if verb in SETUP:
            if started:
                raise GuideError(f"{where}: ./lab.sh {verb} partway through a guide wipes or refuses the lab. Put "
                                 f"setup commands only at the top, under Before you start", module)
            if verb == "reset":
                state.initialized = False
                ran.clear()
            elif verb == "init":
                if state.initialized:
                    raise GuideError(f"{where}: ./lab.sh init refuses a lab that's already set up, as it is after "
                                     f"the guide before this one", module)
                state.initialized = True
            continue
        if verb == "help":
            continue
        started = True
        if state.initialized is False and verb != "down":
            raise GuideError(f"{where}: the lab was reset, so ./lab.sh init comes before ./lab.sh {verb}", module)
        state.initialized = True
        if verb == "mode":
            state.mode = args[0]
        elif verb == "sign":
            state.signing = signing_values()[args[0]]
        elif verb == "policy":
            state.policy[f"m{args[0]}"] = args[1]
        elif verb == "down":
            stopped = True
        elif verb == "check":
            missing = sorted(scenarios - ran)
            if missing or not ran:
                need = ", ".join(f"./lab.sh run {s}" for s in missing) or "a run"
                raise GuideError(f"{where}: ./lab.sh check {module} comes before the runs it needs: {need}", module)
            checked_since_run = True
        elif verb == "run":
            runs.append(_record_run(where, c, args, state, module, gaps))
            ran.add(args[0])
            checked_since_run = False
    if not checked_since_run:
        raise GuideError(f"modules/{path.name}: the guide must end its runs with ./lab.sh check {module}", module)
    return runs


def _record_run(where: str, c: Command, args: list[str], state: State, module: int, gaps: list[int]) -> Run:
    unknown = [name for name, value in (("mode", state.mode), ("signing", state.signing), *state.policy.items())
               if value is None]
    if unknown:
        missing = ", ".join(f"modules/{n}.md" for n in gaps)
        raise GuideError(f"{where}: this run's {', '.join(unknown)} is unknown because {missing} is missing or "
                         f"broken. Set it under Before you start, or wait for that guide", module)
    answer = args[args.index("--answer") + 1] if "--answer" in args else None
    policy = tuple((k, v) for k, v in state.policy.items() if v is not None)
    return Run(module, args[0], str(state.mode), str(state.signing), policy, answer, "--clean" in args,
               " ".join(["run", *args]), c.path, c.line)


def simulate(guide_dir: Path = MODULES_DIR, modules: Iterable[int] = MODULES, focus: int | None = None) -> list[Run]:
    """Every run the guides make, read in module order from a fresh bundle's settings.

    With focus, a broken guide other than focus counts as missing, so one lane's error never turns another lane's
    test red. Without focus, the first error raises.
    """
    state = shipped_state()
    gaps: list[int] = []
    runs: list[Run] = []
    for n in modules:
        path = guide_dir / f"{n}.md"
        if not path.is_file():
            # The settings a missing guide would leave are unknown, so anything after it must set its own.
            state = unknown_state()
            gaps.append(n)
            continue
        try:
            runs.extend(_guide(path, n, state, gaps))
        except GuideError:
            if focus is None or focus == n:
                raise
            state = unknown_state()
            gaps.append(n)
    return runs
