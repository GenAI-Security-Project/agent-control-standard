"""Checks on the seven attendee guides, the glossary and the guide-run manifest (issue #589, LAB-16 Task 5).

Version 1.2.0. Owner: Rock Lambros. Standard library only. Run with:

    uv run --project adapters --locked --group test python -m pytest labs/finbot/modules/tests -v

The per-module tests stay red for a module until its guide lands (Tasks 6 to 13). The simulator, glossary and
manifest tests pass on their own.

A guide is the attendee's script, so its fenced commands must be commands the lab really takes, and the runs they
make must be the runs the recordings cover. guide_sim.py follows the commands. This file checks the prose: every
section in order, short sentences, each glossary term linked at its first use, no person named, and the trust
boundary stated.
"""
from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

import guide_sim as sim  # noqa: E402

MODULES_DIR = sim.MODULES_DIR
BUNDLE = sim.BUNDLE
REPO_ROOT = BUNDLE.parents[1]
GLOSSARY = MODULES_DIR / "glossary.md"
MANIFEST = BUNDLE / "scenarios" / "manifest.json"
MODULES = tuple(sim.MODULES)
MAX_WORDS = 25

SECTIONS = ("What you'll see", "Before you start", "Run it with ACS off", "Run it with ACS on", "What changed",
            "What ACS gave you", "What this doesn't show", "Check your work")
# Module 7 has no off run. Its attendee makes a forgery instead.
SECTIONS_7 = SECTIONS[:2] + ("Make a forgery",) + SECTIONS[3:]

# The plan's term list (Task 5 interfaces). The glossary may hold more, and every heading it holds is enforced below.
GLOSSARY_TERMS = ("Agent", "FinBot", "Gateway", "Guardian", "Policy", "OPA", "Rego", "Hook", "Tool call",
                  "Tool result", "Decision", "Shadow mode", "Enforce mode", "Transcript", "Audit log",
                  "Model input log", "Replay", "Epoch", "HMAC", "ML-DSA-65", "Key document", "Fingerprint",
                  "Signature", "Forgery", "Downgrade", "Tool digest", "Neutral deny line", "Trust boundary")
# Every module guide states this sentence word for word (Task 1 fix round 1). The glossary holds it too, so the lanes
# copy one text.
TRUST_BOUNDARY = "Checks read `state/`, so anything that can write `state/` can steer a check."

MANIFEST_KEYS = {"run", "module", "scenario", "mode", "signing", "policy", "answer", "clean", "command", "recording"}
RECORDING_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")  # the gateway's rule for a recording name
# The plan's guide-run table held fifteen. The 2026-11-24 owner sitting split s2 three ways, since module 3's solution
# and module 7's full set change decisions FinBot sees, so a take recorded under the starter can't replay them.
RECORDING_COUNT = 17


def guide(n: int) -> Path:
    return MODULES_DIR / f"{n}.md"


def read_guide(n: int) -> str:
    path = guide(n)
    if not path.is_file():
        pytest.fail(f"modules/{n}.md is missing. Its module lane writes it (LAB-16 Tasks 6 to 13)")
    return path.read_text(encoding="utf-8")


def manifest_runs() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["runs"]


# ---------------------------------------------------------------------------------------------------------------------
# Markdown prose, read the way the claims check reads it: fences are code, HTML comments are markers.
# ---------------------------------------------------------------------------------------------------------------------

COMMENT = re.compile(r"<!--.*?-->", re.S)
INLINE_CODE = re.compile(r"(`+)(.+?)\1", re.S)
LINK = re.compile(r"!?\[([^\]]*)\]\(([^)\s]*)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
UNIT_START = re.compile(r"\s{0,3}(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|\|)")
SENTENCE_END = re.compile(r"[.!?][\"'”’)\]*_]*$")
WORD = re.compile(r"[A-Za-z0-9]")


def prose(text: str) -> str:
    """text with fenced blocks blanked and HTML comments removed, line numbers kept."""
    lines = text.splitlines()
    for start, _info, body in sim.fences(text):
        for i in range(start - 1, start + len(body) + 1):
            if i < len(lines):
                lines[i] = ""
    return COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), "\n".join(lines))


def headings(text: str, level: int) -> list[str]:
    out = []
    for line in prose(text).splitlines():
        m = HEADING.fullmatch(line)
        if m and len(m.group(1)) == level:
            out.append(m.group(2).strip())
    return out


def units(text: str) -> list[str]:
    """Paragraphs, list items, headings, quotes and table cells, each one place a sentence can live."""
    out: list[list[str]] = []
    for line in prose(text).splitlines():
        if not line.strip():
            out.append([])
            continue
        if line.lstrip().startswith("|"):
            if re.fullmatch(r"[\s|:-]+", line):
                continue
            for cell in line.strip().strip("|").split("|"):
                out.extend([[cell], []])
            continue
        if UNIT_START.match(line) or not out:
            out.append([line])
        else:
            out[-1].append(line)
    return [" ".join(u) for u in out if u]


def visible(unit: str) -> str:
    """A unit as a reader sees it: one token for inline code, link text without the target."""
    unit = INLINE_CODE.sub(" code ", unit)
    return LINK.sub(lambda m: m.group(1), unit)


def long_sentences(text: str) -> list[str]:
    found = []
    for unit in units(text):
        words: list[str] = []
        for token in visible(HEADING.sub(r"\2", unit)).split():
            if WORD.search(token):
                words.append(token)
            if SENTENCE_END.search(token):
                if len(words) > MAX_WORDS:
                    found.append(f"{len(words)} words: {' '.join(words)}")
                words = []
        if len(words) > MAX_WORDS:
            found.append(f"{len(words)} words: {' '.join(words)}")
    return found


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: markup and comments dropped, lower case, punctuation gone, spaces to dashes."""
    text = visible(COMMENT.sub("", heading)).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def term_pattern(term: str) -> re.Pattern[str]:
    """term and its plural and possessive forms, matched as whole words in any case."""
    words = term.split()
    head, last = words[:-1], words[-1]
    forms = [re.escape(last)]
    if last.lower().endswith("y"):
        forms.append(re.escape(last[:-1]) + "ies")
    stem = r"\s+".join([*map(re.escape, head), f"(?:{'|'.join(forms)})"])
    return re.compile(rf"(?<![\w-])(?:{stem})(?:s|es|ed|ing)?(?:['’]s)?(?![\w-])", re.I)


def glossary_terms() -> dict[str, str]:
    """Each glossary heading's term and its anchor."""
    text = GLOSSARY.read_text(encoding="utf-8")
    return {visible(COMMENT.sub("", h)).strip(): slug(h) for h in headings(text, 2)}


def segments(text: str) -> list[tuple[str, str | None]]:
    """The guide's prose outside headings, split into plain text and link text with its target, in reading order."""
    body = "\n".join(line for line in prose(text).splitlines() if not HEADING.fullmatch(line))
    body = INLINE_CODE.sub(" ", body)
    out: list[tuple[str, str | None]] = []
    at = 0
    for m in LINK.finditer(body):
        out.append((body[at:m.start()], None))
        out.append((m.group(1), m.group(2)))
        at = m.end()
    out.append((body[at:], None))
    return out


def unlinked_first_uses(text: str, terms: dict[str, str]) -> list[str]:
    problems = []
    for term, anchor in terms.items():
        pattern = term_pattern(term)
        wanted = re.compile(rf"(?:\./)?glossary\.md#{re.escape(anchor)}")
        for chunk, target in segments(text):
            m = pattern.search(chunk)
            if m is None:
                continue
            if target is None or not wanted.fullmatch(target):
                where = "as plain text" if target is None else f"linked to {target}"
                problems.append(f"{term!r} first appears {where} ({m.group(0)!r}). Link it as "
                                f"[{m.group(0)}](glossary.md#{anchor})")
            break
    return problems


def person_rules() -> tuple[list[re.Pattern[str]], list[str]]:
    """Patterns for the people and accounts GOVERNANCE.md lists, read from that file so no name is copied here."""
    governance = (REPO_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    names: set[str] = set()
    for m in re.finditer(r"([A-Z][a-z]+(?: [A-Z][a-z]+)+)(?: \(([A-Z][a-z]+)\))? \(\[@([\w-]+)\]", governance):
        full, nickname, handle = m.groups()
        names.update({full, full.split()[-1], handle})
        if nickname:
            names.add(nickname)
    patterns = [re.compile(rf"(?<![\w@.-]){re.escape(n)}(?![\w-])") for n in sorted(names)]
    # An @handle anywhere, but not the @ inside an email address, and any home directory path.
    patterns += [re.compile(r"(?<![\w.])@[A-Za-z0-9][A-Za-z0-9-]*"),
                 re.compile(r"/Users/|/home/|~/|[A-Za-z]:\\Users\\")]
    return patterns, sorted(names)


def people_named(text: str) -> list[str]:
    patterns, _ = person_rules()
    return [f"line {n}: {m.group(0)!r}" for n, line in enumerate(text.splitlines(), 1)
            for p in patterns for m in p.finditer(line)]


# ---------------------------------------------------------------------------------------------------------------------
# Per module guide. Red for a module until its lane lands.
# ---------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("n", MODULES)
def test_guide_exists(n):
    assert guide(n).is_file(), f"modules/{n}.md is missing"


@pytest.mark.parametrize("n", MODULES)
def test_guide_has_every_section(n):
    expected = SECTIONS_7 if n == 7 else SECTIONS
    found = headings(read_guide(n), 2)
    assert found == list(expected), (f"modules/{n}.md's ## headings must be exactly {list(expected)} in that order. "
                                     f"Use ### for anything inside a section. Found {found}")


@pytest.mark.parametrize("n", MODULES)
def test_sentences_stay_short(n):
    found = long_sentences(read_guide(n))
    assert not found, f"modules/{n}.md has sentences over {MAX_WORDS} words:\n" + "\n".join(found)


@pytest.mark.parametrize("n", MODULES)
def test_glossary_terms_linked_at_first_use(n):
    problems = unlinked_first_uses(read_guide(n), glossary_terms())
    assert not problems, f"modules/{n}.md:\n" + "\n".join(problems)


@pytest.mark.parametrize("n", MODULES)
def test_commands_are_known_verbs(n):
    """Every command a reader could copy parses under its verb's grammar, and the steps run in an order the lab
    accepts. A broken earlier guide counts as missing here, so it never turns this module red."""
    read_guide(n)
    try:
        sim.simulate(modules=range(1, n + 1), focus=n)
    except sim.GuideError as e:
        pytest.fail(str(e))


@pytest.mark.parametrize("n", MODULES)
def test_no_person_named(n):
    found = people_named(read_guide(n))
    assert not found, f"modules/{n}.md names a person, an account or a home path:\n" + "\n".join(found)


@pytest.mark.parametrize("n", MODULES)
def test_guide_states_the_trust_boundary(n):
    # prose() drops comments and fences, so the sentence counts only where an attendee reads it.
    assert TRUST_BOUNDARY in prose(read_guide(n)), f"modules/{n}.md must say, word for word, in prose: {TRUST_BOUNDARY}"


@pytest.mark.parametrize("n", MODULES)
def test_guide_runs_match_the_manifest(n):
    read_guide(n)
    try:
        runs = sim.simulate(modules=range(1, n + 1), focus=n)
    except sim.GuideError as e:
        pytest.fail(str(e))
    found = [r.as_manifest() for r in runs if r.module == n]
    keys = sim.Run.MANIFEST_KEYS
    expected = [{k: e[k] for k in keys} for e in manifest_runs() if e["module"] == n]
    assert found == expected, (f"modules/{n}.md's runs don't match scenarios/manifest.json for module {n}.\n"
                               f"guide:    {found}\nmanifest: {expected}")


# ---------------------------------------------------------------------------------------------------------------------
# The glossary
# ---------------------------------------------------------------------------------------------------------------------

def test_glossary_has_every_term():
    terms = glossary_terms()
    missing = [t for t in GLOSSARY_TERMS if t not in terms]
    assert not missing, f"glossary.md lacks a ## heading for {missing}"
    assert len(set(terms.values())) == len(terms), "two glossary headings share an anchor"


def test_glossary_states_the_trust_boundary():
    assert TRUST_BOUNDARY in GLOSSARY.read_text(encoding="utf-8")


def test_glossary_sentences_stay_short():
    found = long_sentences(GLOSSARY.read_text(encoding="utf-8"))
    assert not found, "glossary.md:\n" + "\n".join(found)


def test_glossary_names_no_person():
    found = people_named(GLOSSARY.read_text(encoding="utf-8"))
    assert not found, "glossary.md:\n" + "\n".join(found)


# ---------------------------------------------------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------------------------------------------------

def test_manifest_is_well_formed():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["format"] == "acs-lab-manifest/1"
    runs = data["runs"]
    names = [r["run"] for r in runs]
    assert len(names) == len(set(names)), "run names repeat"
    state = sim.shipped_state()
    modes = set(sim.mode_values())
    signings = set(sim.signing_values().values())
    scenarios = sim.scenario_ids()
    for r in runs:
        extra = set(r) - MANIFEST_KEYS - {"shared_proof"}
        assert MANIFEST_KEYS <= set(r) and not extra, f"{r['run']} has keys {sorted(r)}"
        assert r["module"] is None or r["module"] in MODULES, r
        assert r["scenario"] in scenarios, r
        assert r["mode"] in modes and r["signing"] in signings, r
        assert r["policy"] is None or set(r["policy"]) == set(state.policy), r
        assert r["answer"] in (None, "approve", "reject") and isinstance(r["clean"], bool), r
        assert RECORDING_NAME.fullmatch(r["recording"]), r
    assert len({r["recording"] for r in runs}) == RECORDING_COUNT
    captures = [r for r in runs if r["module"] is None]
    assert [c["run"] for c in captures] == ["pins-s6-clean"]
    assert captures[0]["command"] == f"record {captures[0]['recording']} s6 --clean"


def test_manifest_runs_cover_every_module():
    assert {r["module"] for r in manifest_runs()} - {None} == set(MODULES)


# ---------------------------------------------------------------------------------------------------------------------
# The simulator and the prose rules on sample text
# ---------------------------------------------------------------------------------------------------------------------

SAMPLE_1 = """\
# Module 1: Wire it in

## Run it with ACS off

```sh
./lab.sh mode off
./lab.sh run s1
```

```text
DONE: output in a text fence is never followed
```

## Run it with ACS on

```sh
# A comment line is skipped.
./lab.sh mode enforce
./lab.sh run s1
./lab.sh check 1
```
"""

SAMPLE_2 = """\
## Run it with ACS on

```json
{"vendor_domains": ["northwind-supplies.example"]}
```

### Or let the lab write the answer

```sh
./lab.sh policy 3 solution
./lab.sh sign hmac
./lab.sh run s4a --answer approve
./lab.sh check 2
```
"""


def write(directory: Path, files: dict[int, str]) -> Path:
    for n, text in files.items():
        (directory / f"{n}.md").write_text(textwrap.dedent(text), encoding="utf-8")
    return directory


def test_sim_reads_a_sample_guide(tmp_path):
    runs = sim.simulate(write(tmp_path, {1: SAMPLE_1}), modules=[1])
    assert [r.as_manifest() for r in runs] == [
        {"module": 1, "scenario": "s1", "mode": "off", "signing": "ML-DSA-65",
         "policy": {"m3": "starter", "m4": "starter", "m5": "starter", "m6": "starter"},
         "answer": None, "clean": False, "command": "run s1"},
        {"module": 1, "scenario": "s1", "mode": "enforce", "signing": "ML-DSA-65",
         "policy": {"m3": "starter", "m4": "starter", "m5": "starter", "m6": "starter"},
         "answer": None, "clean": False, "command": "run s1"},
    ]


def test_sim_carries_state_into_the_next_guide(tmp_path):
    runs = sim.simulate(write(tmp_path, {1: SAMPLE_1, 2: SAMPLE_2}), modules=[1, 2])
    last = runs[-1].as_manifest()
    assert last["module"] == 2 and last["mode"] == "enforce" and last["signing"] == "HMAC-SHA256"
    assert last["policy"]["m3"] == "solution" and last["answer"] == "approve"
    assert last["command"] == "run s4a --answer approve"


def test_sim_starts_from_the_shipped_settings():
    state = sim.shipped_state()
    assert (state.mode, state.signing) == ("enforce", "ML-DSA-65")
    assert state.policy == {"m3": "starter", "m4": "starter", "m5": "starter", "m6": "starter"}


def test_sim_missing_guide_leaves_the_state_unknown(tmp_path):
    with pytest.raises(sim.GuideError, match=r"mode.*modules/1\.md is missing"):
        sim.simulate(write(tmp_path, {2: "```sh\n./lab.sh run s2\n```\n"}), modules=[1, 2])


def test_sim_guide_that_sets_everything_stands_alone(tmp_path):
    text = ("```sh\n./lab.sh mode shadow\n./lab.sh sign mldsa\n./lab.sh policy 3 starter\n./lab.sh policy 4 starter\n"
            "./lab.sh policy 5 starter\n./lab.sh policy 6 starter\n./lab.sh run s2\n./lab.sh check 2\n```\n")
    runs = sim.simulate(write(tmp_path, {2: text}), modules=[1, 2])
    assert runs[0].mode == "shadow" and runs[0].module == 2


@pytest.mark.parametrize("line, why", [
    ("lab.sh run s1", "./lab.sh"),
    ("docker compose up", "./lab.sh"),
    ("./lab.sh mode loud", "mode"),
    ("./lab.sh sign rsa", "sign"),
    ("./lab.sh policy 2 solution", "policy"),
    ("./lab.sh policy 3 answer", "policy"),
    ("./lab.sh run s9", "scenario"),
    ("./lab.sh run s4a --answer maybe", "--answer"),
    ("./lab.sh run s1 --clean --clean", "--clean"),
    ("./lab.sh record s1__off s1", "owner"),
    ("./lab.sh run s1 \\", "continuation"),
])
def test_sim_refuses_what_the_lab_would_refuse(tmp_path, line, why):
    with pytest.raises(sim.GuideError, match=re.escape(why)):
        sim.simulate(write(tmp_path, {1: f"```sh\n{line}\n```\n"}), modules=[1])


def test_sim_skips_fences_that_are_not_shell():
    fences = sim.fences("```json\n{}\n```\n~~~text\nout\n~~~\n````sh\n./lab.sh up\n````\n")
    assert [(f[1], f[2]) for f in fences] == [("json", ["{}"]), ("text", ["out"]), ("sh", ["./lab.sh up"])]


def test_known_verbs_come_from_lab_sh_and_the_cli():
    verbs = sim.known_verbs()
    assert {"run", "record", "mode", "sign", "up", "reset", "help"} <= verbs  # lab.sh's own dispatch
    assert {"check", "policy", "forge", "verify", "downgrade", "model-log", "approver", "init"} <= verbs  # the CLI
    assert not {v for v in verbs if v.startswith("_")}, "internal verbs aren't the attendee's"


def test_host_verbs_follow_the_dispatch_table():
    text = ("case $verb in\n    a) x ;;\n    *) w ;;\nesac\n"
            "case $verb in\n    up | -u)\n        y ;;\n    new)\n        z ;;\n"
            "    *)\n        lab \"$verb\" \"$@\" ;;\nesac\n")
    assert sim.host_verbs(text) == {"up", "-u", "new"}


def test_sentence_rule_on_a_sample():
    short = "Run the lab. " * 3
    long = " ".join(["word"] * 26) + "."
    assert long_sentences(short) == []
    assert len(long_sentences(long)) == 1
    assert long_sentences("```sh\n" + long + "\n```\n") == []
    assert long_sentences(f"`{long}` is one code token.") == []


def test_link_rule_on_a_sample():
    terms = {"Guardian": "guardian", "Tool call": "tool-call"}
    good = "The [Guardian](glossary.md#guardian) sees each [tool call](glossary.md#tool-call). The Guardian answers."
    assert unlinked_first_uses(good, terms) == []
    bad = "The Guardian answers. See the [Guardian](glossary.md#guardian). Two [tool calls](glossary.md#decision)."
    problems = unlinked_first_uses(bad, terms)
    assert len(problems) == 2 and "plain text" in problems[0] and "glossary.md#decision" in problems[1]
    assert unlinked_first_uses("## The Guardian\n\n`./lab.sh guardian`\n", terms) == []


def test_slug_matches_github():
    assert slug("ML-DSA-65") == "ml-dsa-65"
    assert slug("Tool call") == "tool-call"
    assert slug("Forgery <!-- claim:C-04 -->") == "forgery"
    assert slug("Forgery<!-- claim:C-04 -->") == "forgery"


def test_person_rule_reads_governance():
    patterns, names = person_rules()
    assert len(names) >= 6, "GOVERNANCE.md's lead table changed shape, so the deny list came back short"
    assert people_named("Mail collector@exfil.example and ap@northwind-supplies.example.") == []
    assert people_named("Ask @someone first.") and people_named("Open /Users/x/lab.")


# The command order the plan's guide-run table implies, one list per guide. The module lanes write their fences in
# this order, and this test proves the manifest is reachable through the guide grammar at all.
REFERENCE_COMMANDS = {
    1: ["mode off", "run s1", "mode enforce", "run s1", "check 1"],
    2: ["mode off", "run s2", "mode shadow", "run s2", "check 2"],
    3: ["mode enforce", "run s2", "run s3", "policy 3 solution", "run s2", "run s3", "check 3"],
    4: ["mode off", "run s4a", "mode enforce", "policy 4 solution", "approver", "run s4a --answer approve",
        "run s4a --answer reject", "run s4b", "check 4"],
    5: ["mode off", "run s5", "model-log", "mode enforce", "policy 5 solution", "run s5", "model-log", "check 5"],
    6: ["mode off", "run s6", "mode enforce", "policy 6 solution", "run s6", "check 6"],
    7: ["sign hmac", "run s2", "forge", "sign mldsa", "run s2", "forge", "verify --keys-only", "downgrade",
        "logs acs-guardian", "check 7"],
}


def test_manifest_is_reachable_by_guides(tmp_path):
    files = {n: "```sh\n" + "".join(f"./lab.sh {c}\n" for c in cmds) + "```\n"
             for n, cmds in REFERENCE_COMMANDS.items()}
    runs = sim.simulate(write(tmp_path, files))
    keys = sim.Run.MANIFEST_KEYS
    assert [r.as_manifest() for r in runs] == [{k: e[k] for k in keys} for e in manifest_runs() if e["module"]]
    verbs = sim.known_verbs()
    assert all(c.split()[0] in verbs for cmds in REFERENCE_COMMANDS.values() for c in cmds)


# ---------------------------------------------------------------------------------------------------------------------
# Fix round 1: every command a reader could copy goes through one grammar, and the guide's steps run in an order the
# lab accepts. Each probe starts from guides that pass, changes one guide, and must be refused naming why.
# ---------------------------------------------------------------------------------------------------------------------

def fence(cmds: list[str], tag: str = "sh") -> str:
    return f"```{tag}\n" + "".join(f"./lab.sh {c}\n" for c in cmds) + "```\n"


def reference_files() -> dict[int, str]:
    return {n: fence(cmds) for n, cmds in REFERENCE_COMMANDS.items()}


def with_guide(n: int, text: str) -> dict[int, str]:
    files = reference_files()
    files[n] = text
    return files


R1 = REFERENCE_COMMANDS[1]
SH_BLOCK = "put this command in a sh block"
R7 = REFERENCE_COMMANDS[7]

PROBES = {
    "operator after a verb": (1, fence([*R1[:-1], "check 1 && ./lab.sh record s1__x s1"]), "shell operator"),
    "semicolon": (1, fence([*R1[:-1], "check 1; ./lab.sh up"]), "shell operator"),
    "pipe": (1, fence([*R1[:-1], "check 1 | tee out"]), "shell operator"),
    "redirect": (1, fence([*R1[:-1], "check 1 > out.txt"]), "shell operator"),
    "command substitution": (1, fence([*R1[:-1], "check $(echo 1)"]), "shell operator"),
    "check of no module": (1, fence([*R1[:-1], "check 9"]), "check 1"),
    "check of another module": (1, fence([*R1[:-1], "check 2"]), "check 1"),
    "bare check": (1, fence([*R1[:-1], "check"]), "check 1"),
    "typo'd verify flag": (7, fence([*R7[:6], "verify --keys-onyl", *R7[7:]]), "verify"),
    "typo'd service": (7, fence([*R7[:8], "logs acs-gaurdian", R7[9]]), "logs"),
    "traces value": (1, fence(["traces maybe", *R1]), "traces"),
    "argument to a verb that takes none": (7, fence([*R7[:2], "forge now", *R7[3:]]), "forge"),
    "check before its runs": (1, fence(["check 1", *R1]), "before"),
    "no check after the last run": (1, fence(R1[:-1]), "check 1"),
    "reset between runs": (1, fence([*R1[:2], "reset", *R1[2:]]), "reset"),
    "init partway": (7, fence([*R7[:4], "init", *R7[4:]]), "init"),
    "init when guide 1 already did it": (2, fence(["init", *REFERENCE_COMMANDS[2]]), "init"),
    "upstream openai": (1, fence(["upstream openai", *R1]), "replay"),
    "owner-only verb": (1, fence(["record s1__x s1", *R1]), "owner only"),
    "underscore verb": (1, fence(["_drive s1", *R1]), "_drive"),
    "pins rewrites the shipped registry": (6, fence(["pins", *REFERENCE_COMMANDS[6]]), "pins"),
    "down before the end": (1, fence([*R1[:2], "down", *R1[2:]]), "down"),
    "up partway": (1, fence([*R1[:2], "up", *R1[2:]]), "up"),
    "record in a text fence": (1, fence(R1) + fence(["record s1__x s1"], "text"), SH_BLOCK),
    "unknown fence tag": (1, fence(R1) + fence(["record s1__x s1"], "terminal"), "terminal"),
    "shell-session fence": (1, fence(R1) + fence(["check 1"], "shell-session"), "shell-session"),
    "fence inside a list item": (1, fence(R1) + "\n1. Then run:\n\n    ```sh\n    ./lab.sh record s1__x s1\n    ```\n",
                                 "owner only"),
    "indented code block": (1, fence(R1) + "\nThen:\n\n    ./lab.sh record s1__x s1\n", SH_BLOCK),
    "inline code": (1, fence(R1) + "\nOr run `./lab.sh record s1__x s1` yourself.\n", SH_BLOCK),
    "inline lab without lab.sh": (1, fence(R1) + "\nRun `lab check 1` again.\n", SH_BLOCK),
    "bare command in prose": (1, fence(R1) + "\nThen run ./lab.sh check 1 again.\n", SH_BLOCK),
    "inline code of another module's check": (1, fence(R1) + "\nCompare `./lab.sh check 2`.\n", SH_BLOCK),
}


@pytest.mark.parametrize("name", PROBES)
def test_probe_is_refused(tmp_path, name):
    module, text, why = PROBES[name]
    with pytest.raises(sim.GuideError, match=re.escape(why)):
        sim.simulate(write(tmp_path, with_guide(module, text)), focus=module)


def test_reference_guides_pass_every_rule(tmp_path):
    runs = sim.simulate(write(tmp_path, reference_files()))
    assert len(runs) == len([e for e in manifest_runs() if e["module"]])


@pytest.mark.parametrize("text", [
    "Run `./lab.sh` from `labs/finbot`.\n",  # the script named alone, re-review false positive
    "The `lab state` is yours to wipe.\n",  # lab as a plain word, re-review false positive
    "Install Docker Desktop, and the lab needs nothing else.\n",
    "lab.sh hands every other verb to the CLI.\n",
    "```text\nDONE: module 1 passed\n```\n",
    "```json\n{\"a\": 1}\n```\n",
    "```rego\nallow if { true }\n```\n",
    "The `check` verb reads `state/`.\n",  # prose naming a verb isn't a command
])
def test_allowed_extras_pass(tmp_path, text):
    sim.simulate(write(tmp_path, with_guide(1, fence(R1) + "\n" + text)), focus=1)


def test_setup_commands_may_lead_guide_one(tmp_path):
    sim.simulate(write(tmp_path, with_guide(1, fence(["doctor", "init", "up", *R1]))), focus=1)


def test_reset_at_the_top_then_init(tmp_path):
    text = fence(["reset", "init", "up", *REFERENCE_COMMANDS[2]])
    sim.simulate(write(tmp_path, with_guide(2, text)), focus=2)


def test_an_earlier_broken_guide_leaves_the_later_one_its_own(tmp_path):
    files = reference_files()
    files[1] = fence(["record s1__x s1"])
    standalone = fence(["mode off", "sign mldsa", *(f"policy {n} starter" for n in (3, 4, 5, 6)), "run s2",
                        "mode shadow", "run s2", "check 2"])
    files[2] = standalone
    runs = sim.simulate(write(tmp_path, files), modules=[1, 2], focus=2)
    assert [r.module for r in runs] == [2, 2]
    with pytest.raises(sim.GuideError) as e:
        sim.simulate(write(tmp_path, files), modules=[1, 2], focus=1)
    assert e.value.module == 1


def test_every_lab_verb_has_a_grammar_or_a_refusal():
    verbs = sim.known_verbs()
    covered = set(sim.GRAMMAR) | set(sim.REFUSED)
    assert verbs - covered == set(), "a new lab verb needs a guide grammar or a stated refusal in guide_sim.py"
    assert set(sim.GRAMMAR) <= verbs, "the grammar names a verb the lab doesn't take"


def test_owner_only_verbs_come_from_lab_sh():
    assert sim.owner_only_verbs() == {"record"}
    assert sim.owner_only_verbs("# Command table:\n#   x A    owner only: y\n#   z      z\n# Exit 0\n") == {"x"}


def test_dispatch_is_the_table_with_the_catch_all():
    text = ("case $verb in\n    a) x ;;\n    *) lab \"$verb\" \"$@\" ;;\nesac\n"
            "f() {\n  case $verb in\n    b) z ;;\n    *) lab \"$verb\" ;;\n  esac\n}\n")
    assert sim.host_verbs(text) == {"a"}
    with pytest.raises(sim.GuideError):
        sim.host_verbs("case $verb in\n    a) x ;;\nesac\n")


def test_scenarios_follow_lab_sh_and_the_files():
    assert sim.scenario_ids() == {"s1", "s2", "s3", "s4a", "s4b", "s5", "s6"}
    assert sim.scenario_patterns() == ["s[1-6]", "s[1-6][ab]"]


def test_services_come_from_compose():
    assert {"acs-guardian", "acs-gateway", "finbot", "opa", "acs-viewer"} <= sim.service_names()


def test_trust_boundary_must_be_visible():
    hidden = f"<!-- {TRUST_BOUNDARY} -->\n\n```text\n{TRUST_BOUNDARY}\n```\n"
    assert TRUST_BOUNDARY not in prose(hidden)
    assert TRUST_BOUNDARY in prose(f"Note. {TRUST_BOUNDARY}\n")


# ---------------------------------------------------------------------------------------------------------------------
# Fix round 2: lab commands live in one place, sh, bash or console fences, where the order is walked. Anything outside
# one that reads as a lab command once folded is refused, however it is spelled.
# ---------------------------------------------------------------------------------------------------------------------

CYRILLIC_A = "\u0430"
FULLWIDTH_DOT = "\uff0e"
ZERO_WIDTH = "\u200b"
BETWEEN = fence(R1[:2]) + "\n{}\n\n" + fence(R1[2:])

PROBES_R2 = {
    "entity in pre": (1, fence(R1) + "\n<pre>&#46;/lab.sh record s1__x s1</pre>\n", SH_BLOCK),
    "lab.sh in a pre block": (1, fence(R1) + "\n<pre>\nlab.sh check 9\n</pre>\n", SH_BLOCK),
    "code element": (1, fence(R1) + "\n<code>./lab.sh check 1</code>\n", SH_BLOCK),
    "blockquoted sh fence, docker": (1, fence(R1) + "\n> ```sh\n> docker compose down -v\n> ```\n", SH_BLOCK),
    "blockquoted sh fence, lab": (1, fence(R1) + "\n> ```sh\n> ./lab.sh check 1\n> ```\n", SH_BLOCK),
    "blockquote line": (1, fence(R1) + "\n> Run `./lab.sh check 1`.\n", SH_BLOCK),
    "table cell": (1, fence(R1) + "\n| Step | Command |\n|---|---|\n| one | `./lab.sh check 1` |\n", SH_BLOCK),
    "untagged fence": (1, fence(R1) + fence(["check 1"], ""), SH_BLOCK),
    "cyrillic inline": (1, fence(R1) + f"\nRun `./l{CYRILLIC_A}b.sh check 1`.\n", SH_BLOCK),
    "cyrillic prose": (1, fence(R1) + f"\nRun ./l{CYRILLIC_A}b.sh check 1 now.\n", SH_BLOCK),
    "cyrillic text fence": (1, fence(R1) + f"```text\n./l{CYRILLIC_A}b.sh check 1\n```\n", SH_BLOCK),
    "fullwidth dot inline": (1, fence(R1) + f"\nRun `{FULLWIDTH_DOT}/lab.sh check 1`.\n", SH_BLOCK),
    "zero width inline": (1, fence(R1) + f"\nRun `./lab{ZERO_WIDTH}.sh check 1`.\n", SH_BLOCK),
    "no dot slash inline": (1, fence(R1) + "\nRun `lab.sh check 1`.\n", SH_BLOCK),
    "no dot slash text fence": (1, fence(R1) + "```text\nlab.sh check 9\n```\n", SH_BLOCK),
    "bash lab.sh inline": (1, fence(R1) + "\nRun `bash lab.sh check 9`.\n", SH_BLOCK),
    "dot slash lab without .sh": (1, fence(R1) + "\nRun `./lab check 1`.\n", SH_BLOCK),
    "prompt in a text fence": (1, fence(R1) + "```text\n$ ./lab.sh record s1__x s1\n```\n", SH_BLOCK),
    "docker compose in prose": (1, fence(R1) + "\nIf stuck, run docker compose down -v.\n", SH_BLOCK),
    "docker inline": (1, fence(R1) + "\nCheck with `docker ps`.\n", SH_BLOCK),
    "inline reset between runs": (1, BETWEEN.format("If it breaks, run `./lab.sh reset`."), SH_BLOCK),
    "inline down between runs": (1, BETWEEN.format("Run `./lab.sh down` for a break."), SH_BLOCK),
    "inline mode between runs": (1, BETWEEN.format("Now run `./lab.sh mode shadow`."), SH_BLOCK),
    "text fence reset between runs": (1, BETWEEN.format("```text\n./lab.sh reset\n```"), SH_BLOCK),
    "inline init in guide 3": (3, fence(REFERENCE_COMMANDS[3]) + "\nIf you skipped it, run `./lab.sh init`.\n",
                               SH_BLOCK),
    "inline run in guide 1": (1, fence(R1) + "\nYou can also run `./lab.sh run s3`.\n", SH_BLOCK),
    "html comment is never read, but a pre is": (1, fence(R1) + "\n<pre>./lab.sh up</pre>\n", SH_BLOCK),
    "prompt in a sh fence": (1, fence(R1) + "```sh\n$ ./lab.sh check 1\n```\n", "prompt"),
    "cyrillic in a sh fence": (1, fence(R1) + f"```sh\n./l{CYRILLIC_A}b.sh check 1\n```\n", "lookalike"),
    "zero width in a sh fence": (1, fence(R1) + f"```sh\n./lab.sh check{ZERO_WIDTH} 1\n```\n", "lookalike"),
    "shell tag is not a command block": (1, fence(R1) + fence(["check 1"], "shell"), "shell"),
    "up before init in guide 1": (1, fence(["up", "init", *R1]), "init"),
    "reset, up, init in guide 2": (2, fence(["reset", "up", "init", *REFERENCE_COMMANDS[2]]), "init"),
}


@pytest.mark.parametrize("name", PROBES_R2)
def test_probe_r2_is_refused(tmp_path, name):
    module, text, why = PROBES_R2[name]
    with pytest.raises(sim.GuideError, match=re.escape(why)):
        sim.simulate(write(tmp_path, with_guide(module, text)), focus=module)


@pytest.mark.parametrize("tag", ["sh", "bash", "console"])
def test_each_command_tag_is_walked(tmp_path, tag):
    runs = sim.simulate(write(tmp_path, with_guide(1, fence(R1, tag))), modules=[1])
    assert [r.mode for r in runs] == ["off", "enforce"]


SESSION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.mark.parametrize("args", [[], ["--keys-only"], ["--session", SESSION], ["--keys-only", "--session", SESSION],
                                  ["--session", SESSION, "--keys-only"]])
def test_verify_takes_the_kit_flags(args):
    assert sim.parse(" ".join(["./lab.sh", "verify", *args]), 7)


@pytest.mark.parametrize("args", [["--session"], ["--keys-only", "--keys-only"], ["--chain"],
                                  ["--session", SESSION, "--session", SESSION]])
def test_verify_refuses_what_the_kit_refuses(args):
    with pytest.raises(sim.GuideError) as e:
        sim.parse(" ".join(["./lab.sh", "verify", *args]), 7)
    assert str(e.value) == sim.kit_parser("verify").USAGE


def test_verify_flags_come_from_the_kit(monkeypatch):
    """The rule is the kit's parser itself, so a flag the kit learns is one the guides may use, with nothing copied."""
    kit = sim.kit_parser("verify")
    real = kit.parse_arguments

    def taught(argv):
        return (True, None) if argv == ["--learned"] else real(argv)

    monkeypatch.setattr(kit, "parse_arguments", taught)
    assert sim.parse("./lab.sh verify --learned", 7)


@pytest.mark.parametrize("args", [[], ["--session", SESSION]])
def test_forge_takes_the_kit_flags(args):
    assert sim.parse(" ".join(["./lab.sh", "forge", *args]), 7)


@pytest.mark.parametrize("args", [["--session"], ["now"], ["--keys-only"], ["--session", SESSION, "--session", SESSION]])
def test_forge_refuses_what_the_kit_refuses(args):
    with pytest.raises(sim.GuideError) as e:
        sim.parse(" ".join(["./lab.sh", "forge", *args]), 7)
    assert str(e.value) == sim.kit_parser("forge").USAGE


def test_forge_flags_come_from_the_kit(monkeypatch):
    kit = sim.kit_parser("forge")
    real = kit.parse_arguments

    def taught(argv):
        return None if argv == ["--learned"] else real(argv)

    monkeypatch.setattr(kit, "parse_arguments", taught)
    assert sim.parse("./lab.sh forge --learned", 7)


@pytest.mark.parametrize("verb", ["forge", "verify"])
def test_kit_session_must_be_a_session_id(verb):
    """A placeholder such as <id> passes a parser that takes any string, then fails when copied (review M6)."""
    with pytest.raises(sim.GuideError, match="session id"):
        sim.parse(f"./lab.sh {verb} --session not-a-session", 7)


def test_need_init_verbs_come_from_lab_sh():
    assert sim.need_init_verbs() == {"up", "run", "record"}


def test_fold_reads_what_a_reader_sees():
    assert sim.fold(f"&#46;/l{CYRILLIC_A}b{ZERO_WIDTH}.sh") == "./lab.sh"
    assert sim.fold("$ ./lab.sh up") == "./lab.sh up"
    assert sim.fold("bash lab.sh up") == "lab.sh up"
    assert sim.fold(f"{FULLWIDTH_DOT}/lab.sh") == "./lab.sh"
