"""One runner for every suite, with a sealed slice a steward holds.

This is the runner docs/HELD-OUT-CONFORMANCE.md describes, built. A suite is
data: a small JSON file under ``suites/`` that names its corpus, where the
question sits inside each member, the verdict vocabulary and which fields are
opaque identifiers. Adding a suite means adding a file, never a branch here.

Four things the design asks for, and where each one lives:

* Suites as data: ``load_suite``.
* A sealed slice whose generator is public and whose seed is not: ``seal``.
  The steward publishes ``commitment(seed)`` before a release and the seed
  after it, and anyone can then regenerate the slice with ``reveal``.
* An attested adapter: the implementation under test runs out of process, one
  child for the whole run, and the run record pins the bytes of every file its
  command line names, not the name it calls itself.
* A run-end seal: the record closes with a digest over everything above it,
  including the transcript's digest, so an edited record no longer verifies.

Stdlib only, like the rest of the rail, so a relying party needs nothing but a
CPython install.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import hmac
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from typing import Any

RUN_SCHEMA = "agent-evidence-vectors/heldout-run/v1"
SEALED_SCHEMA = "agent-evidence-vectors/heldout-sealed/v1"
SUITE_SCHEMA = "agent-evidence-vectors/heldout-suite/v1"
SEED_DOMAIN = b"agent-evidence-vectors/heldout-seed/v1"
MIN_SEED_BYTES = 32
ANSWER_TIMEOUT_SECONDS = 30.0

HERE = os.path.dirname(os.path.abspath(__file__))


class RunnerError(Exception):
    """A condition under which nothing honest can be reported as a result."""


# --------------------------------------------------------------------------
# Suites and corpora


def corpora_root() -> str:
    """The corpora beside the installed package, or the checkout root."""
    installed = os.path.join(HERE, "corpora")
    if os.path.isdir(installed):
        return installed
    return os.path.dirname(os.path.dirname(HERE))


def suite_names() -> list[str]:
    return sorted(
        name[: -len(".json")]
        for name in os.listdir(os.path.join(HERE, "suites"))
        if name.endswith(".json")
    )


def load_suite(name_or_path: str) -> dict[str, Any]:
    """A suite by shipped name, or by path to a descriptor of one's own."""
    path = name_or_path
    if not os.path.isfile(path):
        path = os.path.join(HERE, "suites", f"{name_or_path}.json")
    if not os.path.isfile(path):
        raise RunnerError(
            f"no suite named {name_or_path!r}; shipped suites: {', '.join(suite_names())}"
        )
    raw = _read(path)
    suite: dict[str, Any] = json.loads(raw)
    if suite.get("schema") != SUITE_SCHEMA:
        raise RunnerError(f"{path} is not a {SUITE_SCHEMA} descriptor")
    corpus = suite["corpus"]
    suite["_dir"] = corpus if os.path.isabs(corpus) else os.path.join(corpora_root(), corpus)
    suite["_digest"] = _sha(raw)
    return suite


def load_public(suite: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Every published member, the manifest, and the corpus digest recomputed."""
    manifest = json.loads(_read(os.path.join(suite["_dir"], "MANIFEST.json")))
    if manifest.get("suite") != suite["suite"]:
        raise RunnerError(
            f"{suite['_dir']} holds suite {manifest.get('suite')!r}, "
            f"the descriptor names {suite['suite']!r}"
        )
    members = []
    blob = hashlib.sha256()
    for entry in manifest["vectors"]:
        raw = _read(os.path.join(suite["_dir"], entry["file"]))
        blob.update(raw)
        document = json.loads(raw)
        members.append(_member(document, "public"))
    return members, manifest, blob.hexdigest()


def _member(document: dict[str, Any], partition: str) -> dict[str, Any]:
    return {
        "id": document["id"],
        "family": document["family"],
        "expected": document["expected"],
        "document": document,
        "partition": partition,
    }


# --------------------------------------------------------------------------
# The sealed slice


def commitment(seed: bytes) -> str:
    """What the steward publishes before a release: it binds, it does not reveal."""
    return _sha(SEED_DOMAIN + b"\0commit\0" + seed)


def read_seed(path: str) -> bytes:
    seed = _read(path).strip()
    if len(seed) < MIN_SEED_BYTES:
        raise RunnerError(
            f"the seed in {path} is {len(seed)} bytes; a seed shorter than "
            f"{MIN_SEED_BYTES} can be searched for, and a searched seed is a published one"
        )
    return seed


def _tag(seed: bytes, *parts: str) -> str:
    message = b"\0".join(part.encode("utf-8") for part in parts)
    return hmac.new(seed, SEED_DOMAIN + b"\0" + message, hashlib.sha256).hexdigest()


def select(
    members: list[dict[str, Any]], seed: bytes, per_family: int, suite: dict[str, Any]
) -> list[dict[str, Any]]:
    """Which public members the sealed slice re-instantiates, per family.

    Every family contributes, so a sealed result can be compared with the
    public result family by family; the choice inside a family is the seed's.
    Only a member carrying an opaque identifier can be respelled. One without
    any would come out byte-identical to its published self, which a lookup
    table answers, so it is never chosen.
    """
    if per_family < 1:
        raise RunnerError("a sealed slice needs at least one member per family")
    families: dict[str, list[dict[str, Any]]] = {}
    for member in members:
        families.setdefault(member["family"], [])
        question = member["document"][suite["question"]]
        if rekey(question, seed, member["id"], suite) != question:
            families[member["family"]].append(member)
    bare = sorted(family for family, pool in families.items() if not pool)
    if bare:
        raise RunnerError(f"families with no member that can be respelled: {', '.join(bare)}")
    chosen = []
    for family in sorted(families):
        ranked = sorted(families[family], key=lambda m: _tag(seed, "select", m["id"]))
        chosen.extend(ranked[:per_family])
    return chosen


def rekey(question: Any, seed: bytes, member_id: str, suite: dict[str, Any]) -> Any:
    """The same question with every opaque identifier respelled.

    The map is keyed by the seed and the member, and it is applied to every
    string equal to an opaque value anywhere in the question, so equality
    inside the member survives: a duplicated request_id stays duplicated and
    a step that cites a session still cites the same one.
    """
    keys = set(suite["opaque"]["keys"])
    uuid_keys = set(suite["opaque"]["uuidKeys"])
    found: dict[str, bool] = {}
    for key, value in _string_fields(question):
        if key in keys or key in uuid_keys:
            found[value] = found.get(value, False) or key in uuid_keys
    renamed = {}
    for value, is_uuid in found.items():
        digest = _tag(seed, "rename", member_id, value)
        renamed[value] = _uuid4_shape(digest) if is_uuid else f"h-{digest[:12]}"
    return _replace(copy.deepcopy(question), renamed)


def _string_fields(node: Any) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str):
                yield key, value
            else:
                yield from _string_fields(value)
    elif isinstance(node, list):
        for item in node:
            yield from _string_fields(item)


def _replace(node: Any, renamed: dict[str, str]) -> Any:
    if isinstance(node, dict):
        return {key: _replace(value, renamed) for key, value in node.items()}
    if isinstance(node, list):
        return [_replace(item, renamed) for item in node]
    if isinstance(node, str):
        return renamed.get(node, node)
    return node


def _uuid4_shape(digest: str) -> str:
    h = list(digest[:32])
    h[12] = "4"
    h[16] = "89ab"[int(h[16], 16) % 4]
    s = "".join(h)
    return f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"


def identify(document: dict[str, Any], suite: dict[str, Any]) -> str:
    """A member's name is a digest of its bytes, as in the public corpus."""
    payload = json.dumps(
        {key: document[key] for key in suite["identity"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "v" + _sha(payload)[:16]


def seal(suite: dict[str, Any], seed: bytes, per_family: int) -> dict[str, Any]:
    """The sealed slice as data: a manifest and its member documents."""
    public, _, corpus_digest = load_public(suite)
    question_key = suite["question"]
    members = []
    for source in select(public, seed, per_family, suite):
        document = copy.deepcopy(source["document"])
        document[question_key] = rekey(document[question_key], seed, source["id"], suite)
        document["id"] = identify(document, suite)
        members.append({"document": document, "derivedFrom": source["id"]})
    members.sort(key=lambda m: m["document"]["id"])
    return {
        "schema": SEALED_SCHEMA,
        "suite": suite["suite"],
        "commitment": commitment(seed),
        "perFamily": per_family,
        "sourceCorpusDigest": corpus_digest,
        "generatorDigest": generator_digest(),
        "members": members,
    }


def write_sealed(sealed: dict[str, Any], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "SEALED.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sealed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def load_sealed(path: str, suite: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sealed = json.loads(_read(path))
    if sealed.get("schema") != SEALED_SCHEMA or sealed.get("suite") != suite["suite"]:
        raise RunnerError(f"{path} is not a sealed slice of {suite['suite']}")
    members = []
    for item in sealed["members"]:
        document = item["document"]
        if identify(document, suite) != document["id"]:
            raise RunnerError(f"sealed member {document['id']} is not named after its bytes")
        members.append(_member(document, "sealed"))
    return members, sealed


def reveal(suite: dict[str, Any], seed: bytes, sealed: dict[str, Any]) -> list[str]:
    """Every way a published seed fails to reproduce the slice a run used."""
    problems = []
    if commitment(seed) != sealed["commitment"]:
        problems.append("the seed does not open the published commitment")
    again = seal(suite, seed, sealed["perFamily"])
    if again["sourceCorpusDigest"] != sealed["sourceCorpusDigest"]:
        problems.append("the public corpus changed since the slice was sealed")
    mine = [m["document"]["id"] for m in again["members"]]
    theirs = [m["document"]["id"] for m in sealed["members"]]
    if mine != theirs:
        problems.append("the seed regenerates a different slice than the one held")
    return problems


def generator_digest() -> str:
    """The bytes of this file, which is the sealed generator and the runner both."""
    return _sha(_read(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# The attested adapter run


def adapter_files(argv: list[str]) -> list[dict[str, str]]:
    """A digest for every element of the command line that names a file.

    The program is resolved on PATH the way the child will resolve it. An
    implementation name and a version string are a claim; these are bytes a
    second party can recompute.
    """
    pinned = []
    for index, arg in enumerate(argv):
        path = shutil.which(arg) if index == 0 else None
        if path is None and os.path.isfile(arg):
            path = arg
        if path is not None:
            real = os.path.realpath(path)
            pinned.append({"arg": arg, "path": real, "sha256": _sha(_read(real))})
    if not pinned:
        raise RunnerError(f"no element of the adapter command {argv!r} names a file to pin")
    return pinned


class Adapter:
    """One child process for the whole run, spoken to in JSON lines."""

    def __init__(self, argv: list[str], stderr_path: str, timeout: float) -> None:
        self.timeout = timeout
        self._stderr = open(stderr_path, "wb")
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
            )
        except OSError as exc:
            self._stderr.close()
            raise RunnerError(f"the adapter could not be started: {exc}") from exc
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def ask(self, request: bytes) -> tuple[bytes | None, str]:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(request + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return None, "adapter-exited"
        try:
            line = self._lines.get(timeout=self.timeout)
        except queue.Empty:
            return None, "adapter-timeout"
        if line is None:
            return None, "adapter-exited"
        return line.rstrip(b"\n"), ""

    def close(self) -> int | None:
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            code = self.proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        self._stderr.close()
        return code


def judge(
    member: dict[str, Any], line: bytes | None, stop: str, suite: dict[str, Any]
) -> dict[str, Any]:
    """One row: pass or fail, and the branch that produced it."""
    expected = member["expected"]
    row: dict[str, Any] = {
        "id": member["id"],
        "family": member["family"],
        "partition": member["partition"],
        "expectedVerdict": expected["verdict"],
        "expectedCode": expected.get("code"),
    }
    if line is None:
        return {**row, "pass": False, "stopReason": stop}
    try:
        answer = json.loads(line)
    except ValueError:
        return {**row, "pass": False, "stopReason": "answer-not-json"}
    if not isinstance(answer, dict) or answer.get("verdict") not in suite["verdicts"]:
        return {**row, "pass": False, "stopReason": "answer-outside-vocabulary"}
    row["verdict"] = answer["verdict"]
    row["code"] = answer.get("code")
    if answer["verdict"] != expected["verdict"]:
        return {**row, "pass": False, "stopReason": "verdict-differs"}
    if expected.get("code") is not None and answer.get("code") != expected["code"]:
        return {**row, "pass": False, "stopReason": "code-differs"}
    return {**row, "pass": True, "stopReason": "matched"}


def run(
    suite: dict[str, Any],
    argv: list[str],
    sealed_path: str | None,
    transcript_path: str,
    timeout: float = ANSWER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run every member through one adapter child and return the sealed record."""
    public, _, corpus_digest = load_public(suite)
    members = list(public)
    sealed_meta = None
    if sealed_path is not None:
        sealed_members, sealed = load_sealed(sealed_path, suite)
        if sealed["sourceCorpusDigest"] != corpus_digest:
            raise RunnerError("the sealed slice was cut from a different public corpus")
        members.extend(sealed_members)
        sealed_meta = {
            "commitment": sealed["commitment"],
            "members": len(sealed_members),
            "digest": _sha(_read(sealed_path)),
            "generatorDigest": sealed["generatorDigest"],
        }
    if not members:
        raise RunnerError("the suite has no members, and a run that scores nothing is not a pass")
    # Content-addressed names sort into an order that says nothing about
    # partition or verdict, so a sealed member cannot be spotted by position.
    members.sort(key=lambda m: m["id"])
    pinned = adapter_files(argv)
    started = _now()
    rows = []
    stderr_path = transcript_path + ".stderr"
    adapter = Adapter(argv, stderr_path, timeout)
    with open(transcript_path, "wb") as transcript:
        for member in members:
            request = json.dumps(
                {"question": member["document"][suite["question"]]},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            line, stop = adapter.ask(request)
            transcript.write(b"> " + request + b"\n")
            transcript.write(b"< " + (line if line is not None else stop.encode()) + b"\n")
            rows.append(judge(member, line, stop, suite))
    exit_code = adapter.close()
    ended = _now()
    record: dict[str, Any] = {
        "schema": RUN_SCHEMA,
        "suite": {
            "name": suite["name"],
            "id": suite["suite"],
            "descriptorDigest": suite["_digest"],
        },
        "corpusDigest": corpus_digest,
        "sealed": sealed_meta,
        "runner": {"generatorDigest": generator_digest(), "python": sys.version.split()[0]},
        "adapter": {"argv": argv, "files": pinned, "exitCode": exit_code},
        "started": started,
        "ended": ended,
        "transcriptDigest": _sha(_read(transcript_path)),
        "stderrDigest": _sha(_read(stderr_path)),
        "totals": totals(rows),
        "rows": rows,
    }
    record["seal"] = seal_digest(record)
    return record


def totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Pass counts per partition and per family, and the gap between them."""
    out: dict[str, Any] = {}
    for partition in ("public", "sealed"):
        mine = [r for r in rows if r["partition"] == partition]
        families: dict[str, list[int]] = {}
        for r in mine:
            counts = families.setdefault(r["family"], [0, 0])
            counts[0] += int(r["pass"])
            counts[1] += 1
        out[partition] = {
            "pass": sum(int(r["pass"]) for r in mine),
            "of": len(mine),
            "families": {f: {"pass": c[0], "of": c[1]} for f, c in sorted(families.items())},
        }
    pub, sea = out["public"], out["sealed"]
    out["gap"] = None
    if pub["of"] and sea["of"]:
        out["gap"] = round(pub["pass"] / pub["of"] - sea["pass"] / sea["of"], 6)
    return out


def seal_digest(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "seal"}
    return _sha(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def verify_record(record: dict[str, Any], transcript_path: str | None) -> list[str]:
    problems = []
    if record.get("schema") != RUN_SCHEMA:
        problems.append("not a run record")
    if record.get("seal") != seal_digest(record):
        problems.append("the seal does not cover this record; it was edited after the run")
    if transcript_path is not None and _sha(_read(transcript_path)) != record.get(
        "transcriptDigest"
    ):
        problems.append("the transcript is not the one this record sealed")
    return problems


def status(record: dict[str, Any]) -> int:
    """0 only when something was scored and every scored row passed."""
    scored = record["totals"]["public"]["of"] + record["totals"]["sealed"]["of"]
    if scored == 0:
        return 2
    failed = [r for r in record["rows"] if not r["pass"]]
    return 1 if failed else 0


# --------------------------------------------------------------------------
# Controls the runner ships about itself


def control_main(kind: str, suite_name: str) -> int:
    """Adapters that must NOT be scored conformant, used by the self-test.

    lookup: answers from a table of the public corpus keyed on question bytes,
    the cheapest adapter a published corpus admits. It passes every public
    member and must fail the sealed slice. deny: one answer for everything.
    exit: leaves before answering anything.
    """
    if kind == "exit":
        return 0
    suite = load_suite(suite_name)
    table = {}
    for member in load_public(suite)[0]:
        key = json.dumps(
            member["document"][suite["question"]], sort_keys=True, separators=(",", ":")
        )
        table[key] = member["expected"]
    for raw in sys.stdin:
        question = json.loads(raw)["question"]
        if kind == "deny":
            answer: dict[str, Any] = {"verdict": "deny", "code": None}
        else:
            key = json.dumps(question, sort_keys=True, separators=(",", ":"))
            hit = table.get(key)
            answer = (
                {"verdict": hit["verdict"], "code": hit.get("code")}
                if hit
                else {"verdict": "allow", "code": None}
            )
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
    return 0


def self_test(suite_name: str = "acs-core") -> int:
    """Each control must be refused, and for the reason it exists to show."""
    suite = load_suite(suite_name)
    seed = b"self-test seed, public on purpose, never a steward's seed"
    with tempfile.TemporaryDirectory() as tmp:
        sealed_path = write_sealed(seal(suite, seed, 1), tmp)
        sealed = json.loads(_read(sealed_path))

        def control(kind: str) -> dict[str, Any]:
            argv = [sys.executable, os.path.abspath(__file__), "_control", kind, suite_name]
            return run(suite, argv, sealed_path, os.path.join(tmp, f"{kind}.transcript"), 10.0)

        lookup, deny, gone = control("lookup"), control("deny"), control("exit")
        t = lookup["totals"]
        untouched = verify_record(lookup, os.path.join(tmp, "lookup.transcript"))
        edited = copy.deepcopy(lookup)
        edited["rows"][0]["pass"] = not edited["rows"][0]["pass"]
        checks = [
            (not reveal(suite, seed, sealed), "the seed does not reproduce its own slice"),
            (bool(reveal(suite, seed + b"x", sealed)), "a wrong seed opened the commitment"),
            (t["public"]["pass"] == t["public"]["of"], "the lookup control misses public members"),
            (t["sealed"]["pass"] < t["sealed"]["of"], "the seal does not separate a lookup table"),
            (status(lookup) != 0, "a lookup table was scored conformant"),
            (status(deny) != 0, "a constant answer was scored conformant"),
            (
                status(gone) != 0
                and all(r["stopReason"] == "adapter-exited" for r in gone["rows"]),
                "an adapter that left before answering was not refused as having left",
            ),
            (not untouched, "an untouched record failed its own seal"),
            (bool(verify_record(edited, None)), "an edited record still verified"),
        ]
    failures = [message for held, message in checks if not held]
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"held-out self-test: {len(checks)} controls, {len(failures)} failed")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# Command line


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def main(argv: list[str] | None = None) -> int:
    args_in = sys.argv[1:] if argv is None else argv
    if args_in[:1] == ["_control"]:
        return control_main(args_in[1], args_in[2])
    parser = argparse.ArgumentParser(
        prog="agent-evidence-heldout",
        description="Run a suite and a sealed slice against an out-of-process adapter.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("suites", help="list the shipped suites")
    p = sub.add_parser("commit", help="print the commitment a steward publishes for a seed")
    p.add_argument("--seed-file", required=True)
    p = sub.add_parser("seal", help="steward: cut the sealed slice from a seed")
    p.add_argument("--suite", default="acs-core")
    p.add_argument("--seed-file", required=True)
    p.add_argument("--per-family", type=int, default=2)
    p.add_argument("--out", required=True)
    p = sub.add_parser("reveal", help="check a published seed against a held slice")
    p.add_argument("--suite", default="acs-core")
    p.add_argument("--seed-file", required=True)
    p.add_argument("--sealed", required=True)
    p = sub.add_parser("run", help="run the suite against an adapter: run [opts] -- CMD ...")
    p.add_argument("--suite", default="acs-core")
    p.add_argument("--sealed", default=None, help="SEALED.json from the steward")
    p.add_argument("--record", default="heldout-run.json")
    p.add_argument("--transcript", default="heldout-run.transcript")
    p.add_argument("--timeout", type=float, default=ANSWER_TIMEOUT_SECONDS)
    p.add_argument("adapter", nargs=argparse.REMAINDER)
    p = sub.add_parser("verify", help="check a run record's seal and transcript")
    p.add_argument("record")
    p.add_argument("--transcript", default=None)
    p = sub.add_parser("self-test", help="run the runner's own negative controls")
    p.add_argument("--suite", default="acs-core")
    args = parser.parse_args(args_in)
    try:
        return _dispatch(args)
    except RunnerError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "suites":
        print("\n".join(suite_names()))
        return 0
    if args.command == "commit":
        print(commitment(read_seed(args.seed_file)))
        return 0
    if args.command == "self-test":
        return self_test(args.suite)
    if args.command == "verify":
        problems = verify_record(json.loads(_read(args.record)), args.transcript)
        for line in problems:
            print(f"FAIL {line}", file=sys.stderr)
        print("record verifies" if not problems else "record does not verify")
        return 1 if problems else 0
    suite = load_suite(args.suite)
    if args.command == "seal":
        sealed = seal(suite, read_seed(args.seed_file), args.per_family)
        path = write_sealed(sealed, args.out)
        print(
            f"sealed {len(sealed['members'])} member(s) to {path}; "
            f"commitment {sealed['commitment']}"
        )
        return 0
    if args.command == "reveal":
        problems = reveal(suite, read_seed(args.seed_file), json.loads(_read(args.sealed)))
        for line in problems:
            print(f"FAIL {line}", file=sys.stderr)
        print(
            "the seed reproduces the slice"
            if not problems
            else "the seed does not reproduce the slice"
        )
        return 1 if problems else 0
    adapter = args.adapter[1:] if args.adapter[:1] == ["--"] else args.adapter
    if not adapter:
        raise RunnerError("name the adapter command after --")
    record = run(suite, adapter, args.sealed, args.transcript, args.timeout)
    with open(args.record, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    t = record["totals"]
    print(
        f"public {t['public']['pass']}/{t['public']['of']}, "
        f"sealed {t['sealed']['pass']}/{t['sealed']['of']}, "
        f"gap {t['gap']}; record {args.record}, seal {record['seal']}"
    )
    return status(record)


if __name__ == "__main__":
    sys.exit(main())
