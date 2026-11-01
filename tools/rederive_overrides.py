"""Keep the theme partial overrides reproducible across a mkdocs-material bump.

Each override in overrides/partials/ is an installed Material partial plus a small
change. Three files under overrides/.upstream/partials/ record it: a byte copy of the
installed partial, and the unified diff from that copy to the override. MkDocs skips
dot directories, so none of this is published.

Two modes:

    uv run python tools/rederive_overrides.py --record
        First use, and after a hand edit of an override. Records the diff from the
        committed upstream copy to the current override. It copies the installed partial
        only when no committed copy exists, and refuses when the committed copy differs
        from the installed partial, because that change belongs to the bump flow.

    uv run python tools/rederive_overrides.py [--accept-delta <hex>]
        The bump flow, run after relocking to a new mkdocs-material. Prints how the
        installed partials differ from the committed copies. Nothing is written until
        that delta is accepted by its sha256, so a person reads what upstream changed
        before the override is rebuilt on top of it. The recorded diff is then replayed
        with git apply, which refuses when a context line it relies on has changed.

This runs with the repository's Python because it imports `material` to find the
installed partials.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PARTIALS = ("header.html", "nav.html", "nav-item.html")
UPSTREAM = Path("overrides/.upstream/partials")
OVERRIDES = Path("overrides/partials")
REPO = Path(__file__).resolve().parents[1]


def installed_partial(name: str, base: Path | None = None) -> Path:
    """Path of the installed Material partial, or of a stand-in under base."""
    if base is not None:
        return base / name
    import material

    return Path(material.__file__).parent / "templates" / "partials" / name


def record_diff(upstream: str, override: str, name: str) -> str:
    return "".join(difflib.unified_diff(
        upstream.splitlines(True), override.splitlines(True),
        fromfile=f"{name}.upstream", tofile=name, n=3,
    ))


def render_deltas(deltas: dict[str, str]) -> str:
    """The text a person reads and accepts. The hash covers exactly this text."""
    return "".join(deltas[name] for name in PARTIALS if deltas.get(name))


def _tofile(diff_text: str) -> str:
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0].strip()
            # The name becomes a path inside the scratch directory, so it must be a
            # bare file name. A diff is reviewed as text, and a path here would not be.
            if name != Path(name).name or name in ("", ".", ".."):
                raise SystemExit(f"refusing diff target {name!r}: not a bare file name")
            return name
    raise SystemExit("diff has no +++ line")


def apply_diff(upstream: Path, diff: Path, out: Path) -> None:
    """Replay diff onto upstream and write the result to out, or exit with git's reason."""
    diff_text = diff.read_text(encoding="utf-8")
    if not diff_text:
        # An empty recorded diff means the override equals upstream. git apply refuses
        # an empty patch, so the copy is the whole replay.
        shutil.copyfile(upstream, out)
        return
    target = _tofile(diff_text)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / target
        shutil.copyfile(upstream, work)
        # The ceiling stops git from finding an enclosing repository, so paths in the
        # diff resolve against the scratch directory and nowhere else. A git hook
        # exports GIT_DIR and its companions, and any of them would point git at another
        # repository and its config regardless of the ceiling, so they are dropped.
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(Path(tmp).parent))
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            env.pop(name, None)
        for args in (["git", "apply", "--check", str(diff.resolve())], ["git", "apply", str(diff.resolve())]):
            result = subprocess.run(args, cwd=tmp, env=env, capture_output=True, text=True)
            if result.returncode != 0:
                raise SystemExit(f"git apply refused {diff.name} on {upstream}:\n{result.stderr.strip()}")
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(work), str(out))


def _record(root: Path, installed: Path | None) -> int:
    # --record re-baselines nothing. A committed copy that differs from the installed
    # partial means upstream moved, and only the bump flow shows that delta to a person
    # before adopting it. Every partial is checked before anything is written.
    stale = [name for name in PARTIALS
             if (root / UPSTREAM / name).exists()
             and (root / UPSTREAM / name).read_bytes() != installed_partial(name, installed).read_bytes()]
    if stale:
        for name in stale:
            print(f"{UPSTREAM / name} differs from the installed partial. --record will not adopt an "
                  f"upstream change. Run `uv run python tools/rederive_overrides.py`, read the delta, then "
                  f"run it again with `--accept-delta <hex>`.", file=sys.stderr)
        return 1
    (root / UPSTREAM).mkdir(parents=True, exist_ok=True)
    for name in PARTIALS:
        copy = root / UPSTREAM / name
        if not copy.exists():
            # First use only: there is no committed baseline to protect yet.
            shutil.copyfile(installed_partial(name, installed), copy)
            print(f"copied the installed partial to {UPSTREAM / name}")
        override = (root / OVERRIDES / name).read_text(encoding="utf-8")
        diff = record_diff(copy.read_text(encoding="utf-8"), override, name)
        (root / UPSTREAM / f"{name}.diff").write_text(diff, encoding="utf-8")
        print(f"recorded {UPSTREAM / name}.diff")
    return 0


def _bump(root: Path, installed: Path | None, accepted: str | None) -> int:
    import material

    print(f"mkdocs-material {material.__version__}")
    deltas = {}
    for name in PARTIALS:
        committed = (root / UPSTREAM / name).read_text(encoding="utf-8")
        current = installed_partial(name, installed).read_text(encoding="utf-8")
        deltas[name] = record_diff(committed, current, name)
    if not any(deltas.values()):
        print("installed partials equal the committed copies, nothing to re-derive")
        return 1

    text = render_deltas(deltas)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if accepted != digest:
        print(text, end="")
        if accepted is not None:
            print("\nthe --accept-delta value does not match the delta above")
        print(f"\nRead the delta above, then run:\n"
              f"uv run python tools/rederive_overrides.py --accept-delta {digest}")
        return 2

    # Replay every override into scratch first. A refusal on one partial must leave the
    # committed files untouched, not half of them rebuilt.
    with tempfile.TemporaryDirectory() as tmp:
        built = {}
        for name in PARTIALS:
            out = Path(tmp) / name
            apply_diff(installed_partial(name, installed), root / UPSTREAM / f"{name}.diff", out)
            built[name] = out.read_text(encoding="utf-8")
        for name in PARTIALS:
            if deltas[name]:
                (root / UPSTREAM / f"{name}.delta").write_text(deltas[name], encoding="utf-8")
            shutil.copyfile(installed_partial(name, installed), root / UPSTREAM / name)
            (root / OVERRIDES / name).write_text(built[name], encoding="utf-8")
            upstream = (root / UPSTREAM / name).read_text(encoding="utf-8")
            (root / UPSTREAM / f"{name}.diff").write_text(record_diff(upstream, built[name], name), encoding="utf-8")
            print(f"{name}: copied the installed partial to {UPSTREAM / name}")
            print(f"{name}: applied {UPSTREAM / name}.diff to {OVERRIDES / name}")
            print(f"{name}: re-recorded {UPSTREAM / name}.diff")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--record", action="store_true", help="copy the installed partials and record the diffs")
    mode.add_argument("--accept-delta", metavar="HEX", help="sha256 of the printed delta, to adopt it")
    parser.add_argument("--root", type=Path, default=REPO, help="checkout to work in (default: this repository)")
    parser.add_argument("--installed", type=Path, help="directory standing in for the installed partials (tests)")
    args = parser.parse_args(argv)
    if args.record:
        return _record(args.root, args.installed)
    return _bump(args.root, args.installed, args.accept_delta)


if __name__ == "__main__":
    sys.exit(main())
