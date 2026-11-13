#!/usr/bin/env python3
"""Publish JSON schemas to the paths their own $id values declare.

Every schema sits at the path its $id names, so publishing is a copy and the check
that a draft is not claiming a normative URI is an identity test rather than a list
of directory names to keep extending.

$id is attacker-influenced input, not trusted identity. Anyone who can land a file under
specification/ controls the string, and a fork pull request reaches this code on the
runner before review. Every path derived from it is validated and contained.
"""
from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin

BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

# A publishable tail: version directory, then nested names, ending in .json.
SAFE_TAIL = re.compile(r"^v[0-9]+(?:\.[0-9]+)*/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.json$")


class SchemaError(Exception):
    """A schema has an unusable $id, an unsafe publish path, or an unresolvable $ref."""


def _read(source: Path) -> dict[Path, tuple[dict, bytes]]:
    """Parse every JSON file under source that declares an $id, keeping its raw bytes.

    The bytes travel with the parsed document so the publish step writes what it
    validated. Re-reading at write time would leave a window that widens with every
    file, because the whole package is validated in between.

    Files without an $id are skipped rather than fatal. Example payloads and fixtures
    live under specification/ too, and a contributor adding one must not stop the deploy.
    """
    root = source.resolve()
    schemas: dict[Path, tuple[dict, bytes]] = {}
    for path in sorted(source.rglob("*.json")):
        # A symlink's own path satisfies every check above while its target supplies
        # the bytes, so resolve first and require the real file to sit inside source.
        if not path.resolve().is_relative_to(root):
            raise SchemaError(f"{path}: resolves outside {source}, refusing to read it")
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise SchemaError(f"{path}: not valid UTF-8: {error}") from error
        except json.JSONDecodeError as error:
            raise SchemaError(f"{path}: invalid JSON: {error}") from error
        if not isinstance(doc, dict) or "$id" not in doc:
            continue
        schemas[path] = (doc, raw)
    return schemas


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source that declares an $id."""
    return {path: doc for path, (doc, _raw) in _read(source).items()}


def target_for(doc: dict, path: Path, source: Path) -> str:
    """Return the validated publish path a document's $id declares.

    The $id must name the file's own location under source. That identity is what
    keeps a draft out of the normative namespace. Claiming it would mean declaring
    an $id that names the draft directory, and SAFE_TAIL refuses that for want of a
    version segment. No directory name is involved, so nothing needs extending when
    someone invents a new word for "not ready yet".
    """
    sid = doc.get("$id")
    if not sid:
        raise SchemaError(f"{path}: no $id")
    if not sid.startswith(BASE):
        raise SchemaError(f"{path}: $id outside namespace: {sid}")

    tail = sid[len(BASE) :]
    # SAFE_TAIL admits no % in any character class, so this is not the layer that
    # stops a percent-encoded traversal. It stays because it labels the attempt.
    # An operator reading a build log can tell someone trying something from
    # someone making a typo.
    if unquote(tail) != tail:
        raise SchemaError(f"{path}: $id must not be percent-encoded: {sid}")
    if not SAFE_TAIL.match(tail):
        raise SchemaError(
            f"{path}: $id tail {tail!r} is not a safe publish path. "
            "Expected v<version>/<name>.json with no traversal and no absolute prefix."
        )
    on_disk = path.relative_to(source).as_posix()
    if tail != on_disk:
        raise SchemaError(
            f"{path}: $id declares {tail!r} but the file sits at {on_disk!r}. "
            "A schema publishes at its own location, so the two must match."
        )
    return tail


def iter_refs(node: object) -> Iterator[str]:
    """Yield every $ref string anywhere in a parsed document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_refs(item)


def resolve_pointer(doc: dict, pointer: str) -> bool:
    """Return whether a JSON Pointer resolves inside doc. An empty pointer means the root."""
    if pointer in ("", "/"):
        return True
    node: object = doc
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                return False
            node = node[int(token)]
        else:
            return False
    return True


def verify_refs(docs: dict[Path, dict], by_id: dict[str, dict]) -> None:
    """Fail if a $ref inside our namespace does not resolve, fragment included.

    Checking only the file leaves the likeliest real breakage undetected: renaming a
    $defs entry another schema points at. The package holds one cross-file fragment
    reference and it targets the signature definition.
    """
    for path, doc in docs.items():
        sid = doc["$id"]
        for ref in iter_refs(doc):
            target, fragment = urldefrag(urljoin(sid, ref))
            if not target.startswith(BASE):
                continue  # external reference, not ours to publish
            if target not in by_id:
                raise SchemaError(
                    f"{path}: $ref {ref!r} resolves to {target}, which no $id publishes"
                )
            if fragment == "" or fragment.startswith("/"):
                if not resolve_pointer(by_id[target], fragment):
                    raise SchemaError(
                        f"{path}: $ref {ref!r} points at {fragment!r}, "
                        f"which does not exist in {target}"
                    )


def publish(source: Path, out: Path) -> list[str]:
    """Write every schema to its $id-declared path. Return sorted relative paths.

    Nothing is written until every schema validates and every $ref resolves, so a
    failed build leaves no output directory rather than a partial one. The bytes
    written are the bytes parsed, so no second read can substitute content that
    nothing checked.
    """
    parsed = _read(source)
    if not parsed:
        raise SchemaError(f"no schemas found under {source}")

    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    claimed: dict[str, str] = {}
    planned: list[tuple[Path, str, bytes]] = []

    for path, (doc, raw) in parsed.items():
        rel = target_for(doc, path, source)
        sid = doc["$id"]
        # Belt and braces. The identity check makes two files sharing one $id
        # unreachable through this function, but target_for has other callers.
        if sid in seen:
            raise SchemaError(f"{path}: duplicate $id {sid}, already declared by {seen[sid]}")
        seen[sid] = path

        # A case-insensitive filesystem collapses two of these into one file, so the
        # tree a maintainer checks out is not the tree the Linux runner publishes.
        folded = rel.casefold()
        if folded in claimed:
            raise SchemaError(
                f"{path}: publishes to {rel!r}, which differs from {claimed[folded]!r} "
                "only by case, so the two collide on a case-insensitive filesystem"
            )
        claimed[folded] = rel

        destination = (out / rel).resolve()
        # Belt and braces. SAFE_TAIL should make this unreachable. If it ever is
        # reachable, the build stops rather than writing outside the artifact.
        if not destination.is_relative_to(out_root):
            raise SchemaError(f"{path}: $id escapes the output root: {sid}")

        planned.append((destination, rel, raw))
        by_id[sid] = doc

    verify_refs({path: doc for path, (doc, _raw) in parsed.items()}, by_id)

    for destination, _rel, payload in planned:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    return sorted(rel for _destination, rel, _payload in planned)


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else Path("specification")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site/schema")
    try:
        files = publish(source, out)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"published {len(files)} schemas to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
