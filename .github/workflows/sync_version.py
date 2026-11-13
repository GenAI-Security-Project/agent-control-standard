#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The OWASP GenAI Security Project and the ACS contributors
"""
Synchronize the release version from version.txt to the packaging metadata.

Two version numbers live in this repository and they move independently.

The RELEASE version in version.txt tracks the repository: tooling, licensing,
governance, and documentation changes. This script owns it.

The SPECIFICATION version is the one implementers pin against. It appears in
the schema $id (https://.../schema/v0.1.0/...), in the specification/v0.1.0/
directory name, in every $ref between those files, and in the specification
document headers. It changes only when the specification itself changes, and
it changes through a deliberate migration that moves the directory and
rewrites the references together.

An earlier version of this script rewrote the specification version from
version.txt. That produced a schema whose "version" field disagreed with its
own $id and $refs, and it reformatted the whole schema file (json.dump at
indent 4 over a 2-space document) on every run. Both are why the schema and
the specification document are deliberately not touched here.
"""

import pathlib
import re
import sys

# Matches the version assignment in the [project] table, capturing the
# surrounding quotes so the original quoting style survives the rewrite.
PYPROJECT_VERSION = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)

# Same pattern the workflow validates against, repeated here so the script is
# safe to run by hand outside CI.
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sync_version.py <version>", file=sys.stderr)
        return 1

    version = sys.argv[1].strip()
    if not SEMVER.match(version):
        print(f"Not a valid semantic version: {version!r}", file=sys.stderr)
        return 1

    pyproject = pathlib.Path("pyproject.toml")
    if not pyproject.is_file():
        print("pyproject.toml not found. Run from the repository root.", file=sys.stderr)
        return 1

    original = pyproject.read_text(encoding="utf-8")
    updated, count = PYPROJECT_VERSION.subn(rf'\g<1>"{version}"', original, count=1)

    if count == 0:
        print("No version assignment found in pyproject.toml", file=sys.stderr)
        return 1

    if updated == original:
        print(f"pyproject.toml already at version {version}")
        return 0

    pyproject.write_text(updated, encoding="utf-8")
    print(f"Updated pyproject.toml to version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
