#!/usr/bin/env python3
"""Assert that the deployed site serves each schema at the URI its $id declares.

A status code is not the property worth checking. A traversal that overwrites the root
schema still returns 200, and so does a truncated or stale document.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Pages fronts content through a CDN, so a fresh deployment can 404 briefly. curl's
# --retry does not cover a 404, which is why this polls explicitly.
ATTEMPTS = 6
DELAY_SECONDS = 10


def fetch(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def paths_from(source: Path) -> list[str]:
    """Derive every publishable path from the schema tree.

    Returns tails such as v0.1.0/acs_schema.json. The caller supplies the base URL
    including the /schema segment, matching how the workflows already join the two.

    Two hardcoded paths duplicated across two workflows left 42 of the 44 published
    URIs with no post-deploy check and nothing keeping the two copies in step.
    """
    from publish_schemas import load_schemas, target_for

    return sorted(target_for(doc, path, source) for path, doc in load_schemas(source).items())


def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            if attempt < ATTEMPTS:
                time.sleep(DELAY_SECONDS)
            continue
        if not isinstance(doc, dict):
            # It parsed and it is wrong. Retrying cannot change a served document,
            # and .get on a list raises an AttributeError instead of reporting.
            raise SystemExit(f"::error::{url} is not a JSON object, served {type(doc).__name__}")
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")


def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[2] == "--from":
        paths = paths_from(Path(argv[3]))
    elif len(argv) >= 3:
        paths = argv[2:]
    else:
        print(
            "usage: verify_published.py <base-url> --from <schema-source-dir>\n"
            "   or: verify_published.py <base-url> <path> [<path> ...]",
            file=sys.stderr,
        )
        return 2
    for path in paths:
        check(argv[1], path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
