#!/usr/bin/env python3
"""Strip contributor text, logins, emails, and links from recorded GitHub API responses.

Version 1.0. Owner: ACS project leads. Used to record the intake tool's fixtures.

Usage: python3 -I scrub.py OUT_DIR RAW.json [RAW.json ...]

Each response was recorded read-only with `gh api` against this repository. The fixtures
are committed, so nothing a contributor wrote, and nothing that names a contributor, may
survive. The scrub replaces `email`, `name`, `message`, `title`, `body`, `html_url`,
`avatar_url`, `url`, and the other free-text keys below with fixed strings at any depth.
Every `login` becomes `login-N`, numbered by first appearance across all the files of one
run, so the same person is the same fixed string in every fixture. The two bots the gate
names stay as they are, because they are not contributors and the tests need them.

Structure survives: `type`, ids of non-person objects, states, label names, file paths,
SHAs, and timestamps. A label's `name` is kept because the gate reads label names. Any
string that is a URL becomes a fixed API URL, and any string that still contains a
recorded login is replaced whole. The run fails if an email or a non-API URL remains.

The committed fixtures are this script's output plus hand edits made afterwards, so a
re-run reproduces the scrub and not the edits. Re-apply them after any re-recording:
in reviews.json, review 900001 has a null `user` (a deleted account) and review 900002 has
a `type: Bot` reviewer. In comments.json, the bot's legacy queue comment keeps its opening
sentence, the bot's keyword warning keeps its `<!-- acs-closing-keyword:108 -->` marker,
and three comments are added: 910001, a contributor copying the marker and the data line,
910002, a contributor copying the legacy opening sentence, and 910003, the bot's own
marked comment. In timeline.json, three `unlabeled` events are added: 920001, the bot
removing the queue label, 920002, a lead removing it, and 920003, a lead removing another
label.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

KEPT_LOGINS = frozenset({"github-actions[bot]", "dependabot[bot]"})
TEXT_KEYS = frozenset({
    "email", "name", "message", "title", "body", "html_url", "avatar_url", "url",
    "patch", "description", "full_name", "payload", "signature", "body_text", "body_html",
})
# Branch names are free text a contributor chooses. The two base branches are not.
KEPT_REFS = frozenset({"main", "integration"})
TEXT = "scrubbed"
API_URL = "https://api.github.com/scrubbed"
_EMAIL = re.compile(r"@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}")
_URL = re.compile(r"https://(?!api\.github\.com/)")


class Scrubber:
    def __init__(self) -> None:
        self.logins: dict[str, str] = {}

    def login(self, value: str) -> str:
        if value in KEPT_LOGINS:
            return value
        key = value.casefold()
        if key not in self.logins:
            self.logins[key] = f"login-{len(self.logins) + 1}"
        return self.logins[key]

    def collect(self, node: object) -> None:
        """Number every login first, so later strings can be checked against all of them."""
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "login" and isinstance(value, str):
                    self.login(value)
                else:
                    self.collect(value)
        elif isinstance(node, list):
            for item in node:
                self.collect(item)

    def string(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            return API_URL
        folded = value.casefold()
        for original in self.logins:
            if original in folded and value not in KEPT_LOGINS:
                return TEXT
        return value

    def scrub(self, node: object, parent: str | None = None) -> object:
        if isinstance(node, list):
            return [self.scrub(item, parent) for item in node]
        if not isinstance(node, dict):
            return self.string(node) if isinstance(node, str) else node
        person = "login" in node
        out = {}
        for key, value in node.items():
            if key == "login" and isinstance(value, str):
                out[key] = self.login(value)
            elif person and key == "id":
                out[key] = 1
            elif person and key == "node_id":
                out[key] = TEXT
            elif key == "name" and parent in ("label", "labels"):
                out[key] = value
            elif key in TEXT_KEYS and isinstance(value, str):
                out[key] = API_URL if key.endswith("url") else TEXT
            elif key.endswith("_url") and isinstance(value, str):
                out[key] = API_URL
            elif key == "ref" and isinstance(value, str) and value not in KEPT_REFS:
                out[key] = TEXT
            elif key == "label" and isinstance(value, str):
                out[key] = TEXT
            else:
                out[key] = self.scrub(value, key)
        return out


def check(text: str, name: str) -> None:
    if _EMAIL.search(text) or _URL.search(text) or "http://" in text:
        raise SystemExit(f"{name}: an email or a non-API URL survived the scrub")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        raise SystemExit("usage: scrub.py OUT_DIR RAW.json [RAW.json ...]")
    out_dir = Path(argv[1])
    raws = [(Path(path), json.loads(Path(path).read_text(encoding="utf-8"))) for path in argv[2:]]
    scrubber = Scrubber()
    for _path, data in raws:
        scrubber.collect(data)
    for path, data in raws:
        text = json.dumps(scrubber.scrub(data), indent=1, sort_keys=True) + "\n"
        check(text, path.name)
        (out_dir / path.name).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
