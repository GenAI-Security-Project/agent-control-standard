"""Keep specification and code changes off the publishing branch.

`main` publishes the site and all 44 schema $id URIs on every merge. A change to
normative content lands on `integration` first, so those URIs move only on a deliberate
promotion. GitHub rulesets cannot express "the paths in the diff decide the base
branch", so this does. A page added under docs/ also needs `integration`, because its
`nav` entry lives in mkdocs.yml, which is outside the lane.

The allowlist is positive. Anything it does not name requires `integration`, which makes
a directory nobody anticipated a failure rather than a silent pass.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable

PUBLISHING_BRANCH = "main"

# Directory prefixes that may target the publishing branch. The trailing slash is load
# bearing: without it, a prefix test reads docs/specimen.md as a match for docs/spec.
DOCS_LANE_DIRECTORIES = (
    "docs/topics/",
    "design/",
)

# Exact files that may target the publishing branch.
#
# mkdocs.yml, overrides/, landing/, docs/stylesheets/, and docs/assets/ are deliberately
# absent even though a reader would call all five documentation. CODEOWNERS treats them
# as privilege-escalation surfaces and says why: mkdocs.yml accepts a hooks: key that
# executes Python inside the build job, overrides holds templates the build renders into
# every page, and a stylesheet or asset reaches a third party through url(), @font-face,
# or @import with no script at all. A lane that deploys on merge is the wrong lane for
# any of them.
DOCS_LANE_FILES = frozenset({
    "docs/README.md",
    "README.md",
    "CONTRIBUTORS.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "STYLE.md",
    "LICENSING.md",
    "NOTICE",
})

# Branches a promotion pull request comes from. These carry specification paths by
# definition.
PROMOTION_HEADS = frozenset({"integration"})
PROMOTION_HEAD_PREFIXES = ("release/",)


def in_docs_lane(path: str) -> bool:
    """True when a path may target the publishing branch directly."""
    if path in DOCS_LANE_FILES:
        return True
    return path.startswith(DOCS_LANE_DIRECTORIES)


def is_promotion(head_ref: str, head_repo: str, base_repo: str) -> bool:
    """True when this is a promotion from a branch inside this repository.

    The repository test is not optional and runs first. A pull request's head ref is a
    branch name the contributor chose, and a fork may name a branch anything, so
    exempting on the ref alone would let somebody fork, create a branch called
    `integration`, and walk a specification change onto the publishing branch.
    """
    if head_repo != base_repo:
        return False
    return head_ref in PROMOTION_HEADS or head_ref.startswith(PROMOTION_HEAD_PREFIXES)


def paths_requiring_integration(paths: Iterable[str]) -> list[str]:
    """Return every changed path that may not target the publishing branch."""
    return sorted({path for path in paths if not in_docs_lane(path)})


# A path added under this prefix is a new page. The deploy runs the test suite before it
# builds, and a page with no `nav` entry fails it, so a new page merged straight to the
# publishing branch stops every deploy until a `mkdocs.yml` change arrives by promotion.
NEW_PAGE_PREFIX = "docs/"

# Statuses from `git diff --name-status` that put a path into the tree. A rename or copy
# carries a similarity score after its letter, as in R100. The workflow passes
# --no-renames, so a rename reaches this script as a delete plus an add and the old
# path stays visible to the path rule. R and C stay here so a listing produced without
# that flag still counts the new path as an addition.
ADDING_STATUSES = ("A", "R", "C")


def added_pages_requiring_integration(added: Iterable[str]) -> list[str]:
    """Return every added path under docs/, which needs a `nav` entry from `integration`."""
    return sorted({path for path in added if path.startswith(NEW_PAGE_PREFIX)})


def parse_name_status(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split `git diff --name-status` output into changed paths and added paths.

    Each line is a status, a tab, and a path. A rename or copy names the old path and
    then the new one, and only the new path is a change here, the same path
    `--name-only` reports. A line with no tab is a bare path from an older listing and
    counts as changed, not added.
    """
    changed: list[str] = []
    added: list[str] = []
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if "\t" not in line:
            changed.append(line.strip())
            continue
        fields = line.split("\t")
        status, path = fields[0].strip(), fields[-1]
        changed.append(path)
        if status.startswith(ADDING_STATUSES):
            added.append(path)
    return changed, added


def decide(
    paths: Iterable[str],
    base_ref: str,
    head_ref: str,
    head_repo: str,
    base_repo: str,
    added: Iterable[str] = (),
) -> tuple[int, str]:
    """Return an exit status and the message to print.

    `added` names the paths the pull request adds. It defaults to empty so a caller that
    knows only the changed paths gets the path rule alone.
    """
    if base_ref != PUBLISHING_BRANCH:
        return 0, f"Base branch is {base_ref!r}, not {PUBLISHING_BRANCH!r}. Nothing to check."
    if is_promotion(head_ref, head_repo, base_repo):
        return 0, f"Promotion from {head_ref!r}. Specification paths are expected here."
    offenders = paths_requiring_integration(paths)
    new_pages = [path for path in added_pages_requiring_integration(added)
                 if path not in offenders]
    if not offenders and not new_pages:
        return 0, "Every changed path is in the documentation lane."
    parts = []
    if offenders:
        listing = "\n".join(f"  {path}" for path in offenders)
        parts.append(
            f"These paths may not target `{PUBLISHING_BRANCH}`. Retarget this pull "
            f"request at `integration`:\n{listing}\n\n"
            f"`{PUBLISHING_BRANCH}` publishes the site and all 44 schema $id URIs on "
            "merge, so specification and code changes land on `integration` and "
            "publish on a promotion."
        )
    if new_pages:
        listing = "\n".join(f"  {path}" for path in new_pages)
        parts.append(
            f"These new pages may not target `{PUBLISHING_BRANCH}`. Retarget this pull "
            f"request at `integration`:\n{listing}\n\n"
            "A new page needs a titled `nav` entry in `mkdocs.yml`, and `mkdocs.yml` "
            "reaches the publishing branch only through `integration`. The deploy runs "
            "the guards before it builds, so a page without its `nav` entry stops every "
            f"deploy of `{PUBLISHING_BRANCH}`."
        )
    return 1, "\n\n".join(parts) + " See CONTRIBUTING.md."


def main(argv: list[str]) -> int:
    """Read the changed paths from a file and the refs from the environment."""
    if len(argv) != 2:
        print("usage: base_branch_guard.py <git-diff-name-status-listing>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        paths, added = parse_name_status(handle)
    status, message = decide(
        paths,
        os.environ.get("BASE_REF", ""),
        os.environ.get("HEAD_REF", ""),
        os.environ.get("HEAD_REPO", ""),
        os.environ.get("BASE_REPO", ""),
        added,
    )
    print(message, file=sys.stderr if status else sys.stdout)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
