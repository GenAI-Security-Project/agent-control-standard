# Contribution Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Strategic Adoption Plan v3 committed outcome into a repository that filters contributions without a maintainer in the loop for every decision, before the OWASP kick-off on Thursday, September 10, 2026.

**Architecture:** A positive path allowlist decides which changes may target the publishing branch, enforced by a pure Python function under test and a thin workflow that calls it. Issue forms stamp descriptive labels and never decision labels, so the maintainer-only rule holds structurally. `CONTRIBUTING.md` carries the single statement of Current Priority Scope that every other surface links to.

**Tech Stack:** Python 3 standard library only for the guard, pytest for its tests, GitHub Actions for enforcement, GitHub issue forms (YAML), GitHub rulesets, `gh` CLI for repository configuration.

**Spec:** `design/2026-09-09-contribution-governance-design.md` (v1.1)

## Global Constraints

- Editorial rules come from `STYLE.md`. American English, active voice, plain words. No em dashes, no semicolons, no sentences opening with a conjunction.
- Every commit is signed off: `git commit -s`. The DCO requires it.
- Python guards live in `tools/`, their tests in `tests/`. `testpaths = ["tests"]` in `pyproject.toml` means a test written anywhere else never runs in CI.
- The guard uses the Python standard library only. It runs in a job that does not install `uv`, and adding a dependency to `uv.lock` for it would put the deploy gate at risk.
- Actions are pinned to commit SHAs. Reuse the exact pins already in `.github/workflows/deploy-pages.yml`: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1).
- Workflows declare `permissions: {}` at the top level and grant per job.
- The required status check context is the **job id**. The guard job id is `base-branch-guard` and the ruleset requires that exact string. They change together or not at all.
- Work happens on branch `feature/contribution-governance`. Phase 1 lands as a pull request. Phase 2 is operator-run.

---

## Phase 1: Repository files

Safe for subagent execution. Every task is a file change on the feature branch, reviewable in a pull request, reversible by `git revert`.

### Task 1: The base-branch guard

**Files:**
- Create: `tools/base_branch_guard.py`
- Create: `tests/test_base_branch_guard.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `decide(paths: Iterable[str], base_ref: str, head_ref: str, head_repo: str, base_repo: str) -> tuple[int, str]` returning an exit status and a message. Also `in_docs_lane(path: str) -> bool`, `is_promotion(head_ref: str, head_repo: str, base_repo: str) -> bool`, `paths_requiring_integration(paths: Iterable[str]) -> list[str]`, and the constant `PUBLISHING_BRANCH = "main"`. Task 2 invokes the module as a script.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_base_branch_guard.py`:

```python
"""Guards for the rule that keeps specification and code off the publishing branch.

The allowlist is positive, so the interesting cases are the ones nobody enumerated. A
directory that did not exist when the list was written has to fail, and a fork branch
named like a promotion branch has to fail, because both are how an allowlist quietly
turns into a blocklist.
"""

import sys
from pathlib import Path

# Matches the import style the other tools tests use, in test_publish_schemas.py:12.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from base_branch_guard import (  # noqa: E402
    PUBLISHING_BRANCH,
    decide,
    in_docs_lane,
    is_promotion,
    paths_requiring_integration,
)

REPO = "GenAI-Security-Project/agent-control-standard"
FORK = "someone/agent-control-standard"


def test_allowlisted_documentation_path_is_in_the_lane():
    assert in_docs_lane("docs/topics/core_concepts.md")
    assert in_docs_lane("CONTRIBUTING.md")
    assert in_docs_lane("design/2026-09-09-contribution-governance-design.md")


def test_specification_paths_are_not_in_the_lane():
    assert not in_docs_lane("specification/v0.1.0/acs_schema.json")
    assert not in_docs_lane("docs/spec/instrument/hooks.md")


def test_normative_concept_prose_is_not_in_the_lane():
    """Concept pages define the terms the specification uses, so they travel with it."""
    assert not in_docs_lane("docs/concepts/capability.md")
    assert not in_docs_lane("docs/identity/standards.md")


def test_build_surfaces_are_not_in_the_lane():
    """A reader calls these documentation. Each one reaches code or a third party."""
    assert not in_docs_lane("mkdocs.yml")
    assert not in_docs_lane("overrides/main.html")
    assert not in_docs_lane("landing/index.html")
    assert not in_docs_lane("docs/stylesheets/extra.css")
    assert not in_docs_lane("docs/assets/logo.svg")


def test_directory_matching_requires_the_separator():
    """A prefix check without the slash reads docs/specimen.md as docs/spec."""
    assert in_docs_lane("docs/topics/anything.md")
    assert not in_docs_lane("docs/topicsextra.md")


def test_an_unanticipated_directory_fails_closed():
    assert not in_docs_lane("reference-implementations/agt/main.ts")
    assert not in_docs_lane("something/nobody/planned.txt")


def test_paths_requiring_integration_returns_only_offenders_sorted():
    changed = ["CONTRIBUTING.md", "specification/a.json", "docs/spec/b.md"]
    assert paths_requiring_integration(changed) == [
        "docs/spec/b.md",
        "specification/a.json",
    ]


def test_promotion_from_integration_in_this_repository():
    assert is_promotion("integration", REPO, REPO)


def test_promotion_from_a_release_branch_in_this_repository():
    assert is_promotion("release/v0.2.0", REPO, REPO)


def test_a_fork_branch_named_integration_is_not_a_promotion():
    """head.ref is a name the contributor chose. Only the repository check is trustworthy."""
    assert not is_promotion("integration", FORK, REPO)
    assert not is_promotion("release/v0.2.0", FORK, REPO)


def test_documentation_only_pull_request_to_main_passes():
    status, message = decide(["docs/topics/faq.md"], PUBLISHING_BRANCH, "docs/faq", FORK, REPO)
    assert status == 0
    assert "documentation lane" in message


def test_specification_pull_request_to_main_fails_and_names_the_file():
    status, message = decide(
        ["specification/v0.1.0/acs_schema.json"], PUBLISHING_BRANCH, "spec/x", FORK, REPO
    )
    assert status == 1
    assert "specification/v0.1.0/acs_schema.json" in message
    assert "integration" in message


def test_mixed_diff_fails():
    """Only the offenders appear in the listing.

    The assertion reads the listing rather than the whole message on purpose. The
    message ends with "See CONTRIBUTING.md.", so a naive `not in message` check can
    never pass and would push somebody into changing the guard to satisfy the test.
    """
    status, message = decide(
        ["CONTRIBUTING.md", "specification/a.json"], PUBLISHING_BRANCH, "mix", FORK, REPO
    )
    listing = message.split("\n\n")[0]
    assert status == 1
    assert "specification/a.json" in listing
    assert "CONTRIBUTING.md" not in listing


def test_promotion_passes_with_specification_paths():
    status, message = decide(
        ["specification/a.json"], PUBLISHING_BRANCH, "integration", REPO, REPO
    )
    assert status == 0
    assert "Promotion" in message


def test_any_other_base_passes_without_consulting_the_allowlist():
    status, message = decide(
        ["specification/a.json"], "integration", "spec/x", FORK, REPO
    )
    assert status == 0
    assert "Nothing to check" in message


def test_an_empty_diff_passes():
    status, _ = decide([], PUBLISHING_BRANCH, "empty", FORK, REPO)
    assert status == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
uv run pytest tests/test_base_branch_guard.py -v
```

Expected: collection error, `ModuleNotFoundError: No module named 'tools.base_branch_guard'`.

- [ ] **Step 3: Write the guard**

Create `tools/base_branch_guard.py`:

```python
"""Keep specification and code changes off the publishing branch.

`main` publishes the site and all 44 schema $id URIs on every merge. A change to
normative content lands on `integration` first, so those URIs move only on a deliberate
promotion. GitHub rulesets cannot express "the paths in the diff decide the base
branch", so this does.

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


def decide(
    paths: Iterable[str],
    base_ref: str,
    head_ref: str,
    head_repo: str,
    base_repo: str,
) -> tuple[int, str]:
    """Return an exit status and the message to print."""
    if base_ref != PUBLISHING_BRANCH:
        return 0, f"Base branch is {base_ref!r}, not {PUBLISHING_BRANCH!r}. Nothing to check."
    if is_promotion(head_ref, head_repo, base_repo):
        return 0, f"Promotion from {head_ref!r}. Specification paths are expected here."
    offenders = paths_requiring_integration(paths)
    if not offenders:
        return 0, "Every changed path is in the documentation lane."
    listing = "\n".join(f"  {path}" for path in offenders)
    return 1, (
        f"These paths may not target `{PUBLISHING_BRANCH}`. Retarget this pull request "
        f"at `integration`:\n{listing}\n\n"
        f"`{PUBLISHING_BRANCH}` publishes the site and all 44 schema $id URIs on merge, "
        "so specification and code changes land on `integration` and publish on a "
        "promotion. See CONTRIBUTING.md."
    )


def main(argv: list[str]) -> int:
    """Read the changed paths from a file and the refs from the environment."""
    if len(argv) != 2:
        print("usage: base_branch_guard.py <file-listing-changed-paths>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        paths = [line.strip() for line in handle if line.strip()]
    status, message = decide(
        paths,
        os.environ.get("BASE_REF", ""),
        os.environ.get("HEAD_REF", ""),
        os.environ.get("HEAD_REPO", ""),
        os.environ.get("BASE_REPO", ""),
    )
    print(message, file=sys.stderr if status else sys.stdout)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
uv run pytest tests/test_base_branch_guard.py -v
```

Expected: 16 passed.

- [ ] **Step 5: Run the whole suite to confirm nothing else broke**

```bash
uv run pytest -v
```

Expected: all pass. `tests/conftest.py` has broken on nearly every change to this suite, so this step is not optional.

- [ ] **Step 6: Prove the guard by injection, not by reading**

```bash
printf 'specification/v0.1.0/acs_schema.json\nCONTRIBUTING.md\n' > /tmp/changed.txt
BASE_REF=main HEAD_REF=spec/x HEAD_REPO=fork/x BASE_REPO=GenAI-Security-Project/agent-control-standard \
  python3 tools/base_branch_guard.py /tmp/changed.txt; echo "exit=$?"
```

Expected: exit=1, message naming `specification/v0.1.0/acs_schema.json` and not `CONTRIBUTING.md`.

```bash
printf 'docs/topics/faq.md\n' > /tmp/changed.txt
BASE_REF=main HEAD_REF=docs/x HEAD_REPO=fork/x BASE_REPO=GenAI-Security-Project/agent-control-standard \
  python3 tools/base_branch_guard.py /tmp/changed.txt; echo "exit=$?"
```

Expected: exit=0.

- [ ] **Step 7: Commit**

```bash
git add tools/base_branch_guard.py tests/test_base_branch_guard.py
git commit -s -m "Add the guard that keeps specification changes off the publishing branch"
```

---

### Task 2: The guard workflow

**Files:**
- Create: `.github/workflows/pr-base-guard.yml`

**Interfaces:**
- Consumes: `tools/base_branch_guard.py` from Task 1, invoked as a script with one argument.
- Produces: a check run named `base-branch-guard`. Phase 2 Step 10 requires that exact string in `protect-main`.

- [ ] **Step 1: Write the workflow**

```yaml
# Keeps specification and code changes off the branch that publishes on merge.
#
# The job id below is the check run name the protect-main ruleset requires. Renaming the
# job without renaming the required check leaves a required status check that never
# reports, which blocks every pull request to main permanently.
name: PR base guard

on:
  pull_request:
    branches: ["main"]

permissions: {}

concurrency:
  group: pr-base-guard-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  base-branch-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          # Both endpoints of the diff have to be present to compute a merge base.
          fetch-depth: 0

      - name: List the changed paths
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          set -euo pipefail
          # Three-dot compares against the merge base, so commits that landed on the
          # base branch after this pull request opened do not count as its changes.
          git diff --name-only "${BASE_SHA}...${HEAD_SHA}" > changed.txt
          cat changed.txt

      - name: Enforce the documentation lane
        env:
          # Passed through the environment rather than interpolated into the shell. A
          # head ref is contributor-controlled text and ${{ }} inside run: executes.
          BASE_REF: ${{ github.event.pull_request.base.ref }}
          HEAD_REF: ${{ github.event.pull_request.head.ref }}
          HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}
          BASE_REPO: ${{ github.repository }}
        run: python3 tools/base_branch_guard.py changed.txt
```

- [ ] **Step 2: Validate the YAML parses**

```bash
uv run python -c "import yaml;yaml.safe_load(open('.github/workflows/pr-base-guard.yml'))" \
  && echo OK
```

Expected: `OK`. It must be `uv run python`: the system `python3` on this machine has no PyYAML, and `import yaml` there fails with `ModuleNotFoundError` that reads like broken YAML.

- [ ] **Step 3: Confirm the job id matches the required check string**

```bash
grep -n "^  base-branch-guard:" .github/workflows/pr-base-guard.yml
```

Expected: one match. This string is repeated in Phase 2 Step 10.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/pr-base-guard.yml
git commit -s -m "Run the base branch guard on every pull request to main"
```

---

### Task 3: Issue forms

**Files:**
- Create: `.github/ISSUE_TEMPLATE/1-bug.yml`
- Create: `.github/ISSUE_TEMPLATE/2-proposal.yml`
- Create: `.github/ISSUE_TEMPLATE/3-reference-implementation.yml`
- Create: `.github/ISSUE_TEMPLATE/4-conformance-report.yml`
- Create: `.github/ISSUE_TEMPLATE/5-documentation.yml`
- Create: `.github/ISSUE_TEMPLATE/6-something-else.yml`
- Modify: `.github/ISSUE_TEMPLATE/config.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: labels `type:bug`, `type:proposal`, `type:refimpl`, `type:conformance`, `type:docs`, and `status:needs-triage`. Phase 2 Step 2 creates them. A form referencing a label that does not exist fails to apply it silently.

**Rule for every form:** no form may declare a `scope:`, `priority:`, `workstream:`, or `status:accepted` label. That prohibition is the whole enforcement mechanism for maintainer-only decision labels.

- [ ] **Step 1: Write the scope dropdown that every form shares**

Each of the six forms ends with this block, copied verbatim:

```yaml
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 2: Write `1-bug.yml`**

```yaml
name: Bug report
description: Something is broken in the specification, a schema, the site, CI, or tooling.
title: "[Bug] "
labels: ["type:bug", "status:needs-triage"]
body:
  - type: markdown
    attributes:
      value: >-
        Do not file a security vulnerability here. Use private vulnerability reporting.
        See SECURITY.md.
  - type: textarea
    id: what
    attributes:
      label: What is broken
      description: One or two sentences.
    validations:
      required: true
  - type: input
    id: where
    attributes:
      label: Where
      description: File path, schema $id, documentation page, or workflow name.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What the specification says, and what happens instead
      description: Quote the line if there is one.
    validations:
      required: true
  - type: textarea
    id: impact
    attributes:
      label: Impact on implementers
      description: Who breaks, and how badly.
    validations:
      required: false
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 3: Write `2-proposal.yml`**

```yaml
name: Feature or specification proposal
description: A new capability, hook, event, or AgBOM component.
title: "[Proposal] "
labels: ["type:proposal", "status:needs-triage"]
body:
  - type: markdown
    attributes:
      value: >-
        Specification changes affect every downstream implementer. Open a Discussion
        first and link it below.
  - type: textarea
    id: problem
    attributes:
      label: The problem
      description: What cannot be done today. Describe the problem, not the solution.
    validations:
      required: true
  - type: textarea
    id: wire
    attributes:
      label: Why the wire has to carry it
      description: >-
        SPEC_REVIEW_PRINCIPLES.md principle 3 is that something goes on the wire only if
        it is lost otherwise. Make that case.
    validations:
      required: true
  - type: checkboxes
    id: constituencies
    attributes:
      label: Which constituencies this affects
      description: From SPEC_REVIEW_PRINCIPLES.md principle 2.
      options:
        - label: Observed Agent implementers
        - label: Guardian implementers
        - label: Policy authors
        - label: Auditors and incident responders
        - label: Platform and harness vendors
        - label: Enterprise deployers
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: Including riding an existing element rather than adding one.
    validations:
      required: true
  - type: input
    id: discussion
    attributes:
      label: Discussion link
      description: The Discussion thread where this was raised.
    validations:
      required: true
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 4: Write `3-reference-implementation.yml`**

```yaml
name: Reference implementation work
description: A port to another runtime, a hardening task, or a new adapter.
title: "[RefImpl] "
labels: ["type:refimpl", "status:needs-triage"]
body:
  - type: markdown
    attributes:
      value: >-
        This is the work the project needs most. Check the open issues labelled
        `help wanted` before filing, since the one you want may already be accepted.
  - type: input
    id: target
    attributes:
      label: Target runtime or language
      description: For example Python, Go, Rust, Codex, or an existing implementation to harden.
    validations:
      required: true
  - type: textarea
    id: proves
    attributes:
      label: What this proves
      description: >-
        A reference implementation earns its place by demonstrating something the
        specification alone cannot. Say what.
    validations:
      required: true
  - type: dropdown
    id: intent
    attributes:
      label: Do you intend to implement this yourself
      options:
        - "Yes, I want this assigned to me"
        - "No, I am proposing it for someone else"
    validations:
      required: true
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 5: Write `4-conformance-report.yml`**

```yaml
name: Conformance or dogfooding report
description: You ran ACS against a real harness and it did not behave as specified.
title: "[Conformance] "
labels: ["type:conformance", "status:needs-triage"]
body:
  - type: markdown
    attributes:
      value: >-
        **Stop if you found a security vulnerability.** A dogfooding run is the most
        likely place to find one. Do not describe it here. Use private vulnerability
        reporting: see SECURITY.md.
  - type: textarea
    id: setup
    attributes:
      label: What you ran
      description: Harness, adapter, Guardian, versions, and configuration.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What you expected
      description: Cite the specification section that led you to expect it.
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: What happened
      description: Include the wire payload if you have it, with secrets removed.
    validations:
      required: true
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 6: Write `5-documentation.yml`**

```yaml
name: Documentation
description: A page is wrong, unclear, or missing.
title: "[Docs] "
labels: ["type:docs", "status:needs-triage"]
body:
  - type: input
    id: page
    attributes:
      label: Page
      description: URL or file path.
    validations:
      required: true
  - type: textarea
    id: problem
    attributes:
      label: What is wrong or missing
    validations:
      required: true
  - type: dropdown
    id: priority-scope
    attributes:
      label: Current Priority Scope
      description: >-
        Read the Current Priority Scope in CONTRIBUTING.md before answering. An honest
        "deferred" is more useful to us than a hopeful "in focus".
      options:
        - Feeds the runnable Guardian reference implementation
        - Feeds the AGT interoperability benchmark
        - Feeds conformance evidence
        - This is deferred or out of scope and I am filing it to be tracked
        - I am not sure
    validations:
      required: true
```

- [ ] **Step 7: Write `6-something-else.yml`**

This form is the most important one in the set and the easiest to leave out. The strongest technical contribution the project has received from outside fits none of the five above.

```yaml
name: Something else
description: >-
  A structural finding, a question the other forms do not fit, or an idea that does not
  have a shape yet. Nothing here is required except the description.
title: ""
labels: ["type:proposal", "status:needs-triage"]
body:
  - type: markdown
    attributes:
      value: >-
        The other forms exist to make triage fast. This one exists because the most
        valuable contributions rarely fit a form. Tell us what you found.
  - type: textarea
    id: what
    attributes:
      label: What you want to tell us
    validations:
      required: true
```

- [ ] **Step 8: Turn off blank issues**

Modify `.github/ISSUE_TEMPLATE/config.yml`. Change `blank_issues_enabled: true` to `false` and add a line of comment above it. Leave the three `contact_links` exactly as they are.

```yaml
# Routes people away from filing security reports as public issues, which is
# the single most common way a coordinated disclosure gets blown.
#
# Blank issues are off because a form is what applies the type: and
# status:needs-triage labels that triage depends on. The "Something else" form is the
# open door that keeps this from turning away a finding that fits no template.

blank_issues_enabled: false
```

- [ ] **Step 9: Verify no form declares a decision label**

```bash
grep -rn "labels:" .github/ISSUE_TEMPLATE/ | grep -E "scope:|priority:|workstream:|status:accepted" \
  && echo "FAIL: a form stamps a decision label" || echo "OK"
```

Expected: `OK`.

- [ ] **Step 10: Verify all six forms parse**

```bash
for f in .github/ISSUE_TEMPLATE/*.yml; do
  uv run python -c "import yaml;yaml.safe_load(open('$f'))" || echo "FAIL $f"
done; echo done
```

Expected: no `FAIL` lines.

- [ ] **Step 11: Commit**

```bash
git add .github/ISSUE_TEMPLATE/
git commit -s -m "Route every issue through a form that cannot stamp a decision label"
```

---

### Task 4: Pull request template

**Files:**
- Modify: `.github/pull_request_template.md`

**Interfaces:**
- Consumes: the acceptance gate defined in Task 5's `CONTRIBUTING.md`.
- Produces: nothing other tasks read.

- [ ] **Step 1: Replace the file**

```markdown
## What changed

<!-- One or two sentences. What does this PR do and why? -->

## Which issue does this implement

Closes #

<!-- A change that alters behavior, normative text, or adds code needs an issue carrying
     `status:accepted`. If yours is not accepted yet, open the PR anyway. It will wait
     rather than be closed. See Current Priority Scope in CONTRIBUTING.md. -->

- [ ] This is an editorial correction (typo, grammar, link, formatting) with no change in
      meaning, so it needs no issue

## Base branch

- [ ] `integration`, because this touches the specification, schemas, a reference
      implementation, an adapter, tests, or CI
- [ ] `main`, because every changed path is on the documentation lane allowlist in
      CONTRIBUTING.md

## Type of change

- [ ] Specification change (schema, hooks, events, AgBOM)
- [ ] Reference implementation or adapter
- [ ] Documentation
- [ ] Tooling or CI
- [ ] Governance (licensing, security policy, contributor docs)

## Specification changes

<!-- Delete this section if you touched nothing under specification/ or docs/spec/. -->

- [ ] I opened a [Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions) before this PR
- [ ] Schema changes validate against the JSON Schema spec
- [ ] I described the impact on downstream implementers below

**Breaking for implementers?** <!-- yes or no, and what breaks -->

## I tested this

- [ ] I synced my branch with the base branch before opening this
- [ ] `uv run pytest -v` passes on my machine
- [ ] `uv run mkdocs build --strict` passes on my machine

<!-- These three are the difference between a review and a debugging session. A PR that
     has not been run is not ready for someone else's afternoon. -->

## Checklist

- [ ] Commits are signed off with `git commit -s` (required by the DCO)
- [ ] Prose follows [STYLE.md](../STYLE.md)
- [ ] No secrets, tokens, or internal URLs in the diff

## Security

- [ ] This change has no security impact

<!-- If it does, describe it. Do not open a PR for an unreported vulnerability.
     Report it privately first: see SECURITY.md. -->
```

- [ ] **Step 2: Commit**

```bash
git add .github/pull_request_template.md
git commit -s -m "Ask a pull request which issue it implements and whether it was run"
```

---

### Task 5: CONTRIBUTING.md

**Files:**
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the single statement of Current Priority Scope. Forms, templates, and `GOVERNANCE.md` link here and never restate it.

- [ ] **Step 1: Insert the Current Priority Scope section**

Place it immediately after the opening paragraph and before `## Code of Conduct`.

```markdown
## Current Priority Scope

Reviewed at each milestone. Current window: Day 0 to Day 30. Next review October 9, 2026.

The project has one committed outcome:

> A runnable Guardian Agent reference implementation, benchmarked for interoperability
> against Microsoft Agent Governance Toolkit, in the hands of external evaluators within
> ninety days of the September 10, 2026 kick-off. Everything else either feeds that
> outcome or gets deferred.

Every issue and every pull request is accepted against that sentence. This section is the
only place that scope is stated, so if something here disagrees with a form, a template,
or a comment, this wins.

**In focus.** Work that feeds the runnable Guardian, the interoperability benchmark, or
the conformance evidence that makes either credible:

- The mandatory floor decision in PR #21, which gates everything behind it
- The Claude Code, Cursor, and NVIDIA NAT adapters in PR #22
- The AGT reference implementation in PR #60
- Ports of that reference implementation to other runtimes: Python, Go, Rust, Codex
- Production-hardening it, including span batching and OpenTelemetry collection
- Resolving the fail-open default, which issues #32 and #37 attack from opposite ends
- The ACS-Core conformance claim template
- The requirement ledger and behavioral tests in milestone #33
- Closing the Cursor file-read gap
- Conformance and dogfooding reports that document where ACS fails in practice

**Deferred to v0.2.0.** Real work, tracked, landing after Day 90: async and composition,
streaming, batching semantics, recursive ask, quorum, multi-tenant isolation, the Cedar
binding, and AgBOM federation across A2A peers. Negative conformance vectors sit here
too, in #53.

One distinction, because it will otherwise get argued in a pull request. *Batching
semantics in the specification* is deferred. *Batching in the reference implementation*
is in focus, because it is exactly the production-hardening the project asked for. The
two share a word and nothing else.

**Out of scope.** What ACS leaves to deployments by design: the policy engine, the
signature algorithm, the transport, the authentication mechanism, and the policy content.
The specification is opinionated on the contract and permissive on the implementation.
That is a position, not a gap waiting to be filled.

A proposal that is deferred or out of scope is still worth filing. It gets a label and a
tracking issue rather than a close, because a finding the project cannot act on this
quarter is not a finding without value.

## How work gets accepted

Anyone may open an issue. Only an issue carrying `status:accepted` enters the backlog,
and only a maintainer applies that label.

A pull request that changes behavior, alters normative text, or adds code references an
accepted issue. An editorial correction does not, wherever it lands: a typo, a grammar
fix, a broken link, or a formatting repair that leaves the meaning untouched needs no
issue.

If you open a pull request against an issue that is not accepted yet, it will not be
closed and it will not be reviewed. It waits, and a comment will say so. Start from an
issue labelled `help wanted` if you want work that is already accepted.

Maintainers apply `scope:`, `priority:`, `workstream:`, and `status:accepted`. No issue
form can apply them, which is what makes the rule hold rather than depend on everyone
remembering it.
```

- [ ] **Step 2: Replace the Development Process section**

Replace steps 1 through 6 and the paragraph that follows.

```markdown
## Development Process

1. **Fork the repository** and clone your fork
2. **Branch from `integration`.** Use `spec/`, `refimpl/`, `fix/`, or `docs/` followed by
   a short description
3. **Make your changes** following the style guide
4. **Sync with `integration` and run the guards** before you open anything. `uv run
   pytest -v` and `uv run mkdocs build --strict` both have to pass on your machine
5. **Sign your commits** with `git commit -s` (required by the DCO below)
6. **Open a pull request against `integration`**
7. **Address review feedback** to land your change

`integration` is the default branch, so a pull request opened from the GitHub interface
already targets it. `main` publishes the site and all 44 schema `$id` URIs on merge, so
it takes only two kinds of change: a promotion from `integration`, and an editorial
change to a path on the allowlist below. A guard enforces this and will tell you to
retarget if you get it wrong.

Paths that may target `main` directly: `docs/topics/`, `design/`, `docs/README.md`,
`README.md`, `CONTRIBUTORS.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
`SECURITY.md`, `STYLE.md`, `LICENSING.md`, and `NOTICE`. Everything else goes to
`integration`, including `docs/spec/`, `docs/concepts/`, `docs/identity/`, `mkdocs.yml`,
`overrides/`, `landing/`, `docs/stylesheets/`, and `docs/assets/`.

For changes to the spec itself (`acs_schema.json`, hooks, events), open a
[Discussion](https://github.com/GenAI-Security-Project/agent-control-standard/discussions)
before submitting a PR. These affect downstream implementers and warrant a longer
conversation.
```

- [ ] **Step 3: Replace the authorship paragraph**

Delete the paragraph beginning "Commits land under human authorship" and ending "carry through unchanged." Insert this section in its place.

```markdown
## Authorship and AI assistance

Commits land under human authorship. The DCO below is a certification about the origin of
code, and only a person can make one, so every commit carries a `Signed-off-by` line
naming a human who takes responsibility for what the commit contains. That requirement
does not move.

The rest of the trailers are your call. Many contributors here write with AI assistance.
If you want to record that with a `Co-Authored-By` trailer naming the tool, keep it. If
you would rather not, leave it off. Maintainers will not add one and will not remove one,
and its presence has no effect on how a change is reviewed.

A trailer naming a model certifies nothing and moves no responsibility. The human on the
`Signed-off-by` line answers for the change either way. Some employers require their
people to disclose AI assistance, and a visible trailer is the simplest way to satisfy
that. ACS is also a standard about agent provenance, and a project built on the premise
that you should be able to see what an agent did has no business erasing the record of
what an agent did to its own commits.
```

- [ ] **Step 4: Replace the What We Need section**

```markdown
## What We Need

Start with [issues labelled `help wanted`](https://github.com/GenAI-Security-Project/agent-control-standard/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
Every one of them is already accepted, which means you can open a pull request against it
without waiting on triage.

The highest-value contribution right now is running ACS against a real harness and
documenting where it fails. Install the reference implementation, wire it to a coding
agent, and file a conformance report when the behavior and the specification disagree.
That is worth more to this project than a patch nobody asked for.
```

- [ ] **Step 5: Verify the build still passes**

```bash
uv run mkdocs build --strict && uv run pytest -v
```

Expected: both pass.

- [ ] **Step 6: Check for style violations in the prose you wrote**

**Do not edit the DCO.** `CONTRIBUTING.md` lines 79 and 85 carry the Developer's
Certificate of Origin, which is verbatim legal text ending each clause with `; or`. Those
two semicolons are correct and must not be "fixed". The check below excludes that block
so nobody reaches for it.

```bash
awk '/^## Developer.s Certificate of Origin/{skip=1;next} skip && /^## /{skip=0} !skip' \
  CONTRIBUTING.md > /tmp/prose.txt
grep -nE '(^|\. )(And|But|So|Or|Yet) |—|; ' /tmp/prose.txt || echo "clean"
```

Expected: `clean`. Verified against the file as it stands today: 89 of 114 lines kept,
every section except the DCO block, no matches.

The `skip && /^## /` condition is what keeps the sections *after* the DCO in the check. A
plain range expression drops everything to the end of the file, and `awk '!/pattern/,0'`
does not exclude anything at all, because the range opens on the first line that does not
match, which is line one.

- [ ] **Step 7: Commit**

```bash
git add CONTRIBUTING.md
git commit -s -m "State the Current Priority Scope and the acceptance gate in CONTRIBUTING"
```

---

### Task 6: GOVERNANCE.md triage authority

**Files:**
- Modify: `GOVERNANCE.md`

**Interfaces:**
- Consumes: the label taxonomy from Task 3 and Phase 2 Step 2.
- Produces: nothing other tasks read.

- [ ] **Step 1: Insert a section after "Workstream leads"**

```markdown
## Triage authority

Workstream leads and the project lead apply the decision labels: `scope:`, `priority:`,
`workstream:`, and `status:accepted`. Nobody else does, and no issue form can.

Minimum triage on a new issue is two labels, `scope:` and `status:`. `priority:` and
`workstream:` are enrichment applied to accepted work. Requiring four decisions per issue
is how a taxonomy stops getting used in month two.

`priority:P0` is reserved for work on the serial chain the Strategic Adoption Plan names:
the mandatory floor decision, the adapters, the installable Guardian, and the
interoperability benchmark. It does not mean important.

Triage runs on the weekly call. Promotion from `integration` to `main` is a standing item
on the same call, and the project lead owns merging it.
```

- [ ] **Step 2: Commit**

```bash
git add GOVERNANCE.md
git commit -s -m "Record who applies decision labels and what minimum triage is"
```

---

### Task 7: Automation workflows

**Files:**
- Create: `.github/workflows/sync-integration.yml`
- Create: `.github/workflows/open-promotion.yml`
- Create: `.github/workflows/pr-intake.yml`
- Modify: `.github/dependabot.yml`
- Modify: `.github/workflows/sync_version.yml:8` (the `branches` key)

**Interfaces:**
- Consumes: the labels `status:accepted` and `status:needs-triage` from Phase 2 Step 2.
- Produces: nothing other tasks read.

- [ ] **Step 1: Write `sync-integration.yml`**

It opens a pull request rather than pushing. `protect-integration` requires pull requests and blocks non-fast-forward updates, and `GITHUB_TOKEN` is not a bypass actor, so a workflow that pushed would fail on every run.

```yaml
# Keeps integration current with main, so a promotion pull request stays conflict-free.
#
# This opens a pull request rather than pushing. The protect-integration ruleset requires
# pull requests and blocks non-fast-forward updates, and GITHUB_TOKEN is not a bypass
# actor, so a push here would fail on every run.
name: Sync integration from main

on:
  push:
    branches: ["main"]
  workflow_dispatch:

permissions: {}

concurrency:
  group: sync-integration
  cancel-in-progress: false

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Open or update the sync pull request
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          if git merge-base --is-ancestor origin/main origin/integration; then
            echo "integration already contains main. Nothing to sync."
            exit 0
          fi
          if [ "$(gh pr list --base integration --head main --state open --json number --jq 'length')" -gt 0 ]; then
            echo "A sync pull request is already open."
            exit 0
          fi
          gh pr create --base integration --head main \
            --title "Sync integration from main" \
            --body "Documentation landed on main. This carries it to integration so the next promotion does not conflict. The content already passed review on main."
```

- [ ] **Step 2: Write `open-promotion.yml`**

Promotion is the operation the branching model exists to serve, and it is the one nobody remembers to do. A machine opening the pull request means the decision on the weekly call is whether to merge rather than whether to remember.

```yaml
# Opens the weekly promotion pull request from integration to main.
#
# A three-tier branching model pays its whole cost up front and returns nothing until a
# promotion happens. Leaving promotion to memory is how integration accrues specification
# work while main keeps publishing schemas nobody is reading.
name: Open promotion pull request

on:
  schedule:
    # 13:00 UTC Thursday, the morning of the weekly call.
    - cron: "0 13 * * 4"
  workflow_dispatch:

permissions: {}

jobs:
  promote:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Open the promotion pull request if integration is ahead
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          AHEAD="$(git rev-list --count origin/main..origin/integration)"
          if [ "$AHEAD" -eq 0 ]; then
            echo "integration is not ahead of main. Nothing to promote."
            exit 0
          fi
          if [ "$(gh pr list --base main --head integration --state open --json number --jq 'length')" -gt 0 ]; then
            echo "A promotion pull request is already open."
            exit 0
          fi
          gh pr create --base main --head integration \
            --title "Promote integration to main" \
            --body "${AHEAD} commit(s) ahead. Merging publishes the site and every schema \$id URI. Merge with a merge commit, not a squash: squashing flattens the specification history that makes a schema change reviewable later."
```

- [ ] **Step 3: Write `pr-intake.yml`**

The trigger is `pull_request_target` because `GITHUB_TOKEN` is read-only on a `pull_request` event from a fork, which is every external contribution. That trigger is a privilege-escalation surface, so this workflow checks out no code and runs nothing the contributor supplied.

```yaml
# Tells a contributor why their pull request is waiting, and labels it so the queue is
# visible.
#
# pull_request_target is used deliberately: GITHUB_TOKEN is read-only on a pull_request
# event from a fork, and every external contribution is a fork. That trigger runs with
# repository write scope against the base branch, so this workflow checks out no code,
# runs no contributor-supplied script, and reads the pull request body from the event
# payload as data.
name: PR intake

on:
  pull_request_target:
    types: [opened, edited, reopened]

permissions: {}

concurrency:
  group: pr-intake-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      issues: read
    steps:
      - name: Check whether a referenced issue is accepted
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          set -euo pipefail
          # Issue numbers are extracted from the body text, which is untrusted input. It
          # is matched against a digit pattern and never evaluated.
          NUMBERS="$(printf '%s' "${PR_BODY:-}" | grep -oE '#[0-9]+' | tr -d '#' | sort -u || true)"
          if printf '%s' "${PR_BODY:-}" | grep -qiE '^\s*-\s*\[x\]\s*This is an editorial correction'; then
            echo "Declared editorial. No issue required."
            exit 0
          fi
          # The `edited` trigger fires every time anyone touches the body, so without
          # this the queue comment gets reposted on every edit.
          if gh pr view "$PR_NUMBER" --repo "$REPO" --json comments \
             --jq '[.comments[] | select(.author.login == "github-actions")] | length' \
             | grep -qv '^0$'; then
            echo "Already commented on this pull request."
            exit 0
          fi
          for n in $NUMBERS; do
            if gh issue view "$n" --repo "$REPO" --json labels \
               --jq '.labels[].name' 2>/dev/null | grep -qx 'status:accepted'; then
              echo "Issue #$n is accepted."
              exit 0
            fi
          done
          gh pr edit "$PR_NUMBER" --repo "$REPO" --add-label 'status:needs-triage'
          gh pr comment "$PR_NUMBER" --repo "$REPO" --body "Thanks for this. It is queued rather than ignored.

          This pull request does not reference an issue carrying \`status:accepted\`, so a maintainer has not looked at it yet and will not until the underlying issue is triaged. Nothing here is rejected. See [Current Priority Scope](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md#current-priority-scope) for what the project is working on, and [\`help wanted\`](https://github.com/GenAI-Security-Project/agent-control-standard/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) for work that is already accepted.

          If this is an editorial correction, tick that box in the description and this comment stops applying."
```

- [ ] **Step 4: Remove the Dependabot problem rather than solving it**

Modify `.github/dependabot.yml`. Add no `target-branch` key. Instead add this comment above `updates:` so the next reader knows why:

```yaml
# No target-branch key. Dependabot follows the default branch, which is `integration`,
# so both routine and security updates land there and never meet the base-branch guard.
# Setting target-branch would make this depend on undocumented security-update targeting
# behavior for no benefit.
```

- [ ] **Step 5: Point version sync at integration**

In `.github/workflows/sync_version.yml`, change `branches: ["main"]` to `branches: ["integration"]`. `version.txt`, `pyproject.toml`, and `uv.lock` are all off the documentation lane, so a version-sync pull request against `main` would trip the guard.

- [ ] **Step 6: Validate every workflow parses**

```bash
for f in .github/workflows/*.yml .github/dependabot.yml; do
  uv run python -c "import yaml;yaml.safe_load(open('$f'))" || echo "FAIL $f"
done; echo done
```

Expected: no `FAIL` lines.

- [ ] **Step 7: Confirm no workflow grants more than it needs**

```bash
grep -n -A4 "^permissions:" .github/workflows/*.yml .github/workflows/*.yaml
```

Expected: every file has a top-level `permissions: {}` and per-job grants no wider than those written above.

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/ .github/dependabot.yml
git commit -s -m "Automate the sync, the promotion, and the intake comment"
```

---

### Task 8: Scope staleness reminder

**Files:**
- Create: `.github/workflows/scope-review.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the workflow**

```yaml
# Opens an issue when the Current Priority Scope review date passes.
#
# It opens an issue rather than failing a build. A stale scope is a governance problem,
# and blocking a documentation deploy on one helps nobody.
name: Scope review reminder

on:
  schedule:
    - cron: "0 14 * * 1"
  workflow_dispatch:

permissions: {}

jobs:
  remind:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Open a review issue if the date has passed
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          # The date is read from CONTRIBUTING.md so the document stays the single source.
          DUE="$(grep -oE 'Next review [A-Z][a-z]+ [0-9]{1,2}, [0-9]{4}' CONTRIBUTING.md \
                 | head -1 | sed 's/^Next review //')"
          if [ -z "$DUE" ]; then
            echo "::error file=CONTRIBUTING.md::No 'Next review <date>' line found"
            exit 1
          fi
          DUE_EPOCH="$(date -u -d "$DUE" +%s)"
          NOW_EPOCH="$(date -u +%s)"
          if [ "$NOW_EPOCH" -lt "$DUE_EPOCH" ]; then
            echo "Scope review not due until $DUE."
            exit 0
          fi
          TITLE="Review the Current Priority Scope (was due $DUE)"
          if [ "$(gh issue list --state open --search "$TITLE in:title" --json number --jq 'length')" -gt 0 ]; then
            echo "Reminder already open."
            exit 0
          fi
          gh issue create --title "$TITLE" \
            --label 'status:needs-triage' \
            --body "The Current Priority Scope in CONTRIBUTING.md passed its review date of $DUE. Confirm what is still in focus, move what has shipped, and set the next review date. This is a standing item for the weekly call."
```

- [ ] **Step 2: Verify the date parser finds the line Task 5 wrote**

```bash
grep -oE 'Next review [A-Z][a-z]+ [0-9]{1,2}, [0-9]{4}' CONTRIBUTING.md
```

Expected: `Next review October 9, 2026`. If this prints nothing, Task 5 Step 1 was not applied verbatim and the workflow will fail on its first run.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/scope-review.yml
git commit -s -m "Open an issue when the priority scope review date passes"
```

---

### Task 9: Open the Phase 1 pull request

- [ ] **Step 1: Run everything one last time**

```bash
uv run pytest -v && uv run mkdocs build --strict
```

Expected: both pass.

- [ ] **Step 2: Push the branch, and stop**

Push only. Do not open the pull request yet.

```bash
git push -u origin feature/contribution-governance
```

This diff touches `.github/`, `tools/`, and `tests/`, every one of them off the
documentation lane. A pull request from here to `main` would fail the guard it is
installing, so it goes to `integration` instead, and `integration` does not exist until
Phase 2 Step 4. Opening it against `main` now is the single mistake that would deadlock
the whole evening. Phase 2 Step 7 opens it correctly.

---

## Phase 2: Live repository configuration

**Not for subagent execution.** Every step below mutates the public OWASP repository in a way that is outward-facing, hard to reverse, or both: deleting a label removes it from every issue carrying it, filing issues notifies watchers, retargeting a pull request touches someone else's work, and moving the default branch changes what every visitor and every clone gets. The project lead runs these, or explicitly authorizes each one.

**Order is not a preference, and two orderings deadlock the repository.**

Pinning `protect-main` to a literal ref precedes moving the default branch, or the
protection follows the default and leaves `main` bare. Separately, `base-branch-guard`
becomes a required status check **last**, after the guard workflow has reached `main`
through a promotion. A required check that no workflow reports never turns green, so
adding it early blocks the Phase 1 pull request that installs the guard, and then blocks
every documentation pull request whose merge commit does not yet carry the workflow.
Version 1.0 of this plan added it in Step 1 and deadlocked itself.

- [ ] **Step 1: Pin `protect-main` to the literal ref, without the new check**

```bash
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 > /tmp/protect-main.json
# Edit /tmp/protect-main.json:
#   conditions.ref_name.include: ["refs/heads/main"]
#   rules[pull_request].parameters.allowed_merge_methods: ["squash","rebase","merge"]
# Do NOT add base-branch-guard yet. That is Step 10.
# Leave required_approving_review_count at 1. Raising it throttles promotion, which is
# the operation this whole model exists to serve.
gh api -X PUT repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 \
  --input /tmp/protect-main.json
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 \
  --jq '.conditions.ref_name.include, [.rules[]|select(.type=="pull_request").parameters.allowed_merge_methods]'
```

Expected: `["refs/heads/main"]` and `["squash","rebase","merge"]`.

- [ ] **Step 2: Create the label taxonomy**

```bash
gh label edit bug           --name 'type:bug'        --color 'd73a4a'
gh label edit documentation --name 'type:docs'       --color '0075ca'
gh label edit enhancement   --name 'type:proposal'   --color 'a2eeef'
gh label create --force 'type:refimpl'     --color '1d76db' --description 'Reference implementation or adapter work'
gh label create --force 'type:conformance' --color '5319e7' --description 'Conformance or dogfooding report'

gh label create --force 'scope:in-focus' --color '0e8a16' --description 'Feeds the ninety-day committed outcome. Maintainers only'
gh label create --force 'scope:deferred' --color 'fbca04' --description 'Real work, tracked, lands after Day 90. Maintainers only'
gh label create --force 'scope:out'      --color 'e4e669' --description 'Outside what ACS does by design. Maintainers only'

gh label create --force 'status:needs-triage' --color 'ededed' --description 'Not yet triaged. Applied by the issue forms'
gh label create --force 'status:accepted'     --color '0e8a16' --description 'In the backlog. Maintainers only'
gh label create --force 'status:blocked'      --color 'b60205' --description 'Waiting on another decision or PR'
gh label create --force 'status:needs-info'   --color 'd876e3' --description 'Waiting on the filer'

gh label create --force 'priority:P0' --color 'b60205' --description 'On the serial chain to the benchmark. Maintainers only'
gh label create --force 'priority:P1' --color 'd93f0b' --description 'Maintainers only'
gh label create --force 'priority:P2' --color 'fef2c0' --description 'Maintainers only'

for w in spec coding-agents sdk identity outreach; do
  gh label create --force "workstream:$w" --color 'c5def5' --description 'Owning workstream. Maintainers only'
done
```

Before deleting, confirm each is unused. Deletion removes a label from every issue carrying it.

```bash
for l in invalid wontfix duplicate question; do
  echo -n "$l: "; gh issue list --label "$l" --state all --json number --jq 'length'
done
```

Delete only those reporting `0`.

- [ ] **Step 3: Merge the ready pull requests to `main`**

Core-team decision, not an automated step. The sync's plan was merge #21, align #20 with it, then review #22. Doing this before `integration` exists means those pull requests never move.

- [ ] **Step 4: Create `integration` from `main`**

```bash
git fetch origin main
git push origin origin/main:refs/heads/integration
gh api repos/GenAI-Security-Project/agent-control-standard/branches --jq '.[].name'
```

Expected: `integration` present and identical to `main`.

- [ ] **Step 5: Create `protect-integration` and `protect-release`**

```bash
gh api -X POST repos/GenAI-Security-Project/agent-control-standard/rulesets \
  --input /tmp/protect-integration.json
```

`protect-integration` mirrors the pre-change `protect-main`: target `refs/heads/integration`, one approval, `require_code_owner_review: true`, `dismiss_stale_reviews_on_push: true`, `require_last_push_approval: true`, `required_review_thread_resolution: true`, required checks `test` and `build`, merge methods squash and rebase, plus deletion and non-fast-forward rules.

`protect-release` targets `refs/heads/release/*` with deletion, non-fast-forward, one approval, and the same required checks.

- [ ] **Step 6: Retarget the remaining open pull requests**

Because `integration` and `main` are identical, no diff changes and no contributor redoes work.

```bash
for n in 63 24 22 60; do
  gh pr edit "$n" --base integration || echo "skip $n"
done
gh pr list --json number,baseRefName --jq '.[] | "#\(.number) -> \(.baseRefName)"'
```

`#20`, the FAQ, may stay on `main`.

After each retarget, confirm the required checks reported on the new base. Whether a base change re-triggers them is undocumented, and this repository's workflows declare no `pull_request` types. If a check is missing, close and reopen the pull request to force a run. Do not ask the contributor to rebase, which would cost them their existing approvals.

- [ ] **Step 7: Open the Phase 1 pull request against `integration` and merge it**

```bash
gh pr create --base integration --head feature/contribution-governance \
  --title "Install the contribution governance for the OWASP re-launch" \
  --body "Implements design/2026-09-09-contribution-governance-design.md v1.1."
```

It targets `integration` because the diff touches `.github/`, `tools/`, and `tests/`. Merge it once `test` and `build` pass.

- [ ] **Step 8: Promote to `main`**

This publishes the site with the new `CONTRIBUTING.md` and, just as importantly, puts the guard workflow on `main` so Step 10 has something that can report.

```bash
gh pr create --base main --head integration --title "Promote integration to main" \
  --body "Carries the contribution governance to the publishing branch."
```

Merge with a **merge commit**, not a squash.

```bash
git fetch origin main && git ls-tree --name-only origin/main .github/workflows/
```

Expected: `pr-base-guard.yml` present on `main`.

- [ ] **Step 9: Move the default branch to `integration`**

Step 1 must already be done.

```bash
gh repo edit GenAI-Security-Project/agent-control-standard --default-branch integration
gh api repos/GenAI-Security-Project/agent-control-standard --jq '.default_branch'
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 \
  --jq '.conditions.ref_name.include'
```

Expected: `integration`, and `protect-main` still naming `refs/heads/main`.

- [ ] **Step 10: Add `base-branch-guard` to the required checks on `main`**

Only now. The workflow reached `main` in Step 8, so the check can report.

```bash
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 > /tmp/protect-main.json
# Add {"context":"base-branch-guard"} to
# rules[required_status_checks].parameters.required_status_checks
gh api -X PUT repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 \
  --input /tmp/protect-main.json
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets/20720988 \
  --jq '[.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context]'
```

Expected: `["test","build","base-branch-guard"]`.

- [ ] **Step 11: Create the milestones**

```bash
for m in "Day 14:2026-09-24:Reference Implementation lead named. PR #21 floor decision closed. Discussions seeded. Domain transfer counterpart identified." \
         "Day 30:2026-10-09:PR #22 merged with the emission-conformance suite in CI. Documentation and Testing lead seats filled. Conformance claim template published. Fail-open resolution decided." \
         "Day 60:2026-11-06:Installable reference Guardian published. Milestone #33 requirement ledger drafted. AARM mapping session held. Domains transferred. OpenSSF registered." \
         "Day 90:2026-12-04:AGT interoperability benchmark published with results and disagreements. Cursor file-read gap closed. One external ACS-Core compatibility claim."; do
  IFS=':' read -r title due desc <<< "$m"
  gh api -X POST repos/GenAI-Security-Project/agent-control-standard/milestones \
    -f title="$title" -f due_on="${due}T23:59:59Z" -f description="$desc"
done
```

- [ ] **Step 12: File the seeded onramp issues**

Each carries `scope:in-focus`, `status:accepted`, `help wanted`, a workstream, and a priority. These are what make the acceptance gate an invitation rather than a queue.

1. Port the AGT reference implementation to Python
2. Port the AGT reference implementation to Go
3. Port the AGT reference implementation to Rust
4. Build a reference implementation against Codex
5. Add span batching to the reference implementation
6. Configure OpenTelemetry collection and export in the reference implementation
7. Dogfood AGT with ACS and file a conformance report
8. Publish the one-page ACS-Core conformance claim template
9. Choose and reserve a distribution name for the reference implementation

Items 8 and 9 are open decisions in the plan with Day 30 dates, so give them the Day 30 milestone.

- [ ] **Step 13: File the tracked follow-up issues**

1. Workstream vocabulary mismatch between `GOVERNANCE.md` and the plan's open lead seats
2. Label-strip enforcement workflow, if the permission lookup proves workable
3. Org-level project board fed by this label and milestone taxonomy (needs org admin)
4. Declarative logic CI for specification contradiction detection
5. Release-branch versioning, unspecified now that `sync_version.yml` follows `integration`
6. A comment on #52 that the DCO check stays indifferent to non-sign-off trailers
7. Confirm whether Dependabot security updates honor a non-default `target-branch`

- [ ] **Step 14: Verify the whole thing end to end**

```bash
# The guard fires on a real pull request. specification/proposals/ exists; a README at
# specification/README.md does not, so creating a new file is what actually produces a
# diff here.
git fetch origin integration
git checkout -b scratch/guard-proof origin/integration
mkdir -p specification/v0.1.0
printf 'guard proof, delete me\n' > specification/v0.1.0/GUARD_PROOF.txt
git add specification/v0.1.0/GUARD_PROOF.txt
git commit -s -m "Prove the guard fires"
git push -u origin scratch/guard-proof
gh pr create --base main --head scratch/guard-proof \
  --title "Scratch: prove the guard" --body "Delete me"
```

Expected: the `base-branch-guard` check fails and names
`specification/v0.1.0/GUARD_PROOF.txt`. Then clean up.

```bash
gh pr close scratch/guard-proof --delete-branch
```

```bash
gh label list --limit 100
gh api repos/GenAI-Security-Project/agent-control-standard --jq '.default_branch'
gh api repos/GenAI-Security-Project/agent-control-standard/rulesets --jq '.[]|"\(.name) \(.target) \(.enforcement)"'
gh issue list --label 'help wanted' --json number,title --jq 'length'
```

Expected: the taxonomy from Step 2, default branch `integration`, three branch rulesets plus the repository ruleset, and nine `help wanted` issues.

---

## Self-review

**Spec coverage.** Current Priority Scope is Task 5. Branching and the allowlist are Tasks 1, 2, and 5 plus Phase 2 Steps 4, 6, 7, and 8. Labels are Task 3 and Phase 2 Step 2. Issue intake is Task 3. The pull request gate is Tasks 4 and 7. Rulesets are Phase 2 Steps 1, 5, and 10. CODEOWNERS for `reference-implementations/` and `adapters/` is deliberately deferred until #60 and #22 land, since a CODEOWNERS entry for a path that does not exist is inert. Authorship is Task 5. The seeded onramp is Phase 2 Step 12. The sign-up form is specified in the design and is not a repository change. Promotion cadence is Task 7 and Task 6.

**Placeholders.** None. Every code and configuration step carries its content. Phase 2 Steps 1, 5, and 10 describe ruleset JSON edits rather than pasting the full payload, because the payload is fetched from the live API and edited in place, and a stale copy pasted here would overwrite fields the API added since.

**Type consistency.** `decide`, `in_docs_lane`, `is_promotion`, and `paths_requiring_integration` carry the same signatures in the test file, the implementation, and the Interfaces block. `is_promotion` takes three arguments everywhere. The job id `base-branch-guard` is identical in Task 2 Step 1, Task 2 Step 3, Phase 2 Step 10, and Phase 2 Step 14. The label strings in Task 3 match those created in Phase 2 Step 2.

**Executed, not assumed.** The guard module, its sixteen tests, the `gh label` and `gh repo` flags, the pull-request-count idiom, the PyYAML availability, and the DCO-excluding style check were all run before this plan was finalized. The premortem found six defects that way, including a test that could never pass and a Phase 2 ordering that deadlocked its own pull request.
