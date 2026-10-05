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
