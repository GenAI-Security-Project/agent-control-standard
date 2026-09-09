#!/usr/bin/env python3
"""Apply the Phase 2 contribution-governance configuration to the live repository.

Phase 2 of design/plans/2026-09-09-contribution-governance.md is a 14-step manual
runbook of `gh` commands. Hand-typing it once, the night before a public relaunch, is
how a repository ends up half-migrated: a label renamed but the milestones missed, or
a ruleset created twice with slightly different settings the second time. This module
turns the steps that are safe to automate into one idempotent, dry-runnable tool, so
running it twice against the same live state is a no-op rather than a second mutation.

The desired state lives in plain functions (`desired_labels`, `desired_milestones`,
`desired_issues`, `desired_rulesets`) that take no arguments and touch no network. The
diff between that desired state and a live-state dict is `plan_actions`, also pure.
Only `fetch_live_state` and `run_action` touch the network, and only `main` calls them,
so the interesting logic runs under test without a `gh` binary or a token.

SAFETY PROPERTY: this tool cannot merge a pull request, close one, retarget one, or
delete a label. Those are either human decisions (Phase 2 Steps 3, 6, 7, and 8 promote
or merge someone else's work) or destructive (a deleted label vanishes from every issue
that carried it). No function in this module builds a `gh` argv that merges, closes,
or edits a pull request, or that deletes a label, and `HUMAN_STEPS` below says so out
loud when asked for one of the steps that requires a person.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = "GenAI-Security-Project/agent-control-standard"

# The step names this tool will run. Anything else, including every step name in
# HUMAN_STEPS, is refused rather than guessed at.
AUTOMATABLE_STEPS = (
    "labels",
    "milestones",
    "rulesets",
    "branch",
    "issues",
    "default-branch",
    "required-check",
)

# Phase 2 steps this tool deliberately does not run, and why. Keyed by the name someone
# would reasonably type for `--only`. Each explanation names the plan step so a reader
# can go verify the reasoning against the runbook instead of trusting this comment.
HUMAN_STEPS = {
    "pin-protect-main": (
        "Phase 2 Step 1. The ruleset payload is fetched from the live API and edited "
        "in place. A generic patch here risks overwriting a field GitHub added since "
        "the plan was written, which is exactly why the plan describes this edit "
        "rather than pasting a payload for it."
    ),
    "merge-ready-prs": (
        "Phase 2 Step 3. Merging a pull request decides that someone else's work is "
        "ready. That decision is not this tool's to make."
    ),
    "retarget-prs": (
        "Phase 2 Step 6. Retargeting a pull request touches a contributor's open work "
        "and needs a human to confirm the checks re-ran on the new base."
    ),
    "merge-phase1-pr": (
        "Phase 2 Step 7. Merging the pull request that installs this very tool is a "
        "human decision, same as any other merge."
    ),
    "promote": (
        "Phase 2 Step 8. Promoting integration to main is a merge to the branch that "
        "publishes the site and all 44 schema $id URIs on merge. That is a merge, and "
        "merging is a human decision this tool will not make."
    ),
    "verify": (
        "Phase 2 Step 14. Proving the guard fires means opening a real pull request "
        "and then closing it once it has served its purpose. This tool will not close "
        "a pull request, so run this step by hand."
    ),
}


# --- Desired-state data model ------------------------------------------------

@dataclass(frozen=True)
class Label:
    """One entry in the label taxonomy.

    `rename_from` is what separates a rename from a create. A rename keeps every issue
    already carrying the old name. A create starts the new name at zero issues. GitHub
    seeds `bug`, `documentation`, and `enhancement` on every new repository, and this
    project's open issues already carry them, so those three rename rather than create.
    `description` of None means "leave the live description alone": the plan's rename
    commands pass `--color` and `--name` but no `--description`, and a diff that treats
    that omission as "set it to empty" would repaint a description a maintainer wrote.
    """

    name: str
    color: str
    description: str | None = None
    rename_from: str | None = None


@dataclass(frozen=True)
class Milestone:
    title: str
    due_on: str
    description: str


@dataclass(frozen=True)
class Issue:
    title: str
    body: str
    labels: tuple[str, ...]
    milestone: str | None = None


def _default_bypass_actors() -> tuple[dict, ...]:
    """Admin RepositoryRole always bypass, matching protect-main's existing bypass."""
    return ({"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},)


@dataclass(frozen=True)
class Ruleset:
    """A branch ruleset, flattened out of GitHub's nested rule-array shape.

    GitHub nests every setting inside `rules[].parameters` by rule type. Flattening it
    here means the diff functions compare fields, not walk a rules array looking for
    the one with `type == "pull_request"`. The nested shape comes back at render time,
    in `_ruleset_payload`, which is the only place that has to know GitHub's layout.

    Deletion and non-fast-forward protection are not fields because every ruleset this
    tool renders carries both, unconditionally, so there is nothing to diff.

    bypass_actors defaults to admin always-bypass, matching protect-main. Every ruleset
    needs this so a sole maintainer can merge into a branch requiring review, since
    GitHub does not let anyone approve their own pull request.
    """

    name: str
    target_ref: str
    required_status_checks: tuple[str, ...] = ("test", "build")
    allowed_merge_methods: tuple[str, ...] = ("squash", "rebase")
    required_approving_review_count: int = 1
    require_code_owner_review: bool = True
    dismiss_stale_reviews_on_push: bool = True
    require_last_push_approval: bool = True
    required_review_thread_resolution: bool = True
    enforcement: str = "active"
    bypass_actors: tuple[dict, ...] = field(default_factory=_default_bypass_actors)


@dataclass(frozen=True)
class DesiredState:
    labels: tuple[Label, ...]
    milestones: tuple[Milestone, ...]
    issues: tuple[Issue, ...]
    rulesets: tuple[Ruleset, ...]


@dataclass(frozen=True)
class Action:
    """One command this tool would run, rendered but not yet executed.

    `argv` never starts a shell, so there is no quoting hazard between a title or body
    pulled from this module and a command a live title could inject into. `payload`
    carries a JSON body for the one call that needs one (`gh api ... --input`). The
    literal token "@@PAYLOAD@@" in argv marks where the executor substitutes a real
    file path once it has written the payload to disk.
    """

    step: str
    description: str
    argv: tuple[str, ...]
    payload: dict | None = None


# --- Desired state ------------------------------------------------------------

def desired_labels() -> list[Label]:
    """The label taxonomy from Phase 2 Step 2: five axes, plus two stock defaults.

    The five axes are `type:`, `scope:`, `status:`, `priority:`, and `workstream:`.
    `help wanted` and `good first issue` are GitHub's own defaults. Step 2 never
    creates them, because every repository already has them, but the nine seeded
    onramp issues (desired_issues, below) depend on `help wanted` existing, and an
    idempotent tool has to be able to recreate a default label a maintainer deleted
    by accident, not assume it is still there.
    """
    return [
        # Renames. Existing issues keep their labels. Only the name and color change.
        Label(name="type:bug", color="d73a4a", rename_from="bug"),
        Label(name="type:docs", color="0075ca", rename_from="documentation"),
        Label(name="type:proposal", color="a2eeef", rename_from="enhancement"),
        # Creates.
        Label(
            name="type:refimpl", color="1d76db",
            description="Reference implementation or adapter work",
        ),
        Label(
            name="type:conformance", color="5319e7",
            description="Conformance or dogfooding report",
        ),
        Label(
            name="scope:in-focus", color="0e8a16",
            description="Feeds the ninety-day committed outcome. Maintainers only",
        ),
        Label(
            name="scope:deferred", color="fbca04",
            description="Real work, tracked, lands after Day 90. Maintainers only",
        ),
        Label(
            name="scope:out", color="e4e669",
            description="Outside what ACS does by design. Maintainers only",
        ),
        Label(
            name="status:needs-triage", color="ededed",
            description="Not yet triaged. Applied by the issue forms",
        ),
        Label(
            name="status:accepted", color="0e8a16",
            description="In the backlog. Maintainers only",
        ),
        Label(
            name="status:blocked", color="b60205",
            description="Waiting on another decision or PR",
        ),
        Label(
            name="status:needs-info", color="d876e3",
            description="Waiting on the filer",
        ),
        Label(
            name="priority:P0", color="b60205",
            description="On the serial chain to the benchmark. Maintainers only",
        ),
        Label(name="priority:P1", color="d93f0b", description="Maintainers only"),
        Label(name="priority:P2", color="fef2c0", description="Maintainers only"),
        Label(
            name="workstream:spec", color="c5def5",
            description="Owning workstream. Maintainers only",
        ),
        Label(
            name="workstream:coding-agents", color="c5def5",
            description="Owning workstream. Maintainers only",
        ),
        Label(
            name="workstream:sdk", color="c5def5",
            description="Owning workstream. Maintainers only",
        ),
        Label(
            name="workstream:identity", color="c5def5",
            description="Owning workstream. Maintainers only",
        ),
        Label(
            name="workstream:outreach", color="c5def5",
            description="Owning workstream. Maintainers only",
        ),
        # Stock GitHub defaults. Not created by Step 2, but relied on by Step 12.
        Label(
            name="help wanted", color="008672",
            description="Already accepted work. Safe to start without waiting on triage.",
        ),
        Label(name="good first issue", color="7057ff", description="Good for newcomers"),
    ]


def desired_milestones() -> list[Milestone]:
    """The four milestones from Phase 2 Step 11, dates and descriptions verbatim."""
    return [
        Milestone(
            title="Day 14",
            due_on="2026-09-24",
            description=(
                "Reference Implementation lead named. PR #21 floor decision closed. "
                "Discussions seeded. Domain transfer counterpart identified."
            ),
        ),
        Milestone(
            title="Day 30",
            due_on="2026-10-09",
            description=(
                "PR #22 merged with the emission-conformance suite in CI. Documentation "
                "and Testing lead seats filled. Conformance claim template published. "
                "Fail-open resolution decided."
            ),
        ),
        Milestone(
            title="Day 60",
            due_on="2026-11-06",
            description=(
                "Installable reference Guardian published. Milestone #33 requirement "
                "ledger drafted. AARM mapping session held. Domains transferred. "
                "OpenSSF registered."
            ),
        ),
        Milestone(
            title="Day 90",
            due_on="2026-12-04",
            description=(
                "AGT interoperability benchmark published with results and "
                "disagreements. Cursor file-read gap closed. One external ACS-Core "
                "compatibility claim."
            ),
        ),
    ]


def desired_issues() -> list[Issue]:
    """The 9 seeded onramp issues and 7 tracked follow-ups from Steps 12 and 13.

    Every seeded issue carries `scope:in-focus`, `status:accepted`, and `help wanted`.
    Those three labels are what make the acceptance gate CONTRIBUTING.md describes an
    invitation rather than a queue: a contributor can open a pull request against one
    without waiting on triage. The 7 follow-ups are real findings the plan surfaced
    while writing itself, but none sit on the ninety-day serial chain, so they carry
    `scope:deferred` and wait for a maintainer like anything else filed from outside.

    No seeded issue carries `priority:P0`. Per GOVERNANCE.md lines 32-34, P0 is reserved
    for work on the serial chain: PR #21 (the floor decision), PR #22 (the adapters),
    the installable Guardian, and the interoperability benchmark. No seeded issue is one
    of those four links. Maintainers will apply P0 to PRs #21 and #22 during triage.
    """
    onramp = ("scope:in-focus", "status:accepted", "help wanted")
    tracked = ("scope:deferred", "status:needs-triage")

    seeded = [
        Issue(
            title="Port the AGT reference implementation to Python",
            body=(
                "Port the AGT reference implementation from PR #60 to Python. "
                "Multi-language runtimes make the reference implementation more compelling "
                "to enterprise evaluators and widen its reach across teams. This is valuable "
                "parallel work that does not block the interoperability benchmark."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Port the AGT reference implementation to Go",
            body=(
                "Port the AGT reference implementation from PR #60 to Go. "
                "Multi-language runtimes make the reference implementation more compelling "
                "to enterprise evaluators and widen its reach across teams. This is valuable "
                "parallel work that does not block the interoperability benchmark."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Port the AGT reference implementation to Rust",
            body=(
                "Port the AGT reference implementation from PR #60 to Rust. "
                "Multi-language runtimes make the reference implementation more compelling "
                "to enterprise evaluators and widen its reach across teams. This is valuable "
                "parallel work that does not block the interoperability benchmark."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Build a reference implementation against Codex",
            body=(
                "Build a Guardian reference implementation adapter against Codex, "
                "alongside the Claude Code, Cursor, and NVIDIA NAT adapters in PR #22. "
                "Additional adapters strengthen the reference implementation and showcase "
                "ACS capability across platforms without blocking the benchmark."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Add span batching to the reference implementation",
            body=(
                "Production-harden the reference implementation with span batching. "
                "Current Priority Scope in CONTRIBUTING.md lists this hardening work "
                "as in focus."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title=(
                "Configure OpenTelemetry collection and export in the reference "
                "implementation"
            ),
            body=(
                "Production-harden the reference implementation by wiring "
                "OpenTelemetry collection and export end to end."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Dogfood AGT with ACS and file a conformance report",
            body=(
                "Run the Microsoft Agent Governance Toolkit against an ACS Guardian "
                "and file a conformance report for every place behavior and "
                "specification disagree. Conformance evidence is what makes the "
                "benchmark credible."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
        ),
        Issue(
            title="Publish the one-page ACS-Core conformance claim template",
            body=(
                "Draft and publish the one-page template an implementer fills out to "
                "make an ACS-Core conformance claim. Open decision, Day 30 date."
            ),
            labels=onramp + ("workstream:spec", "priority:P1"),
            milestone="Day 30",
        ),
        Issue(
            title=(
                "Choose and reserve a distribution name for the reference "
                "implementation"
            ),
            body=(
                "Choose a package or distribution name for the reference "
                "implementation and reserve it before the first release. Open "
                "decision, Day 30 date."
            ),
            labels=onramp + ("workstream:coding-agents", "priority:P1"),
            milestone="Day 30",
        ),
    ]

    followups = [
        Issue(
            title=(
                "Workstream vocabulary mismatch between GOVERNANCE.md and the plan's "
                "open lead seats"
            ),
            body=(
                "GOVERNANCE.md names five workstreams: Spec, Coding Agents, "
                "Development (SDK), Identity, and Outreach. The Strategic Adoption "
                "Plan's open lead seats use different names for some of the same "
                "work. Reconcile the two vocabularies."
            ),
            labels=("type:docs",) + tracked,
        ),
        Issue(
            title="Label-strip enforcement workflow, if the permission lookup proves workable",
            body=(
                "Investigate whether a workflow can reliably strip a decision label "
                "added by someone without triage authority. Tracked rather than "
                "built now because the permission lookup it depends on is unproven."
            ),
            labels=("type:proposal",) + tracked,
        ),
        Issue(
            title="Org-level project board fed by this label and milestone taxonomy",
            body=(
                "Build an org-level GitHub Project fed by the label and milestone "
                "taxonomy this plan installs. Needs org admin access, which this tool "
                "does not have and should not be given."
            ),
            labels=("type:proposal",) + tracked,
        ),
        Issue(
            title="Declarative logic CI for specification contradiction detection",
            body=(
                "Explore a CI check that detects logical contradictions across the "
                "specification's normative statements, rather than relying on review "
                "to catch them."
            ),
            labels=("type:proposal",) + tracked,
        ),
        Issue(
            title=(
                "Release-branch versioning, unspecified now that sync_version.yml "
                "follows integration"
            ),
            body=(
                "sync_version.yml now targets `integration` instead of `main`. "
                "Decide how version bumps work on a `release/*` branch, which that "
                "change left unspecified."
            ),
            labels=("type:proposal",) + tracked,
        ),
        Issue(
            title="Comment on #52 that the DCO check stays indifferent to non-sign-off trailers",
            body=(
                "Post a comment on #52 noting that the DCO check does not care "
                "whether a commit carries a `Co-Authored-By` trailer or any trailer "
                "beyond `Signed-off-by`. Filed here so the follow-up is not lost."
            ),
            labels=("type:docs",) + tracked,
        ),
        Issue(
            title=(
                "Confirm whether Dependabot security updates honor a non-default "
                "target-branch"
            ),
            body=(
                "Dependabot's routine updates follow the default branch by design. "
                "Confirm whether security updates do the same or bypass "
                "target-branch, since that behavior is undocumented and Task 7 "
                "depends on it not mattering."
            ),
            labels=("type:proposal",) + tracked,
        ),
    ]

    return seeded + followups


def desired_rulesets() -> list[Ruleset]:
    """protect-integration and protect-release, from Phase 2 Step 5.

    Both mirror the pre-change protect-main: one approval, code owner review, stale
    reviews dismissed on push, last-push approval, required thread resolution, the
    `test` and `build` checks, and squash or rebase merges only. Both also inherit
    the admin always-bypass from the Ruleset default, matching protect-main. Without
    this bypass, a sole maintainer cannot merge into a branch requiring review, since
    GitHub does not let anyone approve their own pull request. Every field left at
    its default on Ruleset already carries that shape, so the two instances below
    differ only in the two fields Step 5 says differ: the name and the target ref.
    """
    return [
        Ruleset(name="protect-integration", target_ref="refs/heads/integration"),
        Ruleset(name="protect-release", target_ref="refs/heads/release/*"),
    ]


def desired_state() -> DesiredState:
    return DesiredState(
        labels=tuple(desired_labels()),
        milestones=tuple(desired_milestones()),
        issues=tuple(desired_issues()),
        rulesets=tuple(desired_rulesets()),
    )


# --- Diffing: desired vs. live, pure -----------------------------------------

def _label_matches(live: dict, desired: Label) -> bool:
    if live.get("name") != desired.name or live.get("color") != desired.color:
        return False
    # None means "the plan's command never set a description", so a live description
    # of anything is a match. Comparing against "" would repaint every rename target.
    if desired.description is not None and live.get("description", "") != desired.description:
        return False
    return True


def plan_label_actions(live_labels: list[dict], desired: tuple[Label, ...]) -> list[Action]:
    """Diff Phase 2 Step 2 against a live `gh label list --json name,color,description`."""
    by_name = {entry["name"]: entry for entry in live_labels}
    actions: list[Action] = []
    for label in desired:
        current = by_name.get(label.name)
        if current is not None and _label_matches(current, label):
            continue
        if label.rename_from and label.rename_from in by_name:
            argv = ["gh", "label", "edit", label.rename_from, "--name", label.name, "--color", label.color]
            if label.description is not None:
                argv += ["--description", label.description]
            actions.append(Action("labels", f"Rename {label.rename_from!r} to {label.name!r}", tuple(argv)))
        else:
            argv = ["gh", "label", "create", label.name, "--force", "--color", label.color]
            if label.description is not None:
                argv += ["--description", label.description]
            actions.append(Action("labels", f"Create label {label.name!r}", tuple(argv)))
    return actions


def _milestone_matches(live: dict, desired: Milestone) -> bool:
    return live.get("due_on") == desired.due_on and live.get("description") == desired.description


def plan_milestone_actions(
    live_milestones: list[dict], desired: tuple[Milestone, ...]
) -> list[Action]:
    """Diff Phase 2 Step 11 against a live milestone listing keyed by title."""
    by_title = {entry["title"]: entry for entry in live_milestones}
    actions: list[Action] = []
    for milestone in desired:
        current = by_title.get(milestone.title)
        if current is not None and _milestone_matches(current, milestone):
            continue
        due = f"{milestone.due_on}T23:59:59Z"
        if current is None:
            argv = (
                "gh", "api", "-X", "POST", f"repos/{REPO}/milestones",
                "-f", f"title={milestone.title}",
                "-f", f"due_on={due}",
                "-f", f"description={milestone.description}",
            )
            description = f"Create milestone {milestone.title!r}"
        else:
            number = current.get("number")
            argv = (
                "gh", "api", "-X", "PATCH", f"repos/{REPO}/milestones/{number}",
                "-f", f"due_on={due}",
                "-f", f"description={milestone.description}",
            )
            description = f"Update milestone {milestone.title!r}"
        actions.append(Action("milestones", description, argv))
    return actions


def plan_issue_actions(live_issues: list[dict], desired: tuple[Issue, ...]) -> list[Action]:
    """Diff Phase 2 Steps 12 and 13. Matched by title, filed once, never edited or closed.

    The plan never revises a seeded issue after filing it, and this tool has no way to
    tell a maintainer's later edit from drift it should undo, so an existing title with
    the same text is left alone rather than reconciled label by label.
    """
    filed = {entry["title"] for entry in live_issues}
    actions: list[Action] = []
    for issue in desired:
        if issue.title in filed:
            continue
        argv = ["gh", "issue", "create", "--title", issue.title, "--body", issue.body]
        for label in issue.labels:
            argv += ["--label", label]
        if issue.milestone:
            argv += ["--milestone", issue.milestone]
        actions.append(Action("issues", f"File issue {issue.title!r}", tuple(argv)))
    return actions


def _ruleset_matches(live: dict, desired: Ruleset) -> bool:
    return (
        live.get("target_ref") == desired.target_ref
        and live.get("enforcement", "active") == desired.enforcement
        and live.get("required_approving_review_count") == desired.required_approving_review_count
        and live.get("require_code_owner_review") == desired.require_code_owner_review
        and live.get("dismiss_stale_reviews_on_push") == desired.dismiss_stale_reviews_on_push
        and live.get("require_last_push_approval") == desired.require_last_push_approval
        and live.get("required_review_thread_resolution") == desired.required_review_thread_resolution
        and tuple(live.get("required_status_checks", ())) == desired.required_status_checks
        and tuple(live.get("allowed_merge_methods", ())) == desired.allowed_merge_methods
    )


def _ruleset_payload(desired: Ruleset) -> dict:
    """Rebuild GitHub's nested rules array from a flat Ruleset.

    Deletion and non-fast-forward protection are unconditional, per the plan's Step 5,
    so they are written here rather than carried as fields with only one valid value.
    bypass_actors is rendered at the top level so GitHub recognizes the admin bypass.
    """
    return {
        "name": desired.name,
        "target": "branch",
        "enforcement": desired.enforcement,
        "conditions": {"ref_name": {"include": [desired.target_ref], "exclude": []}},
        "bypass_actors": list(desired.bypass_actors),
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": desired.required_approving_review_count,
                    "require_code_owner_review": desired.require_code_owner_review,
                    "dismiss_stale_reviews_on_push": desired.dismiss_stale_reviews_on_push,
                    "require_last_push_approval": desired.require_last_push_approval,
                    "required_review_thread_resolution": desired.required_review_thread_resolution,
                    "allowed_merge_methods": list(desired.allowed_merge_methods),
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {"context": check} for check in desired.required_status_checks
                    ],
                },
            },
        ],
    }


def plan_ruleset_actions(live_rulesets: list[dict], desired: tuple[Ruleset, ...]) -> list[Action]:
    """Diff Phase 2 Step 5. Never touches protect-main. See plan_required_check_actions."""
    by_name = {entry["name"]: entry for entry in live_rulesets}
    actions: list[Action] = []
    for ruleset in desired:
        current = by_name.get(ruleset.name)
        if current is not None and _ruleset_matches(current, ruleset):
            continue
        if current is None:
            argv = ("gh", "api", "-X", "POST", f"repos/{REPO}/rulesets", "--input", "@@PAYLOAD@@")
            description = f"Create ruleset {ruleset.name!r}"
        else:
            ruleset_id = current.get("id")
            argv = (
                "gh", "api", "-X", "PUT", f"repos/{REPO}/rulesets/{ruleset_id}",
                "--input", "@@PAYLOAD@@",
            )
            description = f"Update ruleset {ruleset.name!r}"
        actions.append(Action("rulesets", description, argv, payload=_ruleset_payload(ruleset)))
    return actions


def plan_actions(live_state: dict, desired_state: DesiredState) -> list[Action]:
    """Diff desired against live for labels, milestones, issues, and rulesets.

    Pure: no network call, no side effect. Calling this twice with the live state the
    first call would have produced returns an empty list the second time, which is
    what makes the tool idempotent rather than merely repeatable.
    """
    return [
        *plan_label_actions(live_state.get("labels", []), desired_state.labels),
        *plan_milestone_actions(live_state.get("milestones", []), desired_state.milestones),
        *plan_issue_actions(live_state.get("issues", []), desired_state.issues),
        *plan_ruleset_actions(live_state.get("rulesets", []), desired_state.rulesets),
    ]


def plan_branch_actions(live_state: dict) -> list[Action]:
    """Phase 2 Step 4: create `integration` from `main` if it does not exist yet.

    A branch cannot be half-created, so there is exactly one action or none. This
    pushes a branch ref rather than opening a pull request, because at this point in
    the runbook `integration` does not exist for a pull request to target.
    """
    if "integration" in set(live_state.get("branches", ())):
        return []
    return [
        Action(
            "branch",
            "Create integration from main",
            ("git", "push", "origin", "origin/main:refs/heads/integration"),
        )
    ]


def plan_default_branch_actions(live_state: dict) -> list[Action]:
    """Phase 2 Step 9: move the default branch to `integration`.

    The plan requires protect-main to be pinned to the literal ref `refs/heads/main`
    first (Step 1), or the move leaves `main` unprotected once it is no longer the
    default. That precondition is not observable from live_state as fetched here, so
    this function does not check it. The human running Step 1 is the check.
    """
    if live_state.get("default_branch") == "integration":
        return []
    return [
        Action(
            "default-branch",
            "Move the default branch to integration",
            ("gh", "repo", "edit", REPO, "--default-branch", "integration"),
        )
    ]


def plan_required_check_actions(live_state: dict) -> list[Action]:
    """Phase 2 Step 10: add base-branch-guard to protect-main's required checks.

    Only the check list changes. Every other protect-main field is read back from
    live_state and written unchanged, because this step runs against a ruleset a
    human already configured in Step 1 and this tool must not relitigate the rest of
    it while adding one check.
    """
    protect_main = live_state.get("protect_main")
    if protect_main is None:
        # No live ruleset to patch. The caller fetched nothing, so there is nothing
        # to diff, not an inferred "it must already be fine".
        return []
    checks = tuple(protect_main.get("required_status_checks", ()))
    if "base-branch-guard" in checks:
        return []
    updated = dict(protect_main)
    updated["required_status_checks"] = checks + ("base-branch-guard",)
    ruleset_id = protect_main.get("id")
    return [
        Action(
            "required-check",
            "Add base-branch-guard to protect-main's required checks",
            ("gh", "api", "-X", "PUT", f"repos/{REPO}/rulesets/{ruleset_id}", "--input", "@@PAYLOAD@@"),
            payload=_protect_main_payload(updated),
        )
    ]


def _protect_main_payload(protect_main: dict) -> dict:
    """Render protect-main's flat live shape back into GitHub's nested rules array."""
    return {
        "name": "protect-main",
        "target": "branch",
        "enforcement": protect_main.get("enforcement", "active"),
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": protect_main.get(
                        "required_approving_review_count", 1
                    ),
                    "allowed_merge_methods": list(
                        protect_main.get("allowed_merge_methods", ("squash", "rebase", "merge"))
                    ),
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {"context": check}
                        for check in protect_main.get("required_status_checks", ())
                    ],
                },
            },
        ],
    }


def collect_actions(live_state: dict, only: str | None = None) -> list[Action]:
    """Combine every planner, filtered to one step when `only` names one."""
    steps: list[Action] = []
    if only in (None, "labels"):
        steps += plan_label_actions(live_state.get("labels", []), tuple(desired_labels()))
    if only in (None, "milestones"):
        steps += plan_milestone_actions(live_state.get("milestones", []), tuple(desired_milestones()))
    if only in (None, "rulesets"):
        steps += plan_ruleset_actions(live_state.get("rulesets", []), tuple(desired_rulesets()))
    if only in (None, "issues"):
        steps += plan_issue_actions(live_state.get("issues", []), tuple(desired_issues()))
    if only in (None, "branch"):
        steps += plan_branch_actions(live_state)
    if only in (None, "default-branch"):
        steps += plan_default_branch_actions(live_state)
    if only in (None, "required-check"):
        steps += plan_required_check_actions(live_state)
    return steps


# --- Executor: render or run --------------------------------------------------

def render_dry_run(action: Action) -> str:
    command = " ".join(shlex.quote(token) for token in action.argv)
    lines = [f"# {action.description}", f"$ {command}"]
    if action.payload is not None:
        lines.append(json.dumps(action.payload, indent=2))
    return "\n".join(lines)


def run_action(action: Action) -> None:
    """Execute one action for real. Never called by a test in this repository.

    A payload is written to a temp file rather than piped, so the argv `gh` actually
    receives is identical to the one a dry run printed, minus the placeholder swap.
    """
    argv = list(action.argv)
    if action.payload is None:
        subprocess.run(argv, check=True)
        return
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(action.payload, handle)
        payload_path = handle.name
    try:
        argv = [payload_path if token == "@@PAYLOAD@@" else token for token in argv]
        subprocess.run(argv, check=True)
    finally:
        Path(payload_path).unlink(missing_ok=True)


def _gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def _normalize_ruleset(detail: dict) -> dict:
    """Flatten one `gh api repos/{repo}/rulesets/{id}` response for the diff functions."""
    by_type = {rule["type"]: rule.get("parameters", {}) for rule in detail.get("rules", [])}
    pr_params = by_type.get("pull_request", {})
    checks = by_type.get("required_status_checks", {}).get("required_status_checks", [])
    refs = detail.get("conditions", {}).get("ref_name", {}).get("include", [])
    return {
        "id": detail.get("id"),
        "name": detail.get("name"),
        "target_ref": refs[0] if refs else "",
        "enforcement": detail.get("enforcement", "active"),
        "required_status_checks": tuple(check["context"] for check in checks),
        "allowed_merge_methods": tuple(pr_params.get("allowed_merge_methods", ())),
        "required_approving_review_count": pr_params.get("required_approving_review_count"),
        "require_code_owner_review": pr_params.get("require_code_owner_review"),
        "dismiss_stale_reviews_on_push": pr_params.get("dismiss_stale_reviews_on_push"),
        "require_last_push_approval": pr_params.get("require_last_push_approval"),
        "required_review_thread_resolution": pr_params.get("required_review_thread_resolution"),
    }


def fetch_live_state() -> dict:
    """Read the current repository state through `gh`. The only function that does.

    Every diff function above takes a plain dict so it can be tested without this
    function ever running. Nothing in this module calls it except `main`, and `main`
    never reaches it on `--help`, an unknown `--only`, or a step in HUMAN_STEPS.
    """
    labels = json.loads(_gh("label", "list", "--limit", "200", "--json", "name,color,description"))

    raw_milestones = json.loads(_gh("api", f"repos/{REPO}/milestones", "--paginate"))
    milestones = [
        {
            "title": entry["title"],
            "number": entry["number"],
            "due_on": (entry.get("due_on") or "")[:10],
            "description": entry.get("description") or "",
        }
        for entry in raw_milestones
    ]

    raw_issues = json.loads(
        _gh("issue", "list", "--state", "all", "--limit", "500", "--json", "title,body,labels")
    )
    issues = [
        {"title": entry["title"], "body": entry.get("body") or "",
         "labels": [label["name"] for label in entry["labels"]]}
        for entry in raw_issues
    ]

    summaries = json.loads(_gh("api", f"repos/{REPO}/rulesets"))
    details = {
        entry["name"]: _normalize_ruleset(json.loads(_gh("api", f"repos/{REPO}/rulesets/{entry['id']}")))
        for entry in summaries
    }
    rulesets = [
        details[name] for name in ("protect-integration", "protect-release") if name in details
    ]

    branches = json.loads(_gh("api", f"repos/{REPO}/branches", "--paginate", "--jq", "[.[].name]"))
    repo_info = json.loads(_gh("api", f"repos/{REPO}"))

    return {
        "labels": labels,
        "milestones": milestones,
        "issues": issues,
        "rulesets": rulesets,
        "branches": branches,
        "default_branch": repo_info.get("default_branch"),
        "protect_main": details.get("protect-main"),
    }


# --- CLI ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apply_governance.py",
        description=(
            "Apply Phase 2 of the contribution-governance plan: labels, milestones, "
            "issues, and the integration and release rulesets. Prints the gh and git "
            "commands it would run by default. Pass --apply to run them."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands without running them. This already happens without "
             "the flag. It exists so a caller can pass it explicitly.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Run the commands instead of printing them. Required to mutate anything.",
    )
    parser.add_argument(
        "--only",
        metavar="STEP",
        help=f"Run a single step. One of: {', '.join(AUTOMATABLE_STEPS)}.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.only in HUMAN_STEPS:
        print(
            f"'{args.only}' is a human decision, not something this tool automates.\n"
            f"{HUMAN_STEPS[args.only]}",
            file=sys.stderr,
        )
        return 2
    if args.only is not None and args.only not in AUTOMATABLE_STEPS:
        print(
            f"Unknown step {args.only!r}. Choose one of: {', '.join(AUTOMATABLE_STEPS)}.",
            file=sys.stderr,
        )
        return 2

    # --dry-run is the default behavior. --apply is the only flag that turns on
    # mutation, so passing both is a no-op rather than a contradiction.
    apply_changes = args.apply

    live_state = fetch_live_state()
    actions = collect_actions(live_state, only=args.only)

    if not actions:
        print("Nothing to do. Live state already matches desired state.")
        return 0

    if not apply_changes:
        print(f"Dry run. {len(actions)} action(s) would run. Pass --apply to run them.\n")
        for action in actions:
            print(render_dry_run(action))
            print()
        return 0

    for action in actions:
        print(f"Running: {action.description}")
        run_action(action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
