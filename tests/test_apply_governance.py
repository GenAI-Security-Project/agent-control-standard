"""Tests for the Phase 2 governance executor.

Everything here is a pure-function test. None of it shells out to `gh`, opens a
socket, or touches the live OWASP repository: the whole point of structuring
apply_governance.py as desired-state functions plus a diff is that the diff is
testable without either.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

# Matches the import style the other tools tests use, in test_publish_schemas.py:12.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from apply_governance import (  # noqa: E402
    AUTOMATABLE_STEPS,
    HUMAN_STEPS,
    Ruleset,
    build_parser,
    collect_actions,
    desired_issues,
    desired_labels,
    desired_milestones,
    desired_rulesets,
    desired_state,
    main,
    plan_actions,
    plan_branch_actions,
    plan_default_branch_actions,
    plan_required_check_actions,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ISSUE_TEMPLATE_DIR = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"

FORBIDDEN_ARGV_SUBSTRINGS = ("pr merge", "pr close", "pr edit", "label delete")

FIVE_AXES = ("type:", "scope:", "status:", "priority:", "workstream:")
STOCK_DEFAULTS = {"help wanted", "good first issue"}


# --- Label taxonomy -----------------------------------------------------------

def test_label_taxonomy_is_exactly_the_five_axes_plus_stock_defaults():
    for label in desired_labels():
        assert label.name.startswith(FIVE_AXES) or label.name in STOCK_DEFAULTS, (
            f"{label.name!r} is outside the five axes and the two stock defaults"
        )


def test_renames_are_distinct_from_creates():
    renames = {label.rename_from: label for label in desired_labels() if label.rename_from}
    assert set(renames) == {"bug", "documentation", "enhancement"}
    assert renames["bug"].name == "type:bug" and renames["bug"].color == "d73a4a"
    assert renames["documentation"].name == "type:docs" and renames["documentation"].color == "0075ca"
    assert renames["enhancement"].name == "type:proposal" and renames["enhancement"].color == "a2eeef"

    created_names = {label.name for label in desired_labels() if not label.rename_from}
    # A create must never collide with a name a rename target already owns.
    assert created_names.isdisjoint(renames[k].name for k in renames)


def _labels_declared_in_issue_forms() -> list[str]:
    """Parse every `labels:` line out of the real issue form files.

    A form referencing a label the tool never creates fails to apply it silently, per
    the plan's Task 3 Interfaces note, so this reads the actual files rather than a
    fixture that could drift from them.
    """
    pattern = re.compile(r"^labels:\s*(\[.*\])\s*$")
    declared: list[str] = []
    for path in sorted(ISSUE_TEMPLATE_DIR.glob("*.yml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = pattern.match(line.strip())
            if match:
                declared.extend(json.loads(match.group(1)))
    return declared


def test_issue_form_labels_are_all_in_the_desired_taxonomy():
    declared = _labels_declared_in_issue_forms()
    assert declared, "expected at least one labels: line under .github/ISSUE_TEMPLATE"
    taxonomy = {label.name for label in desired_labels()}
    for name in declared:
        assert name in taxonomy, f"{name!r} is stamped by a form but never created by the tool"


def test_issue_forms_never_stamp_a_decision_label():
    """No form may apply scope:, priority:, workstream:, or status:accepted.

    That prohibition, not code, is the whole enforcement mechanism for maintainer-only
    decision labels, so it is worth asserting on the forms directly and not just on
    the taxonomy the tool creates.
    """
    decision_prefixes = ("scope:", "priority:", "workstream:")
    for name in _labels_declared_in_issue_forms():
        assert not name.startswith(decision_prefixes), f"a form stamps decision label {name!r}"
        assert name != "status:accepted", "a form stamps status:accepted"


# --- Milestones -----------------------------------------------------------------

def test_milestone_due_dates_are_exact():
    due_dates = {milestone.title: milestone.due_on for milestone in desired_milestones()}
    assert due_dates == {
        "Day 14": "2026-09-24",
        "Day 30": "2026-10-09",
        "Day 60": "2026-11-06",
        "Day 90": "2026-12-04",
    }


# --- Issues -----------------------------------------------------------------------

def test_desired_issues_returns_sixteen():
    assert len(desired_issues()) == 16


def test_every_seeded_onramp_issue_carries_the_three_onramp_labels():
    """An issue carrying help wanted is one of the 9 seeded onramp issues.

    Checked this way, rather than by slicing the first 9, so the assertion survives
    desired_issues() being reordered: the label combination is the actual contract,
    not the position in the list.
    """
    onramp = [issue for issue in desired_issues() if "help wanted" in issue.labels]
    assert len(onramp) == 9
    for issue in onramp:
        assert "scope:in-focus" in issue.labels
        assert "status:accepted" in issue.labels


def test_tracked_followups_are_the_remaining_seven():
    followups = [issue for issue in desired_issues() if "help wanted" not in issue.labels]
    assert len(followups) == 7
    for issue in followups:
        assert "scope:in-focus" not in issue.labels


def test_issue_labels_are_all_in_the_desired_taxonomy():
    taxonomy = {label.name for label in desired_labels()}
    for issue in desired_issues():
        for name in issue.labels:
            assert name in taxonomy, f"issue {issue.title!r} uses undeclared label {name!r}"


def test_issue_milestones_when_set_name_a_desired_milestone():
    milestone_titles = {milestone.title for milestone in desired_milestones()}
    for issue in desired_issues():
        if issue.milestone is not None:
            assert issue.milestone in milestone_titles


def test_no_seeded_issue_carries_priority_p0():
    """P0 is reserved for the serial chain: the floor decision, adapters, Guardian, and
    benchmark. GOVERNANCE.md lines 32-34 enforce this rule. The only P0 issues are PR
    #21 (the floor decision) and PR #22 (the adapters), which are pull requests rather
    than seeded issues. Runtime ports and other work are valuable but carry P1."""
    p0_issues = []
    for issue in desired_issues():
        if "priority:P0" in issue.labels:
            p0_issues.append(issue.title)
    assert not p0_issues, (
        f"The following issues carry priority:P0 but should not: {p0_issues}. "
        f"GOVERNANCE.md reserves P0 for the serial chain links: the floor decision "
        f"(PR #21), adapters (PR #22), the installable Guardian, and the interoperability "
        f"benchmark. Runtime ports and other work are P1."
    )


def test_all_nine_seeded_issues_carry_scope_status_and_help_wanted():
    """The nine seeded onramp issues must all carry scope:in-focus, status:accepted, and
    help wanted. These three labels signal to contributors that the work is ready to
    start without waiting on triage."""
    required_labels = {"scope:in-focus", "status:accepted", "help wanted"}
    seeded = [issue for issue in desired_issues() if "help wanted" in issue.labels]
    assert len(seeded) == 9, f"expected 9 seeded onramp issues, found {len(seeded)}"
    for issue in seeded:
        issue_labels = set(issue.labels)
        missing = required_labels - issue_labels
        assert not missing, (
            f"issue {issue.title!r} is missing labels {missing}"
        )


# --- Rulesets -----------------------------------------------------------------

def test_desired_rulesets_are_protect_integration_and_protect_release():
    rulesets = {ruleset.name: ruleset for ruleset in desired_rulesets()}
    assert set(rulesets) == {"protect-integration", "protect-release"}
    assert rulesets["protect-integration"].target_ref == "refs/heads/integration"
    assert rulesets["protect-release"].target_ref == "refs/heads/release/*"
    for ruleset in rulesets.values():
        assert ruleset.required_approving_review_count == 1
        assert ruleset.require_code_owner_review is True
        assert ruleset.dismiss_stale_reviews_on_push is True
        assert ruleset.require_last_push_approval is True
        assert ruleset.required_review_thread_resolution is True
        assert ruleset.required_status_checks == ("test", "build")
        assert ruleset.allowed_merge_methods == ("squash", "rebase")


def test_every_ruleset_carries_admin_bypass():
    """Every ruleset must carry a bypass entry for RepositoryRole 5 (admin).

    Without it, a sole maintainer cannot merge into a branch requiring review,
    because GitHub does not let anyone approve their own pull request. When that
    maintainer is the only one awake the night before a public relaunch, a missing
    bypass means the workflow that installs this very tool becomes unmergeable the
    instant the protected branch is created, halting the migration halfway through.
    """
    for ruleset in desired_rulesets():
        assert ruleset.bypass_actors is not None, (
            f"ruleset {ruleset.name!r} has no bypass_actors"
        )
        # Check it has at least one entry for admin role
        admin_bypasses = [
            entry for entry in ruleset.bypass_actors
            if entry.get("actor_id") == 5
            and entry.get("actor_type") == "RepositoryRole"
            and entry.get("bypass_mode") == "always"
        ]
        assert admin_bypasses, (
            f"ruleset {ruleset.name!r} has bypass_actors but no entry for "
            f"RepositoryRole 5 with always mode"
        )


def test_ruleset_payload_includes_bypass_actors_at_top_level():
    """The rendered payload must include bypass_actors at the top level.

    A bypass buried inside rules goes unrecognized and does not grant the expected
    override, leaving the maintainer in the lockout scenario described above.
    """
    from apply_governance import _ruleset_payload

    for ruleset in desired_rulesets():
        payload = _ruleset_payload(ruleset)
        assert "bypass_actors" in payload, (
            f"payload for {ruleset.name!r} has no top-level bypass_actors field"
        )
        assert isinstance(payload["bypass_actors"], list), (
            f"bypass_actors in {ruleset.name!r} payload is not a list"
        )
        # Check that at least one entry is for admin role
        admin_entries = [
            entry for entry in payload["bypass_actors"]
            if entry.get("actor_id") == 5
            and entry.get("actor_type") == "RepositoryRole"
            and entry.get("bypass_mode") == "always"
        ]
        assert admin_entries, (
            f"payload for {ruleset.name!r} has bypass_actors but no admin "
            f"RepositoryRole 5 entry"
        )


def test_required_status_checks_rule_carries_strict_and_enforce_fields():
    """Every ruleset payload must include strict_required_status_checks_policy and
    do_not_enforce_on_create in the required_status_checks rule parameters.

    GitHub's ruleset API returns HTTP 422 with error message naming only the rule
    index (/rules/3) rather than the missing field when these parameters are absent.
    This opaque error is why the discovery overhead of a failing test here is worth
    it: a later breakage will surface immediately, not as a cryptic 422 after
    someone reruns the tool.
    """
    from apply_governance import _ruleset_payload

    for ruleset in desired_rulesets():
        payload = _ruleset_payload(ruleset)
        # Find the required_status_checks rule
        required_checks_rules = [
            rule for rule in payload.get("rules", [])
            if rule.get("type") == "required_status_checks"
        ]
        assert required_checks_rules, (
            f"payload for {ruleset.name!r} has no required_status_checks rule"
        )
        rule = required_checks_rules[0]
        params = rule.get("parameters", {})
        assert "strict_required_status_checks_policy" in params, (
            f"payload for {ruleset.name!r} required_status_checks rule is missing "
            f"strict_required_status_checks_policy"
        )
        assert "do_not_enforce_on_create" in params, (
            f"payload for {ruleset.name!r} required_status_checks rule is missing "
            f"do_not_enforce_on_create"
        )
        assert params["strict_required_status_checks_policy"] is False, (
            f"strict_required_status_checks_policy for {ruleset.name!r} should be False"
        )
        assert params["do_not_enforce_on_create"] is False, (
            f"do_not_enforce_on_create for {ruleset.name!r} should be False"
        )


def test_required_status_checks_parameters_contains_exactly_three_keys():
    """The required_status_checks rule parameters must contain exactly the three
    expected keys: required_status_checks, strict_required_status_checks_policy, and
    do_not_enforce_on_create. A stray key could trigger the same 422 error from the
    other direction."""
    from apply_governance import _ruleset_payload

    expected_keys = {
        "required_status_checks",
        "strict_required_status_checks_policy",
        "do_not_enforce_on_create"
    }
    for ruleset in desired_rulesets():
        payload = _ruleset_payload(ruleset)
        required_checks_rules = [
            rule for rule in payload.get("rules", [])
            if rule.get("type") == "required_status_checks"
        ]
        rule = required_checks_rules[0]
        params = rule.get("parameters", {})
        actual_keys = set(params.keys())
        assert actual_keys == expected_keys, (
            f"payload for {ruleset.name!r} required_status_checks parameters has "
            f"keys {actual_keys} but expected exactly {expected_keys}"
        )


# --- plan_actions: idempotence and completeness ---------------------------------

def _live_matching(desired) -> dict:
    """Build a live-state dict that already satisfies every desired object.

    Used to prove idempotence: feeding this back into plan_actions must return an
    empty list, because there is nothing left for the tool to do.
    """
    return {
        "labels": [
            {
                "name": label.name,
                "color": label.color,
                "description": label.description if label.description is not None else "",
            }
            for label in desired.labels
        ],
        "milestones": [
            {"title": m.title, "due_on": m.due_on, "description": m.description, "number": i}
            for i, m in enumerate(desired.milestones)
        ],
        "issues": [
            {"title": issue.title, "body": issue.body, "labels": list(issue.labels)}
            for issue in desired.issues
        ],
        "rulesets": [asdict(ruleset) for ruleset in desired.rulesets],
    }


def test_plan_actions_is_idempotent_against_matching_live_state():
    desired = desired_state()
    live = _live_matching(desired)
    assert plan_actions(live, desired) == []


def test_plan_actions_against_empty_live_state_returns_one_action_per_desired_object():
    desired = desired_state()
    empty_live = {"labels": [], "milestones": [], "issues": [], "rulesets": []}
    actions = plan_actions(empty_live, desired)
    expected_count = (
        len(desired.labels) + len(desired.milestones) + len(desired.issues) + len(desired.rulesets)
    )
    assert len(actions) == expected_count


def test_plan_actions_against_missing_keys_behaves_like_empty_live_state():
    """live_state.get(..., []) means a caller who fetched nothing gets full actions,
    not a crash."""
    desired = desired_state()
    assert len(plan_actions({}, desired)) == len(plan_actions(
        {"labels": [], "milestones": [], "issues": [], "rulesets": []}, desired
    ))


def test_label_rename_is_detected_even_when_the_old_name_is_still_live():
    """A live label still named `bug` produces a rename action, not a create."""
    desired = desired_state()
    live = _live_matching(desired)
    live["labels"] = [
        entry for entry in live["labels"] if entry["name"] != "type:bug"
    ] + [{"name": "bug", "color": "d73a4a", "description": "Something isn't working"}]
    actions = plan_actions(live, desired)
    label_actions = [a for a in actions if a.step == "labels"]
    assert len(label_actions) == 1
    assert "bug" in label_actions[0].argv
    assert "edit" in label_actions[0].argv
    assert "create" not in label_actions[0].argv


# --- Singleton steps: branch, default-branch, required-check --------------------

def test_branch_action_only_fires_when_integration_is_missing():
    assert plan_branch_actions({"branches": ["main"]}) != []
    assert plan_branch_actions({"branches": ["main", "integration"]}) == []


def test_default_branch_action_only_fires_when_not_already_integration():
    assert plan_default_branch_actions({"default_branch": "main"}) != []
    assert plan_default_branch_actions({"default_branch": "integration"}) == []


def test_required_check_action_only_fires_when_the_check_is_missing():
    without_check = {
        "protect_main": {"id": 1, "required_status_checks": ("test", "build")}
    }
    with_check = {
        "protect_main": {"id": 1, "required_status_checks": ("test", "build", "base-branch-guard")}
    }
    assert plan_required_check_actions(without_check) != []
    assert plan_required_check_actions(with_check) == []
    assert plan_required_check_actions({}) == []


# --- SAFETY: the tool cannot merge, close, retarget a PR, or delete a label -----

def _all_actions_for_safety_scan() -> list:
    """Every action this tool can render, across every planner, for both an empty
    and an already-satisfied live state. This is the "full desired state, not a
    sample" the safety property has to hold over.
    """
    desired = desired_state()
    matching_live = _live_matching(desired)
    matching_live["branches"] = ["main", "integration"]
    matching_live["default_branch"] = "integration"
    matching_live["protect_main"] = {
        "id": 1, "required_status_checks": ("test", "build", "base-branch-guard"),
    }

    empty_live: dict = {"labels": [], "milestones": [], "issues": [], "rulesets": []}
    empty_live["branches"] = []
    empty_live["default_branch"] = "main"
    empty_live["protect_main"] = {"id": 1, "required_status_checks": ("test", "build")}

    actions = []
    for live in (matching_live, empty_live):
        actions += collect_actions(live)
    return actions


def test_no_action_ever_merges_closes_edits_a_pr_or_deletes_a_label():
    actions = _all_actions_for_safety_scan()
    assert actions, "expected at least one action to scan"
    for action in actions:
        rendered = " ".join(action.argv)
        for forbidden in FORBIDDEN_ARGV_SUBSTRINGS:
            assert forbidden not in rendered, (
                f"action {action.description!r} renders forbidden command fragment "
                f"{forbidden!r}: {action.argv}"
            )


def test_the_module_source_never_spells_a_forbidden_gh_subcommand():
    """Belt and braces on top of the behavioral scan: the literal strings never
    appear anywhere in the module, so no code path, reachable or not, can emit them.
    """
    source = (REPO_ROOT / "tools" / "apply_governance.py").read_text(encoding="utf-8")
    for forbidden in FORBIDDEN_ARGV_SUBSTRINGS:
        assert forbidden not in source, f"module source contains {forbidden!r}"


# --- CLI --------------------------------------------------------------------------

def test_dry_run_is_the_default_and_apply_is_a_separate_flag():
    args = build_parser().parse_args([])
    assert args.apply is False
    args = build_parser().parse_args(["--apply"])
    assert args.apply is True


def test_only_accepts_a_step_name():
    args = build_parser().parse_args(["--only", "labels"])
    assert args.only == "labels"


def test_main_refuses_a_human_only_step_without_touching_the_network():
    for step in HUMAN_STEPS:
        status = main(["--only", step])
        assert status != 0


def test_main_refuses_an_unknown_step():
    status = main(["--only", "definitely-not-a-real-step"])
    assert status != 0


def test_automatable_steps_and_human_steps_do_not_overlap():
    assert set(AUTOMATABLE_STEPS).isdisjoint(HUMAN_STEPS)


def test_plan_step_3_6_7_are_represented_among_the_human_steps():
    """The plan calls out Steps 3, 6, and 7 by name as staying human. This asserts
    the tool actually says so for something shaped like each of them, rather than
    just being silent."""
    assert "merge-ready-prs" in HUMAN_STEPS
    assert "retarget-prs" in HUMAN_STEPS
    assert "merge-phase1-pr" in HUMAN_STEPS
