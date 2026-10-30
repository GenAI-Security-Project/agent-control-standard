"""Tests for the intake tool: the data model, the data line, the helpers, and the gate."""
from __future__ import annotations

import dataclasses
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import closing_choice  # noqa: E402
import pr_intake  # noqa: E402
import roadmap_model  # noqa: E402
from pr_intake import (  # noqa: E402
    BotComment, Facts, Reference, Review, decide, facts_hash, parse_data_line, render_comment, render_data_line,
    safe_path, unmet_routes,
)

TODAY = date(2026, 11, 10)
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
TEMPLATE = Path(__file__).resolve().parents[1] / ".github" / "pull_request_template.md"


def make_facts(**overrides) -> Facts:
    base = dict(
        number=7, state="open", draft=False, author="alice", author_is_bot=False, title="t", body="b",
        base="main", head_sha="a" * 40, created_at=NOW, updated_at=NOW, labels=frozenset(),
        paths=("docs/a.md",), paths_truncated=False, references=(), references_dropped=0, reviews=(),
        last_unlabel=None, last_author_comment_at=None, bot_comment=None, auto_merge=False,
        author_record=False, held_use={}, roster=frozenset({"bob"}), mode="enforced", sweep=False,
        event_action=None,
    )
    base.update(overrides)
    return Facts(**base)


def reference(number: int = 5) -> Reference:
    return Reference(
        number=number, kind="issue", is_pull=False, state="open", labels=frozenset({"accepted"}),
        assignees=frozenset(), milestoned=False, author_commented_at=None, unresolved=False,
    )


def test_data_line_round_trips():
    fields = {
        "reason": "no_accepted,held_cap", "route": "roster", "issues": "5,6", "since": "2026-11-01",
        "cleared": "2026-11-02", "head": "a" * 12, "cleared_head": "b" * 12, "facts": "0123456789ab",
        "claimed": "5:2026-11-01,6:2026-11-02", "seen": "2026-11-01T00:00:00Z,2026-11-02T00:00:00Z",
    }
    line = render_data_line(fields)
    assert line.startswith(pr_intake.DATA_PREFIX) and line.endswith("-->") and "\n" not in line
    assert parse_data_line(line) == fields
    assert parse_data_line(line + "\n" + pr_intake.MARKER) == fields


def test_parse_data_line_reads_line_one_only():
    body = "hello\n" + pr_intake.MARKER + "\n<!-- acs-intake-data since=2020-01-01 -->"
    assert parse_data_line(body) is None
    assert parse_data_line("") is None


@pytest.mark.parametrize(
    "line",
    [
        "<!-- acs-intake-data reason=a b -->",
        "<!-- acs-intake-data reason=a>b -->",
        "<!-- acs-intake-data bogus=1 -->",
        "<!-- acs-intake-data -->",
        "<!-- acs-intake-data reason= -->",
        "<!-- acs-intake-data reason=a --> trailing",
    ],
)
def test_data_line_rejects_bad_shapes(line):
    assert parse_data_line(line) is None


def test_render_data_line_refuses_what_it_could_not_read_back():
    with pytest.raises(ValueError):
        render_data_line({"reason": "a b"})
    with pytest.raises(ValueError):
        render_data_line({"bogus": "1"})


def test_facts_hash_changes_with_references_and_with_a_review_crossing_thirty_days_not_with_updated_at():
    base = make_facts()
    digest = facts_hash(base, TODAY)
    assert len(digest) == 12 and int(digest, 16) >= 0
    assert facts_hash(dataclasses.replace(base, updated_at=NOW + timedelta(days=1)), TODAY) == digest
    assert facts_hash(dataclasses.replace(base, references=(reference(),)), TODAY) != digest

    submitted = datetime(2026, 10, 15, tzinfo=timezone.utc)
    review = Review(login="bob", state="CHANGES_REQUESTED", association="MEMBER", submitted_at=submitted, commit_id="c" * 40)
    reviewed = dataclasses.replace(base, reviews=(review,))
    fresh = facts_hash(reviewed, submitted.date() + timedelta(days=30))
    stale = facts_hash(reviewed, submitted.date() + timedelta(days=31))
    assert fresh != stale


def test_editorial_ticked_agrees_with_closing_choice_on_the_template_line():
    line = next(l for l in TEMPLATE.read_text().splitlines() if "This is an editorial correction" in l)
    ticked = line.replace("[ ]", "[x]", 1)
    assert pr_intake.editorial_ticked(ticked) is True
    assert pr_intake.editorial_ticked(line) is False
    for text in (ticked, line, "**" + ticked + "**"):
        assert pr_intake.editorial_ticked(text) == bool(closing_choice.EDITORIAL.search(closing_choice.normalize(text)))


def test_safe_path_replaces_backtick_marker_and_at():
    cleaned = safe_path("a`b<!-- x -->@c d.md")
    assert not any(char in cleaned for char in "`<>@! ")
    assert cleaned.startswith("a?b?") and cleaned.endswith("?c?d.md")
    assert safe_path("docs/ok-1_2.md") == "docs/ok-1_2.md"
    assert len(safe_path("a" * 500)) == 200


def test_facts_hash_changes_with_cleared_head_and_with_reference_kind():
    base = make_facts()
    digest = facts_hash(base, TODAY)

    def with_cleared(value):
        comment = pr_intake.BotComment(id=1, body="", data={"cleared_head": value}, legacy=False)
        return facts_hash(dataclasses.replace(base, bot_comment=comment), TODAY)

    assert with_cleared("a" * 12) != digest
    assert with_cleared("a" * 12) != with_cleared("b" * 12)

    closing = dataclasses.replace(reference(), kind="close")
    mention = dataclasses.replace(reference(), kind="mention")
    assert facts_hash(dataclasses.replace(base, references=(closing,)), TODAY) != facts_hash(
        dataclasses.replace(base, references=(mention,)), TODAY
    )


def test_facts_hash_survives_none_beside_a_value_in_sort_ties():
    base = make_facts()
    reviews = tuple(
        Review(login="bob", state="APPROVED", association="MEMBER", submitted_at=None, commit_id=commit)
        for commit in (None, "c" * 40)
    )
    refs = tuple(
        dataclasses.replace(reference(), author_commented_at=when) for when in (None, NOW)
    )
    forward = dataclasses.replace(base, reviews=reviews, references=refs)
    backward = dataclasses.replace(base, reviews=reviews[::-1], references=refs[::-1])
    assert facts_hash(forward, TODAY) == facts_hash(backward, TODAY)


# --- The gate -------------------------------------------------------------------------

ROSTER = frozenset({"rocklambros", "lrd0036"})
OPENED = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
HEAD = "a" * 40
TICKED = "- [x] This is an editorial correction on the documentation lane (typo, grammar, link, formatting)"
NEEDS_TRIAGE = roadmap_model.NEEDS_TRIAGE
POPULATION = Path(__file__).resolve().parent / "fixtures" / "pr_intake" / "population.json"


def facts(**overrides) -> Facts:
    """A non-roster pull request with no references, in enforced mode, opened after the rule."""
    base = dict(
        number=354, state="open", draft=False, author="outsider", author_is_bot=False, title="Add a thing",
        body="b", base="integration", head_sha=HEAD, created_at=OPENED, updated_at=OPENED,
        labels=frozenset(), paths=("tools/x.py",), paths_truncated=False, references=(), references_dropped=0,
        reviews=(), last_unlabel=None, last_author_comment_at=None, bot_comment=None, auto_merge=False,
        author_record=False, held_use={}, roster=ROSTER, mode="enforced", sweep=False, event_action="opened",
    )
    base.update(overrides)
    return Facts(**base)


def issue(number, *, state="open", kind="contribute", labels=(roadmap_model.ACCEPTED,), assignees=(),
          milestoned=False, commented=None, is_pull=False, unresolved=False) -> Reference:
    return Reference(
        number=number, kind=kind, is_pull=is_pull, state=state, labels=frozenset(labels),
        assignees=frozenset(assignees), milestoned=milestoned, author_commented_at=commented, unresolved=unresolved,
    )


def review(*, login="rocklambros", state="APPROVED", association="MEMBER", days=1, commit=HEAD, today=TODAY) -> Review:
    submitted = datetime.combine(today - timedelta(days=days), datetime.min.time(), tzinfo=timezone.utc)
    return Review(login=login, state=state, association=association, submitted_at=submitted, commit_id=commit)


BOT_WRITE_AT = datetime(2026, 11, 10, 3, 10, tzinfo=timezone.utc)


def with_comment(f: Facts, decision) -> Facts:
    """The facts as the next run reads them, after the writer applied `decision`.

    The comment is posted or edited, and the label is set or removed. A removal by the bot
    shows up in the timeline as the bot's own unlabel.
    """
    if decision.comment is not None:
        body = decision.comment
        f = dataclasses.replace(f, bot_comment=BotComment(id=1, body=body, data=parse_data_line(body), legacy=False))
    if decision.label == "set":
        f = dataclasses.replace(f, labels=f.labels | {NEEDS_TRIAGE})
    elif decision.label == "clear":
        f = dataclasses.replace(f, labels=f.labels - {NEEDS_TRIAGE}, last_unlabel=(roadmap_model.BOT_LOGIN, BOT_WRITE_AT))
    return f


def outcome(decision):
    return decision.outcome, decision.route, decision.reasons


def test_known_bot_author_is_out_of_scope():
    for author in sorted(pr_intake.KNOWN_BOTS):
        for mode in ("enforced", "legacy"):
            decision = decide(facts(author=author, author_is_bot=True, mode=mode), TODAY)
            assert decision.outcome == "skip" and decision.label == "keep"
            assert decision.comment is None and decision.data is None and decision.disable_auto_merge is False


def test_unknown_bot_author_is_evaluated_as_non_roster():
    decision = decide(facts(author="renovate[bot]", author_is_bot=True), TODAY)
    assert outcome(decision) == ("queue", None, ("no_accepted",))
    assert decision.label == "set" and decision.comment is not None


def test_draft_is_skipped():
    for mode in ("enforced", "legacy"):
        decision = decide(facts(draft=True, mode=mode), TODAY)
        assert decision.outcome == "skip" and decision.label == "keep" and decision.comment is None


def test_roster_author_passes_case_insensitively():
    stored = facts(author="Lrd0036".casefold())
    assert outcome(decide(stored, TODAY)) == ("pass", "roster", ())
    assert outcome(decide(facts(author="Lrd0036"), TODAY)) == ("pass", "roster", ())
    # Never queued and never labeled: nothing to write.
    quiet = decide(stored, TODAY)
    assert quiet.label == "keep" and quiet.comment is None
    labeled = decide(dataclasses.replace(stored, labels=frozenset({NEEDS_TRIAGE})), TODAY)
    assert labeled.label == "clear" and labeled.data["reason"] == "cleared" and labeled.data["route"] == "roster"


def test_approved_review_by_roster_collaborator_passes():
    decision = decide(facts(reviews=(review(login="LRD0036".casefold(), association="COLLABORATOR", days=400),)), TODAY)
    assert outcome(decision) == ("pass", "review", ())


def test_approved_review_by_roster_login_without_role_does_not_count():
    for association in ("CONTRIBUTOR", "NONE", "FIRST_TIME_CONTRIBUTOR"):
        decision = decide(facts(reviews=(review(association=association),)), TODAY)
        assert outcome(decision) == ("queue", None, ("no_accepted",))
    stranger = decide(facts(reviews=(review(login="someone", association="MEMBER"),)), TODAY)
    assert stranger.outcome == "queue"


def test_commented_reviews_do_not_count():
    decision = decide(facts(reviews=(review(state="COMMENTED"), review(state="DISMISSED"))), TODAY)
    assert outcome(decision) == ("queue", None, ("no_accepted",))


def test_changes_requested_at_29_days_passes_and_at_31_days_is_sent_back_or_awaiting():
    fresh = decide(facts(reviews=(review(state="CHANGES_REQUESTED", days=29),)), TODAY)
    assert outcome(fresh) == ("pass", "review", ())
    edge = decide(facts(reviews=(review(state="CHANGES_REQUESTED", days=30),)), TODAY)
    assert edge.outcome == "pass"
    stale = facts(reviews=(review(state="CHANGES_REQUESTED", days=31),))
    assert outcome(decide(stale, TODAY)) == ("queue", None, ("sent_back", "no_accepted"))
    replied = dataclasses.replace(stale, last_author_comment_at=datetime.combine(
        TODAY - timedelta(days=5), datetime.min.time(), tzinfo=timezone.utc))
    assert decide(replied, TODAY).reasons == ("awaiting_rereview", "no_accepted")
    # A newer roster review, even a comment, means the lead has looked again.
    relooked = dataclasses.replace(stale, reviews=stale.reviews + (review(state="COMMENTED", days=20),))
    assert decide(relooked, TODAY).reasons == ("no_accepted",)


def test_push_after_changes_requested_is_awaiting_rereview_not_sent_back():
    decision = decide(facts(reviews=(review(state="CHANGES_REQUESTED", days=45, commit="c" * 40),)), TODAY)
    assert decision.reasons[0] == "awaiting_rereview"
    assert "sent_back" not in decision.reasons
    assert decision.data["reason"] == "awaiting_rereview"
    assert "re-review" in decision.comment or "second review" in decision.comment


def test_hand_clear_records_the_head_and_holds_while_it_matches():
    queued = facts(labels=frozenset({NEEDS_TRIAGE}))
    first = decide(queued, TODAY)
    unlabeled = dataclasses.replace(
        with_comment(queued, first), labels=frozenset(), last_unlabel=("rocklambros", OPENED + timedelta(days=1))
    )
    cleared = decide(unlabeled, TODAY)
    assert outcome(cleared) == ("pass", "hand", ())
    assert cleared.data["cleared_head"] == HEAD and cleared.data["reason"] == "cleared"
    assert cleared.data["cleared_at"] == "2026-11-03T12:00:00Z"
    assert cleared.data["route"] == "hand" and cleared.data["cleared"] == TODAY.isoformat()
    assert cleared.label == "keep" and cleared.comment is not None
    held = decide(with_comment(unlabeled, cleared), TODAY + timedelta(days=3))
    assert outcome(held) == ("pass", "hand", ())
    assert held.label == "keep" and held.comment is None


def test_hand_clear_stops_holding_when_the_head_sha_changes():
    queued = facts(labels=frozenset({NEEDS_TRIAGE}))
    unlabeled = dataclasses.replace(
        with_comment(queued, decide(queued, TODAY)), labels=frozenset(), last_unlabel=("lrd0036", OPENED)
    )
    cleared = with_comment(unlabeled, decide(unlabeled, TODAY))
    pushed = dataclasses.replace(cleared, head_sha="b" * 40)
    requeued = decide(pushed, TODAY)
    assert outcome(requeued) == ("queue", None, ("no_accepted",))
    assert requeued.label == "set" and requeued.comment is not None
    # The recorded head is carried, so the old unlabel cannot clear the new head next run.
    assert requeued.data["cleared_head"] == HEAD
    assert decide(with_comment(pushed, requeued), TODAY).outcome == "queue"


def test_hand_clear_by_non_roster_is_reversed():
    queued = facts(labels=frozenset({NEEDS_TRIAGE}))
    removed = dataclasses.replace(
        with_comment(queued, decide(queued, TODAY)), labels=frozenset(), last_unlabel=("outsider", OPENED)
    )
    decision = decide(removed, TODAY)
    assert outcome(decision) == ("queue", None, ("no_accepted",))
    assert decision.label == "set" and "cleared_head" not in decision.data
    assert "someone other than a lead" in decision.comment
    # The bot's own removal on an earlier clear is not a removal to reverse in words.
    # The label is outside the hash, so the short circuit restores it without a comment.
    by_bot = decide(dataclasses.replace(removed, last_unlabel=(roadmap_model.BOT_LOGIN, OPENED)), TODAY)
    assert by_bot.label == "set" and by_bot.comment is None
    # The reversal renders once. Once the label is back, the next run writes nothing.
    settled = decide(with_comment(removed, decision), TODAY)
    assert settled.outcome == "queue" and settled.label == "keep" and settled.comment is None


def test_author_merged_record_passes():
    assert outcome(decide(facts(author_record=True), TODAY)) == ("pass", "record", ())


def test_editorial_on_the_docs_lane_passes():
    decision = decide(facts(body=TICKED, paths=("docs/topics/a.md", "design/b.md", "README.md")), TODAY)
    assert outcome(decision) == ("pass", "editorial", ())


def test_editorial_off_lane_queues_naming_sanitized_paths():
    hostile = "specification/v`1<!--x-->@y #1.json"
    decision = decide(facts(body=TICKED, paths=("docs/topics/a.md", hostile, "docs/spec/b.md")), TODAY)
    assert outcome(decision) == ("queue", None, ("editorial_off_lane",))
    assert f"`{safe_path(hostile)}`" in decision.comment and "`docs/spec/b.md`" in decision.comment
    assert "`docs/topics/a.md`" not in decision.comment
    assert hostile not in decision.comment


def test_motivating_example_queues():
    # PR #354: editorial box ticked, one path under reference-implementations/, Refs #92 on a
    # help wanted issue the author commented on two days earlier. The tick on an off-lane path
    # queues before the help wanted route is read.
    claimed = issue(92, labels=(roadmap_model.ACCEPTED, "help wanted"), commented=OPENED - timedelta(days=2))
    f = facts(body=TICKED + "\n\nRefs #92", paths=("reference-implementations/x.py",), references=(claimed,),
              held_use={92: (354,)})
    decision = decide(f, TODAY)
    assert outcome(decision) == ("queue", None, ("editorial_off_lane",))
    assert unmet_routes(f, TODAY) == ("roster", "engaged", "record", "editorial")
    assert "`reference-implementations/x.py`" in decision.comment
    # Without the tick the same pull request passes on the claim.
    assert outcome(decide(dataclasses.replace(f, body="Refs #92"), TODAY)) == ("pass", "help_wanted", ())


def test_truncated_paths_queue_with_their_own_reason_and_never_pass_editorial():
    on_lane = tuple(f"docs/topics/p{n}.md" for n in range(3000))
    decision = decide(facts(body=TICKED, paths=on_lane, paths_truncated=True), TODAY)
    assert outcome(decision) == ("queue", None, ("paths_truncated",))
    assert decision.comment.count("`docs/topics/") <= 1
    both = decide(facts(body=TICKED, paths=("src/x.py",), paths_truncated=True), TODAY)
    assert both.reasons == ("editorial_off_lane", "paths_truncated")
    # Truncation without the tick is not a reason: the editorial route was never claimed.
    assert decide(facts(paths=on_lane, paths_truncated=True), TODAY).reasons == ("no_accepted",)


def test_first_two_pull_requests_on_a_held_issue_pass_and_the_third_queues():
    held = issue(40, assignees=("outsider",))
    use = {40: (300, 354, 400)}
    for number in (300, 354):
        assert outcome(decide(facts(number=number, references=(held,), held_use=use), TODAY)) == ("pass", "assignment", ())
    third = decide(facts(number=400, references=(held,), held_use=use), TODAY)
    assert outcome(third) == ("queue", None, ("held_cap",))
    assert "#40 already clears PR #300 and PR #354." in third.comment


def test_first_two_pull_requests_on_a_help_wanted_issue_pass_and_the_third_queues():
    wanted = issue(41, labels=(roadmap_model.ACCEPTED, "help wanted"), commented=OPENED - timedelta(days=1))
    use = {41: (354, 360, 365)}
    for number in (354, 360):
        assert outcome(decide(facts(number=number, references=(wanted,), held_use=use), TODAY)) == ("pass", "help_wanted", ())
    third = decide(facts(number=365, references=(wanted,), held_use=use), TODAY)
    assert outcome(third) == ("queue", None, ("held_cap",))
    assert "#41 already clears PR #354 and PR #360." in third.comment


def test_issue_author_without_assignment_queues():
    decision = decide(facts(references=(issue(42),), held_use={42: (354,)}), TODAY)
    assert outcome(decision) == ("queue", None, ("not_held",))
    assert "This pull request references #42, which is accepted and is not assigned to you." in decision.comment
    assert "To claim one, comment on it" in decision.comment


def test_help_wanted_with_prior_comment_passes_and_without_queues():
    labels = (roadmap_model.ACCEPTED, "help wanted")
    claimed = issue(43, labels=labels, commented=OPENED - timedelta(hours=1))
    assert outcome(decide(facts(references=(claimed,), held_use={43: (354,)}), TODAY)) == ("pass", "help_wanted", ())
    silent = issue(43, labels=labels)
    assert outcome(decide(facts(references=(silent,), held_use={43: (354,)}), TODAY)) == ("queue", None, ("not_held",))


def test_help_wanted_comment_after_open_does_not_count():
    late = issue(92, labels=(roadmap_model.ACCEPTED, "help wanted"), commented=datetime(2026, 11, 3, 9, tzinfo=timezone.utc))
    decision = decide(facts(references=(late,), held_use={92: (354,)}), TODAY)
    assert outcome(decision) == ("queue", None, ("not_held",))
    assert "You commented on #92 on 2026-11-03. If that was a claim, it is waiting on a lead." in decision.comment
    assert decision.data["claimed"] == "92:2026-11-03"


def test_closed_accepted_reference_gets_its_own_reason():
    decision = decide(facts(references=(issue(44, state="closed"),)), TODAY)
    assert outcome(decision) == ("queue", None, ("closed_accepted",))
    assert "This pull request references #44, which was accepted and is now closed." in decision.comment


def test_reference_to_a_pull_request_number_is_not_an_issue():
    as_pull = issue(45, is_pull=True, assignees=("outsider",))
    assert outcome(decide(facts(references=(as_pull,), held_use={45: (354,)}), TODAY)) == ("queue", None, ("no_accepted",))
    unknown = issue(46, unresolved=True, assignees=("outsider",))
    assert decide(facts(references=(unknown,)), TODAY).reasons == ("no_accepted",)


def test_body_failing_two_routes_renders_both_paragraphs():
    f = facts(references=(issue(10, state="closed"), issue(11), issue(12)), held_use={11: (354,), 12: (354,)})
    decision = decide(f, TODAY)
    assert outcome(decision) == ("queue", None, ("closed_accepted", "not_held"))
    assert unmet_routes(f, TODAY) == ("roster", "engaged", "record", "editorial", "held", "help_wanted")
    assert "#10, which was accepted and is now closed" in decision.comment
    assert "#11 and #12, which are accepted, and neither is assigned to you." in decision.comment
    assert decision.comment.index("#10, which") < decision.comment.index("#11 and #12")
    assert decision.data["issues"] == "10,11,12"


def test_prior_comment_is_named_as_possibly_waiting():
    asked = issue(47, commented=OPENED - timedelta(days=4))
    decision = decide(facts(references=(asked, issue(48)), held_use={47: (354,), 48: (354,)}), TODAY)
    assert decision.reasons == ("not_held",)
    assert "You commented on #47 on 2026-10-29. If that was a claim, it is waiting on a lead." in decision.comment
    assert "#48 on" not in decision.comment
    assert "To claim one" not in decision.comment
    assert decision.data["claimed"] == "47:2026-10-29"


def test_legacy_mode_matches_todays_three_exits():
    queued = decide(facts(mode="legacy"), TODAY)
    assert queued.outcome == "queue" and queued.label == "set" and queued.data is None
    assert queued.comment.startswith(pr_intake.LEGACY_PREFIX)
    assert queued.disable_auto_merge is False
    exits = {
        "accepted, even closed": facts(mode="legacy", references=(issue(50, state="closed"),)),
        "editorial ticked": facts(mode="legacy", body=TICKED, paths=("src/x.py",)),
        "already commented": facts(mode="legacy", bot_comment=BotComment(id=9, body=pr_intake.LEGACY_PREFIX, data=None, legacy=True)),
    }
    for name, f in exits.items():
        decision = decide(f, TODAY)
        assert decision.label == "keep" and decision.comment is None, name
        assert decision.notices, name
    # Legacy never clears a label, even for a roster author.
    roster = decide(facts(mode="legacy", author="rocklambros", labels=frozenset({NEEDS_TRIAGE}),
                          bot_comment=BotComment(id=9, body=pr_intake.LEGACY_PREFIX, data=None, legacy=True)), TODAY)
    assert roster.label == "keep" and roster.comment is None


def test_legacy_sweep_writes_nothing():
    decision = decide(facts(mode="legacy", sweep=True), TODAY)
    assert decision.label == "keep" and decision.comment is None and decision.disable_auto_merge is False
    assert any("queue" in notice for notice in decision.notices)


def test_pre_rule_pull_request_comment_says_the_rule_is_new():
    old = decide(facts(created_at=datetime(2026, 10, 1, tzinfo=timezone.utc)), TODAY)
    assert "The rule is new, and its 30-day clock starts on 2026-11-10." in old.comment
    assert "The rule is new" not in decide(facts(), TODAY).comment


def test_keyword_warning_present_when_a_closing_keyword_names_a_milestoned_issue():
    roadmap = issue(60, kind="close", labels=(), milestoned=True)
    decision = decide(facts(references=(roadmap,)), TODAY)
    assert "says it closes #60, which is on the project roadmap" in decision.comment
    # A roster author is not queued, but the merger still gets the warning.
    lead = decide(facts(author="rocklambros", references=(roadmap,)), TODAY)
    assert lead.outcome == "pass" and "which is on the project roadmap" in lead.comment
    for quiet in (issue(60, kind="contribute", labels=(), milestoned=True), issue(60, kind="close", labels=())):
        assert "project roadmap" not in decide(facts(references=(quiet,)), TODAY).comment


def test_auto_merge_disabled_whenever_on_for_a_non_roster_milestoned_close():
    roadmap = issue(61, kind="close", labels=(), milestoned=True)
    passing = decide(facts(auto_merge=True, author_record=True, references=(roadmap,)), TODAY)
    assert passing.outcome == "pass" and passing.disable_auto_merge is True
    assert ("Auto-merge is off because this pull request closes roadmap issue #61. "
            "A lead merges it by hand after confirming delivery.") in passing.comment
    for event in ("opened", "edited", "synchronize", "auto_merge_enabled", None):
        assert decide(facts(auto_merge=True, author_record=True, references=(roadmap,), event_action=event), TODAY).disable_auto_merge
    assert decide(facts(auto_merge=True, author="rocklambros", references=(roadmap,)), TODAY).disable_auto_merge is False
    assert decide(facts(auto_merge=False, author_record=True, references=(roadmap,)), TODAY).disable_auto_merge is False
    closed = issue(61, kind="close", labels=(), milestoned=True, state="closed")
    assert decide(facts(auto_merge=True, author_record=True, references=(closed,)), TODAY).disable_auto_merge is False
    # A queued pull request never merges itself either.
    assert decide(facts(auto_merge=True), TODAY).disable_auto_merge is True


def test_unchanged_facts_keep_label_and_comment():
    f = facts(references=(issue(70),), held_use={70: (354,)})
    first = decide(f, TODAY)
    again = decide(with_comment(f, first), TODAY + timedelta(days=2))
    assert outcome(again) == outcome(first)
    assert again.label == "keep" and again.comment is None


def test_bot_label_writes_do_not_defeat_the_short_circuit():
    f = facts(references=(issue(71),), held_use={71: (354,)})
    queued = decide(f, TODAY)
    assert queued.label == "set" and queued.comment is not None
    after_queue = with_comment(f, queued)
    assert NEEDS_TRIAGE in after_queue.labels
    again = decide(after_queue, TODAY)
    assert again.outcome == "queue" and again.label == "keep" and again.comment is None

    passing = dataclasses.replace(after_queue, author_record=True)
    cleared = decide(passing, TODAY)
    assert cleared.label == "clear" and cleared.comment is not None
    after_clear = with_comment(passing, cleared)
    assert after_clear.last_unlabel[0] == roadmap_model.BOT_LOGIN and NEEDS_TRIAGE not in after_clear.labels
    settled = decide(after_clear, TODAY + timedelta(days=1))
    assert settled.outcome == "pass" and settled.label == "keep" and settled.comment is None


def test_second_hand_clear_after_a_push_is_a_fresh_clear():
    first_at = OPENED + timedelta(days=1)
    queued = facts()
    removed = dataclasses.replace(
        with_comment(queued, decide(queued, TODAY)), labels=frozenset(), last_unlabel=("rocklambros", first_at)
    )
    cleared = decide(removed, TODAY)
    assert cleared.data["cleared_head"] == HEAD
    pushed = dataclasses.replace(with_comment(removed, cleared), head_sha="b" * 40)
    requeued = decide(pushed, TODAY)
    assert requeued.outcome == "queue" and requeued.label == "set"
    assert requeued.data["cleared_at"] == "2026-11-03T12:00:00Z"
    # The same old removal, read again with the label back, still does not clear the new head.
    relabeled = with_comment(pushed, requeued)
    assert decide(relabeled, TODAY).outcome == "queue"
    # A lead removes the label again after the push: a fresh clear at the new head.
    second_at = first_at + timedelta(days=2, hours=3)
    again = dataclasses.replace(relabeled, labels=frozenset(), last_unlabel=("lrd0036", second_at))
    fresh = decide(again, TODAY)
    assert outcome(fresh) == ("pass", "hand", ())
    assert fresh.label == "keep" and fresh.comment is not None
    assert fresh.data["cleared_head"] == "b" * 40 and fresh.data["cleared_at"] == "2026-11-05T15:00:00Z"
    held = decide(with_comment(again, fresh), TODAY)
    assert outcome(held) == ("pass", "hand", ()) and held.comment is None


def test_data_line_values_are_capped_so_decide_is_total():
    many = tuple(issue(1000 + n, commented=OPENED - timedelta(days=1)) for n in range(14))
    decision = decide(facts(references=many), TODAY)
    assert decision.reasons == ("not_held",)
    claimed = decision.data["claimed"].split(",")
    assert claimed == [f"{1000 + n}:2026-11-01" for n in range(pr_intake.MAX_CLAIM_READS)]
    assert parse_data_line(decision.comment) == decision.data
    huge = tuple(issue(999_999_000 + n, commented=OPENED - timedelta(days=1)) for n in range(40))
    wide = decide(facts(references=huge), TODAY)
    assert parse_data_line(wide.comment) == wide.data
    assert wide.data["issues"].split(",")[0] == "999999000"


# One changed value per Facts field. The set of keys must equal the dataclass fields, so a
# field added later fails here until someone decides what changing it means.
def _mutations(base: Facts) -> dict:
    return {
        "number": 999,
        "state": "closed",
        "draft": True,
        "author": "rocklambros",
        "author_is_bot": True,
        "title": "Fixes #92",
        "body": TICKED,
        "base": "main",
        "head_sha": "b" * 40,
        # Before the author's comment on #92, so the claim no longer counts.
        "created_at": OPENED - timedelta(days=10),
        "updated_at": OPENED + timedelta(days=3),
        "labels": frozenset({NEEDS_TRIAGE}),
        "paths": ("docs/topics/a.md",),
        "paths_truncated": True,
        "references": base.references + (issue(93),),
        "references_dropped": 3,
        "reviews": (),
        "last_unlabel": ("rocklambros", OPENED),
        "last_author_comment_at": OPENED + timedelta(days=60),
        "bot_comment": None,
        "auto_merge": True,
        "author_record": True,
        "held_use": {92: (354, 400, 500)},
        "roster": base.roster | {"outsider"},
        "mode": "legacy",
        "sweep": True,
        "event_action": "edited",
    }


@pytest.mark.parametrize("age", [29, 31])
@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(Facts)])
def test_hash_short_circuit_cannot_hide_a_changed_decision(field, age):
    # The review is 30 days before TODAY, so `today` sits at 29 or 31 days past it. At 31 the
    # base queues with sent_back first and held_cap second, the shape where a change behind
    # the first reason is the one a hash gap would hide.
    submitted = TODAY - timedelta(days=30)
    today = submitted + timedelta(days=age)
    wanted = issue(92, labels=(roadmap_model.ACCEPTED, "help wanted"), commented=OPENED - timedelta(days=2))
    base = facts(
        references=(wanted,), held_use={92: (100, 200, 354)},
        reviews=(review(state="CHANGES_REQUESTED", days=30, today=TODAY),),
    )
    mutations = _mutations(base)
    assert set(mutations) == {f.name for f in dataclasses.fields(Facts)}
    before = decide(base, today)
    stored = with_comment(base, before) if before.comment else base
    changed = dataclasses.replace(stored, **{field: mutations[field]})
    fresh = decide(dataclasses.replace(base, **{field: mutations[field]}), today)
    after = decide(changed, today)
    if (fresh.outcome, fresh.reasons) != (before.outcome, before.reasons) and after.outcome != "skip" and changed.mode == "enforced":
        assert after.comment is not None, field
    if age == 31:
        assert before.reasons == ("sent_back", "held_cap")
    # The same facts read on the other side of the 30-day line always render.
    other = submitted + timedelta(days=60 - age)
    crossed = decide(with_comment(base, decide(base, other)), today)
    assert crossed.comment is not None


def test_since_survives_a_rerender_and_resets_on_clear():
    day0 = TODAY
    f = facts(references=(issue(80),), held_use={80: (354,)})
    first = decide(f, day0)
    assert first.data["since"] == day0.isoformat()
    grown = dataclasses.replace(with_comment(f, first), references=(issue(80), issue(81, state="closed")))
    rerendered = decide(grown, day0 + timedelta(days=5))
    assert rerendered.comment is not None and rerendered.reasons == ("closed_accepted", "not_held")
    assert rerendered.data["since"] == day0.isoformat()
    cleared = decide(dataclasses.replace(with_comment(grown, rerendered), author_record=True), day0 + timedelta(days=6))
    assert cleared.outcome == "pass" and "since" not in cleared.data
    assert cleared.data["cleared"] == (day0 + timedelta(days=6)).isoformat()
    after = dataclasses.replace(with_comment(grown, cleared), author_record=False)
    requeued = decide(after, day0 + timedelta(days=9))
    assert requeued.data["since"] == (day0 + timedelta(days=9)).isoformat()


def test_render_comment_contains_one_html_comment_pair_and_no_at_sign():
    hostile = ("x/`code`.md", "y/<!-- marker -->.md", "z/@someone.md", "w/#1.md", "v/-->.md") + tuple(
        f"src/{'q' * 300}{n}.py" for n in range(30)
    )
    claimed = issue(9, commented=OPENED - timedelta(days=1))
    f = facts(body=TICKED, paths=hostile, references=(claimed,), references_dropped=7, author="mallory@example")
    decision = decide(f, TODAY)
    for text in (decision.comment, render_comment(f, decision, TODAY)):
        assert text.count("<!--") == 2 and text.count("-->") == 2
        assert "@" not in text and "mallory" not in text
        lines = text.split("\n")
        assert parse_data_line(lines[0]) == decision.data and lines[1] == pr_intake.MARKER
        assert len(text) <= 8000
        assert "and 15 more" in text
    # Every name the bot quotes comes out of a code span, at most 200 characters each.
    assert "`x/?code?.md`" in decision.comment
    long_issue = facts(references=(issue(9),), references_dropped=4)
    assert "and 4 more" in decide(long_issue, TODAY).comment


def _from_json(row: dict) -> Facts:
    def when(value):
        return None if value is None else datetime.fromisoformat(value.replace("Z", "+00:00"))

    raw = dict(row)
    for key in ("created_at", "updated_at", "last_author_comment_at"):
        if key in raw:
            raw[key] = when(raw[key])
    for key in ("labels", "roster"):
        if key in raw:
            raw[key] = frozenset(raw[key])
    if "paths" in raw:
        raw["paths"] = tuple(raw["paths"])
    if "references" in raw:
        raw["references"] = tuple(
            Reference(**{**ref, "labels": frozenset(ref["labels"]), "assignees": frozenset(ref["assignees"]),
                         "author_commented_at": when(ref.get("author_commented_at"))})
            for ref in raw["references"]
        )
    if "reviews" in raw:
        raw["reviews"] = tuple(Review(**{**r, "submitted_at": when(r.get("submitted_at"))}) for r in raw["reviews"])
    if raw.get("last_unlabel") is not None:
        raw["last_unlabel"] = (raw["last_unlabel"][0], when(raw["last_unlabel"][1]))
    if "held_use" in raw:
        raw["held_use"] = {int(n): tuple(numbers) for n, numbers in raw["held_use"].items()}
    if raw.get("bot_comment") is not None:
        raw["bot_comment"] = BotComment(**raw["bot_comment"])
    return facts(**raw)


def test_decide_matches_the_recorded_population():
    """Every recorded open pull request decides as recorded.

    The fixture is a JSON object: `{"generated_by": <the recording script's path>,
    "recorded": "YYYY-MM-DD", "rows": [<row>, ...]}`. Each row is an object:
    `{"facts": {<Facts field>: <value>, ...}, "today": "YYYY-MM-DD", "expected":
    {"outcome": "pass"|"queue"|"skip", "route": <str or null>, "reasons": [<reason>, ...]}}`.
    `facts` holds overrides on this module's `facts()` defaults in JSON form: datetimes as
    ISO 8601 strings, sets and tuples as lists, `references` and `reviews` as lists of
    objects with the dataclass fields, `last_unlabel` as `[login, datetime]`, `held_use`
    with string keys, and `bot_comment` as an object with the `BotComment` fields. `today`
    is optional and defaults to TODAY.
    """
    document = json.loads(POPULATION.read_text())
    assert (Path(__file__).resolve().parents[1] / document["generated_by"]).exists()
    rows = document["rows"]
    assert len(rows) == 56
    for row in rows:
        today = date.fromisoformat(row.get("today", TODAY.isoformat()))
        decision = decide(_from_json(row["facts"]), today)
        expected = row["expected"]
        assert outcome(decision) == (expected["outcome"], expected["route"], tuple(expected["reasons"])), row["facts"].get("number")


# --- Collecting facts -------------------------------------------------------------------

import copy  # noqa: E402
import re  # noqa: E402
import time  # noqa: E402

import gh_runner  # noqa: E402
from pr_intake import BudgetStop, CallCounter, ListingError, Listings, collect_facts, load_listings  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "pr_intake"
API = f"repos/{roadmap_model.REPO}"
COLLECT_ROSTER = frozenset({"login-13", "login-4"})
OWN_ISSUE_URL = f"https://github.com/{roadmap_model.REPO}/issues"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def http(obj, status: int = 200) -> str:
    return f"HTTP/2.0 {status} OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(obj)


def slurp(*pages) -> str:
    return json.dumps(list(pages))


def runner_from_fixtures(mapping: dict):
    """A runner that serves `mapping[path]` and counts every call.

    A value is the stdout string, or a `(code, stdout, stderr)` tuple. Every argv must
    pass the real allowlist, so a test cannot pass on a shape the runner would refuse.
    A path the mapping does not name fails the test.
    """
    calls: list[list[str]] = []

    def run(args, stdin=None):
        gh_runner._check_allowlist(args)
        calls.append(list(args))
        path = args[-1]
        assert path in mapping, f"unexpected read {path}"
        value = mapping[path]
        return value if isinstance(value, tuple) else (0, value, "")

    run.calls = calls
    return run


def listing_mapping(*, accepted=None, open_pulls=None, closed_pulls=None) -> dict:
    accepted = fixture("accepted_all.json") if accepted is None else accepted
    return {
        f"{API}/issues?labels=status%3Aaccepted&state=all&per_page=100": slurp(accepted),
        f"{API}/issues?milestone=%2A&state=all&per_page=100": slurp([i for i in accepted if i["milestone"]]),
        f"{API}/pulls?state=open&per_page=100": slurp(fixture("pulls_open.json") if open_pulls is None else open_pulls),
        f"{API}/pulls?state=closed&sort=updated&direction=desc&per_page=100": slurp(
            fixture("pulls_closed.json") if closed_pulls is None else closed_pulls
        ),
    }


def pull_mapping(number: int = 229, *, pull=None, files=None, reviews=None, comments=None, timeline=None) -> dict:
    pull = fixture("pull.json") if pull is None else pull
    files = [fixture("files_page1.json"), fixture("files_page2.json")] if files is None else files
    return {
        f"{API}/pulls/{number}": http(pull),
        f"{API}/pulls/{number}/files?per_page=100": slurp(*files),
        f"{API}/pulls/{number}/reviews?per_page=100": slurp(fixture("reviews.json") if reviews is None else reviews),
        f"{API}/issues/{number}/comments?per_page=100": slurp(fixture("comments.json") if comments is None else comments),
        f"{API}/issues/{number}/timeline?per_page=100": slurp(fixture("timeline.json") if timeline is None else timeline),
    }


def claim_mapping(*numbers: int, served: dict | None = None) -> dict:
    served = served or {}
    return {f"{API}/issues/{n}/comments?per_page=100": slurp(served.get(n, [])) for n in numbers}


def with_body(body: str, **changes) -> dict:
    pull = fixture("pull.json")
    pull["body"] = body
    pull.update(changes)
    return pull


def collect(mapping: dict, *, listings: Listings | None = None, number: int = 229, counter=None, roster=COLLECT_ROSTER):
    run = runner_from_fixtures(mapping)
    if listings is None:
        listings = load_listings(runner_from_fixtures(listing_mapping()))
    got = collect_facts(
        run, number, listings=listings, roster=roster, mode="enforced", sweep=False, event_action="opened",
        counter=counter or CallCounter(),
    )
    return got, run.calls


def read_paths(calls) -> list[str]:
    return [call[-1] for call in calls]


def test_collect_paginates_files_and_flags_truncation():
    got, calls = collect(pull_mapping())
    assert len(got.paths) == 56 and got.paths_truncated is False
    assert ["api", "--paginate", "--slurp", f"{API}/pulls/229/files?per_page=100"] in calls
    assert got.paths[0] == fixture("files_page1.json")[0]["filename"]
    assert got.paths[-1] == fixture("files_page2.json")[-1]["filename"]

    short, _ = collect(pull_mapping(pull=with_body("scrubbed", changed_files=57)))
    assert short.paths_truncated is True

    page = [{"filename": f"docs/topics/f{i}.md"} for i in range(100)]
    full, _ = collect(pull_mapping(pull=with_body("scrubbed", changed_files=3000), files=[page] * 30))
    assert len(full.paths) == 3000 and full.paths_truncated is True


def test_changelog_anchor_is_not_a_reference():
    body = (
        "Bumps the thing.\n<details><summary>Changelog</summary>\n"
        '<ul><li><a href="https://github.com/other/repo/issues/92">#92</a> Closes <a href="https://github.com/other/repo/pull/361">#361</a></li>\n'
        f'<li><a href="{OWN_ISSUE_URL}/362">#362</a></li></ul></details>\nRefs #351'
    )
    got, calls = collect({**pull_mapping(pull=with_body(body)), **claim_mapping(351, 362)})
    numbers = [ref.number for ref in got.references]
    assert 92 not in numbers and 361 not in numbers
    assert set(numbers) == {351, 362}


def test_sixty_four_kilobyte_anchor_body_parses_under_one_second():
    bodies = (
        ("<a " * 22_000)[: closing_choice.MAX_CHARS],
        ('<a href="https://example.com/x">#92 ' * 2_000)[: closing_choice.MAX_CHARS],
        ("<a href=" + "a" * 2_040 + ">#5 </a  >") * 30,
        ("</a" + " " * 60) * 1_000,
    )
    for body in bodies:
        started = time.monotonic()
        got, _ = collect({**pull_mapping(pull=with_body(body)), **claim_mapping(92)})
        assert time.monotonic() - started < 1.0
        assert 92 not in {ref.number for ref in got.references}


def test_pull_request_numbers_are_marked_is_pull_from_the_pulls_listings_never_by_keyword():
    got, calls = collect({**pull_mapping(pull=with_body("Closes #354\nCloses #358\nRefs #92")), **claim_mapping(92)})
    refs = {ref.number: ref for ref in got.references}
    assert refs[354].is_pull and refs[358].is_pull and not refs[92].is_pull
    assert refs[354].kind == "close" and refs[92].kind == "contribute"
    assert not refs[354].unresolved and not refs[358].unresolved
    paths = read_paths(calls)
    assert not any(re.search(r"/issues/(354|358|92)$", path) for path in paths)
    assert not any("/issues/354" in path or "/issues/358" in path for path in paths)


def test_closed_accepted_issue_is_collected_as_closed_not_as_a_pull_request():
    got, calls = collect(pull_mapping(pull=with_body("Refs #276 and Refs #9999")))
    refs = {ref.number: ref for ref in got.references}
    assert refs[276].state == "closed" and refs[276].is_pull is False and refs[276].unresolved is False
    assert roadmap_model.ACCEPTED in refs[276].labels and refs[276].milestoned is True
    assert refs[9999].unresolved is True and refs[9999].state is None and refs[9999].labels == frozenset()
    assert not any("/issues/276" in path or "/issues/9999" in path for path in read_paths(calls))


def test_collect_makes_at_most_twelve_calls_whatever_the_body():
    body = " ".join(f"Refs #{n}" for n in range(1, 1_001)) + " Refs #92 #362 #361 #351 #322 #284 #283 #282"
    accepted_open = (92, 362, 361, 351, 322, 284, 283, 282)
    got, calls = collect({**pull_mapping(pull=with_body(body)), **claim_mapping(*accepted_open)})
    assert len(calls) <= 12
    assert len(got.references) == pr_intake.MAX_REFERENCES
    assert got.references_dropped == 1_000 - pr_intake.MAX_REFERENCES
    assert [ref.number for ref in got.references] == list(range(1, pr_intake.MAX_REFERENCES + 1))

    with pytest.raises(BudgetStop):
        collect({**pull_mapping(pull=with_body(body)), **claim_mapping(*accepted_open)}, counter=CallCounter(limit=3))


def test_collect_reads_claim_comments_only_for_open_accepted_unassigned_references_and_at_most_five():
    accepted = fixture("accepted_all.json")
    for issue_obj in accepted:
        if issue_obj["number"] == 282:
            issue_obj["assignees"] = [{"login": "Login-1", "type": "User"}]
    listings = load_listings(runner_from_fixtures(listing_mapping(accepted=accepted)))
    body = "Refs #276, #282, #92, #362, #361, #351, #322, #284, #283"
    served = {92: fixture("issue_comments.json")}
    got, calls = collect(
        {**pull_mapping(pull=with_body(body)), **claim_mapping(92, 362, 361, 351, 322, served=served)}, listings=listings
    )
    claims = [path for path in read_paths(calls) if re.search(r"/issues/[0-9]+/comments", path) and "/229/" not in path]
    assert claims == [f"{API}/issues/{n}/comments?per_page=100" for n in (92, 362, 361, 351, 322)]
    refs = {ref.number: ref for ref in got.references}
    assert refs[92].author_commented_at == datetime(2026, 9, 14, 8, 35, 42, tzinfo=timezone.utc)
    assert refs[282].assignees == frozenset({"login-1"}) and refs[282].author_commented_at is None
    assert refs[284].author_commented_at is None


def test_held_use_counts_the_authors_open_pulls_naming_the_issue():
    open_pulls = fixture("pulls_open.json")
    for pull_obj in open_pulls:
        if pull_obj["number"] == 24:
            pull_obj["body"] = "Part of #92"
        if pull_obj["number"] == 354:
            pull_obj["body"] = "Refs #92"
    listings = load_listings(runner_from_fixtures(listing_mapping(open_pulls=open_pulls)))
    got, _ = collect({**pull_mapping(pull=with_body("Refs #92")), **claim_mapping(92)}, listings=listings)
    assert got.held_use == {92: (24, 229)}


def test_held_use_ignores_drafts():
    accepted = fixture("accepted_all.json")
    for issue_obj in accepted:
        if issue_obj["number"] == 282:
            issue_obj["assignees"] = [{"login": "login-1", "type": "User"}]
    open_pulls = fixture("pulls_open.json")
    template = next(p for p in open_pulls if p["number"] == 24)
    drafts = []
    for draft_number in (24, 25):
        draft = copy.deepcopy(template)
        draft.update(number=draft_number, draft=True, body="Refs #282")
        drafts.append(draft)
    open_pulls = [p for p in open_pulls if p["number"] != 24] + drafts
    listings = load_listings(runner_from_fixtures(listing_mapping(accepted=accepted, open_pulls=open_pulls)))
    got, _ = collect(pull_mapping(pull=with_body("Refs #282"), reviews=[], timeline=[]), listings=listings)
    assert got.held_use == {282: (229,)}
    assert outcome(decide(got, TODAY)) == ("pass", "assignment", ())


def test_collect_skips_null_review_users_and_bot_reviewers():
    got, _ = collect(pull_mapping())
    assert len(got.reviews) == 11
    assert all(review.login and not review.login.endswith("[bot]") for review in got.reviews)
    assert "DISMISSED" not in {review.state for review in got.reviews}
    lead = [review for review in got.reviews if review.login == "login-13"]
    assert lead[-1].state == "CHANGES_REQUESTED" and lead[-1].association == "MEMBER"
    assert lead[-1].commit_id == fixture("pull.json")["head"]["sha"]
    assert got.last_author_comment_at == datetime(2026, 10, 28, 19, 30, 7, tzinfo=timezone.utc)


def test_timeline_facts_read_the_roster_unlabel_and_never_commit_dates():
    timeline = fixture("timeline.json")
    committed = [event for event in timeline if event["event"] == "committed"]
    assert committed and all("created_at" not in event for event in committed)
    assert any(event["event"] == "head_ref_force_pushed" for event in timeline)
    for event in committed:
        event["author"]["date"] = event["committer"]["date"] = "not a date"
    got, _ = collect(pull_mapping(timeline=timeline))
    assert got.last_unlabel == ("login-13", datetime(2026, 10, 25, tzinfo=timezone.utc))


def _comments_without(*ids: int) -> list:
    return [comment for comment in fixture("comments.json") if comment["id"] not in ids]


def test_bot_comment_found_by_exact_login_and_marker_only():
    got, _ = collect(pull_mapping())
    assert got.bot_comment.id == 910003 and got.bot_comment.legacy is False
    assert got.bot_comment.data == {"reason": "no_accepted", "since": "2026-11-02", "head": "9d3efa31a6ac", "facts": "0123456789ab"}

    comments = fixture("comments.json")
    for comment in comments:
        if comment["id"] == 910003:
            comment["user"]["login"] = "GitHub-Actions[bot]"
    near_miss, _ = collect(pull_mapping(comments=comments))
    assert near_miss.bot_comment.id != 910003 and near_miss.bot_comment.legacy is True


def test_legacy_prefix_in_a_contributor_comment_is_not_adopted():
    bot_ids = [c["id"] for c in fixture("comments.json") if c["user"]["login"] == roadmap_model.BOT_LOGIN]
    got, _ = collect(pull_mapping(comments=_comments_without(*bot_ids)))
    assert got.bot_comment is None


def test_legacy_bot_comment_is_adopted():
    legacy_ids = [
        c["id"] for c in fixture("comments.json")
        if c["user"]["login"] == roadmap_model.BOT_LOGIN and c["body"].startswith(pr_intake.LEGACY_PREFIX)
    ]
    got, _ = collect(pull_mapping(comments=_comments_without(910003)))
    assert got.bot_comment.id == legacy_ids[0] and got.bot_comment.legacy is True and got.bot_comment.data is None

    keyword_only, _ = collect(pull_mapping(comments=_comments_without(910003, *legacy_ids)))
    assert keyword_only.bot_comment.legacy is True
    assert pr_intake.LEGACY_KEYWORD_MARKER in keyword_only.bot_comment.body


def test_listing_failure_raises_ListingError():
    for path in listing_mapping():
        mapping = listing_mapping()
        mapping[path] = (1, "", "boom")
        with pytest.raises(ListingError):
            load_listings(runner_from_fixtures(mapping))


def test_author_record_reads_reviews_once_per_merged_pull():
    closed = fixture("pulls_closed.json")
    mine = []
    for pull_obj in closed:
        if pull_obj["number"] in (357, 356):
            pull_obj["user"]["login"] = "login-1"
            mine.append(pull_obj["number"])
    approved = {"user": {"login": "Login-13", "type": "User"}, "state": "APPROVED", "author_association": "MEMBER",
                "submitted_at": "2026-10-29T14:00:00Z", "commit_id": "c" * 40}
    reviews = {357: [approved], 356: [{**approved, "author_association": "NONE"}]}
    listings = load_listings(runner_from_fixtures(listing_mapping(closed_pulls=closed)))
    mapping = {
        **pull_mapping(), **pull_mapping(24),
        **{f"{API}/pulls/{n}/reviews?per_page=100": slurp(reviews[n]) for n in mine},
    }
    run = runner_from_fixtures(mapping)
    for number in (229, 24):
        got = collect_facts(
            run, number, listings=listings, roster=COLLECT_ROSTER, mode="enforced", sweep=True,
            event_action=None, counter=CallCounter(),
        )
        assert got.author_record is True
    record_reads = [path for path in read_paths(run.calls) if re.search(r"/pulls/35[67]/reviews", path)]
    assert sorted(record_reads) == sorted(f"{API}/pulls/{n}/reviews?per_page=100" for n in mine)
    assert listings.approved_merged["login-1"] == frozenset({357})


def test_logins_are_casefolded_on_collection():
    pull = with_body("scrubbed")
    pull["user"]["login"] = "Login-1"
    reviews = fixture("reviews.json")
    for review_obj in reviews:
        if review_obj["user"] and review_obj["user"]["login"] == "login-13":
            review_obj["user"]["login"] = "LOGIN-13"
    timeline = fixture("timeline.json")
    for event in timeline:
        if event["event"] == "unlabeled" and event["actor"]["login"] == "login-13":
            event["actor"]["login"] = "Login-13"
    got, _ = collect(pull_mapping(pull=pull, reviews=reviews, timeline=timeline))
    assert got.author == "login-1"
    assert "login-13" in {review.login for review in got.reviews}
    assert got.last_unlabel[0] == "login-13"
    assert got.last_author_comment_at is not None


def test_fixtures_carry_no_email_or_url():
    email = re.compile(r"@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}")
    foreign = re.compile(r"https://(?!api\.github\.com/)")
    files = sorted(FIXTURES.glob("*.json"))
    assert len(files) >= 11
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not email.search(text), path.name
        assert not foreign.search(text), path.name
        assert "http://" not in text, path.name


# Applying a decision. The fake below serves scripted `-i` responses in order and records
# every argv with its stdin. It enforces the production allowlist the same way
# `runner_from_fixtures` does, so a test cannot pass on a write shape gh_runner refuses.

from pr_intake import Decision, WriteError, apply  # noqa: E402

OK = "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
COMMENT = pr_intake.render_data_line({"reason": "no_accepted"}) + "\n" + pr_intake.MARKER + "\n\nQueued."


def write_runner(*responses):
    calls: list[tuple[list[str], str | None]] = []
    queue = list(responses)

    def run(args, stdin=None):
        gh_runner._check_allowlist(args)
        calls.append((list(args), stdin))
        value = queue.pop(0) if queue else OK
        return value if isinstance(value, tuple) else (0, value, "")

    run.calls = calls
    return run


def decision(**overrides) -> Decision:
    base = dict(
        outcome="queue", route=None, reasons=("no_accepted",), label="keep", comment=None, data=None,
        disable_auto_merge=False, notices=(),
    )
    base.update(overrides)
    return Decision(**base)


def raw(status: int, reason: str, body: str, **headers) -> tuple[int, str, str]:
    lines = [f"HTTP/2.0 {status} {reason}"] + [f"{name.replace('_', '-')}: {value}" for name, value in headers.items()]
    return 1, "\r\n".join(lines) + "\r\n\r\n" + body, "gh: request failed"


def bot_comment(comment_id: int = 910003) -> BotComment:
    return BotComment(id=comment_id, body=COMMENT, data=parse_data_line(COMMENT), legacy=False)


def apply_with(run, f: Facts, d: Decision, **kwargs):
    sleeps: list[float] = []
    done = apply(run, f, d, sleep=sleeps.append, **kwargs)
    return done, sleeps


def test_apply_edits_existing_bot_comment_and_never_posts_twice():
    run = write_runner()
    done, _ = apply_with(run, facts(bot_comment=bot_comment()), decision(comment=COMMENT))
    assert done == ["comment_edit"]
    assert run.calls == [
        (["api", "-i", "-X", "PATCH", f"{API}/issues/comments/910003", "--input", "-"], json.dumps({"body": COMMENT}))
    ]


def test_apply_posts_when_no_bot_comment():
    run = write_runner(http({"id": 1}, 201))
    done, _ = apply_with(run, facts(), decision(comment=COMMENT))
    assert done == ["comment_post"]
    (args, stdin), = run.calls
    assert args == ["api", "-i", "-X", "POST", f"{API}/issues/354/comments", "--input", "-"]
    assert json.loads(stdin) == {"body": COMMENT}


def test_apply_writes_nothing_on_keep():
    for f, d in (
        (facts(), decision()),
        (facts(auto_merge=False), decision(disable_auto_merge=True)),
        (facts(auto_merge=True), decision(disable_auto_merge=False)),
    ):
        run = write_runner()
        assert apply_with(run, f, d) == ([], [])
        assert run.calls == []


def test_apply_order_is_comment_label_auto_merge():
    run = write_runner(OK, OK, (0, "", ""), http({"auto_merge": None}))
    f = facts(auto_merge=True, bot_comment=bot_comment())
    done, _ = apply_with(run, f, decision(comment=COMMENT, label="set", disable_auto_merge=True), pace=0)
    assert done == ["comment_edit", "label_set", "auto_merge_off"]
    assert [args for args, _ in run.calls] == [
        ["api", "-i", "-X", "PATCH", f"{API}/issues/comments/910003", "--input", "-"],
        ["api", "-i", "-X", "POST", f"{API}/issues/354/labels", "--input", "-"],
        ["pr", "merge", "354", "--disable-auto", "--repo", roadmap_model.REPO],
        ["api", "-i", f"{API}/pulls/354"],
    ]
    assert json.loads(run.calls[1][1]) == {"labels": [NEEDS_TRIAGE]}
    assert run.calls[2][1] is None and run.calls[3][1] is None


def test_apply_treats_404_on_label_delete_as_done():
    run = write_runner(raw(404, "Not Found", '{"message":"Label does not exist"}'))
    done, _ = apply_with(run, facts(labels=frozenset({NEEDS_TRIAGE})), decision(label="clear"))
    assert done == ["label_clear"]
    assert run.calls == [(["api", "-i", "-X", "DELETE", f"{API}/issues/354/labels/status%3Aneeds-triage"], None)]

    # A 404 anywhere else is a failure, and the error carries no response text.
    run = write_runner(raw(404, "Not Found", '{"message":"secret-ish text"}'))
    with pytest.raises(WriteError) as error:
        apply_with(run, facts(), decision(label="set"))
    assert str(error.value) == "label_set returned HTTP 404"


@pytest.mark.parametrize("status", [403, 429])
def test_apply_honors_retry_after_once_from_the_headers(status):
    refused = raw(status, "Forbidden", '{"message":"You have exceeded a secondary rate limit"}', Retry_After="7")
    run = write_runner(refused, http({"id": 1}, 201))
    done, sleeps = apply_with(run, facts(), decision(comment=COMMENT))
    assert done == ["comment_post"]
    assert sleeps == [7]
    assert len(run.calls) == 2 and run.calls[0] == run.calls[1]

    # The retry happens once. A second refusal raises, naming the write and the status only.
    run = write_runner(refused, refused, OK)
    with pytest.raises(WriteError) as error:
        apply_with(run, facts(), decision(comment=COMMENT))
    assert str(error.value) == f"comment_post returned HTTP {status}"
    assert len(run.calls) == 2

    # Without the header there is no retry at all.
    run = write_runner(raw(status, "Forbidden", '{"message":"nope"}'), OK)
    with pytest.raises(WriteError):
        apply_with(run, facts(), decision(comment=COMMENT))
    assert len(run.calls) == 1


def test_apply_raises_without_sleeping_on_a_primary_rate_limit():
    primary = raw(403, "Forbidden", '{"message":"API rate limit exceeded for installation ID 1."}', Retry_After="60")
    run = write_runner(primary, OK)
    with pytest.raises(WriteError) as error:
        apply_with(run, facts(), decision(comment=COMMENT, label="set"))
    assert str(error.value) == "rate_limit_primary"
    assert len(run.calls) == 1


def test_apply_paces_writes():
    run = write_runner(OK, OK, (0, "", ""), http({"auto_merge": {"merge_method": "squash"}}), (0, "", ""))
    f = facts(auto_merge=True)
    sleeps: list[float] = []
    done = apply(run, f, decision(comment=COMMENT, label="set", disable_auto_merge=True), pace=2.5, sleep=sleeps.append)
    assert done == ["comment_post", "label_set", "auto_merge_off", "converted_to_draft"]
    # Four writes, three gaps. The re-read between the last two is not a write.
    assert sleeps == [2.5, 2.5, 2.5]

    _, single = apply_with(write_runner(), facts(), decision(comment=COMMENT), pace=2.5)
    assert single == []


def test_apply_never_edits_a_contributor_comment_carrying_the_marker_or_the_legacy_prefix():
    contributor_ids = {910001, 910002}
    bot_ids = [c["id"] for c in fixture("comments.json") if c["user"]["login"] == roadmap_model.BOT_LOGIN]
    renamed = _comments_without(*[i for i in bot_ids if i != 910003])
    for comment in renamed:
        if comment["id"] == 910003:
            comment["user"]["login"] = "GitHub-Actions[bot]"

    for comments in (_comments_without(*bot_ids), renamed):
        got, _ = collect(pull_mapping(comments=comments))
        assert got.bot_comment is None
        run = write_runner(http({"id": 1}, 201))
        done, _ = apply_with(run, got, decision(comment=COMMENT))
        assert done == ["comment_post"]
        (args, _stdin), = run.calls
        assert args[3] == "POST" and args[4] == f"{API}/issues/229/comments"
        assert not any(str(i) in arg for arg in args for i in contributor_ids | {910003})


def test_apply_falls_back_to_draft_when_auto_merge_survives_the_disable():
    run = write_runner((0, "", ""), http({"auto_merge": {"merge_method": "squash"}}), (0, "", ""))
    done, _ = apply_with(run, facts(auto_merge=True), decision(disable_auto_merge=True))
    assert done == ["auto_merge_off", "converted_to_draft"]
    assert [args for args, _ in run.calls] == [
        ["pr", "merge", "354", "--disable-auto", "--repo", roadmap_model.REPO],
        ["api", "-i", f"{API}/pulls/354"],
        ["pr", "ready", "354", "--undo", "--repo", roadmap_model.REPO],
    ]

    run = write_runner((0, "", ""), http({"auto_merge": None}))
    done, _ = apply_with(run, facts(auto_merge=True), decision(disable_auto_merge=True))
    assert done == ["auto_merge_off"] and len(run.calls) == 2

    run = write_runner((1, "", "gh: some failure text"))
    with pytest.raises(WriteError) as error:
        apply_with(run, facts(auto_merge=True), decision(disable_auto_merge=True))
    assert str(error.value) == "auto_merge_off exited 1"
