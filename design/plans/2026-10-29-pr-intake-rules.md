# PR Intake Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

Version 2.0, 2026-10-29, rewritten after the plan premortem (six perspectives. Findings and resolutions in `design/2026-10-29-pr-intake-rules-premortem.md`, "Plan premortem").

Deviations from this plan are recorded in the design's Amendments section.

**Goal:** Replace the intake bot's two bash steps with one Python gate that queues pull requests no maintainer asked for, owns the queue label, lists the queue on the health issue, and returns to today's behavior when switched off.

**Architecture:** A pure `decide(facts, today)` in `tools/pr_intake.py` over a `Facts` record collected through a shared, allowlisted `gh` runner (`tools/gh_runner.py`) that never puts free text on argv. The workflow checks out the pull request's base ref and runs the tool on events, nightly, and on dispatch. `roadmap_sync.py` renders a queued section from the bot's own data lines. `monitor_roadmap.py` watches the nightly sweep. Every write the bot makes is reversible by a dispatch.

**Tech Stack:** Python 3 standard library only (`python3 -I -S`), GitHub Actions, `gh` CLI, pytest with the repository's stubbed-`gh` harness.

**Spec:** `design/2026-10-29-pr-intake-rules-design.md` v3.0, with the amendments the plan premortem made (listed in the premortem's "Plan premortem" section and applied to the spec in Task 11). Tracking issue #362.

## Global Constraints

- `tools/pr_intake.py` and `tools/gh_runner.py` import only the standard library and sibling modules under `tools/`. They run under `python3 -I -S`. Every pattern in them is linear with bounded repeats and no nested quantifiers, the rule `closing_choice.py` states for itself.
- `pr-intake.yml` keeps `permissions: {}` at the top. The job has `contents: read`, `pull-requests: write`, `issues: read`. No `${{ }}` inside any `run:` in any job. The pull request head is never checked out. The job carries `timeout-minutes: 20`.
- Nothing from a pull request (title, body, paths, logins) reaches `gh` argv, a `--jq` program, a shell, or a workflow command. Bodies go to `gh` on stdin as JSON. The allowlist never admits `-f`, `-F`, `--jq`, `-q`, `-t`, or `--template` in any position.
- Comment discovery is `user.login == roadmap_model.BOT_LOGIN` exactly, plus the marker `<!-- acs-intake -->`, or for a legacy comment the same login plus the legacy prefix. A comment by any other login is never a candidate.
- Every login the tool compares is casefolded on collection. `roadmap_model.trusted_logins` is already casefolded.
- The health section renders numbers, reason codes, dates, and days only. No contributor login, no fetched text. A data line with a reason outside `REASONS` or a malformed value is dropped and counted.
- `KNOWN_BOTS` (Dependabot and the Actions bot) and drafts are out of the gate's scope in both modes. Any other `type: Bot` author is evaluated as a non-roster author.
- Legacy mode (variables unset or tool SHA mismatch) writes on event runs only, for human authors, and only when no referenced issue is accepted, the editorial box is not ticked, and no bot comment exists. A legacy or dry-run sweep writes nothing.
- Cron `10 3 * * *`. The header comment says ordering before the 04:10 roadmap sweep is best effort under the scheduler delays this repository has measured. Concurrency expression exactly as in the spec.
- Prose follows STYLE.md: no em dashes, no semicolons, American English.
- Commits are signed off (`git commit -s`). Branch `fix/362-pr-intake-gate` from `origin/integration`, deleted after merge.
- File names as tracked: `.github/pull_request_template.md`, `tests/test_doc_links.py`. zizmor runs as CI does: `uv run --locked --only-group zizmor zizmor <files>`.

## Review Focus

1. A body whose only accepted reference is inside an HTML anchor to another repository (Dependabot changelog). Expected: not a reference. Pinned in Task 4.
2. A review whose `user` is null (deleted account) or whose `user.type` is `Bot`. Expected: skipped at collection, no crash. Pinned in Task 4.
3. A files listing of exactly 3,000 entries, or shorter than `changed_files`. Expected: queued with reason `paths_truncated`, never an editorial pass. Pinned in Task 3.
4. A legacy bot comment plus a contributor comment that copies the marker or the legacy prefix. Expected: the bot edits only its own comment. Pinned in Tasks 4 and 5.
5. The motivating example, PR #354: editorial box ticked, one path under `reference-implementations/`, `Refs #92` where the author commented on #92 two days earlier. Expected: queued with reason `editorial_off_lane`. Pinned in Task 3.

---

### Task 1: The shared gh runner

**Files:**
- Create: `tools/gh_runner.py`
- Modify: `tools/fetch_roadmap.py` (`_graphql` sends its body on stdin. `_runner` delegates with the import kept inside the function body so the deploy step's import guard at line 439 holds), `tools/roadmap_sync.py` (`GitHub.call_list(self, args, stdin=None)` passes `input=stdin`), `tests/test_fetch_roadmap.py` (`fake_run(args, stdin=None)` reads the query from `json.loads(stdin)["query"]`. The env assertion at line 259 becomes the six-key set)
- Test: `tests/test_gh_runner.py`

**Interfaces:**
- Produces: `GH = "/usr/bin/gh"`. `REPO` imported from `roadmap_model`. `class RunnerError(RuntimeError)`. `Runner = Callable[[list[str], str | None], tuple[int, str, str]]`. `make_runner(gh: str = GH, token: str | None = None) -> Runner` where `run(args, stdin=None)` passes `input=stdin`. `paginate(run: Runner, path: str) -> list` raising `RunnerError` on a non-zero exit, non-JSON output, or a page that is not a list. `split_http(stdout: str) -> tuple[int, dict[str, str], str]` lifted from `fetch_roadmap._split_http`. `remaining(run: Runner) -> int | None` reading `resources.core.remaining` from `("api", "rate_limit")` in Python.
- The allowlist is a tuple of argv shape tuples, each element a literal or a compiled pattern. Reads: `("api", "-i", PATH)`, `("api", "--paginate", "--slurp", PATH)`, `("api", "-i", RUNS_PATH)`, `("api", "rate_limit")`, `("api", "-i", "graphql", "--input", "-")`. Writes, every one with `-i` so the status line and headers return on stdout: `("api", "-i", "-X", "PATCH", COMMENT_PATH, "--input", "-")`, `("api", "-i", "-X", "POST", COMMENTS_PATH, "--input", "-")`, `("api", "-i", "-X", "POST", LABELS_PATH, "--input", "-")`, `("api", "-i", "-X", "DELETE", LABEL_PATH)`, `("pr", "merge", DIGITS, "--disable-auto", "--repo", REPO)`, `("pr", "ready", DIGITS, "--undo", "--repo", REPO)`. `PATH` matches `^repos/<REPO>/(pulls|issues)(/[0-9]{1,9})?(/(files|reviews|comments|timeline|labels))?(\?[A-Za-z0-9_=&%.-]*)?$` with `<REPO>` escaped. `RUNS_PATH` is `^repos/<REPO>/actions/workflows/pr-intake\.yml/runs\?[A-Za-z0-9_=&]*$`. `COMMENT_PATH` is `^repos/<REPO>/issues/comments/[0-9]{1,9}$`. `COMMENTS_PATH` is `^repos/<REPO>/issues/[0-9]{1,9}/comments$`. `LABELS_PATH` is `^repos/<REPO>/issues/[0-9]{1,9}/labels$`. `LABEL_PATH` is `^repos/<REPO>/issues/[0-9]{1,9}/labels/status%3Aneeds-triage$`. `DIGITS` is `^[0-9]{1,9}$`.
- The runner keeps `fetch_roadmap._runner`'s properties: absolute `gh`, env of exactly `{PATH, HOME, GH_TOKEN, GH_HOST, GH_PROMPT_DISABLED, GH_NO_UPDATE_NOTIFIER}`, `timeout=60`, the synthetic 401 without a token, failure tuples for timeout and a missing binary, and `_check_allowlist(args)` raising `RunnerError` before any subprocess.

- [ ] **Step 1: Write the failing tests**: `test_runner_refuses_argv_outside_the_allowlist`. `test_runner_refuses_free_text_flags_in_every_position` (parametrized over `-f`, `-F`, `--jq`, `-q`, `-t`, `--template` inserted at each index of an otherwise valid shape). `test_runner_passes_a_hostile_body_only_through_stdin` (fake `gh` records argv and stdin. The body carries `@x`, `-rf ../`, and `--jq`). `test_runner_env_is_minimal_and_never_echoes_stderr` (a 40-character token. The fake writes it to stderr. The caller's output carries only a class). `test_paginate_flattens_slurp_pages`. `test_paginate_raises_on_nonzero_exit_and_on_non_json`. `test_runner_without_token_returns_synthetic_401`. `test_graphql_shape_takes_its_body_on_stdin`. `test_remaining_reads_core_remaining_in_python`.
- [ ] **Step 2: Run `uv run pytest tests/test_gh_runner.py -v`. Expected: FAIL, module not found.**
- [ ] **Step 3: Implement `tools/gh_runner.py`.**
- [ ] **Step 4: Run the tests. Expected: PASS.**
- [ ] **Step 5: Move the roadmap fetch onto the runner**: `fetch_roadmap._graphql` sends `json.dumps({"query": query, "variables": {k: v for k, v in variables.items() if v is not None}})` on stdin with argv `["api", "-i", "graphql", "--input", "-"]`. `_runner` delegates to `make_runner` with `import gh_runner` inside its body. `roadmap_sync.GitHub.call_list` gains `stdin`. `tests/test_fetch_roadmap.py` line 259 becomes the six-key set and `fake_run` reads the query from stdin. Run `uv run pytest tests/test_fetch_roadmap.py tests/test_roadmap_sync_health.py -q`. Expected: PASS after those two test edits.
- [ ] **Step 6: Commit** `git add tools/gh_runner.py tests/test_gh_runner.py tools/fetch_roadmap.py tools/roadmap_sync.py tests/test_fetch_roadmap.py && git commit -s -m "Add an allowlisted gh runner that never puts free text on argv"`

### Task 2: Facts, Decision, reasons, and the data line

**Files:**
- Create: `tools/pr_intake.py` (data model and parsing only in this task)
- Test: `tests/test_pr_intake.py`

**Interfaces:**
- Produces, in `tools/pr_intake.py`:
  - `MARKER = "<!-- acs-intake -->"`, `DATA_PREFIX = "<!-- acs-intake-data "`, `LEGACY_PREFIX = "Thanks for this. It is queued rather than ignored."`, `LEGACY_KEYWORD_MARKER = "<!-- acs-closing-keyword"`, `KNOWN_BOTS = frozenset({"dependabot[bot]", "github-actions[bot]"})`, `RULE_LANDED: date` (a module constant set in the rollout commit, the `roadmap_model.RULES_VERSION` pattern), `MAX_REFERENCES = 20`, `MAX_CLAIM_READS = 5`, `MAX_CALLS = 600`, `BUDGET_RESERVE = 150`.
  - `REASONS = ("no_accepted", "closed_accepted", "not_held", "editorial_off_lane", "paths_truncated", "held_cap", "sent_back", "awaiting_rereview", "retracted")`. `CLEAR_ROUTES = ("roster", "review", "hand", "record", "editorial", "assignment", "help_wanted")`.
  - `@dataclass(frozen=True) class Reference: number: int; kind: str; is_pull: bool; state: str | None; labels: frozenset[str]; assignees: frozenset[str]; milestoned: bool; author_commented_at: datetime | None; unresolved: bool`
  - `@dataclass(frozen=True) class Review: login: str; state: str; association: str; submitted_at: datetime | None; commit_id: str | None`
  - `@dataclass(frozen=True) class BotComment: id: int; body: str; data: dict[str, str] | None; legacy: bool`
  - `@dataclass(frozen=True) class Facts:` number, state, draft, author (casefolded), author_is_bot, title, body, base, head_sha, created_at, updated_at, labels (frozenset), paths (tuple[str, ...]), paths_truncated (bool), references (tuple[Reference, ...]), references_dropped (int), reviews (tuple[Review, ...]), last_unlabel (tuple[str, datetime] | None, actor casefolded), last_author_comment_at (datetime | None), bot_comment (BotComment | None), auto_merge (bool), author_record (bool), held_use (dict[int, tuple[int, ...]], the author's open pull requests including this one that reference the issue, sorted ascending, for every referenced open accepted issue), roster (frozenset[str]), mode (str, "legacy" or "enforced"), sweep (bool), event_action (str | None).
  - `@dataclass(frozen=True) class Decision:` outcome ("pass", "queue", "skip"), route (str | None), reasons (tuple[str, ...]), label ("set", "clear", "keep"), comment (str | None), data (dict[str, str] | None), disable_auto_merge (bool), notices (tuple[str, ...]).
  - `parse_data_line(body: str) -> dict[str, str] | None` reads line 1 of the body only, matching `^<!-- acs-intake-data ((?:[a-z_]+=[A-Za-z0-9,._:-]+ ?){1,12})-->$`, keys `reason`, `route`, `issues`, `since`, `cleared`, `head`, `cleared_head`, `facts`, `claimed`, `seen`. `render_data_line(fields) -> str`. `facts_hash(facts: Facts, today: date) -> str` (12 hex of sha256 over every field `decide` reads plus the derived booleans `engaged_by_fresh_review` and `editorial_ticked`). `editorial_ticked(body: str) -> bool` defined as `bool(closing_choice.EDITORIAL.search(closing_choice.normalize(body)))`. `safe_path(path: str) -> str` as `re.sub(r"[^A-Za-z0-9._/-]", "?", path)[:200]`.
  - `claimed` is empty or a comma list of `<issue>:<YYYY-MM-DD>`. `seen` is `<pull updated_at>,<max updated_at of the referenced accepted issues from the listings>`.

- [ ] **Step 1: Write the failing tests**: `test_data_line_round_trips`. `test_parse_data_line_reads_line_one_only` (a well-formed line on line 3 with `since=2020-01-01` is ignored). `test_data_line_rejects_bad_shapes` (a space or `>` in a value, an unknown key). `test_facts_hash_changes_with_references_and_with_a_review_crossing_thirty_days_not_with_updated_at`. `test_editorial_ticked_agrees_with_closing_choice_on_the_template_line`. `test_safe_path_replaces_backtick_marker_and_at`.
- [ ] **Step 2: Run them. Expected: FAIL.**
- [ ] **Step 3: Implement the dataclasses and the functions.**
- [ ] **Step 4: Run them. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Add the intake tool's facts, decision, and data line"`

### Task 3: The gate: `decide`

**Files:**
- Modify: `tools/pr_intake.py`
- Test: `tests/test_pr_intake.py`

**Interfaces:**
- Produces: `decide(facts: Facts, today: date) -> Decision`. `unmet_routes(facts, today) -> tuple[str, ...]`. `render_comment(facts, decision, today) -> str`. `GATE_ORDER = ("bot", "roster", "engaged", "record", "editorial", "held", "help_wanted")`.
- Consumes: `closing_choice.parse_references`, `closing_choice.EDITORIAL`, `closing_choice.normalize`, `base_branch_guard.in_docs_lane`, `roadmap_model.NEEDS_TRIAGE`.
- Routes, in order. `bot`: `facts.author in KNOWN_BOTS` or `facts.draft` skips (no label, no comment). `roster`: `facts.author in facts.roster` passes. `engaged`: an `APPROVED` review by a roster login with association in `{"OWNER", "MEMBER", "COLLABORATOR"}` (dismissed reviews are absent from `facts.reviews`), or a `CHANGES_REQUESTED` by such a login with `submitted_at >= today - 30 days`, or a hand clear that stands: `last_unlabel` by a roster login and `bot_comment.data["cleared_head"] == facts.head_sha`. On the evaluation that first sees a roster unlabel with no `cleared_head` recorded, the decision records `cleared_head=facts.head_sha` and passes. `record`: `facts.author_record`. `editorial`: `editorial_ticked(body)` and every path on the lane and `not paths_truncated` passes. `editorial_ticked(body)` with any path off the lane queues with `editorial_off_lane` naming the paths, before routes `held` and `help_wanted` are read (the motivating example). `editorial_ticked(body)` with `paths_truncated` queues with `paths_truncated`. `held`: a referenced open accepted issue with the author in `assignees`, and this pull request's number among the two lowest in `held_use[n]`. A third queues with `held_cap` naming the two. `help_wanted`: a referenced open accepted issue carrying `help wanted` with `author_commented_at < facts.created_at`, under the same two-lowest rule from `held_use`.
- A `CHANGES_REQUESTED` older than 30 days with no newer roster review yields `awaiting_rereview` when the author pushed (`head_sha` differs from the review's `commit_id`) or commented after it (`last_author_comment_at` later than the review), else `sent_back`.
- `disable_auto_merge` is true whenever `facts.auto_merge`, the author is not on the roster, and `parse_references(title, body)` yields a `close` on an open milestoned issue, on every event. The comment then carries "Auto-merge is off because this pull request closes roadmap issue #n. A lead merges it by hand after confirming delivery."
- The short circuit: when the data line's `facts` equals `facts_hash(facts, today)` and its `reason` equals the new decision's first reason, `label` is `keep` and `comment` is `None`. A changed `(outcome, reasons)` always renders. `since` carries forward from the data line while the outcome stays `queue` and resets on a clear. A clear writes `reason=cleared route=<route> cleared=<date>`.
- Legacy mode: `label` is `set` and a comment renders only when all hold: `not facts.sweep`, no referenced issue carries `status:accepted` in any state, `editorial_ticked(body)` is false, `facts.bot_comment is None`, the author is not in `KNOWN_BOTS`. Otherwise `label` is `keep`, `comment` is `None`, and `notices` carry the would-do lines. Legacy never clears a label.
- Comment text: the spec's wording per unmet route, one paragraph per route. The claim line reads "You commented on #a on <date>. If that was a claim, it is waiting on a lead.", the queued line, the keyword warning, the new-rule line for pull requests opened before `RULE_LANDED`. Paths through `safe_path`, wrapped in backticks, at most 20. "and N more" when `references_dropped`. The data line is line 1 and the marker line 2. The whole comment cut at 8,000 characters.

- [ ] **Step 1: Write the failing tests**, each through a `facts(**overrides)` helper (defaults: non-roster author `outsider`, no references, enforced mode, roster `{"rocklambros", "lrd0036"}`):

```python
def test_known_bot_author_is_out_of_scope(): ...
def test_unknown_bot_author_is_evaluated_as_non_roster(): ...
def test_draft_is_skipped(): ...
def test_roster_author_passes_case_insensitively(): ...          # author "Lrd0036" stored casefolded
def test_approved_review_by_roster_collaborator_passes(): ...
def test_approved_review_by_roster_login_without_role_does_not_count(): ...
def test_commented_reviews_do_not_count(): ...
def test_changes_requested_at_29_days_passes_and_at_31_days_is_sent_back_or_awaiting(): ...
def test_push_after_changes_requested_is_awaiting_rereview_not_sent_back(): ...
def test_hand_clear_records_the_head_and_holds_while_it_matches(): ...
def test_hand_clear_stops_holding_when_the_head_sha_changes(): ...
def test_hand_clear_by_non_roster_is_reversed(): ...
def test_author_merged_record_passes(): ...
def test_editorial_on_the_docs_lane_passes(): ...
def test_editorial_off_lane_queues_naming_sanitized_paths(): ...
def test_motivating_example_queues(): ...                          # Review Focus 5
def test_truncated_paths_queue_with_their_own_reason_and_never_pass_editorial(): ...  # Review Focus 3
def test_first_two_pull_requests_on_a_held_issue_pass_and_the_third_queues(): ...
def test_first_two_pull_requests_on_a_help_wanted_issue_pass_and_the_third_queues(): ...
def test_issue_author_without_assignment_queues(): ...
def test_help_wanted_with_prior_comment_passes_and_without_queues(): ...
def test_help_wanted_comment_after_open_does_not_count(): ...
def test_closed_accepted_reference_gets_its_own_reason(): ...
def test_reference_to_a_pull_request_number_is_not_an_issue(): ...
def test_body_failing_two_routes_renders_both_paragraphs(): ...
def test_prior_comment_is_named_as_possibly_waiting(): ...
def test_legacy_mode_matches_todays_three_exits(): ...
def test_legacy_sweep_writes_nothing(): ...
def test_pre_rule_pull_request_comment_says_the_rule_is_new(): ...
def test_keyword_warning_present_when_a_closing_keyword_names_a_milestoned_issue(): ...
def test_auto_merge_disabled_whenever_on_for_a_non_roster_milestoned_close(): ...
def test_unchanged_facts_keep_label_and_comment(): ...
def test_hash_short_circuit_cannot_hide_a_changed_decision(): ...  # parametrized over every Facts field and today at 29 and 31 days
def test_since_survives_a_rerender_and_resets_on_clear(): ...
def test_render_comment_contains_one_html_comment_pair_and_no_at_sign(): ...  # hostile paths carrying a backtick, <!--, @, #1
def test_decide_matches_the_recorded_population(): ...            # tests/fixtures/pr_intake/population.json from Task 4
```

- [ ] **Step 2: Run them. Expected: FAIL.**
- [ ] **Step 3: Implement `unmet_routes`, `render_comment`, `decide`.**
- [ ] **Step 4: Run them. Expected: PASS (the population test after Task 4 records the fixture).**
- [ ] **Step 5: Commit** `git commit -s -m "Decide the intake gate from facts a lead performed"`

### Task 4: Collecting facts

**Files:**
- Modify: `tools/pr_intake.py`
- Create: `tests/fixtures/pr_intake/scrub.py` and the scrubbed fixtures `pull.json`, `files_page1.json`, `files_page2.json`, `reviews.json` (one `"user": null` entry, one `type: Bot` entry), `comments.json` (a bot comment, a legacy bot comment, a contributor comment copying the marker, a contributor comment starting with the legacy prefix), `timeline.json` (one `committed` event with no `created_at`, one `head_ref_force_pushed`, one `unlabeled` by a roster login, one `unlabeled` by `BOT_LOGIN`), `issue_comments.json`, `pulls_open.json`, `pulls_closed.json`, `accepted_all.json`, `population.json` (the 56 live open pull requests' gate-relevant facts with logins and numbers replaced and no text, with expected `(outcome, route, reasons)`, generated by a recorded script named in the file header)
- Test: `tests/test_pr_intake.py`

**Interfaces:**
- Produces: `@dataclass class Listings: accepted: dict[int, dict]; milestoned: dict[int, dict]; open_pulls: list[dict]; merged_pulls: list[dict]; approved_merged: dict[str, frozenset[int]]` with `load_listings(run) -> Listings` reading `issues?labels=status%3Aaccepted&state=all&per_page=100`, the milestoned issues, `pulls?state=open&per_page=100`, and `pulls?state=closed&sort=updated&direction=desc&per_page=100` filtered to `merged_at` not null, each through `paginate`. `approved_merged` is built lazily per author with one `pulls/{n}/reviews` read per merged pull request by that author and cached on the instance. `class ListingError(RuntimeError)` wrapping a `RunnerError` from a shared listing.
- `collect_facts(run: Runner, number: int, *, listings: Listings, roster: frozenset[str], mode: str, sweep: bool, event_action: str | None, counter: CallCounter) -> Facts` where `CallCounter` counts runner calls and raises `BudgetStop` past `MAX_CALLS`.
- Behavior: every per-pull-request list uses `paginate`. `files` is truncated when `len == 3000` or `len < pull["changed_files"]`. The body is cut at `closing_choice.MAX_CHARS`. Anchors whose `href` host is not `github.com/<REPO>` are stripped with bounded patterns (`<a\s[^<>]{0,2048}>` and `</a\s*>`, no `DOTALL`, no `.*?`). References are deduplicated and cut to the first `MAX_REFERENCES` distinct numbers in document order, title first, the rest counted in `references_dropped`. A reference is resolved against the listings only, never through `issues/{m}`: `is_pull` when its number is in `open_pulls` or `merged_pulls`, `state` and labels from `accepted` or `milestoned`, `unresolved` when in none. `issues/{n}/comments` is read only for a referenced open accepted issue that does not list the author in `assignees`, at most `MAX_CLAIM_READS` per pull request. `author_commented_at` is the earliest comment by the author on that issue. `last_author_comment_at` is the newest comment by the author on the pull request. Reviews with a null `user` or `user.type == "Bot"` are skipped at collection, dismissed reviews dropped, logins casefolded. `last_unlabel` is `(actor.login, created_at)` of the newest `unlabeled` event for `status:needs-triage`, and `author.date` and `committer.date` are never read. `held_use` is filled from `open_pulls` bodies through `parse_references`. The bot comment is the first comment with `user.login == BOT_LOGIN` exactly carrying the marker, else the first with that login starting with `LEGACY_PREFIX` or containing `LEGACY_KEYWORD_MARKER` (`legacy=True`). Dates parse with `datetime.fromisoformat(v.replace("Z", "+00:00"))`.

- [ ] **Step 1: Write the failing tests** against the fixtures through a `runner_from_fixtures(mapping)` stub that counts calls: `test_collect_paginates_files_and_flags_truncation`. `test_changelog_anchor_is_not_a_reference` (Review Focus 1). `test_sixty_four_kilobyte_anchor_body_parses_under_one_second`. `test_pull_request_numbers_are_marked_is_pull_from_the_pulls_listings_never_by_keyword`. `test_closed_accepted_issue_is_collected_as_closed_not_as_a_pull_request`. `test_collect_makes_at_most_twelve_calls_whatever_the_body` (1,000 distinct references). `test_collect_reads_claim_comments_only_for_open_accepted_unassigned_references_and_at_most_five`. `test_collect_skips_null_review_users_and_bot_reviewers` (Review Focus 2). `test_timeline_facts_read_the_roster_unlabel_and_never_commit_dates`. `test_bot_comment_found_by_exact_login_and_marker_only` (Review Focus 4). `test_legacy_prefix_in_a_contributor_comment_is_not_adopted`. `test_legacy_bot_comment_is_adopted`. `test_listing_failure_raises_ListingError`. `test_author_record_reads_reviews_once_per_merged_pull`. `test_logins_are_casefolded_on_collection`. `test_fixtures_carry_no_email_or_url` (no `@` followed by a dotted domain and no `https://` outside `api.github.com` in any fixture file).
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Implement `load_listings`, `collect_facts`, the scrub script, and record the fixtures.** The scrub replaces `email`, `name`, `message`, `title`, `body`, `html_url`, `avatar_url`, `url`, and every `login` with fixed strings at any depth.
- [ ] **Step 4: Run `uv run pytest tests/test_pr_intake.py -q`. Expected: PASS, the population test included.**
- [ ] **Step 5: Commit** `git commit -s -m "Collect intake facts from the shared listings within a call budget"`

### Task 5: Applying a decision

**Files:**
- Modify: `tools/pr_intake.py`
- Test: `tests/test_pr_intake.py`

**Interfaces:**
- Produces: `apply(run: Runner, facts: Facts, decision: Decision, *, pace: float = 1.0, sleep=time.sleep) -> list[str]` returning the writes made (`"comment_edit"`, `"comment_post"`, `"label_set"`, `"label_clear"`, `"auto_merge_off"`, `"converted_to_draft"`). `class WriteError(RuntimeError)`.
- Order: comment, then label, then auto-merge. Each write's status line is read with `split_http`. A `DELETE` label returning 404 is success. A 403 or 429 whose headers carry `Retry-After` sleeps that many seconds once and retries. A 403 whose body says `API rate limit exceeded` raises `WriteError("rate_limit_primary")` without sleeping. The auto-merge write runs `pr merge --disable-auto`, re-reads `pulls/{n}`, and when `auto_merge` is still non-null runs `pr ready --undo` and records `"converted_to_draft"`. The bot never edits a comment whose author is not `BOT_LOGIN`. Comment bodies are JSON on stdin.

- [ ] **Step 1: Write the failing tests**: `test_apply_edits_existing_bot_comment_and_never_posts_twice`. `test_apply_posts_when_no_bot_comment`. `test_apply_writes_nothing_on_keep`. `test_apply_order_is_comment_label_auto_merge`. `test_apply_treats_404_on_label_delete_as_done`. `test_apply_honors_retry_after_once_from_the_headers`. `test_apply_raises_without_sleeping_on_a_primary_rate_limit`. `test_apply_paces_writes`. `test_apply_never_edits_a_contributor_comment_carrying_the_marker_or_the_legacy_prefix`. `test_apply_falls_back_to_draft_when_auto_merge_survives_the_disable`.
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Implement `apply`.**
- [ ] **Step 4: Run. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Apply intake decisions with paced, reversible writes"`

### Task 6: Modes, arming, the sweep, retract, and `main`

**Files:**
- Modify: `tools/pr_intake.py`
- Test: `tests/test_pr_intake.py`

**Interfaces:**
- Produces: `ARMED_MODULES = ("tools/pr_intake.py", "tools/gh_runner.py", "tools/closing_choice.py", "tools/base_branch_guard.py", "tools/roadmap_model.py")`. `tool_sha(repo: Path) -> str` (sha256 over the concatenated git blob SHAs of the five modules, in that order, 40 hex). `arming(env, repo) -> str` returning `"enforced"` when `PR_INTAKE_ENFORCED == "true"` and `PR_INTAKE_TOOL_SHA == tool_sha(repo)`, `"mismatched"` when enforced is requested and the SHA differs, else `"legacy"`. `evaluate_one(run, number, *, listings, roster, mode, today, sweep, event_action, counter, write: bool) -> tuple[Decision, list[str]]`. `run_sweep(run, numbers, *, mode, write, ...) -> Summary` with `@dataclass class Summary: mode: str; tool_sha: str; evaluated: int; newly_queued: int; queued_total: int; cleared: int; unchanged: int; skipped: int; out_of_scope: int; errors: list[tuple[int, str]]; writes: int; calls: int; rate_limit_remaining: int | None` and the identity `evaluated == newly_queued + cleared + unchanged + skipped + out_of_scope + len(errors)`. `retract(run, numbers, *, authors: str) -> Summary`. `main(argv=None) -> int` accepting `--gh PATH` (tests only, default `GH`).
- `main` reads `PR_NUMBER`, `INTAKE_MODE` (`evaluate`, `dryrun`, or `retract`), `INTAKE_AUTHORS` (`all` or `bots`), `EVENT_NAME`, `EVENT_ACTION`, `GITHUB_STEP_SUMMARY`, `PR_INTAKE_ENFORCED`, `PR_INTAKE_TOOL_SHA`. Event runs: a `ListingError`, a per-pull-request `RunnerError`, or a `WriteError` other than the auto-merge write prints `::notice::` and returns 0. The auto-merge write's failure prints `::error::` and returns 1. On `synchronize`, when `editorial_ticked(body)` is false after reading the pull alone, the run prints a notice and returns 0 before loading listings. Sweeps (`schedule` or `workflow_dispatch` without `PR_NUMBER`): bots and drafts are filtered from the listing before collection and counted `out_of_scope`. The bot comment and the pull are read first, and when the data line's `seen` matches and the label state matches the reason the pull request is `unchanged` and nothing else is read. `remaining(run)` is read before the loop and after every ten evaluations, and below `BUDGET_RESERVE`, or past `MAX_CALLS`, the loop stops, the rest are counted `skipped`, and the run returns 1. Per-pull-request errors go to `Summary.errors` as `::error::#n: <class>` and the run returns 1 when any. The summary line begins `mode=<enforced|legacy|mismatched> tool_sha=<12 hex>` and is appended to the step summary. Batching applies on any sweep: an author with more than three newly queued pull requests gets the full comment on the newest and `"Queued for the reason given on PR #n."` plus the data line on the rest. A sweep in `mismatched` mode runs the legacy pass, prints `::error::PR_INTAKE_TOOL_SHA does not match the armed modules on this ref; dry-sweep and re-arm, or unset PR_INTAKE_ENFORCED`, and returns 1. Event runs in `mismatched` mode run legacy and return 0. `dryrun` runs the enforced logic with `write=False`, prints every decision, and prints `arm with PR_INTAKE_TOOL_SHA=<value>`. A legacy sweep writes nothing. Staleness guard: before `apply`, re-read `updated_at` and skip when it moved. `retract` refuses when `arming` returns `"enforced"` (`::error::Unset PR_INTAKE_ENFORCED before retracting`, return 1), otherwise removes the queue label from every open pull request whose bot comment carries the marker (or, with `authors=bots`, from every open pull request by a `KNOWN_BOTS` author, comment or not), edits any bot comment to the data line `reason=retracted since=<date>`, the marker, and "Retracted. This pull request is not queued."

- [ ] **Step 1: Write the failing tests**: `test_arming_requires_both_variables_and_changes_when_any_of_the_five_modules_changes`. `test_sweep_summary_identity_holds`. `test_sweep_fails_red_on_a_listing_failure_and_on_a_per_pull_error`. `test_event_run_exits_zero_on_read_failure_and_writes_nothing`. `test_event_run_is_red_when_auto_merge_disable_fails`. `test_synchronize_without_the_box_short_circuits`. `test_sweep_skips_a_pull_request_changed_during_the_sweep`. `test_sweep_reads_only_the_comment_and_the_pull_for_an_unchanged_pull_request`. `test_sweep_stops_at_the_budget_reserve_and_is_red`. `test_scheduled_sweep_is_red_when_enforcement_is_requested_but_unarmed`. `test_summary_line_names_the_mode`. `test_dryrun_writes_nothing_and_prints_every_decision_and_the_arm_value`. `test_retract_refuses_while_enforced`. `test_retract_keeps_the_marker_so_the_next_queue_edits_not_posts`. `test_retract_scoped_to_bots_touches_only_known_bots`. `test_any_sweep_batches_an_author_with_many_queues`. `test_roster_unparsable_produces_zero_writes_and_a_warning`. `test_sweep_over_the_population_reports_the_expected_summary`.
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `uv run pytest tests/test_pr_intake.py -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Run the intake gate on events, nightly, and on dispatch, with arming, dry run, and retract"`

### Task 7: The workflow

**Files:**
- Modify: `.github/workflows/pr-intake.yml` (rewrite)
- Modify: `tests/test_pr_intake_workflow.py` (rewrite. The old bash-step tests go except `test_accepted_lookup_is_one_call_whatever_the_body`, which is carried over as a tool test)

**Interfaces:**
- The workflow: `on: pull_request_target: types: [opened, edited, reopened, ready_for_review, synchronize, unlabeled, auto_merge_enabled]`, `pull_request_review: types: [submitted, dismissed]`, `schedule: - cron: "10 3 * * *"`, `workflow_dispatch: inputs: pr_number (string, optional), mode (choice evaluate|dryrun|retract, default evaluate), authors (choice all|bots, default all)`. `permissions: {}`. `concurrency` as the spec. One job `intake` named "PR intake" with `timeout-minutes: 20`, `permissions: contents: read, pull-requests: write, issues: read` (each commented). `if:` restricting pull request events to a base of `main`, `integration`, or `release/*`, and `edited` to a change of body, title, or base: `github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || ((github.event.pull_request.base.ref == 'main' || github.event.pull_request.base.ref == 'integration' || startsWith(github.event.pull_request.base.ref, 'release/')) && (github.event.action != 'edited' || github.event.changes.body || github.event.changes.title || github.event.changes.base))`. Steps: checkout `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` with `persist-credentials: false` and `ref: ${{ github.event.pull_request.base.ref || 'integration' }}`. One run step with `env`: `GH_TOKEN`, `PR_NUMBER: ${{ github.event.pull_request.number || inputs.pr_number }}`, `INTAKE_MODE: ${{ inputs.mode || 'evaluate' }}`, `INTAKE_AUTHORS: ${{ inputs.authors || 'all' }}`, `EVENT_NAME: ${{ github.event_name }}`, `EVENT_ACTION: ${{ github.event.action }}`, `PR_INTAKE_ENFORCED: ${{ vars.PR_INTAKE_ENFORCED }}`, `PR_INTAKE_TOOL_SHA: ${{ vars.PR_INTAKE_TOOL_SHA }}`. `run: python3 -I -S tools/pr_intake.py`. The header comment says the job checks out the pull request's base ref, never the head. `main`, `integration`, and `release/*` are ruleset-protected and the `if:` admits no other base.
- The harness: `run_tool(tmp_path, env, state)` executes `[sys.executable, "-I", "-S", "tools/pr_intake.py", "--gh", fake]` with the step's `env` block as the environment and a fake `gh` serving the recorded fixtures. `test_run_line_is_exactly_this` asserts the YAML `run:` is `python3 -I -S tools/pr_intake.py` with no `--gh`.

- [ ] **Step 1: Write the failing workflow tests**: `test_triggers_and_cron`. `test_cron_runs_before_the_roadmap_sweep`. `test_checkout_is_the_base_ref_never_the_head`. `test_base_ref_guard_admits_only_protected_branches`. `test_permissions_are_exactly_these`. `test_job_has_a_twenty_minute_timeout`. `test_concurrency_expression`. `test_no_step_interpolates_into_run_in_any_job`. `test_edited_guard_covers_body_title_and_base`. `test_step_env_is_exactly_this`. `test_run_line_is_exactly_this`. `test_run_tool_against_fixtures_queues_and_comments`. `test_sweep_pages_thirty_five_stubbed_pull_requests`. `test_one_failed_evaluation_makes_the_sweep_red_with_its_error_line`. `test_event_run_read_failure_exits_zero_with_no_write`. `test_accepted_lookup_is_one_call_whatever_the_body` (carried over).
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Rewrite `pr-intake.yml` and the harness.**
- [ ] **Step 4: Run `uv run pytest tests/test_pr_intake_workflow.py tests/test_closing_choice_workflow.py -q` and `uv run --locked --only-group zizmor zizmor .github/workflows/pr-intake.yml`. Expected: PASS. Zizmor clean.**
- [ ] **Step 5: Commit** `git commit -s -m "Run the intake gate from one workflow step on a protected base ref"`

### Task 8: The health issue's queued section

**Files:**
- Modify: `tools/roadmap_sync.py` (`SECTION_TITLES`, `_snapshot`, `build_report`, `render_health`, the exclusion tuple at line 503), `.github/workflows/roadmap-sync.yml` (the `sweep` and `dryrun` jobs gain `actions: read` commented `# Lists the intake sweep's runs for the health issue's queued section.`, and the step `env` gains `PR_INTAKE_BASELINES: ${{ vars.PR_INTAKE_BASELINES }}`)
- Test: `tests/test_roadmap_sync_health.py`, `tests/test_roadmap_sync_workflow.py` (lines 54 and 55)

**Interfaces:**
- `SECTION_TITLES` gains `("queued_pulls", "Queued pull requests", "Open pull requests the intake gate holds, by reason, with how long each has waited. Numbers only; the search link lists authors. This tool runs from main and reports nothing until promotion.")`, placed before `promotion`.
- `_snapshot` keeps its signature. Inside its own `try/except SyncError` that appends `"queued_pulls"` to `failed`: `snapshot["queued_pulls"]` as `[[number, reason, since, claimed, created_at], ...]` for every open issue-listing item with a `pull_request` key and the `status:needs-triage` label, from the bot's data line read from `issues/{n}/comments` where `user.login == BOT_LOGIN` (a labeled pull request with no bot data line is recorded as `[number, None, None, "", created_at]`). `snapshot["intake_sweep"]` as `[conclusion, run_id, created_at]` from `gh.get("actions/workflows/pr-intake.yml/runs?event=schedule&status=completed&per_page=1")["workflow_runs"]`, never through `paginate`. `snapshot["intake_recent"]` as `[[number, author_is_trusted, data_line_route, merged_at], ...]` for pull requests closed in the last 120 days, from `pulls?state=closed&sort=updated&direction=desc&per_page=100` and their bot data lines.
- `build_report` fills `report["queued_pulls"]` with `[number, reason, days, claimed]` sorted by days descending (`days` from `created_at`), `report["queued_unrecorded"]` with the numbers that carry the label and no data line, `report["queued_meta"]` with the sweep triple, and `report["intake_counts"]` with `median_age_days`, `hand_cleared_60d` (data lines whose `route` is `hand`), `non_roster_merges_60d`, `non_roster_merges_prior_60d`, `claims_waiting` (counted once per author and issue). A data line whose `reason` is not in `REASONS` or whose `since` is not an ISO date is dropped and counted in `report["queued_unreadable"]`. `"queued_pulls"` and `"intake_recent"` join the exclusion tuple at line 503.
- `render_health` renders: the sweep line (`the nightly intake sweep run <id> concluded <conclusion>` or "no completed scheduled run"). The counts line with the baseline from `PR_INTAKE_BASELINES` (`recorded=YYYY-MM-DD median_age=N hand_cleared_60d=N non_roster_merges_60d=N`) or "baseline not recorded. A project lead sets PR_INTAKE_BASELINES", and when recorded "Review due <recorded + 60 days>: if claims waiting rose or non-roster merges fell against the prior 60 days, a project lead sets PR_INTAKE_ENFORCED=false". "Claims waiting on a lead" as `- #<issue>: commented <N> days ago by the author of PR #<n>` sorted by days descending with "(14 days or more)" where it applies, and the note "Any comment by the author before the pull request counts, so read the issue before acting.", then `- #n: <reason>, N days` grouped by reason, with "Queued more than 30 days", "Awaiting re-review", "Sent back, no response", and "Labeled without a gate record" as sub-lists. One line `[All queued pull requests with authors](https://github.com/<REPO>/pulls?q=is%3Apr+is%3Aopen+label%3Astatus%3Aneeds-triage)`.

- [ ] **Step 1: Write the failing tests**: extend `SNAPSHOT`. `test_queued_section_renders_numbers_reasons_days_only` (a queued pull by `outsider`: `"outsider" not in body`). `test_queued_section_ignores_a_data_line_from_anyone_but_the_bot`. `test_queued_section_drops_a_malformed_data_line`. `test_queued_headings_for_thirty_days_awaiting_sent_back_and_unrecorded`. `test_claims_counted_once_per_author_and_issue`. `test_hand_cleared_counts_the_route_not_the_merge`. `test_baseline_line_when_unset_and_when_set`. `test_intake_read_failure_degrades_one_section`. `test_sections` gains the assertion. `test_render_never_leaks_titles_or_mentions` keeps passing. The workflow test pins the permission and the env key.
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Implement**, importing `pr_intake.parse_data_line`, `pr_intake.MARKER`, `pr_intake.REASONS`.
- [ ] **Step 4: Run `uv run pytest tests/test_roadmap_sync_health.py tests/test_roadmap_sync_workflow.py -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "List the intake queue on the health issue, numbers and reasons only"`

### Task 9: The monitor watches the nightly sweep

**Files:**
- Modify: `tools/monitor_roadmap.py`, `.github/workflows/monitor-roadmap.yml` (`actions: read` on the job with a comment. The step `env` gains `PR_INTAKE_ENFORCED: ${{ vars.PR_INTAKE_ENFORCED }}` and `PR_INTAKE_TOOL_SHA: ${{ vars.PR_INTAKE_TOOL_SHA }}`. The job `if` gains `|| vars.PR_INTAKE_ENFORCED == 'true'`), `tests/test_monitor_roadmap.py`

**Interfaces:**
- `check_intake(runs: list | None, now: datetime) -> list[str]`: a problem when no completed scheduled run exists, the latest is older than 30 hours, or its conclusion is not `success`, named `the nightly intake sweep run <id> concluded <conclusion>`. `cancelled` and `skipped` are named as such. `CHECK_NAMES["intake"] = "the nightly intake sweep"`. `evaluate(env, *, read_json, read_issue, now, read_runs=lambda: None)` runs the check when `env.get("PR_INTAKE_ENFORCED") == "true"`. `_read_runs()` calls `repos/<REPO>/actions/workflows/pr-intake.yml/runs?event=schedule&status=completed&per_page=1` through the shared runner. `post` and `_gh` stay on the monitor's own subprocess call, unchanged, because their `-f body=` shape must not enter the allowlist. A comment in the module says the monitor runs from `main` and sees nothing until promotion.

- [ ] **Step 1: Write the failing tests**: `test_check_intake` parametrized over missing, stale, failure, cancelled, success, and an in-progress latest run being ignored. `test_evaluate_runs_intake_only_when_enforced`. `test_evaluate_reads_enforced_from_env` (asserts `read_runs` was called). `test_monitor_workflow_passes_the_intake_switch`. Update `test_monitor_workflow_is_exactly_this` with the permission, the two env lines, and the `if`.
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `uv run pytest tests/test_monitor_roadmap.py -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Have the roadmap monitor raise the lead alarm when the intake sweep fails"`

### Task 10: The contributor-facing text and its guards

**Files:**
- Modify: `CONTRIBUTING.md`, `README.md`, `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/3-reference-implementation.yml`, `GOVERNANCE.md`, `.github/CODEOWNERS` (header), `tools/apply_governance.py` (lines 302 to 305, the `help wanted` seed), `tests/test_doc_links.py` (`CONTRIBUTING.md` joins `ROOT_MARKDOWN_FILES`)
- Test: `tests/test_pull_request_template.py`, new `tests/test_intake_prose_guard.py`, `tests/test_governance_files.py`

**Interfaces:**
- CONTRIBUTING "How work gets accepted": replace lines 61 to 64 (the editorial paragraph) and 70 to 74 (the waiting paragraph). Keep lines 59 and 66 to 68 verbatim (`tests/test_pull_request_template.py::test_contributing_explains_the_choice` pins line 67). The replacement, verbatim, one sentence per route in `GATE_ORDER` order after `bot`:

  > If you are a project lead, a workstream lead, or a code owner, your pull requests are not queued. A lead's approval, or a lead's request for changes within the last 30 days, clears the queue. If a lead has approved and merged a pull request of yours before, your pull requests are not queued. An editorial fix to a page under `docs/topics/` or `design/` (a typo, a link, formatting, no change in meaning) needs no issue: tick the editorial box in the pull request template, and keep every changed file on that lane. Otherwise the pull request needs an accepted issue that a lead assigned to you. Comment on the issue to claim it before opening the pull request. The comment is the claim, and a lead assigns you. An issue labeled `help wanted` is open to anyone who commented on it before opening the pull request, two open pull requests per person per issue. A pull request that meets none of these waits with the `status:needs-triage` label and a bot comment naming the missing step. It is not closed. If a form, a template, or a bot comment disagrees with this section, this section wins.

- CONTRIBUTING "What We Need": drop "which means you can open a pull request against it without waiting on triage" and say: `Comment on one to claim it, then open the pull request. The comment is the claim.` README's acceptance paragraph says the same and keeps `[Triage authority](./GOVERNANCE.md#triage-authority)` verbatim (`tests/test_governance_files.py::test_front_door_defers_to_triage_authority`). The mermaid flow gains the claim step.
- The template checkbox line: `- [ ] This is an editorial correction on the documentation lane (typo, grammar, link, formatting) with no change in meaning, so it needs no issue`. The template comment's second paragraph reads exactly: "A change that alters behavior, normative text, or adds code needs an issue carrying `status:accepted` that a lead assigned to you, or a `help wanted` issue you commented on first. Comment on the issue to claim it before opening the pull request. If you open the pull request without that, it waits rather than being closed, and a bot comment says which step is missing. See How work gets accepted in CONTRIBUTING.md."
- The `help wanted` description, in the form line, the seed, and the live label: "Already accepted work. Comment on the issue to claim it before opening the pull request."
- GOVERNANCE "Triage authority" gains: `A lead or a triage volunteer holding the repository's triage role or higher accepts a claim on an issue by assigning the claimant. GitHub lets a lead assign a non-collaborator only after that person has commented on the issue, which is why the claim is a comment.` "How leadership changes" and the Triage volunteers section each gain: `A roster entry also exempts that login's pull requests from intake and lets their approval clear another contributor's, so add one only for a person who reviews here.` The CODEOWNERS header gains one line: `# An owner login here is also exempt from pull request intake and can clear another contributor's by approval.`

- [ ] **Step 1: Write the failing tests**: `test_template_checkbox_matches_both_editorial_checks_when_ticked` (both `closing_choice.EDITORIAL.search(normalize(line))` and `pr_intake.editorial_ticked(line)` match the ticked line and not the unticked one). `test_claim_phrase_is_in_contributing_readme_template_form_and_seed`. `test_contributing_has_the_precedence_sentence`. `test_contributing_routes_follow_gate_order` (imports `pr_intake.GATE_ORDER`, maps each route after `bot` to a key phrase: "project lead", "approval", "merged a pull request of yours", "editorial", "assigned you", "help wanted", asserts they appear in that order). `test_what_we_need_no_longer_promises_no_triage`. `test_codeowners_header_names_the_leads_and_the_lapsed_invitations` extended with the exemption line.
- [ ] **Step 2: Run. Expected: FAIL.**
- [ ] **Step 3: Edit the files.** Run `uv run mkdocs build --strict`.
- [ ] **Step 4: Run `uv run pytest -q`. Expected: PASS.**
- [ ] **Step 5: Commit** `git commit -s -m "Say the intake gate in CONTRIBUTING, README, the template, the form, and GOVERNANCE"`

### Task 11: Design records, the pull request, and the rollout checklist

**Files:**
- Modify: `design/2026-10-29-pr-intake-rules-design.md` (the plan premortem's spec amendments: the auto-merge rule keyed on state, the hand-clear head record, the help-wanted cap, the editorial-first ordering, `awaiting_rereview` and `paths_truncated`, the sweep budget, the base-ref `if`, the honest base-ref sentence in Risks, the baselines variable, the dry-run mode, the retract order, `Part of #362`)
- Add to the branch, by explicit `git add` of the three files only: `design/2026-10-29-pr-intake-rules-design.md`, `design/2026-10-29-pr-intake-rules-premortem.md`, `design/plans/2026-10-29-pr-intake-rules.md`
- Create: `claudedocs/pr362-body.md` (not committed), started from `.github/pull_request_template.md` verbatim

- [ ] **Step 0: The owner's line.** Rock Lambros replaces the design's "the owner writes one line here" with `Deviation accepted, <date>, Rock Lambros.` or `Overridden, <date>, Rock Lambros.` If overridden, stop: the closing-choice check is a required check on `integration`, and changing it is in no task.
- [ ] **Step 1: Run the whole suite and the guards**: `uv run pytest -q`, `uv run mkdocs build --strict`, `uv run --locked --only-group zizmor zizmor .github/workflows/`. Expected: all pass.
- [ ] **Step 2: Commit the design records** `git commit -s -m "Record the intake gate design, its premortem, and its plan"`.
- [ ] **Step 3: Open the pull request** against `integration`: What changed (three sentences). Under `## Which issue does this implement` write `Part of #362` and nothing else that closes. No closing word anywhere else in the body. Base `integration`. Types Tooling or CI, Documentation, Governance. "I tested this" with the commands above. A Security subsection (token scope, the argv allowlist, the base-ref `if`). A Rollout subsection carrying the checklist from Step 4. Reviewers `bar-capsule`, `afogel`. Edit issue #362's body to say v3.0, link the spec, and replace "by assignment or authorship" with "by assignment, or by a prior comment on a `help wanted` issue". Request one non-author approval. Resolve every thread and push every fix before requesting it (the ruleset dismisses approvals on push). Do not admin-merge.
- [ ] **Step 4: The rollout, posted as a checklist comment on issue #362 and ticked there.** Precondition: the GOVERNANCE/CODEOWNERS reconciliation pull request is merged, or a project lead has written on issue #362 that the three roster entries without repository access stay and why. (a) Rock Lambros dispatches `mode=dryrun` with the variables unset. Expected: a summary with zero writes and `arm with PR_INTAKE_TOOL_SHA=<value>`. He posts the would-queue numbers and reasons on issue #362, naming PR #24, PR #112, PR #113, PR #297, PR #253, PR #255, PR #259, and the three verbs that clear them (approve, a fresh request for changes, assign). (b) The same in `#team-genai-asi-acs-general` and on the weekly call agenda. (c) Done when a re-dispatched `dryrun` lists none of the named numbers, or a project lead writes "proceed with the remainder" on issue #362. (d) A project lead opens a throwaway pull request with auto-merge enabled, dispatches `evaluate` on it, and comments on issue #362 which write name the summary reports and the value of `autoMergeRequest` afterwards. Expected: null. (e) Promote. Confirm the next roadmap sweep renders "Queued pull requests" and the next monitor run logs the intake line. (f) A project lead (repository admin) edits the live `help wanted` label description, dispatches `retract` with `authors=bots` to clear the seven inherited Dependabot labels, then in one sitting outside 03:00 to 04:30 UTC sets `PR_INTAKE_TOOL_SHA` from the dry run's line, `PR_INTAKE_ENFORCED=true`, and dispatches `evaluate`. Expected: `mode=enforced` in the summary. (g) The next morning's health issue is read. The project lead sets `PR_INTAKE_BASELINES` from its "Queued pull requests" counts and comments the values and the review date on issue #362. (h) A project lead closes issue #362 by hand, which GOVERNANCE counts as delivered. Undo order at any step: unset `PR_INTAKE_ENFORCED`, then dispatch `mode=retract`.

---

## Self-review

Spec coverage: gate routes 0 to 6 with the editorial-first ordering and the two caps (Task 3), writes and reversibility with the draft fallback (Task 5), triggers including the review and unlabel events, the protected-base guard, modes, dry run, retract, sweep semantics, the budget, pacing, staleness, concurrency, cron (Tasks 6, 7), the runner allowlist with no free text (Task 1), the health section, counts, baselines variable, degradation (Task 8), the monitor with its switch (Task 9), documentation, guards, the label seed (Task 10), the spec amendments, the owner's line, the rollout with actors and expected results (Task 11).

Type consistency: `Runner` from Task 1 everywhere. `Facts`, `Decision`, `Reference`, `Review`, `BotComment` from Task 2. `Listings` and `CallCounter` from Task 4. `Summary` from Task 6. `evaluate` keeps its existing keyword signature in Task 9.

Review Focus: 1, 2, and 4 in Task 4 (4 also in Task 5), 3 and 5 in Task 3.

Proportion: tests and signatures. The only bodies transcribed are the contributor-facing sentences the precedence rule makes normative.
