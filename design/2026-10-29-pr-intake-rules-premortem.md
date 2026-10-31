# Adversarial premortem: PR intake rules design

Artifact: `design/2026-10-29-pr-intake-rules-design.md` v1.1 (Round 1), then v2.0 (Rounds 2 to 5). Date: 2026-10-29. Orchestrated as a multi-subagent premortem. Each perspective read the artifacts and the live repository independently.

Round 1 was run against v1.1 and found that the design's two rules did not reach the outcome stated in its intent. The design was rewritten as v2.0 before Rounds 2 to 5, which attack v2.0. The Round 1 record is kept in full because the measurements that moved the design are in it.

## Round 1. Problem framing and inputs (against v1.1)

Perspectives spawned: Data Scientist (lead), Governance / Risk, Red Teamer, ML Engineer. Skipped: Security Architect and MLOps / SRE, because the framing layer had no trust-boundary or operational surface anchored. They lead Rounds 3 and 4.

Premortem narrative. Six months out, the fifteen pull requests that motivated the rule are still in the review queue, now saying `Part of` instead of `Fixes`, and twenty newer ones from other authors say the same. The one-line comment fix the editorial rule was written for was merged in a week after its author unticked the box and left `Refs #92` in place. Thirty pull requests carry `status:needs-triage`, six of them approved by a workstream lead, two of them from contributors who filed the issue they were fixing, and nobody on the weekly call can see the list because the health issue lists issues only. A contributor who followed the "start from help wanted" paragraph got a bot comment telling them to ask permission. The design document naming one contributor by full name as the reason for the rule has been on `main` since November.

Findings, surviving at Plausible or above.

1. The claim rule keys on the closing keyword, and `Part of` is a one-word bypass the design protects as an anti-goal.
   - Impact: Critical. Rule 2 is most of the design and lands without changing review load.
   - Confidence: Very likely (prior Very likely from three perspectives. The Data Scientist and Governance measurements are independent of each other: fifteen non-roster open pull requests already use `Part of`, `Refs`, or `Contributes to` against the same accepted issues, and the fifteen-PR author's own PR #337 is one of them).
   - Evidence anchor: design v1.1 "Anti-goals: Queuing a pull request for a `Part of`, `Refs`, or `Contributes to` reference. Those close nothing." Live PR #337: "Part of #92 / Fixes #336".
   - Failure mode: the queued authors edit `Fixes` to `Part of`. The accepted-issue gate passes them (an accepted issue is referenced), the claim step is silent by design, and the review queue is unchanged. The project has also trained contributors that `Part of` is the spelling that avoids a queue.
   - Blind spot: "declares Fixes" and "unrequested work" coincided in one week's sample.
   - Opportunity cost: a CODEOWNERS-gated change to `.github/` and `tools/` for no reduction in queue size.
   - Cross-attack: the Governance counterargument (forcing `Part of` is a win for roadmap accounting, since `assess` marks a contributing merge unverified) was weighed and held insufficient: the intent names review attention as the harm, and a `Part of` pull request demands the same review. Posterior stays Very likely.

2. Assignment is not where this project records claims. 9 of 94 open milestoned issues carry any assignee. 3 of the 4 merged non-roster pull requests that closed a milestoned issue were unassigned. GitHub refuses to assign a non-collaborator who has not commented on the issue, so "one action" is three actions across two people and two objects.
   - Impact: High. The rule is a blanket hold on every non-roster pull request, not a classifier.
   - Confidence: Very likely (measured on the live listing by two perspectives independently).
   - Evidence anchor: design v1.1 "which is one action in the GitHub interface". `GET /repos/.../assignees/<login>` returns 404 for every author the sweep would queue.
   - Failure mode: every contributor pull request on roadmap work waits for a three-step hand clearance, and claim requests on issues become the new flood with no stated decline rule.
   - Blind spot: assignment was treated as a scarce deliberate act. Here it is an unused field.
   - Opportunity cost: maintainer attention moves from reviewing pull requests to answering claim comments and clearing labels.

3. Rule 1 does not catch its own example. PR #354 says `Refs #92`, #92 is accepted, and the intake gate passes any mention of an accepted issue. Untick the box and both bots pass.
   - Impact: High.
   - Confidence: Very likely (traced through the live body and both code paths by three perspectives).
   - Evidence anchor: `pr-intake.yml` lines 39 and 58-63 (`NUMBERS` is every `#n` in the body. The first accepted one exits 0). Design v1.1 "no issue, the editorial box ticked" is false on the data.
   - Failure mode: a contributor learns "Refs an accepted issue, untick the box". The design claims a closed door.
   - Blind spot: the exemption's only function is to waive the accepted-issue requirement. A pull request that already names an accepted issue gains nothing from it.
   - Opportunity cost: a red required check on honest declarations with zero attention saved on the example.

4. The red required check on an honest editorial declaration reverses a settled decision and would have failed the project lead's own PR #357.
   - Impact: Medium.
   - Confidence: Likely (the 2026-09-09 governance design rejected a red check for this box in so many words. PR #357 is a measured case. PR #323's editorial tick on `docs/spec/conformance.md` passes).
   - Evidence anchor: `design/2026-09-09-contribution-governance-design.md` lines 390-406 ("turning it into a red required check would make the gate feel like a rejection"). Design v1.1 anti-goal "Blocking a lead's or a triage volunteer's own pull request".
   - Failure mode: leads untick the box on their own prose fixes, contributors copy them, and the box stops meaning anything.
   - Blind spot: the trade was made by naming examples, not by running the rule over merged history (one true positive, one lead false positive).
   - Opportunity cost: a governance event per typo.

5. The prose definition is wrong in both directions. A file suffix admits GOVERNANCE.md (the roster Rule 2 trusts), `.github/pull_request_template.md` (the sentence both regexes match), 23 normative spec pages, and eight reference-implementation READMEs. It rejects 273 schema description strings, 33 nav titles, seven issue-template YAMLs, the landing copy, and both LICENSE files. The definition also contradicts itself on `.github/`.
   - Impact: Medium.
   - Confidence: Very likely for the misclassification (it is the definition). Plausible for frequency.
   - Evidence anchor: design v1.1 "A changed path is prose when its file name ends in `.md` ... Everything else is code ... including every file under ... `.github/`". `roadmap_model.py` line 203 reads GOVERNANCE.md as the roster.
   - Failure mode: a template edit that pre-ticks the box makes every later pull request editorial. A `MUST` to `SHOULD` edit in `docs/spec/` is editorial by suffix.
   - Blind spot: "published prose" was operationalized as a format.
   - Opportunity cost: the exemption covers the files that decide what the bots do.

6. "Open and milestoned" is not "accepted": 19 of 94 open milestoned issues lack `status:accepted` (deferred v0.2.0 issues, one blocked), and GOVERNANCE.md's "the two mean the same thing" is refuted by the data. A pull request on one of those gets two queue comments.
   - Impact: Medium.
   - Confidence: Very likely (measured).
   - Evidence anchor: GOVERNANCE.md lines 39-41. Design v1.1 "the definition the existing 'Flag closing keywords' step uses".
   - Failure mode: two definitions of roadmap inside one workflow. The "one comment, not two" promise breaks on the rarest path.
   - Blind spot: the equivalence was checked in the write direction only.

7. The queue label is a one-way ratchet with no owner, no drain, and no agenda line. 53 label events in 120 pull requests, 16 removals, all by one person. Dependabot pull requests have carried it since September. The project lead's own PR #355 went stale 48 minutes after the issue was accepted. The health issue lists issues only. A lead who removes the label by hand has it re-added by the next edit or sweep.
   - Impact: High.
   - Confidence: Very likely (timeline data and `roadmap_sync.py` lines 594 and 612 both say so).
   - Evidence anchor: design v1.1 "The bot never removes the label". The dispatch sweep can add and never remove.
   - Failure mode: within weeks the label means nothing, leads stop reading it, and the one promise in the bot comment ("a lead clears the queue label here") is broken by default.
   - Blind spot: "a lead removes it" was read as a process. It is one person's habit.
   - Opportunity cost: the signal the whole design produces decays to noise.

8. The retroactive sweep queues six pull requests from five contributors who followed the rules in force: PR #253 (approved by Lance Dye), PR #24 (changes requested by Rock, three human comments), PR #291 and PR #278 (authors fixing the issue they filed), PR #259, PR #255.
   - Impact: High. These are the "good contributor driven off" cases, identifiable by name.
   - Confidence: Very likely (the sweep simulation ran the repository's own parser and roster against live bodies).
   - Evidence anchor: design v1.1 names only the fifteen as the sweep's target.
   - Failure mode: a bot tells an approved contributor to go ask for the issue. A bug reporter is told to ask permission to fix the bug they reported.
   - Blind spot: the sweep was sized against one author.

9. `help wanted` is the project's recruiting path, every such issue is milestoned, and the rule queues its takers while CONTRIBUTING.md ("you can open a pull request against it without waiting on triage") and the existing queue comment still point at the label.
   - Impact: High.
   - Confidence: Very likely (both texts quoted. Five of six open help-wanted issues unassigned).
   - Evidence anchor: CONTRIBUTING.md "What We Need". `pr-intake.yml` line 68.
   - Failure mode: two project texts send a first-timer in a loop. CONTRIBUTING's own precedence rule then says the bot is wrong.
   - Blind spot: the design edited the paragraph that states the rule, not the one contributors land on.

10. A late body edit after approval closes a roadmap issue through auto-merge, because the label is advisory, auto-merge is enabled, approvals are dismissed only by pushes, and the squash message is the body.
    - Impact: High. This is the exact outcome the design exists to stop.
    - Confidence: Plausible (every precondition verified live: `allow_auto_merge: true`, `squash_merge_commit_message: PR_BODY`, ruleset requires no label. The unknown is whether anyone tries).
    - Evidence anchor: design v1.1 "The bots label and comment. People close."
    - Failure mode: open with `Part of`, collect an approval, maintainer enables auto-merge, author edits to `Fixes`. Intake labels, closing-choice passes, GitHub closes the issue and the roadmap counts it delivered.
    - Blind spot: "people close" assumes a person at merge time.

11. The retrofit creates implementation hazards the design does not specify: the files listing has no failure policy (an empty listing makes "every path is prose" vacuously true, and the test stub returns empty by default). A checkout ahead of the accepted-issue step chains the existing bot to a fallible step in a job with no `contents` scope. The dispatch sweep's one `gh pr list` call reads 30 of 56 open pull requests. A listing failure in the sweep exits green. There is no kill switch for Rule 2. The keyword step's exact-string marker cannot match the claim comment's marker on mixed sets (and `sort -u` orders `9` after `132`). The title path is dead under the keyword step's body-only guard. The existing steps fail on dispatch unless gated. Path text reaches a `::error::` workflow command. The concurrency group collapses on dispatch. Two steps fetch the same listing.
    - Impact: Medium (each Low to Medium. Together they describe a bash-and-Python hybrid that cannot be made consistent).
    - Confidence: Likely (each traced to a line of the workflow or the tool. The ML Engineer reproduced the sort order locally).
    - Evidence anchor: `pr-intake.yml` lines 18-20, 25-27, 36, 78, 88-105. `gh pr list --help` default limit 30. `closing_choice.py` docstring "Nothing from them is echoed".
    - Failure mode: a green run that did nothing, a required check that flakes on an API hiccup, or a duplicate comment on the pull requests the design most wants to handle gently.
    - Blind spot: the design kept the bash steps and added a Python step beside them, so every shared fact (the box, the keyword, the markers, the listing) has two readers.

12. The design document names a contributor by full name as the problem case, in a directory that publishes to `main`, with a count that is wrong on the day of writing (14 of 15 declare a closing keyword on a milestoned issue. None of the 15 has received a human review).
    - Impact: Medium. Reputational, in a public governance record, reversible only by a history rewrite the project denies on `main`.
    - Confidence: Likely (fires if committed as written).
    - Evidence anchor: design v1.1 named one contributor beside the phrase "fifteen open pull requests".
    - Failure mode: the contributor finds the sentence. Any later conduct question starts from it.
    - Blind spot: design documents are written as memos and published as record.

Cross-attack log.
- Governance challenged Data Scientist finding 1 with the roadmap-accounting reading. Red Teamer added that the `Part of` substitution also removes today's merge-time advisory for those pull requests. Confidence held at Very likely. Impact raised to Critical because the two perspectives together show the rule loses on both the attention axis and the accounting axis.
- ML Engineer challenged the Data Scientist's "one action" claim from the other side: even if assignment were routine, the label has no invalidation event, so the clearing step cannot be one action. Merged into findings 2 and 7.
- Red Teamer's auto-merge path (finding 10) was tested against the Governance claim that "people close": auto-merge is on and approvals survive body edits. Confidence set at Plausible rather than Likely because no incident exists. Impact High because the harm is the design's named harm.
- Governance finding 6 (red check reverses the 2026-09-09 decision) was tested against the owner's explicit ask for a closing-choice failure. The earlier design's reasoning stands on the data (one lead false positive on three merged editorial pull requests), so the finding survives and the v2 design records the deviation for the owner to override.
- The ML Engineer's "checkout with no contents scope" was challenged (public repository checkout may succeed without the scope). Held at Plausible. The fix is one permission line either way.
- Dropped as correlated rather than independent: the four restatements of the `help wanted` contradiction and the three of the `Part of` bypass were merged, with no band raised on count.

Stop signal: not reached. Findings 1, 2, 3, 7, 8, 9 are High or Critical at Likely or above and change the design's shape. The design was rewritten as v2.0 before Round 2.

## What v2.0 changed in response

- One gate, not two rules. A non-roster pull request is reviewed when its author holds a referenced accepted issue (assigned, or the issue's author) or when a roster member has reviewed the pull request. The editorial box waives that only for Markdown. The claim rule keys on any reference to an accepted issue, so `Part of` is no longer a bypass (findings 1, 3, 6).
- The bot owns the queue label: it sets it when the gate holds and clears it when the gate no longer holds, re-evaluated on every pull request event, nightly, and on dispatch. The health issue lists queued pull requests (findings 7, 8).
- A roster review counts as a claim accepted, and an accepted issue's author holds it by default (finding 8).
- No red required check. The closing-choice check is unchanged. A code-path editorial pull request is queued, not failed. Recorded as a deviation from the owner's "closing_choice rejects the editorial box" ask, for the owner to override (finding 4).
- Prose is a `.md` suffix or a root notice file, never under `.github/`. Roster authors keep the box on any path (finding 5).
- Auto-merge is disabled on a pull request the bot queues (finding 10).
- One Python tool replaces the bash steps: one parser, one marker, one comment edited in place, paginated listings, a kill switch, an attended sweep that fails red, path text sanitized (finding 11).
- CONTRIBUTING's "What We Need" and the bot comment are rewritten so `help wanted` says claim first (finding 9).
- The design names no contributor and states the measured count (finding 12).

## Round 2. Methodology and inputs (against v2.0)

Perspectives spawned: ML Engineer (lead), Data Scientist. Rounds 2 to 5 were run as one batch against v2.0, each perspective assigned its round's layer, because v2.0 was a whole-design rewrite and the layers were independent.

Premortem narrative. Six months out, the gate's measurable outcome reads zero every night and nobody can say whether it did anything: the count measured the bot's agreement with itself. Thirty accepted issues filed by eleven outsiders, milestoned in one afternoon three weeks before the rule existed, became thirty standing pass tokens, and one contributor with one accepted issue referenced it on five unrelated pull requests. Twelve pull requests carry two bot comments, the old one still promising that the editorial box clears them. The weekly agenda lists eight Dependabot bumps under "queued more than 30 days".

Findings, surviving at Plausible or above.

1. The v2 replay over the 56 open pull requests: 16 pass, 40 queue (28 "accepted and not held", 11 "no accepted issue", 1 editorial on code). Four of the six Round 1 collateral cases are resolved. PR #255 and PR #259 (Aaron Ormerod, who has a merged lead-approved pull request on file) still queue, because the gate reads no fact about a contributor's record.
   - Impact: Medium. Confidence: Very likely (replayed with the repository's parser, roster, and live facts).
   - Resolution in v3: gate 3, the author's merged-and-approved record.

2. Issue authorship as a hold is a retroactive trust grant: 30 of 78 open accepted issues were filed by non-roster authors, all accepted by one milestone action on 2026-10-05. One filer holds 16. Any one of them clears any pull request that mentions it, and the "unassign" remedy does not exist for a hold nobody granted. PR #337's `Fixes #336` (an unlabeled issue its author filed the same day) needs one milestone to pass.
   - Impact: High. Confidence: Very likely (measured. Three perspectives independently).
   - Resolution in v3: assignment is the only hold. A filer who wants to build is assigned at acceptance.

3. The success metric is satisfied by labeling everything. At open time the gate would have queued 4 of the 6 non-roster pull requests this repository has ever merged (PR #254, PR #202, PR #48, PR #168).
   - Impact: High. Confidence: Likely.
   - Resolution in v3: three outcome counts on the health issue with baselines and a written failure condition. False-queue and false-pass counted.

4. The claim step's measured reply rate where queued authors already tried it is zero: issue #92 (20 comments from 9 outsiders, 0 roster), issue #33 (45, 7, 0), issue #182 (8, 0). The one claim that worked took 18 days. Three of the eleven GOVERNANCE leads hold no repository access and cannot assign.
   - Impact: High. Confidence: Very likely.
   - Resolution in v3: the comment no longer promises assignment. A prior comment on the issue is named as a waiting claim. `help wanted` plus a comment passes outright. "claimed, unassigned" is a health-issue count. Issue #145 stays the real fix.

5. "Any review state" lets a months-old `CHANGES_REQUESTED`, a `DISMISSED`, or a drive-by `COMMENTED` review clear a pull request forever. Five of the seven review-based passes rest on a review at a stale commit. A null review user crashes the event run.
   - Impact: High. Confidence: Very likely (review objects read. Three perspectives).
   - Resolution in v3: `APPROVED` not dismissed, or `CHANGES_REQUESTED` within 30 days, by a roster login with `OWNER`, `MEMBER`, or `COLLABORATOR` association. Null users and `Bot` reviewers skipped. A roster hand clear counts. A 30-day-silent sent-back state is listed.

6. The editorial exemption's non-roster positive class is empty in the record (0 of 6 merged non-roster pull requests ticked the box), while a `.md` suffix admits 23 normative spec pages. Ticking the box on PR #255 or PR #294 would pass a normative-text change with no issue.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: the box covers the documentation lane only, one definition shared with the publishing lane.

7. Twelve open pull requests carry the old marker-less queue comment. The first sweep would post a second comment on each. Per-pull-request listings (files, reviews, comments) are unpaginated (PR #169 has 213 files). The comment reports one route where PR #354 fails two. The Facts record lacks labels, state, draft, age, and reference kind. The `edited` guard misses base changes. Dependabot's changelog anchors parse as this repository's issue numbers.
   - Impact: Medium. Confidence: Very likely (each measured).
   - Resolution in v3: legacy comment adoption. All listings paginate. Every unmet route rendered. Facts widened. Base in the guard. Anchors to other repositories dropped. Bots out of scope.

Cross-attack log.
- The Data Scientist's "author record" pass fact was tested against the Red Teamer's abuse lens (Round 3): a merged lead-approved pull request is a lead act, not forgeable, and clears nothing in the fifteen-PR set. Adopted.
- The ML Engineer's proposal to count `COMMENTED` reviews was rejected by the Red Teamer's and Governance's independent evidence that a thread reply is the lead's channel for saying no. The Data Scientist's 30-day expiry on `CHANGES_REQUESTED` was adopted over the Red Teamer's head-SHA rule, because approvals are already dismissed on push by the ruleset and a changes-requested review is engagement that decays, not a commit-bound fact.

## Round 3. Adversarial robustness and trust boundaries (against v2.0)

Perspectives spawned: Red Teamer (lead), Security Architect.

Premortem narrative. Six months out, a contributor who wanted a roadmap issue closed got a lead to leave a one-line comment review, force-pushed a schema change, edited the body to `Fixes`, and auto-merge took it: the bot never queued the pull request, so the control that disables auto-merge never ran. A forged `<!-- acs-intake -->` comment on another pull request became the text the bot "edited" and the nightly sweep copied into the pinned agenda. A fork pull request with twenty 3,000-character paths made the sweep red every night. A `gh api -f body=@...` read a runner file into a comment.

Findings, surviving at Plausible or above.

1. A roster review of any state at any commit is a permanent pass, and it is the branch where the auto-merge control never engages.
   - Impact: Critical. Confidence: Likely (five of seven live review passes at stale commits. `allow_auto_merge: true`. The ruleset dismisses on push only).
   - Resolution in v3: gate 2 as above. Auto-merge disabled on any non-roster `edited` run that adds a closing keyword on a milestoned issue, whatever the gate decides. The disable failure is red on event runs. A rehearsal precedes enforcement.

2. The queue reason "read from the bot comment" is a fork-writable channel into the locked health issue, and marker-only comment discovery lets the bot edit a contributor's comment.
   - Impact: High. Confidence: Likely.
   - Resolution in v3: comment discovery by exact `BOT_LOGIN` plus marker. The health renderer reads data lines only from bot-authored comments. No logins rendered.

3. `pull-requests: write` can rewrite any pull request body, which is the squash message the roadmap reads delivery from. The design's text-safety rule covered workflow commands and the comment, not argv.
   - Impact: High. Confidence: Likely for scope, Plausible for exploitation.
   - Resolution in v3: a shared `gh_runner.py` with an argv allowlist, bodies on stdin, `PR_NUMBER` validated, stderr never echoed. A byte-identical argv test under a hostile fixture.

4. The auto-merge disable's permission need is unverified and the rollout never calls it (0 of 56 open pull requests have auto-merge on).
   - Impact: High. Confidence: Plausible.
   - Resolution in v3: rehearsal step with assertion. Convert-to-draft fallback.

5. `synchronize` under `pull_request_target` makes every fork push an unapproved write-token run against the shared hourly budget. A hostile pull request with long paths overflows the comment and makes the sweep red nightly. Two hundred open pull requests cost more than the budget per sweep.
   - Impact: High. Confidence: Likely.
   - Resolution in v3: `synchronize` re-evaluates only when the box is ticked. Paths capped at 200 characters and twenty, comment at 8,000. Facts hash skips unchanged pull requests. Per-pull-request degrade. Rate-limit remaining in the summary.

6. The roster is fifteen login strings, three without repository access and three uninvolved org admins. A drive-by review from any is a pass. A re-registered login inherits the trust. The kill switch off is below the status quo. Claim comments are free and invisible. The dispatch sweep's `gh pr list` default reads 30 of 56. The files endpoint caps at 3,000.
   - Impact: Medium each. Confidence: Likely.
   - Resolution in v3: association check on reviews. Legacy mode equals today's behavior. "claimed, unassigned" count. Pagination everywhere. Truncation detected.

7. Code execution from the fork through `pull_request_target`: tested negative under the stated constraints (base-branch YAML, trusted checkout, text via `env`, `python3 -I -S`), with three conditions the builder must keep (no path or title in argv or `--jq`, pinned action SHAs, the author filter on comments). Supply chain, checkout head, and the `${{ }}` rule were checked and held.
   - Impact: Critical if a condition fails. None while they hold. Confidence: Unlikely as designed. Parked in the tail-risk line.

Cross-attack log.
- The Security Architect's "recompute the reason from facts at sweep time" was weighed against the ML Engineer's "data line in the comment": recomputation doubles the nightly API cost, and the channel the Architect feared is closed by the exact-login author check. The data line, author-checked, was adopted. The Architect's counterargument conceded the point.
- The Red Teamer's per-issue cap of two was tested against the owner's non-goal (no per-author cap): it is per issue, bounded, and leaves the assigning lead as the drain. Adopted.
- The Security Architect confirmed zizmor is clean on the v2 trigger set and that the checkout can equal the head only when the head is the protected branch itself.

## Round 4. Operations (against v2.0)

Perspectives spawned: MLOps / SRE (lead).

Premortem narrative. Six months out, the rule merged on a Thursday and the promotion landed twelve days later. In between, every new pull request arrived with no label and no comment while the nightly sweep reported green, and then the first live sweep posted forty comments in one minute, fifteen to one author, and went red on request twenty-one with a secondary rate limit. The red email went to one mailbox. A lead unset the variable. The forty comments stayed.

Findings, surviving at Plausible or above.

1. The gap between merging to `integration` and promoting to `main` switches intake off entirely: the old bash steps are gone, the tool is absent on `main`, and the measured gap after other people's merges is 7.3, 10.5, and 17.1 days.
   - Impact: High. Confidence: Very likely.
   - Resolution in v3: the job checks out the pull request's base ref (same ruleset, same approval), so the tool binds on merge. Recorded as a change from the closing-choice precedent for the owner.

2. The kill switch freezes a bad state with no undo. A wrong first sweep reaches 50 pull requests and 24 authors and the retraction rides the promotion cadence.
   - Impact: Critical. Confidence: Likely.
   - Resolution in v3: `mode=retract`. Every write reversible. Legacy comment adoption so day one leaves one bot comment per pull request.

3. Nothing interlocks the variable with the tool version that was dry-run. The first enforcing run is a contributor's event within hours.
   - Impact: High. Confidence: Likely.
   - Resolution in v3: enforcement requires `PR_INTAKE_ENFORCED=true` and `PR_INTAKE_TOOL_SHA` equal to the tool's blob SHA. A changed tool runs in legacy mode until re-armed.

4. A red nightly sweep emails whoever last edited the cron line, the repository's measured response to a red scheduled run is none (1 failure in 249 runs, never rerun), and a persistent cause is red every night.
   - Impact: High. Confidence: Very likely.
   - Resolution in v3: `monitor_roadmap.py` checks the last scheduled intake conclusion and comments on the health issue mentioning every lead on change (decision 17 reused). `::error::` per failed pull request. The sweep's status line at the top of the health section.

5. Two writers with no version check (event run and sweep), `cancel-in-progress` cutting a run between the label and the comment, an unpaced write burst at the 80-per-minute line, no `Retry-After`, forty needless comment edits a night, no cron time, and a health render that runs before the sweep would.
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: re-read `updated_at` before writing. Comment before label. Writes only on change. Paced. `Retry-After` honored. Cron 03:30 before the 04:10 render. Concurrency expression pinned.

6. Stub-based workflow tests cannot catch a real API shape change (the bot login already differs between GraphQL and REST. `gh --json` fields differ from REST).
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: recorded real responses as fixtures. The legacy-mode sweep fails red when facts read empty for a pull request the listing says has data.

Cross-attack log.
- The SRE's counterargument to its own top finding (Rock promotes same day after his own merges) was tested against the measured windows and the CODEOWNERS rule that the approving lead, not the author, sets the merge time. The finding held and the base-ref checkout was adopted over the "keep the bash steps as a fallback" alternative because the fallback keeps two readers of every shared fact for an unbounded window.

## Round 5. Governance and second-order effects (against v2.0)

Perspectives spawned: Governance / Risk (lead).

Premortem narrative. Six months out, the recruiting funnel has a step with nobody in the middle: `help wanted` says claim it, the claim goes unanswered, the pull request is queued, and the health issue lists the contributor's handle under "queued more than 30 days" in a locked issue they cannot reply to. The conformance report issue #145 named as the contribution the project most wants was the second row.

Findings, surviving at Plausible or above.

1. The claim step is unowned and measured at one grant in four. The bot's comment promises an action the project does not perform.
   - Impact: Critical. Confidence: Very likely.
   - Resolution in v3: as Round 2 finding 4, plus the `help wanted` standing-request route, so the advertised path needs no lead action.

2. The health issue's queued section would list contributors by login in a record whose own test forbids it.
   - Impact: High. Confidence: Very likely.
   - Resolution in v3: numbers, reason codes, days. One search link. The invariant's test extended.

3. The retroactive sweep as written queues 40 of 56, including PR #78 (which the owner told others to coordinate with), PR #113 (named by issue #145 as wanted), and two drafts. The collateral grew from Round 1's six because v2 widened the reference rule.
   - Impact: High. Confidence: Very likely.
   - Resolution in v3: drafts out of scope. The rollout's step 3 has leads clear the collateral by the gate's own facts from the dry list before arming. Per-author batching on the first sweep. The 30-day clock starts at the sweep for pre-rule pull requests.

4. Four contributor-facing surfaces would contradict the gate (the template's "open the PR anyway", README's paragraph and diagram, CONTRIBUTING lines 73-74, the reference-implementation form), and CONTRIBUTING's precedence sentence covers only the scope section.
   - Impact: Medium. Confidence: Very likely.
   - Resolution in v3: all four edited in the same pull request. A precedence sentence added to "How work gets accepted". A guard test on the phrase.

5. The deviation from the owner's red-check ask has no decision owner or date. `trusted_logins` now serves three purposes and the roster-change procedure does not know. A GOVERNANCE sentence overloads "assign".
   - Impact: Medium. Confidence: Likely.
   - Resolution in v3: the owner writes one line before the implementing pull request opens. A sentence under "How leadership changes" says what a roster entry grants. The claim sentence names the act.

Cross-attack log.
- Governance's proposal that `help wanted` plus a comment should pass was tested against the Red Teamer's abuse lens: the exposure is bounded to issues leads chose to advertise, the comment is public, a lead withdraws consent by removing the label, and the fifteen-PR author has zero comments on the eighteen issues his pull requests close. Adopted.
- Governance's objection to issue-authorship holds matched Round 2 and Round 3 from independent data. Dropped from v3.

## Dropped ledger

- A contributor who holds one accepted issue references it on unrelated pull requests. Evidence: issue #184, five pull requests by its author. Posterior: Likely, but bounded by the per-issue cap of two and shown on the health issue. Accepted, not dropped. Recorded here because the residual is deliberate.
- The roster trusts login strings and a renamed login could be re-registered. Posterior: Unlikely (GitHub's released-username behavior, no incident). Trigger that would raise it: a roster member renames. Held as a tail risk. The reconciliation follow-up and a user-ID pin in the roster test are the remedy.
- Two queue comments when a milestoned issue lacks `status:accepted` (v2). Posterior: Unlikely in v3, which has one comment per pull request by construction. Dropped.
- The concurrency group collapsing on dispatch (v2). Resolved by the pinned expression. Dropped.
- `closing-choice` runs only for `integration` while intake has no branch filter. Posterior: Unlikely to matter. The docs lane carries no code and v3 moved the editorial rule into intake. Dropped.
- Path text reaching a `::error::` workflow command. Resolved: nothing from the pull request reaches a workflow command in v3. Dropped.

Tail risks (Critical, irreversible, below Plausible): code execution from a fork through `pull_request_target`, parked with its three conditions (Round 3 finding 7). Trigger that would raise it: any pull request text reaching `gh` argv, `--jq`, or a shell.

## Convergence statement

Round 5 was the last layer. Rounds 2 to 5 were run against v2.0 in one batch and every surviving finding is resolved or accepted in v3.0 above. No round against v3.0 has been run. The implementation plan's premortem attacks v3.0 as built.

## Prioritized remediation plan

Ordered by expected cost reduction per unit of effort. Each item names the v3.0 section that carries it and the test that proves it landed.

1. Count only `APPROVED` (not dismissed) or `CHANGES_REQUESTED` within 30 days by a roster login with a repository association. Skip `COMMENTED`, `DISMISSED`, null users, bots. Closes Round 3 finding 1 (Critical, Likely). Owner: the implementer of `decide`. Verify: `test_pr_intake.py` review-state cases.
2. Disable auto-merge on queue and on a non-roster `edited` run that adds a milestoned close. Red on failure. Rehearse before enforcement. Closes Round 3 findings 1 and 4. Verify: the rehearsal record in the rollout, `test_pr_intake.py` auto-merge cases.
3. Assignment is the only hold. `help wanted` plus a prior comment passes. The author's merged-and-approved record passes. Per-issue cap of two. Closes Round 2 findings 1, 2, 4 and Round 5 findings 1, 3. Verify: the replay over the 56 open pull requests in the plan's premortem, and the named `decide` cases.
4. Base-ref checkout. Two-variable arming with the tool SHA. `mode=retract`. Legacy mode equals today. Closes Round 4 findings 1, 2, 3 and Round 3 finding 6. Verify: `test_pr_intake_workflow.py` checkout and mode cases. A retract run on one pull request before enforcement.
5. Exact-login comment discovery with legacy adoption. Data line. Health section with numbers, reasons, days, counts, and the sweep status. The monitor's conclusion check. Closes Round 3 finding 2, Round 4 finding 4, Round 5 finding 2, Round 2 findings 3 and 7. Verify: `test_roadmap_sync_health.py` and `test_monitor_roadmap.py` cases.
6. `gh_runner.py` with the argv allowlist and stdin bodies. Closes Round 3 finding 3. Verify: `test_gh_runner.py` byte-identical argv.
7. Pagination everywhere, truncation detection, caps, pacing, `Retry-After`, write-on-change, staleness guard, comment-before-label, cron at 03:30, concurrency expression, `synchronize` scoped to the editorial tick. Closes Round 3 finding 5 and Round 4 finding 5. Verify: the workflow tests named in v3.0.
8. The documentation lane as the editorial definition. The four contributor-facing surfaces edited. The precedence sentence. The template tick test. Closes Round 2 finding 6 and Round 5 finding 4. Verify: the guard tests.
9. Recorded real fixtures and the legacy-mode empty-facts check. Closes Round 4 finding 6. Verify: `tests/fixtures/` and the sweep case.
10. The owner's one-line decision on the red check. The GOVERNANCE sentences. The roster reconciliation follow-up. Closes Round 5 finding 5. Verify: the line in v3.0 before the implementing pull request opens.

## Residual risk

- The roster as the author exemption still trusts a Markdown table. A reconciliation with repository access is a follow-up with an owner (the project leads) and precedes enforcement.
- Claims on issues have no responder. The design stops promising one and makes the backlog visible, and issue #145 is the fix the project already filed.
- A contributor who holds one assigned issue can clear two pull requests with it. Deliberate.
- Integration's ruleset is trusted as much as main's for the checkout. Both require one code-owner approval. Both are admin-bypassable. The owner may revert to the `main` checkout at the cost of the measured gap.
- The tail risk above, with its conditions pinned by tests.

## Plan premortem (against `design/plans/2026-10-29-pr-intake-rules.md` v1.0)

Perspectives spawned, one batch, each attacking the plan as an executable artifact handed task by task to fresh implementers: Red Teamer, Data Scientist, ML Engineer, Security Architect, MLOps / SRE, Governance / Risk. Each read the plan, the spec, this report, the code the plan modifies, and the live repository, and several replayed the plan's rules against the 56 open pull requests. Sixty-eight findings came back. After merging duplicates, forty-one survived at Plausible or above. All are resolved in plan v2.0.

Premortem narrative. Six months out, the gate's monitor never ran because the workflow never passed it the switch. The health section's first line was unreadable every night for want of a permission. A tool fix de-armed the gate for three weeks and every signal stayed green. The motivating pull request passed on the strength of a dogfooding comment. One contributor's fifteen pull requests passed after one comment on issue #92. The first "dry" sweep wrote thirty labels. A lead's one-click clear outlived three pushes because the timeline's commit dates belong to the pusher.

Findings, merged, with the plan's resolution.

1. The monitor's intake check reads a variable the workflow never passes (ML Engineer, Governance, SRE). High, Very likely. v2.0 Task 9 passes both variables and extends the job `if`. The default `read_runs=lambda: None` keeps the existing `evaluate` calls.
2. The roadmap sweep reads the Actions runs endpoint without `actions: read`, and the plan forbade the workflow edit. An unwrapped failure degrades every section and latches the roadmap alarm (ML Engineer, SRE, Security Architect, Data Scientist). High, Likely. v2.0 Task 8 grants the permission on both jobs, reads runs with `gh.get`, and wraps the intake reads in their own degradation.
3. The runner allowlist cannot serve the roadmap fetch's GraphQL argv or the monitor's `-f body=`, so Task 1's delegation step forces a widening to free text (ML Engineer, SRE, Security Architect). High, Very likely. v2.0 Task 1 sends GraphQL bodies on stdin through `--input -`, forbids `-f`, `-F`, `--jq`, `-q`, `-t`, `--template` in every position by test, and leaves the monitor's post on its own subprocess.
4. The workflow harness runs the `run:` line against a fake `gh` on `PATH`, but the runner calls `/usr/bin/gh` by absolute path (ML Engineer). High, Very likely. v2.0 Task 6 adds `--gh PATH` for tests and Task 7 pins the real run line separately.
5. `Facts` lacked the event action, the per-issue use, and a source for the rule's landing date. The edit-adds-a-close rule had no input to compute "adds" (ML Engineer, Security Architect, Red Teamer). High, Likely. v2.0 keys the auto-merge disable on state (auto-merge on, non-roster author, a close on an open milestoned issue) on every event including `auto_merge_enabled`, which the Red Teamer showed is the event the edit rule missed. `RULE_LANDED` is a module constant. `held_use` is a field with an ordering rule.
6. A tool change silently de-arms the gate and nothing renders the mode. The arming SHA covered one of five modules (Governance, SRE, Security Architect). High, Likely. v2.0 Task 6 makes a mismatched sweep red with the remedy in the error line, prints the mode first in every summary, and arms over five modules.
7. A legacy-mode sweep writes, so the rollout's dry sweep is not dry, and legacy mode dropped today's editorial and already-commented exits (Governance, SRE, Data Scientist). High, Likely. v2.0 defines legacy as today's three exits on event runs only, adds `dryrun`, and makes any legacy sweep write-free.
8. The nightly sweep spends 440 to 816 of the 1,000 hourly calls in the roadmap sweep's hour with no cap, no primary-limit abort, and no job timeout. Per-reference reads let one body spend the budget. Task 7 deleted the one-call regression test (SRE, Red Teamer, Security Architect). High, Likely. v2.0 filters bots and drafts before collection, resolves references against the listings only, caps claim reads at five, skips unchanged pull requests on a `seen` key, reads the rate limit every ten evaluations, stops at a reserve, and sets a twenty-minute timeout. The old test is carried over.
9. The motivating example, PR #354, passes through the help-wanted route on a dogfooding comment, and that route is uncapped (Data Scientist, Red Teamer). Critical, Very likely. v2.0 queues an editorial tick with any off-lane path before the issue routes are read, and caps the help-wanted route at two open pull requests per author per issue, the same as assignment.
10. "False queues" measured the designed path (approved non-roster merges land within 1.4 hours of approval, with no trigger on review), and the baselines could not be read from the sweep summary (Data Scientist, Governance, SRE). Critical, Very likely. v2.0 adds the `pull_request_review` trigger, counts hand clears by route from the data line, records baselines in a repository variable with a review date, and compares 60-day windows.
11. `last_push_at` from `committed` timeline events is a git date the pusher sets, and the events carry no `created_at` (Red Teamer, Security Architect, Data Scientist). High, Likely. v2.0 adds the `unlabeled` trigger, records `cleared_head` on the data line, holds a hand clear while the head matches, and never reads commit dates.
12. A changed path rendered into the bot's own comment reopens the fork-writable channel into the locked health issue and lets the bot mention anyone (Red Teamer, Security Architect). High, Likely. v2.0 sanitizes paths, puts the data line on line 1 and parses only line 1, and drops malformed rows in the renderer.
13. The facts hash short circuit swallowed the 30-day expiry and every omitted fact. `since` reset on every rewrite (Data Scientist, ML Engineer). High, Likely. v2.0 hashes every field `decide` reads plus the date-dependent booleans, and carries `since` forward while the outcome stays queued.
14. "Sent back, no response" labeled the lead's silence as the contributor's on the one live case, and "claimed" counted critiques and questions (Data Scientist). Medium, Very likely. v2.0 adds `awaiting_rereview`, counts claims once per author and issue, and softens the claim line.
15. The rollout had no actor, surface, or exit criterion, armed before promoting (so the first enforced sweep ran with no agenda and no alarm), and `Closes #362` closed the tracking issue at step 1 (Governance, SRE). High, Likely. v2.0 Task 11 is a checklist posted on issue #362 with actors and expected results, promotion before arming, `Part of #362`, and a hand close.
16. The legacy-comment adoption dropped the bot-login condition, so the bot could overwrite a contributor's comment (Security Architect). Medium, Plausible. v2.0 requires the bot login on both branches.
17. Every `type: Bot` author out of scope is below today for GitHub App authors (Red Teamer). Medium, Plausible. v2.0 scopes out `KNOWN_BOTS` only.
18. Seven Dependabot pull requests carry the label with no bot record, and the summary could not reconcile the out-of-scope count (Data Scientist). Medium, Very likely. v2.0 adds `out_of_scope` to the summary identity, a bot-scoped retract before the live sweep, and a "Labeled without a gate record" sub-list.
19. The CONTRIBUTING line range deleted the closing-keyword paragraph a test pins, the seven route sentences were not written, the template path and the link-check test were misnamed, the `help wanted` label still promised "safe to start without waiting on triage", and the README's governance link was not protected (Governance, ML Engineer). High, Very likely. v2.0 Task 10 carries the sentences verbatim, the exact line ranges, the tracked file names, the label seed, and a test that the prose follows `GATE_ORDER`.
20. The owner's deviation line was never written, and the roster reconciliation the spec made a precondition was dropped (Governance). Medium, Likely. v2.0 Task 11 Step 0 is the owner's line and the rollout's precondition is the reconciliation.
21. Smaller: no reason code for a truncated listing. `rate_limit` outside the allowlist. `Retry-After` unreadable without `-i`. `paginate` failure unspecified. Logins not casefolded. The health snapshot's three collisions with `roadmap_sync` as it stands. The monitor alarming on an in-progress run. The auto-merge draft fallback with no code path. Fixtures carrying commit emails. The null review user pinned at the wrong layer. The base-ref guarantee false for 26 branches. The cron-order test proving nothing. Zizmor pinned at a version CI does not run. All adopted in v2.0 as the perspectives proposed.

Cross-attack log.
- Hand-clear expiry: the Red Teamer proposed timeline order, the Security Architect a recorded head SHA with an `unlabeled` trigger, the Data Scientist commit dates plus a head record. The head record won: it is a server fact the bot writes, needs no assumption about timeline ordering, and the trigger makes the first observation immediate.
- Auto-merge: the ML Engineer and the Security Architect built the "adds" rule from before-and-after bodies. The Red Teamer showed the dangerous moment is the enable, not the edit, and that `pull_request_target` has an `auto_merge_enabled` type. The state rule won, and the trade (no auto-merge on non-roster pull requests that close roadmap issues) is recorded in the spec.
- Reference reads: the Data Scientist wanted one `issues/{n}` read for numbers in neither listing. The Red Teamer and the Security Architect showed any per-reference read is a budget attack. The listings won: the accepted listing is read with `state=all`, pull request numbers come from the two pulls listings, and a number in no listing is "not accepted" without a claim about what it is.
- Help-wanted cap: the Data Scientist argued for one, the Red Teamer for two. Two won, one rule for both issue routes, stated in CONTRIBUTING.
- Budget stop: the Red Teamer proposed exit 0 with the rest skipped, the SRE exit 1. Exit 1 won: a sweep that could not finish is a condition a lead must see, and the mode line names it.
- Timeout: ten minutes (Red Teamer) against twenty (SRE). Twenty, because pacing at one second per write over forty queued pull requests plus the reads is already past ten.
- The data line's position: last match (Red Teamer) against line 1 (Security Architect). Line 1 won. It needs no multiline parse and a path cannot precede it.

Dropped ledger.
- Red Teamer, the base-ref checkout as a new capability: Remote (a write-access branch already runs its own workflow file). The honest comment and the `if:` guard were adopted for the statement's sake.
- Security Architect, `actions: read` possibly unneeded on a public repository: not tested. The permission is added regardless and the dry run records the observation.
- SRE, red on every tool edit trains the leads to expect red: weighed against the measured response to a green run (none) and held the other way.

Convergence statement. The six perspectives reached the same five High findings from different evidence (the monitor switch, the sweep permission, the runner allowlist, the dry sweep that writes, the de-arming tool change), and the Critical findings (the motivating example passing, the outcome measure counting the designed path) came from the Data Scientist's replay alone, which the other lenses could not have produced. No finding contradicted a spec-level resolution. Eleven amend the spec and are listed in Task 11. Stop signal reached for the plan: a second round would re-read the same code.
