# Roadmap rollout design: premortem record

Version: 1.0
Owner: ACS project leads
Date: 2026-10-04
Artifact: `design/2026-10-04-roadmap-rollout-design.md`, from version 1.0 (91f9874) to the
version at b8ca42c

Five rounds ran on October 4, 2026. Each round assumed the rollout had failed six months later
and worked backward. Reviewers read the code and the live repository settings, not only the
design.

## Round 1: framing

Six perspectives. Findings folded into version 1.1 (654072b):

- `apply_governance.py` declared the old ruleset shape, so a full run would revert the rollout's
  ruleset changes.
- The OWASP skill filtered rows on Initiative, which other ASI teams share, so it would have
  reported their rows as orphaned.
- The deliverable types did not match the sheet's dropdown.
- The roster parser read only one heading and could crash the sweep.
- Rebase merges let commit messages close issues past any body check.

Decisions taken in response: admin bypass stays and is reported, promotion is prompted rather
than automated, six contribution spellings, and no request to an OWASP org owner.

## Round 2: mechanisms

Five perspectives. The central finding, from four reviewers independently, was that the closing
check read one section while GitHub closes issues from the whole squash message, and the
template prefilled `Closes`. Version 1.2 (2925115) made the check read the body only, with no
issue lookups, and added exemptions, a kill switch, the undo log, and the monitor gap fix.

## Round 3: side doors

Five perspectives. Reviewers found closes that no pre-merge check sees: the pull request title,
edits in the merge box, sidebar links, and a decoy pull request on the same commit. Version 1.3
(0b35cbc) moved delivery verification into the model. An issue counts as done only when the
landed commit declares the close and is on `main`, or a project lead closed it by hand.

## Round 4: verification

Three perspectives. A lead's reclose turned "not on `main`" into done, and the health issue
advised exactly that. Reverts read as done. The deploy build lacked the grant to read pull
request closers. Version 1.4 (eaa85b9) fixed these, recorded decisions 12 to 16, and cut what
did not prevent a false claim, at the project lead's request. Decision 17 (f8ecee4) added
alerting every project lead.

## Round 5: final pass

One reviewer across all lenses, reporting High and Critical only. Two findings, both fixed in
66a6ff1 and b8ca42c:

- The alarm comment would fail on the locked health issue. The monitor now unlocks, comments,
  and relocks on a state change, and rollout tests it with a dispatch input.
- An open milestoned issue that lost `status:accepted` stopped counting as remaining, so a
  milestone could read Published with open work. Every open issue in a milestone now counts.

## Convergence

Round 5 produced no finding that needed new machinery, which is the stop signal.

## Dropped ledger

- A lapsed lead's self-close counting as delivered. Unlikely, and decision 12 now limits hand
  closes to project leads.
- Checking volunteers' repository permission by API. Low value, since code-owner review gates
  the table.
- A ruleset hash in the health issue. Superseded by delivery verification.
- Proving the health issue was written by the sweep. Needs an `actions: read` grant on the
  monitor, which is its own decision.
- A closed issue added to a milestone after its close. Unlikely, and it counts by its close.
- A `partial` sweep status. Removed in favor of today's rule that any failed read degrades.

## Residual risk

- Admins can bypass every ruleset except `protect-branch-existence`, by decision 14. The health
  issue reports bypassed merges and direct pushes, but not ruleset edits, which `GITHUB_TOKEN`
  cannot read.
- A project lead's hand close is an attestation, not a verification, by decision 12.
- Fred Wilmot holds the admin role, by decision.
