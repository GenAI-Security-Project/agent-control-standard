# Premortem: the roadmap page design

Version: 1.0
Owner: ACS project lead
Date: 2026-10-04
Artifact: `design/2026-10-04-roadmap-page-design.md`, versions 1.0 through 1.4, revised to 1.5

Five rounds, 27 independent reviews. Every finding was grounded in a quoted passage, a live API
response, or a scratch build. Correlated findings from several reviewers raised confidence only when
they brought different evidence.

## Convergence

The premortem did not converge. All five rounds completed, and round five still produced High
findings. The pattern across rounds is itself the main finding: each round's fixes introduced the
next round's defects. Moving the fetch into its own job in version 1.3 created the Critical job-skip
defect that round four found, and the switches added in version 1.3 contradicted the preview path
round four tested. The design grew from about 200 lines to about 820 to hold a page that lists
milestones.

The strongest single counterargument to building it as specified came from round five: GitHub's own
milestone page already shows the same content with no code and no injection surface, and the
practice the design depends on, setting and closing milestones, has not yet held in this repository.

## Rounds

| Round | Layer | Perspectives | Highest surviving findings |
| --- | --- | --- | --- |
| 1 | Problem framing and data | all six | Automatic milestone closing reported unshipped work as Published by four separate paths. Milestoning auto-accepted deferred and untriaged work. A relative link failed the strict build. |
| 2 | Methodology | all six | The post-render scan could not detect script injection. The default concurrency cancelled pending acceptance events. Withdrawn was unreachable. `allowed-tools` restricts nothing. Promotion has failed since September 24. |
| 3 | Security | four, Data Scientist and Governance skipped as covered in round 2 | The title guard covered one of four rendered classes. Python-Markdown parsed top-level raw HTML lines. The OWASP model read text a write-role account could plant. |
| 4 | Implementation and operations | three, Data Scientist and Security Architect skipped as unchanged | A separate fetch job silently skipped build and deploy (Critical). `MEMBER` means organization membership. The render switch, fixture rule, and preview path contradicted each other. |
| 5 | Governance and second-order effects | three | Progress counts a practice the repository does not follow. The design repeats the September 9 milestone bet. Author drops bypass the Unverified class. A merge credits whatever the pull request body claims to close. Several governance decisions were being made by default. |

## Dropped ledger

| Claim | Anchor | Posterior | Why dropped |
| --- | --- | --- | --- |
| The search index reopens injection | `search/search_index.json` | Remote | Two reviewers confirmed Material re-escapes indexed text |
| Workflow files on `integration` and tools on `main` drift apart | the `ref: main` checkout | Unlikely | Low impact. Recorded as residual risk |
| Milestoning an already-closed issue pads progress | issue classes | Unlikely | Rare and visible on the card |
| Quarter boundary timezone shift | `due_on` storage | Unlikely | GitHub stores the chosen date at 00:00Z, verified. The UI path is tested in migration step 1 |
| A fork pull request alters the committed fixture to hide a defect | `tests/fixtures/` | Unlikely | `/tests/` is code-owned and review is required |
| Dispatching deploy-pages with inputs | `workflow_dispatch` | Unlikely | Needs the Write role, which can already push a workflow |
| Secondary rate limits during migration `--apply` | migration step 4 | Unlikely | The tool is idempotent and paced |

Tail risks, Critical and irreversible below Plausible: none. Every Critical finding was either fixed
or is a decision listed in the design.

## Prioritized remediation

Ordered by expected cost reduction per unit of effort. Items marked "decision" need the project lead.

1. **Decision 1, phase 0 first.** Closes the proportionality finding and most of the attack surface at
   once. Verification: milestones stay current through four weekly calls before the page is built.
2. **Decision 2, "Closes #N".** Closes the near-zero progress finding. Verification: the migration
   check's "possibly delivered" list is empty after triage, and new accepted work closes on merge.
3. **Decision 11, repair promotion.** Nothing in the design reaches the site until it is done.
4. **Spec 1.5 mechanical fixes.** Already applied: the single build driver, the deploy `if`, the
   read-only `dryrun` job, strict roster parsing, per-milestone queries with a node bound, the
   `roadmap.json` schema, the Unverified class covering every close by a non-maintainer, the
   closing-keyword comment, the single-call pr-intake check, and the hardened OWASP script.
   Verification: the test table in the design.
5. **Decisions 3 to 8.** Each changes data or wording, not code structure, so the implementation can
   carry the current defaults behind one mapping table and change them in one place.
6. **Decisions 9 and 10.** Token and alerting changes, each its own approval.

## Residual risk

Recorded in the design's Residual risk section: promotion, triage throughput, eight deliverables in
one quarter, one alarm inbox, the shared build job holding a read-only token, write-role accounts,
the health issue landing on the board, version skew, inactivity, and the search index's dependence on
Material's escaping.
