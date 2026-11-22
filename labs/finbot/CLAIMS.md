# Claims ledger for the FinBot lab

This file lists every claim the guided FinBot lab makes, the evidence behind each, and the limits on it. It also lists what the lab doesn't claim. A named human signs it before any keeper take is recorded (the sign-off table at the bottom).

The deck, the narration, the run sheets and the recording live outside this repository. A person reads them against this file before a take is kept, because no test can. The section on what tests enforce says where that line falls.

Evidence names code on the lab branch, and the sign gate refuses a backticked path the repository doesn't hold. Text in an evidence cell after `Unconfirmed:` names a fact this tree can't show yet, and Rock decides it before signing.

A claim marker is an HTML comment such as `<!-- claim:C-03 -->`. It goes in the same paragraph, list item, table row or heading as the claim, before or after the sentence on the same line. A marker binds to every sentence that touches its own source line, in Markdown, raw HTML and HTML pages alike, and it never clears a sentence on another line. A sentence ends at a period, question mark or exclamation mark, after any closing quotes or brackets. A marker on a line of its own marks nothing in Markdown prose. Inside raw HTML or a page, a marker alone on its line binds the next line that holds text, and a marker alone in a table cell binds its row, every cell of it, as a GFM row on one line does. A trigger inside inline code needs a marker too, so a command belongs in a fenced block, where triggers are exempt. The check reads `.md`, `.markdown`, `.html`, `.htm` and `.txt` files, and reads `.rst`, `.adoc`, `.mdx` and a suffixless README as plain text. Directories named `tests` or `test` are never scanned, so attendee prose doesn't belong under one.

## Claims

| Id | Claim | Evidence | Limits |
|---|---|---|---|
| C-01 | FinBot's code ran unchanged at 1450fc4. Four settings differ from FinBot's own `docker-compose.yml`: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `LLM_TIMEOUT` (60 to 360) and `WEB_CONCURRENCY` (3 to 1). `REDIS_URL` and `DATABASE_URL` match FinBot's own compose. The Guardian lives on a network FinBot can't reach. | Unconfirmed: the lab compose file (LAB-15) isn't on this tree, so the four settings and the networks can't be read here. | A claim about the compose file as shipped. It says nothing about FinBot's code beyond that commit. |
| C-02 | Every Guardian decision in a run with signing on was signed with ML-DSA-65 as specified in FIPS 204, pure mode, empty context. The library isn't a FIPS 140-3 validated module. | `adapters/src/acs/core/_mldsa.py` (pure mode, empty context string). `adapters/src/acs/guardian/_response_signing.py` and `adapters/src/acs/client/_key_document.py` (the `ACS_RESPONSE_SIGNING` setting and its off values). | Signing is off unless `ACS_RESPONSE_SIGNING=ML-DSA-65` is set. While signing is off, Guardian answers stay on HMAC-SHA256. Requests always stay on HMAC-SHA256. |
| C-03 | A forged decision fails under ML-DSA-65 when the verifier got the Guardian's public key over a channel the forger doesn't control. The lab can pin the key by fingerprint. | `adapters/src/acs/client/_key_document.py` (`ACS_GUARDIAN_KEY_FINGERPRINT`, when set, must equal the chosen key's fingerprint). Unconfirmed: that the lab compose sets the pin (LAB-15). | The pin is optional in the code, so an unpinned run gets no fingerprint check. The key document is a lab convention until issue #460. A verifier that fetched the key from the forger's channel gets no protection. |
| C-04 | Anyone holding the shared HMAC key, here the gateway, can forge a Guardian allow. Decision signing makes a forgery detectable. | `adapters/src/acs/core/_signing.py` and `adapters/src/acs/client/_signing.py` (HMAC with a shared secret, and keyring verification for ML-DSA-65). Unconfirmed: the decision viewer (LAB-13) isn't on the lab branch yet. On its own branch, labs/finbot/viewer/verify.py and model.py run acs-verify over each session file, keys only, and leave the audit chain to lab verify. A row reads verified only for an ML-DSA-65 answer the viewer checked, so a forged answer in such a session reads failed, and an HMAC session reads not checked. | Detectable means a verifier holding the public key can tell. It doesn't mean anyone looked. |
| C-05 | A Guardian signing with ML-DSA-65 refuses a session whose ClientHello doesn't offer ML-DSA-65, so a client that can only verify HMAC never gets the fallback. | `adapters/src/acs/guardian/example_guardian.py` (the handshake raises `SESSION_REFUSED`, lab convention, issue #316). | The refusal covers the response algorithm only. Requests stay on HMAC-SHA256. |
| C-06 | Two of nineteen hook methods are governed live: `steps/toolCallRequest` and `steps/toolCallResult`. `steps/sessionStart` opens the chain, and `steps/sessionEnd` closes a session the gateway drops. | `adapters/gateway/src/acs_gateway/guardian.py` (the four method constants in `METHODS`). `docs/spec/instrument/hooks.md` (nineteen native hooks). | The gateway gates function tools only. Hosted and client-run tool types answer 501 in enforce. |
| C-07 | Retired 2026-11-22: the clips do not state an attempt count. | Rock, 2026-11-22. | None. |
| C-08 | Replay serves recorded model answers for the branches we recorded. Any other branch gets a fixed neutral reply, and the viewer marks it. | `adapters/gateway/src/acs_gateway/upstream.py` (`miss_response`, with fixed ids and the neutral line, the `replay_miss` audit line and the `acs.lab.replay_miss` event). `labs/finbot/viewer/model.py:57-58` and `labs/finbot/viewer/model.py:962-965` (the decision viewer turns each `replay_miss` audit line into a row of its own with the note `replay miss: recorded neutral reply`). `labs/finbot/viewer/static/app.js:131-136` (the page draws a row's note on its own line under the row). Unconfirmed: until capture, the recordings (LAB-16) and the name of the recorded model. | A miss is a fixed line, never a model's guess. |
| C-09 | In enforce mode the lab fails closed, per D-036. Shadow mode forwards traffic on gateway faults. The v0.1.0 specification default is still proceed until the change in issue #32 merges. | `adapters/gateway/README.md` (enforce fails closed on anything it can't gate, and shadow records and forwards unchanged). `adapters/src/acs/guardian/example_guardian.py` (`on_decision_failure` is `deny` unless `ACS_ON_DECISION_FAILURE=proceed`). `specification/v0.1.0/handshake.json` (default `proceed`). | The hook adapters (Claude Code, Cursor, NAT) keep their own default and aren't part of the lab. |
| C-10 | The lab isn't the project's committed outcome. LAB-10 times signatures only. | `adapters/benchmarks/signatures/` (signature timings, no comparison harness). | None beyond the claim itself. |
| C-11 | Release 0.1.5 adds experimental ML-DSA-65 signing, off by default, as a lab convention. | `adapters/src/acs/client/_key_document.py` (unset or `HMAC-SHA256` means off). `adapters/pyproject.toml` (the `pqc` extra). Unconfirmed: `version.txt` reads 0.1.4 on this tree, so the release itself waits on the cut. | Experimental means no support commitment. |
| C-12 | The lab ran on the build team's machines and in CI. | Unconfirmed: no run record exists on this tree. | No run by anyone outside the build team. |
| C-13 | The lab runs the v0.1.0 schemas plus labeled lab conventions. | `adapters/src/acs/client/_handshake.py` and `adapters/src/acs/guardian/example_guardian.py` (the `x_acs_lab_response_algorithms` and `x_acs_lab_response_algorithm` fields). `adapters/src/acs/client/_key_document.py` (the `acs-lab-keys/1` document). | Each convention names the issue that would settle it (#316, #460). None is in the specification. |
| C-14 | In enforce mode the lab runs default deny while `handshake.json` still defaults `on_decision_failure` to `proceed`. D-036 decided deny, and the specification change is pending (issue #32). | `specification/v0.1.0/handshake.json` (default `proceed`). `adapters/src/acs/guardian/example_guardian.py` (the ServerHello posture). | A lab run that reads the specification alone would see the opposite default. |
| C-15 | The lab proves nothing about interoperability with any other implementation. | No second implementation runs in the lab. | None beyond the claim itself. |
| C-16 | The lab supports macOS and Linux only. Windows is untested. | Rock, 2026-11-17. | A Windows machine may work. Nobody on the build team checked. |
| C-17 | FinBot can't bypass the Guardian. It never talks to the Guardian, the Guardian lives on a network FinBot can't reach, and FinBot reaches the model only through the gateway, which requires this lab's client token. | `labs/finbot/compose.yaml:65-67` (FinBot joins finbot-net and drive-net only). `labs/finbot/compose.yaml:212-213` and `labs/finbot/compose.yaml:248-249` (the Guardian and OPA join acs-net only). `labs/finbot/compose.yaml:324-325` (acs-net is internal). `labs/finbot/compose.openai.yaml` adds no network and mounts the model key into the gateway only, at `labs/finbot/compose.openai.yaml:12-19`. `labs/finbot/compose.yaml:58` (FinBot's model base URL is the gateway) and `labs/finbot/compose.yaml:60` (FinBot's key is the lab's client token). `adapters/gateway/src/acs_gateway/app.py:1479-1511` (`ClientTokenGate` answers 401 to a request without that exact bearer, before the body is read) and `adapters/gateway/src/acs_gateway/app.py:1516-1523` (the gate wraps every route once a token file is set), with the file set at `labs/finbot/compose.yaml:135`. `labs/finbot/cli/commands.py:146-147` and `labs/finbot/cli/commands.py:172` (lab init generates the token and writes it to the secret file and to .env). `labs/finbot/lab.sh:267-271` (the lab won't start without it). Unconfirmed: that no network gives FinBot another route to a model. finbot-net isn't internal (`labs/finbot/compose.yaml:323`), so FinBot can reach the internet, a model provider's API included. FinBot's model calls stay on the gateway because of its base URL and because it holds no model key, not because the network confines it. | A blocked action is visible to the agent that tried it, as with any enforcement point. The Guardian decides only the steps the gateway sends it, the two governed hooks in C-06. |

## Not claimed

| Id | The lab doesn't claim | Why |
|---|---|---|
| N-01 | That the control is hidden from the agent. | Hiding it isn't the goal. Any control that blocks an action is visible to the agent it stops, through the failed action and the neutral deny line. What the lab claims is that the agent can't bypass it (C-17). |
| N-02 | That requests are attributable. | Requests stay on HMAC inside the trust boundary by design. |
| N-03 | That key publication or revocation is solved. | The key document is a lab convention until issue #460. |
| N-04 | That signing proves the record is complete, or that the gateway honored a deny. | A signature covers one decision. It doesn't cover decisions that never reached the Guardian. |
| N-05 | That downgrade is fully prevented. | Full detection needs transcript binding (issue #13). |
| N-06 | That the stack is ACS-Core conformant. | It sends 4 of the 7 minimum hooks (`sessionStart`, `toolCallRequest`, `toolCallResult`, `sessionEnd`), and wrapped MCP has no wire definition yet (issue #383). |
| N-07 | Retired 2026-11-22: the ledger no longer lists this non-claim. | Rock, 2026-11-22. |
| N-08 | That replay reproduces a live model. | Replay serves what was recorded and a fixed line for anything else. |
| N-09 | That 0.2.0 is released, or that the demo branch is a release. | The demo branch is a lab branch. |
| N-10 | That ACS is benchmarked against, or interoperates with, Microsoft's Agent Governance Toolkit. | LAB-10 times ACS signatures only. |
| N-11 | That 0.1.5 makes an ACS-Crypto or ACS-Core claim. | Signing is experimental and off by default. |
| N-12 | Retired 2026-11-22: the ledger no longer lists this non-claim. | Rock, 2026-11-22. |
| N-13 | That the signing library is a FIPS 140-3 validated module. | ML-DSA-65 follows FIPS 204, and the library has no FIPS 140 validation. |

## Banned phrasing

One case-insensitive phrase per line. A phrase matches on word boundaries. A unit (defined under what the tests enforce) that holds one fails the check unless it also carries a marker, written as an HTML comment such as `<!-- claim:N-06 -->`, for a Not claimed row that names that phrase in the block below. A marker for another row doesn't excuse it. A marker written as plain text isn't a marker.

```claims-banned
ACS-Core conformant
ACS-Crypto
interoperates with
interoperability with
Agent Governance Toolkit
AGT
FIPS 140
FIPS validated
FIPS-validated
can't tell a control exists
invisible to the agent
hidden from the agent
attributable
revocation is solved
proves the record is complete
prove the record is complete
prevents downgrade
stops attacks
blocks every
tested by attendees
independently tested
benchmarked against
0.2.0 is released
production-ready
reproduces a live model
Zenity
supports Windows
Windows is supported
works on Windows
runs on Windows
runs under Windows
```

Each Not claimed row names the banned phrases it excuses, as `N-NN: phrase | phrase`. Every Not claimed row needs a line here unless it's retired, and every phrase must be on the banned list above. A retired row keeps its id, opens with `Retired` and the date of the ruling, and has no line, so it excuses nothing and its old phrases stay banned.

```claims-not-claimed
N-01: can't tell a control exists | invisible to the agent | hidden from the agent
N-02: attributable
N-03: revocation is solved
N-04: proves the record is complete | prove the record is complete
N-05: prevents downgrade
N-06: ACS-Core conformant
N-08: reproduces a live model
N-09: 0.2.0 is released
N-10: Agent Governance Toolkit | AGT | interoperates with | interoperability with | benchmarked against
N-11: ACS-Crypto
N-13: FIPS 140 | FIPS validated | FIPS-validated
```

## Claim triggers

One case-insensitive word stem per line, matched at the start of a word. A unit that holds one needs a marker for a row in this ledger, such as `<!-- claim:C-03 -->`. Code blocks are exempt, because they hold commands.

```claims-triggers
prove
guarantee
prevent
verif
conform
secure
FIPS
signed with
forge
tamper
fail closed
fails closed
unchanged
unmodified
Windows
```

## Scan exclusions

The check scans prose an attendee reads: Markdown, HTML and plain-text files (`.md`, `.markdown`, `.html`, `.htm`, `.txt`, `.rst`, `.adoc`, `.mdx`, and a `README` with no suffix, in any letter case). It never scans code, such as `.py`, `.rego`, `.sh`, `.js`, `.css`, `.yaml` and `.json` files or script and style inside a page, because code comments and identifiers make no claim to attendees. Below, one glob per line, relative to the scanned directory, excludes prose files too. Test directories are excluded for the same reason as code. The ledger itself is never scanned.

```claims-exclude
**/tests/**
**/test/**
state/**
replay/recordings/**
CLAIMS.md
**/*.lock
policy/tools/inputs/**
```

## What the tests enforce and what only a reader catches

The check reads Markdown as markdown-it-py renders it, under CommonMark with GitHub's table and strikethrough rules, and reads HTML as a browser parses it, then matches the text a reader sees. Each block is one unit: a paragraph, a list item, a table row, a heading or a code block. A marker binds only to the sentences that touch its own source line, with the two HTML exceptions named at the top of this file. A raw HTML cell or element whose content holds a blank line renders that content as Markdown, so each paragraph inside it is its own unit. Markdown, HTML and plain-text files are scanned, each by its own reader: `.md` and `.markdown` render as Markdown, `.html` and `.htm` parse as HTML, and `.txt`, `.rst`, `.adoc`, `.mdx` and a suffixless `README` are plain text, matched one line at a time. Code files and test directories aren't scanned (see Scan exclusions). A marker counts only inside a real HTML comment, so a marker in a code span, in a code block or after an escaped angle bracket doesn't count. The check never skips a file silently. A prose file it doesn't read is named as SKIPPED with the reason: a file or directory symlink, which it never follows, a file that isn't a regular file, a directory it can't list, a file over 4 MiB, or a file that isn't valid UTF-8 and has no UTF byte order mark, such as a Windows-1252 file or a UTF-16 file with none. A file that opens with a UTF-8, UTF-16 or UTF-32 byte order mark is decoded and scanned. A prose file it can't read as text, or one over 4 MiB, fails the run, and at the sign gate any skip does.

The test enforces these:

- No banned phrase appears in lab text unless its unit carries a marker for a Not claimed row that names that phrase in the claims-not-claimed block.
- No unit outside a code block holds a claim trigger without a marker.
- Every marker names an id that exists in this ledger.
- Every id, claim row and machine block sits above `## Sign-off`, no id repeats, and no machine block appears twice.
- With `--require-signed`, the sign-off row is filled in, its digest matches the ledger text above it, no claim row says Unconfirmed in any case, no claim row has empty or placeholder evidence, every backticked path a claim row's evidence cites before any Unconfirmed note exists in the repository, and the ledger holds claim rows. Placeholder evidence has no letter or digit once punctuation and link syntax are gone, or is only N/A, NA or none, or is or opens with TBD, TBA, TBC, TODO, pending, not yet, to be confirmed or to be determined.

Only a reader catches these:

- A marker on a sentence that says more than its row does.
- A paraphrase that avoids every banned phrase and every trigger.
- A banned phrase split across lines in a plain-text file, which is matched one line at a time.
- Code and tests, which aren't scanned. Text that code shows an attendee, such as a CLI message or a page built by script, is a reader's job.
- Any place where markdown-it-py reads Markdown differently from GitHub. Both follow CommonMark, which settles lists, tabs, indented and fenced code, lazy continuation, block quotes, raw HTML blocks and a line that opens with a comment. GitHub adds GFM, and the check enables GFM tables and strikethrough. It doesn't model GFM footnotes: a footnote reads as paragraph text, a one-word footnote is read from its definition, and a footnote paragraph indented after a blank line is unindented first, so it reads as prose, as GitHub shows it. GitHub doesn't render admonitions, collapsibles or definition lists, so they read as paragraphs, and an admonition body after a blank line is a code block on GitHub and to the check alike. Emphasis and code marks left as text in raw HTML are dropped before matching. An underscore between two letters or digits is part of the word, and any other underscore reads as a space. A test records pandoc's gfm reading, from a second CommonMark implementation, of every Markdown layout below and every reviewer probe, and the check must agree with each one. Those fixtures check how the source is read, not how markers bind, because both readings run the check's own binder. A separate generated test pins binding: a marker position (after, before or alone on its line) in each Markdown and HTML container, with each sentence ending, beside an overclaim on the line before or after. A generated test crosses each container (paragraph, list item after a paragraph at several indents, a marker indented past its item's content, nested list, block quote, block-quote list, admonition, collapsible, definition list, task list, footnote, table cell, and the HTML elements `<details>`, `<summary>`, `<div>`, `<section>`, `<p>`, `<td>`, `<th>` and `<li>`) with each placement (alone, hard-wrapped, emphasis, code, link, fenced block, marker first, and beside a marked sibling) in every scanned Markdown and HTML suffix, in both directions: every unmarked claim is caught, and every honestly marked one passes. A reader confirms what the page shows for any construct outside those tests.
- A marked line with no closing punctuation, such as a line that ends in a colon or with no period, joins the next line's sentence, so the marker reaches that line too. A code span that wraps across lines hides its line break the same way, and so does a line break inside a start tag, such as an attribute wrapped onto the next line.
- A footnote reference or a `<sup>` right after a period, which hides the sentence end, so a marker on that line reaches the next line's sentence.
- Three honest HTML layouts that fail loudly rather than miss anything. A marker alone on the line after its claim, inside the same element, binds nothing, because no text line follows it. A claim cell that holds a `<p>` or a blank line becomes a unit apart from a marker-only cell beside it. After an omitted `</td>`, a marker-only cell binds by line. Each one reports the claim, and the fix is to put the marker on the claim's line.
- Deliberate obfuscation by someone with commit access. The check exists to catch an accidental overclaim. Hiding one on purpose is a reviewer's job.
- An edit to this ledger made after signing with a recomputed digest. The digest has no key, so anyone can recompute it.
- Anything outside the repository: the deck, the narration, the run sheets, and the words spoken in a recording.
- Anything a viewer sees but no file holds, such as video frames and audio.
- Evidence that stopped being true after a later code change.

## Sign-off

The signer fills in the row on 2026-11-30 with a name, an ISO date, the full commit SHA the ledger was signed at, and the sha256 of the ledger text above this section, which `python3 labs/finbot/cli/lab_claims.py --digest` prints. The digest catches an edit made without recomputing it, which then reads as unsigned. The digest has no key, so an edit with a recomputed digest passes the gate, and only a reader catches it.

| Signed by | Date | Commit | Ledger sha256 |
|---|---|---|---|
| | | | |
