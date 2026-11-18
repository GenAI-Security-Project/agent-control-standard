# Claims ledger for the FinBot lab

This file lists every claim the guided FinBot lab makes, the evidence behind each, and the limits on it. It also lists what the lab doesn't claim. A named human signs it before any keeper take is recorded (the sign-off table at the bottom).

The deck, the narration, the run sheets and the recording live outside this repository. A person reads them against this file before a take is kept, because no test can. The section on what tests enforce says where that line falls.

Evidence names code on the lab branch. A row that starts its evidence with `Unconfirmed:` names a fact this tree can't show yet, and Rock decides it before signing.

## Claims

| Id | Claim | Evidence | Limits |
|---|---|---|---|
| C-01 | FinBot's code ran unchanged at 1450fc4. Four settings differ from FinBot's own `docker-compose.yml`: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `LLM_TIMEOUT` (60 to 360) and `WEB_CONCURRENCY` (3 to 1). `REDIS_URL` and `DATABASE_URL` match FinBot's own compose. The Guardian lives on a network FinBot can't reach. | Unconfirmed: the lab compose file (LAB-15) isn't on this tree, so the four settings and the networks can't be read here. | A claim about the compose file as shipped. It says nothing about FinBot's code beyond that commit. |
| C-02 | Every Guardian decision in a run with signing on was signed with ML-DSA-65 as specified in FIPS 204, pure mode, empty context. The library isn't a FIPS 140-3 validated module. | `adapters/src/acs/core/_mldsa.py` (pure mode, empty context string). `adapters/src/acs/guardian/decision_keys.py` (the `ACS_RESPONSE_SIGNING` setting). | Signing is off unless `ACS_RESPONSE_SIGNING=ML-DSA-65` is set, and answers then stay on HMAC-SHA256. Requests always stay on HMAC-SHA256. |
| C-03 | A forged decision fails under ML-DSA-65 when the verifier got the Guardian's public key over a channel the forger doesn't control. The lab pins the key by fingerprint. | `adapters/src/acs/client/_key_document.py` (`ACS_GUARDIAN_KEY_FINGERPRINT` must equal the chosen key's fingerprint). | The key document is a lab convention until issue #460. A verifier that fetched the key from the forger's channel gets no protection. |
| C-04 | Anyone holding the shared HMAC key, here the gateway, can forge a Guardian allow. Decision signing makes a forgery detectable. | `adapters/src/acs/core/_signing.py` and `adapters/src/acs/client/_signing.py` (HMAC with a shared secret, and keyring verification for ML-DSA-65). | Detectable means a verifier holding the public key can tell. It doesn't mean anyone looked. |
| C-05 | A Guardian signing with ML-DSA-65 refuses a session whose ClientHello doesn't offer ML-DSA-65, so a client that can only verify HMAC never gets the fallback. | `adapters/src/acs/guardian/example_guardian.py` (the handshake raises `SESSION_REFUSED`, lab convention, issue #316). | The refusal covers the response algorithm only. Requests stay on HMAC-SHA256. |
| C-06 | Two of nineteen hook methods are governed live: `steps/toolCallRequest` and `steps/toolCallResult`. `steps/sessionStart` opens the chain. | `adapters/gateway/src/acs_gateway/guardian.py` (the three method constants and the open-session call). `docs/spec/instrument/hooks.md` (nineteen native hooks). | The gateway gates function tools only. Hosted and client-run tool types answer 501 in enforce. |
| C-07 | Each clip is the take we kept after N attempts, with N stated per clip. The clips are demonstrations, not rates. | Unconfirmed: no clip or attempt count exists on this tree. | A clip says what one take showed. It gives no rate of anything. |
| C-08 | Replay serves recorded model answers for the branches we recorded. Any other branch gets a fixed neutral reply, and the viewer marks it. | `adapters/gateway/src/acs_gateway/upstream.py` (`miss_response`, with fixed ids and the neutral line, and the `acs.lab.replay_miss` event). Unconfirmed: the recordings (LAB-16), the name of the recorded model, and the viewer mark (LAB-13). | A miss is a fixed line, never a model's guess. |
| C-09 | The lab fails closed, per D-036. The v0.1.0 specification default is still proceed until the change in issue #32 merges. | `adapters/gateway/README.md` (the gateway's posture is always fail closed). `adapters/src/acs/guardian/example_guardian.py` (`on_decision_failure` is `deny` unless `ACS_ON_DECISION_FAILURE=proceed`). `specification/v0.1.0/handshake.json` (default `proceed`). | The hook adapters (Claude Code, Cursor, NAT) keep their own default and aren't part of the lab. |
| C-10 | The lab isn't the project's committed outcome. LAB-10 times signatures only. | `adapters/benchmarks/signatures/` (signature timings, no comparison harness). | None beyond the claim itself. |
| C-11 | Release 0.1.5 adds experimental ML-DSA-65 signing, off by default, as a lab convention. | `adapters/src/acs/guardian/decision_keys.py` (unset or `HMAC-SHA256` means off). `adapters/pyproject.toml` (the `pqc` extra). Unconfirmed: `version.txt` reads 0.1.4 on this tree, so the release itself waits on the cut. | Experimental means no support commitment. |
| C-12 | The lab ran on the build team's machines and in CI. | Unconfirmed: no run record exists on this tree. | No run by anyone outside the build team. |
| C-13 | The lab runs the v0.1.0 schemas plus labeled lab conventions. | `adapters/src/acs/client/_handshake.py` and `adapters/src/acs/guardian/example_guardian.py` (the `x_acs_lab_response_algorithms` and `x_acs_lab_response_algorithm` fields). `adapters/src/acs/client/_key_document.py` (the `acs-lab-keys/1` document). | Each convention names the issue that would settle it (#316, #460). None is in the specification. |
| C-14 | The lab runs default deny while `handshake.json` still defaults `on_decision_failure` to `proceed`. D-036 decided deny, and the specification change is pending (issue #32). | `specification/v0.1.0/handshake.json` (default `proceed`). `adapters/src/acs/guardian/example_guardian.py` (the ServerHello posture). | A lab run that reads the specification alone would see the opposite default. |
| C-15 | The lab proves nothing about interoperability with any other implementation. | No second implementation runs in the lab. | None beyond the claim itself. |
| C-16 | The lab supports macOS and Linux only. Windows is untested. | Rock, 2026-11-17. | A Windows machine may work. Nobody on the build team checked. |

## Not claimed

| Id | The lab doesn't claim | Why |
|---|---|---|
| N-01 | That the agent can't tell a control exists. | It can infer one from failed actions and the neutral deny line. |
| N-02 | That requests are attributable. | Requests stay on HMAC inside the trust boundary by design. |
| N-03 | That key publication or revocation is solved. | The key document is a lab convention until issue #460. |
| N-04 | That signing proves the record is complete, or that the gateway honored a deny. | A signature covers one decision. It doesn't cover decisions that never reached the Guardian. |
| N-05 | That downgrade is fully prevented. | Full detection needs transcript binding (issue #13). |
| N-06 | That the stack is ACS-Core conformant. | It sends 3 of the 7 minimum hooks, and wrapped MCP has no wire definition yet (issue #383). |
| N-07 | That ACS stops a given attack at any rate. | Clips are kept takes, not measurements. |
| N-08 | That replay reproduces a live model. | Replay serves what was recorded and a fixed line for anything else. |
| N-09 | That 0.2.0 is released, or that the demo branch is a release. | The demo branch is a lab branch. |
| N-10 | That ACS is benchmarked against, or interoperates with, Microsoft's Agent Governance Toolkit. | LAB-10 times ACS signatures only. |
| N-11 | That 0.1.5 makes an ACS-Crypto or ACS-Core claim. | Signing is experimental and off by default. |
| N-12 | That the lab was tested by anyone outside the build team. | The outside tester slot (LAB-17) was cut. |

## Disclosures

Say each of these wherever the lab is shown.

- The neutral deny line is the one artifact the agent sees when a control acts. It is a fixed sentence, and the agent can infer a control from it.
- Replay serves recorded branches only. Any other branch gets a fixed neutral reply.
- A clip is the kept take after N attempts, with N stated on the clip.

## Banned phrasing

One case-insensitive phrase per line. A phrase matches on word boundaries. A line or paragraph that holds one fails the check unless it also carries a marker for a row in the Not claimed table, such as `claim:N-06`.

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
Zenity
supports Windows
Windows is supported
works on Windows
runs on Windows
runs under Windows
```

## Claim triggers

One case-insensitive word stem per line, matched at the start of a word. A paragraph or line that holds one needs a marker for a row in this ledger, such as `claim:C-03`. Markdown code fences are exempt, because they hold commands.

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
```

## Scan exclusions

One glob per line, relative to the scanned directory. The ledger itself is never scanned.

```claims-exclude
state/**
replay/recordings/**
CLAIMS.md
**/*.lock
policy/tools/inputs/**
```

## What the tests enforce and what only a reader catches

The test enforces these:

- No banned phrase appears in lab text unless its line or paragraph carries a marker for a Not claimed row.
- No line or paragraph holding a claim trigger lacks a marker.
- Every marker names an id that exists in this ledger.
- With `--require-signed`, the sign-off row is filled in.

Only a reader catches these:

- A marker on a sentence that says more than its row does.
- A paraphrase that avoids every banned phrase and every trigger.
- Anything outside the repository: the deck, the narration, the run sheets, and the words spoken in a recording.
- Anything a viewer sees but no file holds, such as video frames and audio.
- Evidence that stopped being true after a later code change.
- A clip shown without its attempt count.

## Sign-off

The signer fills in the row on 2026-11-30 with a name, an ISO date and the full commit SHA the ledger was signed at.

| Signed by | Date | Commit |
|---|---|---|
| | | |
