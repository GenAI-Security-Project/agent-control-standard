# ACS-Core negative conformance suite

Negative conformance vectors for the mandatory profile of the OWASP Agent
Control Standard, read at commit `9d4a9da` of
`GenAI-Security-Project/agent-control-standard`. The four normative files the
vectors cite are vendored in `spec-vendored/` and pinned by sha256 in
`MANIFEST.json`.

## Nothing has been run against this

There is no reference adapter in the specification's repository at the pinned
commit, and the two pull requests that carried one are closed. So this corpus
ships with a self-check and with no observed results. `MANIFEST.json` carries
an empty `observedRuns` array and `aee-verify` refuses a non-empty one,
because a run row is added by whoever ran it, naming what they ran and what
they ran it against. The counts here describe inputs with declared
expectations. They are not a score, and nothing in this directory is evidence
that any implementation does anything.

One run has since happened, on 2026-09-18, against the reference Guardian in
`reference-implementations/agt` of the specification's repository at commit
`dc26547` on `integration`, which postdates the pinned commit. It is not
recorded in `observedRuns` because the row shape is not yet defined here, and
a run against a Guardian validating a later schema than the one this corpus
pins is a result about that pairing, not about the pinned specification. The
four members of family `acs-f-9` were written from that run.

## Identifiers are minted here, and bound to a sentence

The specification carries no requirement identifiers. Its normative sentences
are addressable by section number and by line, and both move on an edit that
changes nothing about the requirement, so a vector citing either would keep
citing after a reword and quietly mean something else. Each row in the
requirement table quotes its normative sentence; `gen_vectors.py` locates that
sentence in the vendored copy, records the line it derived rather than one
typed by hand, and hashes the NFC bytes. A reword stops the build.

That is the whole argument for the identifier scheme, and it is why the
identifier is opaque. `ACS-R-004` names a sentence. A name built out of a
section number names a position, and a position is the thing that moves.

## A verdict is a code, never prose

Every member asserting a refusal names a value from the specification's own
fixed error registry, and `aee-verify` refuses a member that invents one.
Substring matching against operator messages fails a correct implementation
that words a refusal differently and passes a wrong one that words the right
cause, which are the two errors that matter in opposite directions.

The disposition vocabulary the specification calls free is deliberately not
asserted anywhere here. A field the specification does not fix is a field two
conformant implementations may spell differently, and scoring on it would
measure agreement with one of them.

## Three verdicts, because two hide a gap

A member is `allow`, `deny`, or `unmeasurable`. The third exists because the
specification has requirements whose violation it gives a deployment no
conformant way to detect: the revoked-mandate member is one, since revocation
propagation is listed as pending in the specification's own identity overview,
and the HMAC wrong-signer member is another, since under the symmetric baseline
the verification key is the signing key.
Scoring that member as a rejection would credit an implementation for behaviour
nothing requires. Scoring it as a pass would delete the gap from the record.
Every `unmeasurable` member carries the reason it cannot be measured, and the
self-check refuses one that does not.

## Every rejecting family accepts something

`aee-verify` refuses a corpus in which a family rejects and never
accepts. A suite of rejections alone awards full marks to a deployment that
denies every input, and that deployment governs nothing. The sequenced family
carries a sequenced control for the same reason: a single-step positive
satisfies the gate in appearance only, because it cannot tell an engine
honouring a turn boundary from a harness that reset the counter.

## Two columns beyond the verdict

Each member declares an `evidenceBasis` of `substrate` or `artifact`, and a
`witnessScope` of `SELF`, `PEER` or `EXTERNAL`. The first says whether the
expectation rests on an observation of the run or on a record the run emitted
about itself; a party holding the enclosing key and not the observation key can
move every row to `artifact` and emit something byte-identical to what an
honest producer with no observation vantage emits, so only a declaration
separates them. The second says who can check the member without the
enforcement point's cooperation. Most rows are `SELF`, and that is a finding
about the wire format rather than a failure of the corpus.

A `coverage` field says which rung of the coverage ladder a member exercises:
`supported`, `configured`, `effective`, `observed`. Declared support and
effective enforcement are different properties, and a corpus that does not
separate them scores a deployment on what it says about itself.

## Layout

| path | what it is |
|---|---|
| `vectors/` | one file per member, named after a digest of its own declaration |
| `spec-vendored/` | the four normative files the requirements are read from, pinned by digest |
| `MANIFEST.json` | the requirement table, the families, the scope-away list, counts and corpus digest |
| `INDEX.md` | every requirement and every member in one table |
| `gen_vectors.py` | regenerates the corpus byte-identically |

## Running it

```
aee-verify vectors-acs-core/       # self-check, from the repository root
python3 gen_vectors.py             # regenerate, byte-identically
python3 gen_vectors.py --check     # refuse a tree the generator does not emit
```

`aee-verify` is the one harness for every corpus in this repository. It reads
the `suite` field of a `MANIFEST.json`, judges the members that suite declares,
and refuses by name a suite it does not know. Each corpus used to carry a
Python self-check of its own, so the command a reader was told to run differed
per corpus and three of the six were wired into no workflow at all. Build it
with `go build -o aee-verify ./cmd/aee-verify`.

## What is deliberately absent

An open pull request is moving four surfaces of the mandatory profile, and no
vector is written against any of them. `MANIFEST.json` lists them with the
reason. The list is the part of a corpus a reader cannot reconstruct from the
corpus, so it is recorded rather than left implicit.

A second list, `awaitingText` in `MANIFEST.json`, holds cases raised on the
specification's tracker that no sentence at the pinned commit says. A member
for one of them would cite a requirement that does not say what it tests, so
each waits for its sentence and is minted from that sentence when it lands.

## The same property at two witness scopes

The sealed-session members in `acs-f-6` come in a pair per profile. A seal that
drops a head the Guardian already published is refused with `CHAIN_MISMATCH`
under both the HMAC baseline and ACS-Crypto, and only the witness scope
differs: `PEER` under the baseline, where the Observed Agent holds the session
key and the heads already published to it, and `EXTERNAL` under ACS-Crypto,
where the public key lets a third party show which heads the Guardian signed.
The baseline stops at the peer because the Guardian holds the same key and can
re-sign a shorter chain, so the Core half never claims a third-party witness.

## A wrong signer and an undeterminable one

Family `acs-f-10` carries one substitution under both profiles: the Observed
Agent signs a chain head and presents it as the Guardian's. Here the two
profiles do not differ only in witness scope; they give different verdicts.
Under ACS-Crypto the signature verifies only under the Observed Agent's own key
while its `key_id` resolves to the Guardian's, so it fails verification and is
refused with `SIGNATURE_INVALID`, and a party holding only the Guardian's
public key can see the wrong signer, which makes the member `EXTERNAL`. It has
an accepting twin signed by the Guardian. Under the HMAC baseline both parties
hold the session key, the Observed Agent's MAC verifies under the key the
`key_id` resolves to, and nothing in the head or the public material says who
computed it. That member is `unmeasurable`, citing the section 8.6 sentence
that puts non-repudiation in ACS-Crypto, and `SELF`, because the only accounts
of who signed are the two key-holders' own. A verifier has to report "the
signer is wrong" and "the signer cannot be determined" as different outcomes,
so the corpus does not give them one shape.

A third member refuses the claim rather than the signature. An HMAC head the
Guardian did sign, presented to a third party as proof of which Guardian issued
it, is graded `deny` with no registry code, because the symmetric tier cannot
carry that claim and a surface that only calls it weak lets it through. It is
`EXTERNAL`: the algorithm and the claim are both in the presented bytes, so an
outside party can refuse it without the Guardian's account or the key. Its
accepting twin presents the same head to a key-holder as integrity evidence, so
a verifier that refuses every HMAC head fails the family rather than passing it.

Nothing here tests content filtering, model robustness, or prompt injection
detection. The member about attributed content tests one property: that
provenance establishes lineage and confers no authority. A suite that reached
past that would be measuring a judgment rather than a rule.
