# Held-out ACS-Core slice

A published corpus cannot tell an implementation that reads each request from one that looks the answer up, because a lookup table keyed on the published bytes passes every member. The held-out slice closes that gap for the ACS-Core vectors without keeping the corpus secret.

## Who holds what

- The **Spec workstream** holds the seed, as the steward of the conformance suite (#19, closed into #33). It is stored as the repository secret `ACS_HELDOUT_SEED`, which only maintainers can set and which a pull request from a fork never sees.
- **Everyone** holds the generator. It is [`heldout-runner/agent_evidence_vectors/heldout.py`](heldout-runner/agent_evidence_vectors/heldout.py), retained in this repository byte for byte from agent-evidence-vectors 0.17.7 and recorded with its digest in [`acs-core-source.json`](acs-core-source.json), so the way a sealed member is made is public, reviewable here and changed only by a diff in this repository.
- The **commitment** to the seed is published below before the seed is used, and the seed is published after the release it measured, so anyone can regenerate the slice and check the run.

A sealed member is a published member with every opaque identifier (`request_id`, `session_id`, `turn_id`, `step_id`, `provenance_id`, `source_id`) respelled through a map keyed by the seed. The map keeps equality inside the member, so a duplicated `request_id` stays duplicated and the member asks the same question in bytes nobody has seen. Members with no opaque identifier are never sealed, since they would come out byte-identical to the published copy.

## What the job reports

`.github/workflows/acs-core-conformance.yml` runs the reference Guardian, then runs the retained suite through [`scripts/acs-core-heldout-adapter.py`](../scripts/acs-core-heldout-adapter.py). Nothing is installed from outside the repository for this. The adapter receives only each member's payload, never its id or expected verdict. The record pins the adapter's bytes, the corpus digest, the runner's own digest and the transcript digest, and closes with a seal over itself; the runner's `verify` command rechecks it.

On `integration`, with the secret set, the sealed slice is mixed into the run in an order that does not reveal which members are sealed. The record reports public and sealed pass rates per family and the gap between them. A real implementation scores about the same on both; a lookup table passes the public members and fails the sealed ones. On a pull request the job runs the public corpus and the runner's own controls only.

## Steward steps

From `reference-implementations/agt`, with Python 3.11 or later and nothing else installed:

```sh
H=conformance/heldout-runner/agent_evidence_vectors/heldout.py
head -c 48 /dev/urandom | base64 > seed                    # keep it out of the repository
python3 "$H" commit --seed-file seed                       # publish this digest below first
gh secret set ACS_HELDOUT_SEED < seed
# after the release the slice measured:
python3 "$H" reveal --seed-file seed --sealed SEALED.json
```

## Published commitments

| Release | Commitment | Seed |
|---|---|---|
| v0.2.0 | not yet set | not yet published |
