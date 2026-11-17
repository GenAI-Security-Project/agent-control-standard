# Checking a Transcript With acs-verify

`acs-verify` checks a Guardian session after the fact, with nothing but the transcript and the Guardian's key document. It recomputes the audit chain, verifies every decision signature, checks that each answer belongs to the request before it, and checks that the signing key was valid when the request was made. It names the first line that fails. Issue #584 adds it.

Until now only the example Guardian computed its chain (`compute_entry_hash` in `acs/guardian/example_guardian.py`). `acs-verify` lets someone other than the Guardian that wrote a log check it.

## Running it

From `adapters/`, with the `pqc` extra for ML-DSA-65:

```bash
uv run --extra pqc python -m acs.testing.verify state/transcripts/<session_id>.jsonl \
    --keys state/keys/guardian-keys.json \
    --expect-fingerprint sha256:<the fingerprint the Guardian printed at startup>
```

The command is `python -m acs.testing.verify`, and it calls itself `acs-verify` in its output. It prints plain text by default. `--json` prints one JSON object instead.

| Flag | What it does |
|---|---|
| `--keys FILE` | The Guardian's key document (`acs-lab-keys/1`), read through the same reader as `ACS_GUARDIAN_KEYS`: no symlink, no FIFO, no group or other write. Every response must verify under ML-DSA-65 with the key its `key_id` names. |
| `--expect-fingerprint FP` | The fingerprint the Guardian printed at startup. Every key that verifies a response must have it. Repeat the flag to accept more than one key. |
| `--key-id ID` | Accept only this `key_id` from the key document. |
| `--hmac-secret FILE` | The shared HMAC secret, read under the same owner-only rule as `ACS_HMAC_SECRET_FILE`. With `--keys`, it also checks every request signature. Without `--keys`, HMAC-SHA256 becomes the response algorithm. |
| `--keys-only` | Check signatures, bindings and key validity, but not the chain. |
| `--max-bytes N` | Refuse a transcript larger than N bytes. The default is 256 MiB. |
| `--json` | Print one JSON object. |

| Exit code | Meaning |
|---|---|
| 0 | Every line checked passed. The output says whether the whole transcript verified, and if not, which request lines no signed decision covers and where the tail starts. |
| 1 | A verification failure. The output names the line, a stable code, and the reason. |
| 2 | A usage error, or input that can't be read: a missing transcript or one over `--max-bytes`, a key document that can't be parsed, holds no usable key, or has a malformed `revoked` list, a `--key-id` the document doesn't hold, a secret file that is too short or readable by others, or a missing `pqc` extra. `--json` still prints one object, with `"result": "error"`. |

A transcript line that isn't strict JSON is a verification failure at that line, not an unreadable input, because the transcript is the evidence being checked. A repeated key inside one object and the constants `NaN` and `Infinity` fail too, since two readers could take such a line two ways. A request holding a value RFC 8785 can't encode, such as an integer beyond 2**53 or `1e400`, fails at its line as `not_canonical`, since no signature can cover it. A `request_id` that appears twice fails at the second line as `duplicate_request_id`, since a request is sent once.

## What it reads

The transcript is the lab gateway's file (A.7): one `{"dir": "req" | "resp", "envelope": {...}}` object per line, in send order. A request that got no usable answer is followed by `{"dir": "resp", "envelope": null, "cause": "..."}`. Each response line answers the request line just before it.

## What it checks

Each request and its answer go through these checks in order, and the first failure stops the run.

1. Every request names the same `session_id` as the first one.
2. With `--hmac-secret`, the request's signature verifies under the HMAC session key.
3. With `--keys`, the answer must be signed with ML-DSA-65 by a key the document holds, under the `key_id` the signature names. The key comes from the document, never from the envelope's `algorithm` (issue #308, RFC 8725 section 3.1). With `--hmac-secret` alone, the answer must verify under the HMAC session key.
4. The key must be live and not revoked at the request's own `timestamp`. That timestamp sits inside the request hash the signed answer carries, so nobody without the Guardian's private key can move it. Whoever holds a stolen private key can, though: they can sign a request hash with a timestamp from before the revocation. Offline, acs-verify can't tell that apart from a genuine early entry. So a key revoked after an entry's timestamp still verifies that entry, and whenever a revoked key signed any entry in the transcript, the output prints a warning that the entry could be backdated.
5. With `--expect-fingerprint`, the key that verified the answer has one of the expected fingerprints.
6. The answer carries the request's JSON-RPC `id` and `request_id`, and under ML-DSA-65 `x_acs_lab_request_sha256`, the SHA-256 of the request's section 10 signed input. `acs.core.verify_with_keyring` always runs with `require_request_digest=True`, so an answer relayed from another session fails.
7. For each answer that carries `chain_hash`, the chain is recomputed exactly as the example Guardian builds it and must reach that value.

The flags decide the response algorithm, and nothing in the transcript does. A rewritten ServerHello can't switch the check to HMAC. With `--keys`, an answer signed with the shared HMAC secret fails, even when `--hmac-secret` is also given.

### The chain

Each entry is the one `append_to_chain` writes: `entry_id` and `step_id` are `params.request_id`, `step_type` is the method, `request_hash` is the SHA-256 of the JCS form of `params` with its signature, and `timestamp` is the request's own. The head is the SHA-256 of the entry's JCS form followed by the previous head's 32 raw bytes (specification section 8.2).

The Guardian chains every method except `system/ping` and `handshake/hello`: `steps/*`, `protocols/*`, `agbom/*`, and any method it doesn't know. acs-verify reads that rule from the Guardian's own predicate, `acs.guardian._chain.chains_method`, so the two can't drift apart.

A request that got no answer, or an error with no `chain_hash`, may or may not have been chained. The Guardian refuses a bad signature before it chains, but an answer lost to a timeout leaves a chained entry behind. `acs-verify` holds such requests until the next signed `chain_hash`, then tries each of them in and out. It holds at most 12 at once, and more than 12 between two checkpoints fails as `chain_unsettled`. Only a request whose cause proves it failed before it was sent isn't held: `guardian_url_rejected`, `envelope_not_signable`, `request_envelope_invalid`, and `request_exceeds_max_payload`. Every other cause is held, `transport_failure` and `on_wire_failed` included, because a reply can be lost after the Guardian chained the step, and an on_wire callback can fail on the answer as well as on the request. When a chain mismatch is reported, its reason names any request lines that were left out as never sent.

### What a pass covers

A pass claims only what a signature covers. A request the chain settles in or out still has no signed decision: whatever the Guardian decided for it, nothing in the file proves it. So acs-verify lists every request line that no signed decision covers under `no signed decision` (`unsigned_lines` in JSON): a request with a null or missing answer, a chained request answered without a `chain_hash`, such as a refused replay, and every `system/ping`, which is unsigned by design. Deleting or nulling a decision, or inserting a request with no answer, shows up there.

Entries cut from the end of a transcript leave no trace, since nothing signed after them is missing. When the last checkpoint isn't the verified answer to `steps/sessionEnd`, or lines follow it, the output says `tail unverified` and names those lines.

A transcript is complete only when its last line is the verified answer to `steps/sessionEnd` and no request line lacks a signed decision. Otherwise the output never says the whole transcript verified, and the JSON form carries `"complete": false`. The exit code is still 0 for such a pass, so a script that needs a complete transcript reads `complete`.

## What a pass proves

Under ML-DSA-65 with `--expect-fingerprint`, a pass shows that the Guardian holding that key signed each decision, as the answer to the request beside it, at a time its key was valid, and that the chain the Guardian committed to matches the requests in the file up to the last checkpoint.

Without `--expect-fingerprint`, a pass proves only that the transcript matches the key document next to it. Anyone who can replace both can make that pass.

Under HMAC-SHA256, a pass proves only that someone holding the shared secret wrote each answer. The agent side holds that secret too, so HMAC can't say which side wrote an entry (specification section 8.6). A decision forged with the secret passes under HMAC and fails under ML-DSA-65.

## Lab conventions

Each item below is a lab convention, off unless you use it, and named with the issue that would settle it.

- The key document format `acs-lab-keys/1` and the startup fingerprint, until issue #460 settles key publication.
- The request hash `x_acs_lab_request_sha256`, from issue #576. Issue #13 (Handshake downgrade is undetectable without transcript binding to subsequent traffic) is the closest tracking issue.
- ML-DSA-65 response signing and the handshake fields that negotiate it, until issue #316 settles verifier rules.
- The transcript format, from the lab plan's A.7.

The audit chain itself is in the specification. Checking it across Guardians is issue #18 (Audit chain trust depends on a single Guardian, no cross-Guardian verification protocol).
