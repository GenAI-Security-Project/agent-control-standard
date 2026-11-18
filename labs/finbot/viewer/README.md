# FinBot Lab Decision Viewer

The decision viewer shows every step the lab gateway governs as it happens, one row per step, with the Guardian's signed decision and whether its signature checks. <!-- claim:C-04 --> It is read only. Issue #586 tracks it, and BUILD_PLAN Appendix A.12 names what it must paint.

## What it shows

Each row carries the time, the method, the tool, the decision, the reason codes, the signature algorithm, and a check mark. The page polls every 500 ms and needs no reload. A large label above the table names the latest beat:

`handshake`, `first_allow`, `shadow_decision`, `deny`, `allow_after_fix`, `ask_pending`, `ask_resolved`, `modify`, `digest_mismatch`, `forge_passes_hmac`, `forge_fails_mldsa`, `keys_only_verify`, `downgrade_refused`. <!-- claim:C-03 --> <!-- claim:C-04 --> <!-- claim:C-05 -->

With ACS off the gateway writes no transcript, so the page reads "no ACS record". An epoch bump, such as `lab mode off`, starts that count again.

### The decision and what the gateway applied

The decision column holds the decision in the Guardian's answer, as the transcript recorded it. The audit log is the gateway's own word on what it did, and no signature covers it, so it never changes that column. <!-- claim:N-04 --> When the gateway applied something else, the cell shows it underneath. A shadow row says the gateway forwarded the call. A row reads conflict, in white on red, when the audit line names a Guardian decision the answer doesn't hold, or says the gateway allowed a call the answer didn't allow.

### The check mark

The mark is a word, so its meaning never rests on color:

| Mark | Means |
|---|---|
| verified | acs-verify checked this answer's ML-DSA-65 signature under the key document, its binding to its request, and the key's validity at the request's time, and found no fault in the lines judged so far, read from the file on disk at that judge. It doesn't show the transcript is complete: a deleted or reordered entry still reads verified here, and lab verify checks the whole transcript <!-- claim:C-04 --> <!-- claim:N-04 --> |
| key warning | As verified, but acs-verify warned, such as for a key the key document now revokes. The note gives the warning <!-- claim:C-04 --> |
| failed | acs-verify found a fault at this row, or the file holds requests for another session. The note gives the code <!-- claim:C-04 --> |
| not checked | Nothing here could check this row: no key document, an HMAC session, a session too long for the viewer, a session that failed at another row, a row waiting to be judged again under a changed key document, or a file that changed while it was read |
| unsigned | The answer carries no signature, in a session that passed, or in one nothing here could check |
| no answer | No usable answer came back, and the note says why |

acs-verify (`acs.testing.verify`) runs over the lines the viewer has read from a session file each time the file grows, so its own rules judge each row: the signature under the key its key_id names, the request binding and hash, the key's validity at the request's own time, a request_id seen twice, a request from another session, a cause on a signed answer, and a discards line away from its answer. <!-- claim:C-04 --> It runs keys only and skips the audit chain, so a deleted or reordered entry still reads verified here. lab verify checks the chain over the finished transcript. <!-- claim:N-04 -->

The viewer adds two rules of its own. A file whose requests name a session other than the file's name fails at its first request, since lines copied from another session each pass on their own. Every judge reads the session's file from disk and compares it with a hash of every byte read before, so a mark comes only from bytes on the disk when it runs. A judge runs when the file's inode, size, mtime or ctime changes. A file replaced or cut shorter, or edited in a way that moves one of those, even at the same size, loses all its rows at that judge, and the viewer reads it again from the start. A write that moves neither mtime nor ctime, such as a write through a memory map held open on macOS, is caught only when the file next grows or its session is judged for another reason, such as a key change. A file that leaves the directory, or falls out of the 200 newest, loses its rows, and the page names it and says why. When the key document changes on disk, every mark judged under the old one reads not checked until its session is judged again, from disk. A mark is as old as its session's last judge. A changed file is usually judged at the next poll. While many sessions change at once, it waits one poll for each session judged ahead of it, at most 200 polls, 100 seconds, when every followed file changes together. <!-- claim:C-04 -->

A discards line, the gateway's word that it withheld the answer before it, is a row of its own that reads unsigned, since no signature covers it. It marks the answer just before it withheld. A discards line anywhere else fails at its own row and marks no answer.

A session is judged only when its first signed answer names ML-DSA-65. The viewer holds no HMAC secret, and anyone holding that secret can write an HMAC answer, the agent side included (specification section 8.6), so an HMAC session reads not checked and never verified. In a session judged under ML-DSA-65, an HMAC or unsigned answer fails. <!-- claim:C-04 -->

A replay miss is a row of its own, noted as the recorded neutral reply. <!-- claim:C-08 -->

## Run it

```bash
ACS_TRANSCRIPT_DIR=state/transcripts ACS_AUDIT_FILE=state/audit.log \
  uv run --project adapters --extra pqc python labs/finbot/viewer/server.py
```

It binds `127.0.0.1:8095` and prints `ACS_VIEWER_LISTENING port=<port>` once it listens. `--host` and `--port` override the bind. In the lab's container it binds `0.0.0.0` and the compose file publishes it on `127.0.0.1` only.

| Setting | Default | Purpose |
|---|---|---|
| `ACS_TRANSCRIPT_DIR` | required | The gateway's transcript directory |
| `ACS_AUDIT_FILE` | unset | The gateway's audit log. Unset, rows show no applied decision and no ASK rows |
| `ACS_GUARDIAN_KEYS` | unset | The Guardian's key document. Unset or unusable, every row reads not checked |
| `ACS_GUARDIAN_KEY_ID`, `ACS_GUARDIAN_KEY_FINGERPRINT` | unset | The same pin the gateway puts on the key document |
| `ACS_VIEWER_VERIFY_DIR` | `verify` beside the transcript directory | Where the module 7 commands write their results <!-- claim:C-03 --> |
| `ACS_VIEWER_PAINT_LOG` | unset, so off | Where the page logs each beat it paints, for the video shoot |

The viewer runs as the gateway's user, since the gateway writes its logs with mode 0600.

## Limits

Every store is bounded, so a junk or endless log costs bounded memory and bounded time per poll. Measured in round 4, a session grown to 512 MiB costs one stat a poll once past the cap, 0.14 ms, and the viewer held 45 MiB:

| Bound | Value |
|---|---|
| Bytes read from one log per poll | 256 KiB. The next poll carries on |
| Longest line | A line still incomplete past 1 MiB is one unreadable row, cut short. A line that completes within a read is kept whole, so one line holds at most about 1.25 MiB |
| Rows kept | 5000. The oldest go first |
| Rows in one answer to the page | 500. The page asks again at once while more wait |
| Rows on the page | 1000. The oldest go first |
| Session files followed | 200, the most recently changed. A file that falls out of them loses its rows |
| Lines judged per session | 2000 lines or 8 MiB. Past it the session's rows read not checked, the note names the lab command that checks the whole file, and the file is read no further unless it is replaced or cut shorter |
| Judging per poll | 0.25 seconds across sessions, the longest-waiting first. The rest wait for the next poll. A poll always judges at least one session. One judge at the cap, which reads the file, hashes it and checks every line, measured 0.19 seconds on typical lines and 0.24 seconds on lines filling 7.8 MiB, so the worst poll judges for about 0.5 seconds |
| Audit lines waiting for their step | 10000 |
| A silent connection | dropped after 10 seconds |

A run of unreadable lines is one row with a count.

## Safety

The logs hold text an attacker can shape through the model or the Guardian, so every string the viewer serves escapes control characters, bidi overrides and other invisible characters, exactly once (issue #468). The page writes text with `textContent` and text nodes only, maps each decision through a fixed set before it names a style, and loads nothing from another origin.

A localhost bind doesn't stop a page on another site from reaching the viewer through DNS rebinding. Every request must name `127.0.0.1`, `localhost` or `[::1]` in its Host header, and a paint must come from the page's own origin. The viewer never writes, renames, truncates or locks a log. Its one write is the paint log, and only when `ACS_VIEWER_PAINT_LOG` is set.

## Lab conventions

Each of these is a lab convention, off the default ACS path, until its issue settles it:

- The key document format `acs-lab-keys/1` (issue #460).
- ML-DSA-65 response signing and the `x_acs_lab_response_algorithm` negotiation (issue #316).
- The request hash `x_acs_lab_request_sha256` in each answer (issue #13).
- The gateway's discards line, which marks an answer the gateway withheld (issue #577).
- The module 7 result files, one JSON object each, accepted for LAB-16 (plan LAB-13, open question 1). <!-- claim:C-03 -->

```json
{"kind": "forge", "algorithm": "HMAC-SHA256", "result": "verified", "entry": 7, "detail": "a forged allow verifies"}
```

`kind` is `forge`, `keys_only` or `downgrade`, `algorithm` is `HMAC-SHA256` or `ML-DSA-65`, `result` is `verified`, `broken` or `refused`, and `entry` is a transcript line or null. A file of any other shape is skipped. <!-- claim:C-03 --> <!-- claim:C-04 --> <!-- claim:C-05 -->

## Test it

```bash
uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/viewer/tests -v
```

The tests write their fixtures through the gateway's own transcript writer and acs.client's audit writer, run one session against the real example Guardian, and pin every event name and field the viewer reads to the gateway's source.
