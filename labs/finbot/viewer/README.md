# FinBot Lab Decision Viewer

The decision viewer shows every step the lab gateway governs as it happens, one row per step, so a lab session reads like a live log of what the Guardian decided and whether its answer verifies. It is read only. Issue #586 tracks it, and BUILD_PLAN Appendix A.12 names what it must paint.

## What it shows

Each row carries the time, the method, the tool, the decision, the reason codes, the signature algorithm, and a verify mark. The page polls every 500 ms and needs no reload. A large label above the table names the latest beat:

`handshake`, `first_allow`, `shadow_decision`, `deny`, `allow_after_fix`, `ask_pending`, `ask_resolved`, `modify`, `digest_mismatch`, `forge_passes_hmac`, `forge_fails_mldsa`, `keys_only_verify`, `downgrade_refused`.

With ACS off the gateway writes no transcript, so the page reads "no ACS record". An epoch bump, such as `lab mode off`, starts that count again.

The verify mark is a word, so its meaning never rests on color:

| Mark | Means |
|---|---|
| verified | The answer verifies under ML-DSA-65 with the key document, bound to its request, with the key live at the request's time |
| failed | The answer doesn't verify, or it is an HMAC answer in a session whose ServerHello verified under ML-DSA-65 |
| not checked | No key document is loaded, or the answer is HMAC-signed |
| unsigned | The answer carries no signature |
| no answer | No usable answer came back, and the note says why |

The verdict is acs-verify's own (`acs.testing.verify`), run on each request and answer pair with `--keys-only`. The audit chain spans a whole session, so `lab verify` checks it over the transcript.

An HMAC decision is never marked verified here. The viewer holds no HMAC secret, and anyone holding that secret can write an HMAC answer, the agent side included (specification section 8.6). That gap is the point of module 7.

## Run it

```bash
ACS_TRANSCRIPT_DIR=state/transcripts ACS_AUDIT_FILE=state/audit.log \
  uv run --project adapters --extra pqc python labs/finbot/viewer/server.py
```

It binds `127.0.0.1:8095` and prints `ACS_VIEWER_LISTENING port=<port>` once it listens. `--host` and `--port` override the bind. In the lab's container it binds `0.0.0.0` and the compose file publishes it on `127.0.0.1` only.

| Setting | Default | Purpose |
|---|---|---|
| `ACS_TRANSCRIPT_DIR` | required | The gateway's transcript directory |
| `ACS_AUDIT_FILE` | unset | The gateway's audit log. Unset, rows carry no shadow or applied decisions and no ASK rows |
| `ACS_GUARDIAN_KEYS` | unset | The Guardian's key document. Unset or unusable, every ML-DSA-65 answer reads not checked |
| `ACS_GUARDIAN_KEY_ID`, `ACS_GUARDIAN_KEY_FINGERPRINT` | unset | The same pin the gateway puts on the key document |
| `ACS_VIEWER_VERIFY_DIR` | `verify` beside the transcript directory | Where the module 7 commands write their results |
| `ACS_VIEWER_PAINT_LOG` | unset, so off | Where the page logs each beat it paints, for the video shoot |

The viewer runs as the gateway's user, since the gateway writes its logs with mode 0600.

## Safety

The logs hold text an attacker can shape through the model or the Guardian, so every string the viewer serves escapes control characters, bidi overrides and other invisible characters (issue #468). The page writes text with `textContent` only and loads nothing from another origin.

A localhost bind doesn't stop a page on another site from reaching the viewer through DNS rebinding. Every request must name `127.0.0.1`, `localhost` or `[::1]` in its Host header, and a paint must come from the page's own origin. The viewer never writes, renames, truncates or locks a log. Its one write is the paint log, and only when `ACS_VIEWER_PAINT_LOG` is set.

## Lab conventions

Each of these is a lab convention, off the default ACS path, until its issue settles it:

- The key document format `acs-lab-keys/1` (issue #460).
- ML-DSA-65 response signing and the `x_acs_lab_response_algorithm` negotiation (issue #316).
- The request hash `x_acs_lab_request_sha256` in each answer (issue #13).
- The gateway's discards line, which marks an answer the gateway withheld (issue #577).
- The module 7 result files in the verify directory, one JSON object each, accepted for LAB-16 (plan LAB-13, open question 1):

```json
{"kind": "forge", "algorithm": "HMAC-SHA256", "result": "verified", "entry": 7, "detail": "a forged allow verifies"}
```

`kind` is `forge`, `keys_only` or `downgrade`, `algorithm` is `HMAC-SHA256` or `ML-DSA-65`, `result` is `verified`, `broken` or `refused`, and `entry` is a transcript line or null. A file of any other shape is skipped.

## Test it

```bash
uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/viewer/tests -v
```

The tests write their fixtures through the gateway's own transcript writer and acs.client's audit writer, run one session against the real example Guardian, and pin every event name and field the viewer reads to the gateway's source.
