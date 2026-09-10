# Inspector

A terminal viewer for the Guardian's logs. It tails the envelope log, the audit log and the session-context log, and prints each ACS envelope, decision, audit entry and session chain entry as it lands.

It imports nothing from the Guardian, the bridge or the adapter, and it reads the logs purely as files. It contains no AGT vocabulary and no host vocabulary. Those boundaries are enforced by [`test/invariants.test.ts`](../../test/invariants.test.ts) at the root of the tree, and a round-trip test keeps its copy of the log entry type honest with the Guardian's.

## Get started

Start it from `reference-implementations/agt`, after the Guardian, because the Guardian creates the `.acs/` directory.

```bash
bun run inspector
```

```
Envelope Inspector — tailing .acs/envelopes.jsonl, .acs/audit.jsonl, and .acs/session-context.jsonl
Ctrl-C to stop.

last_observed_posture=(none observed)  fail-open proceeds=0
```

To replay a session that is already recorded:

```bash
bun run inspector -- --from-start
```

| Flag | Variable | Default |
|---|---|---|
| `--envelope-log` | `ACS_ENVELOPE_LOG` | `.acs/envelopes.jsonl` |
| `--audit-log` | `ACS_AUDIT_LOG` | `.acs/audit.jsonl` |
| `--session-context-log` | `ACS_SESSION_CONTEXT_LOG` | `.acs/session-context.jsonl` |

A flag wins over its variable. The Inspector honours `NO_COLOR` and prints no colour when stdout is not a terminal.

## What each line means

An envelope prints as a header line and the envelope body. The header carries the sequence number from the log, the time it was recorded, the direction, the method and the JSON-RPC id. A response carries a decision badge above the body, with the reason codes and policy references on the same line:

```
● DENY  reason_codes=[destructive_shell_command_blocked]  policy_references=[agt_stock#destructive_shell_command_blocked]
```

A session chain entry prints as one line: the step number within the session, the tool, the chain hash and the session id. A step whose hash does not continue the previous one is flagged as a broken chain. An evicted session that comes back reads as one.

An audit entry prints with its outcome and the failure that caused it. The banner is reprinted whenever an audit entry changes it. It shows the last posture an audit entry carried, which is the observed posture and not the negotiated one, and the running count of fail-open proceeds.

The three logs are tailed independently. The audit log's raw session id is never matched against the envelope log's derived one; the [host adapter README](../host-adapter/README.md#the-audit-log) says why they differ.

## Files

| File | What it holds |
|---|---|
| `src/main.ts` | The `bun run inspector` entry point, flag parsing, and the loop |
| `src/tail-envelope-log.ts`, `src/tail-audit-log.ts`, `src/tail-session-context.ts` | One tailer per log |
| `src/render.ts` | Every rendered line, the decision badge, the posture banner, and the chain check |

## Tests

```bash
bun test packages/inspector
```

Four files. They render fixed entries and tail fixed files.
