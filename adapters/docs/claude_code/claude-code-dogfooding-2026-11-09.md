# What Claude Code does before there is a step to decide

For [#434](https://github.com/GenAI-Security-Project/agent-control-standard/issues/434), I claimed the
category the issue's list did not have: failures that end before there is a step the Guardian can
decide. This report covers that category on one host, and one case that does produce a step: a call
the Guardian allows and the host then runs again.

Claude Code `2.1.283`, the shipped `claude_code` adapter and the example Guardian ran five scenarios
five times each on a clean Linux runner. Two of them never put a `toolCallRequest` on the wire. A
truncated tool call is rejected by the client, and a truncated response stream is retried below the
hook. The third repeats an allowed call: five identical `Write` calls, five `allow` decisions, five
files.

AngeYobo reported the third outcome first on OpenCode ([report and captures](https://gist.github.com/AngeYobo/4c095d5458a14524ac662a44cee3eff8),
fixture at PR [#113](https://github.com/GenAI-Security-Project/agent-control-standard/pull/113)). These runs reach
the same outcome from a different host, a different Guardian and a different cause, so this is a
second path to it, not his finding folded into another report. I am not claiming the outcome as new.

This report covers five scenarios in one client on one platform. It does not establish ACS-Core
conformance and does not close #434.

## What ran

| Component | Version or configuration |
| --- | --- |
| ACS checkout | `db457a84393bd80954c9b70b2271a719bf7c61cd`, `integration` |
| Recorder on that tree | `88acdfce`: the same tree plus a 17-line, test-only recorder that appends the bytes each request carried to the file named by `ACS_ENVELOPE_LOG`. It reads nothing and decides nothing, and it is off unless that variable is set. The envelope captures below come from it. |
| ACS wire version | `0.1.0` |
| Host | Claude Code `2.1.283`, `--print --permission-mode acceptEdits`, `ubuntu-latest` |
| Adapter | `adapters/src/acs/integrations/claude_code/adapter.py`, wired through a project-level `.claude/settings.json` on all six hook events |
| Guardian | `acs-example-guardian`, shipped policy, OS-assigned port |
| Transport | Loopback HTTP, HMAC-SHA256 with the secret in the environment, no key file |
| Model | Local scripted Anthropic `/v1/messages` endpoint, five modes; no model judgment under test |
| Python | `3.12.16` |

Only the model is faked. The client, the adapter and the Guardian are the ones a user installs. Each
rep got its own scratch workspace, its own Guardian on a fresh port and its own endpoint port; the
runner's own `~/.claude` was never touched.

The runs were made in a private CI workflow, so the workflow URLs are not public. The five JSON files
in this directory are the captures: per rep, the endpoint's request log (including the `tool_result`
the client echoed back), the Guardian's step log, the envelopes it received, the client's
stdout/stderr, and the files left in the workspace. Paths under the CI workspace are normalized to
`$GITHUB_WORKSPACE`; nothing else in the captures was edited.

## Expected and observed behavior

[Instrument §6.4](../../../docs/spec/instrument/specification.md#64-honoring-decisions-normative)
governs what the host does once a decision exists. The first two rows below are the case where no
decision is asked for, which §6.4 does not cover.

| Scenario | Repetitions | Endpoint requests | `toolCallRequest` at the Guardian | Tool ran | Outcome |
| --- | --- | --- | --- | --- | --- |
| Control: complete call | 5/5 | 2 (streamed) | 1, `allow` | yes, 2120 B | `report.txt` written, exit 0 |
| Arguments cut mid-JSON, `stop_reason: max_tokens` | 5/5 | 2 (streamed) | **0** | no | client rejects the call, exit 0 |
| Stream ends before `message_stop` | 5/5 | 3 (2 streamed, 1 non-streamed retry) | **0** | no | exit 1, `stream_truncated` |
| TCP reset mid-stream | 5/5 | 3 (2 streamed, 1 non-streamed retry) | **0** | no | exit 1, `stream_truncated` |
| Same `Write` offered five times | 5/5 | 6 (streamed) | **5, all `allow`**, one distinct `arguments_sha256` | yes, 5 times | exit 0, 2120 B file |

### Truncated arguments never reach the adapter

The client rejects the call itself and hands the verdict back to the endpoint. All five reps, the
same first 200 bytes:

```
<tool_use_error>InputValidationError: Write was called with input that could not be parsed as JSON.
You sent (first 200 of 922 bytes): {"file_path": "report.txt", "content": "line 01: the quick brown ...
```

The Guardian's step log goes `userMessage → agentResponse` with no `toolCallRequest` between them, in
all five reps. No envelope existed for the hook to judge.

### A truncated stream is retried where the Guardian cannot see it

Each rep produced three requests at the endpoint: two streamed, then one non-streaming retry. The
client's own message names it:

> This was the non-streaming retry of streaming request (no Anthropic request-id), which failed with:
> stream_truncated, StreamTruncatedError, StreamTruncated; 41 stream events received, first after 4 ms,
> none in the final 0 ms.

The Guardian saw `sessionStart / turnStart / userMessage / sessionEnd` and nothing of the three
attempts: one prompt, no attempt recorded beneath it. Whatever the retry policy is, it runs below the
hook. `drop` and `reset` differ only in how the stream dies; both were retried the same way.

### A repeated call is dispatched and allowed every time

Five identical `Write` calls: five `toolCallRequest → allow → toolCallResult` pairs, five files
written, one session, exit 0. Within each session the five step envelopes carry one distinct
`arguments_sha256` and five distinct `request_id`s. Across the five sessions the argument hash differs
— the payload carries session-scoped fields — so the identity that matters here is the one inside a
session, where the repeated action is byte-for-byte the same.

This is the outcome AngeYobo reported on OpenCode, and the two reports reach it as independent paths:

| | AngeYobo | These runs |
| --- | --- | --- |
| Host | OpenCode `1.18.30`, macOS | Claude Code `2.1.283`, Linux |
| Guardian | AGT reference Guardian (Bun), policy engine | `acs-example-guardian` (Python), shipped policy |
| Cause of the repetition | client retry of one call | the model offering the same call five times in a row |
| Outcome | allow, allow, executed twice | allow five times, executed five times |

His two rows and my five rows behave the same way for one reason, in the next section.

## Replay detection keys on `request_id`, and the specification says so

[Instrument §10.3](../../../docs/spec/instrument/specification.md#103-replay-protection) is explicit
about what a Guardian rejects:

> Guardians MUST reject requests whose `timestamp` is more than the negotiated skew window ... MUST
> reject duplicate `request_id` values within the session with `REPLAY_DETECTED` (`-32005`), and
> SHOULD reject duplicate `nonce` values within a sliding window the deployment configures.

Nothing in §10.3 requires deduplicating *distinct* envelopes that carry the same action. The
implementation matches it: `check_replay` keeps the set of seen `request_id`s per session
(`adapters/src/acs/guardian/example_guardian.py:296-304`) and is called for every step
(`:512`). A step the model offers again gets a fresh id, so `REPLAY_DETECTED` is not reachable from a
repeated call. That is why his two variants and my five calls behave identically: replay protection
counts envelopes, not actions.

So the repeated call is a policy question, not a replay bug, and there is no `MUST`-level
disagreement to file. The observation belongs here, in the report. The `nonce` half of §10.3 is a
separate, `SHOULD`-level matter, recorded at the end of this section.

### Minimal reproduction

[`scripts/repro-request-id-replay.py`](../../scripts/repro-request-id-replay.py) isolates the mechanism
from any host. It starts the shipped Guardian, opens one session, sends the same `Write` twice under
two `request_id`s, then sends the first one again. Output on `ubuntu-latest`, ACS `db457a8`, Python
`3.12.16`:

```
sessionStart                           result: allow
same action, request_id #1             result: allow
same action, request_id #2             result: allow
same action, request_id #1 again       error: -32005
same nonce, first send                 result: allow
same nonce, second send                result: allow

distinct request_ids, same action, both allowed: True
repeated request_id refused with -32005:         True
repeated nonce refused with -32005 (SHOULD):     False
```

The same command exits 1 if either of the two `MUST` halves stops holding, so it can run in CI
unchanged. The nonce line is printed and does not affect the exit status.

### Observation: the nonce half of §10.3 is not implemented

§10.3 also makes a duplicate `nonce` a SHOULD. The example Guardian keeps nonce state — `seen_nonces`,
merged across Guardian instances and evicted on a window — but never reads it back to reject
anything: two envelopes carrying the same nonce and different `request_id`s are both allowed, as the
run above shows. The adapters emit no `nonce` at all; the field is OPTIONAL in v0.1, and
`docs/claude_code/README.md` already records that. So no client in these runs is affected, and this is
a gap against a SHOULD rather than a MUST. Recorded here as an observation; no issue is filed with this
report.

## Reproduce the runs

Install Claude Code `2.1.283`, Python 3.12 and `uv`. From `adapters`, install the locked dependencies:

```sh
uv sync --locked
```

Then, from the repository root, run one mode at a time. Each run needs new scratch output:

```sh
adapters/.venv/bin/python adapters/scripts/dogfood-claude-code.py \
  --acs adapters \
  --stub adapters/scripts/stub-anthropic-endpoint.py \
  --mode length --reps 5 --out out/length.json
```

`--mode` takes `complete`, `length`, `drop`, `reset` or `loop`, and `--record` adds the envelope log
the captures above include. The envelope section needs the recorder described in the table above; on a
tree without it, `--record` writes an empty file and nothing else changes. The runner gives each rep
its own workspace, Guardian and endpoint, writes nothing outside them, and never touches the user's
`~/.claude`.

The example Guardian imports `fcntl`, so these runs need a POSIX host. Windows is not covered by this
report and none of its numbers come from a Windows machine.

## Limits and follow-up

No specification disagreement appeared in these five scenarios. The first two rows are failures on
the client side of the hook: the evidence that the call existed at all is the client's own
`tool_result` echo and the endpoint's request log, because the Guardian has no record to correlate.

What stayed untested: Claude Code `2.1.283` only, no second host in this run; no real model or API,
so nothing here is a claim about model behaviour; `-32005` never fired in these five scenarios and is
exercised only by the reproduction above; `ASK`, `DEFER` and `MODIFY` were not exercised; Windows is
excluded for the reason above.

One open question for the maintainers, from the same comment where I claimed this category: should
client-side failures in the part of a turn the hook never sees be recorded in #434's list as
coverage-boundary entries, or stay outside it? A report that covers only what the hook saw will look
complete while this class is missing. The runs above do not settle that; they only show the class
exists and is reproducible.
