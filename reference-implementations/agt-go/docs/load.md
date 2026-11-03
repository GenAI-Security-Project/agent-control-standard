# Load

`make load` sends signed `toolCallRequest` steps from many concurrent clients through
the Guardian in process, over the evaluator `EVALUATOR` selects (`agt`), and reports decisions per second, latency, `engine_saturated` refusals, the `opa`
processes alive at once and their memory, and the audit log's size on disk. The `agt`
evaluator runs one `opa` process for each decision. It is not part of
`make check`. `ACS_LOAD_CLIENTS`, `ACS_LOAD_STEPS` (steps per client, all in one
session), `ACS_LOAD_MAX_ENGINE_CALLS`, `ACS_LOAD_AUDIT_MAX_ENVELOPE_FILE_BYTES` and
`ACS_LOAD_AUDIT_MAX_ENVELOPE_FILES` select the run; `agtbridge/load_test.go` defines them. The test
fails if the audit log reports an error, splits or drops a record it keeps, or exceeds its
rotation bound. The `opa` process count and memory are
read from `/proc`, so they are measured on Linux only and read 0 elsewhere.

```bash
make load
```

## Measured on 14 October 2026

Linux amd64, 20 cores, 125 GiB, shared with other work (load average 18 to 27 before
the runs). 20 steps per client, the policy branches of the parity corpus, `opa_timeout`
5s. Decided/s counts every answer except `engine_saturated` refusals, which are counted
apart; it includes the Guardian's own DENY when the decision timeout ends a call.

With `limits.max_engine_calls` 256, the library default:

| Clients | Decided/s | p50 | p99 | Max | `engine_saturated` | `opa` at once | Their memory |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 20 | 51ms | 52ms | 62ms | 0 | 1 | 32 MiB |
| 8 | 99 | 82ms | 94ms | 113ms | 0 | 8 | 236 MiB |
| 16 | 128 | 119ms | 168ms | 188ms | 0 | 16 | 455 MiB |
| 32 | 129 | 222ms | 488ms | 589ms | 0 | 30 | 902 MiB |
| 64 | 133 | 440ms | 1.211s | 1.479s | 0 | 61 | 1731 MiB |
| 128 | 135 | 920ms | 1.799s | 2.218s | 0 | 126 | 3608 MiB |
| 256 | 129 | 1.757s | 4.12s | 5s | 0 | 253 | 7011 MiB |
| 512 | 122 | 830ms | 5.628s | 8.508s | 5817 | 236 | 6931 MiB |

With `limits.max_engine_calls` 32, as `guardian.yaml` ships:

| Clients | Decided/s | p50 | p99 | Max | `engine_saturated` | `opa` at once | Their memory |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 32 | 128 | 238ms | 447ms | 527ms | 0 | 30 | 845 MiB |
| 64 | 126 | 29ms | 451ms | 708ms | 840 | 23 | 680 MiB |
| 256 | 111 | 79ms | 745ms | 1.093s | 4542 | 28 | 742 MiB |
| 512 | 116 | 241ms | 1.008s | 1.434s | 9283 | 25 | 632 MiB |

Decisions per second stop rising near 16 concurrent decisions on this host; past that,
each added decision adds latency and about 28 MiB, not decisions. At 256, decisions
reach the 5s decision timeout, where an agent stops waiting and applies its failure
posture. With 32, no step is refused while clients do not exceed the limit, a step past
it is refused at once with a signed DENY `engine_saturated`, and every decision stays
under 1.5s.

`limits.max_engine_calls` is a property of the host. Run `make load` on the deployment's
hardware and set it above the point where decisions per second stop rising, and below
the point where the slowest decision nears the decision timeout.

## Audit log growth

Each step writes about 1.6 KB to the two audit files. At the 130
decisions per second `agt` sustains on this host, that is about 12 MiB a minute. Each file
has its own rotation: `guardian.yaml` keeps at most 1 GiB of envelopes, deleting the oldest
file, and at most 2.25 GiB of events, which the deployment archives ([Configuration](configuration.md)). The writer's queue is bounded by
`audit.max_queue_records` and `audit.max_queue_bytes`, 4096 records and 64 MiB in
`guardian.yaml`, so a stalled disk does not grow it further; records past either limit
are dropped and counted. At 1.6 KB per step, 4096 records take about 6.5 MiB. A write
failure turns the log off for the rest of the process.

## Session length

Each step copies the session's context entries twice: when the store returns the session,
and when the Guardian builds the engine's input. A step's cost therefore grows with the
session's length, up to `limits.max_entries` (10000 in `guardian.yaml`). The tables above
use 20 steps per session.
