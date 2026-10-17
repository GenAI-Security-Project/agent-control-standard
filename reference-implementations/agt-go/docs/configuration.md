# Standalone Guardian configuration

`guardian --config PATH` reads one YAML document. The command validates every
required value after loading the file. Unknown YAML keys and unknown `ACS__`
environment variables stop startup.

`guardian.yaml` is runnable local configuration. A deployment should copy it
to an operator-owned location, replace the secret and audit paths, select its
policy deployment, and choose limits for its workload.

## Server

| Key | Meaning | Constraint |
| --- | --- | --- |
| `server.host` | Listener host or address. | Non-empty. |
| `server.port` | Listener port or service name. `0` asks the operating system for a free port. | Non-empty. |
| `server.read_header_timeout` | Maximum time to read HTTP headers. | Positive duration. |
| `server.read_timeout` | Maximum time to read a complete request. | Positive duration. |
| `server.write_timeout` | Maximum time to write an HTTP response. | Must exceed `protocol.decision_timeout`. |
| `server.idle_timeout` | HTTP keep-alive idle limit. | Positive duration. |
| `server.shutdown_grace` | Duration given to each shutdown phase: in-flight work, cancellation-answer delivery, and audit flush. | Positive duration. |

The command serves `POST /acs`, `GET /healthz` and `GET /readyz`. Readiness is
enabled only after the policy engine and Guardian are ready.

## Policy

| Key | Meaning | Constraint |
| --- | --- | --- |
| `policy.deployment_dir` | Root directory of one AGT policy deployment. | Existing absolute path, or relative to the configuration file. |
| `policy.manifest` | AGT manifest within `policy.deployment_dir`. | Non-empty relative path that cannot escape the deployment directory. |
| `policy.mapping` | ACS verdict mapping within `policy.deployment_dir`. | Same path rule as `policy.manifest`. |
| `policy.evaluator` | `agt` uses AGT's runtime library. `go` uses the Go reproduction. | Required: `agt` or `go`. The reference YAML selects `agt`. `make build` includes AGT; `make build EVALUATOR=go` refuses `agt` at startup. |
| `policy.opa_path` | The OPA executable or its directory. | Required for `agt`: absolute or relative to the configuration file. Directory paths select `opa` on Unix and `opa.exe` on Windows. `make agt-native` copies the host executable to `.acs/agt/bin/`. Not read by `go`. |
| `policy.opa_timeout` | The bound AGT puts on each `opa` run; past it, AGT denies the step. | Required for `agt`: a duration such as `4s`, positive, a whole number of milliseconds, and shorter than `protocol.decision_timeout`. AGT's timer starts after `opa` starts, so leave room for process start and signing; `guardian.yaml` leaves one second. Not read by `go`. |
| `policy.ask_substitution` | Endpoint behavior when ASK cannot be completed. | `none`, `deny` or `defer`. |
| `policy.tool_aliases` | Optional map from an Observed Agent's tool name to the manifest's tool name. | Both names must be non-empty. |

`ask_substitution: none` leaves an ASK from the engine unchanged. `deny` returns DENY
`approver_unavailable`. `defer` returns DEFER with a deny timeout decision. The
setting belongs to this Guardian endpoint; it is not tied to a particular host
product. The reference configuration uses `deny` because its host examples do
not provide an ACS approval channel.

A tool alias changes only the policy input. The signed ACS request, the
SessionContext chain and audit records keep the original tool name.

Build selection and evaluator selection are separate. The `agteval` build tag
includes AGT; `policy.evaluator` selects which evaluator runs.
`ACS__POLICY__EVALUATOR=go` selects the Go evaluator in either build.
An AGT build still links the library when the Go evaluator is selected.
`make run EVALUATOR=go` builds without that dependency and selects the Go evaluator.

The AGT build includes the library and `agt-native.json` beside the binary.
Linux and macOS builds also embed the platform library directory under `.acs/agt/` for tests.
To deploy elsewhere, keep the library and `agt-native.json` in one directory.
Set `LD_LIBRARY_PATH` on Linux or `DYLD_LIBRARY_PATH` on macOS to that directory.
On Windows, keep the DLL beside the executable or add its directory to `PATH`.
The Guardian refuses startup if the build record is missing or its checksum differs from the library.

## Security and audit

| Key | Meaning | Constraint |
| --- | --- | --- |
| `security.hmac_key_id` | The `key_id` the deployment gives its secret (§10): an opaque label, such as `2026-10`. A request signed under any other `key_id` is refused with `SIGNATURE_INVALID`. | Non-empty; no default. |
| `security.hmac_secret_file` | File holding the shared HMAC secret, the HKDF input keying material. | Absolute path, or relative to the configuration file; standard base64 that decodes to at least 32 bytes, surrounding whitespace ignored; protect with operating-system permissions. |
| `audit.envelope_log` | JSONL file for inbound and outbound ACS envelopes. | Absolute path, or relative to the configuration file. A symbolic link at the path is refused. On Unix, a file that group or other can access is refused; the Guardian does not change its mode. A missing directory is created with mode `0700`. |
| `audit.event_log` | JSONL file for Guardian audit events. | Absolute path, or relative to the configuration file. A symbolic link at the path is refused. On Unix, a file that group or other can access is refused; the Guardian does not change its mode. A missing directory is created with mode `0700`. |
| `audit.max_file_bytes` | Size at which each audit file rotates: it becomes `<file>.1`, older ones move up. `0` keeps every record, for a deployment that rotates the files with its own tooling. | Zero or positive. `guardian.yaml` ships 268435456 (256 MiB). |
| `audit.max_files` | Rotated files kept per audit file; the one past it is deleted. A log keeps at most `max_file_bytes × (max_files + 1)` bytes, plus one record larger than `max_file_bytes`. | Zero or positive; needs `max_file_bytes`, which in turn needs at least 1, so a rotation never deletes the live log. `guardian.yaml` ships 3, so at most 1 GiB per log. |
| `audit.max_queue_records` | Records waiting for the background writer, the one being written included. A record past it is dropped and counted. | Positive. `guardian.yaml` ships 4096. |
| `audit.max_queue_bytes` | Bytes of records waiting for the writer, the one being written included, so a stalled disk holds at most this many bytes of records. A record past it is dropped and counted. | At least `2 × limits.max_body_bytes + 256`, so one request of the largest body fits. `guardian.yaml` ships 67108864 (64 MiB). |
| `storage.provider` | Where sessions, replay history and policy state live. `memory`: in this process, lost when it stops, one process per endpoint. | `memory`, the one provider this command ships. A host that embeds the `guardian` package passes its own `SessionContextStore` for durability or replicas. |

Envelope records contain raw requests and answers, including tool arguments
and results. Treat both audit files as sensitive.

A background writer appends the records, so a slow disk never delays a
decision. When a record would take its queue past `audit.max_queue_records`
or `audit.max_queue_bytes`, it is dropped and counted; logging continues as
space frees. A write failure turns
the log off for the rest of the process, and every later record is dropped
and counted. The first queue-full drop, the first write failure and the first
record offered after shutdown closed the log each print one line to stderr. A
dropped record keeps its `seq`, so the numbers in a file skip it within one
run. Shutdown gives the writer its own `server.shutdown_grace`. The command
exits with an error when a record was dropped or the queue did not flush, and
names how many records were lost; a record offered after that count, by an
engine that ignored cancellation, gets only its stderr line. The Guardian
records a request before it checks the signature, so unsigned requests share
the queue with signed ones and can push them out of a full queue.

Two standalone processes may share this configuration file, policy directory
and HMAC secret. Give each process its own `server.port`, `audit.envelope_log`
and `audit.event_log`; two processes must not write the same JSONL files. The
standalone command keeps sessions in its own memory. Replicas serving one
endpoint therefore embed the library with a shared `SessionContextStore`.

## Protocol

| Key | Meaning | Constraint |
| --- | --- | --- |
| `protocol.on_decision_failure` | Failure posture advertised in `ServerHello`. | `proceed` or `deny`. |
| `protocol.decision_timeout` | Default deadline for a policy decision. | Positive duration and shorter than `server.write_timeout`. |
| `protocol.skew_window` | Accepted timestamp distance in either direction. | Positive duration. |

`on_decision_failure` tells the Observed Agent what to do when it cannot obtain
or verify a decision. The Guardian cannot enforce the agent's behavior after
communication fails. The `guardian.Config` zero value advertises `proceed`;
`guardian.yaml` explicitly advertises `deny`.

## Limits

| Key | Meaning | Constraint |
| --- | --- | --- |
| `limits.max_sessions` | Sessions held by the in-memory store. | Positive integer. |
| `limits.max_entries` | Context entries retained per session. | Positive integer. |
| `limits.max_reservations` | Requests remembered per session for replay protection. Each reservation stores the request ID and its nonce when present. | Positive integer. |
| `limits.max_skill_approvals` | Skill approvals retained across sessions. | Positive integer. |
| `limits.max_engine_calls` | Policy evaluations allowed to run concurrently. Under `agt` each one is an `opa` process. | Positive integer. `guardian.yaml` ships 32, measured in [Load](load.md); the library default is 256. |
| `limits.max_policy_state_bytes` | Per-session engine state size. | Positive integer. |
| `limits.max_body_bytes` | HTTP request-body size. | Positive integer. |
| `limits.max_deferrals` | DEFER decisions allowed in one session. | Positive integer. |
| `limits.session_retention` | Idle time before an in-memory session may be removed. | At least twice `protocol.skew_window`. |

The two-window retention rule ensures that every accepted future-dated request
is stale before its replay history can be removed. Reaching any store bound is
an explicit refusal; the store never drops a live session to admit another.

## Environment overrides

The prefix is `ACS__`. A double underscore enters a nested YAML object; a
single underscore remains part of a key name. Values use the same decoding and
validation as YAML.

```bash
ACS__SERVER__PORT=8788 \
ACS__POLICY__DEPLOYMENT_DIR=/opt/acs/policy \
ACS__POLICY__ASK_SUBSTITUTION=defer \
ACS__POLICY__TOOL_ALIASES__shell=bash \
ACS__SECURITY__HMAC_SECRET_FILE=/run/secrets/acs-hmac \
guardian --config /etc/acs/guardian.yaml
```

For example, `ACS__LIMITS__MAX_ENGINE_CALLS` overrides
`limits.max_engine_calls`. Environment variables do not create an alternate
configuration surface: an override for a key absent from the declared schema
is rejected.

The checked-in configuration uses port `8787` for `make run`. Automated checks
and interactive host examples set `ACS__SERVER__PORT` to `0` and point the audit
logs at a temporary directory; the conformance check also sets its own HMAC key.
They read the chosen address from the Guardian at startup and leave
`guardian.yaml` unchanged.
