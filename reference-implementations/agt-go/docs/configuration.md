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
| `server.write_timeout` | Maximum time to write a response. | Must exceed `protocol.decision_timeout`. |
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
| `policy.ask_substitution` | Endpoint behavior when ASK cannot be completed. | `none`, `deny` or `defer`. |
| `policy.tool_aliases` | Optional map from an Observed Agent's tool name to the manifest's tool name. | Both names must be non-empty. |

`ask_substitution: none` returns ASK unchanged. `deny` returns DENY
`approver_unavailable`. `defer` returns DEFER with a deny timeout decision. The
setting belongs to this Guardian endpoint; it is not tied to a particular host
product. The reference configuration uses `deny` because its host examples do
not provide an ACS approval channel.

A tool alias changes only the policy input. The signed ACS request, the
SessionContext chain and audit records keep the original tool name.

## Security and audit

| Key | Meaning | Constraint |
| --- | --- | --- |
| `security.hmac_key_id` | `key_id` advertised and used by the HMAC signer. | Non-empty. |
| `security.hmac_secret_file` | File holding shared HMAC input keying material. | Absolute path, or relative to the configuration file; at least 32 bytes; protect with operating-system permissions. |
| `audit.envelope_log` | JSONL file for inbound and outbound ACS envelopes. | Absolute path, or relative to the configuration file. |
| `audit.event_log` | JSONL file for Guardian audit events. | Absolute path, or relative to the configuration file. |

Envelope records contain raw requests and responses, including tool arguments
and results. Treat both audit files as sensitive. The writer is asynchronous
and bounded. Shutdown gives the writer its own `server.shutdown_grace`; failure
to flush makes the command exit with an error.

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
| `limits.max_engine_calls` | Policy evaluations allowed to run concurrently. | Positive integer. |
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
and interactive host examples override only `ACS__SERVER__PORT` with `0`. They
read the chosen address from the Guardian at startup and leave `guardian.yaml`
unchanged.
