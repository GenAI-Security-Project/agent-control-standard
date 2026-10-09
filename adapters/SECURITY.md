# Adapter security posture

This document is the threat model for the three reference adapters
(`claude-code/`, `cursor/`, `nat/`), the `example-guardian/`, and the
shared helpers in `_common/`. It says what attacks the code defends
against, how, and what is explicitly out of scope.

ACS is a security project — the whole point of the standard is to
police agent behavior. Adapter code that itself has security holes
undermines the standard. This document and the tests under
`_common/tests/test_security.py` are the falsifiers for every claim
below.

## In-scope components

| Component | Trust posture |
|---|---|
| Adapter process (`claude-code/`, `cursor/`) | Shell-spawned by the framework per hook event. Runs as the framework's user. Reads framework JSON from stdin. |
| Adapter middleware (`nat/`) | In-process inside the agent's Python runtime. Same address space as the agent. |
| Guardian process (`example-guardian/`) | HTTP server. Holds the HMAC secret. Computes the rolling audit chain. |
| Wire transport | JSON-RPC over HTTP (deployments wrap with HTTPS / mTLS for production). |
| HMAC shared secret | Loaded from `ACS_HMAC_SECRET_FILE` (preferred) or `ACS_HMAC_SECRET` (env-var fallback). |
| Cache files | `~/.cache/acs-adapter-handshake/` (ServerHello cache), `~/.cache/acs-adapter-session/` (per-session step-id tracking). |
| Audit log | `ACS_AUDIT <json>` lines on adapter stderr. |

## Threat model

### Defended attacks (with the mitigation that defeats each)

**T1 — Envelope tampering on the wire.**
An attacker intercepts the adapter ↔ Guardian connection and modifies
the payload, method, or session_id.
*Mitigation:* HMAC-SHA256 over JCS-canonicalized envelope with the
signature field removed (Specification §10). Both sides verify with
`hmac.compare_digest` (constant-time). Signed input includes
`method`, `metadata.session_id`, `request_id`, and `timestamp` so the
signature is bound to the whole envelope.
*Test:* `test_acs_core_conformance.py::Core07_BaselineIntegrity::test_tampered_request_signature_invalid`

**T2 — Cross-session signature lift.**
An attacker captures a signed envelope from session A and replays it
under a different session_id.
*Mitigation:* HMAC key is HKDF-SHA256-derived per-session from
`(input_keying_material, session_id)`. A signature valid under
session A's derived key fails verification under session B's key.
*Test:* covered indirectly by `HmacSigning::test_signed_request_accepted`
(uses session-specific key derivation).

**T3 — Replay within a session.**
Same envelope re-sent within the same session_id.
*Mitigation:* Guardian tracks `request_id` per session and rejects
duplicates with `REPLAY_DETECTED` (-32005, §10.3). Per-session,
in-memory; bounded by session lifetime.
*Test:* `ReplayRejection::test_duplicate_request_id_rejected`

**T4 — Stale or future-dated envelope.**
Captured envelope replayed outside the freshness window.
*Mitigation:* Guardian rejects timestamps outside the negotiated skew
window (default ±5 min) with `TIMESTAMP_OUT_OF_WINDOW` (-32006, §10.3).
*Test:* `TimestampSkew::test_ancient_timestamp_rejected`,
`test_future_timestamp_rejected`

**T5 — SSRF via `ACS_GUARDIAN_URL`.**
Attacker controls the env var; sets it to `file:///etc/passwd` to
read arbitrary files, or to `data://` to feed a crafted response.
*Mitigation:* `validate_guardian_url()` rejects any scheme that is
not `http` or `https`. Called from every adapter's `call_guardian`
and from `do_handshake` / `ping` in `_common`.
*Test:* `GuardianUrlSchemeAllowlist::test_file_scheme_rejected` and
five other scheme rejections.

**T6 — Guardian HTTP DoS via oversized body.**
Attacker POSTs a request with Content-Length > available RAM,
expecting the Guardian to allocate.
*Mitigation:* Guardian refuses Content-Length > `MAX_REQUEST_BODY_BYTES`
(1 MiB, matches the handshake's `max_payload_size_bytes`) before
reading the body. Returns 413 + JSON-RPC error -32600.
*Test:* `GuardianBodySizeCap::test_oversized_request_rejected`

**T7 — Leaked HMAC secret via world-readable file.**
Operator (or misconfiguration) leaves `ACS_HMAC_SECRET_FILE` mode
0644 / 0640; any local process can read the key.
*Mitigation:* `load_hmac_secret()` rejects the file unless its mode is
`& 0o077 == 0` (no group / other access) AND it is owned by the
running user AND it is not a symlink. `SecretFilePermissionsError`
prevents the adapter from silently using a leaked secret.
*Test:* `HmacSecretFilePermissions::{test_world_readable_rejected,
test_group_readable_rejected, test_symlink_rejected}`

**T8 — Cache / session-state poisoning.**
Local attacker writes the handshake cache or session-state file
between adapter invocations. For session-state, this would let them
inject a fake `parent_step_id` into the next `subagentStart` payload.
*Mitigation:* Both cache directories created mode 0700; cache files
created mode 0600 via `os.open(...O_CREAT, 0o600)`. A local attacker
without same-uid privileges cannot read or write the state.
*Test:* `CacheDirPermissions::{test_session_state_dir_is_0700,
test_session_state_file_is_0600}`

**T9 — Regex DoS via oversized command.**
Attacker submits a multi-MB command string crafted to trigger
catastrophic backtracking in the destructive-bash regex set.
*Mitigation:* `scan_destructive_bash_safely()` refuses to scan
commands longer than `DESTRUCTIVE_SCAN_MAX_LEN` (8 KiB). The skip is
audited and the caller MUST treat the return value `"input_too_large"`
as suspicious — NOT as "safe to allow." Real shell commands are tiny;
multi-KB strings are either tunneled data or a DoS attempt.
*Test:* `RegexInputSizeCap::test_oversized_command_is_short_circuited`

**T10 — Audit-log injection.**
Field values in audit events (`session_id`, `method`, `error=str(e)`)
could contain newlines or control characters that, if naively written,
would let an attacker forge fake `ACS_AUDIT` lines.
*Mitigation:* `audit_event()` emits a single line of
`json.dumps(payload, sort_keys=True)`. JSON encoding escapes `\n`,
`\r`, and other control characters in string values. The
`ACS_AUDIT ` prefix is the only unescaped text.
*No dedicated test* — the property is enforced by the JSON encoder;
adding a test would be checking stdlib behavior.

**T11 — Handshake downgrade.**
Attacker MITMs the handshake response to claim the Guardian doesn't
support signing, hoping the adapter then sends unsigned envelopes.
*Mitigation:* The adapter signs iff its own `ACS_HMAC_SECRET` /
`_FILE` is set, regardless of what `signature_algorithms_supported`
the handshake advertised. The handshake's advertised algorithm list
is informational; it does not control the adapter's signing behavior.
*No test* — this is an absence of behavior. Verified by reading the
code: `sign_envelope()` consults `load_hmac_secret()` only.

**T12 — Guardian-side signature stripping.**
Attacker MITMs the Guardian's response and removes the `signature`
field, hoping the adapter's response verification silently accepts.
*Mitigation:* `verify_signature()` returns False if a signature is
absent AND the adapter has `ACS_HMAC_SECRET` configured. The adapter
rejects the response and fails per `ACS_DEFAULT_DENY` posture (audit
event in either case).
*No dedicated test* — covered indirectly by the conformance suite's
signed round-trip tests (Core07_BaselineIntegrity), which would fail
if signature absence were silently accepted.

### Out of scope (deployment / operational concerns)

**O1 — Plaintext HTTP exposes payload content.**
Even when HMAC-signed, the body is readable on the wire. An attacker
on the network path can read tool names, arguments, prompts, results.
*Posture:* Use HTTPS for any non-loopback deployment. Set
`ACS_GUARDIAN_URL=https://...` and put the Guardian behind TLS (real
cert, or mTLS for stronger client identity). The adapter's URL
allowlist accepts `https://`. We do not bundle a TLS implementation.

**O2 — Regex bypass via shell quoting / expansion.**
Shell evaluates `r''m -rf /` as `rm -rf /` after quote removal. The
adapter only sees the literal `r''m -rf /` from the framework, which
does not match our destructive-bash regex. Same for `$(echo rm) -rf /`,
backslash escapes, locale-dependent commands, etc.
*Posture:* The destructive-bash regex is a teaching artifact and a
defense-in-depth heuristic, NOT a security boundary. Production
deployments wire a real policy engine (OPA/Rego, Cedar, or a vendor
policy bundle) into the Guardian. Documented in
`example-guardian/example_guardian.py` and `adapters/README.md`.

**O3 — Secret in env-var visible to child processes / `ps eauxw`.**
`ACS_HMAC_SECRET` shows up in `/proc/PID/environ` and is inherited by
any child process the adapter or Guardian spawns.
*Posture:* That's exactly why `ACS_HMAC_SECRET_FILE` exists. The env
var is a development convenience; production deployments use the file
path with mode 0600. Documented in the Guardian README.

**O4 — Compromised Guardian.**
A Guardian that holds the symmetric HMAC key can re-sign a rewritten
chain head and present a clean history. The HMAC baseline detects
network tampering and cross-Guardian disagreement but cannot prove
non-repudiation against the Guardian itself.
*Posture:* That's what the ACS-Crypto profile (asymmetric / PQC
signatures) and the ACS-Audit profile (`request_hash` per
ContextEntry) are for. v0.1 baseline acknowledges this tradeoff
(`conformance.md:30`); we don't implement those profiles.

**O5 — Compromised secret-file storage.**
A reader of the storage volume (cloud snapshot, backup, etc.) gets
the HMAC key. File permissions don't help there.
*Posture:* Encrypted storage, sealed secrets (Vault, K8s sealed
secrets, KMS-backed envelopes). Out of scope for the adapter; the
adapter just receives the key bytes from a file path.

**O6 — Memory disclosure / core dumps.**
HMAC key in process memory. No explicit zeroize.
*Posture:* Disable core dumps in production (`ulimit -c 0` /
`fs.suid_dumpable=0`). Python doesn't expose secure-erase primitives;
acceptable v0.1 tradeoff.

**O7 — Compromised adapter binary.**
A malicious adapter binary (shipped via supply-chain attack on the
ACS repo, or a tampered local install) does whatever it wants.
*Posture:* Out of scope. Verify the adapter against the published
hash. The ACS-Inspect profile addresses the AgBOM side; binary
integrity of the adapter itself is a deployment-tools concern.

**O8 — Compromised framework (Claude Code / Cursor / NAT).**
If Claude Code itself is compromised, all bets are off — it can
choose not to call hooks, ignore deny responses, etc. ACS-Core §6.4
("decision honoring") is a property the framework must implement; an
adapter cannot enforce it on a hostile framework.
*Posture:* Framework integrity is a separate trust boundary outside
ACS's scope.

## Mitigation matrix at a glance

| Threat | Mitigation | Test |
|---|---|---|
| T1 envelope tampering | HMAC-SHA256 over JCS canonical input | `HmacSigning::test_tampered_request_rejected` |
| T2 cross-session lift | per-session HKDF key derivation | (covered by T1 verification path) |
| T3 in-session replay | per-session `request_id` set + -32005 | `ReplayRejection::test_duplicate_request_id_rejected` |
| T4 timestamp skew | skew-window check + -32006 | `TimestampSkew::test_ancient_timestamp_rejected` |
| T5 SSRF | URL scheme allowlist (http/https) | `GuardianUrlSchemeAllowlist::*` (6 tests) |
| T6 body-size DoS | Content-Length cap + 413 | `GuardianBodySizeCap::test_oversized_request_rejected` |
| T7 leaky secret file | mode/owner/symlink check on `ACS_HMAC_SECRET_FILE` | `HmacSecretFilePermissions::*` (4 tests) |
| T8 cache poisoning | dir 0700 + file 0600 | `CacheDirPermissions::*` (2 tests) |
| T9 regex DoS | 8 KiB input cap + audit | `RegexInputSizeCap::*` (3 tests) |
| T10 log injection | `json.dumps` escaping | enforced by stdlib |
| T11 handshake downgrade | adapter signs based on own config, not handshake | code-level |
| T12 response sig stripping | `verify_signature` False when sig absent + secret set | code-level |

## How to report a finding

**Do not file public issues for security vulnerabilities.** Use
GitHub's [private vulnerability reporting](https://github.com/GenAI-Security-Project/agent-control-standard/security/advisories/new)
to disclose privately — the process and response commitment are in
[`CONTRIBUTING.md` § Reporting Security Issues](../CONTRIBUTING.md#reporting-security-issues).
(An earlier version of this paragraph said to open a labeled public
issue, which contradicted CONTRIBUTING.md and pointed at a CODEOWNERS
file that doesn't exist — a researcher following the nearest
instruction file would have posted a public zero-day. PR #22 review.)
