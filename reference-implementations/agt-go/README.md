# Go Guardian reference implementation

This module implements an ACS v0.1.0 Guardian in Go. Its default policy engine
evaluates the same checked-in Agent Governance Toolkit (AGT) Rego policies as the
[TypeScript reference](../agt/README.md), using OPA's Go library.

Forty-nine sessions recorded from the TypeScript Guardian produce the same
dispositions, reason codes, policy references, reasoning and modifications.
Those cases establish observed parity for the covered behavior, not general
equivalence to AGT's Rust runtime. See [conformance](docs/conformance.md) for
ACS-Core claims and [differences](docs/differences.md) for the exact boundary.

## Start here

| Goal | Start with |
| --- | --- |
| Run the standalone Guardian | [Quick start](#quick-start) |
| Embed the Go library | [Library use](#library-use) and [embedding](docs/embedding.md) |
| Try a governed Codex session | [Codex example](examples/codex/README.md) |
| Try a governed OpenCode session | [OpenCode example](examples/opencode/README.md) |
| Run the complete local gate | [`make check`](#verification) |
| Inspect ACS-Core coverage | [Conformance](docs/conformance.md) |
| Configure a deployment | [Configuration](docs/configuration.md) |

## Quick start

Running the Guardian requires Go 1.27.1 or newer, Make and OpenSSL. The full
quality gate also requires curl and Bun 1.3.11 or newer. The Guardian runtime
itself is Go.

From this directory:

```bash
make run
```

The target creates `.acs/hmac-secret` for local development and starts the
Guardian from [`guardian.yaml`](guardian.yaml). The reference configuration
listens on `127.0.0.1:8787`, loads the checked-in AGT deployment from `../agt`,
keeps sessions in memory and writes raw ACS envelopes under `.acs/`.
`make run` stays in the foreground. Press `Ctrl+C` to stop the Guardian and
release the port.

Readiness returns HTTP 200 with an empty body:

```bash
curl --fail http://127.0.0.1:8787/readyz
```

Run a signed allow-and-deny demonstration without an external agent host:

```bash
go test -count=1 ./cmd/guardian -run '^TestServesDecisions$' -v
```

The test starts the built command. The checked-in policy allows `ls -la` and denies
`echo rm -rf /`.

## Architecture

```text
Observed Agent -> signed ACS/JSON-RPC -> guardian.Guardian -> PolicyEngine
                                             |                  |
                                             |                  +-> agtbridge -> OPA
                                             +-> Signer
                                             +-> SessionContextStore
                                             +-> AuditLog
```

| Part | Path | Responsibility |
| --- | --- | --- |
| ACS wire types | [`acs/`](acs/) | Envelopes, handshake, decisions, hook payloads and SessionContext objects. |
| Guardian | [`guardian/`](guardian/) | Validation, authentication, negotiation, replay protection, session ordering, policy decisions and signed responses. |
| AGT policy engine | [`agtbridge/`](agtbridge/) | AGT manifest loading, policy input, annotations, OPA evaluation and verdict conversion. |
| Standalone command | [`cmd/guardian/`](cmd/guardian/) | `POST /acs`, `/healthz` and `/readyz`. |
| Store contract | [`guardian/guardiantest/`](guardian/guardiantest/) | Shared contract suite for durable `SessionContextStore` implementations. |
| Host examples | [`examples/`](examples/) | Custom engine, Codex and OpenCode integrations. |

The library keeps the ACS contract inside the Guardian. Deployments provide
the policy engine, key custody, session storage and audit destination through
four interfaces. AGT is the standalone command's engine, not a dependency of
the Guardian package.

### How AGT is used

AGT's ACS policy runtime has no official Go binding. The TypeScript reference
uses AGT's Node package. That package loads AGT's Rust runtime, which invokes
the OPA command-line program. This Go implementation instead runs the
unchanged, checked-in AGT Rego policies with OPA's Go library. `agtbridge`
implements only the AGT manifest behavior those policies use: it builds the
policy input, runs annotations, converts verdicts and preserves policy state.
Startup fails if the manifest asks for an unsupported AGT feature. The exact
boundary and its trade-offs are documented in
[differences](docs/differences.md#agt).

## Scope and limitations

- The Guardian implements all five ACS dispositions. The checked-in AGT policy deployment
  emits ALLOW, DENY and MODIFY; it has no configured approver or DEFER mapping.
- The default store is bounded but in memory. A restart loses its sessions.
  Durable and multi-replica deployments provide `SessionContextStore`.
- JSONL audit files contain raw ACS envelopes, including tool arguments. Protect
  them as sensitive data.
- The checked-in AGT policies are a protocol demonstration, not a complete egress
  control. Its measured policy limits are listed in
  [differences](docs/differences.md#measured-policy-limits).
- Every request except `system/ping` must be signed. Responses to authenticated
  requests are signed while the configured signer is available. An unsigned
  ping response, an error produced before authentication, and the internal
  error produced when signing itself fails are unsigned.
- The project ships no container and no Inspector.

## Library use

```go
engine, err := agtbridge.New(ctx, os.DirFS("/opt/acs/policy"),
    "policy/manifest.yaml", "mapping.yaml", agtbridge.Options{})
signer, err := guardian.NewHMACSigner(
    guardian.HMACKey{ID: "default", Secret: secret},
)
g, err := guardian.New(guardian.Config{
    Engine: engine,
    Signer: signer,
})
http.Handle("/acs", g)
```

A deployment with its own engine, signer, store or audit log implements the
corresponding interface. A nil store selects the bounded in-memory store. A nil
audit log records nothing. The Guardian passes the request `context.Context` to
all four interfaces without interpreting deployment-specific values in it.

[`examples/custom-engine`](examples/custom-engine/) demonstrates all four
interfaces without importing `agtbridge`. Until this nested module receives a
version tag, use it from a repository checkout or an explicit commit version.

## Configuration

The command requires `--config PATH`. [`guardian.yaml`](guardian.yaml) is a
runnable local configuration, not a production template. Required values are
validated at startup; unknown YAML keys and unknown `ACS__` environment
variables stop startup.

Environment overrides use `ACS__` as the prefix and `__` between nested keys:

```bash
ACS__SERVER__PORT=8788 \
ACS__POLICY__DEPLOYMENT_DIR=/opt/acs/policy \
ACS__SECURITY__HMAC_SECRET_FILE=/run/secrets/acs-hmac \
go run ./cmd/guardian --config /etc/acs/guardian.yaml
```

See [configuration](docs/configuration.md) for every key, constraint and path
rule.

## Verification

After a fresh clone, install the dependencies used by the quality gate:

```bash
make setup
```

`make setup` downloads Go modules and installs the locked dependencies of the
existing TypeScript conformance runner. It does not install Codex or OpenCode.

Then run:

```bash
make check
```

`make check` is the complete local gate. It checks formatting and module
tidiness, runs `go vet`, Staticcheck and `govulncheck`, runs race-enabled Go
tests and the actual OpenCode plugin callback tests, checks the custom-engine
module, runs the shared ACS conformance command against a live Go Guardian,
enforces the coverage floor, and runs `make docs-check`.

`make docs-check` checks local file links and qualified Go test names in every
Markdown file in this module. It also requires a test for each conformance row
that claims implemented behavior.

The gate exercises signed Codex and OpenCode adapter sessions with simulated
host events. It does not launch either external CLI or a model. Use
`make codex-example` or `make opencode-example` for an interactive host run.
Each command starts its own Guardian on an operating-system-assigned port and
stops that Guardian when the external CLI exits. Their temporary Guardian logs
are isolated, so Codex and OpenCode examples can run at the same time. The
examples were tested with Codex CLI 0.154.0 and OpenCode 2.0.11.

Run `make help` for the public targets. `scripts/record-ts-cases.sh` refreshes
the TypeScript recordings and requires Bun.

## Reference documents

| Document | Contents |
| --- | --- |
| [Conformance](docs/conformance.md) | ACS-Core requirement, implementation status and covering tests. |
| [Configuration](docs/configuration.md) | Standalone command configuration and environment overrides. |
| [Embedding](docs/embedding.md) | Interface behavior, ordering and storage invariants. |
| [Differences](docs/differences.md) | Deliberate differences from the TypeScript reference and AGT runtime boundary. |
| [Coverage relative to TypeScript](docs/test-parity.md) | Accounting for the TypeScript test files. |
| [Regression matrix](docs/regression-matrix.md) | Public ACS findings and external Guardian vectors covered here. |
| [Canonical form](docs/canonical-form.md) | Canonicalization, hashes, signatures and independent vectors. |

## License

Apache License 2.0; see [`../../LICENSING.md`](../../LICENSING.md). The AGT
policy files remain under their MIT license. The RFC 8785 vectors under
`internal/jcs/testdata/` come from the RFC author's reference implementation
under Apache License 2.0.
