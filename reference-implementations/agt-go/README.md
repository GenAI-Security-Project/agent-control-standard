# Go Guardian reference implementation

This module implements an ACS v0.1.0 Guardian in Go. Its default policy engine
runs the same checked-in Agent Governance Toolkit (AGT) Rego policies as the
[TypeScript reference](../agt/README.md), with OPA's Go library.

Forty-nine sessions recorded from the TypeScript reference produce the same
dispositions, reason codes, policy references, reasoning and modifications here
(`agtbridge.TestRecordedCases`). That is parity on the behavior those sessions cover, not
general equivalence to AGT's runtime. [Conformance](docs/conformance.md) maps each
ACS-Core item to the tests that cover it.

## Start here

### In this README

| Goal | Section |
| --- | --- |
| Run the standalone Guardian | [Quick start](#quick-start) |
| Use the Guardian as a Go library | [Use it as a Go library](#use-it-as-a-go-library) |
| Run the quality gate | [Verification](#verification) |
| Know what is out of scope | [Scope and limitations](#scope-and-limitations) |

### Other documents

| Goal | Document |
| --- | --- |
| Understand how the Guardian works | [Architecture](docs/architecture.md) |
| Review the code | [Architecture: read the code in this order](docs/architecture.md#read-the-code-in-this-order) |
| Configure a deployment | [Configuration](docs/configuration.md) |
| Plug in your own engine, store, signer or audit log | [Extend the Guardian](docs/extending.md) |
| Try a governed Codex or OpenCode session | [Codex example](examples/codex/README.md), [OpenCode example](examples/opencode/README.md) |
| Check the ACS-Core claims | [Conformance](docs/conformance.md) |
| See what is signed and hashed, byte by byte | [Canonical form](docs/canonical-form.md) |
| Compare with the TypeScript reference | [Differences](docs/differences.md), [TypeScript test parity](docs/test-parity.md) |
| See which public findings are covered | [Regression matrix](docs/regression-matrix.md) |

## Quick start

Running the Guardian requires Go 1.27.1 or newer, Make and OpenSSL. The
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

## Use it as a Go library

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

- `guardian.Config` requires `Engine` and `Signer`. A nil `Store` selects
  `guardian.MemorySessionContextStore`, and a nil `AuditLog` records nothing.
- Mount the Guardian as an `http.Handler` at your own route, or call
  `Guardian.Handle(ctx, body)` from any transport.
- Put what you resolve from the request, a tenant or an endpoint, in `ctx`. The Guardian
  passes `ctx` to all four interfaces and never reads it.
- To plug in your own engine, store, signer or audit log, see
  [extend the Guardian](docs/extending.md).
- [`examples/custom-engine`](examples/custom-engine/) is its own Go module. Until it
  receives a version tag, use it from a repository checkout or an explicit commit version.

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

`make check` is the quality gate. It checks formatting and module
tidiness, runs `go vet`, Staticcheck and `govulncheck`, runs race-enabled Go
tests and the actual OpenCode plugin callback tests, checks the custom-engine
module, runs the shared ACS conformance command against a live Go Guardian,
enforces the coverage floor, and runs `make docs-check`.

`make docs-check` checks local file links and qualified Go test names in every
Markdown file in this module. It also requires a test for each conformance row
that claims implemented behavior.

The gate exercises signed Codex and OpenCode adapter sessions with simulated
host events. It does not launch either external CLI or a model; the
[Codex](examples/codex/README.md) and [OpenCode](examples/opencode/README.md)
examples describe the interactive runs.

Run `make help` for the public targets. `scripts/record-ts-cases.sh` refreshes
the TypeScript recordings and requires Bun.

## Scope and limitations

- The Guardian implements all five ACS dispositions; the checked-in AGT policies emit
  only ALLOW, DENY and MODIFY ([dispositions](docs/conformance.md#dispositions)).
- The default store is bounded but in memory. A restart loses its sessions.
  For durable or multi-replica use, write your own `SessionContextStore`
  ([extend the Guardian](docs/extending.md)).
- JSONL audit files contain raw ACS envelopes, including tool arguments. Protect
  them as sensitive data.
- The checked-in AGT policies are a protocol demonstration, not a complete egress
  control. Their measured limits are listed in
  [differences](docs/differences.md#measured-policy-limits).
- Every request except `system/ping` must be signed. The signature row in
  [conformance](docs/conformance.md) says which answers are signed.
- The module ships no container, no Inspector and no Claude Code example.

## License

Apache License 2.0; see [`../../LICENSING.md`](../../LICENSING.md). The AGT
policy files remain under their MIT license. The RFC 8785 vectors under
`internal/jcs/testdata/` come from the RFC author's reference implementation
under Apache License 2.0.
