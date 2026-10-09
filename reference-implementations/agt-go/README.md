# Go Guardian reference implementation

This module implements an ACS v0.1.0 Guardian in Go. The default build uses the
Agent Governance Toolkit (AGT) runtime in the Guardian process.
Both reference implementations use the same checked-in [AGT policies](../agt/README.md).
An optional build uses a Go reproduction of the runtime without cgo.

Forty-nine sessions recorded from the TypeScript reference produce the same
dispositions, reason codes, policy references, reasoning and modifications here, through
each evaluator (`agtbridge.TestRecordedCases`). `agtbridge.TestEvaluatorsAgree` also
compares the two evaluators step by step. That is parity on the behavior those sessions
cover. [Conformance](docs/conformance.md) maps each
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
| Select a platform or build a container | [Build and package](docs/building.md) |

## Quick start

The AGT build supports Linux amd64 and arm64, both Mac architectures, and Windows amd64.
The build requires Go 1.27.1 or newer
and a C compiler. Install Make, OpenSSL, Git, curl, jq and [rustup](https://rustup.rs).
The quality gate also requires Bun 1.3.11 or newer.

The AGT evaluator is the default. The first build compiles AGT's runtime library
and downloads `opa` into `.acs/agt/`. [`agt-native.lock`](agt-native.lock) pins
the source commit, Rust toolchain and OPA executable.
The build refuses tracked changes and untracked files in the AGT source checkout.
Later builds reuse the compiled library. CI defines a complete check for each native platform.
See [Build and package](docs/building.md) for toolchains and verification limits.

From this directory:

```bash
make run
```

The target creates `.acs/hmac-secret` for local development.
The target starts the Guardian from [`guardian.yaml`](guardian.yaml), with `policy.evaluator: agt`.
The Guardian listens on `127.0.0.1:8787` and loads the checked-in deployment from `../agt`.
Sessions stay in memory. Raw ACS envelopes are written under `.acs/`.
`make run` stays in the foreground. Press `Ctrl+C` to stop the Guardian and
release the port.

Readiness returns HTTP 200 with an empty body:

```bash
curl --fail http://127.0.0.1:8787/readyz
```

Run every test with AGT, including the signed allow-and-deny demonstration:

```bash
make test
```

`cmd/guardian.TestServesDecisions` starts the built command.
The checked-in policy allows `ls -la` and denies `echo rm -rf /`.

Without a C toolchain or Rust, run `make run EVALUATOR=go`.
The target builds without cgo and selects `policy.evaluator: go`.
The Go evaluator runs AGT's policies without the OPA executable.

### Select the build and evaluator

| Command | Result |
| --- | --- |
| `make` or `make build` | Build every package with AGT and write the host binary. |
| `make run` | Build with AGT and start the reference configuration. |
| `make build EVALUATOR=go` | Build every package and the Guardian without cgo. |
| `make run EVALUATOR=go` | Build without cgo and start with the Go evaluator. |
| `make test` | Run every test with AGT and the race detector. |
| `make test EVALUATOR=go` | Run every test without cgo. |
| `make build GOOS=windows GOARCH=amd64` | Build a Windows binary with AGT and a compatible native toolchain. |
| `make image` | Build Linux amd64 and arm64 images into a local OCI archive. |

The build tag `agteval` includes the AGT evaluator. That build needs cgo and
links AGT's runtime library. The Go build omits the tag and uses `CGO_ENABLED=0`.

At startup, `policy.evaluator` selects `agt` or `go`. The environment variable
`ACS__POLICY__EVALUATOR` overrides that setting. The reference YAML selects `agt`.
A build without AGT refuses `agt`; it never substitutes the Go evaluator.
Selecting `go` in an AGT build still requires the linked AGT library.
Use `make build EVALUATOR=go` to remove that dependency.

## Use it as a Go library

```go
evaluator, err := agteval.New(agteval.Config{
    ManifestPath: "/opt/acs/policy/policy/manifest.yaml",
    OPAPath:      "/usr/local/bin/opa",
    OPATimeout:   5 * time.Second,
})
engine, err := agtbridge.New(os.DirFS("/opt/acs/policy"), "mapping.yaml",
    evaluator, agtbridge.Options{})
signer, err := guardian.NewHMACSigner(
    guardian.HMACKey{ID: "default", Secret: secret},
)
g, err := guardian.New(guardian.Config{
    Engine: engine,
    Signer: signer,
})
http.Handle("/acs", g)
```

- `agtbridge/agteval` requires cgo and the `agteval` build tag.
  Build every evaluator before the Guardian serves.
  `agteval.New` temporarily sets OPA configuration in the process environment.
  `goeval.New(ctx, os.DirFS("/opt/acs/policy"), "policy/manifest.yaml")` builds the Go evaluator.
  Importing `guardian` or `agtbridge` alone adds no native dependency.
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

`make setup` builds AGT's runtime library and downloads the pinned OPA executable.
The target downloads Go modules and installs the locked TypeScript conformance dependencies.
Codex and OpenCode are not required by the quality gate.

Then run:

```bash
make check
```

`make check` is the complete quality gate:

- Check formatting and module tidiness.
- Run `go vet` and Staticcheck with and without the `agteval` tag.
- Run `govulncheck`.
- Build every package with AGT and without cgo.
- Run every Go test without cgo.
- Run every Go test with the race detector, with and without AGT.
- Compare both evaluators on the recorded cases.
- Check the custom-engine module and OpenCode plugin callbacks.
- Run the shared ACS conformance checks against a live Guardian using AGT.
- Enforce the coverage floor and check documentation.

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
policy files remain under their MIT license. AGT's runtime library is built from
AGT's MIT-licensed source on your machine and is not part of this repository. The RFC 8785 vectors under
`internal/jcs/testdata/` come from the RFC author's reference implementation
under Apache License 2.0.
