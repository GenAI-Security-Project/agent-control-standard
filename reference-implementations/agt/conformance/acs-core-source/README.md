# Probity Vectors

Test an agent-evidence verifier against saved records with known outcomes. The corpora cover valid records, altered bytes, missing evidence and open specification interpretations.

<a name="run-the-suite-against-your-verifier"></a>

## Try it

Install the Go verifier from the source tag, then run the harness from the same source commit. You need Go 1.24+, Python 3.13+ and [uv](https://docs.astral.sh/uv/), with Go's executable directory on your PATH.

```bash
go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.17.0
uvx --from git+https://github.com/probityai/agent-evidence-vectors@906dca103e2fe2e1e719dc58f8337b1b90b6562d agent-evidence-vectors --verifier "aee-verify --json"
```

Open `conformance-report.json` for the per-vector results. A complete external run has `rail: external`, `verifier.vectorsExecuted` equal to `totals.vectors`, and zero `totals.suiteRefusals`. The report separates conformance from reason-code agreement.

See [installation routes and release identity](DISTRIBUTION.md) for package availability and signature checks.

<a name="what-a-conformance-claim-must-show"></a>
<a name="the-verification-pipeline"></a>
<a name="the-failure-code-contract"></a>
<a name="what-the-suite-compares"></a>
<a name="two-layers-one-set-of-bytes-statementlayer"></a>
<a name="the-registry"></a>
<a name="indeterminate-vectors"></a>

## Test your verifier

The harness calls your executable with a vector-file path. Return a verdict through the exit status and a JSON object on the last line of stdout. The [verifier contract](docs/reference/verifier-contract.md) covers output fields, key policy and comparison rules.

Use the [GitHub Action](action.yml) to run the same check in your build and retain its report. The [CI guide](docs/guides/runner.md) gives a workflow step and the available inputs.

## Choose your next step

| I want to | Read |
| --- | --- |
| Pick a format and corpus | [Corpus guide](docs/guides/corpora.md) |
| Implement the verifier interface | [Verifier contract](docs/reference/verifier-contract.md) |
| Understand what the fixtures test | [Corpus measurements](docs/research/corpus-measurements.md) |
| Compare descriptor and decision IDs | [GovOps ID profile](interop/govops-capability-id/README.md) |
| Check frozen execution boundaries | [REMORA boundary readers](interop/remora-boundary-readers/README.md) |
| Find outside implementation results | [Run ledger](RUNS.md) and [independence record](docs/research/independence.md) |
| Check release bytes and signatures | [Release verification](docs/reference/release-verification.md) |
| Report a run or disagreement | [Run reporting](docs/guides/report-run.md) |

<a name="what-the-suite-judges"></a>
<a name="one-harness-judges-every-corpus-here"></a>

Each corpus manifest records its source revision, digest and expected outcomes. [DISTRIBUTION.md](DISTRIBUTION.md) lists the shipped corpora and installation routes.

<a name="conformance-vectors"></a>
<a name="what-the-corpus-forces-as-a-measured-number"></a>
<a name="detector-liveness-and-the-anchor-beside-every-refusal"></a>
<a name="condition-ids"></a>
<a name="used-by"></a>
<a name="on-independence"></a>
<a name="verify-a-release-without-trusting-us"></a>

For fixture coverage, see [Corpus measurements](docs/research/corpus-measurements.md). For outside results, see [External records](docs/research/external-records.md). To check signed release bytes, use [Release verification](docs/reference/release-verification.md).

<a name="layout"></a>
<a name="the-go-witness-attestor-witnessattestor"></a>

Source maps: [repository layout](docs/reference/layout.md), [corpus readers](docs/reference/corpus-readers.md) and [witness attestor](docs/reference/witness-attestor.md).

<a name="how-this-suite-is-maintained"></a>
<a name="arriving-from-somewhere-else"></a>
<a name="cite-this"></a>

## Contribute

[Open an issue](https://github.com/probityai/agent-evidence-vectors/issues/new) with the corpus revision, verifier build and report. For patches, start with [CONTRIBUTING.md](CONTRIBUTING.md). For citations, use the [citation guide](docs/reference/citing.md).

Need to check a supplied claim against saved evidence? See [Probity Verify](https://github.com/probityai/probity-verify). Browse the [Probity projects](https://github.com/probityai) for records, vocabulary and admission tools.

Apache-2.0. [LICENSE](LICENSE).
