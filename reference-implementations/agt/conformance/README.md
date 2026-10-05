# Run the retained ACS-Core vectors

The reference Guardian report reads this repository's copy of `vectors-acs-core`.
No vectors package is installed. The ACS Spec workstream reviews changes here and
versions the suite with ACS releases, as decided in [#19](https://github.com/GenAI-Security-Project/agent-control-standard/issues/19).

The import preserves all 43 members from Vectors source
[`58bf482`](https://github.com/probityai/agent-evidence-vectors/tree/58bf482e9f07668e2a8f99e7e9a88609f58112fd/vectors-acs-core).
That source declares version 0.17.0: 15 accept, 26 reject and 2 indeterminate inputs.
`acs-core-source.json` records the original Git blobs and SHA-256 digests.
`acs-core-source/` retains the original license, project metadata and README.
Attribution is also in the repository's `NOTICE`.

From `reference-implementations/agt`, start the Guardian with `bun run guardian`.
Then run:

```sh
python3 scripts/check-acs-core-vendor.py
python3 scripts/run-acs-core-vectors.py \
  --vectors conformance/vectors-acs-core \
  --guardian http://127.0.0.1:8787/acs \
  --out acs-core-results.jsonl --summary acs-core-summary.md
```

The runner also finds this copy when `--vectors` is omitted, regardless of the
current directory. Python 3.10 or later supplies everything the runner needs.
The original imported README describes the upstream corpus's own generator and
self-check commands; those commands are separate from this Guardian report.

Each input retains its original requirement, ID, expected verdict and context.
The four quoted specification files still bind to ACS `9d4a9da`, not today's
specification. `outOfScope` and `awaitingText` remain in the unchanged manifest.
The import makes no schema or verdict change and adds no `observedRuns` row.

The report keeps raw requests and tool-adapted requests separate. It records
unsupported subjects as `NOT RUN` and transport failures as unmeasured. Declared
input counts are not observed results. A failing member does not fail this
informational job; no answered request exits 2. The report does not certify full
ACS-Core deployment conformance, independent operation or host adoption.
