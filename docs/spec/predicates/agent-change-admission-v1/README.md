# agent-change-admission-v1 — conformance vectors

Companion to [`agent-change-admission-v1.md`](../agent-change-admission-v1.md).

```bash
pip install cryptography
python3 check_admission.py          # runs all 23 vectors, exit 0 == all pass
python3 check_admission.py --emit-examples   # regenerate examples/
```

Each rejection reason code in the spec is locked by at least one negative vector (N1–N20);
P1–P3 are the positive paths. `vector_results.json` is the recorded result of the run above.

Keys are generated in-process by the harness; nothing here is a real credential.
