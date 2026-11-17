# Signature Benchmark

ML-DSA-65 signatures are about 100 times larger than HMAC-SHA256 tags and take far longer to produce. They still cost well under a millisecond on a laptop. This page gives the numbers and says what they do not tell you.

## Results

One run on the machine below. Times are microseconds per call.

| Algorithm | Signature (bytes) | Public key (bytes) | Signed envelope (bytes) | Sign median | Sign p95 | Verify median | Verify p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| HMAC-SHA256 | 32 | 32 | 366 | 8.6 | 9.0 | 8.6 | 9.1 |
| ML-DSA-65 | 3,309 | 1,952 | 4,732 | 369.3 | 1,120.7 | 104.7 | 119.8 |
| ECDSA-P256 | 64 | 65 | 409 | 24.4 | 28.3 | 59.9 | 69.8 |

The hybrid is missing. The reference library has no hybrid signing on this branch, and the composite ML-DSA work in PR #564 would settle its form. A hybrid would cost roughly the sum of its two parts plus a longer signature, but that is an estimate, not a measurement.

HMAC-SHA256 has no public key. Its "public key" column is the 32 byte shared secret, which both sides must hold.

## Machine and versions

| Item | Value |
|---|---|
| Machine | Apple M3 Max (arm64, 16 logical CPUs) |
| OS | Darwin 25.5.0 |
| Python | 3.13.7 |
| cryptography | 50.0.2 |
| OpenSSL | OpenSSL 4.0.3 29 Sep 2026 |
| Commit | 76f09396b6b86c2da1fd58ff51000697245b27cb |
| Date | 2026-11-17 |

## Method

The benchmark signs a Guardian decision response to a `steps/toolCallRequest` step. The request carries a payment tool call with a few arguments, and the response is an `allow` decision with reason codes. The envelope is canonicalized with RFC 8785 (JCS) on every call, as an adapter does.

Each algorithm runs through the library calls an adapter uses. HMAC-SHA256 uses `sign_with_key` and `verify_with_key`. ML-DSA-65 uses `sign_with_signing_key` and `verify_with_keyring`. ECDSA-P256 is a benchmark primitive that no envelope function signs with, so its timed region adds `signing_input` to match the canonicalization the other two do inside their calls.

Each run makes 100 warm-up calls and then times 1,000 calls with `time.perf_counter_ns`. The table reports the median and the 95th percentile. A signing call gets a fresh copy of the envelope, made before the clock starts.

Signed envelope size is the compact JSON of the response with its signature, in bytes.

To rerun it, install the `pqc` extra and run this from `adapters/`:

```bash
uv run --extra pqc python -m benchmarks.signatures
```

The command prints the table and writes `results.json` and `results.md` under `adapters/benchmarks/signatures/results/`. The JSON file records the machine, versions, commit and date shown above.

## What the numbers mean

They show cost per signature on one laptop under normal load. Use them to compare algorithms and to judge whether a signature fits your latency budget.

They do not predict your deployment. A container on a shared x86 host will differ, and the gap between algorithms can move with the CPU and the OpenSSL build. Run the command on the hardware you care about.

ML-DSA-65 signing is slower at the tail. Its p95 is about three times its median because signing retries internally until it finds an acceptable signature. Budget for the p95, not the median.

ML-DSA-65 verifies faster than it signs, and ECDSA-P256 does the opposite. A Guardian that signs every decision and an agent that verifies every decision therefore pay different costs.

The timings cover signing and verification only. They leave out network time, policy evaluation, and key loading. ML-DSA-65 verification through the keyring also checks that the response answers its request before any crypto, which the HMAC and ECDSA rows do not include. That check costs little next to the crypto.

The benchmark does not test security. It also says nothing about which algorithm to choose, which D-047 and issue #532 decide on other grounds.
