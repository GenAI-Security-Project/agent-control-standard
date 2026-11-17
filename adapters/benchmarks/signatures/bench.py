"""Measure signature size, public key size, sign time and verify time (issue #583).

Run from adapters/:  uv run --extra pqc python -m benchmarks.signatures

Every timed call goes through the library an adapter runs. HMAC-SHA256 uses sign_with_key and
verify_with_key. ML-DSA-65 uses sign_with_signing_key and verify_with_keyring. Both
canonicalize the envelope with JCS inside the call. ECDSA-P256 is a benchmark primitive that no
envelope function signs with (acs.core._ecdsa, lab convention, settled by PR #564 and issue #532),
so its timed region adds signing_input() to match what the other two do internally.

The signed message is the Guardian's decision response to a toolCallRequest step, since that is
the message ML-DSA signs in the lab. Verification through the keyring also checks the response
against its request before any crypto, as an adapter does. That check is cheap next to the
crypto, and it is part of the ML-DSA verify number but not the HMAC or ECDSA one.

There is no hybrid in acs.core, so none is measured. Timings are wall clock on a machine that
does other work, so read them as orders of magnitude, not as a ranking to the microsecond.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime
import json
import math
import os
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as _openssl_backend

from acs.core import (
    Keyring,
    MLDSA65SigningKey,
    request_envelope,
    sign_with_key,
    sign_with_signing_key,
    signing_input,
    verify_with_key,
    verify_with_keyring,
)
from acs.core._ecdsa import (
    ecdsa_p256_generate,
    ecdsa_p256_public_bytes,
    ecdsa_p256_sign,
    ecdsa_p256_verify,
)

DEFAULT_ITERATIONS = 1000
DEFAULT_WARMUP = 100
NOT_MEASURED = {"hybrid": "acs.core has no hybrid signing on this branch (PR #564 would settle it)"}
_KEY_ID = "bench-key-1"
_HERE = Path(__file__).resolve().parent


def _workload() -> tuple[dict, dict]:
    """A realistic toolCallRequest and the Guardian's signed-over decision response to it."""
    request_id = str(uuid.uuid4())
    request = request_envelope(
        "steps/toolCallRequest", request_id=request_id,
        metadata={"session_id": str(uuid.uuid4()), "agent_id": "finbot", "turn_id": str(uuid.uuid4())},
        payload={"tool_name": "payments__send_payment", "tool_arguments": {
            "vendor_id": "v-1042", "amount": 1850.75, "currency": "USD",
            "memo": "Invoice 2026-1187, net 30", "bank_account_number": "000123456789"}})
    response = {"jsonrpc": "2.0", "id": request["id"],
                "result": {"acs_version": "0.1.0", "request_id": request_id, "decision": "allow",
                           "reason_codes": ["policy_allow"],
                           "reason": "payment is under the approval threshold"}}
    return request, response


def _percentile(sorted_ns: list[int], q: float) -> float:
    # Nearest rank, so every reported value is a sample that happened.
    index = max(0, math.ceil(q * len(sorted_ns)) - 1)
    return sorted_ns[index] / 1000.0


def _time(fn, iterations: int, warmup: int) -> tuple[float, float]:
    """Median and p95 in microseconds of fn(), which returns its own elapsed nanoseconds."""
    for _ in range(warmup):
        fn()
    samples = sorted(fn() for _ in range(iterations))
    return _percentile(samples, 0.50), _percentile(samples, 0.95)


def _timed(call):
    def run() -> int:
        start = time.perf_counter_ns()
        call()
        return time.perf_counter_ns() - start
    return run


def _signatures(iterations: int, warmup: int):
    request, response = _workload()
    hmac_key = os.urandom(32)
    mldsa_key = MLDSA65SigningKey.generate(_KEY_ID)
    keyring = Keyring([mldsa_key.verification_key()])
    ec_key = ecdsa_p256_generate()
    ec_public = ecdsa_p256_public_bytes(ec_key)

    signed_hmac = sign_with_key(copy.deepcopy(response), hmac_key, key_id=_KEY_ID)
    signed_mldsa = sign_with_signing_key(copy.deepcopy(response), mldsa_key)
    ec_message = signing_input(response)
    ec_signature = ecdsa_p256_sign(ec_key, ec_message)

    # A benchmark of a broken verify would still print numbers, so check each path first.
    assert verify_with_key(signed_hmac, hmac_key)
    assert verify_with_keyring(signed_mldsa, keyring, expected_key_id=_KEY_ID, request=request)
    assert ecdsa_p256_verify(ec_public, ec_message, ec_signature)

    def size(envelope: dict) -> int:
        return len(json.dumps(envelope, separators=(",", ":")).encode())

    ec_envelope = copy.deepcopy(response)
    ec_envelope["result"]["signature"] = {"algorithm": "ECDSA-P256", "key_id": _KEY_ID,
                                          "value": base64.b64encode(ec_signature).decode()}
    # Each sign call gets a fresh copy made outside the timed region, since signing mutates it.
    def sign_timed(sign):
        def run():
            envelope = copy.deepcopy(response)
            start = time.perf_counter_ns()
            sign(envelope)
            return time.perf_counter_ns() - start
        return run

    cases = [
        ("HMAC-SHA256", 32, len(hmac_key), size(signed_hmac),
         lambda e: sign_with_key(e, hmac_key, key_id=_KEY_ID),
         lambda: verify_with_key(signed_hmac, hmac_key)),
        ("ML-DSA-65", len(base64.b64decode(signed_mldsa['result']['signature']['value'])), len(mldsa_key.verification_key().public_key),
         size(signed_mldsa),
         lambda e: sign_with_signing_key(e, mldsa_key),
         lambda: verify_with_keyring(signed_mldsa, keyring, expected_key_id=_KEY_ID, request=request)),
        ("ECDSA-P256", len(ec_signature), len(ec_public), size(ec_envelope),
         lambda e: ecdsa_p256_sign(ec_key, signing_input(e)),
         lambda: ecdsa_p256_verify(ec_public, signing_input(ec_envelope), ec_signature)),
    ]
    for name, sig_bytes, pub_bytes, env_bytes, sign, verify in cases:
        sign_median, sign_p95 = _time(sign_timed(sign), iterations, warmup)
        verify_median, verify_p95 = _time(_timed(verify), iterations, warmup)
        yield {"algorithm": name, "signature_bytes": sig_bytes, "public_key_bytes": pub_bytes,
               "envelope_bytes": env_bytes, "sign_median_us": sign_median, "sign_p95_us": sign_p95,
               "verify_median_us": verify_median, "verify_p95_us": verify_p95}


def _cpu_model() -> str:
    try:
        if sys.platform == "darwin":
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                  text=True, check=True).stdout.strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return platform.processor() or "unknown"


def _commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, cwd=_HERE).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def environment(iterations: int, warmup: int) -> dict:
    return {
        "machine": f"{_cpu_model()} ({platform.machine()}, {os.cpu_count()} logical CPUs)",
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": _openssl_backend.openssl_version_text(),
        "commit": _commit(),
        "date": datetime.date.today().isoformat(),
        "iterations": iterations,
        "warmup": warmup,
    }


def run(iterations: int = DEFAULT_ITERATIONS, warmup: int = DEFAULT_WARMUP) -> dict:
    if iterations < 1 or warmup < 0:
        raise ValueError("iterations must be at least 1 and warmup at least 0")
    return {"environment": environment(iterations, warmup),
            "rows": list(_signatures(iterations, warmup)),
            "not_measured": dict(NOT_MEASURED)}


def to_markdown(result: dict) -> str:
    lines = ["| Algorithm | Signature (bytes) | Public key (bytes) | Signed envelope (bytes) | "
             "Sign median (us) | Sign p95 (us) | Verify median (us) | Verify p95 (us) |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for r in result["rows"]:
        lines.append(f"| {r['algorithm']} | {r['signature_bytes']:,} | {r['public_key_bytes']:,} | "
                     f"{r['envelope_bytes']:,} | {r['sign_median_us']:.1f} | {r['sign_p95_us']:.1f} | "
                     f"{r['verify_median_us']:.1f} | {r['verify_p95_us']:.1f} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.signatures", description=__doc__.split("\n")[0])
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--out-dir", type=Path, default=_HERE / "results")
    args = parser.parse_args(argv)
    result = run(args.iterations, args.warmup)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    table = to_markdown(result)
    (args.out_dir / "results.md").write_text(table)
    print(table)
    return 0
