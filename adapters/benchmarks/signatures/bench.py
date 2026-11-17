"""Measure signature size, public key size, sign time and verify time (issue #583).

Run from adapters/:  uv run --extra pqc python -m benchmarks.signatures
Results go to a temporary directory. --update-reference rewrites the committed ones.

Every timed call goes through the library an adapter runs. HMAC-SHA256 uses sign_with_key and
verify_with_key. ML-DSA-65 uses sign_with_signing_key and verify_with_keyring. Both
canonicalize the envelope with JCS, encode the signature in base64 and attach or decode it inside
the call. ECDSA-P256 is a benchmark primitive that no envelope function signs with
(acs.core._ecdsa, lab convention, settled by PR #564 and issue #532), so sign_ecdsa_envelope and
verify_ecdsa_envelope do that same envelope-level work around the raw ECDSA call, and the three
timed regions match.

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
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as _openssl_backend

from acs.core import (
    Keyring,
    container_key,
    MLDSA65SigningKey,
    request_envelope,
    sign_with_key,
    sign_with_signing_key,
    signing_input,
    verify_with_key,
    verify_with_keyring,
)
from acs.core._signing import decode_signature_value
from acs.core._ecdsa import (
    ecdsa_p256_generate,
    ecdsa_p256_public_bytes,
    ecdsa_p256_sign,
    ecdsa_p256_verify,
)

DEFAULT_ITERATIONS = 1000
DEFAULT_WARMUP = 100
NOT_MEASURED = {"hybrid": "acs.core has no hybrid signature yet (PR #564 would settle its form)"}
_KEY_ID = "bench-key-1"
_HERE = Path(__file__).resolve().parent
# The committed numbers the docs page quotes. Only --update-reference writes here.
REFERENCE_DIR = _HERE / "results"


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


def sign_ecdsa_envelope(envelope: dict, key, *, key_id: str) -> dict:
    """Sign in place the way sign_with_key does: canonicalize, sign, base64 and attach.

    The library has no ECDSA envelope function (lab convention, see the module docstring), so
    this does the same envelope-level work the HMAC and ML-DSA calls do, and the three timed
    regions match.
    """
    signature = ecdsa_p256_sign(key, signing_input(envelope))
    container_name = container_key(envelope)
    container = envelope.setdefault(container_name, {})
    container["signature"] = {"algorithm": "ECDSA-P256",
                              "value": base64.b64encode(signature).decode("ascii"),
                              "key_id": key_id}
    return envelope


def verify_ecdsa_envelope(envelope: dict, public_key: bytes) -> bool:
    """Verify the way verify_with_key does: read the signature object, decode it, check it."""
    container = envelope.get(container_key(envelope))
    if not isinstance(container, dict):
        return False
    sig = container.get("signature")
    if not isinstance(sig, dict) or sig.get("algorithm") != "ECDSA-P256":
        return False
    signature = decode_signature_value(sig.get("value"))
    if signature is None:
        return False
    return ecdsa_p256_verify(public_key, signing_input(envelope), signature)


def _signature_bytes(envelope: dict) -> int:
    return len(base64.b64decode(envelope[container_key(envelope)]["signature"]["value"]))


def _signed_size(envelope: dict) -> int:
    return len(json.dumps(envelope, separators=(",", ":")).encode())


def _signatures(iterations: int, warmup: int):
    request, response = _workload()
    hmac_key = os.urandom(32)
    mldsa_key = MLDSA65SigningKey.generate(_KEY_ID)
    keyring = Keyring([mldsa_key.verification_key()])
    ec_key = ecdsa_p256_generate()
    ec_public = ecdsa_p256_public_bytes(ec_key)

    signed_hmac = sign_with_key(copy.deepcopy(response), hmac_key, key_id=_KEY_ID)
    signed_mldsa = sign_with_signing_key(copy.deepcopy(response), mldsa_key)
    signed_ec = sign_ecdsa_envelope(copy.deepcopy(response), ec_key, key_id=_KEY_ID)

    # A benchmark of a broken verify would still print numbers, so check each path first.
    assert verify_with_key(signed_hmac, hmac_key)
    assert verify_with_keyring(signed_mldsa, keyring, expected_key_id=_KEY_ID, request=request)
    assert verify_ecdsa_envelope(signed_ec, ec_public)

    # Each sign call gets a fresh copy made outside the timed region, since signing mutates it.
    def sign_timed(sign):
        def run():
            envelope = copy.deepcopy(response)
            start = time.perf_counter_ns()
            sign(envelope)
            return time.perf_counter_ns() - start
        return run

    cases = [
        ("HMAC-SHA256", signed_hmac, len(hmac_key),
         lambda e: sign_with_key(e, hmac_key, key_id=_KEY_ID),
         lambda: verify_with_key(signed_hmac, hmac_key)),
        ("ML-DSA-65", signed_mldsa, len(mldsa_key.verification_key().public_key),
         lambda e: sign_with_signing_key(e, mldsa_key),
         lambda: verify_with_keyring(signed_mldsa, keyring, expected_key_id=_KEY_ID, request=request)),
        ("ECDSA-P256", signed_ec, len(ec_public),
         lambda e: sign_ecdsa_envelope(e, ec_key, key_id=_KEY_ID),
         lambda: verify_ecdsa_envelope(signed_ec, ec_public)),
    ]
    for name, signed, pub_bytes, sign, verify in cases:
        sign_median, sign_p95 = _time(sign_timed(sign), iterations, warmup)
        verify_median, verify_p95 = _time(_timed(verify), iterations, warmup)
        yield {"algorithm": name, "signature_bytes": _signature_bytes(signed),
               "public_key_bytes": pub_bytes, "envelope_bytes": _signed_size(signed),
               "sign_median_us": sign_median, "sign_p95_us": sign_p95,
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


def core_source_sha256() -> str:
    """SHA-256 over the acs.core source files, by relative path and bytes, in sorted order."""
    import acs.core
    root = Path(acs.core.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def environment(iterations: int, warmup: int) -> dict:
    return {
        "machine": f"{_cpu_model()} ({platform.machine()}, {os.cpu_count()} logical CPUs)",
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": _openssl_backend.openssl_version_text(),
        "source_sha256": core_source_sha256(),
        "acs_adapters": importlib.metadata.version("acs-adapters"),
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


_ENVIRONMENT_LABELS = (
    ("machine", "Machine"), ("os", "OS"), ("python", "Python"), ("cryptography", "cryptography"),
    ("openssl", "OpenSSL"), ("acs_adapters", "acs-adapters"),
    ("source_sha256", "SHA-256 of the acs.core source"),
    ("date", "Date"), ("warmup", "Warm-up calls"), ("iterations", "Timed calls"),
)


def environment_markdown(result: dict) -> str:
    env = result["environment"]
    lines = ["| Item | Value |", "|---|---|"]
    lines += [f"| {label} | {env[key]} |" for key, label in _ENVIRONMENT_LABELS]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.signatures", description=__doc__.split("\n")[0])
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--out-dir", type=Path, default=None,
                        help="where to write results (default: a new temporary directory)")
    where.add_argument("--update-reference", action="store_true",
                        help="write the committed reference results the docs page quotes")
    args = parser.parse_args(argv)
    result = run(args.iterations, args.warmup)
    if args.update_reference:
        out_dir = REFERENCE_DIR
    else:
        out_dir = args.out_dir or Path(tempfile.mkdtemp(prefix="acs-signature-benchmark-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    table = to_markdown(result)
    (out_dir / "results.md").write_text(table)
    (out_dir / "environment.md").write_text(environment_markdown(result))
    print(table)
    print(f"Wrote results.json, results.md and environment.md to {out_dir}")
    return 0
