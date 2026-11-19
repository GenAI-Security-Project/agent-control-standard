"""Guards that every reference implementation pins the exact AGT commit, SDK/crate version,
and OPA version declared in `reference-implementations/agt/agt.lock`."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGT_DIR = ROOT / "reference-implementations" / "agt"
AGT_GO_DIR = ROOT / "reference-implementations" / "agt-go"
AGT_LOCK = AGT_DIR / "agt.lock"
AGT_NATIVE_LOCK = AGT_GO_DIR / "agt-native.lock"
TS_CASES_JSON = AGT_GO_DIR / "agtbridge" / "testdata" / "ts-cases.json"

TS_PACKAGE_MANIFESTS = (
    AGT_DIR / "package.json",
    AGT_DIR / "packages" / "agt-bridge" / "package.json",
    AGT_DIR / "packages" / "conformance" / "package.json",
)

COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _git_blob_sha1(path: Path) -> str:
    raw = path.read_bytes()
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def validate_agt_pin_sync(
    agt_lock: dict,
    native_lock: dict,
    ts_manifests: dict[str, dict],
) -> list[str]:
    """Return any drift between `agt.lock`, `agt-native.lock`, and TypeScript package manifests."""
    violations: list[str] = []

    agt_repo = agt_lock.get("agt_repo", "")
    agt_ref = agt_lock.get("agt_ref", "")
    opa_version = agt_lock.get("opa_version", "")
    sdk_package = agt_lock.get("sdk_package", "")
    sdk_version = agt_lock.get("sdk_version", "")

    if not agt_repo:
        violations.append("agt.lock is missing agt_repo")
    if not COMMIT_SHA_RE.match(str(agt_ref)):
        violations.append(f"agt.lock agt_ref {agt_ref!r} is not a 40-char lowercase hex SHA")
    if not SEMVER_RE.match(str(opa_version)):
        violations.append(f"agt.lock opa_version {opa_version!r} is not a valid semver string")
    if not sdk_package or not sdk_version:
        violations.append("agt.lock is missing sdk_package or sdk_version")

    if native_lock.get("agt_repo") != agt_repo:
        violations.append(
            f"agt-native.lock agt_repo {native_lock.get('agt_repo')!r} != agt.lock {agt_repo!r}"
        )
    if native_lock.get("agt_ref") != agt_ref:
        violations.append(
            f"agt-native.lock agt_ref {native_lock.get('agt_ref')!r} != agt.lock {agt_ref!r}"
        )
    if native_lock.get("opa_version") != opa_version:
        violations.append(
            f"agt-native.lock opa_version {native_lock.get('opa_version')!r} != agt.lock {opa_version!r}"
        )
    if native_lock.get("crate_version") != sdk_version:
        violations.append(
            f"agt-native.lock crate_version {native_lock.get('crate_version')!r} != agt.lock sdk_version {sdk_version!r}"
        )

    for label, pkg in ts_manifests.items():
        deps = pkg.get("dependencies") or {}
        dev_deps = pkg.get("devDependencies") or {}
        raw_ver = deps.get(sdk_package) or dev_deps.get(sdk_package)
        if not raw_ver:
            violations.append(f"{label} does not declare a dependency on {sdk_package!r}")
            continue
        cleaned = re.sub(r"^[^0-9]*", "", str(raw_ver))
        if cleaned != sdk_version:
            violations.append(
                f"{label} pins {sdk_package}@{cleaned!r}, expected {sdk_version!r} from agt.lock"
            )

    return violations


def test_agt_lock_and_implementations_stay_in_sync():
    agt_lock = _load_json(AGT_LOCK)
    native_lock = _load_json(AGT_NATIVE_LOCK)
    ts_manifests = {
        str(path.relative_to(ROOT)): _load_json(path)
        for path in TS_PACKAGE_MANIFESTS
    }
    violations = validate_agt_pin_sync(agt_lock, native_lock, ts_manifests)
    assert not violations, "AGT pin drift detected:\n" + "\n".join(violations)


def test_ts_cases_recording_tracks_agt_lock_blob():
    recording = _load_json(TS_CASES_JSON)
    recorded_blob = recording.get("ts_trees", {}).get("agt.lock")
    actual_blob = _git_blob_sha1(AGT_LOCK)
    assert recorded_blob == actual_blob, (
        f"ts-cases.json records agt.lock blob {recorded_blob!r}, "
        f"but reference-implementations/agt/agt.lock hashes to {actual_blob!r}"
    )


def test_validate_agt_pin_sync_rejects_drift():
    agt_lock = _load_json(AGT_LOCK)
    native_lock = _load_json(AGT_NATIVE_LOCK)
    ts_manifests = {
        str(path.relative_to(ROOT)): _load_json(path)
        for path in TS_PACKAGE_MANIFESTS
    }

    drifted_ref = {**native_lock, "agt_ref": "0" * 40}
    assert any("agt_ref" in v for v in validate_agt_pin_sync(agt_lock, drifted_ref, ts_manifests))

    drifted_opa = {**native_lock, "opa_version": "0.69.0"}
    assert any("opa_version" in v for v in validate_agt_pin_sync(agt_lock, drifted_opa, ts_manifests))

    drifted_crate = {**native_lock, "crate_version": "0.2.0"}
    assert any("crate_version" in v for v in validate_agt_pin_sync(agt_lock, drifted_crate, ts_manifests))
