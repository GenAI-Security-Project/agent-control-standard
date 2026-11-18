"""Structure guards for the FinBot lab's OPA policy pack (labs/finbot/policy, issue #585).

Stdlib only and no OPA, so the root suite catches a broken pack without the binary. Whether each starter and
solution passes or fails its tests exactly as tools/modules.json says is check_pack.py's job, which runs real OPA.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "labs" / "finbot" / "policy"
MANIFEST = PACK / "tools" / "modules.json"

# The A.10 reason codes, the only ones a module may emit.
REASON_CODES = {"tool_unregistered", "tool_content_hash_mismatch", "external_recipient", "payment_over_threshold",
                "sensitive_field_redacted", "egress_blocked"}
# Builtins that reach the network or the OPA runtime. A policy that calls one can stall past ACS_OPA_TIMEOUT_MS or
# read the server's configuration.
NETWORK_BUILTINS = ("http.send", "net.lookup_ip_addr", "opa.runtime", "net.cidr_expand")
# RFC 2606 and RFC 6761 names, plus FinBot's own internal .finbot mailboxes.
RESERVED_SUFFIXES = (".example", ".finbot", ".test", ".invalid", ".localhost", "example.com", "example.net",
                     "example.org")
ADDRESS_OR_HOST = re.compile(r"[A-Za-z0-9_.+-]+@([A-Za-z0-9_.-]+)|[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@\\]*@)?([^/?#:\\]+)")


def manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def modules() -> list[dict]:
    return [m for m in manifest()["modules"] if "live" in m]


def policy_files() -> list[Path]:
    return sorted(PACK.rglob("*.rego"))


def test_live_files_equal_their_starters() -> None:
    differ = [m["live"] for m in modules()
              if (PACK / m["live"]).read_bytes() != (PACK / m["variants"]["starter"]["file"]).read_bytes()]
    assert not differ, f"live module files differ from their starters: {differ}"


def test_every_manifest_file_exists() -> None:
    missing = []
    for module in manifest()["modules"]:
        paths = [module.get("live")] + [v.get(key) for v in module["variants"].values()
                                        for key in ("file", "data_patch")]
        missing += [p for p in paths if p and not (PACK / p).is_file()]
    assert not missing, f"the manifest names files that don't exist: {missing}"


def test_every_module_has_a_solution_with_no_failures() -> None:
    for module in manifest()["modules"]:
        assert module["variants"]["solution"]["fails"] == [], module["id"]


def test_every_starter_fails_at_least_one_test() -> None:
    for module in modules():
        fails = module["variants"]["starter"]["fails"]
        assert fails, module["id"]
        # Each named test exists in the module's test file, so the guides never quote a test that is gone.
        tests = (PACK / "tests" / f"{module['id']}_test.rego").read_text()
        assert all(re.search(rf"^{name} if \{{", tests, re.M) for name in fails), module["id"]


def test_no_policy_file_uses_network_builtins() -> None:
    used = [(path.relative_to(PACK).as_posix(), b) for path in policy_files() for b in NETWORK_BUILTINS
            if b in path.read_text()]
    assert not used, f"policy files call network or runtime builtins: {used}"


def test_inputs_use_reserved_domains() -> None:
    inputs = sorted((PACK / "tools" / "inputs").glob("*.json"))
    assert inputs
    for path in inputs:
        for match in ADDRESS_OR_HOST.finditer(path.read_text()):
            host = (match.group(1) or match.group(2)).lower()
            assert host.endswith(RESERVED_SUFFIXES), f"{path.name} names {host}, which isn't a reserved domain"


def test_modules_emit_only_a10_reason_codes() -> None:
    emitted = {code for path in policy_files() if "tests" not in path.parts
               for code in re.findall(r'deny_codes contains "([a-z_]+)"', path.read_text())}
    assert emitted <= REASON_CODES, emitted - REASON_CODES


@pytest.mark.parametrize("module_id", ["m3", "m4", "m5", "m6"])
def test_variants_share_the_finbot_package(module_id: str) -> None:
    module = next(m for m in modules() if m["id"] == module_id)
    for variant in module["variants"].values():
        assert (PACK / variant["file"]).read_text().count("\npackage finbot\n") == 1, variant["file"]


def test_data_json_holds_the_wp6_keys() -> None:
    data = json.loads((PACK / "data.json").read_text())
    assert set(data) == {"finbot_lab"}
    assert set(data["finbot_lab"]) == {"tools", "vendor_domains", "payment_ask_threshold", "egress_allow"}
    assert data["finbot_lab"]["payment_ask_threshold"] == 5000
