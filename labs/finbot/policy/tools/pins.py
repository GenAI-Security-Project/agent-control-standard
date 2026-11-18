"""Build the policy pack's tool registry from the gateway's model input log.

Each line of the log (ACS_GATEWAY_MODEL_INPUT_LOG) is one request body the gateway forwarded upstream. Every
function tool a body declares is pinned under its name with the digest the gateway sends as tool.version, computed
by the gateway's own ToolDigests, so the policy and the gateway can never hash a declaration two ways. The digest
in tool.version is a lab convention until issue #38 settles how a tool call binds to its declaration.

A name gets one digest per distinct declaration across the log, since FinBot's agents declare some tools, such as
get_vendor_details, more than once with different descriptions. A name declared twice in one body has no digest
at the gateway, so it stops the build rather than pinning a tool every step of it would deny.

Usage, from the gateway's environment:

    uv run --project adapters/gateway --locked python labs/finbot/policy/tools/pins.py \\
        --model-log <model-inputs.jsonl> --data labs/finbot/policy/data.json

Exit 0 when data.json was written, 2 on an unreadable log or data file or a declaration the gateway can't digest.
Owner: the ACS lab maintainers (issue #585).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from acs_gateway.tool_digest import ToolDigests

__version__ = "1.0.0"


class PinsError(ValueError):
    """The log can't produce a registry the gateway would match."""


def _declared_names(body: dict[str, Any]) -> list[str]:
    # The same filter ToolDigests applies, so a name is pinned exactly when the gateway would digest it.
    tools = body.get("tools")
    return [tool["name"] for tool in (tools if isinstance(tools, list) else [])
            if isinstance(tool, dict) and tool.get("type") == "function"
            and isinstance(tool.get("name"), str) and tool["name"]]


def build_pins(bodies: Iterable[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    """{"<name>": {"digests": [sorted digests]}} for every function tool the bodies declare."""
    found: dict[str, set[str]] = {}
    for number, body in enumerate(bodies, start=1):
        if not isinstance(body, dict):
            raise PinsError(f"body {number} is not a JSON object")
        skipped: list[str] = []
        digests = ToolDigests(body, on_skip=lambda name, _reason: skipped.append(name))
        if digests.repeated is not None:
            raise PinsError(f"body {number} declares {digests.repeated} more than once, so the gateway gives it no "
                            "digest and every step of it would deny")
        for name in _declared_names(body):
            digest = digests.get(name)
            if digest is None:
                cause = "RFC 8785 can't encode its declaration" if name in skipped else "it has no digest"
                raise PinsError(f"body {number} declares {name}, but {cause}")
            found.setdefault(name, set()).add(digest)
    return {name: {"digests": sorted(values)} for name, values in sorted(found.items())}


def write_tools(data_path: Path, pins: dict[str, dict[str, list[str]]]) -> None:
    """Replace finbot_lab.tools in data_path and keep every other key.

    The file is replaced in one rename, so OPA's --watch never loads half of it.
    """
    data = json.loads(data_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("finbot_lab"), dict):
        raise PinsError(f"{data_path} has no finbot_lab object")
    data["finbot_lab"]["tools"] = pins
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    fd, temporary = tempfile.mkstemp(dir=data_path.parent, prefix=".data.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(temporary, 0o644)
        os.replace(temporary, data_path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _read_log(path: Path) -> list[dict[str, Any]]:
    bodies = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            bodies.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise PinsError(f"{path} line {number} is not JSON: {e.msg}") from None
    return bodies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin FinBot's tool declarations into the policy pack's data.json.")
    parser.add_argument("--model-log", type=Path, required=True, help="the gateway's model input log (JSONL)")
    parser.add_argument("--data", type=Path, required=True, help="the policy pack's data.json")
    args = parser.parse_args(argv)
    try:
        pins = build_pins(_read_log(args.model_log))
        write_tools(args.data, pins)
    except (PinsError, OSError, ValueError) as e:
        print(f"pins: {e}", file=sys.stderr)
        return 2
    print(f"pins: wrote {len(pins)} tools to {args.data}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
