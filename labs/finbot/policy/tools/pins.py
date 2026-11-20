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

Only lines from clean, completed runs count. The scenario driver writes each run record with "model_input_span",
the log offsets from the run's setup to its end, and "poisoned", true when the run changed a tool's declaration (s6
without --clean). pins reads only the lines inside the span of a record that says result completed and poisoned false.
Each span opens before setup, so a tool declared only during setup keeps its pin. Every other line is ignored: a
poisoned run, a run killed before it wrote a record, FinBot traffic between runs, and a record from before the flag
existed, which can't show its run was clean. Pinning a changed declaration would put its digest beside the clean one,
and the module 6 policy would then allow the poisoned tool.

pins refuses rather than guess when a clean span shares lines with a run that isn't known to be clean, since offsets
alone can't tell the two runs' lines apart. It also refuses a span past the end of the log, a span that doesn't start
and end on a line boundary, an unreadable record or span, and a state with no clean completed run. The run records
are read from --runs, by default the runs directory beside the log, which is where the driver writes them.

Exit 0 when data.json was written. Exit 2, with data.json left unchanged and one line on stderr, on an unreadable log,
data file or run record, any refusal above, a log that pins no tools, or a declaration the gateway can't digest.
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

__version__ = "1.3.0"


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


CLEAN_RUN = "Run ./lab.sh mode off, then ./lab.sh run s6 --clean, then ./lab.sh pins"


def _offsets(value: Any) -> tuple[int, int] | None:
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value) and value[0] <= value[1]):
        return value[0], value[1]
    return None


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _on_lines(span: tuple[int, int], log: bytes) -> bool:
    """True when the span starts at 0 or after a newline, and ends after a newline or holds nothing."""
    start, end = span
    return ((start == 0 or log[start - 1:start] == b"\n")
            and (end == start or log[end - 1:end] == b"\n"))


def clean_spans(runs: Path, log: bytes) -> list[tuple[int, int]]:
    """The model input spans of clean, completed runs, refused when any of them can't be told apart from the rest."""
    log_size = len(log)
    clean: list[tuple[str, tuple[int, int]]] = []
    # Runs not known to be clean, with the lines they wrote, or None when the record doesn't say.
    unsure: list[tuple[str, tuple[int, int] | None]] = []
    for path in sorted(runs.glob("*.json")) if runs.is_dir() else []:
        if not path.is_file():
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise PinsError(f"run record {path.stem} can't be read ({e}), so its lines can't be told apart") from None
        if not isinstance(record, dict):
            raise PinsError(f"run record {path.stem} is not a JSON object")
        span = _offsets(record.get("model_input_span"))
        if "model_input_span" in record and span is None:
            raise PinsError(f"run record {path.stem} has a model_input_span that can't be read")
        # A record from before the span field still names the window it read, which bounds the lines it wrote.
        lines = span or _offsets(record.get("model_inputs"))
        if lines is not None and lines[1] > log_size:
            raise PinsError(f"run record {path.stem} names lines past the end of the model input log, so the log "
                            "changed under the run records")
        # A span cut inside a line would count half a request as the run's own, or leave out part of one.
        if span is not None and not _on_lines(span, log):
            raise PinsError(f"run record {path.stem} has a model_input_span that doesn't start and end on a line "
                            "boundary")
        if record.get("result") == "completed" and record.get("poisoned") is False:
            if span is None:
                raise PinsError(f"run record {path.stem} is a clean run with no model_input_span")
            clean.append((path.stem, span))
        elif record.get("poisoned") is not False:
            # A poisoned run, or one whose record can't say. A run marked clean that didn't complete changed no tool.
            unsure.append((path.stem, lines))
    for stem, span in clean:
        for other, lines in unsure:
            if lines is None or _overlap(span, lines):
                raise PinsError(f"run {stem} shares model input lines with run {other}, which may have changed a "
                                f"tool, so pins can't tell their lines apart. {CLEAN_RUN}")
    if not clean:
        raise PinsError(f"no clean, completed run is on record, so nothing shows which declarations are clean. "
                        f"{CLEAN_RUN}")
    return [span for _, span in clean]


def _read_log(path: Path, spans: list[tuple[int, int]] | None = None) -> list[dict[str, Any]]:
    """Every JSON body in the log, or with spans only the lines that start inside one of them."""
    bodies = []
    offset = 0
    for number, raw in enumerate(path.read_bytes().splitlines(keepends=True), start=1):
        at, offset = offset, offset + len(raw)
        line = raw.decode("utf-8")
        if not line.strip() or (spans is not None and not any(s <= at < e for s, e in spans)):
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
    parser.add_argument("--runs", type=Path, default=None,
                        help="the driver's run records (default: the runs directory beside the model log)")
    args = parser.parse_args(argv)
    runs = args.runs if args.runs is not None else args.model_log.parent / "runs"
    try:
        pins = build_pins(_read_log(args.model_log, clean_spans(runs, args.model_log.read_bytes())))
        if not pins:
            # An empty registry denies every step, so a capture run that pinned nothing must not report success.
            raise PinsError(f"{args.model_log} pins no tools: it holds no request body that declares a function tool")
        write_tools(args.data, pins)
    except (PinsError, OSError, ValueError) as e:
        print(f"pins: {e}", file=sys.stderr)
        return 2
    print(f"pins: wrote {len(pins)} tools to {args.data}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
