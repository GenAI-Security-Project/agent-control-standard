"""Tests for pins.py. Run with the gateway's environment, which holds acs_gateway.tool_digest:

    uv run --project adapters/gateway --locked python -m pytest labs/finbot/policy/tools/test_pins.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pins  # noqa: E402
from acs_gateway.tool_digest import ToolDigests  # noqa: E402

FIXTURE = HERE / "fixtures" / "model-inputs.jsonl"


def clean_runs(directory: Path, log: Path) -> Path:
    """A runs directory holding one clean, completed run whose span covers the whole log, as the driver writes it."""
    runs = directory / "runs"
    runs.mkdir(exist_ok=True)
    size = log.stat().st_size if log.exists() else 0
    record = {"format": "acs-lab-run/1", "run_id": "clean", "result": "completed", "poisoned": False,
              "model_input_span": [0, size]}
    (runs / "clean.json").write_text(json.dumps(record))
    return runs


def bodies() -> list[dict]:
    return [json.loads(line) for line in FIXTURE.read_text().splitlines()]


def function(name: str, description: str) -> dict:
    return {"type": "function", "name": name, "description": description,
            "parameters": {"type": "object", "properties": {}}, "strict": False}


def test_build_pins_matches_the_gateway_digest() -> None:
    first = bodies()[0]
    built = pins.build_pins([first])
    digests = ToolDigests(first)
    assert set(built) == {"get_vendor_details", "finmail__send_email"}
    for name, entry in built.items():
        assert entry == {"digests": [digests.get(name)]}
        assert entry["digests"][0].startswith("sha256:")


def test_build_pins_collects_every_declaration() -> None:
    built = pins.build_pins(bodies())
    expected = sorted({ToolDigests(body).get("get_vendor_details") for body in bodies()})
    assert len(expected) == 2
    assert built["get_vendor_details"] == {"digests": expected}
    # A body's non-function tools, such as web_search, are never pinned, as the gateway never digests them.
    assert set(built) == {"get_vendor_details", "finmail__send_email"}


def test_repeated_name_in_one_body_fails() -> None:
    body = {"tools": [function("get_vendor_details", "a"), function("get_vendor_details", "b")]}
    with pytest.raises(pins.PinsError, match="get_vendor_details"):
        pins.build_pins([body])


def test_unencodable_declaration_fails() -> None:
    body = {"tools": [function("finmail__send_email", "lone \ud800 surrogate")]}
    with pytest.raises(pins.PinsError, match="finmail__send_email"):
        pins.build_pins([body])


def test_write_tools_keeps_other_keys(tmp_path: Path) -> None:
    data = tmp_path / "data.json"
    data.write_text(json.dumps({"finbot_lab": {"tools": {"old": {"digests": ["sha256:00"]}},
                                               "vendor_domains": ["northwind-supplies.example"],
                                               "payment_ask_threshold": 5000, "egress_allow": []}}))
    new = {"finmail__send_email": {"digests": ["sha256:aa"]}}
    pins.write_tools(data, new)
    text = data.read_text()
    assert text.endswith("}\n")
    written = json.loads(text)
    assert written == {"finbot_lab": {"tools": new, "vendor_domains": ["northwind-supplies.example"],
                                      "payment_ask_threshold": 5000, "egress_allow": []}}
    assert text == json.dumps(written, indent=2, sort_keys=True) + "\n"


def test_main_exit_codes(tmp_path: Path) -> None:
    data = tmp_path / "data.json"
    data.write_text(json.dumps({"finbot_lab": {"tools": {}, "vendor_domains": [], "payment_ask_threshold": 5000,
                                               "egress_allow": []}}))
    runs = clean_runs(tmp_path, FIXTURE)
    assert pins.main(["--model-log", str(FIXTURE), "--data", str(data), "--runs", str(runs)]) == 0
    assert set(json.loads(data.read_text())["finbot_lab"]["tools"]) == {"get_vendor_details", "finmail__send_email"}
    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"tools": []}\nnot json\n')
    before = data.read_text()
    (tmp_path / "b").mkdir()
    broken_runs = clean_runs(tmp_path / "b", broken)
    assert pins.main(["--model-log", str(broken), "--data", str(data), "--runs", str(broken_runs)]) == 2
    assert data.read_text() == before
    assert pins.main(["--model-log", str(tmp_path / "missing.jsonl"), "--data", str(data), "--runs", str(runs)]) == 2


EMPTY_LOGS = {
    "empty": "",
    "blank": "\n  \n",
    "no-function-tools": '{"tools": []}\n{"tools": [{"type": "web_search"}]}\n',
    "no-tools-key": '{"input": "hi"}\n',
}


@pytest.mark.parametrize("log", EMPTY_LOGS.values(), ids=EMPTY_LOGS.keys())
def test_main_fails_on_a_log_that_pins_no_tools(tmp_path: Path, log: str, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data.json"
    data.write_text(json.dumps({"finbot_lab": {"tools": {"old": {"digests": ["sha256:00"]}}, "vendor_domains": [],
                                               "payment_ask_threshold": 5000, "egress_allow": []}}))
    before = data.read_text()
    model_log = tmp_path / "model-inputs.jsonl"
    model_log.write_text(log)
    runs = clean_runs(tmp_path, model_log)
    assert pins.main(["--model-log", str(model_log), "--data", str(data), "--runs", str(runs)]) == 2
    assert "pins no tools" in capsys.readouterr().err
    assert data.read_text() == before


# Interface pins. The policy reads these stack interfaces, so each test fails when the gateway or the Guardian
# changes one and the pack would silently stop matching.

INPUTS = sorted((HERE / "inputs").glob("*.json"))


@pytest.mark.parametrize("path", INPUTS, ids=lambda p: p.stem)
def test_inputs_match_the_payloads_the_gateway_builds(path: Path) -> None:
    from acs.guardian.opa_backend import build_input
    from acs_gateway.app import ASK_ANSWER_FIELD
    from acs_gateway.apply import call_payload, result_payload

    document = json.loads(path.read_text())["input"]
    payload = dict(document["payload"])
    tool = payload["tool"]
    if document["method"] == "steps/toolCallRequest":
        answer = payload.pop(ASK_ANSWER_FIELD, None)
        built = call_payload(tool["name"], {k: v["value"] for k, v in payload["arguments"].items()}, tool["version"])
        assert built == payload
        if answer is not None:
            assert answer["approver"] == {"type": "human", "id": "lab-approver"}
            assert answer["answer"] == "approve"
    else:
        output = payload["outputs"][0]["value"]
        built, _parsed, _repeated = result_payload(tool["name"], json.dumps(output), None, tool["version"])
        assert built == payload
    assert build_input(document["method"], {"payload": document["payload"]}) == {"input": document}


def test_the_ask_answer_field_and_the_approver_the_gateway_sends() -> None:
    import inspect

    from acs_gateway import app

    assert app.ASK_ANSWER_FIELD == "x_acs_lab_ask_answer"
    # base.rego's ask_approved compares the approver with exactly this object.
    assert '"approver": {"type": "human", "id": settings.approver_id}' in inspect.getsource(app)


def test_the_gateway_honors_the_packs_ask() -> None:
    from acs_gateway.app import ask_settings
    from acs_gateway.config import MAX_ASK_S

    details = {"approver": {"type": "human", "id": "lab-approver"}, "question": "Approve a transfer of 7500?",
               "timeout_seconds": 240}
    settings = ask_settings(details)
    assert not isinstance(settings, str), settings
    assert settings.approver_id == "lab-approver"
    assert settings.timeout_s <= MAX_ASK_S


def test_the_verdict_keys_the_pack_sets_are_allowed() -> None:
    from acs.guardian.opa_backend import VERDICT_DECISIONS, VERDICT_KEYS

    assert {"decision", "reasoning", "reason_codes", "modifications", "ask_details"} <= VERDICT_KEYS
    assert VERDICT_DECISIONS == {"allow", "deny", "modify", "ask"}


# ---------------------------------------------------------------------------------------------------------------------
# Only clean, completed runs reach the registry (LAB-16 Task 11 fix rounds 1 and 2)
# ---------------------------------------------------------------------------------------------------------------------

CLEAN = {"tools": [function("finmail__send_email", "Send an email message."),
                   function("get_vendor_details", "Get the details of the vendor")]}
SETUP_ONLY = {"tools": [function("finmail__send_email", "Send an email message."),
                        function("update_vendor_status", "Set a vendor's status")]}
POISONED = {"tools": [function("finmail__send_email", "Send an email message, and something else.")]}
CLEAN_DIGEST = ToolDigests(CLEAN).get("finmail__send_email")
UNSET = object()


class StateDir:
    """state/ as the driver leaves it: the model input log and one run record per run, each with its span."""

    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "runs").mkdir(parents=True)
        self.log = root / "model-inputs.jsonl"
        self.log.write_bytes(b"")
        self.data = root / "data.json"
        self.data.write_text(json.dumps({"finbot_lab": {"tools": {}, "vendor_domains": [],
                                                        "payment_ask_threshold": 5000, "egress_allow": []}}))
        self.count = 0

    def lines(self, bodies: list[dict]) -> tuple[int, int]:
        """Lines with no record, as a run killed before it wrote one leaves them."""
        start = self.log.stat().st_size
        with self.log.open("ab") as f:
            for body in bodies:
                f.write(json.dumps(body).encode() + b"\n")
        return start, self.log.stat().st_size

    def record(self, span: object, *, poisoned: object = False, result: str = "completed",
               window: object = None) -> str:
        self.count += 1
        run_id = f"run{self.count}"
        record: dict = {"format": "acs-lab-run/1", "run_id": run_id, "result": result}
        if span is not UNSET:
            record["model_input_span"] = list(span) if isinstance(span, tuple) else span
        if poisoned is not UNSET:
            record["poisoned"] = poisoned
        if window is not None:
            record["model_inputs"] = list(window)
        (self.root / "runs" / f"{run_id}.json").write_text(json.dumps(record))
        return run_id

    def run(self, bodies: list[dict], **fields: object) -> str:
        return self.record(self.lines(bodies), **fields)

    def pins(self, *extra: str) -> int:
        return pins.main(["--model-log", str(self.log), "--data", str(self.data), *extra])

    def tools(self) -> dict:
        return json.loads(self.data.read_text())["finbot_lab"]["tools"]


def refused(state: StateDir, capsys: pytest.CaptureFixture[str], before: str) -> str:
    """Asserts one exit 2 that left data.json alone, and returns its one stderr line."""
    assert state.pins() == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1, err
    assert state.data.read_text() == before
    return err[0]


def test_poisoned_run_is_left_out_and_setup_lines_kept(tmp_path: Path) -> None:
    state = StateDir(tmp_path / "state")
    state.run([SETUP_ONLY, POISONED], poisoned=True)
    state.run([SETUP_ONLY, CLEAN])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]
    # A tool declared only during a clean run's setup stays in, or later setups would deny it as unregistered.
    assert "update_vendor_status" in state.tools()


def test_killed_run_with_no_record_is_left_out(tmp_path: Path) -> None:
    # SIGKILL, an OOM kill or a full disk can end an s6 run after its override reached the log and before its record.
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    state.lines([SETUP_ONLY, POISONED])
    state.run([CLEAN])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_killed_run_at_the_end_of_the_log_is_left_out(tmp_path: Path) -> None:
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    state.lines([POISONED])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_lines_after_a_poisoned_span_are_left_out(tmp_path: Path) -> None:
    # FinBot's background agents can still write after the driver closes the span.
    state = StateDir(tmp_path / "state")
    state.run([POISONED], poisoned=True)
    state.lines([POISONED])
    state.run([CLEAN])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_clean_span_inside_a_poisoned_run_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Two runs at once: the clean run's span opens while the s6 run is still writing.
    state = StateDir(tmp_path / "state")
    p0, _ = state.lines([POISONED])
    c0, _ = state.lines([CLEAN, POISONED])
    _, end = state.lines([POISONED])
    state.record((p0, end), poisoned=True)
    state.record((c0, end))
    line = refused(state, capsys, state.data.read_text())
    assert "run2" in line and "run1" in line


def test_poisoned_span_inside_a_clean_span_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    c0, _ = state.lines([CLEAN])
    p0, p1 = state.lines([POISONED])
    _, end = state.lines([CLEAN])
    state.record((c0, end))
    state.record((p0, p1), poisoned=True)
    refused(state, capsys, state.data.read_text())


def test_record_without_the_poisoned_key_is_not_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A record from before the driver wrote the flag can't show its run was clean.
    state = StateDir(tmp_path / "state")
    state.run([POISONED], poisoned=UNSET)
    line = refused(state, capsys, state.data.read_text())
    assert "./lab.sh run s6 --clean" in line
    state.run([CLEAN])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_old_record_overlapping_a_clean_span_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A record with no span still names its window. Its run may have been poisoned, so the overlap can't be read.
    state = StateDir(tmp_path / "state")
    c0, _ = state.lines([CLEAN])
    w0, w1 = state.lines([POISONED])
    _, end = state.lines([CLEAN])
    state.record((c0, end))
    state.record(UNSET, poisoned=UNSET, window=(w0, w1))
    refused(state, capsys, state.data.read_text())


def test_clean_run_that_did_not_complete_is_left_out(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    state.run([POISONED], result="broken")
    refused(state, capsys, state.data.read_text())
    state.run([CLEAN])
    assert state.pins() == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_two_clean_spans_may_overlap(tmp_path: Path) -> None:
    state = StateDir(tmp_path / "state")
    a0, _ = state.lines([SETUP_ONLY])
    b0, _ = state.lines([CLEAN])
    _, end = state.lines([CLEAN])
    state.record((a0, end))
    state.record((b0, end))
    assert state.pins() == 0
    assert {"update_vendor_status", "finmail__send_email", "get_vendor_details"} <= set(state.tools())


@pytest.mark.parametrize("poisoned", [True, UNSET])
def test_no_clean_run_names_the_clean_run(tmp_path: Path, poisoned: object,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    state.run([CLEAN], poisoned=poisoned)
    assert "./lab.sh run s6 --clean" in refused(state, capsys, state.data.read_text())


def test_no_runs_directory_names_the_clean_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    state.lines([CLEAN])
    (state.root / "runs").rmdir()
    assert "./lab.sh run s6 --clean" in refused(state, capsys, state.data.read_text())


@pytest.mark.parametrize("poisoned", [True, False])
def test_span_past_the_end_of_the_log_is_refused(tmp_path: Path, poisoned: bool,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    # The gateway only appends, so a span past the end means the log was cut or replaced under the records.
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    size = state.log.stat().st_size
    state.record((size + 10, size + 20), poisoned=poisoned)
    refused(state, capsys, state.data.read_text())


@pytest.mark.parametrize("span", [None, [5], [9, 3], ["0", 10], [True, 10], [-1, 10]])
def test_a_clean_run_with_an_unreadable_span_is_refused(tmp_path: Path, span: object,
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    state.lines([CLEAN])
    state.record(span)
    assert "run2" in refused(state, capsys, state.data.read_text())


def test_a_poisoned_run_with_no_span_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Nothing says where its lines are, so no clean span can be shown to miss them.
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    state.record(UNSET, poisoned=True)
    refused(state, capsys, state.data.read_text())


def test_an_unreadable_run_record_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    (state.root / "runs" / "cut.json").write_text('{"poisoned": tr')
    assert "cut" in refused(state, capsys, state.data.read_text())


def test_runs_directory_can_be_named(tmp_path: Path) -> None:
    state = StateDir(tmp_path / "state")
    state.run([CLEAN])
    elsewhere = tmp_path / "elsewhere"
    (state.root / "runs").rename(elsewhere)
    assert state.pins() == 2
    assert state.pins("--runs", str(elsewhere)) == 0
    assert state.tools()["finmail__send_email"]["digests"] == [CLEAN_DIGEST]


def test_span_starting_mid_line_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The re-review's probe: a clean span opening 5 bytes into a poisoned line. Its start reads as inside the span
    # only if pins trusts the offset, so a span off a line boundary is refused.
    # The poisoned lines here come from a run killed before its record, so no overlap refusal can fire first.
    state = StateDir(tmp_path / "state")
    p0, _ = state.lines([POISONED])
    _, end = state.lines([CLEAN])
    state.record((p0 + 5, end))
    assert "line boundary" in refused(state, capsys, state.data.read_text())


def test_span_ending_mid_line_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = StateDir(tmp_path / "state")
    c0, c1 = state.lines([CLEAN])
    state.lines([POISONED])
    state.record((c0, c1 + 5))
    assert "line boundary" in refused(state, capsys, state.data.read_text())
