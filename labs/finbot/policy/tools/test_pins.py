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
    assert pins.main(["--model-log", str(FIXTURE), "--data", str(data)]) == 0
    assert set(json.loads(data.read_text())["finbot_lab"]["tools"]) == {"get_vendor_details", "finmail__send_email"}
    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"tools": []}\nnot json\n')
    before = data.read_text()
    assert pins.main(["--model-log", str(broken), "--data", str(data)]) == 2
    assert data.read_text() == before
    assert pins.main(["--model-log", str(tmp_path / "missing.jsonl"), "--data", str(data)]) == 2


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
    assert pins.main(["--model-log", str(model_log), "--data", str(data)]) == 2
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
