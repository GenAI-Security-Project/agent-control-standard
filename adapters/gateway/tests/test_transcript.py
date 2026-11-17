import json
import uuid

import pytest

from acs_gateway.transcript import ModelInputLog, Transcript


def test_transcript_appends_lines_in_order(tmp_path):
    session_id = str(uuid.uuid4())
    transcript = Transcript(tmp_path / "t")
    transcript.append(session_id, "req", {"id": 1})
    transcript.append(session_id, "resp", {"id": 1, "result": {}})
    path = tmp_path / "t" / f"{session_id}.jsonl"
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines == [{"dir": "req", "envelope": {"id": 1}}, {"dir": "resp", "envelope": {"id": 1, "result": {}}}]
    assert (path.stat().st_mode & 0o777) == 0o600


def test_transcript_refuses_a_session_id_that_is_not_a_uuid(tmp_path):
    with pytest.raises(ValueError):
        Transcript(tmp_path).append("../escape", "req", {})


def test_transcript_refuses_an_unknown_direction(tmp_path):
    with pytest.raises(ValueError):
        Transcript(tmp_path).append(str(uuid.uuid4()), "sideways", {})


def test_model_input_log_appends_each_body(tmp_path):
    log = ModelInputLog(tmp_path / "model-inputs.jsonl")
    log.append({"input": "a"})
    log.append({"input": "b"})
    lines = (tmp_path / "model-inputs.jsonl").read_text().splitlines()
    assert [json.loads(line) for line in lines] == [{"input": "a"}, {"input": "b"}]


def test_model_input_log_without_a_path_writes_nothing(tmp_path):
    ModelInputLog(None).append({"input": "a"})
    assert list(tmp_path.iterdir()) == []


def test_transcript_records_a_missing_response_with_its_cause(tmp_path):
    session_id = str(uuid.uuid4())
    Transcript(tmp_path).append(session_id, "resp", None, cause="decision_timeout")
    line = json.loads((tmp_path / f"{session_id}.jsonl").read_text())
    assert line == {"dir": "resp", "envelope": None, "cause": "decision_timeout"}


def test_transcript_refuses_a_missing_envelope_without_a_cause(tmp_path):
    with pytest.raises(ValueError):
        Transcript(tmp_path).append(str(uuid.uuid4()), "resp", None)
