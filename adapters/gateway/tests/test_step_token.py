"""The step token decides, as one step, whether a worker may start a transcript write (review CR5-9)."""
import time
import uuid

from acs_gateway.guardian import StepToken


def claimed() -> StepToken:
    token = StepToken(time.monotonic() + 5)
    assert token.claim(str(uuid.uuid4()))
    return token


def test_no_write_starts_after_retirement():
    token = claimed()
    token.retire()
    assert token.begin_write() is False


def test_retirement_reports_a_write_already_under_way():
    token = claimed()
    assert token.begin_write() is True
    assert token.retire() is True
    token.end_write()
    assert token.begin_write() is False


def test_retirement_with_no_write_under_way_reports_none():
    token = claimed()
    assert token.begin_write() is True
    token.end_write()
    assert token.retire() is False


def test_the_worker_writes_nothing_once_retired_between_its_lines():
    """Retirement forced after the request line and before the response line: the response line never starts."""
    from acs_gateway.guardian import write_line

    lines, token = [], claimed()
    assert write_line(token, lambda: lines.append("req")) is True
    token.retire()
    assert write_line(token, lambda: lines.append("resp")) is False
    assert lines == ["req"]


def test_no_send_starts_after_retirement():
    token = claimed()
    token.retire()
    assert token.begin_send() is False


def test_retirement_reports_a_send_already_under_way():
    token = claimed()
    assert token.begin_send() is True
    assert token.retire() is True
    token.end_send()
