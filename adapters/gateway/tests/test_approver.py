"""The approver page and its registry (LAB-08, issue #581): what it shows, and what it refuses."""
from __future__ import annotations

import asyncio
import re
import threading
import time
from typing import Any

import pytest
from starlette.testclient import TestClient

from acs_gateway.approver import Approvals, create_approver_app

ORIGIN = "http://127.0.0.1:8090"
SECRET = "approver-secret-" + "0123456789abcdef" * 2
AUTH = {"Authorization": f"Bearer {SECRET}"}


def _fields(**overrides: Any) -> dict[str, Any]:
    base = {"session_id": "s1", "call_id": "call_1", "tool": "pay_vendor", "arguments": {"vendor": 7, "amount": 900},
            "question": "Pay vendor 7?", "approver_id": "lab-approver", "context": "Vendor 7 is new this week."}
    return {**base, **overrides}


class Held:
    """One wait() running on its own loop in a thread, as the gateway's request would, while a test drives the page."""

    def __init__(self, approvals: Approvals, seconds: float = 5.0, **overrides: Any) -> None:
        self.result: Any = "unset"
        deadline = time.monotonic() + seconds

        def run() -> None:
            self.result = asyncio.run(approvals.wait(**_fields(**overrides), deadline=deadline))

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        end = time.monotonic() + 2
        while not approvals.pending() and time.monotonic() < end:
            time.sleep(0.01)

    def join(self) -> Any:
        self.thread.join(10)
        return self.result


@pytest.fixture
def page():
    approvals = Approvals()
    client = TestClient(create_approver_app(approvals, SECRET), base_url=ORIGIN, headers=AUTH)
    with client:
        yield approvals, client


def _token(client: TestClient) -> str:
    html = client.get("/").text
    match = re.search(r'name="token" value="([^"]+)"', html)
    assert match, html
    return match.group(1)


def _post(client: TestClient, data: dict[str, str], **headers: str) -> Any:
    return client.post("/answer", data=data, headers={"Origin": ORIGIN, **headers}, follow_redirects=False)


def test_approve_resolves_the_wait_and_leaves_the_list(page):
    approvals, client = page
    held = Held(approvals)
    ask_id = approvals.pending()[0].ask_id
    response = _post(client, {"id": ask_id, "choice": "approve", "token": _token(client)})
    assert response.status_code == 303
    assert held.join() == "approve"
    assert approvals.pending() == []


def test_reject_resolves_the_wait(page):
    approvals, client = page
    held = Held(approvals)
    ask_id = approvals.pending()[0].ask_id
    assert _post(client, {"id": ask_id, "choice": "reject", "token": _token(client)}).status_code == 303
    assert held.join() == "reject"


def test_no_answer_by_the_deadline_returns_none_and_a_late_answer_is_refused(page):
    approvals, client = page
    held = Held(approvals, seconds=0.3)
    ask_id = approvals.pending()[0].ask_id
    token = _token(client)
    assert held.join() == "timeout"
    assert approvals.pending() == []
    assert _post(client, {"id": ask_id, "choice": "approve", "token": token}).status_code == 409


def test_a_cancelled_wait_leaves_the_list():
    approvals = Approvals()

    async def run() -> None:
        task = asyncio.create_task(approvals.wait(**_fields(), deadline=time.monotonic() + 5))
        await asyncio.sleep(0.05)
        assert len(approvals.pending()) == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert approvals.pending() == []


def test_the_page_escapes_tool_arguments_and_names(page):
    approvals, client = page
    held = Held(approvals, seconds=0.5, tool="<img src=x onerror=alert(1)>",
                arguments={"note": "</pre><script>alert('x')</script>", "q": "\"'&"})
    html = client.get("/").text
    held.join()
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html and "&lt;img src=x" in html
    assert "Pay vendor 7?" in html and "lab-approver" in html and "Vendor 7 is new this week." in html


def test_the_page_sends_headers_that_keep_it_out_of_frames_and_scripts(page):
    _, client = page
    response = client.get("/")
    assert response.headers["x-frame-options"] == "DENY"
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "form-action 'self'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"


def test_answers_take_post_only(page):
    _, client = page
    assert client.get("/answer").status_code == 405


@pytest.mark.parametrize("case", ["missing_token", "stale_token", "foreign_origin", "no_origin", "cross_site",
                                  "rebound_host"])
def test_cross_site_answers_are_refused(page, case):
    approvals, client = page
    held = Held(approvals, seconds=0.6)
    ask_id = approvals.pending()[0].ask_id
    data = {"id": ask_id, "choice": "approve", "token": _token(client)}
    headers = {"Origin": ORIGIN}
    if case == "missing_token":
        del data["token"]
    elif case == "stale_token":
        data["token"] = "A" * 43
    elif case == "foreign_origin":
        headers["Origin"] = "http://evil.example"
    elif case == "no_origin":
        headers = {}
    elif case == "cross_site":
        headers["Sec-Fetch-Site"] = "cross-site"
    elif case == "rebound_host":
        # A rebinding name that resolves to 127.0.0.1 still names itself in Host and Origin.
        headers = {"Origin": "http://evil.example:8090", "Host": "evil.example:8090"}
    response = client.post("/answer", data=data, headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert held.join() == "timeout"


def test_a_page_from_a_rebound_host_is_refused(page):
    _, client = page
    assert client.get("/", headers={"Host": "evil.example:8090"}).status_code == 403


def test_only_approve_or_reject_and_no_other_field(page):
    approvals, client = page
    held = Held(approvals, seconds=0.6)
    ask_id = approvals.pending()[0].ask_id
    token = _token(client)
    assert _post(client, {"id": ask_id, "choice": "allow", "token": token}).status_code == 400
    extra = {"id": ask_id, "choice": "approve", "token": token, "arguments": "{\"amount\": 1}"}
    assert _post(client, extra).status_code == 400
    assert held.join() == "timeout"


def test_a_token_answers_only_the_calls_its_page_showed(page):
    approvals, client = page
    earlier = Held(approvals, seconds=0.8, call_id="call_1")
    token = _token(client)
    later = Held(approvals, seconds=0.8, call_id="call_2")
    end = time.monotonic() + 2
    while len(approvals.pending()) < 2 and time.monotonic() < end:
        time.sleep(0.01)
    ask_id = next(p.ask_id for p in approvals.pending() if p.call_id == "call_2")
    assert _post(client, {"id": ask_id, "choice": "approve", "token": token}).status_code == 403
    assert _post(client, {"id": "nope", "choice": "approve", "token": _token(client)}).status_code == 403
    assert later.join() == "timeout" and earlier.join() == "timeout"


def test_a_token_answers_each_call_once(page):
    approvals, client = page
    first = Held(approvals, seconds=2, call_id="call_1")
    second = Held(approvals, seconds=0.8, call_id="call_2")
    end = time.monotonic() + 2
    while len(approvals.pending()) < 2 and time.monotonic() < end:
        time.sleep(0.01)
    token = _token(client)
    ids = {p.call_id: p.ask_id for p in approvals.pending()}
    assert _post(client, {"id": ids["call_1"], "choice": "approve", "token": token}).status_code == 303
    assert _post(client, {"id": ids["call_1"], "choice": "reject", "token": token}).status_code in (403, 409)
    assert first.join() == "approve"
    assert second.join() == "timeout"


def test_without_the_secret_there_is_no_page_and_no_answer(page):
    approvals, client = page
    held = Held(approvals, seconds=0.6)
    ask_id = approvals.pending()[0].ask_id
    token = _token(client)
    bare = TestClient(create_approver_app(approvals, SECRET), base_url=ORIGIN)
    page_ = bare.get("/")
    assert page_.status_code == 401 and "pay_vendor" not in page_.text
    # Host and Origin say loopback, as a local process or a sibling container can claim. Without the secret, 401.
    response = bare.post("/answer", data={"id": ask_id, "choice": "approve", "token": token},
                         headers={"Origin": ORIGIN, "Host": "127.0.0.1:8090"}, follow_redirects=False)
    assert response.status_code == 401
    wrong = bare.post("/answer", data={"id": ask_id, "choice": "approve", "token": token},
                      headers={"Origin": ORIGIN, "Authorization": "Bearer " + "x" * 48}, follow_redirects=False)
    assert wrong.status_code == 401
    assert held.join() == "timeout"


def test_the_secret_entered_once_is_kept_in_a_same_site_cookie(page):
    approvals, _ = page
    browser = TestClient(create_approver_app(approvals, SECRET), base_url=ORIGIN)
    assert browser.post("/login", data={"secret": "wrong" * 8}, headers={"Origin": ORIGIN},
                        follow_redirects=False).status_code == 401
    assert browser.post("/login", data={"secret": SECRET}, headers={"Origin": "http://evil.example"},
                        follow_redirects=False).status_code == 403
    login = browser.post("/login", data={"secret": SECRET}, headers={"Origin": ORIGIN}, follow_redirects=False)
    assert login.status_code == 303
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and SECRET.lower() not in cookie
    held = Held(approvals)
    page_ = browser.get("/")
    assert page_.status_code == 200 and "pay_vendor" in page_.text
    token = re.search(r'name="token" value="([^"]+)"', page_.text).group(1)
    answer = browser.post("/answer", data={"id": approvals.pending()[0].ask_id, "choice": "reject", "token": token},
                          headers={"Origin": ORIGIN}, follow_redirects=False)
    assert answer.status_code == 303
    assert held.join() == "reject"


def test_invisible_and_bidi_characters_in_labels_are_shown_as_escapes(page):
    approvals, client = page
    held = Held(approvals, seconds=0.5, tool="pay\u202evendor\u200b", question="Pay?\u2066", approver_id="lab\u200d",
                context="ok\u202e")
    html = client.get("/").text
    held.join()
    for char in ("\u202e", "\u200b", "\u2066", "\u200d"):
        assert char not in html
    assert "pay\\u202evendor\\u200b" in html and "Pay?\\u2066" in html and "lab\\u200d" in html
    assert "ok\\u202e" in html
