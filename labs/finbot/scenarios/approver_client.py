"""The gateway's approver page, as lab run --answer uses it (issue #589, LAB-16 Task 4, LAB-08). Standard library only.

Version 1.0.0. Owner: Rock Lambros.

The page is acs_gateway/approver.py. It listens on port 8090 in the gateway, which the lab container reaches at the
gateway's acs-net address, ACS_GATEWAY_ADMIN_HOST. Its module docstring sets the rules an answer meets, and this
client meets each one: the bearer secret from state/secrets/approver.token, a loopback Host, an Origin equal to
http://<that Host>, and the page token the page minted with its forms, which covers each shown call once. So the
client answers exactly as the page's own form does, and no rule is loosened for it.

The page shows held calls only as HTML forms, so the client reads the hidden id and token fields of those forms.
answer() posts one choice for the one waiting call. Two waiting calls is a run the guide never asks for, so the
client answers neither and says so. Lab convention until issue #175 defines how an approver's answer reaches the
Guardian, the same convention the page carries.
"""
from __future__ import annotations

import html
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

APPROVER_PORT = 8090
CHOICES = ("approve", "reject")
POLL_S = 1.0
# D-043 and LAB-08: a held call waits up to 240 seconds for a person, then the gateway denies it.
WAIT_S = 240.0
TIMEOUT_S = 10.0
# Consecutive failed polls a watch rides through before it stops. A restart of the gateway or one 5xx shouldn't end
# the watch, and a page that stays down shouldn't keep it polling for the whole run.
MAX_FAILED_POLLS = 30
MAX_READ = 1024 * 1024
_ID = re.compile(r'<input type="hidden" name="id" value="([^"]*)">')
_TOKEN = re.compile(r'<input type="hidden" name="token" value="([^"]*)">')


class ApproverError(Exception):
    """The page refused the client or can't be read."""


@dataclass(frozen=True)
class Waiting:
    """One held call the page shows, with the page token that may answer it."""
    ask_id: str
    token: str


@dataclass
class Outcome:
    """What a watch saw: how many polls showed a waiting call, and whether every answer it posted was taken.

    status is the last post's HTTP status. answered is True only when every post got 303."""
    choice: str | None
    polls_waiting: int = 0
    answered: bool = False
    status: int | None = None
    error: str | None = None
    ask_ids: list[str] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # The page answers a taken choice with 303 to /. Following it would turn the answer into a page load, so the 303
    # itself is the result.
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    # acs-net is internal, so a proxy from the environment could only send the bearer somewhere else.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class Approver:
    """The page at host:port, addressed with a loopback Host as a browser on the host would."""

    def __init__(self, host: str, token: str, *, port: int = APPROVER_PORT, deadline_s: float = TIMEOUT_S) -> None:
        self.base = f"http://{host}:{port}"
        self.host_header = f"127.0.0.1:{port}"
        self.origin = f"http://{self.host_header}"
        self.token = token
        # A total deadline for each request, not only a per-socket timeout. Each socket operation gets half, and a
        # request that still runs past the whole is refused, so one slow poll can't outlast the driver's quiet window
        # (re-review I-R1).
        self.deadline_s = deadline_s
        self.timeout = deadline_s / 2
        self._opener = _opener()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Host": self.host_header}

    def _in_time(self, started: float) -> None:
        if time.monotonic() - started > self.deadline_s:
            raise ApproverError(f"the approver page took longer than {self.deadline_s:g} seconds to answer")

    def waiting(self) -> list[Waiting]:
        """Every call the page shows as waiting."""
        request = urllib.request.Request(self.base + "/", headers=self._headers())
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                data = response.read(MAX_READ + 1)
        except urllib.error.HTTPError as e:
            e.close()
            raise ApproverError(f"the approver page refused the driver with HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ApproverError(f"the approver page didn't answer ({getattr(e, 'reason', e)})") from None
        self._in_time(started)
        if len(data) > MAX_READ:
            raise ApproverError(f"the approver page is larger than {MAX_READ} bytes")
        page = data.decode("utf-8", errors="replace")
        ids = [html.unescape(v) for v in _ID.findall(page)]
        tokens = [html.unescape(v) for v in _TOKEN.findall(page)]
        if len(ids) != len(tokens):
            raise ApproverError("the approver page's forms can't be read")
        return [Waiting(a, t) for a, t in zip(ids, tokens)]

    def post(self, waiting: Waiting, choice: str) -> int:
        """Posts choice for one waiting call, as the page's own form does. Returns the HTTP status."""
        if choice not in CHOICES:
            raise ApproverError(f"the answer must be {' or '.join(CHOICES)}")
        body = urllib.parse.urlencode({"id": waiting.ask_id, "choice": choice, "token": waiting.token}).encode("ascii")
        headers = {**self._headers(), "Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"}
        request = urllib.request.Request(self.base + "/answer", data=body, method="POST", headers=headers)
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
        except urllib.error.HTTPError as e:
            e.close()
            status = e.code
        except (urllib.error.URLError, OSError) as e:
            raise ApproverError(f"the approver page didn't answer ({getattr(e, 'reason', e)})") from None
        self._in_time(started)
        return status


def read_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as e:
        raise ApproverError(f"the approver token can't be read ({e.strerror}). Run ./lab.sh init first") from None
    if not token:
        raise ApproverError("the approver token file is empty. Run ./lab.sh init first")
    return token


def watch(approver: Approver, *, stop: threading.Event, choice: str | None = None, poll_s: float = POLL_S,
          on_poll: Callable[[list[Waiting]], None] | None = None,
          on_poll_start: Callable[[], None] | None = None,
          on_poll_end: Callable[[], None] | None = None) -> Outcome:
    """Polls the page until stop is set. With a choice, posts it once for each call held, one at a time.

    on_poll gets every poll's waiting calls, so the driver can hold its quiet timer while a person decides. A failed
    poll is recorded, since a held call could have gone unseen during it, and the watch polls again. It stops after
    MAX_FAILED_POLLS failures in a row (review I1). on_poll_start and on_poll_end bracket each poll, so the driver
    can count a poll still in flight as busy (re-review I-R1).
    """
    outcome = Outcome(choice=choice)
    failed = 0
    posted: set[str] = set()
    while not stop.is_set():
        if on_poll_start is not None:
            on_poll_start()
        try:
            items = approver.waiting()
        except ApproverError as e:
            if on_poll_end is not None:
                on_poll_end()
            outcome.error = outcome.error or str(e)
            failed += 1
            if failed >= MAX_FAILED_POLLS:
                break
            stop.wait(poll_s)
            continue
        failed = 0
        if on_poll is not None:
            on_poll(items)
        if on_poll_end is not None:
            on_poll_end()
        if items:
            outcome.polls_waiting += 1
            outcome.ask_ids += [i.ask_id for i in items if i.ask_id not in outcome.ask_ids]
        # Each held call gets the choice once. FinBot's agent can retry a rejected call, and the retry is a new held
        # call that nobody would answer, so it waited out the ask deadline (2026-11-24, s4a__reject).
        fresh = [i for i in items if i.ask_id not in posted]
        if choice is not None and fresh and outcome.error is None:
            if len(items) == 1:
                posted.add(items[0].ask_id)
                try:
                    outcome.status = approver.post(items[0], choice)
                except ApproverError as e:
                    outcome.error = str(e)
                    outcome.answered = False
                    break
                # True only while every post so far was taken. The first post has no earlier one to answer for.
                outcome.answered = outcome.status == 303 and (len(posted) == 1 or outcome.answered)
                if outcome.status != 303:
                    outcome.error = f"the approver page refused the answer with HTTP {outcome.status}"
            else:
                outcome.error = f"{len(items)} calls wait for approval at once, so the driver answered none"
        stop.wait(poll_s)
    return outcome


def answer(choice: str, *, host: str, token_file: Path, port: int = APPROVER_PORT, wait_s: float = WAIT_S,
           poll_s: float = POLL_S) -> Outcome:
    """Waits up to wait_s for the one waiting call, posts choice for it once, and returns what happened."""
    approver = Approver(host, read_token(token_file), port=port)
    outcome = Outcome(choice=choice)
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        items = approver.waiting()
        if len(items) > 1:
            outcome.error = f"{len(items)} calls wait for approval at once, so the driver answered none"
            return outcome
        if items:
            outcome.polls_waiting, outcome.ask_ids = 1, [items[0].ask_id]
            outcome.status = approver.post(items[0], choice)
            outcome.answered = outcome.status == 303
            if not outcome.answered:
                outcome.error = f"the approver page refused the answer with HTTP {outcome.status}"
            return outcome
        time.sleep(poll_s)
    outcome.error = f"no call waited for approval within {wait_s:g} seconds"
    return outcome
