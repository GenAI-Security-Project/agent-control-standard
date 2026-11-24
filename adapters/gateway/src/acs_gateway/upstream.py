"""Where model answers come from: live, capture or replay (issue #579, BUILD_PLAN A.8 and WP15).

Each mode is an httpx transport under the gateway's one upstream client, so gating never knows which mode answered.
Live with no key file passes no transport at all, which is the gateway's behavior before upstream modes existed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from acs_gateway import secretfile
from acs_gateway.apply import NEUTRAL_LINE
from acs_gateway.sessions import conversation_parts, is_stream
from acs_gateway.telemetry import replay_miss

if TYPE_CHECKING:
    from acs_gateway.config import GatewayConfig
    from acs_gateway.sessions import Session

# The gateway's branch tokens travel to capture and replay on this header, set after every client x-acs-* header is
# stripped and removed again before a request leaves for a real upstream (A.8).
BRANCH_HEADER = "x-acs-lab-branch"
# The gateway's arrival for a request travels to capture as an httpx request extension, which no header carries and
# LiveTransport drops before the request leaves (round 2, R5).
ARRIVAL_EXTENSION = "acs_lab_arrival"

# FinBot's per-visitor values at 1450fc4, which differ in every fresh FinBot and so can't be replayed verbatim
# (PREMORTEM P2): the namespace ns_<user id> (session.py:233-240, routing.py:23), the user id user_<token_urlsafe(12)>,
# workflow ids wf_, wf_chat_ and wf_review_ (runner.py:38, chat.py:105, api.py:330), transfer ids tr_<token_hex(12)>
# (finstripe server.py:30), uuid4 interaction ids, and the current time in every agent's GLOBAL_CONTEXT (base.py:320).
# A namespace is ns_ and the user id, so the user id inside it is matched as its own value: a recording then can't
# carry an old namespace past a request that names the user only by id, or the other way round (fix round 2, R2).
# An id-shaped run inside any other longer token isn't an id.
_EDGE = r"(?<![A-Za-z0-9_-])"
_USER = r"(?:(?<=" + _EDGE + r"ns_)|" + _EDGE + r")user_[A-Za-z0-9_-]{16}(?![A-Za-z0-9_-])"
_ID = re.compile(
    r"(?P<user>" + _USER + r")|" + _EDGE + r"(?:"
    r"(?P<wf>wf_(?:chat_|review_)?[A-Za-z0-9_-]{16})"
    r"|(?P<tr>tr_[0-9a-f]{24})"
    r"|(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"|(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r")(?![A-Za-z0-9_-])")
_PLACEHOLDER = re.compile(r"\{\{acs:(?:user|wf|tr|uuid|time):\d+\}\}")
_USER_VALUE = re.compile(_USER)
_SKELETON_ENTRY = re.compile(r"(?:user|wf|tr|uuid|time):[1-9][0-9]*")


def _inside_git_work_tree(path: Path) -> bool:
    """True when any parent holds .git, so a key file there could be committed (PREMORTEM P24)."""
    for parent in path.resolve(strict=False).parents:
        if (parent / ".git").exists():
            return True
    return False


def read_key_file(path: Path) -> str:
    """The model key, from a file the lab writes outside the repository. No message ever carries the key itself.

    Held to the gateway's other secret files by load_secret_file, and refused inside a git work tree (PREMORTEM P24).
    """
    name = "ACS_UPSTREAM_KEY_FILE"
    if _inside_git_work_tree(path):
        raise ValueError(f"{name} {path} is inside a git work tree, and the key must live outside the repository")
    key = secretfile.load_secret_file(path, name)
    if not key:
        raise ValueError(f"{name} {path} is empty")
    if any(c.isspace() or not c.isprintable() for c in key):
        # The key becomes one header value, so anything that could split or extend the header is refused.
        raise ValueError(f"{name} {path} must hold one key on one line with no spaces")
    return key


def _strings(value: Any) -> Iterator[str]:
    """Every string in a JSON value, in document order."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def placeholder_map(body: Any) -> dict[str, str]:
    """Each FinBot-generated value in a request mapped to its placeholder, {{acs:<kind>:<n>}}.

    n counts distinct values of one kind in the order they first appear, the system text first and then the whole
    body in document order. A capture and its replay come from the same agent at the same step, so the same
    position holds the same kind of value in both, and the numbering lines up.
    """
    mapping: dict[str, str] = {}
    counts: dict[str, int] = {}
    sources = [conversation_parts(body)[0]] if isinstance(body, dict) else []
    for text in [*sources, *_strings(body)]:
        for match in _ID.finditer(text):
            value = match.group(0)
            if value not in mapping:
                kind = match.lastgroup or "id"
                counts[kind] = counts.get(kind, 0) + 1
                mapping[value] = f"{{{{acs:{kind}:{counts[kind]}}}}}"
    return mapping


def id_skeleton(body: Any, mapping: dict[str, str]) -> list[str]:
    """Every mapped id in the request, in document order, as kind:n. A recording stores it, and replay fills only a
    request with the same skeleton, so an id that moved or an extra one never shifts which value a placeholder takes
    (fix round 2, R3)."""
    return [mapping[m.group(0)][6:-2] for text in _strings(body) for m in _ID.finditer(text) if m.group(0) in mapping]


def unmapped_user_id(value: Any) -> bool:
    """Whether a value with placeholders still holds a user id or namespace, which would leak into another FinBot."""
    return any(_USER_VALUE.search(text) for text in _strings(value))


def holds_mapped_user(value: Any, mapping: dict[str, str]) -> bool:
    """Whether a value with placeholders still holds a mapped user id in any form the id pattern missed: another case,
    a longer token around it, or the bare 16 characters (fix round 3, R-M2). Compared case-insensitively."""
    users = [real.lower() for real, placeholder in mapping.items() if placeholder.startswith("{{acs:user:")]
    if not users:
        return False
    text = "\n".join(_strings(value)).lower()
    return any(user in text or user.removeprefix("user_") in text for user in users)


def to_placeholders(value: Any, mapping: dict[str, str]) -> Any:
    """value with every mapped id replaced by its placeholder. An id-shaped value the request never held, one the
    model made up, stays as it is."""
    if isinstance(value, str):
        return _ID.sub(lambda m: mapping.get(m.group(0), m.group(0)), value)
    if isinstance(value, dict):
        return {k: to_placeholders(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [to_placeholders(v, mapping) for v in value]
    return value


def fill(value: Any, mapping: dict[str, str]) -> tuple[Any, bool]:
    """value with each placeholder replaced by the live request's value, and False when any had no live value.

    An unfilled placeholder makes the whole answer a miss for the caller, never a guess at the missing id.
    """
    live = {placeholder: real for real, placeholder in mapping.items()}
    complete = True

    def one(match: re.Match[str]) -> str:
        nonlocal complete
        if match.group(0) in live:
            return live[match.group(0)]
        complete = False
        return match.group(0)

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return _PLACEHOLDER.sub(one, item)
        if isinstance(item, dict):
            return {k: walk(v) for k, v in item.items()}
        if isinstance(item, list):
            return [walk(v) for v in item]
        return item

    return walk(value), complete


def replay_key(body: dict[str, Any], mapping: dict[str, str]) -> tuple[str, int, int]:
    """(first user message with placeholders, turn, step), read from the request alone (A.8, PREMORTEM P11).

    The turn is the number of user messages, so each turn of one chat has its own answer (fix round 2, CR1). The
    step is the number of function_call_output items, so an SDK retry or an agent rerun lands on the same step.
    """
    first_user = _first_user_text(body)
    items = body.get("input")
    if isinstance(items, str):
        return to_placeholders(first_user, mapping), 1, 0
    items = items if isinstance(items, list) else []
    turn = sum(1 for i in items if isinstance(i, dict) and i.get("role") == "user")
    # Only outputs the gateway governs, the same ones the branch counts, so a capture never writes a step its branch
    # can't cover (fix round 3, CR3-5).
    step = sum(1 for i in _governed_items(body) if i.get("type") == "function_call_output")
    return to_placeholders(first_user, mapping), turn, step


def _first_user_text(body: dict[str, Any]) -> str:
    """The first user message, picked by the rule sessions use, as the text a person reads: a string as it is, a list
    of parts as its text parts joined, so a hand-written match targets plain text (fix round 3, CR3-10). Any other
    shape falls back to the session's own form."""
    items = body.get("input")
    if isinstance(items, str):
        return items
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("role") == "user":
            content = item.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "".join(p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
            break
    return conversation_parts(body)[1]


def _governed_items(body: Any) -> list[dict[str, Any]]:
    items = body.get("input") if isinstance(body, dict) else None
    return [i for i in items if isinstance(i, dict) and i.get("type") in ("function_call", "function_call_output")
            and isinstance(i.get("call_id"), str) and i["call_id"]] if isinstance(items, list) else []


def off_branch(body: Any) -> str:
    """Off governs nothing, so every call and output in the request is delivered: one a for each (A.8)."""
    return ",".join("a" for _ in _governed_items(body))


def _token(outcome: Any, result: bool) -> str:
    if outcome.outcome == "delivered":
        return "a"
    if outcome.outcome == "removed":
        return "d"
    # A denied output is stored rewritten to the neutral line. The gateway's own record says so, never the request.
    if result and outcome.item is not None and outcome.item.get("output") == NEUTRAL_LINE:
        return "d"
    return "m"


def call_ids(items: Any) -> list[str]:
    """The call_ids of the function calls among an upstream reply's output items, read before gating removes any. A
    whole answer passes its output list and a stream passes each item as it decides it, so both count the same calls
    (rehearsal R7)."""
    return [i["call_id"] for i in items if isinstance(i, dict) and i.get("type") == "function_call"
            and isinstance(i.get("call_id"), str) and i["call_id"]] if isinstance(items, list) else []


def reply_call_ids(reply: Any) -> list[str]:
    """call_ids for a whole answer."""
    return call_ids(reply.get("output") if isinstance(reply, dict) else None)


def _position(body: Any) -> int:
    items = body.get("input") if isinstance(body, dict) else None
    return len(items) if isinstance(items, list) else 0


@dataclass(frozen=True)
class Arrival:
    """Where a request stood when it passed the input phase: its session and its arrival number there. Off mode has
    no sessions, so its arrivals carry None and the gateway's own count of ungoverned requests (round 2, R5)."""
    session: Session | None
    number: int

    @property
    def order(self) -> tuple[int, int]:
        """Later attempts compare greater: a newer session's arrival, or a later one on the same session."""
        return (self.session.ordinal if self.session is not None else 0, self.number)


def note_arrival(session: Session, body: Any) -> Arrival:
    """Count a request in as it passes the input phase, under the session lock, so a later attempt at the same
    position is known before an earlier one's reply comes back."""
    session.arrivals += 1
    session.latest_arrival[_position(body)] = session.arrivals
    return Arrival(session, session.arrivals)


def note_reply_calls(session: Session, call_ids: list[str], body: Any, arrival: Arrival | None = None) -> None:
    """Place this reply's calls where the request that produced them ended, for session_branch.

    A client keeps only the reply it last received for a request, so a removed call from an earlier attempt at the
    same request, an SDK retry or a rerun, stops counting (fix round 3, CR3-1). That is the attempt that arrived
    last, not the one that finished last: a client retries an attempt it gave up on, which can still finish after
    the retry, so a reply whose request a later arrival at the same position has replaced places nothing (final
    review I-1). Capture keeps the line of the same attempt, so the two agree. An arrival counted on another
    session, one later bumped or evicted, is superseded here too, since a retry on this session may already have
    placed its calls (round 2, R6). No arrival, after a fault before the input phase finished, places as before.
    """
    position = _position(body)
    if arrival is not None and (arrival.session is not session
                                or session.latest_arrival.get(position, 0) > arrival.number):
        return
    kept = set(call_ids)
    for call_id, outcome in session.calls.items():
        if call_id in kept:
            outcome.position = position
        elif outcome.position == position:
            outcome.position = None


def session_branch(session: Session, body: Any) -> str:
    """Enforce's branch tokens, one per governed item, from the session's own outcome records (A.8): a delivered,
    d removed or replaced by the neutral line, m rewritten. Shadow and off change nothing, so they use off_branch.

    Calls and outputs take their tokens in the order the request holds them. A call the gateway removed never comes
    back from the client, so its d goes where the request that produced it ended, which is where its siblings and
    the model's next items sit in every later resend. The producing request and its retries end exactly there, so
    they carry no token for calls they haven't been shown yet. A history call the session has no record of, after an
    epoch bump or an eviction, reached the model as the client sent it, so it is a, as off would say (CR3-8).
    """
    items = body.get("input") if isinstance(body, dict) and isinstance(body.get("input"), list) else []
    removed: dict[int, int] = {}
    for outcome in session.calls.values():
        if outcome.outcome == "removed" and outcome.position is not None:
            removed[outcome.position] = removed.get(outcome.position, 0) + 1
    tokens: list[str] = []
    for index, item in enumerate(items):
        tokens += ["d"] * removed.get(index, 0)
        call_id = item.get("call_id") if isinstance(item, dict) else None
        if not isinstance(call_id, str) or not call_id:
            continue
        if item.get("type") == "function_call":
            outcome = session.calls.get(call_id)
            tokens.append("a" if outcome is None else _token(outcome, result=False))
        elif item.get("type") == "function_call_output":
            outcome = session.results.get(call_id)
            recorded = outcome.item.get("output") if outcome is not None and outcome.item is not None else None
            if item.get("output") == NEUTRAL_LINE and recorded != NEUTRAL_LINE:
                # The gateway withheld this resend (a reused call_id), so the model got the neutral line (CR3-2).
                tokens.append("d")
            else:
                tokens.append("a" if outcome is None else _token(outcome, result=True))
    return ",".join(tokens)


def _audit(event: str, **fields: Any) -> None:
    from acs.client import audit_event

    audit_event(event, **fields)


_BRANCH = re.compile(r"(?:[adm](?:,[adm])*)?")
_RECORDING_FIELDS = ("scenario", "match", "turn", "step", "branch", "stream", "ids", "response")


@dataclass(frozen=True)
class Recording:
    """One recording line (A.8, plus turn and ids):
    {"scenario", "match", "turn", "step", "branch", "stream", "ids", "response"}.

    match is a regular expression for the first user message with placeholders, matched in full. A non-streamed
    response is the Responses API body. A streamed one is the list of {"event", "data"} server-sent events.
    """
    scenario: str
    match: re.Pattern[str]
    turn: int
    step: int
    branch: str
    stream: bool
    ids: list[str]
    response: Any


def _recording(raw: str) -> Recording:
    """One line, checked, or ValueError naming what is wrong."""
    try:
        line = json.loads(raw)
    except ValueError as e:
        raise ValueError(f"not JSON ({e.msg})") from None
    if not isinstance(line, dict) or set(line) != set(_RECORDING_FIELDS):
        raise ValueError(f"a recording line has exactly the fields {', '.join(_RECORDING_FIELDS)}")
    if not isinstance(line["scenario"], str) or not isinstance(line["match"], str):
        raise ValueError("scenario and match are strings")
    try:
        match = re.compile(line["match"])
    except re.error as e:
        raise ValueError(f"match is not a regular expression ({e})") from None
    turn, step = line["turn"], line["step"]
    for name, value in (("turn", turn), ("step", step)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} is a whole number of at least 0")
    if not isinstance(line["branch"], str) or not _BRANCH.fullmatch(line["branch"]):
        raise ValueError("branch is a comma-separated list of a, d and m tokens")
    if len([t for t in line["branch"].split(",") if t]) < step:
        # Every function_call_output the gateway forwards has an outcome, so a step needs at least as many tokens.
        raise ValueError(f"branch has fewer tokens than step {step}, so the line could never match")
    if not isinstance(line["stream"], bool):
        raise ValueError("stream is true or false")
    if not isinstance(line["ids"], list) or not all(isinstance(i, str) and _SKELETON_ENTRY.fullmatch(i)
                                                    for i in line["ids"]):
        raise ValueError("ids is a list of kind:n entries")
    response = line["response"]
    if line["stream"]:
        if not isinstance(response, list) or not all(
                isinstance(e, dict) and set(e) == {"event", "data"} and isinstance(e["event"], str)
                and isinstance(e["data"], dict) for e in response):
            raise ValueError("a streamed response is a list of {event, data} objects")
    elif not isinstance(response, dict) or not isinstance(response.get("output"), list):
        raise ValueError("a response is a Responses API object with an output list")
    return Recording(line["scenario"], match, turn, step, line["branch"], line["stream"], line["ids"], response)


class RecordingStore:
    """Every recording under ACS_RECORDINGS_DIR, loaded once at startup so a bad line stops the gateway there."""

    def __init__(self, files: list[list[Recording]]) -> None:
        # One list per file, in file name order, each in line order.
        self.files = files

    @classmethod
    def load(cls, directory: Path, scenario: str | None = None) -> RecordingStore:
        """Every *.jsonl file in directory, or only <scenario>.jsonl when ACS_REPLAY_SCENARIO names one, so two
        scenarios sharing a key never collide (fix round 3, CR3-3)."""
        if not directory.is_dir():
            raise ValueError(f"ACS_RECORDINGS_DIR {directory} is not a directory")
        if scenario is not None:
            only = directory / f"{scenario}.jsonl"
            if not only.is_file():
                raise ValueError(f"ACS_REPLAY_SCENARIO file {only} does not exist")
            paths = [only]
        else:
            paths = sorted(directory.glob("*.jsonl"))
        files = []
        for path in paths:
            recordings = []
            for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not raw.strip():
                    continue
                try:
                    recordings.append(_recording(raw))
                except ValueError as e:
                    raise ValueError(f"{path}:{number}: {e}") from None
            files.append(recordings)
        return cls(files)

    def find(self, first_user: str, turn: int, step: int, branch: str, stream: bool,
             ids: list[str]) -> tuple[Recording | None, bool]:
        """The recording that fits every part of the key, the id skeleton included (fix round 3, CR3-3), and whether
        some line fit all but the skeleton.

        Files are searched in name order, and within a file the last fitting line wins. Capture refuses to start over
        an existing file, so within one file a later line for the same key is a retry's reply, the one the client
        kept and followed up on (fix round 4, I-1)."""
        shape_only = False
        for recordings in self.files:
            for recording in reversed(recordings):
                if (recording.turn == turn and recording.step == step and recording.branch == branch
                        and recording.stream == stream and recording.match.fullmatch(first_user)):
                    if recording.ids == ids:
                        return recording, False
                    shape_only = True
        return None, shape_only


# The documented miss: fixed ids and the gateway's own neutral line, so a miss never looks like a model's guess.
MISS_RESPONSE_ID = "resp_replay_miss"
MISS_MESSAGE_ID = "msg_replay_miss"


def miss_response(model: Any) -> dict[str, Any]:
    message = {"type": "message", "id": MISS_MESSAGE_ID, "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": NEUTRAL_LINE, "annotations": []}]}
    return {"id": MISS_RESPONSE_ID, "object": "response", "created_at": 0, "status": "completed",
            "model": model if isinstance(model, str) else None, "output": [message]}


def miss_events(model: Any) -> list[dict[str, Any]]:
    """The miss as the whole event set a model streams for one message, in the Responses API's order.

    Enforce rebuilds a stream event by event and ends it on text for a message nobody announced (stream.py), so the
    miss announces its message and its part before the text, as a model does. FinBot's chat (chat.py at 1450fc4)
    reads only the delta and output_item.done, which is why a shorter stream once looked complete.
    """
    done = miss_response(model)
    message = done["output"][0]
    part = message["content"][0]
    where = {"item_id": MISS_MESSAGE_ID, "output_index": 0, "content_index": 0}
    events: list[dict[str, Any]] = [
        {"type": "response.created", "response": {**done, "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {**message, "status": "in_progress", "content": []}},
        {"type": "response.content_part.added", **where, "part": {**part, "text": ""}},
        {"type": "response.output_text.delta", **where, "delta": NEUTRAL_LINE, "logprobs": []},
        {"type": "response.output_text.done", **where, "text": NEUTRAL_LINE, "logprobs": []},
        {"type": "response.content_part.done", **where, "part": part},
        {"type": "response.output_item.done", "output_index": 0, "item": message},
        {"type": "response.completed", "response": done},
    ]
    return [{"event": event["type"], "data": {"type": event["type"], "sequence_number": number,
                                              **{k: v for k, v in event.items() if k != "type"}}}
            for number, event in enumerate(events)]


def encode_events(events: list[dict[str, Any]]) -> bytes:
    return "".join(f"event: {e['event']}\ndata: {json.dumps(e['data'])}\n\n" for e in events).encode("utf-8")


@dataclass(frozen=True)
class _Answer:
    content: bytes
    content_type: str
    miss: dict[str, Any] | None


def _response(status: int, content: bytes, content_type: str) -> httpx.Response:
    """An unread response, as a network transport returns one, since the gateway reads the raw stream in off mode."""
    return httpx.Response(status, headers={"content-type": content_type, "content-length": str(len(content))},
                          stream=httpx.ByteStream(content))


class ReplayTransport(httpx.AsyncBaseTransport):
    """Answers POST <base>/responses from recordings. It opens no socket and holds no credential.

    An answer depends only on the request bytes and the gateway's branch tokens, both the same on a byte-identical
    retry, so a retry gets exactly the first answer, a miss included, with no cache (PREMORTEM P11).
    """

    def __init__(self, store: RecordingStore) -> None:
        self.store = store

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or not request.url.path.endswith("/responses"):
            error = {"error": {"message": "Unknown request URL.", "type": "invalid_request_error", "param": None,
                               "code": "unknown_url"}}
            return _response(404, json.dumps(error).encode("utf-8"), "application/json")
        answer = self._answer(await request.aread(), request.headers.get(BRANCH_HEADER))
        if answer.miss is not None:
            _audit("replay_miss", **answer.miss)
            # The transport runs inside the gateway's upstream send, so the miss marks that model call's span (LAB-09,
            # A.8, A.9). With tracing off this does nothing.
            replay_miss(**answer.miss)
        return _response(200, answer.content, answer.content_type)

    def _answer(self, raw: bytes, branch: str | None) -> _Answer:
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            body = None
        if not isinstance(body, dict):
            return self._miss(None, "unreadable_request", None, "", False)
        stream = is_stream(body)
        mapping = placeholder_map(body)
        first_user, turn, step = replay_key(body, mapping)
        if branch is None:
            branch = off_branch(body)
        recording, shape_only = self.store.find(first_user, turn, step, branch, stream, id_skeleton(body, mapping))
        if recording is None:
            return self._miss(body.get("model"), "placeholder_mismatch" if shape_only else "no_recording", step,
                              branch, stream)
        response, complete = fill(recording.response, mapping)
        if not complete:
            return self._miss(body.get("model"), "placeholder_unfilled", step, branch, stream,
                              scenario=recording.scenario)
        if stream:
            return _Answer(encode_events(response), "text/event-stream", None)
        return _Answer(json.dumps(response).encode("utf-8"), "application/json", None)

    @staticmethod
    def _miss(model: Any, cause: str, step: int | None, branch: str, stream: bool, **extra: Any) -> _Answer:
        fields = {"cause": cause, "step": step, "branch": branch, "stream": stream, **extra}
        if stream:
            return _Answer(encode_events(miss_events(model)), "text/event-stream", fields)
        return _Answer(json.dumps(miss_response(model)).encode("utf-8"), "application/json", fields)


class LiveTransport(httpx.AsyncBaseTransport):
    """The real upstream through an ordinary httpx client, so proxy settings and timeouts stay what they are in plain
    live mode. With a key it replaces the client's Authorization header, so FinBot never holds the real key."""

    def __init__(self, key: str | None) -> None:
        self._key = key
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        for name in [n for n in request.headers if n.lower().startswith("x-acs-")]:
            del request.headers[name]
        request.extensions.pop(ARRIVAL_EXTENSION, None)
        if self._key is not None:
            request.headers["authorization"] = f"Bearer {self._key}"
        return await self._client.send(request, stream=True)

    async def aclose(self) -> None:
        await self._client.aclose()


def _delta_part(event: Any) -> tuple[Any, ...] | None:
    """The streamed part a delta event adds to, or None when the event carries no text delta."""
    data = event.get("data") if isinstance(event, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("delta"), str):
        return None
    return (data.get("type"), data.get("item_id"), data.get("output_index"), data.get("content_index"),
            data.get("summary_index"))


def _part_texts(events: list[dict[str, Any]]) -> list[str]:
    """Each streamed part's deltas joined, one text per part, in the order the parts first appear."""
    parts: dict[tuple[Any, ...], list[str]] = {}
    for event in events:
        part = _delta_part(event)
        if part is not None:
            parts.setdefault(part, []).append(event["data"]["delta"])
    return ["".join(pieces) for pieces in parts.values()]


def _rejoin_deltas(raw: list[dict[str, Any]], normalized: list[dict[str, Any]],
                   mapping: dict[str, str]) -> list[dict[str, Any]]:
    """normalized with each streamed part whose deltas, joined, still hold a user id remapped as one text.

    The part's text is joined from the raw deltas, mapped with to_placeholders and kept in the part's first delta
    event; its other delta events are dropped. Replay sends the part as one delta, which a streaming client reads
    as it reads several. Parts that hold no user id keep their deltas as they came."""
    parts: dict[tuple[Any, ...], list[int]] = {}
    for i, event in enumerate(raw):
        part = _delta_part(event)
        if part is not None:
            parts.setdefault(part, []).append(i)
    first: dict[int, str] = {}
    dropped: set[int] = set()
    for indexes in parts.values():
        mapped = "".join(normalized[i]["data"]["delta"] for i in indexes)
        if not (unmapped_user_id(mapped) or holds_mapped_user(mapped, mapping)):
            continue
        first[indexes[0]] = to_placeholders("".join(raw[i]["data"]["delta"] for i in indexes), mapping)
        dropped.update(indexes[1:])
    if not first:
        return normalized
    out = []
    for i, event in enumerate(normalized):
        if i in dropped:
            continue
        if i in first:
            event = {**event, "data": {**event["data"], "delta": first[i]}}
        out.append(event)
    return out


def parse_events(text: str) -> list[dict[str, Any]] | None:
    """Server-sent events as [{"event", "data"}], or None when any event's data isn't a JSON object."""
    events = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        if not block.strip():
            continue
        name, data = "message", []
        for row in block.split("\n"):
            if row.startswith("event:"):
                name = row[6:].strip()
            elif row.startswith("data:"):
                data.append(row[5:].removeprefix(" "))
        try:
            value = json.loads("\n".join(data))
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        events.append({"event": name, "data": value})
    return events


class _Inflater:
    """Decodes an identity, gzip or deflate body as its chunks arrive, never producing more than the caller allows,
    so a small compressed answer can't inflate past the body limit in memory (fix round 3, CR3-4). Any other
    encoding, brotli or a list of encodings among them, can't be measured or read, so supported is False."""

    def __init__(self, encoding: str) -> None:
        name = encoding.strip().lower()
        self.supported = name in ("", "identity", "gzip", "x-gzip", "deflate")
        self._deflate = name == "deflate"
        self._d: Any = None
        if name in ("gzip", "x-gzip"):
            self._d = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif self._deflate:
            self._d = zlib.decompressobj()

    def feed(self, chunk: bytes, room: int) -> bytes:
        """Up to room + 1 decoded bytes from chunk, so a result longer than room means the limit was passed."""
        if self._d is None:
            return chunk
        try:
            out = self._d.decompress(chunk, room + 1)
        except zlib.error:
            if not self._deflate:
                raise
            # Some servers send raw deflate with no zlib header, which httpx also accepts.
            self._deflate = False
            self._d = zlib.decompressobj(-zlib.MAX_WBITS)
            out = self._d.decompress(chunk, room + 1)
        while len(out) <= room and self._d.unconsumed_tail:
            out += self._d.decompress(self._d.unconsumed_tail, room + 1 - len(out))
        return out

    def finish(self) -> bytes:
        """What the decoder still holds. flush takes no output cap (its argument only sizes the first buffer), and
        none is needed: feed always drains unconsumed_tail while under the limit, so only the decoder's small
        internal buffer is left here, and the caller checks the total (fix round 4, M-1)."""
        return self._d.flush() if self._d is not None else b""


class CaptureTransport(httpx.AsyncBaseTransport):
    """Live, plus one recording line per successful exchange in <ACS_RECORDINGS_DIR>/<scenario>.jsonl (A.8).

    The line holds placeholders for FinBot's generated values, taken from the request, so it replays into another
    FinBot (PREMORTEM P2). It records the body the gateway forwarded, after gating, so the key it writes is the key
    replay computes for the same run. A streamed answer reaches the client only once the whole stream has arrived,
    since the line needs all of it. Headers, the key among them, are never written. A failed write is audited and
    the client still gets its answer.

    A line belongs to the attempt the client kept, which is the last to arrive with the same key, never the last to
    finish (final review I-1). A client retries because it gave up on an attempt that is still running upstream, so
    that attempt can finish after its retry. The gateway takes each request's arrival once, under the session lock,
    and hands it over as the ARRIVAL_EXTENSION request extension. The transport keeps no count of its own, so the
    order it judges by is the order gating saw (round 2, R5). An exchange whose key a later arrival has taken writes
    nothing, whenever it finishes and whatever the later one returns. A request with no arrival, after a fault before
    the input phase finished, is written as it finishes and supersedes nothing.
    """

    def __init__(self, live: LiveTransport, path: Path, scenario: str, max_bytes: int) -> None:
        self._live = live
        self._path = path
        self._scenario = scenario
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        # Line key to the order of its latest arrival, for attempts still in flight. Every exchange runs on the
        # gateway's one event loop and none awaits between reading and writing this, so it needs no lock.
        self._latest: dict[tuple[Any, ...], tuple[int, int]] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raw_request = await request.aread()
        body, key = self._line_key(raw_request, request.headers.get(BRANCH_HEADER))
        carried = request.extensions.get(ARRIVAL_EXTENSION)
        arrival = carried.order if isinstance(carried, Arrival) else None
        if key is not None and arrival is not None:
            latest = self._latest.get(key)
            # A later arrival can reach the transport first, so only a greater order replaces the one held.
            if latest is None or arrival > latest:
                self._latest[key] = arrival
        try:
            return await self._exchange(request, body, key, arrival)
        finally:
            if key is not None and arrival is not None and self._latest.get(key) == arrival:
                # Only in-flight keys stay, so the map never outgrows the requests running at once.
                del self._latest[key]

    @staticmethod
    def _line_key(raw_request: bytes, branch: str | None) -> tuple[dict[str, Any] | None, tuple[Any, ...] | None]:
        """The request parsed, and the key replay would look its line up by, or (None, None) when it can't be read."""
        try:
            body = json.loads(raw_request)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None, None
        if not isinstance(body, dict):
            return None, None
        mapping = placeholder_map(body)
        first_user, turn, step = replay_key(body, mapping)
        return body, (first_user, turn, step, branch if branch is not None else off_branch(body), is_stream(body),
                      tuple(id_skeleton(body, mapping)))

    async def _exchange(self, request: httpx.Request, body: dict[str, Any] | None, key: tuple[Any, ...] | None,
                        arrival: tuple[int, int] | None) -> httpx.Response:
        upstream = await self._live.handle_async_request(request)
        # Capture holds the whole answer to write its line, so the gateway's body limit bounds it in every mode, off
        # included (fix round 2, CR3), on the raw bytes and on the decoded bytes as they stream (fix round 3, CR3-4).
        inflater = _Inflater(upstream.headers.get("content-encoding", ""))
        chunks: list[bytes] = []
        decoded: list[bytes] | None = [] if inflater.supported else None
        size = inflated = 0
        try:
            async for chunk in upstream.aiter_raw():
                size += len(chunk)
                chunks.append(chunk)
                if decoded is not None:
                    try:
                        piece = inflater.feed(chunk, self._max_bytes - inflated)
                    except zlib.error:
                        decoded = None
                    else:
                        inflated += len(piece)
                        decoded.append(piece)
                if size > self._max_bytes or inflated > self._max_bytes:
                    return self._too_large()
            if decoded is not None:
                try:
                    tail = inflater.finish()
                except zlib.error:
                    decoded = None
                else:
                    inflated += len(tail)
                    decoded.append(tail)
                    if inflated > self._max_bytes:
                        return self._too_large()
        finally:
            await upstream.aclose()
        raw = b"".join(chunks)
        if 200 <= upstream.status_code < 300:
            if key is not None and arrival is not None and self._latest.get(key) != arrival:
                _audit("capture_skipped", cause="superseded_attempt", scenario=self._scenario)
            else:
                self._record(body, key, b"".join(decoded) if decoded is not None else None)
        return httpx.Response(upstream.status_code, headers=upstream.headers, stream=httpx.ByteStream(raw))

    def _too_large(self) -> httpx.Response:
        _audit("upstream_error", cause="upstream_too_large", max_body_bytes=self._max_bytes, scenario=self._scenario)
        error = {"error": {"message": "The model service returned a response that is too large.",
                           "type": "server_error", "param": None, "code": "upstream_too_large"}}
        return _response(502, json.dumps(error).encode("utf-8"), "application/json")

    def _record(self, body: dict[str, Any] | None, key: tuple[Any, ...] | None, decoded: bytes | None) -> None:
        if body is None or key is None:
            _audit("capture_skipped", cause="unreadable_request", scenario=self._scenario)
            return
        if decoded is None:
            _audit("capture_skipped", cause="unreadable_response", scenario=self._scenario)
            return
        first_user, turn, step, branch, stream, ids = key
        response: Any
        if stream:
            response = parse_events(decoded.decode("utf-8", "replace"))
        else:
            try:
                response = json.loads(decoded)
            except (ValueError, UnicodeDecodeError, RecursionError):
                response = None
            if not isinstance(response, dict) or not isinstance(response.get("output"), list):
                response = None
        if response is None:
            _audit("capture_skipped", cause="unreadable_response", scenario=self._scenario)
            return
        mapping = placeholder_map(body)
        normalized = to_placeholders(response, mapping)
        if unmapped_user_id(normalized) or holds_mapped_user(normalized, mapping):
            # The request named no such user, so the line would carry this FinBot's namespace into another one.
            _audit("capture_skipped", cause="unmapped_id", scenario=self._scenario)
            return
        if stream:
            # An id split across deltas escapes both checks piece by piece and rejoins on replay (fix round 4, I-2).
            # Each streamed part's deltas are mapped again as one text and kept as one delta, so a mapped id the model
            # spelled across deltas becomes its placeholder: FinBot's answers name the vendor's namespace, and every
            # s5 take of the 2026-11-23 owner sitting was skipped for it. What still holds an id after that is
            # skipped as before.
            normalized = _rejoin_deltas(response, normalized, mapping)
            # Each part is checked on its own: joined with the next part's text, a letter or digit beside an id hides
            # it from the id pattern's edges (review of the 2026-11-23 change).
            if any(unmapped_user_id(text) or holds_mapped_user(text, mapping) for text in _part_texts(normalized)):
                _audit("capture_skipped", cause="unmapped_id", scenario=self._scenario, where="stream_deltas")
                return
        line = {"scenario": self._scenario, "match": re.escape(first_user), "turn": turn, "step": step, "branch": branch,
                "stream": stream, "ids": list(ids), "response": normalized}
        encoded = json.dumps(line, ensure_ascii=False)
        try:
            # A line the loader rejects would stop replay for the whole directory, so it is never written
            # (fix round 3, CR3-5).
            _recording(encoded)
        except ValueError as e:
            _audit("capture_skipped", cause="invalid_line", scenario=self._scenario, error=str(e))
            return
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                # O_NOFOLLOW so a symlink planted at the scenario path can't redirect the write (fix round 2, R5).
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o644)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(encoded + "\n")
        except OSError as e:
            _audit("capture_failed", cause="write_error", scenario=self._scenario, error=type(e).__name__)

    async def aclose(self) -> None:
        await self._live.aclose()


class UpstreamSource:
    """The configured upstream mode, checked at construction so a bad key file or recording stops startup."""

    def __init__(self, config: GatewayConfig) -> None:
        self.mode = config.upstream_mode
        # Replay answers from recordings, so a model name has nothing to choose there.
        self.model = config.upstream_model if self.mode != "replay" else None
        self._key = read_key_file(config.upstream_key_file) if config.upstream_key_file is not None else None
        if config.upstream_key_shared:
            # One line, so the operator who opted in sees what the opt-in means. The key itself is never written.
            sys.stderr.write(f"acs-gateway: ACS_UPSTREAM_KEY_SHARED=1, so every client holding the client token "
                             f"that can reach the model port on {config.listen_host} spends the model key\n")
        self._store = None
        self._capture_path = None
        if self.mode == "capture":
            assert config.recordings_dir is not None
            self._capture_path = config.recordings_dir / f"{config.capture_scenario}.jsonl"
            self._scenario = config.capture_scenario
            self._max_bytes = config.max_body_bytes
            if os.path.lexists(self._capture_path):
                # Replay serves the last matching line within a file, so stale lines from an earlier run would mix with
                # this run's (fix round 2, CR5).
                raise ValueError(f"ACS_CAPTURE_SCENARIO file {self._capture_path} already exists. Move it away or "
                                 "choose another scenario")
        if self.mode == "replay":
            assert config.recordings_dir is not None
            self._store = RecordingStore.load(config.recordings_dir, config.replay_scenario)

    @property
    def records_branch(self) -> bool:
        """Capture and replay key on the gateway's branch tokens, so the gateway hands them over on BRANCH_HEADER."""
        return self.mode in ("capture", "replay")

    @property
    def custom(self) -> bool:
        """False only for live with no key, where the gateway's client stays exactly as it was before #579."""
        return self.mode != "live" or self._key is not None

    def transport(self) -> httpx.AsyncBaseTransport | None:
        """A fresh transport for one lifespan, or None for the default."""
        if self.mode == "replay":
            assert self._store is not None
            return ReplayTransport(self._store)
        if self._capture_path is not None:
            return CaptureTransport(LiveTransport(self._key), self._capture_path, self._scenario, self._max_bytes)
        if self._key is not None:
            return LiveTransport(self._key)
        return None
