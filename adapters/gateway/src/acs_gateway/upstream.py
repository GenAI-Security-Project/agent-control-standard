"""Where model answers come from: live, capture or replay (issue #579, BUILD_PLAN A.8 and WP15).

Each mode is an httpx transport under the gateway's one upstream client, so gating never knows which mode answered.
Live with no key file passes no transport at all, which is the gateway's behavior before upstream modes existed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from acs_gateway.apply import DEFAULT_REDACTION, NEUTRAL_LINE

if TYPE_CHECKING:
    from acs_gateway.config import GatewayConfig

# FinBot's per-visitor values at 1450fc4, which differ in every fresh FinBot and so can't be replayed verbatim
# (PREMORTEM P2): the namespace ns_<user id> (session.py:233-240, routing.py:23), the user id user_<token_urlsafe(12)>,
# workflow ids wf_, wf_chat_ and wf_review_ (runner.py:38, chat.py:105, api.py:330), transfer ids tr_<token_hex(12)>
# (finstripe server.py:30), uuid4 interaction ids, and the current time in every agent's GLOBAL_CONTEXT (base.py:320).
# Order matters: a namespace holds a user id, so it is tried first. An id-shaped run inside a longer token isn't one.
_ID = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"(?P<ns>ns_user_[A-Za-z0-9_-]{16})"
    r"|(?P<user>user_[A-Za-z0-9_-]{16})"
    r"|(?P<wf>wf_(?:chat_|review_)?[A-Za-z0-9_-]{16})"
    r"|(?P<tr>tr_[0-9a-f]{24})"
    r"|(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"|(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r")(?![A-Za-z0-9_-])")
_PLACEHOLDER = re.compile(r"\{\{acs:(?:ns|user|wf|tr|uuid|time):\d+\}\}")


def _inside_git_work_tree(path: Path) -> bool:
    """True when any parent holds .git, so a key file there could be committed (PREMORTEM P24)."""
    for parent in path.resolve(strict=False).parents:
        if (parent / ".git").exists():
            return True
    return False


def read_key_file(path: Path) -> str:
    """The model key, from a file the lab writes outside the repository. No message ever carries the key itself.

    Held to the gateway's other secret files: not a symlink, a regular file, mode 0600 or 0400, owned by the gateway's
    uid. The checks and the read share one descriptor opened with O_NOFOLLOW, so the file can't be swapped between
    them, and O_NONBLOCK keeps a FIFO from stalling startup.
    """
    name = "ACS_UPSTREAM_KEY_FILE"
    if _inside_git_work_tree(path):
        raise ValueError(f"{name} {path} is inside a git work tree, and the key must live outside the repository")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        if path.is_symlink():
            raise ValueError(f"{name} {path} is a symlink") from None
        raise ValueError(f"{name} {path} can't be opened: {e.strerror}") from None
    info = os.fstat(fd)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{name} {path} is not a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"{name} {path} must be mode 0600 or 0400")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ValueError(f"{name} {path} is owned by uid {info.st_uid}, not the gateway's uid {os.geteuid()}")
        raw = f.read()
    try:
        key = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ValueError(f"{name} {path} is not UTF-8 text") from None
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


def _system_text(body: dict[str, Any]) -> str:
    """The instructions field, or the first system or developer message, where FinBot puts its namespace."""
    if isinstance(body.get("instructions"), str):
        return body["instructions"]
    for item in body.get("input") if isinstance(body.get("input"), list) else []:
        if isinstance(item, dict) and item.get("role") in ("system", "developer"):
            return _text(item.get("content"))
    return ""


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


def placeholder_map(body: Any) -> dict[str, str]:
    """Each FinBot-generated value in a request mapped to its placeholder, {{acs:<kind>:<n>}}.

    n counts distinct values of one kind in the order they first appear, the system text first and then the whole
    body in document order. A capture and its replay come from the same agent at the same step, so the same
    position holds the same kind of value in both, and the numbering lines up.
    """
    mapping: dict[str, str] = {}
    counts: dict[str, int] = {}
    sources = [_system_text(body)] if isinstance(body, dict) else []
    for text in [*sources, *_strings(body)]:
        for match in _ID.finditer(text):
            value = match.group(0)
            if value not in mapping:
                kind = match.lastgroup or "id"
                counts[kind] = counts.get(kind, 0) + 1
                mapping[value] = f"{{{{acs:{kind}:{counts[kind]}}}}}"
    return mapping


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


def replay_key(body: dict[str, Any], mapping: dict[str, str]) -> tuple[str, int, str]:
    """(first user message with placeholders, step, branch), read from the request alone (A.8, PREMORTEM P11).

    The step is the number of function_call_output items, so an SDK retry or an agent rerun lands on the same step.
    The branch has one token per output: d when the gateway replaced it with the neutral line, m when it holds the
    default redaction marker, a otherwise. A Guardian redaction with its own replacement text reads as a.
    """
    items = body.get("input")
    if isinstance(items, str):
        return to_placeholders(items, mapping), 0, ""
    items = items if isinstance(items, list) else []
    first_user = next((_text(i.get("content")) for i in items
                       if isinstance(i, dict) and i.get("role") == "user" and i.get("type", "message") == "message"), "")
    tokens = []
    for item in items:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            text = item.get("output") if isinstance(item.get("output"), str) else _text(item.get("output"))
            tokens.append("d" if text == NEUTRAL_LINE else "m" if DEFAULT_REDACTION in text else "a")
    return to_placeholders(first_user, mapping), len(tokens), ",".join(tokens)


def _audit(event: str, **fields: Any) -> None:
    from acs.client import audit_event

    audit_event(event, **fields)


_BRANCH = re.compile(r"(?:[adm](?:,[adm])*)?")
_RECORDING_FIELDS = ("scenario", "match", "step", "branch", "stream", "response")


@dataclass(frozen=True)
class Recording:
    """One recording line (A.8): {"scenario", "match", "step", "branch", "stream", "response"}.

    match is a regular expression for the first user message with placeholders, matched in full. A non-streamed
    response is the Responses API body. A streamed one is the list of {"event", "data"} server-sent events.
    """
    scenario: str
    match: re.Pattern[str]
    step: int
    branch: str
    stream: bool
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
    step = line["step"]
    if not isinstance(step, int) or isinstance(step, bool) or step < 0:
        raise ValueError("step is a whole number of at least 0")
    if not isinstance(line["branch"], str) or not _BRANCH.fullmatch(line["branch"]):
        raise ValueError("branch is a comma-separated list of a, d and m tokens")
    if not isinstance(line["stream"], bool):
        raise ValueError("stream is true or false")
    response = line["response"]
    if line["stream"]:
        if not isinstance(response, list) or not all(
                isinstance(e, dict) and set(e) == {"event", "data"} and isinstance(e["event"], str)
                and isinstance(e["data"], dict) for e in response):
            raise ValueError("a streamed response is a list of {event, data} objects")
    elif not isinstance(response, dict) or not isinstance(response.get("output"), list):
        raise ValueError("a response is a Responses API object with an output list")
    return Recording(line["scenario"], match, step, line["branch"], line["stream"], response)


class RecordingStore:
    """Every recording under ACS_RECORDINGS_DIR, loaded once at startup so a bad line stops the gateway there."""

    def __init__(self, recordings: list[Recording]) -> None:
        self.recordings = recordings

    @classmethod
    def load(cls, directory: Path) -> RecordingStore:
        if not directory.is_dir():
            raise ValueError(f"ACS_RECORDINGS_DIR {directory} is not a directory")
        recordings = []
        for path in sorted(directory.glob("*.jsonl")):
            for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not raw.strip():
                    continue
                try:
                    recordings.append(_recording(raw))
                except ValueError as e:
                    raise ValueError(f"{path.name}:{number}: {e}") from None
        return cls(recordings)

    def find(self, first_user: str, step: int, branch: str, stream: bool) -> Recording | None:
        """The first recording, in file and line order, that fits all four parts of the key."""
        for recording in self.recordings:
            if (recording.step == step and recording.branch == branch and recording.stream == stream
                    and recording.match.fullmatch(first_user)):
                return recording
        return None


# The documented miss: fixed ids and the gateway's own neutral line, so a miss never looks like a model's guess.
MISS_RESPONSE_ID = "resp_replay_miss"
MISS_MESSAGE_ID = "msg_replay_miss"


def miss_response(model: Any) -> dict[str, Any]:
    message = {"type": "message", "id": MISS_MESSAGE_ID, "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": NEUTRAL_LINE, "annotations": []}]}
    return {"id": MISS_RESPONSE_ID, "object": "response", "created_at": 0, "status": "completed",
            "model": model if isinstance(model, str) else None, "output": [message]}


def miss_events(model: Any) -> list[dict[str, Any]]:
    """The miss as the events FinBot's chat reads (chat.py at 1450fc4), in the Responses API's order."""
    done = miss_response(model)
    message = done["output"][0]
    return [
        {"event": "response.created",
         "data": {"type": "response.created", "sequence_number": 0,
                  "response": {**done, "status": "in_progress", "output": []}}},
        {"event": "response.output_text.delta",
         "data": {"type": "response.output_text.delta", "sequence_number": 1, "item_id": MISS_MESSAGE_ID,
                  "output_index": 0, "content_index": 0, "delta": NEUTRAL_LINE, "logprobs": []}},
        {"event": "response.output_item.done",
         "data": {"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": message}},
        {"event": "response.completed",
         "data": {"type": "response.completed", "sequence_number": 3, "response": done}},
    ]


def encode_events(events: list[dict[str, Any]]) -> bytes:
    return "".join(f"event: {e['event']}\ndata: {json.dumps(e['data'])}\n\n" for e in events).encode("utf-8")


def _is_stream(body: dict[str, Any]) -> bool:
    # The gateway's own rule (app.is_stream): any stream value but an absent one, null or false asks for a stream.
    return body.get("stream") is not None and body["stream"] is not False


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

    A byte-identical request gets the bytes it got before from a bounded cache keyed on the request's sha256
    (PREMORTEM P11), so an SDK retry sees exactly the first answer, a miss included.
    """
    CACHE_SIZE = 1024

    def __init__(self, store: RecordingStore) -> None:
        self.store = store
        self.cache: OrderedDict[str, _Answer] = OrderedDict()
        self.cache_hits = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or not request.url.path.endswith("/responses"):
            error = {"error": {"message": "Unknown request URL.", "type": "invalid_request_error", "param": None,
                               "code": "unknown_url"}}
            return _response(404, json.dumps(error).encode("utf-8"), "application/json")
        raw = await request.aread()
        digest = hashlib.sha256(raw).hexdigest()
        answer = self.cache.get(digest)
        if answer is not None:
            self.cache.move_to_end(digest)
            self.cache_hits += 1
        else:
            answer = self._answer(raw)
            self.cache[digest] = answer
            if len(self.cache) > self.CACHE_SIZE:
                self.cache.popitem(last=False)
        if answer.miss is not None:
            _audit("replay_miss", **answer.miss)
        return _response(200, answer.content, answer.content_type)

    def _answer(self, raw: bytes) -> _Answer:
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            body = None
        if not isinstance(body, dict):
            return self._miss(None, "unreadable_request", None, "", False)
        stream = _is_stream(body)
        mapping = placeholder_map(body)
        first_user, step, branch = replay_key(body, mapping)
        recording = self.store.find(first_user, step, branch, stream)
        if recording is None:
            return self._miss(body.get("model"), "no_recording", step, branch, stream)
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
        if self._key is not None:
            request.headers["authorization"] = f"Bearer {self._key}"
        return await self._client.send(request, stream=True)

    async def aclose(self) -> None:
        await self._client.aclose()


class UpstreamSource:
    """The configured upstream mode, checked at construction so a bad key file or recording stops startup."""

    def __init__(self, config: GatewayConfig) -> None:
        self.mode = config.upstream_mode
        self._key = read_key_file(config.upstream_key_file) if config.upstream_key_file is not None else None
        self._store = None
        if self.mode == "replay":
            assert config.recordings_dir is not None
            self._store = RecordingStore.load(config.recordings_dir)

    @property
    def custom(self) -> bool:
        """False only for live with no key, where the gateway's client stays exactly as it was before #579."""
        return self.mode != "live" or self._key is not None

    def transport(self) -> httpx.AsyncBaseTransport | None:
        """A fresh transport for one lifespan, or None for the default."""
        if self.mode == "replay":
            assert self._store is not None
            return ReplayTransport(self._store)
        if self._key is not None:
            return LiveTransport(self._key)
        return None
