"""Where model answers come from: live, capture or replay (issue #579, BUILD_PLAN A.8 and WP15).

Each mode is an httpx transport under the gateway's one upstream client, so gating never knows which mode answered.
Live with no key file passes no transport at all, which is the gateway's behavior before upstream modes existed.
"""
from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from acs_gateway.apply import DEFAULT_REDACTION, NEUTRAL_LINE

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
