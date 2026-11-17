import asyncio

from acs_gateway.sessions import SessionMap, conversation_key


def test_conversation_key_uses_system_and_first_user_message():
    a = {"input": [{"role": "system", "content": "S"}, {"role": "user", "content": "U"},
                   {"type": "function_call_output", "call_id": "c", "output": "x"}]}
    b = {"input": [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]}
    c = {"input": [{"role": "system", "content": "S"}, {"role": "user", "content": "other"}]}
    assert conversation_key(a) == conversation_key(b)
    assert conversation_key(a) != conversation_key(c)


def test_conversation_key_reads_instructions_and_string_input():
    assert conversation_key({"instructions": "S", "input": "U"}) == conversation_key(
        {"input": [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]})


def test_session_map_keeps_one_session_per_key_until_the_epoch_moves():
    sessions = SessionMap()
    first = sessions.get("k")
    assert sessions.get("k") is first
    first.calls["call_1"] = object()
    assert sessions.bump_epoch() == 1
    second = sessions.get("k")
    assert second.session_id != first.session_id
    assert second.calls == {}
    assert isinstance(second.lock, asyncio.Lock)


def test_the_session_map_evicts_the_least_recently_used_session():
    evicted = []
    sessions = SessionMap(max_sessions=2, on_evict=evicted.append)
    a = sessions.get("a")
    b = sessions.get("b")
    sessions.get("a")
    sessions.get("c")
    assert evicted == [b]
    assert sessions.get("a") is a
