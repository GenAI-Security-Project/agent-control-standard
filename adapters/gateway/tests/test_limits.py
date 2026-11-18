"""Size limits on both legs and the session cap (review I7, CR9)."""
from conftest import finbot_request, message_item, response_body


def events(audit, name):
    return [e for e in audit() if e["acs_audit_event"] == name]


def test_an_oversized_request_gets_413_when_governed(gateway, guardian, upstream):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_BODY_BYTES="1000")
    response = client.post("/v1/responses", json=finbot_request(user="x" * 2000))
    assert response.status_code == 413
    assert upstream.received == []


def test_off_mode_applies_no_size_limit(gateway, upstream):
    upstream.reply(response_body(message_item("y" * 5000)))
    client = gateway(ACS_GATEWAY_MAX_BODY_BYTES="1000")
    response = client.post("/v1/responses", json=finbot_request(user="x" * 2000))
    assert response.status_code == 200
    assert len(upstream.received[0].body) > 2000
    assert len(response.content) > 5000


def test_an_oversized_upstream_answer_gets_502(gateway, guardian, upstream, audit):
    upstream.reply(response_body(message_item("y" * 5000)))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_BODY_BYTES="2000")
    response = client.post("/v1/responses", json=finbot_request())
    assert response.status_code == 502
    assert events(audit, "upstream_error")[0]["cause"] == "upstream_too_large"


def test_evicting_a_session_is_audited(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="1")
    client.post("/v1/responses", json=finbot_request(user="first run"))
    client.post("/v1/responses", json=finbot_request(user="second run"))
    opened = [e["session_id"] for e in events(audit, "session_opened")]
    assert [e["session_id"] for e in events(audit, "session_evicted")] == opened[:1]


def test_a_new_conversation_gets_503_when_every_session_is_busy(gateway, guardian, upstream, audit):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="1")
    client.post("/v1/responses", json=finbot_request(user="first run"))
    held = next(iter(client.app.state.gateway.sessions._sessions.values()))
    held.active = 1
    response = client.post("/v1/responses", json=finbot_request(user="second run"))
    assert response.status_code == 503
    assert events(audit, "session_evicted") == []
    assert len(events(audit, "sessions_full")) == 1


def test_the_shadow_relay_releases_each_held_chunk_once_sent():
    import asyncio

    from acs_gateway.app import _continue

    from collections import deque

    # A deque, so each held chunk leaves in constant time (review CR7-8).
    held = deque([b"a", b"b", b"c"])

    async def rest():
        yield b"d"

    async def drain():
        seen, sizes = [], []
        async for chunk in _continue(held, rest()):
            seen.append(chunk)
            sizes.append(len(held))
        return seen, sizes

    seen, sizes = asyncio.run(drain())
    assert seen == [b"a", b"b", b"c", b"d"]
    assert sizes == [2, 1, 0, 0]


def test_eviction_follows_use_not_creation_order(gateway, guardian, upstream, audit):
    from acs_gateway.sessions import conversation_key

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="2")
    gw = client.app.state.gateway
    client.post("/v1/responses", json=finbot_request(user="conversation A"))
    client.post("/v1/responses", json=finbot_request(user="conversation B"))
    a = gw.sessions.peek(conversation_key(finbot_request(user="conversation A")))
    b = gw.sessions.peek(conversation_key(finbot_request(user="conversation B")))
    # A is used again, so B is now the least recently used.
    client.post("/v1/responses", json=finbot_request(user="conversation A"))
    client.post("/v1/responses", json=finbot_request(user="conversation C"))
    assert [e["session_id"] for e in events(audit, "session_evicted")] == [b.session_id]
    assert a in gw.sessions._sessions.values()


def test_a_request_waiting_for_the_lock_keeps_its_session_at_capacity(gateway, guardian, upstream):
    import asyncio

    from acs_gateway.sessions import conversation_key

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="1")
    client.post("/v1/responses", json=finbot_request(user="conversation A"))
    gw = client.app.state.gateway
    key = conversation_key(finbot_request(user="conversation A"))
    s1 = gw.sessions.peek(key)

    async def scenario():
        await s1.lock.acquire()

        pins = []

        async def waiter():
            async with gw._current(key, pins) as session:
                return session

        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        # The holder lets go, and before the queued request wakes, another conversation arrives at capacity.
        s1.lock.release()
        try:
            gw.sessions.get("another conversation")
        except Exception:  # noqa: BLE001
            pass
        return await task

    assert client.portal.call(scenario) is s1



def test_current_requires_the_caller_to_hold_the_pins():
    import inspect

    from acs_gateway.app import Gateway

    pins = inspect.signature(Gateway._current).parameters["pins"]
    assert pins.default is inspect.Parameter.empty


def test_every_pin_is_released_after_refusals_and_faults(gateway, guardian, upstream):
    from conftest import call_item, response_body

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    gw = client.app.state.gateway
    call = call_item("get_vendor_details", {"vendor_id": 7}, "call_1")
    upstream.reply(response_body(call))
    client.post("/v1/responses", json=finbot_request())
    # A refusal under the lock: a call this session never delivered, with a repeated key.
    forged = {"type": "function_call", "call_id": "c9", "name": "send", "arguments": '{"a": 1, "a": 2}'}
    assert client.post("/v1/responses", json=finbot_request(call, forged)).status_code == 400
    # A fault inside gating.

    def boom(*args, **kwargs):
        raise RuntimeError("gating bug")

    gw._gate_input = boom
    assert client.post("/v1/responses", json=finbot_request()).status_code == 500
    assert [s.active for s in gw.sessions._sessions.values()] == [0]


def test_moving_off_a_session_releases_its_pin(gateway, guardian, upstream):
    import asyncio

    from acs_gateway.sessions import conversation_key

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    client.post("/v1/responses", json=finbot_request(user="conversation A"))
    gw = client.app.state.gateway
    key = conversation_key(finbot_request(user="conversation A"))
    s1 = gw.sessions.peek(key)

    async def scenario():
        await s1.lock.acquire()
        pins = []

        async def waiter():
            async with gw._current(key, pins) as session:
                return session, s1.active, list(pins)

        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        # An epoch bump while the request waits moves it to the key's new session.
        gw.sessions.bump_epoch()
        s1.lock.release()
        return await task

    session, s1_active, pins = client.portal.call(scenario)
    assert session is not s1
    assert s1_active == 0 and pins == [session]


def test_a_held_pin_keeps_a_session_once_its_lock_is_free(gateway, guardian, upstream):
    import asyncio

    import pytest as _pytest

    from acs_gateway.sessions import SessionsBusy, conversation_key

    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian, ACS_GATEWAY_MAX_SESSIONS="1")
    client.post("/v1/responses", json=finbot_request(user="conversation A"))
    gw = client.app.state.gateway
    key = conversation_key(finbot_request(user="conversation A"))
    s1 = gw.sessions.peek(key)

    async def scenario():
        pins = []
        async with gw._current(key, pins) as session:
            assert session is s1
        # The lock is free again but the request still holds its pin, as between its input and output phases.
        assert not s1.lock.locked() and s1.active == 1
        with _pytest.raises(SessionsBusy):
            gw.sessions.get("another conversation")
        return gw.sessions.peek(key)

    assert client.portal.call(scenario) is s1
