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
