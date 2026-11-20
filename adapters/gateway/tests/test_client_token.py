"""The model port's client token.

With a key file, anyone who reaches the model port spends the operator's key. On a Linux host that is every local user,
through the bridge network, so the port takes a bearer token from ACS_GATEWAY_CLIENT_TOKEN_FILE, checked before
any upstream call or key swap, in replay as in live.
"""
import json
from dataclasses import replace

import pytest

from acs_gateway import cli
from acs_gateway.config import GatewayConfig
from conftest import finbot_request, message_item, response_body

TOKEN = "c" * 64
KEY = "sk-test-" + "k" * 40


def secret(tmp_path, name: str, text: str, mode: int = 0o600):
    path = tmp_path / "secrets" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(text + "\n")
    path.chmod(mode)
    return path


def token_file(tmp_path, mode: int = 0o600):
    return secret(tmp_path, "client.token", TOKEN, mode)


def live(gateway, tmp_path, **env):
    return gateway(ACS_UPSTREAM_KEY_FILE=str(secret(tmp_path, "openai.key", KEY)),
                   ACS_GATEWAY_CLIENT_TOKEN_FILE=str(token_file(tmp_path)), **env)


def replay(gateway, tmp_path):
    (tmp_path / "rec").mkdir(exist_ok=True)
    return gateway(ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"),
                   ACS_GATEWAY_CLIENT_TOKEN_FILE=str(token_file(tmp_path)))


def bearer(value: str) -> dict:
    return {"authorization": f"Bearer {value}"}


def model_inputs(tmp_path) -> list:
    path = tmp_path / "model-inputs.jsonl"
    return path.read_text().splitlines() if path.exists() else []


REFUSED = [None, bearer("lab-dummy"), bearer(TOKEN[:-1]), bearer(TOKEN + "x"), {"authorization": TOKEN},
           {"authorization": f"bearer {TOKEN}"}, {"authorization": f"Basic {TOKEN}"}]


@pytest.mark.parametrize("headers", REFUSED)
def test_live_refuses_a_missing_or_wrong_token_before_the_upstream(gateway, upstream, tmp_path, audit, headers):
    response = live(gateway, tmp_path).post("/v1/responses", json=finbot_request(), headers=headers or {})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_api_key"
    # No upstream contact, so the key was never used, and nothing was logged as a model input.
    assert upstream.received == []
    assert model_inputs(tmp_path) == []
    [event] = [e for e in audit() if e["acs_audit_event"] == "client_unauthorized"]
    assert event["cause"] == ("missing" if headers is None else "wrong")
    assert TOKEN not in json.dumps(audit()) and KEY not in json.dumps(audit())


def test_live_with_the_token_swaps_in_the_key_and_never_forwards_the_token(gateway, upstream, tmp_path, audit, capfd):
    upstream.reply(response_body(message_item("ok")))
    response = live(gateway, tmp_path).post("/v1/responses", json=finbot_request(), headers=bearer(TOKEN))
    assert response.status_code == 200
    [received] = upstream.received
    assert received.headers["authorization"] == f"Bearer {KEY}"
    assert TOKEN not in json.dumps(received.headers) and TOKEN.encode() not in received.body
    assert TOKEN not in "".join(model_inputs(tmp_path)) and TOKEN not in json.dumps(audit())
    out, err = capfd.readouterr()
    assert TOKEN not in out + err


@pytest.mark.parametrize("headers", [None, bearer("lab-dummy")])
def test_replay_refuses_a_missing_or_wrong_token_too(gateway, tmp_path, audit, headers):
    response = replay(gateway, tmp_path).post("/v1/responses", json=finbot_request(), headers=headers or {})
    assert response.status_code == 401
    assert model_inputs(tmp_path) == []
    assert not [e for e in audit() if e["acs_audit_event"] == "replay_miss"]


def test_replay_with_the_token_answers(gateway, tmp_path):
    response = replay(gateway, tmp_path).post("/v1/responses", json=finbot_request(), headers=bearer(TOKEN))
    assert response.status_code == 200
    assert response.json()["id"] == "resp_replay_miss"


def test_every_path_on_the_model_port_needs_the_token(gateway, tmp_path):
    # A wrong path answers 401 too, so the port tells a caller without the token nothing.
    client = replay(gateway, tmp_path)
    assert client.get("/v1/models").status_code == 401
    assert client.get("/v1/models", headers=bearer(TOKEN)).status_code == 404


def test_a_key_file_needs_the_client_token(tmp_path):
    with pytest.raises(ValueError, match="ACS_GATEWAY_CLIENT_TOKEN_FILE"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path),
                                "ACS_UPSTREAM_KEY_FILE": str(secret(tmp_path, "openai.key", KEY))})


@pytest.mark.parametrize("mode", [{}, {"ACS_UPSTREAM": "live"}, {"ACS_UPSTREAM": "openai"},
                                  {"ACS_UPSTREAM": "capture", "ACS_RECORDINGS_DIR": "rec"},
                                  {"ACS_CAPTURE": "1", "ACS_RECORDINGS_DIR": "rec"}])
def test_every_forwarding_mode_without_a_key_file_refuses_a_client_token(tmp_path, mode):
    # Live and capture send the client's own Authorization header upstream, so it would carry the token to a third
    # party. Only replay, which forwards nothing, takes a token without a key file.
    env = {k: str(tmp_path / v) if k == "ACS_RECORDINGS_DIR" else v for k, v in mode.items()}
    with pytest.raises(ValueError, match="ACS_GATEWAY_CLIENT_TOKEN_FILE needs ACS_UPSTREAM_KEY_FILE"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path),
                                "ACS_GATEWAY_CLIENT_TOKEN_FILE": str(token_file(tmp_path)), **env})


def run_main(monkeypatch, capsys, **env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    code = cli.main()
    return code, capsys.readouterr().err


def test_live_refuses_to_start_without_the_token_file(monkeypatch, capsys, tmp_path):
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="openai", ACS_GATEWAY_HOST="0.0.0.0",
                         ACS_UPSTREAM_KEY_SHARED="1",
                         ACS_UPSTREAM_KEY_FILE=str(secret(tmp_path, "openai.key", KEY)))
    assert code == 2
    assert "ACS_GATEWAY_CLIENT_TOKEN_FILE" in err and KEY not in err


HALF = "h" * 32


@pytest.mark.parametrize(("text", "mode", "why"), [
    (TOKEN, 0o644, "0600"),
    ("short", 0o600, "32 bytes"),
    ("t" * 5000, 0o600, "4096 bytes"),
    (f"{HALF}\n{HALF}", 0o600, "one line"),
    (f"{HALF} {HALF}", 0o600, "one line"),
    (f" {TOKEN}", 0o600, "one line"),
    (f"{HALF}\x07{HALF}", 0o600, "one line"),
    (f"{TOKEN}\r", 0o600, "one line"),
])
def test_a_bad_token_file_stops_startup(monkeypatch, capsys, tmp_path, text, mode, why):
    # A header can't carry a newline, a space splits the scheme from the token, and a control character never
    # survives a client library. Each would leave every client with a 401 and the operator with no clue, so startup
    # refuses the file and says why, without the file's content.
    monkeypatch.setattr(cli, "_serve", _never_serve)
    (tmp_path / "rec").mkdir()
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"),
                         ACS_GATEWAY_CLIENT_TOKEN_FILE=str(secret(tmp_path, "client.token", text, mode)))
    assert code == 2
    assert why in err and text.strip() not in err and HALF not in err


async def _never_serve(servers):
    raise AssertionError("startup should have been refused before serving")


def test_a_token_file_with_one_trailing_newline_loads(tmp_path):
    from acs_gateway.app import load_client_token

    assert load_client_token(token_file(tmp_path)) == TOKEN


@pytest.mark.parametrize("other", ["ACS_GATEWAY_ADMIN_TOKEN_FILE", "ACS_GATEWAY_APPROVER_TOKEN_FILE"])
def test_the_client_token_must_differ_from_the_admin_and_approver_tokens(tmp_path, other):
    # The model port's client is the governed agent. Holding the approver secret would let it release its own held
    # calls, and the admin secret would let it reset the epoch.
    from acs_gateway.app import check_distinct_tokens

    shared = token_file(tmp_path)
    config = GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path), "ACS_UPSTREAM": "replay",
                                     "ACS_RECORDINGS_DIR": str(tmp_path), "ACS_GATEWAY_CLIENT_TOKEN_FILE": str(shared)})
    field = {"ACS_GATEWAY_ADMIN_TOKEN_FILE": "admin_token_file",
             "ACS_GATEWAY_APPROVER_TOKEN_FILE": "approver_token_file"}[other]
    copy = secret(tmp_path, "other.token", TOKEN)
    with pytest.raises(ValueError) as raised:
        check_distinct_tokens(replace(config, **{field: copy}))
    assert "ACS_GATEWAY_CLIENT_TOKEN_FILE" in str(raised.value) and other in str(raised.value)
    assert TOKEN not in str(raised.value)
    check_distinct_tokens(replace(config, **{field: secret(tmp_path, "distinct.token", "d" * 64)}))


def test_startup_refuses_an_admin_token_equal_to_the_client_token(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "_serve", _never_serve)
    (tmp_path / "rec").mkdir()
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"),
                         ACS_GATEWAY_STATE_DIR=str(tmp_path), ACS_GATEWAY_CLIENT_TOKEN_FILE=str(token_file(tmp_path)),
                         ACS_GATEWAY_ADMIN_PORT="0", ACS_GATEWAY_ADMIN_TOKEN_FILE=str(secret(tmp_path, "a.token", TOKEN)))
    assert code == 2
    assert "ACS_GATEWAY_ADMIN_TOKEN_FILE" in err and TOKEN not in err


def drive_gate(scope: dict, received: list | None = None) -> tuple[list, list]:
    """Runs ClientTokenGate on a raw ASGI scope. Returns the scopes the inner app saw and the messages sent back.
    Each call the gate makes to receive is appended to received when given."""
    import asyncio

    from acs_gateway.app import ClientTokenGate

    reached: list = []
    sent: list = []

    async def inner(scope, receive, send):
        reached.append(scope["type"])

    async def receive():
        if received is not None:
            received.append(scope["type"])
        if scope["type"] == "http":
            return {"type": "http.request", "body": b"{}", "more_body": False}
        return {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)

    asyncio.run(ClientTokenGate(inner, TOKEN)(scope, receive, send))
    return reached, sent


@pytest.mark.parametrize("headers", [[], [(b"authorization", f"Bearer {TOKEN}".encode())]])
def test_the_gate_refuses_a_websocket_even_with_the_token(audit, headers):
    # The router has no websocket route today. The gate refuses the scope itself, so one added later is never ungated.
    reached, sent = drive_gate({"type": "websocket", "path": "/v1/responses", "headers": headers})
    assert reached == []
    assert [m["type"] for m in sent] == ["websocket.close"]
    [event] = [e for e in audit() if e["acs_audit_event"] == "client_unauthorized"]
    assert event["cause"] == "websocket"
    assert TOKEN not in json.dumps(audit())


def test_the_gate_refuses_an_unknown_scope_type():
    reached, sent = drive_gate({"type": "webtransport", "path": "/", "headers": []})
    assert reached == [] and sent == []


def test_the_gate_passes_lifespan_through():
    reached, _ = drive_gate({"type": "lifespan"})
    assert reached == ["lifespan"]


def http_scope(*headers: tuple[bytes, bytes]) -> dict:
    return {"type": "http", "method": "POST", "path": "/v1/responses", "headers": list(headers),
            "query_string": b"", "http_version": "1.1", "scheme": "http"}


GOOD = (b"authorization", f"Bearer {TOKEN}".encode())


@pytest.mark.parametrize("headers", [(), ((b"authorization", b"Bearer lab-dummy"),)])
def test_a_refused_request_never_reads_the_body(headers):
    # The check runs on the headers alone, so a caller without the token can't make the gateway buffer or
    # decompress a body. A gate that drained receive first would still refuse, and this test is what catches it.
    received: list = []
    reached, sent = drive_gate(http_scope(*headers), received)
    assert received == []
    assert reached == []
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 401


def test_an_accepted_request_leaves_the_body_to_the_app():
    received: list = []
    reached, _ = drive_gate(http_scope(GOOD), received)
    assert reached == ["http"] and received == []


def test_two_authorization_headers_are_refused_even_when_both_hold_the_token(audit):
    # Proxies and servers disagree on which of two headers wins, so the gate takes exactly one.
    reached, sent = drive_gate(http_scope(GOOD, GOOD))
    assert reached == []
    assert sent[0]["status"] == 401
    [event] = [e for e in audit() if e["acs_audit_event"] == "client_unauthorized"]
    assert event["cause"] == "wrong"


def test_the_gate_compares_the_token_in_constant_time(monkeypatch):
    # A plain == can return at the first differing byte, which leaks the token a byte at a time to a caller who
    # times the 401. The gate must use hmac.compare_digest, so this spies on it.
    import hmac

    from acs_gateway import app as app_module

    calls: list = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(app_module.hmac, "compare_digest", spy)
    reached, _ = drive_gate(http_scope(GOOD))
    assert reached == ["http"]
    assert calls == [(GOOD[1], GOOD[1])]
    calls.clear()
    reached, _ = drive_gate(http_scope((b"authorization", b"Bearer " + b"x" * 64)))
    assert reached == [] and len(calls) == 1
