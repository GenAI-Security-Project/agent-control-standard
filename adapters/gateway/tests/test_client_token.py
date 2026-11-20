"""The model port's client token.

With a key file, anyone who reaches the model port spends the operator's key. On a Linux host that is every local user,
through the bridge network, so the port takes a bearer token from ACS_GATEWAY_CLIENT_TOKEN_FILE, checked before
any upstream call or key swap, in replay as in live.
"""
import json

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


def test_live_without_a_key_file_refuses_a_client_token(tmp_path):
    # The client's own Authorization header goes upstream in that mode, so it would carry the token there.
    with pytest.raises(ValueError, match="ACS_GATEWAY_CLIENT_TOKEN_FILE"):
        GatewayConfig.from_env({"ACS_GATEWAY_STATE_DIR": str(tmp_path),
                                "ACS_GATEWAY_CLIENT_TOKEN_FILE": str(token_file(tmp_path))})


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


@pytest.mark.parametrize(("text", "mode", "why"), [(TOKEN, 0o644, "0600"), ("short", 0o600, "32 bytes")])
def test_a_bad_token_file_stops_startup(monkeypatch, capsys, tmp_path, text, mode, why):
    (tmp_path / "rec").mkdir()
    code, err = run_main(monkeypatch, capsys, ACS_UPSTREAM="replay", ACS_RECORDINGS_DIR=str(tmp_path / "rec"),
                         ACS_GATEWAY_CLIENT_TOKEN_FILE=str(secret(tmp_path, "client.token", text, mode)))
    assert code == 2
    assert why in err and text not in err


def drive_gate(scope: dict) -> tuple[list, list]:
    """Runs ClientTokenGate on a raw ASGI scope. Returns the scopes the inner app saw and the messages sent back."""
    import asyncio

    from acs_gateway.app import ClientTokenGate

    reached: list = []
    sent: list = []

    async def inner(scope, receive, send):
        reached.append(scope["type"])

    async def receive():
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
