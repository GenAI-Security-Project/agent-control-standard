import pytest
from starlette.testclient import TestClient

from acs_gateway.app import create_admin_app, load_admin_token
from conftest import call_item, finbot_request, response_body, transcript_lines


def gated_requests(tmp_path):
    return [line["envelope"]["params"] for line in transcript_lines(tmp_path)
            if line["envelope"].get("method") == "steps/toolCallRequest"]


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "admin.token"
    path.write_text("t" * 40)
    path.chmod(0o600)
    return path


def test_an_epoch_bump_gates_a_seen_call_id_afresh_under_a_new_session(gateway, guardian, upstream, tmp_path,
                                                                       token_file, audit):
    reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    admin = TestClient(create_admin_app(client.app.state.gateway, load_admin_token(token_file)))
    upstream.reply(reply)
    client.post("/v1/responses", json=finbot_request())
    upstream.reply(reply)
    client.post("/v1/responses", json=finbot_request())
    assert len(gated_requests(tmp_path)) == 1
    bumped = admin.post("/epoch", headers={"Authorization": f"Bearer {'t' * 40}"})
    assert bumped.status_code == 200 and bumped.json() == {"epoch": 1}
    upstream.reply(reply)
    client.post("/v1/responses", json=finbot_request())
    requests = gated_requests(tmp_path)
    assert len(requests) == 2
    assert requests[0]["metadata"]["session_id"] != requests[1]["metadata"]["session_id"]
    assert [e["epoch"] for e in audit() if e["acs_audit_event"] == "epoch_bumped"] == [1]


def test_the_epoch_bump_refuses_a_wrong_token(gateway, guardian, token_file):
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian)
    admin = TestClient(create_admin_app(client.app.state.gateway, load_admin_token(token_file)))
    assert admin.post("/epoch", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert admin.post("/epoch").status_code == 401
    assert admin.get("/epoch").status_code == 405


def test_an_admin_token_file_others_can_read_is_refused(token_file):
    token_file.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        load_admin_token(token_file)


def test_a_short_admin_token_is_refused(tmp_path):
    path = tmp_path / "short.token"
    path.write_text("abc")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="32"):
        load_admin_token(path)


def test_an_admin_token_file_owned_by_another_user_is_refused(token_file, monkeypatch):
    real = token_file.stat().st_uid
    monkeypatch.setattr("os.geteuid", lambda: real + 1)
    with pytest.raises(ValueError, match="owned by uid"):
        load_admin_token(token_file)


def test_a_symlinked_admin_token_file_is_refused(token_file, tmp_path):
    link = tmp_path / "link.token"
    link.symlink_to(token_file)
    with pytest.raises(ValueError, match="symlink"):
        load_admin_token(link)
