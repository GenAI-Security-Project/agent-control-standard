"""The viewer's HTTP server: a localhost bind, a polling API, the paint log, and nothing a foreign page can use.

A localhost bind alone doesn't stop a page on another site from reaching the viewer through DNS rebinding, so every
request must name a loopback host, and the one write, the paint log, must come from the page's own origin.
"""
from __future__ import annotations

import http.client
import json
import os
import threading

import pytest

import server as viewer_server
from lab_lines import SESSION_A, LabLogs, answer, tool_request
from model import Model


@pytest.fixture
def static_dir(tmp_path):
    directory = tmp_path / "static"
    directory.mkdir()
    (directory / "index.html").write_text("<!doctype html><title>viewer</title>", encoding="utf-8")
    (directory / "app.js").write_text("// app", encoding="utf-8")
    (tmp_path / "secret.py").write_text("SECRET = 1", encoding="utf-8")
    return directory


@pytest.fixture
def logs(tmp_path):
    return LabLogs(tmp_path / "state")


@pytest.fixture
def start(static_dir, logs):
    servers = []

    def run(paint_log=None):
        model = Model(logs.transcript_dir, logs.audit_file, None, verify_dir=logs.verify_dir)
        httpd = viewer_server.make_server("127.0.0.1", 0, model, static_dir, paint_log)
        threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        servers.append(httpd)
        return httpd.server_address[1]

    yield run
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def call(port, method, path, *, host=None, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    sent = {"Host": f"127.0.0.1:{port}" if host is None else host, **(headers or {})}
    conn.request(method, path, body=body, headers=sent)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, dict(response.getheaders()), data


def rows(port, after=0):
    status, _, data = call(port, "GET", f"/api/rows?after={after}")
    assert status == 200
    return json.loads(data)


def paint(port, body, *, origin="same", host=None):
    host = host or f"127.0.0.1:{port}"
    headers = {"Content-Type": "application/json"}
    if origin == "same":
        headers["Origin"] = f"http://{host}"
    elif origin is not None:
        headers["Origin"] = origin
    return call(port, "POST", "/api/paint", host=host, headers=headers, body=json.dumps(body))


def test_default_bind_is_loopback(monkeypatch, logs):
    seen = {}

    def fake_make_server(host, port, model, static_dir, paint_log):
        seen.update(host=host, port=port, paint_log=paint_log)
        raise SystemExit(0)

    monkeypatch.setattr(viewer_server, "make_server", fake_make_server)
    monkeypatch.setenv("ACS_TRANSCRIPT_DIR", str(logs.transcript_dir))
    monkeypatch.delenv("ACS_VIEWER_PAINT_LOG", raising=False)
    with pytest.raises(SystemExit):
        viewer_server.main([])
    assert seen == {"host": "127.0.0.1", "port": 8095, "paint_log": None}


def test_main_refuses_without_a_transcript_directory(monkeypatch, capsys):
    monkeypatch.delenv("ACS_TRANSCRIPT_DIR", raising=False)
    assert viewer_server.main([]) == 2
    assert "ACS_TRANSCRIPT_DIR" in capsys.readouterr().err


def test_main_prints_the_listening_line(monkeypatch, capsys, logs, static_dir):
    monkeypatch.setenv("ACS_TRANSCRIPT_DIR", str(logs.transcript_dir))
    monkeypatch.setattr(viewer_server, "STATIC_DIR", static_dir)
    monkeypatch.setattr(viewer_server, "serve", lambda httpd: httpd.server_close())
    assert viewer_server.main(["--port", "0"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ACS_VIEWER_LISTENING port=") and out.count("\n") == 1


def test_new_lines_appear_without_reload(start, logs):
    port = start()
    first = rows(port)
    assert first["rows"] == [] and first["no_record"] is True
    req = tool_request("finmail__send_email")
    logs.pair(req, answer(req, "deny", reason_codes=["external_recipient"]))
    second = rows(port, first["next"])
    [row] = second["rows"]
    assert (row["session_id"], row["tool"], row["decision"], row["beat"]) == (
        SESSION_A, "finmail__send_email", "deny", "deny")
    assert set(row) == {"id", "seq", "t", "session_id", "method", "tool", "decision", "reason_codes", "algorithm",
                        "verify", "note", "beat"}
    assert second["no_record"] is False
    assert rows(port, second["next"])["rows"] == []


def test_rows_are_escaped_on_the_wire(start, logs):
    port = start()
    req = tool_request("send\x1b[2J")
    logs.pair(req, answer(req, "deny"))
    _, _, data = call(port, "GET", "/api/rows?after=0")
    assert b"\x1b" not in data and b"\\\\x1b" in data


def test_bad_after_is_refused(start):
    port = start()
    for query in ("after=-1", "after=x", "after=1&after=2", ""):
        assert call(port, "GET", f"/api/rows?{query}")[0] == 400


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8095", "127.0.0.1.evil.example", "", "localhost.",
                                  "10.0.0.1:8095"])
def test_foreign_host_header_refused(start, host):
    port = start()
    for path in ("/", "/api/rows?after=0", "/static/app.js"):
        assert call(port, "GET", path, host=host)[0] == 403


@pytest.mark.parametrize("host", ["localhost:{port}", "127.0.0.1:{port}", "[::1]:{port}", "localhost:18095"])
def test_loopback_host_names_are_served(start, host):
    port = start()
    # A published port can differ from the one the viewer binds in its container, so only the name is checked.
    assert call(port, "GET", "/", host=host.format(port=port))[0] == 200


def test_cross_origin_paint_refused(start, tmp_path):
    log = tmp_path / "paint.jsonl"
    port = start(paint_log=log)
    assert paint(port, {"step": 0, "text": "x"}, origin="http://evil.example")[0] == 403
    assert paint(port, {"step": 0, "text": "x"}, origin=None)[0] == 403
    assert paint(port, {"step": 0, "text": "x"}, origin="null")[0] == 403
    assert not log.exists()


def test_paint_off_by_default(start, tmp_path):
    port = start()
    assert paint(port, {"step": 0, "text": "x"})[0] == 404
    assert rows(port)["paint"] is False
    assert list(tmp_path.rglob("*paint*")) == []


def test_paint_line_shape(start, tmp_path):
    log = tmp_path / "paint.jsonl"
    port = start(paint_log=log)
    assert rows(port)["paint"] is True
    assert paint(port, {"step": 3, "text": "deny \x1b[31m finmail__send_email"})[0] == 204
    assert paint(port, {"step": "end", "text": ""})[0] == 204
    first, end = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert set(first) == {"step", "t", "text"} and first["step"] == 3
    assert first["text"] == "deny \\x1b[31m finmail__send_email"
    assert first["t"].endswith("Z") and len(first["t"]) == len("2026-12-09T10:00:00.000Z")
    assert end["step"] == "end" and set(end) == {"step", "t"}
    assert os.stat(log).st_mode & 0o777 == 0o600


@pytest.mark.parametrize("body", [{"step": 13, "text": "x"}, {"step": -1, "text": "x"}, {"step": True, "text": "x"},
                                  {"step": "3", "text": "x"}, {"step": 1}, {"step": 1, "text": 5}, ["step"]])
def test_bad_paint_is_refused(start, tmp_path, body):
    log = tmp_path / "paint.jsonl"
    port = start(paint_log=log)
    assert paint(port, body)[0] == 400
    assert not log.exists()


def test_static_path_traversal_refused(start):
    port = start()
    for path in ("/static/../secret.py", "/static/%2e%2e/secret.py", "/static/../../server.py",
                 "/static/missing.js", "/static/", "/secret.py", "/static/app.js/"):
        assert call(port, "GET", path)[0] == 404, path
    assert call(port, "GET", "/static/app.js")[0] == 200


def test_every_response_carries_the_safety_headers(start):
    port = start()
    for path in ("/", "/static/app.js", "/api/rows?after=0", "/nothing"):
        _, headers, _ = call(port, "GET", path)
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Content-Security-Policy"].startswith("default-src 'self'")
    _, headers, _ = call(port, "GET", "/", host="evil.example")
    assert headers["Cache-Control"] == "no-store"


def test_viewer_never_writes_logs(start, logs):
    req = tool_request("echo")
    logs.pair(req, answer(req, "allow"))
    logs.audit("decision_applied", session_id=SESSION_A, epoch=0, method=req["method"], tool="echo", call_id="c1",
               request_id=req["params"]["request_id"], decision="allow", guardian_decision="allow",
               reason_codes=None, cause=None, failure_class=None)
    files = [logs.transcript(), logs.audit_file]
    before = {path: (path.read_bytes(), os.stat(path).st_mtime_ns, os.stat(path).st_mode) for path in files}
    port = start()
    for _ in range(5):
        rows(port)
    assert {path: (path.read_bytes(), os.stat(path).st_mtime_ns, os.stat(path).st_mode) for path in files} == before
    assert sorted(p.name for p in logs.root.rglob("*")) == sorted(
        ["audit.log", "transcripts", logs.transcript().name])
