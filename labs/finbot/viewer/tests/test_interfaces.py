"""Pins on every stack interface the viewer reads, so a change on the other side turns red here (WAVE4 brief).

The transcript and audit line shapes are pinned by the fixtures themselves, which the gateway's Transcript writer and
acs.client's audit_event write. These tests pin the rest: the audit event names and fields the gateway emits, the
settings names, the Guardian's refusal reason, and the acs-verify functions the viewer calls. The gateway modules
that emit audit events import Starlette, which this test environment doesn't carry, so their source is read with ast.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import beats
import model
import verify
from conftest import GATEWAY_SRC, REPO_ROOT

GATEWAY = GATEWAY_SRC / "acs_gateway"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _audit_calls(path: Path) -> list[ast.Call]:
    return [node for node in ast.walk(_tree(path)) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_audit"]


def _event_names(path: Path) -> set[str]:
    names = set()
    for call in _audit_calls(path):
        first = call.args[0]
        candidates = [first.body, first.orelse] if isinstance(first, ast.IfExp) else [first]
        names |= {c.value for c in candidates if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    return names


def _literal(node: ast.AST) -> object:
    try:
        return ast.literal_eval(node)
    except ValueError:
        return None


def _dict_keys(node: ast.AST) -> set[str]:
    return {k.value for k in getattr(node, "keys", []) if isinstance(k, ast.Constant)}


def _assigned_dict(path: Path, function: str, target: str) -> set[str]:
    for node in ast.walk(_tree(path)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function:
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Dict)
                        and any(isinstance(t, ast.Name) and t.id == target for t in inner.targets)):
                    return _dict_keys(inner.value)
    raise AssertionError(f"{path.name} has no {target} dict in {function}")


def _call_keywords(path: Path, event: str) -> set[str]:
    for call in _audit_calls(path):
        if isinstance(call.args[0], ast.Constant) and call.args[0].value == event:
            return {k.arg for k in call.keywords if k.arg}
    raise AssertionError(f"{path.name} emits no {event}")


def test_the_gateway_emits_every_event_the_viewer_reads():
    emitted = _event_names(GATEWAY / "app.py") | _event_names(GATEWAY / "upstream.py")
    read = set(model.STEP_EVENTS) | set(model.ASK_EVENTS) | {model.REPLAY_MISS, model.EPOCH_BUMPED}
    assert read <= emitted, read - emitted


def test_step_event_fields():
    fields = _assigned_dict(GATEWAY / "app.py", "_record", "fields")
    assert {"session_id", "epoch", "method", "tool", "call_id", "request_id", "decision", "guardian_decision",
            "reason_codes", "cause"} <= fields


def test_ask_event_fields():
    assert {"session_id", "tool", "request_id", "approver"} <= _call_keywords(GATEWAY / "app.py", "ask_pending")
    resolved = _assigned_dict(GATEWAY / "app.py", "_resolve_ask", "resolved")
    assert {"session_id", "tool", "ask_request_id", "outcome", "decision", "cause"} <= resolved


def test_replay_miss_fields():
    tree = _tree(GATEWAY / "upstream.py")
    dicts = [_dict_keys(node) for node in ast.walk(tree) if isinstance(node, ast.Dict)]
    assert any({"cause", "step", "branch", "stream"} <= keys for keys in dicts)


def test_epoch_bump_and_audit_line_format():
    assert _call_keywords(GATEWAY / "app.py", "epoch_bumped") == {"epoch"}
    from acs.client import _audit
    source = inspect.getsource(_audit)
    assert '"ACS_AUDIT "' in source and model.AUDIT_PREFIX == b"ACS_AUDIT "
    assert '"acs_audit_event"' in source and '"timestamp"' in source


def test_transcript_writer_shape():
    from acs_gateway import transcript
    assert transcript.DIRECTIONS == ("req", "resp")
    assert {"cause", "discards"} <= set(inspect.signature(transcript.Transcript.append).parameters)
    # The discards line and the late cause, as the gateway README's Records section states them.
    readme = (REPO_ROOT / "adapters" / "gateway" / "README.md").read_text(encoding="utf-8")
    assert f'{{"dir": "resp", "envelope": null, "cause": "{model.LATE_CAUSE}", "discards": "<request_id>"}}' in readme


def test_settings_names():
    config = (GATEWAY / "config.py").read_text(encoding="utf-8")
    assert 'env.get("ACS_TRANSCRIPT_DIR"' in config
    from acs.client import _audit, _key_document
    assert 'os.environ.get("ACS_AUDIT_FILE"' in inspect.getsource(_audit)
    assert (verify.KEY_DOCUMENT_ENV, verify.KEY_ID_ENV, verify.KEY_FINGERPRINT_ENV) == (
        _key_document.KEY_DOCUMENT_ENV, _key_document.KEY_ID_ENV, _key_document.KEY_FINGERPRINT_ENV)
    server = (Path(model.__file__).parent / "server.py").read_text(encoding="utf-8")
    for name in ("ACS_TRANSCRIPT_DIR", "ACS_AUDIT_FILE", "ACS_VIEWER_PAINT_LOG", "ACS_VIEWER_VERIFY_DIR"):
        assert f'"{name}"' in server


def test_guardian_refusal_and_method_names():
    from acs.guardian._chain import HANDSHAKE_METHOD
    assert model.HANDSHAKE_METHOD == HANDSHAKE_METHOD
    guardian = _tree(REPO_ROOT / "adapters" / "src" / "acs" / "guardian" / "example_guardian.py")
    constants = {t.id: node.value.value for node in ast.walk(guardian) if isinstance(node, ast.Assign)
                 and isinstance(node.value, ast.Constant) for t in node.targets if isinstance(t, ast.Name)}
    assert constants["UNSUPPORTED_SIGNATURE_ALGORITHM"] == beats.DOWNGRADE_REASON
    refusal = [node for node in ast.walk(guardian) if isinstance(node, ast.Call)
               and getattr(node.func, "id", None) == "GuardianError"
               and node.args and _literal(node.args[0]) == beats.DOWNGRADE_CODE
               and any(k.arg == "data" and "reason" in _dict_keys(k.value) for k in node.keywords)]
    assert refusal


def test_acs_verify_functions_the_viewer_calls():
    from acs.testing import verify as acs_verify
    parameters = inspect.signature(acs_verify.verify_transcript).parameters
    assert {"key_document", "hmac_secret", "expect_fingerprints", "key_id", "keys_only"} <= set(parameters)
    assert callable(acs_verify._read_key_document) and issubclass(acs_verify.UsageError, Exception)
    assert {"ok", "failure"} <= set(acs_verify.Report.__dataclass_fields__)


def test_the_key_document_reader_and_parser_the_viewer_calls():
    # Final review R9: one read through acs.client's trusted-file reader, parsed by acs-verify's strict JSON reader.
    from acs.client import not_writable_by_others, read_trusted_file
    from acs.testing import verify as acs_verify
    assert callable(read_trusted_file) and callable(not_writable_by_others)
    assert {"setting", "max_bytes", "mode_rule", "refused", "require_owner"} <= set(
        inspect.signature(read_trusted_file).parameters)
    assert callable(acs_verify._strict_loads)
