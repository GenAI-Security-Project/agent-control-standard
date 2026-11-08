"""One conformance run against a real client, without touching the ACS tree.

    real Claude Code  ->  ACS claude_code adapter (hook)  ->  example Guardian
                      ->  a controlled Anthropic /v1/messages endpoint (stub_server.py)

The ACS checkout under --acs is used as-is: it is imported from, never patched, so the version
under test is exactly the commit named in the output. The endpoint is the only thing that fakes
anything, and it fakes only the model.

Each rep gets its own temp workspace, its own Guardian on an OS-assigned port, and its own stub
port; the stub's request log, the Guardian's step log and the files the client left behind are
all written into the JSON the run produces.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HOOK_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SessionEnd")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _drain(stream, sink: list[str]) -> None:
    try:
        for line in stream:
            sink.append(line)
    except Exception:  # noqa: BLE001 - the pipe closes when the process dies; the sink keeps what it got
        pass


def _wait_listening(line_reader, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = line_reader()
        if line and "listening" in line:
            return
        time.sleep(0.05)
    raise RuntimeError("stub endpoint did not announce itself")


def _git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True).stdout.strip()


def _summarize(raw: str) -> dict:
    """What the Guardian was handed: method, ids, and the argument blob with a hash.

    The hash is what makes "these two calls are identical" checkable instead of asserted.
    """
    out: dict = {"bytes": len(raw)}
    try:
        doc = json.loads(raw)
    except Exception:
        out["unparsed"] = raw[:400]
        return out
    out["method"] = doc.get("method")
    out["id"] = doc.get("id")
    params = doc.get("params") or {}
    meta = (params.get("metadata") or {}) if isinstance(params, dict) else {}
    out["session_id"] = meta.get("session_id")
    out["request_id"] = meta.get("request_id") or params.get("request_id")
    blob = json.dumps(params, sort_keys=True, separators=(",", ":"))
    out["params_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
    payload = params.get("payload") or {}

    if out["method"] == "steps/toolCallRequest":
        # The step payload hangs off params.payload (see example_guardian.evaluate_step); the schema
        # for its shape is specification/v0.1.0/hooks/tool-call-request.json.
        tool = payload.get("tool") or {}
        out["tool_name"] = tool.get("name") if isinstance(tool, dict) else None
        args = payload.get("arguments")
        blob_args = json.dumps(args, sort_keys=True, separators=(",", ":"))
        out["arguments_sha256"] = hashlib.sha256(blob_args.encode()).hexdigest()
        out["arguments_head"] = blob_args[:240]
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acs", required=True, help="path to the ACS adapters/ directory")
    ap.add_argument("--stub", required=True, help="path to stub_server.py")
    ap.add_argument("--mode", default="complete", choices=("complete", "length", "drop", "reset", "loop"))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--prompt", default="Write report.txt with the standard 40 lines.")
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--record", action="store_true",
                    help="keep the envelopes the Guardian was handed, via a recording proxy")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv[1:])

    acs = Path(a.acs).resolve()
    sys.path.insert(0, str(acs / "src"))
    from acs.testing.harness import launch_guardian, signing_env  # noqa: E402  (needs sys.path above)

    adapter = acs / "src" / "acs" / "integrations" / "claude_code" / "adapter.py"
    if not adapter.exists():
        raise SystemExit(f"adapter not found: {adapter}")
    signing = signing_env()

    run = {
        "scenario": a.mode,
        "prompt": a.prompt,
        "acs_commit": _git(acs, "rev-parse", "HEAD"),
        "acs_dirty": _git(acs, "status", "--porcelain") != "",
        "claude_version": subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout.strip(),
        "python": sys.version.split()[0],
        "reps": [],
    }

    for rep in range(1, a.reps + 1):
        work = Path(tempfile.mkdtemp(prefix=f"acs-{a.mode}-{rep}-"))
        stub_log = work / "stub.jsonl"
        stub_port = free_port()
        stub = subprocess.Popen(
            [sys.executable, str(Path(a.stub).resolve()), str(stub_port)],
            env={**os.environ, "BENCH_LOG": str(stub_log)},
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        _wait_listening(stub.stdout.readline, 10.0)

        envelopes = work / "envelopes.jsonl"
        genv = os.environ.copy()
        genv.update(signing)
        if a.record:
            genv["ACS_ENVELOPE_LOG"] = str(envelopes)
        genv.pop("ACS_HMAC_SECRET_FILE", None)
        guardian, guardian_port = launch_guardian(env=genv)
        glog: list[str] = []
        threading.Thread(target=_drain, args=(guardian.stderr, glog), daemon=True).start()

        guardian_url = f"http://127.0.0.1:{guardian_port}/acs"

        # Project-level settings only: the runner's own ~/.claude is never touched.
        (work / ".claude").mkdir()
        hook = " ".join(
            [f"ACS_GUARDIAN_URL={guardian_url}"]
            + [f"{k}={v}" for k, v in signing.items()]
            + [f"{sys.executable} {adapter}"]
        )
        settings = {"hooks": {ev: [{"matcher": "*", "hooks": [{"type": "command", "command": hook}]}]
                              for ev in HOOK_EVENTS}}
        (work / ".claude" / "settings.json").write_text(json.dumps(settings, indent=2))

        env = {
            **os.environ,
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{stub_port}/{a.mode}",
            "ANTHROPIC_API_KEY": "sk-ant-api03-bench-placeholder",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
        started = time.time()
        try:
            proc = subprocess.run(
                ["claude", "--print", "--permission-mode", "acceptEdits", a.prompt],
                cwd=work, env=env, capture_output=True, text=True, timeout=a.timeout,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            rc, out, err = "timeout", e.stdout or "", e.stderr or ""
        elapsed = round(time.time() - started, 1)

        target = work / "report.txt"
        steps = [ln.rstrip() for ln in glog
                 if "steps/" in ln or "REFUSING" in ln or "WARNING" in ln or "handshake" in ln]
        run["reps"].append({
            "rep": rep,
            "claude_exit": rc,
            "duration_s": elapsed,
            "endpoint": env["ANTHROPIC_BASE_URL"],
            "guardian_port": guardian_port,
            "target_created": target.exists(),
            "target_bytes": target.stat().st_size if target.exists() else 0,
            "files_left": sorted(str(p.relative_to(work)) for p in work.rglob("*") if p.is_file()),
            "claude_stdout": (out or "")[-2000:],
            "claude_stderr": (err or "")[-800:],
            "stub_requests": [json.loads(ln) for ln in stub_log.read_text().splitlines()] if stub_log.exists() else [],
            "guardian_steps": steps,
            "envelopes": [_summarize(json.loads(ln)["body"])
                          for ln in envelopes.read_text().splitlines()] if envelopes.exists() else [],
        })

        for p in (guardian, stub):
            p.terminate()
            try:
                p.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                p.kill()
        print(f"[{a.mode}] rep {rep}/{a.reps}: exit={rc} target={target.exists()} "
              f"steps={len(steps)} requests={len(run['reps'][-1]['stub_requests'])}", flush=True)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(run, indent=2))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
