"""Start and stop an opa server for the opt-in real-OPA tests, and check it is the one this run started.

Not a test module. test_guardian_real_opa.py runs OPA through it, and test_opa_process.py tests the health probe.
"""
from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path

# OPA has to answer GET /health with 200 within this many seconds of starting. A TCP accept isn't enough: a
# container runtime's port proxy accepts before OPA inside it is listening.
HEALTH_DEADLINE_S = 30.0
START_ATTEMPTS = 3


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# No proxies, like opa_backend: the probe talks to 127.0.0.1 and must not follow HTTP_PROXY or a cached opener.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get_json(port: int, path: str):
    with _OPENER.open(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
        return response.status, json.loads(response.read() or b"null")


def healthy(port: int, process, label: str, *, deadline_s: float = HEALTH_DEADLINE_S) -> bool:
    """Poll GET /health until 200, then check the listener is the OPA this run started.

    Each OPA starts with a unique labels.probe, which GET /v1/config reports. A 200 from another listener on the
    port, or from a process that has since exited, doesn't count. False when time runs out.
    """
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            status, _ = _get_json(port, "/health")
            if status == 200:
                _, config = _get_json(port, "/v1/config")
                labels = ((config or {}).get("result") or {}).get("labels") or {}
                return labels.get("probe") == label and process.poll() is None
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(0.1)
    return False


def stop(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@contextlib.contextmanager
def running_opa(opa: str, policy: Path, log_dir: Path) -> Iterator[str]:
    """Start OPA on a fresh port, retrying when a start fails, as when another process took the port first.

    Yields the URL of the lab_test policy's verdict. Fails the test with each attempt's stderr when OPA never
    becomes healthy.
    """
    import pytest
    failures = []
    for attempt in range(START_ATTEMPTS):
        port = free_port()
        label = uuid.uuid4().hex
        log_path = log_dir / f"opa-{attempt}.log"
        with open(log_path, "wb") as log:
            process = subprocess.Popen([opa, "run", "--server", "--addr", f"127.0.0.1:{port}",
                                        "--set", f"labels.probe={label}", str(policy)],
                                       stdout=subprocess.DEVNULL, stderr=log)
        if healthy(port, process, label):
            try:
                yield f"http://127.0.0.1:{port}/v1/data/lab/verdict"
            finally:
                stop(process)
            return
        stop(process)
        failures.append(f"attempt {attempt + 1} on port {port}, exit {process.returncode}: "
                        f"{log_path.read_text(errors='replace')[-2000:]}")
    pytest.fail("OPA did not become healthy:\n" + "\n".join(failures))
