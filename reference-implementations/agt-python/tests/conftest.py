"""Test fixtures: an in-process Guardian and a live HTTP server on a random port."""

from __future__ import annotations

import threading

import pytest

from acs_guardian.server import Guardian, GuardianConfig, serve

from helpers import SECRET


@pytest.fixture()
def guardian() -> Guardian:
    # port 0: the HTTP fixture below binds a free port rather than a fixed one.
    return Guardian(GuardianConfig(secret=SECRET, port=0))


@pytest.fixture()
def server(guardian: Guardian):
    httpd = serve(guardian)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
