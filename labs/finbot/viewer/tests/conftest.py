"""Test setup for the decision viewer (issue #586).

The viewer modules live one directory up and are run as plain scripts in the lab image, so the tests put that
directory on sys.path. The gateway's transcript writer is stdlib only, so its source tree goes on the path too and
every fixture line is written by the gateway's own code.
"""
from __future__ import annotations

import sys
from pathlib import Path

VIEWER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]
GATEWAY_SRC = REPO_ROOT / "adapters" / "gateway" / "src"

for path in (VIEWER_DIR, Path(__file__).resolve().parent, GATEWAY_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
