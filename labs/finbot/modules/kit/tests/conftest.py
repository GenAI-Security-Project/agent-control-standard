"""Test setup for the module 7 kit (issue #589, LAB-16 Task 12).

The kit runs as files the lab CLI loads by path, so the tests put the kit's own directory and the module checks'
test helpers on sys.path. Importing fixtures then adds the checks directory, the CLI and the gateway's source tree.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKS_TESTS = HERE.parents[1] / "checks" / "tests"

for _path in (HERE, CHECKS_TESTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
