"""The example Guardian must start wherever the specification says ACS is deployable (§11).

On POSIX the state file is guarded with flock(2); on Windows fcntl does not exist, so the same
three operations map onto msvcrt byte-range locks (the idiom client/_store.py already uses).
"""
from __future__ import annotations

import os

from acs.guardian import example_guardian


def test_module_imports_on_this_platform():
    # Importing at all is the regression test: a bare `import fcntl` fails on Windows.
    assert hasattr(example_guardian, "_flock")


def test_locks_round_trip(tmp_path):
    path = tmp_path / "state.lock"
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        example_guardian._flock(fd, "ex")
        example_guardian._flock(fd, "un")
        example_guardian._flock(fd, "sh")
        example_guardian._flock(fd, "un")
    finally:
        os.close(fd)
