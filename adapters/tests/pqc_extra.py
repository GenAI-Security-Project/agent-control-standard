"""Skip a whole test module when the pqc extra is absent, with the one reason run_conformance.py expects.

The skip keys on whether the installed cryptography has ML-DSA at all, not on whether
acs.core._mldsa imports. With the extra installed, a broken _mldsa import fails the module
instead of skipping it, so a bug can't hide behind the expected skip.
"""
from __future__ import annotations

import importlib.util
import unittest

PQC_SKIP_REASON = ("the pqc extra is not installed: ML-DSA-65 needs cryptography 50 "
                   "(uv sync --extra pqc), which can't share an environment with the nat extra")


def pqc_installed() -> bool:
    try:
        return importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.mldsa") is not None
    except ModuleNotFoundError:
        return False


def require_pqc() -> None:
    """Call at module import. One ModuleSkipped entry stands for the whole module."""
    if not pqc_installed():
        raise unittest.SkipTest(PQC_SKIP_REASON)
