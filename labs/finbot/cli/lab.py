"""The FinBot lab CLI, run inside the lab container as `python /opt/lab/cli/lab.py <command>` (issue #588, LAB-15).

Version 1.0.0. Owner: Rock Lambros. The host never runs this file. lab.sh hands it every verb that isn't a Docker
lifecycle verb through `docker compose run --rm lab`. Commands live in commands.COMMANDS.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Run by path, so the sibling modules import without a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commands  # noqa: E402
import report  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    try:
        return commands.dispatch(sys.argv[1:] if argv is None else argv)
    except KeyboardInterrupt:
        report.not_yet("interrupted")
        return report.EXIT_NOT_YET
    except Exception as e:  # noqa: BLE001
        # Any crash is a broken environment by the A.11 contract, and gets one line rather than a traceback.
        report.not_yet(f"lab hit an error it didn't expect: {type(e).__name__}: {e}")
        return report.EXIT_BROKEN


if __name__ == "__main__":
    sys.exit(main())
