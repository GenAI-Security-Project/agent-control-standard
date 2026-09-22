"""Command-line entry point.

Environment variables mirror the deployment surface the conformance harness
configures: ``ACS_GUARDIAN_HMAC_SECRET_FILE`` (the shared key material),
``ACS_GUARDIAN_KEY_ID``, ``ACS_GUARDIAN_HOST``, ``ACS_GUARDIAN_PORT``, and
``ACS_ON_DECISION_FAILURE``. Flags override the environment.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .schemas import SPEC_ROOT_ENV
from .server import Guardian, GuardianConfig, serve

DEFAULT_KEY_ID = "conformance"


def _build_config(args: argparse.Namespace) -> GuardianConfig:
    secret_file = args.secret_file or os.environ.get("ACS_GUARDIAN_HMAC_SECRET_FILE")
    if not secret_file:
        raise SystemExit(
            "no HMAC secret: pass --secret-file or set ACS_GUARDIAN_HMAC_SECRET_FILE "
            "(the file's bytes are the HKDF input keying material, 32 bytes minimum)"
        )
    secret = Path(secret_file).read_bytes()
    return GuardianConfig(
        secret=secret,
        key_id=args.key_id or os.environ.get("ACS_GUARDIAN_KEY_ID", DEFAULT_KEY_ID),
        on_decision_failure=args.posture or os.environ.get("ACS_ON_DECISION_FAILURE", "proceed"),
        timeout_ms=args.timeout_ms,
        skew_window_ms=args.skew_window_ms,
        policy_requires_provenance=args.require_provenance,
        spec_root=Path(args.spec_root) if args.spec_root else None,
        host=args.host or os.environ.get("ACS_GUARDIAN_HOST", "127.0.0.1"),
        # `is not None`, not `or`: --port 0 asks the OS for a free port and is falsy.
        port=args.port if args.port is not None else int(os.environ.get("ACS_GUARDIAN_PORT", "8787")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acs-guardian", description="ACS v0.1.0 reference Guardian")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser("serve", help="serve the ACS wire endpoint")
    serve_parser.add_argument("--secret-file", help="file holding the HKDF input keying material")
    serve_parser.add_argument("--key-id", help="key_id carried in signatures (default: conformance)")
    serve_parser.add_argument("--host", help="bind address (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, help="bind port (default: 8787)")
    serve_parser.add_argument("--posture", choices=["proceed", "deny"], help="on_decision_failure")
    serve_parser.add_argument("--timeout-ms", type=int, default=5000)
    serve_parser.add_argument("--skew-window-ms", type=int, default=300_000)
    serve_parser.add_argument("--require-provenance", action="store_true")
    serve_parser.add_argument("--spec-root", help=f"override the schema root (default: ${SPEC_ROOT_ENV} or the repository's)")

    args = parser.parse_args(argv)
    if args.command == "serve":
        config = _build_config(args)
        guardian = Guardian(config)
        server = serve(guardian)
        print(f"acs-guardian serving {server.url}", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
