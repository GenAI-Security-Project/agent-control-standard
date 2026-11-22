"""The lab CLI's commands (issue #588, LAB-15, Appendix A.11). Standard library only.

Each command takes its arguments and returns an exit code from report: 0 pass, 1 not yet, 2 the environment is
broken. LAB-16's lab_modules adds check, policy, _drive, forge, verify and downgrade to COMMANDS.

Paths: LAB_BUNDLE names the bind-mounted labs/finbot directory (/lab in the container). The CLI writes only under it:
state/, .env, replay/recordings/ and, through lab pins and lab policy, policy/data.json and the live .rego files.
"""
from __future__ import annotations

import collections
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import report

HERE = Path(__file__).resolve().parent
# LAB-03's key generator: writes guardian.key and guardian-keys.json into a new directory and prints
# fingerprint=sha256:<hex> first. Lab convention until issue #460.
DECISION_KEYS = [sys.executable, "-m", "acs.guardian.decision_keys"]
GUARDIAN_KEY_ID = "lab-guardian-1"
GUARDIAN_ID = "lab-guardian"
# LAB-12's pins builder imports acs_gateway, so it runs in the gateway's environment.
GATEWAY_PYTHON = os.environ.get("LAB_GATEWAY_PYTHON", "/opt/acs/gateway/.venv/bin/python")
# LAB-10's results table, copied into the image.
BENCH_FILE = HERE.parent / "docs" / "signature-benchmark.md"
ADMIN_TIMEOUT_S = 10.0

# .env settings each `lab <name> <value>` writes. A value of None removes the key.
SETTINGS: dict[str, dict[str, dict[str, str | None]]] = {
    "mode": {v: {"ACS_LAB_MODE": v} for v in ("off", "shadow", "enforce")},
    "upstream": {v: {"ACS_UPSTREAM": v} for v in ("replay", "openai")},
    "sign": {
        "hmac": {"ACS_RESPONSE_SIGNING": "HMAC-SHA256", "ACS_RESPONSE_ALGORITHMS": "HMAC-SHA256"},
        "mldsa": {"ACS_RESPONSE_SIGNING": "ML-DSA-65", "ACS_RESPONSE_ALGORITHMS": "ML-DSA-65"},
    },
    "traces": {
        "on": {"COMPOSE_PROFILES": "traces", "LAB_OTLP_ENDPOINT": "http://jaeger:4318"},
        "off": {"COMPOSE_PROFILES": None, "LAB_OTLP_ENDPOINT": None},
    },
}
DEFAULTS = {"ACS_LAB_MODE": "enforce", "ACS_UPSTREAM": "replay", "ACS_RESPONSE_SIGNING": "ML-DSA-65",
            "ACS_RESPONSE_ALGORITHMS": "ML-DSA-65"}
SECRET_FILES = ("hmac.key", "guardian.key", "admin.token", "approver.token", "client.token")
# FinBot's bearer for the gateway's model port (final review R8). init writes it to state/secrets for the gateway and
# to .env, where compose passes it to FinBot as OPENAI_API_KEY.
CLIENT_TOKEN = "LAB_CLIENT_TOKEN"
# The pin lab verify and lab check 7 pass to acs-verify as --expect-fingerprint (LAB-16). It lives in .env, which the
# gateway and the Guardian don't mount, because the gateway can write state/ and a forger holding its files could
# otherwise pick the key. Only the one-shot lab CLI container mounts the bundle, .env included.
GUARDIAN_FINGERPRINT = "LAB_GUARDIAN_FINGERPRINT"
FINGERPRINT_FORMAT = re.compile(r"sha256:[0-9a-f]{64}")
# The attendee's own model key, pasted in by hand for `lab upstream openai`. lab init can't make it again, so lab reset
# keeps it unless told otherwise.
MODEL_KEY = "openai.key"
DELETE_MODEL_KEY = "--delete-model-key"


def bundle() -> Path:
    return Path(os.environ.get("LAB_BUNDLE") or HERE.parent)


def state() -> Path:
    return bundle() / "state"


# ---------------------------------------------------------------------------------------------------------------------
# .env
# ---------------------------------------------------------------------------------------------------------------------

def _read_env(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def _env_values(lines: list[str]) -> dict[str, str]:
    return dict(line.split("=", 1) for line in lines if "=" in line and not line.lstrip().startswith("#"))


def update_env(changes: dict[str, str | None], *, only_missing: bool = False) -> None:
    """Set or remove keys in .env, keeping every other line, comments and port overrides included."""
    path = bundle() / ".env"
    lines = _read_env(path)
    present = _env_values(lines)
    if only_missing:
        changes = {k: v for k, v in changes.items() if k not in present}
    kept = [line for line in lines if line.split("=", 1)[0] not in changes or line.lstrip().startswith("#")]
    kept += [f"{key}={value}" for key, value in changes.items() if value is not None]
    # Replaced in one rename, so compose never reads a half-written file.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".env.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("".join(f"{line}\n" for line in kept))
    # Owner-only, since .env holds FinBot's client token. compose and the lab CLI read it as the attendee.
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------------------------------------------------

def _write_secret(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(text)
    os.chmod(path, 0o600)


def cmd_init(args: list[str]) -> int:
    """Creates state/, the HMAC secret, the admin, approver and client tokens, the Guardian key and key document,
    and .env."""
    force = "--force" in args
    unknown = [a for a in args if a != "--force"]
    if unknown:
        report.not_yet(f"lab init takes only --force, got {' '.join(unknown)}")
        return report.EXIT_BROKEN
    root = state()
    secrets_dir = root / "secrets"
    keys_dir = root / "keys"
    existing = [name for name in SECRET_FILES if (secrets_dir / name).exists()]
    if existing and not force:
        report.not_yet(f"lab is already initialized ({', '.join(existing)} exist). Run ./lab.sh init --force to "
                       "replace every key, which breaks any transcript signed with the old ones")
        return report.EXIT_NOT_YET
    for directory in (root, keys_dir, root / "transcripts", root / "verify", bundle() / "replay" / "recordings"):
        directory.mkdir(parents=True, exist_ok=True)
    for directory in (secrets_dir, root / "guardian"):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    for name in SECRET_FILES:
        (secrets_dir / name).unlink(missing_ok=True)
    (keys_dir / "guardian-keys.json").unlink(missing_ok=True)

    # 32 random bytes as hex: acs.client wants at least 32 bytes in the HMAC secret, the gateway in its tokens.
    _write_secret(secrets_dir / "hmac.key", secrets.token_hex(32) + "\n")
    _write_secret(secrets_dir / "admin.token", secrets.token_hex(32) + "\n")
    _write_secret(secrets_dir / "approver.token", secrets.token_hex(32) + "\n")
    client_token = secrets.token_hex(32)
    _write_secret(secrets_dir / "client.token", client_token + "\n")

    # The generator refuses an existing directory, so it writes into a fresh one beside the secrets, on the same
    # filesystem, and each file moves into place with a rename.
    workdir = Path(tempfile.mkdtemp(prefix=".keygen-", dir=secrets_dir))
    out_dir = workdir / "out"
    try:
        result = subprocess.run([*DECISION_KEYS, "--out-dir", str(out_dir), "--key-id", GUARDIAN_KEY_ID,
                                 "--guardian-id", GUARDIAN_ID], capture_output=True, text=True, timeout=120)
        fingerprint = next((line.split("=", 1)[1] for line in result.stdout.splitlines()
                            if line.startswith("fingerprint=")), None)
        # The value goes into .env as one line, so anything but the generator's own format is refused.
        if result.returncode != 0 or fingerprint is None or not FINGERPRINT_FORMAT.fullmatch(fingerprint):
            report.not_yet(f"the Guardian key generator failed: {result.stderr.strip() or result.stdout.strip()}")
            return report.EXIT_BROKEN
        os.replace(out_dir / "guardian.key", secrets_dir / "guardian.key")
        os.chmod(secrets_dir / "guardian.key", 0o600)
        os.replace(out_dir / "guardian-keys.json", keys_dir / "guardian-keys.json")
        os.chmod(keys_dir / "guardian-keys.json", 0o644)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    update_env(dict(DEFAULTS), only_missing=True)
    # Both always replaced: reset keeps .env, and a token or pin left from the last lab would no longer match the new
    # keys.
    update_env({CLIENT_TOKEN: client_token, GUARDIAN_FINGERPRINT: fingerprint})
    report.done(f"lab initialized. Guardian decision key {GUARDIAN_KEY_ID}, fingerprint {fingerprint}")
    report.info("Compare that fingerprint with what acs-verify --expect-fingerprint is given. Next: ./lab.sh up")
    return report.EXIT_PASS


# ---------------------------------------------------------------------------------------------------------------------
# settings, epoch, wipe
# ---------------------------------------------------------------------------------------------------------------------

def cmd_set(args: list[str]) -> int:
    """_set <mode|upstream|sign|traces> <value>: validated, then written to .env. lab.sh recreates the services."""
    if len(args) != 2 or args[0] not in SETTINGS:
        report.not_yet(f"_set takes one of {', '.join(SETTINGS)} and a value")
        return report.EXIT_BROKEN
    name, value = args
    choices = SETTINGS[name]
    if value not in choices:
        report.not_yet(f"lab {name} takes {' or '.join(choices)}, got {value}")
        return report.EXIT_BROKEN
    update_env(choices[value])
    report.done(f"{name} set to {value}")
    return report.EXIT_PASS


def cmd_epoch(args: list[str]) -> int:
    """_epoch: POST /epoch on the gateway's admin port, so cached outcomes and sessions start over (A.4)."""
    host = os.environ.get("ACS_GATEWAY_ADMIN_HOST", "").strip()
    port = os.environ.get("ACS_GATEWAY_ADMIN_PORT", "").strip()
    token_file = os.environ.get("ACS_GATEWAY_ADMIN_TOKEN_FILE", "").strip()
    if not (host and port and token_file):
        report.not_yet("ACS_GATEWAY_ADMIN_HOST, ACS_GATEWAY_ADMIN_PORT and ACS_GATEWAY_ADMIN_TOKEN_FILE must be set")
        return report.EXIT_BROKEN
    try:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    except OSError as e:
        report.not_yet(f"the admin token can't be read ({e.strerror}). Run ./lab.sh init first")
        return report.EXIT_BROKEN
    request = urllib.request.Request(f"http://{host}:{port}/epoch", method="POST", data=b"",
                                     headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=ADMIN_TIMEOUT_S) as response:
            epoch = json.load(response).get("epoch")
    except urllib.error.HTTPError as e:
        report.not_yet(f"the gateway refused the epoch bump with HTTP {e.code}")
        return report.EXIT_BROKEN
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        report.not_yet(f"the gateway's admin port didn't answer ({reason}). Run ./lab.sh up")
        return report.EXIT_NOT_YET
    report.done(f"gateway epoch bumped to {epoch}")
    return report.EXIT_PASS


def _remove(path: Path) -> None:
    # A link is removed as a link, so a link to anywhere else never takes its target with it.
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def cmd_wipe(args: list[str]) -> int:
    """_wipe [--delete-model-key]: removes everything inside state/ and nothing outside it. .env and the bundle stay.

    state/secrets/openai.key stays unless --delete-model-key is given. lab.sh asks the attendee before passing it.
    """
    if args not in ([], [DELETE_MODEL_KEY]):
        report.not_yet(f"_wipe takes only {DELETE_MODEL_KEY}, got {' '.join(args)}")
        return report.EXIT_BROKEN
    keep_key = not args
    root = state()
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        report.not_yet(f"{root} is not a plain directory, so lab reset won't touch it")
        return report.EXIT_BROKEN
    if not root.exists():
        report.done("state/ is already empty")
        return report.EXIT_PASS
    if root.resolve().parent != bundle().resolve():
        report.not_yet(f"{root} resolves outside the lab bundle, so lab reset won't touch it")
        return report.EXIT_BROKEN
    secrets_dir = root / "secrets"
    kept = keep_key and (secrets_dir / MODEL_KEY).is_file() and not secrets_dir.is_symlink()
    for child in root.iterdir():
        if kept and child.name == "secrets":
            for secret in secrets_dir.iterdir():
                if secret.name != MODEL_KEY:
                    _remove(secret)
        else:
            _remove(child)
    if kept:
        report.done(f"state/ wiped, except your model key in state/secrets/{MODEL_KEY}. "
                    f"Run ./lab.sh reset {DELETE_MODEL_KEY} to delete it too, or ./lab.sh init to start again")
    else:
        report.done("state/ wiped. Run ./lab.sh init to start again")
    return report.EXIT_PASS


# ---------------------------------------------------------------------------------------------------------------------
# what the attendee looks at
# ---------------------------------------------------------------------------------------------------------------------

def cmd_model_log(args: list[str]) -> int:
    """model-log: the last request the gateway forwarded to the model, pretty-printed and escaped."""
    path = state() / "model-inputs.jsonl"
    if not path.is_file():
        report.not_yet("no model input log yet. Run a scenario first")
        return report.EXIT_NOT_YET
    with path.open(encoding="utf-8", errors="replace") as f:
        last = collections.deque((line for line in f if line.strip()), maxlen=1)
    if not last:
        report.not_yet("the model input log is empty. Run a scenario first")
        return report.EXIT_NOT_YET
    report.done("the model's last input follows")
    try:
        # json.dumps escapes every control character and non-ASCII mark as \uXXXX.
        report.info(json.dumps(json.loads(last[0]), indent=2, ensure_ascii=True))
    except json.JSONDecodeError:
        report.info(last[0].rstrip("\n"))
    return report.EXIT_PASS


def _run_tool(argv: list[str]) -> int:
    return subprocess.run(argv).returncode


def cmd_pins(args: list[str]) -> int:
    """pins: LAB-12's builder writes the tool registry into policy/data.json, then the epoch bumps (A.4)."""
    root = bundle()
    code = _run_tool([GATEWAY_PYTHON, str(root / "policy" / "tools" / "pins.py"),
                      "--model-log", str(state() / "model-inputs.jsonl"), "--data", str(root / "policy" / "data.json")])
    if code != 0:
        report.not_yet("lab pins couldn't build the registry. Run a clean scenario first, then rerun")
        return report.EXIT_BROKEN if code == 2 else report.EXIT_NOT_YET
    report.done("tool registry written to policy/data.json. OPA reloads it on its own")
    return cmd_epoch([])


def cmd_claims(args: list[str]) -> int:
    """claims check [PATH]: LAB-14's ledger check over PATH (lab.sh mounts it at /scan) or the bundle."""
    if not args or args[0] != "check":
        report.not_yet("lab claims takes: check [PATH]")
        return report.EXIT_BROKEN
    rest = args[1:]
    path = rest.pop(0) if rest and not rest[0].startswith("-") else str(bundle())
    try:
        import lab_claims
    except ImportError:
        report.not_yet("the claims check isn't in this image")
        return report.EXIT_BROKEN
    return lab_claims.main([path, "--ledger", str(bundle() / "CLAIMS.md"), *rest])


def cmd_bench(args: list[str]) -> int:
    """bench --show: prints LAB-10's signature benchmark table."""
    if args != ["--show"]:
        report.not_yet("lab bench takes --show")
        return report.EXIT_BROKEN
    try:
        text = BENCH_FILE.read_text(encoding="utf-8")
    except OSError:
        report.not_yet("the benchmark table isn't in this image")
        return report.EXIT_BROKEN
    report.done("signature benchmark (LAB-10)")
    report.info(text.rstrip("\n"))
    return report.EXIT_PASS


def _port(name: str, default: int) -> str:
    return _env_values(_read_env(bundle() / ".env")).get(name, "").strip() or str(default)


def cmd_viewer(args: list[str]) -> int:
    """viewer: where the decision viewer is. The container can't open a browser on the host."""
    report.done(f"the decision viewer is at http://127.0.0.1:{_port('LAB_PORT_VIEWER', 8095)}/")
    return report.EXIT_PASS


def cmd_approver(args: list[str]) -> int:
    """approver: where the approval page is and the token it asks for (LAB-08)."""
    report.done(f"the approver page is at http://127.0.0.1:{_port('LAB_PORT_APPROVER', 8090)}/")
    report.info("It asks for the token in labs/finbot/state/secrets/approver.token on your machine.")
    return report.EXIT_PASS


def cmd_help(args: list[str]) -> int:
    report.info("lab commands: " + ", ".join(sorted(name for name in COMMANDS if not name.startswith("_"))))
    return report.EXIT_PASS


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "init": cmd_init,
    "_set": cmd_set,
    "_epoch": cmd_epoch,
    "_wipe": cmd_wipe,
    "model-log": cmd_model_log,
    "pins": cmd_pins,
    "claims": cmd_claims,
    "bench": cmd_bench,
    "viewer": cmd_viewer,
    "approver": cmd_approver,
    "help": cmd_help,
}

import lab_modules  # noqa: E402  (imported after COMMANDS, since lab_modules calls back into this module)

COMMANDS.update(lab_modules.COMMANDS)


def dispatch(argv: list[str]) -> int:
    if not argv:
        return cmd_help([])
    command = COMMANDS.get(argv[0])
    if command is None:
        report.not_yet(f"unknown command {argv[0]}. Run ./lab.sh help")
        return report.EXIT_BROKEN
    return command(argv[1:])
