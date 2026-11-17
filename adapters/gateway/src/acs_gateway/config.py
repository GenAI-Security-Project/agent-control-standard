"""The gateway's configuration, read once from the environment at startup."""
from __future__ import annotations

import math
import os
import sys
import tempfile
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path

MODES = ("off", "shadow", "enforce")
DEFAULT_GUARDIAN_URL = "http://127.0.0.1:8787/"
DEFAULT_UPSTREAM_URL = "https://api.openai.com/v1"
DEFAULT_DECISION_TIMEOUT_MS = 5000
DEFAULT_READY_TIMEOUT_S = 60.0
DEFAULT_MAX_SESSIONS = 256
DEFAULT_WORKERS = 16
DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024
# The longest a governed stream waits for the upstream's next chunk while it holds the session lock.
DEFAULT_STREAM_IDLE_TIMEOUT_S = 60.0
# The longest a whole governed stream may run in enforce, however steadily the upstream sends.
DEFAULT_STREAM_DEADLINE_S = 600.0
# The longest an ASK may hold a model response. FinBot waits LLM_TIMEOUT (360 s in the lab) for its model call, so
# 240 s leaves room for the call itself (A.3, PREMORTEM P26).
MAX_ASK_S = 240.0
# The event loop waits this long past a decision timeout for a worker stuck outside acs.client's own bound.
STEP_GRACE_S = 1.0


def _positive_number(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive number, got {raw!r}")
    return value


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    """A whole number of at least 1. A fraction is refused rather than truncated, since 0.5 workers would become 0."""
    raw = env.get(name, "").strip()
    if not raw:
        return default
    # str.isdigit also accepts digits from other scripts, which int() then reads, so only ASCII 0-9 count.
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError(f"{name} must be plain ASCII digits, a whole number of at least 1, got {raw!r}")
    if int(raw) < 1:
        raise ValueError(f"{name} must be a whole number of at least 1, got {raw!r}")
    return int(raw)


def _port(env: Mapping[str, str], name: str) -> int | None:
    """A TCP port from 1 to 65535, or None when unset. Plain ASCII digits only, as for the integer settings."""
    raw = env.get(name, "").strip()
    if not raw:
        return None
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= 65535:
        raise ValueError(f"{name} must be a port from 1 to 65535 in plain ASCII digits, got {raw!r}")
    return int(raw)


@dataclass(frozen=True)
class GatewayConfig:
    mode: str
    upstream_url: str
    guardian_url: str
    decision_timeout_s: float
    ready_timeout_s: float
    state_dir: Path
    transcript_dir: Path
    model_input_log: Path | None
    agent_id: str
    admin_host: str
    admin_port: int | None
    admin_token_file: Path | None
    listen_host: str
    listen_port: int
    max_sessions: int = DEFAULT_MAX_SESSIONS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    workers: int = DEFAULT_WORKERS
    stream_idle_timeout_s: float = DEFAULT_STREAM_IDLE_TIMEOUT_S
    stream_deadline_s: float = DEFAULT_STREAM_DEADLINE_S
    # The approver page (LAB-08, issue #581). Off unless a port is set, so an ASK denies as before.
    approver_host: str = "127.0.0.1"
    approver_port: int | None = None
    approver_token_file: Path | None = None
    ask_max_s: float = MAX_ASK_S

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GatewayConfig:
        # Unset means off, so nothing is governed, or blocked, by accident.
        mode = env.get("ACS_LAB_MODE", "off").strip().lower() or "off"
        if mode not in MODES:
            raise ValueError(f"ACS_LAB_MODE must be one of {', '.join(MODES)}, got {mode!r}")
        state_dir = Path(env.get("ACS_GATEWAY_STATE_DIR") or tempfile.gettempdir())
        transcript_dir = env.get("ACS_TRANSCRIPT_DIR", "").strip()
        model_log = env.get("ACS_MODEL_INPUT_LOG", "").strip()
        admin_port = env.get("ACS_GATEWAY_ADMIN_PORT", "").strip()
        token_file = env.get("ACS_GATEWAY_ADMIN_TOKEN_FILE", "").strip()
        listen_port = int(env.get("ACS_GATEWAY_PORT", "").strip() or "8080")
        approver_port = _port(env, "ACS_GATEWAY_APPROVER_PORT")
        approver_token = env.get("ACS_GATEWAY_APPROVER_TOKEN_FILE", "").strip()
        if approver_port is not None:
            if not approver_token:
                # The page releases held tool calls, so it never runs without a secret, on any host.
                raise ValueError("ACS_GATEWAY_APPROVER_PORT needs ACS_GATEWAY_APPROVER_TOKEN_FILE")
            if approver_port == listen_port:
                raise ValueError(f"ACS_GATEWAY_APPROVER_PORT must differ from ACS_GATEWAY_PORT, got {approver_port}")
            # Compared as numbers, so 08090 and 8090 count as the same port.
            if admin_port.isascii() and admin_port.isdigit() and int(admin_port) == approver_port:
                raise ValueError(f"ACS_GATEWAY_APPROVER_PORT must differ from ACS_GATEWAY_ADMIN_PORT, "
                                 f"got {approver_port}")
        decision_timeout_s = _positive_number(env, "ACS_DECISION_TIMEOUT_MS", DEFAULT_DECISION_TIMEOUT_MS) / 1000.0
        ask_max_s = _positive_number(env, "ACS_GATEWAY_ASK_MAX_S", MAX_ASK_S)
        if ask_max_s > MAX_ASK_S:
            raise ValueError(f"ACS_GATEWAY_ASK_MAX_S must be at most {MAX_ASK_S:g}, got {ask_max_s:g}")
        if ask_max_s <= decision_timeout_s + STEP_GRACE_S:
            # The budget covers the hold and the resend that follows an approval, so it must outlast one decision.
            raise ValueError(f"ACS_GATEWAY_ASK_MAX_S must be more than the decision timeout plus "
                             f"{STEP_GRACE_S:g} s ({decision_timeout_s + STEP_GRACE_S:g}), got {ask_max_s:g}")
        return cls(
            mode=mode,
            upstream_url=(env.get("ACS_UPSTREAM_URL", "").strip() or DEFAULT_UPSTREAM_URL).rstrip("/"),
            guardian_url=env.get("ACS_GUARDIAN_URL", "").strip() or DEFAULT_GUARDIAN_URL,
            decision_timeout_s=decision_timeout_s,
            ready_timeout_s=_positive_number(env, "ACS_GUARDIAN_READY_TIMEOUT_S", DEFAULT_READY_TIMEOUT_S),
            state_dir=state_dir,
            transcript_dir=Path(transcript_dir) if transcript_dir else state_dir / "transcripts",
            model_input_log=Path(model_log) if model_log else None,
            agent_id=env.get("ACS_AGENT_ID", "").strip() or "openai-responses-gateway",
            admin_host=env.get("ACS_GATEWAY_ADMIN_HOST", "").strip() or "127.0.0.1",
            admin_port=int(admin_port) if admin_port else None,
            admin_token_file=Path(token_file) if token_file else None,
            listen_host=env.get("ACS_GATEWAY_HOST", "").strip() or "127.0.0.1",
            listen_port=listen_port,
            max_sessions=_positive_int(env, "ACS_GATEWAY_MAX_SESSIONS", DEFAULT_MAX_SESSIONS),
            max_body_bytes=_positive_int(env, "ACS_GATEWAY_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES),
            workers=_positive_int(env, "ACS_GATEWAY_WORKERS", DEFAULT_WORKERS),
            stream_idle_timeout_s=_positive_number(env, "ACS_GATEWAY_STREAM_IDLE_TIMEOUT_S",
                                                   DEFAULT_STREAM_IDLE_TIMEOUT_S),
            stream_deadline_s=_positive_number(env, "ACS_GATEWAY_STREAM_DEADLINE_S", DEFAULT_STREAM_DEADLINE_S),
            approver_host=env.get("ACS_GATEWAY_APPROVER_HOST", "").strip() or "127.0.0.1",
            approver_port=approver_port,
            approver_token_file=Path(approver_token) if approver_token else None,
            ask_max_s=ask_max_s,
        )


def _under_home(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(Path.home().resolve())
    except (OSError, RuntimeError):
        return False


def prepare_state_dirs(env: MutableMapping[str, str]) -> Path:
    """Point acs.client's session and handshake state at the gateway's own directory (PREMORTEM P19).

    acs.client reads ACS_SESSION_STATE_DIR and ACS_HANDSHAKE_CACHE when it is first imported, and falls back to
    ~/.cache, where a NoAnswer stored before the Guardian was ready would outlive the gateway. This runs before
    any acs.client import, and a path under the home directory is refused outright.
    """
    raw = env.get("ACS_GATEWAY_STATE_DIR", "").strip()
    if raw:
        state = Path(raw)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
    else:
        state = Path(tempfile.mkdtemp(prefix="acs-gateway-"))
        env["ACS_GATEWAY_STATE_DIR"] = str(state)
    os.chmod(state, 0o700)
    for name, default in (("ACS_SESSION_STATE_DIR", "sessions"), ("ACS_HANDSHAKE_CACHE", "handshakes")):
        if not env.get(name, "").strip():
            env[name] = str(state / default)
    for name in ("ACS_SESSION_STATE_DIR", "ACS_HANDSHAKE_CACHE"):
        if _under_home(Path(env[name])):
            raise ValueError(f"{name}={env[name]} is under the home directory, and the gateway keeps its state elsewhere")
    return state


def check_client_state_dirs(env: Mapping[str, str]) -> None:
    """Fail loudly when acs.client was imported before prepare_state_dirs and resolved other directories."""
    resolved = {}
    handshake = sys.modules.get("acs.client._handshake")
    store = sys.modules.get("acs.client._store")
    if handshake is not None:
        resolved["ACS_HANDSHAKE_CACHE"] = getattr(handshake, "_HANDSHAKE_CACHE_DIR", None)
    if store is not None:
        resolved["ACS_SESSION_STATE_DIR"] = getattr(store, "_SESSION_STATE_DIR", None)
    for name, path in resolved.items():
        if path is not None and Path(path) != Path(env[name]):
            raise RuntimeError(f"acs.client resolved {name} to {path} before the gateway set {env[name]}")
