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
DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024


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
        return cls(
            mode=mode,
            upstream_url=(env.get("ACS_UPSTREAM_URL", "").strip() or DEFAULT_UPSTREAM_URL).rstrip("/"),
            guardian_url=env.get("ACS_GUARDIAN_URL", "").strip() or DEFAULT_GUARDIAN_URL,
            decision_timeout_s=_positive_number(env, "ACS_DECISION_TIMEOUT_MS", DEFAULT_DECISION_TIMEOUT_MS) / 1000.0,
            ready_timeout_s=_positive_number(env, "ACS_GUARDIAN_READY_TIMEOUT_S", DEFAULT_READY_TIMEOUT_S),
            state_dir=state_dir,
            transcript_dir=Path(transcript_dir) if transcript_dir else state_dir / "transcripts",
            model_input_log=Path(model_log) if model_log else None,
            agent_id=env.get("ACS_AGENT_ID", "").strip() or "openai-responses-gateway",
            admin_host=env.get("ACS_GATEWAY_ADMIN_HOST", "").strip() or "127.0.0.1",
            admin_port=int(admin_port) if admin_port else None,
            admin_token_file=Path(token_file) if token_file else None,
            listen_host=env.get("ACS_GATEWAY_HOST", "").strip() or "127.0.0.1",
            listen_port=int(env.get("ACS_GATEWAY_PORT", "").strip() or "8080"),
            max_sessions=int(_positive_number(env, "ACS_GATEWAY_MAX_SESSIONS", DEFAULT_MAX_SESSIONS)),
            max_body_bytes=int(_positive_number(env, "ACS_GATEWAY_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)),
        )


def _under_home(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(Path.home().resolve())
    except (OSError, RuntimeError):
        return False


def prepare_state_dirs(env: MutableMapping[str, str]) -> Path:
    """Point acs.client's session and handshake state at the gateway's own directory (PREMORTEM P19).

    acs.client reads ACS_SESSION_STATE_DIR and ACS_HANDSHAKE_CACHE when it is first imported, and falls back to
    ~/.cache, where a NoAnswer stored before the Guardian was ready would outlive the gateway. So this runs before
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
            raise ValueError(f"{name}={env[name]} is under the home directory; the gateway keeps its state elsewhere")
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
