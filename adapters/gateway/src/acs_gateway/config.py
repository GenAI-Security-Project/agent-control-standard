"""The gateway's configuration, read once from the environment at startup."""
from __future__ import annotations

import ipaddress
import math
import os
import re
import sys
import tempfile
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from acs.client import ResponseKeys

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
# Upstream modes (issue #579). openai is the A.3 spelling of live.
UPSTREAM_MODES = ("live", "capture", "replay")
_UPSTREAM_ALIASES = {"openai": "live"}
DEFAULT_CAPTURE_SCENARIO = "capture"
# The scenario names a file under ACS_RECORDINGS_DIR, so only a plain name with no path in it is accepted.
_SCENARIO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


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


def _otlp_endpoint(env: Mapping[str, str]) -> str | None:
    """OTEL_EXPORTER_OTLP_ENDPOINT, the URL of an OTLP HTTP receiver such as Jaeger's port 4318, or None.

    Unset leaves tracing off. A value that can't be an export target stops startup, so a typo never means spans quietly
    go nowhere. The value is never echoed in an error, since it could carry a credential, and a URL that does carry
    one is refused: credentials belong in OTEL_EXPORTER_OTLP_HEADERS, which the gateway never logs.
    """
    raw = env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        # Reading the port raises ValueError for a port that isn't a number in range.
        _ = parts.port
    except ValueError:
        parts = None
    if parts is not None and "@" in parts.netloc:
        raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must not carry a user name or password. Put credentials in "
                         "OTEL_EXPORTER_OTLP_HEADERS instead")
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment:
        raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must be an http or https URL with a host and no query, such as "
                         "http://jaeger:4318")
    return raw.rstrip("/")


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
    upstream_mode: str = "live"
    upstream_key_file: Path | None = None
    # A key file on a model port off loopback, allowed by ACS_UPSTREAM_KEY_SHARED=1 (lab convention, issue #588).
    upstream_key_shared: bool = False
    recordings_dir: Path | None = None
    capture_scenario: str = DEFAULT_CAPTURE_SCENARIO
    upstream_model: str | None = None
    replay_scenario: str | None = None
    # Spans (LAB-09, issue #582). None leaves tracing off, with no exporter and no network call.
    otlp_endpoint: str | None = None
    # The pinned Guardian decision key (acs.client ResponseKeys), or None for HMAC-SHA256 answers as before.
    response_keys: ResponseKeys | None = None
    # The model port's client bearer token (final review R8, issue #588). None leaves the port open, as before.
    client_token_file: Path | None = None

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
        upstream_mode, key_file, recordings, scenario = _upstream_settings(env)
        listen_host = env.get("ACS_GATEWAY_HOST", "").strip() or "127.0.0.1"
        shared = env.get("ACS_UPSTREAM_KEY_SHARED", "").strip()
        if shared not in ("", "0", "1"):
            raise ValueError(f"ACS_UPSTREAM_KEY_SHARED must be 0 or 1, got {shared!r}")
        key_shared = key_file is not None and not _loopback(listen_host)
        if key_shared and shared != "1":
            # Off loopback, more than this host's processes can reach the model port, so the operator says so
            # (security scan F1 and F2). The client token below still gates every call. Lab convention: the lab bundle
            # binds every address on a container network that only the lab's containers and the host itself can reach,
            # and says so with ACS_UPSTREAM_KEY_SHARED=1 (issue #588).
            raise ValueError(f"ACS_UPSTREAM_KEY_FILE needs ACS_GATEWAY_HOST on a loopback address, got "
                             f"{listen_host!r}. Set ACS_UPSTREAM_KEY_SHARED=1 only when every client holding the "
                             "client token that can reach the model port may spend the key")
        client_token = env.get("ACS_GATEWAY_CLIENT_TOKEN_FILE", "").strip()
        if key_file is not None and not client_token:
            # With a key file, whoever reaches the model port spends the operator's key: on a Linux host that is any
            # local user, through the bridge network. A client token closes that.
            raise ValueError("ACS_UPSTREAM_KEY_FILE needs ACS_GATEWAY_CLIENT_TOKEN_FILE, the token the model port's "
                             "clients send as their bearer, so only they can spend the key")
        if client_token and upstream_mode != "replay" and key_file is None:
            # Without a key file the client's own Authorization header goes upstream, and it would carry the token.
            raise ValueError("ACS_GATEWAY_CLIENT_TOKEN_FILE needs ACS_UPSTREAM_KEY_FILE outside replay, or the token "
                             "would be forwarded upstream as the client's key")
        model = env.get("ACS_UPSTREAM_MODEL", "").strip()
        replay_scenario = env.get("ACS_REPLAY_SCENARIO", "").strip() if upstream_mode == "replay" else ""
        if replay_scenario and not _SCENARIO.fullmatch(replay_scenario):
            raise ValueError(f"ACS_REPLAY_SCENARIO must be a plain name of letters, digits, _ and -, "
                             f"got {replay_scenario!r}")
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
            listen_host=listen_host,
            upstream_key_shared=key_shared,
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
            upstream_mode=upstream_mode,
            upstream_key_file=key_file,
            recordings_dir=recordings,
            capture_scenario=scenario,
            upstream_model=model or None,
            replay_scenario=replay_scenario or None,
            otlp_endpoint=_otlp_endpoint(env),
            response_keys=_response_keys(env) if mode != "off" else None,
            client_token_file=Path(client_token) if client_token else None,
        )


def _loopback(host: str) -> bool:
    """Whether a listen host binds only loopback. localhost counts, and any other name doesn't, since it could
    resolve anywhere."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _upstream_settings(env: Mapping[str, str]) -> tuple[str, Path | None, Path | None, str]:
    """ACS_UPSTREAM, ACS_CAPTURE, ACS_UPSTREAM_KEY_FILE, ACS_RECORDINGS_DIR and ACS_CAPTURE_SCENARIO (issue #579).

    Unset means live with no key file, which forwards exactly as the gateway did before upstream modes existed.
    """
    raw = env.get("ACS_UPSTREAM", "").strip().lower() or "live"
    mode = _UPSTREAM_ALIASES.get(raw, raw)
    if mode not in UPSTREAM_MODES:
        raise ValueError(f"ACS_UPSTREAM must be one of {', '.join(UPSTREAM_MODES)} (or openai), got {raw!r}")
    capture_flag = env.get("ACS_CAPTURE", "").strip()
    if capture_flag not in ("", "0", "1"):
        raise ValueError(f"ACS_CAPTURE must be 0 or 1, got {capture_flag!r}")
    key = env.get("ACS_UPSTREAM_KEY_FILE", "").strip()
    if mode == "replay":
        # Replay answers with no network and no credentials, so a setting that implies either is a mistake.
        if capture_flag == "1":
            raise ValueError("ACS_CAPTURE=1 can't be combined with ACS_UPSTREAM=replay")
        if key:
            raise ValueError("ACS_UPSTREAM_KEY_FILE can't be set with ACS_UPSTREAM=replay, which uses no credentials")
    elif capture_flag == "1":
        mode = "capture"
    elif capture_flag == "0" and mode == "capture":
        # An operator who sets 0 to stop capture must not find recordings written anyway (final review M-1).
        raise ValueError("ACS_CAPTURE=0 can't be combined with ACS_UPSTREAM=capture")
    recordings = env.get("ACS_RECORDINGS_DIR", "").strip()
    if mode != "live" and not recordings:
        raise ValueError(f"ACS_RECORDINGS_DIR is required with ACS_UPSTREAM={mode}")
    scenario = env.get("ACS_CAPTURE_SCENARIO", "").strip() or DEFAULT_CAPTURE_SCENARIO
    # Only capture writes a file named by the scenario, so no other mode stops on it.
    if mode == "capture" and not _SCENARIO.fullmatch(scenario):
        raise ValueError(f"ACS_CAPTURE_SCENARIO must be a plain name of letters, digits, _ and -, got {scenario!r}")
    return mode, Path(key) if key else None, Path(recordings) if recordings else None, scenario


def _response_keys(env: Mapping[str, str]) -> ResponseKeys | None:
    """The decision key the Guardian's answers must verify under, read once at startup (issue #576).

    ACS_RESPONSE_ALGORITHMS unset or HMAC-SHA256 gives None, which is the gateway at 031a451. ML-DSA-65 loads the key
    document named by ACS_GUARDIAN_KEYS and pins ACS_GUARDIAN_KEY_ID, checked against ACS_GUARDIAN_KEY_FINGERPRINT when
    set. Lab convention until issue #316 settles verifier rules. Any problem refuses startup, so a gateway never runs
    on HMAC when it was told to verify ML-DSA-65.
    """
    # Imported here, since acs.client resolves its state directories on import and prepare_state_dirs runs first.
    from acs.client import response_keys_from_env

    try:
        return response_keys_from_env(env)
    except ValueError:
        raise
    except Exception as e:  # noqa: BLE001
        # A missing pqc extra or an unreadable document surfaces as other errors. All of them stop startup alike.
        raise ValueError(f"the decision key settings can't be used: {e}") from e


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
