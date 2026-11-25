"""The scenario driver behind lab run and lab record (issue #589, LAB-16 Task 4, Appendix A.11). Standard library only.

Version 1.4.0. Owner: Rock Lambros.

    lab _drive <scenario> [--answer approve|reject] [--clean] [--capture STEM]

lab.sh resets FinBot's volumes on the host, then hands off here in the lab container. The driver reaches FinBot on
drive-net and the gateway's admin port and approver page on acs-net. It drives FinBot only through FinBot's own API,
over the routes finbot_routes pins, and never reads FinBot's database. One run, in order:

1. Read the mode, signing and upstream from .env and note where the gateway's two logs end.
2. Bump the gateway epoch, so no session from an earlier run carries into this one.
3. Open a FinBot session: its cookie, CSRF token and namespace.
4. Run the scenario's setup steps, wait for quiet, and bump the epoch again (Task 2 review I1, ruling). Setup's
   background agents end their sessions there, so the run's window holds none of their traffic.
5. Clear the chat history of each surface the scenario chats on (the driver rule, PREMORTEM P10).
6. Note where the logs end. That is the start of the run's window. Run the steps, with --clean skipping the step kind
   the scenario's facts name, while a watch on the approver page answers with --answer or points the attendee there.
7. Wait for quiet: no new model input line for QUIET_S seconds, no call waiting for a person and, in a capture, no
   model call still waiting for its recording line (up to inflight_max_s), bounded at
   DONE_TIMEOUT_S, which covers FinBot's LLM_TIMEOUT of 360 seconds. FinBot's background agents keep working after a
   chat's done marker, so quiet is the only done signal (reports/LAB-16-finbot-facts.md).
8. Take each evidence probe from FinBot's API.
9. Bump the epoch, so the gateway ends the run's sessions with steps/sessionEnd (R9), wait for those lines, and note
   where the logs end. That is the end of the window.
10. Write state/runs/<run_id>.json in the acs-lab-run/1 shape evidence.py reads, and print one DONE or NOT YET: line.
    The record also carries model_input_span, the model input log from setup to the end, and poisoned, true when the
    run performed the step --clean skips. lab pins leaves a poisoned run's lines out of the tool registry.

Exit codes follow A.11: 0 the run completed, 1 it completed short of what a check needs (timed out, a chat with no
done marker, a replay miss, a probe FinBot couldn't answer), 2 the environment is broken. Every FinBot string passes
report.escape, with newlines folded, before it prints.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import approver_client
import finbot_client
import finbot_routes as routes
import report

HERE = Path(__file__).resolve().parent
RUN_FORMAT = "acs-lab-run/1"
SCENARIO_FORMAT = "acs-lab-scenario/1"
SCENARIO_ID = re.compile(r"s[1-6][ab]?")
# The gateway's rule for a recording name, the same one lab.sh checks.
STEM = re.compile(r"[A-Za-z0-9_-]{1,64}")
SURFACES = ("vendor", "copilot")
STEP_KINDS = ("register_vendor", "create_invoice", "chat", "tool_override", "reset_tools")
PROBE_KINDS = ("dead_drop", "inbox", "transfers", "invoice_status", "chat_reply")
# Where each probe lands in the run record's finbot.evidence, the names the module checks read.
EVIDENCE_KEYS = {"dead_drop": "dead_drop", "inbox": "inbox", "transfers": "transfers", "invoice_status": "invoice",
                 "chat_reply": "reply"}
ENV_DEFAULTS = {"ACS_LAB_MODE": "enforce", "ACS_UPSTREAM": "replay", "ACS_RESPONSE_SIGNING": "ML-DSA-65"}
MAX_LOG_READ = 8 * 1024 * 1024
ADMIN_TIMEOUT_S = 10.0
REPLY_SHOWN = 300


@dataclass(frozen=True)
class Settings:
    """Where the driver reaches things and how long it waits. Tests shorten the waits and point at fakes."""
    finbot_url: str = finbot_client.BASE_URL
    approver_port: int = approver_client.APPROVER_PORT
    # The quiet window, by upstream (coordinator ruling 2026-11-19, review C2). The gateway writes a model input line
    # before the upstream call and the Guardian's decision, so the log goes silent for the length of both. Replay
    # answers at once. A live or capture call can take far longer, so those runs wait 30 s. quiet_s, when set,
    # overrides both, for tests.
    quiet_s: float | None = None
    # 15 s, not 5: paced replay holds an answer up to 4 s (gateway REPLAY_PACE_MAX_S), and FinBot's agents spend
    # seconds between model calls connecting their MCP servers. At 8 s setup read as quiet while the fraud agent was
    # still connecting, the driver's calls met FinBot's agents in its SQLite database, and FinBot answered nothing for
    # 40 s (2026-11-24 m3 take). Live runs wait 30 s for the same reason.
    quiet_replay_s: float = 15.0
    quiet_live_s: float = 30.0
    # A capture take also waits while a model call it sent has no recording line yet, up to this long past the last
    # model input line. A slow live call (a judge, say) can outlast quiet_live_s, and a take ended then is cut short
    # and fails its replay (2026-11-23 live sitting). FinBot gives up on a call at its LLM_TIMEOUT of 360 s, so a call
    # still unrecorded past that was abandoned: a retried attempt the gateway never records, or a failed exchange.
    inflight_max_s: float = 360.0
    poll_s: float = 0.5
    done_timeout_s: float = 420.0
    # sessionEnd waits on the decision timeout (5 s in compose.yaml) plus the gateway's grace, per session, in
    # parallel. A session whose start failed never ends, so the wait has a bound.
    end_wait_s: float = 20.0
    approver_wait_s: float = approver_client.WAIT_S
    scenarios_dir: Path = HERE


# Browser chat mode (LAB_CHAT_IN_BROWSER=1, 2026-11-24 lab videos): the driver writes each chat step as a cue for a
# person or the recording toolkit to type into FinBot's own chat page, and reads the reply from FinBot's history,
# instead of posting the message itself. Every other step runs as before. The page each surface chats on, under the
# finbot-ui proxy (ui/proxy.py), which shares the driver's session by carrying its fingerprint headers.
CHAT_PAGES = {"vendor": "/vendor/assistant", "copilot": "/admin/dashboard"}
CHAT_CUE = "chat-cue.json"
AGREEMENT_COOKIE = "agreedToRules"


class DriverError(Exception):
    """The environment is broken. One NOT YET: line, exit 2."""


class Terminated(BaseException):
    """SIGTERM, turned into an exception so the run's record is still written on the way out."""


def _on_sigterm(signum: int, frame: Any) -> None:
    raise Terminated()


def _fold(text: Any) -> str:
    """One line of text: report.escape keeps newlines, so they fold to spaces here first."""
    return " ".join(str(text).splitlines())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------------------------------------------------
# arguments and the scenario
# ---------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Args:
    scenario: str
    answer: str | None
    clean: bool
    capture: str | None


USAGE = "lab _drive takes a scenario from s1 to s6, then only --answer approve|reject, --clean or --capture STEM, each once"


def parse_args(argv: list[str]) -> Args:
    if not argv or not SCENARIO_ID.fullmatch(argv[0]):
        raise DriverError(USAGE)
    answer: str | None = None
    clean = False
    capture: str | None = None
    seen: set[str] = set()
    rest = argv[1:]
    while rest:
        flag = rest.pop(0)
        if flag in seen:
            raise DriverError(USAGE)
        seen.add(flag)
        if flag == "--clean":
            clean = True
        elif flag == "--answer" and rest and rest[0] in approver_client.CHOICES:
            answer = rest.pop(0)
        elif flag == "--capture" and rest and STEM.fullmatch(rest[0]):
            capture = rest.pop(0)
        else:
            raise DriverError(USAGE)
    return Args(argv[0], answer, clean, capture)


def _check_step(step: Any, where: str) -> None:
    if not isinstance(step, dict) or step.get("kind") not in STEP_KINDS:
        raise DriverError(f"{where} isn't a step the driver knows")
    kind = step["kind"]
    if kind == "chat":
        # The surface picks the route, so it is checked here and never trusted (Task 2 re-review).
        if step.get("surface") not in SURFACES or not isinstance(step.get("message"), str):
            raise DriverError(f"{where} needs a surface of vendor or copilot and a message")
    elif kind in ("register_vendor", "create_invoice"):
        if not isinstance(step.get("body"), dict):
            raise DriverError(f"{where} needs a body")
    else:
        server = step.get("server")
        if server not in routes.TOOLS:
            raise DriverError(f"{where} names a server the lab doesn't override")
        if kind == "tool_override" and (step.get("tool") not in routes.TOOLS[server]
                                        or not isinstance(step.get("description"), str)):
            raise DriverError(f"{where} needs one of {server}'s tools and a description")
    routes.step_route(step)


def load_scenario(directory: Path, args: Args) -> dict[str, Any]:
    path = directory / f"{args.scenario}.json"
    try:
        scenario = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DriverError(f"there is no scenario {args.scenario} in this bundle") from None
    except (OSError, ValueError) as e:
        raise DriverError(f"scenario {args.scenario} can't be read: {e}") from None
    if not isinstance(scenario, dict) or scenario.get("format") != SCENARIO_FORMAT or scenario.get("id") != args.scenario:
        raise DriverError(f"scenarios/{args.scenario}.json isn't an {SCENARIO_FORMAT} file for {args.scenario}")
    for part in ("setup", "steps", "evidence"):
        if not isinstance(scenario.get(part), list):
            raise DriverError(f"scenario {args.scenario} has no {part} list")
    for part in ("setup", "steps"):
        for n, step in enumerate(scenario[part]):
            _check_step(step, f"scenario {args.scenario} {part} {n + 1}")
    if scenario.get("done") != {"kind": "quiet"}:
        raise DriverError(f"scenario {args.scenario} must finish on quiet")
    for n, probe in enumerate(scenario["evidence"]):
        if not isinstance(probe, dict) or probe.get("kind") not in PROBE_KINDS:
            raise DriverError(f"scenario {args.scenario} evidence {n + 1} isn't a probe the driver knows")
        if probe["kind"] == "chat_reply" and probe.get("surface") not in SURFACES:
            raise DriverError(f"scenario {args.scenario} evidence {n + 1} needs a surface of vendor or copilot")
        routes.probe_route(probe)
    facts = scenario.get("facts")
    if not isinstance(facts, dict):
        raise DriverError(f"scenario {args.scenario} has no facts")
    if args.clean:
        skips = facts.get("clean_skips")
        if skips not in STEP_KINDS or not any(s["kind"] == skips for s in scenario["steps"]):
            raise DriverError(f"scenario {args.scenario} has nothing for --clean to skip")
    return scenario


# ---------------------------------------------------------------------------------------------------------------------
# the gateway: .env, the admin port, the logs
# ---------------------------------------------------------------------------------------------------------------------

def read_env(bundle: Path) -> dict[str, str]:
    path = bundle / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise DriverError("there is no .env. Run ./lab.sh init first") from None
    except OSError as e:
        raise DriverError(f".env can't be read ({e.strerror})") from None
    values = dict(ENV_DEFAULTS)
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and not key.lstrip().startswith("#"):
            values[key.strip()] = value.strip()
    return values


class Admin:
    """POST /epoch on the gateway's admin port, which ends every held session with steps/sessionEnd (A.4, R9)."""

    def __init__(self) -> None:
        host = os.environ.get("ACS_GATEWAY_ADMIN_HOST", "").strip()
        port = os.environ.get("ACS_GATEWAY_ADMIN_PORT", "").strip()
        token_file = os.environ.get("ACS_GATEWAY_ADMIN_TOKEN_FILE", "").strip()
        if not (host and port and token_file):
            raise DriverError("ACS_GATEWAY_ADMIN_HOST, ACS_GATEWAY_ADMIN_PORT and ACS_GATEWAY_ADMIN_TOKEN_FILE must be "
                              "set")
        try:
            self.token = Path(token_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            raise DriverError(f"the admin token can't be read ({e.strerror}). Run ./lab.sh init first") from None
        self.host = host
        self.url = f"http://{host}:{port}/epoch"
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def bump(self) -> int:
        request = urllib.request.Request(self.url, method="POST", data=b"",
                                         headers={"Authorization": f"Bearer {self.token}"})
        try:
            with self._opener.open(request, timeout=ADMIN_TIMEOUT_S) as response:
                epoch = json.loads(response.read(64 * 1024)).get("epoch")
        except urllib.error.HTTPError as e:
            e.close()
            raise DriverError(f"the gateway refused the epoch bump with HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError, AttributeError) as e:
            raise DriverError(f"the gateway's admin port didn't answer ({getattr(e, 'reason', e)}). "
                              "Run ./lab.sh up") from None
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise DriverError("the gateway's epoch answer has no epoch number")
        return epoch

    def select_replay(self, recording: str | None, pace: float | None = None) -> None:
        """POST /replay: the one recording the gateway replays from, or every one with None (2026-11-24), and the
        recording's own replay pace when the manifest pins one."""
        doc: dict[str, Any] = {"scenario": recording}
        if pace is not None:
            doc["pace"] = pace
        request = urllib.request.Request(self.url.removesuffix("/epoch") + "/replay", method="POST",
                                         data=json.dumps(doc).encode("utf-8"),
                                         headers={"Authorization": f"Bearer {self.token}",
                                                  "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=ADMIN_TIMEOUT_S) as response:
                response.read(64 * 1024)
        except urllib.error.HTTPError as e:
            e.close()
            if recording is None:
                # Every recording is how a gateway with no /replay already serves, so a refusal changes nothing
                # (review M2).
                return
            raise DriverError(f"the gateway refused to replay {recording} with HTTP {e.code}. Check that "
                              "replay/recordings holds it, then run ./lab.sh up") from None
        except (urllib.error.URLError, OSError) as e:
            raise DriverError(f"the gateway's admin port didn't answer ({getattr(e, 'reason', e)}). "
                              "Run ./lab.sh up") from None


# How far back the driver reads at a time to find a log's last newline. Model input lines carry FinBot's whole tool
# list, so one line can be longer than this, and the scan keeps going.
LINE_SCAN_BYTES = 64 * 1024


class Logs:
    """The gateway's audit log and model input log under state/, read as byte offsets like evidence.py reads them."""

    def __init__(self, state: Path) -> None:
        self.audit_path = state / "audit.log"
        self.inputs_path = state / "model-inputs.jsonl"
        self.transcripts = state / "transcripts"

    @staticmethod
    def _size(path: Path) -> int:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0

    @staticmethod
    def _line_end(path: Path) -> int:
        """The offset just after the file's last complete line. The gateway may be mid-write when the driver reads a
        size, and a window or span cut inside a line would split one request between two runs."""
        try:
            with path.open("rb") as f:
                end = f.seek(0, os.SEEK_END)
                at = end
                while at > 0:
                    step = min(LINE_SCAN_BYTES, at)
                    f.seek(at - step)
                    chunk = f.read(step)
                    newline = chunk.rfind(b"\n")
                    if newline >= 0:
                        return at - step + newline + 1
                    at -= step
        except FileNotFoundError:
            pass
        return 0

    def offsets(self) -> tuple[int, int]:
        return self._line_end(self.audit_path), self._line_end(self.inputs_path)

    def transcript_sizes(self) -> dict[str, int]:
        """Each transcript file's name and size. Module 1 compares the run's two maps to show an off run wrote no
        transcript, so sizes, not file times, carry the claim. Links are left out, as evidence.py refuses them."""
        sizes: dict[str, int] = {}
        if not self.transcripts.is_dir():
            return sizes
        for path in sorted(self.transcripts.glob("*.jsonl")):
            if not path.is_symlink() and path.is_file():
                sizes[path.name] = path.stat().st_size
        return sizes

    def inputs_size(self) -> int:
        return self._size(self.inputs_path)

    @staticmethod
    def lines_from(path: Path, start: int = 0) -> int:
        """Whole lines in path from byte start on, 0 when it is missing."""
        count = 0
        try:
            with path.open("rb") as f:
                f.seek(start)
                while chunk := f.read(LINE_SCAN_BYTES):
                    count += chunk.count(b"\n")
        except FileNotFoundError:
            return 0
        return count

    def audit_since(self, start: int) -> list[dict[str, Any]]:
        """ACS_AUDIT lines from start to the last whole line."""
        try:
            with self.audit_path.open("rb") as f:
                f.seek(start)
                data = f.read(MAX_LOG_READ + 1)
        except FileNotFoundError:
            return []
        if len(data) > MAX_LOG_READ:
            raise DriverError(f"the run's audit lines pass {MAX_LOG_READ} bytes")
        data = data[:data.rfind(b"\n") + 1]
        events = []
        for line in data.decode("utf-8", errors="replace").splitlines():
            if not line.startswith("ACS_AUDIT "):
                continue
            try:
                event = json.loads(line[len("ACS_AUDIT "):])
            except ValueError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return events


def _opened(events: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for e in events:
        sid = e.get("session_id")
        if e.get("acs_audit_event") == "session_opened" and isinstance(sid, str) and sid not in ids:
            ids.append(sid)
    return ids


def _awaiting_end(events: list[dict[str, Any]]) -> set[str]:
    """Sessions that negotiated and haven't ended. Only those get steps/sessionEnd (app.py _opened)."""
    negotiated = {e["session_id"] for e in events if e.get("acs_audit_event") == "session_opened"
                  and e.get("handshake") == "Negotiated" and not e.get("cause") and isinstance(e.get("session_id"), str)}
    ended = {e.get("session_id") for e in events if e.get("acs_audit_event") == "session_ended"}
    return negotiated - ended


# ---------------------------------------------------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class ApprovalWatch:
    """The approver page, watched for the length of the steps and the quiet wait."""
    approver: approver_client.Approver | None
    choice: str | None
    settings: Settings
    stop: threading.Event = field(default_factory=threading.Event)
    # When each held call was first seen, so every call gets its own window for a person to answer (review M1).
    first_seen: dict[str, float] = field(default_factory=dict)
    waiting_ids: tuple[str, ...] = ()
    pointed: bool = False
    url: str = ""
    # Why the page isn't watched, when that matters to the run: --answer given where no page runs.
    reason: str | None = None
    # When the poll now in flight started, or None. A poll in flight can't vouch for the page, so it counts as busy.
    in_flight: float | None = None
    # Each poll's total deadline, which bounds finish()'s wait for the thread too.
    poll_deadline_s: float = approver_client.TIMEOUT_S
    outcome: approver_client.Outcome | None = None
    _thread: threading.Thread | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _on_poll(self, items: list[approver_client.Waiting]) -> None:
        with self._lock:
            now = time.monotonic()
            self.waiting_ids = tuple(i.ask_id for i in items)
            for ask_id in self.waiting_ids:
                self.first_seen.setdefault(ask_id, now)
            point = items and self.choice is None and not self.pointed
            if point:
                self.pointed = True
        if point:
            report.info(f"A call waits for approval. Open {self.url} and answer it within "
                        f"{self.settings.approver_wait_s:g} seconds.")

    def _poll_started(self) -> None:
        with self._lock:
            self.in_flight = time.monotonic()

    def _poll_ended(self) -> None:
        with self._lock:
            self.in_flight = None

    def start(self) -> None:
        if self.approver is None:
            return

        def run() -> None:
            self.outcome = approver_client.watch(self.approver, stop=self.stop, choice=self.choice,
                                                 poll_s=self.settings.poll_s, on_poll=self._on_poll,
                                                 on_poll_start=self._poll_started, on_poll_end=self._poll_ended)
            with self._lock:
                self.waiting_ids = ()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def busy(self) -> bool:
        """A call waits for a person, inside the time a person has to answer it."""
        with self._lock:
            if self.in_flight is not None:
                return True
            now = time.monotonic()
            return any(now - self.first_seen[a] < self.settings.approver_wait_s for a in self.waiting_ids)

    def finish(self) -> dict[str, Any]:
        self.stop.set()
        bound = self.settings.poll_s + self.poll_deadline_s * 2
        if self._thread is not None:
            self._thread.join(bound)
            if self._thread.is_alive():
                # Still polling past its own deadlines, so a held call may have gone unseen (re-review I-R2).
                return {"answer": self.choice, "waiting_seen": bool(self.first_seen), "answered": False,
                        "status": None, "error": f"the approver watch didn't stop within {bound:g} seconds"}
        outcome = self.outcome
        if outcome is None:
            return {"answer": self.choice, "waiting_seen": False, "answered": False, "status": None,
                    "error": self.reason}
        error = outcome.error
        return {"answer": self.choice, "waiting_seen": outcome.polls_waiting > 0, "answered": outcome.answered,
                "status": outcome.status, "error": error}


class Run:
    def __init__(self, args: Args, scenario: dict[str, Any], settings: Settings, bundle: Path) -> None:
        self.args = args
        self.scenario = scenario
        self.settings = settings
        self.bundle = bundle
        self.state = bundle / "state"
        self.env = read_env(bundle)
        self.admin = Admin()
        self.logs = Logs(self.state)
        self.finbot = finbot_client.FinBot(settings.finbot_url)
        live = self.env["ACS_UPSTREAM"] != "replay" or args.capture is not None
        self.quiet_s = settings.quiet_s if settings.quiet_s is not None else (
            settings.quiet_live_s if live else settings.quiet_replay_s)
        # The take's recording, which the gateway appends one line to per exchange it records (capture only).
        self.capture_path = (bundle / "replay" / "recordings" / f"{args.capture}.jsonl"
                             if args.capture is not None else None)
        self.capture_inputs_start = 0
        self.replay: str | None = None
        self.ids: dict[str, Any] = {}
        self.chats: list[dict[str, Any]] = []
        self.errors: dict[str, str] = {}
        self.chat_in_browser = os.environ.get("LAB_CHAT_IN_BROWSER", "").strip() == "1"
        self.cue_seq = 0
        # Each run numbers its cues from 1, so the cue also names its run, and a typist tells two runs' first cues
        # apart (2026-11-24 m3 take, where s3's first cue read as s2's).
        self.cue_run = uuid.uuid4().hex
        self.setup_timed_out = False
        self.replay_family: str | None = None

    # -- waits ---------------------------------------------------------------------------------------------------

    def wait_quiet(self, watch: ApprovalWatch | None = None) -> bool:
        """True once no model input line arrives for quiet_s and no call waits for a person. False at the bound."""
        s = self.settings
        deadline = time.monotonic() + s.done_timeout_s
        size = self.logs.inputs_size()
        last_change = time.monotonic()
        while True:
            now = time.monotonic()
            current = self.logs.inputs_size()
            if current != size or (watch is not None and watch.busy()):
                size, last_change = current, now
            quiet_for = now - last_change
            if quiet_for >= self.quiet_s and (quiet_for >= s.inflight_max_s or self.calls_in_flight() == 0):
                return True
            if now >= deadline:
                return False
            time.sleep(s.poll_s)

    def calls_in_flight(self) -> int:
        """Model calls this capture take sent that have no recording line yet: input lines since the take began
        minus the recording's lines. Always 0 outside a capture."""
        if self.capture_path is None:
            return 0
        sent = self.logs.lines_from(self.logs.inputs_path, self.capture_inputs_start)
        return max(0, sent - self.logs.lines_from(self.capture_path))

    def wait_ended(self, start: int) -> list[str]:
        """Waits for sessionEnd on every session negotiated since start. Returns the ones still open at the bound."""
        deadline = time.monotonic() + self.settings.end_wait_s
        while True:
            open_ids = _awaiting_end(self.logs.audit_since(start))
            if not open_ids or time.monotonic() >= deadline:
                return sorted(open_ids)
            time.sleep(self.settings.poll_s)

    # -- FinBot ----------------------------------------------------------------------------------------------------

    def step(self, step: dict[str, Any]) -> None:
        kind = step["kind"]
        if kind == "register_vendor":
            answer = self.finbot.call(routes.REGISTER_VENDOR, body=step["body"])
            if isinstance(answer, dict) and isinstance(answer.get("vendor_id"), int):
                self.ids["vendor_id"] = answer["vendor_id"]
        elif kind == "create_invoice":
            answer = self.finbot.call(routes.CREATE_INVOICE, body=step["body"])
            invoice = answer.get("invoice") if isinstance(answer, dict) else None
            if isinstance(invoice, dict) and isinstance(invoice.get("id"), int):
                self.ids["invoice_id"] = invoice["id"]
        elif kind == "chat":
            if self.chat_in_browser:
                result = self.chat_in_page(step["surface"], step["message"])
            else:
                result = self.finbot.chat(step["surface"], step["message"], timeout=self.settings.done_timeout_s)
            self.chats.append({"surface": step["surface"], "done": result.done})
        else:
            # A fresh namespace has no server row until this GET creates it, and the PUT and reset return 404
            # without one (darklab api.py:75-99, repositories.py:653-680).
            self.finbot.call(routes.SERVER, server=step["server"])
            if kind == "tool_override":
                self.finbot.call(routes.TOOL_OVERRIDES, server=step["server"],
                                 body={"tool_overrides": {step["tool"]: {"description": step["description"]}}})
            else:
                self.finbot.call(routes.RESET_TOOLS, server=step["server"])

    def chat_in_page(self, surface: str, message: str) -> finbot_client.ChatResult:
        """Cues one chat step for FinBot's page and waits, up to the done bound, for FinBot's history to hold the message
        and a reply after it. The cue names the page, the message and the driver's session cookie, so the typist's
        browser joins this run's session. It is written owner-only under state/, like the lab's other secrets."""
        self.cue_seq += 1
        cookie = next((c for c in self.finbot.jar if c.name == finbot_client.SESSION_COOKIE), None)
        if cookie is None:
            raise finbot_client.FinBotError("no FinBot session cookie to hand to the browser")
        port = self.env.get("LAB_PORT_FINBOT", "").strip() or "8097"
        cue = {"run": self.cue_run, "seq": self.cue_seq, "surface": surface, "page": CHAT_PAGES[surface], "message": message,
               "url": f"http://localhost:{port}",
               # The session, then FinBot's CTF agreement, which its pages ask a fresh browser to accept first
               # (finbot/static/pages/agreement.html sets this cookie). The lab's operator accepts it by running the lab.
               "cookies": [{"name": cookie.name, "value": cookie.value, "path": "/", "httpOnly": True},
                           {"name": AGREEMENT_COOKIE, "value": "yes", "path": "/", "httpOnly": False}]}
        folder = self.state / "ui"
        folder.mkdir(mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".cue-")
        with os.fdopen(fd, "w") as f:
            json.dump(cue, f)
        os.replace(tmp, folder / CHAT_CUE)
        report.info(f"Type the message into FinBot's chat at http://localhost:{port}{CHAT_PAGES[surface]}")
        route = routes.probe_route({"kind": "chat_reply", "surface": surface})
        deadline = time.monotonic() + self.settings.done_timeout_s
        while time.monotonic() < deadline:
            messages = self._list(self.finbot.call(route), "messages")
            asked = [n for n, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"
                     and isinstance(m.get("content"), str) and m["content"].strip() == message.strip()]
            if asked:
                replies = [m["content"] for m in messages[asked[-1] + 1:] if isinstance(m, dict)
                           and m.get("role") == "assistant" and isinstance(m.get("content"), str) and m["content"]]
                if replies:
                    return finbot_client.ChatResult(True, replies[-1])
            time.sleep(self.settings.poll_s)
        return finbot_client.ChatResult(False, "")

    def _id(self, name: str) -> Any:
        value = self.ids.get(name, self.scenario["facts"].get(name))
        if not isinstance(value, int) or isinstance(value, bool):
            raise finbot_client.FinBotError(f"the run has no {name}")
        return value

    def probe(self, probe: dict[str, Any]) -> Any:
        kind = probe["kind"]
        if kind == "dead_drop":
            # The module 2 and 3 checks read the route's messages list as FinBot returns it (coordinator note).
            answer = self.finbot.call(routes.DEAD_DROP, query={"limit": 100})
            return self._list(answer, "messages")
        if kind == "inbox":
            return self._list(self.finbot.call(routes.VENDOR_INBOX, query={"limit": 100}), "messages")
        if kind == "transfers":
            return self._list(self.finbot.call(routes.TRANSFERS), "transactions")
        if kind == "invoice_status":
            answer = self.finbot.call(routes.INVOICE, invoice_id=self._id("invoice_id"))
            invoice = answer.get("invoice") if isinstance(answer, dict) else None
            if not isinstance(invoice, dict):
                raise finbot_client.FinBotError("FinBot's invoice answer has no invoice")
            return invoice
        route = routes.probe_route(probe)
        messages = self._list(self.finbot.call(route), "messages")
        replies = [m.get("content") for m in messages if isinstance(m, dict) and m.get("role") == "assistant"]
        if not replies or not isinstance(replies[-1], str):
            # An empty string would read as an empty reply, so a missing one is a probe FinBot couldn't answer.
            raise finbot_client.FinBotError("FinBot's chat history has no reply from the assistant")
        return replies[-1]

    def baseline(self) -> dict[str, list[Any]]:
        """The dead drop and inbox message ids present before the steps, which execute pairs with the epoch the steps
        run under and the audit log's offset when setup went quiet. Setup's onboarding mail lands in the same
        inbox, so the checks count only messages whose ids aren't here (module 3 review). A scenario with no setup
        starts on a FinBot that lab.sh reset to empty volumes, so its baseline is empty without asking."""
        if not self.scenario["setup"]:
            return {"dead_drop_ids": [], "inbox_ids": []}
        dead_drop = self._list(self.finbot.call(routes.DEAD_DROP, query={"limit": 100}), "messages")
        inbox = self._list(self.finbot.call(routes.VENDOR_INBOX, query={"limit": 100}), "messages")
        return {"dead_drop_ids": [m.get("id") for m in dead_drop if isinstance(m, dict)],
                "inbox_ids": [m.get("id") for m in inbox if isinstance(m, dict)]}

    @staticmethod
    def _list(answer: Any, key: str) -> list[Any]:
        value = answer.get(key) if isinstance(answer, dict) else None
        if not isinstance(value, list):
            raise finbot_client.FinBotError(f"FinBot's answer has no {key} list")
        return value

    def snapshot(self, namespace: str) -> dict[str, Any]:
        finbot: dict[str, Any] = {"namespace": namespace, "vendor": {}, "evidence": {}, "chats": self.chats}
        try:
            vendor = self.finbot.call(routes.VENDOR, vendor_id=self._id("vendor_id"))
            finbot["vendor"] = vendor if isinstance(vendor, dict) else {}
        except finbot_client.FinBotError as e:
            self.errors["vendor"] = _fold(e)
        for probe in self.scenario["evidence"]:
            key = EVIDENCE_KEYS[probe["kind"]]
            try:
                finbot["evidence"][key] = self.probe(probe)
            except (finbot_client.FinBotError, ValueError) as e:
                self.errors[key] = _fold(e)
        try:
            now = self.finbot.current_namespace()
            if now != namespace:
                self.errors["namespace"] = "FinBot moved the session to another namespace during the run"
        except finbot_client.FinBotError as e:
            self.errors["namespace"] = _fold(e)
        finbot["errors"] = self.errors
        return finbot

    # -- the whole run ---------------------------------------------------------------------------------------------

    def _approval_watch(self) -> ApprovalWatch:
        host = self.admin.host
        url = f"http://127.0.0.1:{self.env.get('LAB_PORT_APPROVER', '').strip() or approver_client.APPROVER_PORT}/"
        if self.env["ACS_LAB_MODE"] != "enforce":
            # The gateway builds the approver page only in enforce mode (acs_gateway/app.py:155), so off and shadow
            # hold no call for a person and the page isn't there to watch.
            watch = ApprovalWatch(None, self.args.answer, self.settings, url=url)
            if self.args.answer is not None:
                watch.reason = "the approver page runs only in enforce mode, so the answer has no call to go to"
            return watch
        try:
            token = approver_client.read_token(self.state / "secrets" / "approver.token")
            # Under the quiet window, so a poll ends, or fails, before quiet could be called around it.
            deadline = min(approver_client.TIMEOUT_S, self.quiet_s * 0.8)
            approver = approver_client.Approver(host, token, port=self.settings.approver_port, deadline_s=deadline)
        except approver_client.ApproverError as e:
            if self.args.answer is not None:
                raise DriverError(str(e)) from None
            # Unwatched, a held call would read as quiet, so the run can't be called complete (review I1).
            watch = ApprovalWatch(None, None, self.settings, url=url)
            watch.reason = _fold(e)
            return watch
        return ApprovalWatch(approver, self.args.answer, self.settings, url=url, poll_deadline_s=deadline)

    def live_policies(self) -> dict[str, str]:
        """Each policy module's live variant, read by comparing its live file with each variant's file."""
        policy = self.bundle / "policy"
        live: dict[str, str] = {}
        try:
            modules = json.loads((policy / "tools" / "modules.json").read_text(encoding="utf-8"))["modules"]
        except (OSError, ValueError, KeyError, TypeError):
            return live
        for module in modules:
            if not isinstance(module, dict) or not isinstance(module.get("live"), str):
                continue
            try:
                current = (policy / module["live"]).read_bytes()
            except OSError:
                continue
            for name, variant in (module.get("variants") or {}).items():
                path = variant.get("file") if isinstance(variant, dict) else None
                try:
                    if isinstance(path, str) and (policy / path).read_bytes() == current:
                        live[module["id"]] = name
                        break
                except OSError:
                    continue
        return live

    def replay_recording(self) -> str | None:
        """The recording this replay run follows: the one every manifest row with this run's scenario, mode, flags and
        live policies names. None outside replay, in a capture, or when the rows don't settle on one, and the gateway
        then replays from every recording as before.

        Two recordings of one scenario share their first keys, and the gateway searched files in name order, so an off
        run of s1 took s1__enforce's first answer and ran short (2026-11-24 owner sitting)."""
        if self.env.get("ACS_UPSTREAM") != "replay" or self.args.capture is not None:
            return None
        try:
            rows = json.loads((self.settings.scenarios_dir / "manifest.json").read_text(encoding="utf-8"))["runs"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        live = self.live_policies()
        same_run = [r for r in rows if isinstance(r, dict)
                    and r.get("scenario") == self.args.scenario and r.get("mode") == self.env.get("ACS_LAB_MODE")
                    and r.get("answer") == self.args.answer and bool(r.get("clean")) == self.args.clean]
        exact = {r.get("recording") for r in same_run
                 if r.get("policy") is None or r.get("policy") == {k: live.get(k) for k in r["policy"]}}
        # A learner's own policy is not byte for byte a shipped variant, so no row matches on policy. The rows for the
        # same run still settle it unless the recording turns on the policy, as s3's deny and allow do (review M1).
        for found in (exact, {r.get("recording") for r in same_run}):
            if len(found) == 1 and isinstance(next(iter(found)), str):
                return next(iter(found))
        return None

    def replay_pace(self, recording: str | None) -> float | None:
        """The pace the manifest pins for a recording, or None for the gateway's own. A recording that catches FinBot's
        agents racing each other replays only at the pace it was checked at: s4a's reject run missed its recording at
        the lab's 0.1 and matched at 0 (2026-11-24 m4 takes)."""
        if recording is None:
            return None
        try:
            pace = json.loads((self.settings.scenarios_dir / "manifest.json").read_text(encoding="utf-8")) \
                .get("replayPace", {}).get(recording)
        except (OSError, ValueError, AttributeError):
            return None
        if isinstance(pace, bool) or not isinstance(pace, (int, float)) or not 0 <= pace <= 1:
            return None
        return float(pace)

    def _after_setup(self, a0: int, epoch_before: Any) -> tuple[Any, dict[str, Any]]:
        """Setup's quiet, its epoch closed and its sessions ended, then the baseline and a clear chat history."""
        if self.scenario["setup"]:
            if not self.wait_quiet():
                self.setup_timed_out = True
            epoch_before = self.admin.bump()
        self.wait_ended(a0)
        # The audit boundary checks count decisions from: setup is quiet, its epoch is closed and its sessions
        # have ended, so every decision setup made sits before this offset (module 3 review).
        setup_audit_end, _ = self.logs.offsets()
        baseline = {**self.baseline(), "epoch": epoch_before, "audit_offset": setup_audit_end}
        for surface in dict.fromkeys(s["surface"] for s in self.scenario["steps"] if s["kind"] == "chat"):
            self.finbot.call(routes.CLEAR_VENDOR_HISTORY if surface == "vendor" else routes.CLEAR_COPILOT_HISTORY)
        return epoch_before, baseline

    def execute(self) -> int:
        replaying = self.env.get("ACS_UPSTREAM") == "replay" and self.args.capture is None
        if replaying:
            # Always set, so a selection a crashed run left behind never reaches this one.
            self.replay = self.replay_recording()
            if self.replay is None:
                # No single take fits this run, as with a learner's own policy. Its scenario's takes still do, and no
                # other scenario's answer can reach it. The run says so, since an answer may come from a sibling take.
                self.replay_family = self.args.scenario
                report.info(f"No single recording fits this run, so replay draws on {self.args.scenario}'s recordings")
            # Setup draws on every take of this scenario, and the steps on the one take that fits. Setup is vendor
            # onboarding, and FinBot's agents race through it, so its turns land in whichever take recorded that
            # order: s4a__reject held none of the onboarding turns s4a__approve did (2026-11-24 m4 takes).
            self.admin.select_replay(self.args.scenario, self.replay_pace(self.replay))
        try:
            return self._execute()
        finally:
            if replaying and (self.replay is not None or self.replay_family is not None):
                try:
                    self.admin.select_replay(None)
                except DriverError:
                    pass

    def _execute(self) -> int:
        a0, setup_inputs = self.logs.offsets()
        self.capture_inputs_start = setup_inputs
        epoch_before = self.admin.bump()
        try:
            namespace = self.finbot.open_session()
        except finbot_client.FinBotError as e:
            raise DriverError(f"FinBot's session can't be opened: {_fold(e)}. Run ./lab.sh up") from None
        result, error = "completed", None
        try:
            for step in self.scenario["setup"]:
                self.step(step)
            # One retry of the quiet wait and everything after it. FinBot's agents and the driver's calls can meet in
            # FinBot's SQLite database, which then locks and leaves FinBot answering nothing for about 40 s, past the
            # driver's request timeout (2026-11-24 intro and m3 takes). Setup's own steps are never repeated: a second
            # vendor registration would be a second vendor.
            for attempt in (1, 2):
                try:
                    epoch_before, baseline = self._after_setup(a0, epoch_before)
                    break
                except finbot_client.FinBotError as e:
                    if attempt == 2 or "timed out" not in str(e):
                        raise
                    report.info("FinBot was slow to answer after setup, so the driver waits for quiet again")
        except finbot_client.FinBotError as e:
            raise DriverError(f"FinBot failed before the scenario's steps: {_fold(e)}") from None
        if self.setup_timed_out:
            result, error = "timed_out", "the scenario's setup didn't go quiet"

        if self.replay is not None:
            self.admin.select_replay(self.replay, self.replay_pace(self.replay))

        # The run's window starts here: setup's sessions are closed and the history is clear. From here on every exit
        # writes a record, a crash or a signal included, so a check never reads the run before as the newest (M4).
        audit_start, inputs_start = self.logs.offsets()
        started = _now()
        record: dict[str, Any] = {
            "format": RUN_FORMAT, "run_id": "", "scenario": self.args.scenario,
            "flags": {"answer": self.args.answer, "clean": self.args.clean},
            "mode": self.env["ACS_LAB_MODE"], "signing": self.env["ACS_RESPONSE_SIGNING"],
            "upstream": self.env["ACS_UPSTREAM"], "capture": self.args.capture, "replay": self.replay,
            "setup_replay": self.args.scenario if self.env.get("ACS_UPSTREAM") == "replay" and self.args.capture is None
            else None,
            "policy_sha256": "",
            "started": _rfc3339(started), "ended": "", "result": "broken",
            "error": "the driver stopped before the run finished",
            "audit": [audit_start, audit_start], "model_inputs": [inputs_start, inputs_start], "sessions": [],
            # lab pins keeps a poisoned run's model input lines out of the tool registry. The span starts before
            # setup, so it covers every line the run's FinBot wrote, and the flag names the run that changed a tool.
            "model_input_span": [setup_inputs, inputs_start], "poisoned": self._poisoned(),
            "sessions_unended": [], "replay_misses": 0, "setup_replay_misses": 0, "setup_audit_start": a0,
            "epoch": [epoch_before, None], "quiet_s": self.quiet_s,
            "approval": {"answer": self.args.answer, "waiting_seen": False, "answered": False, "status": None,
                         "error": None},
            "finbot": {"namespace": namespace, "vendor": {}, "evidence": {"baseline": baseline}, "chats": self.chats,
                       "errors": self.errors},
        }
        code, label = report.EXIT_BROKEN, "broke"
        watch_box: list[ApprovalWatch] = []
        try:
            code, label = self._window(record, result, error, watch_box)
        except DriverError as e:
            record["result"], record["error"] = "broken", _fold(e)
        except KeyboardInterrupt:
            record["result"], record["error"] = "broken", "interrupted before the run finished (SIGINT)"
        except Terminated:
            record["result"], record["error"] = "broken", "stopped before the run finished (SIGTERM)"
        except Exception as e:  # noqa: BLE001
            # A bug or a surprise from FinBot or the gateway is a broken environment by A.11, never a pass.
            record["result"], record["error"] = "broken", _fold(f"the driver hit an error: {type(e).__name__}: {e}")
        finally:
            if watch_box:
                watch_box[0].stop.set()
            if record["result"] == "broken":
                code, label = report.EXIT_BROKEN, "broke"
                self._close_broken(record, audit_start, inputs_start)
            path = write_record(self.state / "runs", record, started)
        return self.report(record, path, code, label)

    def _close_broken(self, record: dict[str, Any], audit_start: int, inputs_start: int) -> None:
        """Fills what it can of a record whose run broke. Each part is best effort, since the cause may be the very
        log or file it would read."""
        record["ended"] = _rfc3339(_now())
        try:
            audit_end, inputs_end = self.logs.offsets()
            record["audit"] = [audit_start, max(audit_start, audit_end)]
            record["model_inputs"] = [inputs_start, max(inputs_start, inputs_end)]
            record["model_input_span"][1] = max(record["model_input_span"][0], inputs_end)
        except OSError:
            pass
        try:
            record["policy_sha256"] = _evidence().policy_sha256(self.bundle / "policy")
        except Exception:  # noqa: BLE001
            pass

    def _poisoned(self) -> bool:
        """True when the run performs the step its scenario's facts name as the one --clean skips. In s6 that step
        changes send_email's declaration, so the model reads a description no clean run shows."""
        skips = self.scenario["facts"].get("clean_skips")
        return (not self.args.clean and skips is not None
                and any(step["kind"] == skips for step in self.scenario["steps"]))

    def _window(self, record: dict[str, Any], result: str, error: str | None,
                watch_box: list[ApprovalWatch]) -> tuple[int, str]:
        """The run inside its window: the steps, the quiet wait, the snapshot, the final bump. Fills record."""
        audit_start = record["audit"][0]
        transcripts_before = self.logs.transcript_sizes()
        watch = self._approval_watch()
        watch_box.append(watch)
        if result == "completed":
            watch.start()
            skip = self.scenario["facts"].get("clean_skips") if self.args.clean else None
            try:
                for step in self.scenario["steps"]:
                    if step["kind"] != skip:
                        self.step(step)
            except finbot_client.FinBotError as e:
                raise DriverError(f"FinBot failed during the steps: {_fold(e)}") from None
            if not self.wait_quiet(watch):
                result, error = "timed_out", f"FinBot didn't go quiet within {self.settings.done_timeout_s:g} seconds"
        record["approval"] = watch.finish()
        if result == "completed" and not all(c["done"] for c in self.chats):
            result, error = "failed", "a FinBot chat ended without its done marker"
        finbot = self.snapshot(record["finbot"]["namespace"])
        finbot["evidence"]["baseline"] = record["finbot"]["evidence"]["baseline"]
        record["finbot"] = finbot

        record["epoch"][1] = self.admin.bump()
        record["sessions_unended"] = self.wait_ended(audit_start)
        audit_end, inputs_end = self.logs.offsets()
        finbot["evidence"]["transcripts_before"] = transcripts_before
        finbot["evidence"]["transcripts_after"] = self.logs.transcript_sizes()
        events = self.logs.audit_since(audit_start)
        record.update({
            "policy_sha256": _evidence().policy_sha256(self.bundle / "policy"),
            # Stamped after the snapshot and the final bump, on every path.
            "ended": _rfc3339(_now()),
            "result": result,
            "error": error,
            "audit": [audit_start, max(audit_start, audit_end)],
            "model_inputs": [record["model_inputs"][0], max(record["model_inputs"][0], inputs_end)],
            "model_input_span": [record["model_input_span"][0], max(record["model_input_span"][0], inputs_end)],
            "sessions": _opened(events),
            "replay_misses": sum(1 for e in events if e.get("acs_audit_event") == "replay_miss"),
            # Setup's misses too: a setup that got neutral replies leaves FinBot in a state the recording never had,
            # and the run window alone hid them (2026-11-24 premortem, m7 on paced replay).
            "setup_replay_misses": sum(1 for e in self.logs.audit_since(record["setup_audit_start"])
                                       if e.get("acs_audit_event") == "replay_miss")
                                   - sum(1 for e in events if e.get("acs_audit_event") == "replay_miss"),
        })
        return judge(record)

    def report(self, record: dict[str, Any], path: Path, code: int, label: str) -> int:
        where = f"Run record state/runs/{path.name}"
        name = self.args.scenario
        reply = record["finbot"].get("evidence", {}).get("reply")
        if isinstance(reply, str) and reply:
            shown = _fold(reply)
            report.info(f"FinBot's reply: {shown[:REPLY_SHOWN]}{'...' if len(shown) > REPLY_SHOWN else ''}")
        if code == report.EXIT_PASS:
            report.done(f"{name} ran in {record['mode']} mode and FinBot went quiet. {where}")
        else:
            report.not_yet(f"{name} {label}: {record['error']}. {where}")
        port = self.env.get("LAB_PORT_VIEWER", "").strip() or "8095"
        report.info(f"The decision viewer is at http://localhost:{port}/")
        return code


def judge(record: dict[str, Any]) -> tuple[int, str]:
    """Sets the record's result and error from the same conditions the printed line uses, and returns the exit code
    and the line's label. Checks read the record, not the exit code, so only a run printed DONE stores completed
    (review C1). Every other outcome stores timed_out, failed or not_yet, with error saying why in one line. A broken
    environment never reaches here: execute stores broken for it."""
    if record["result"] != "completed":
        return report.EXIT_NOT_YET, record["result"].replace("_", " ")
    misses = record["replay_misses"] + record.get("setup_replay_misses", 0)
    errors = record["finbot"].get("errors") or {}
    approval = record["approval"]
    approval_error = approval.get("error")
    # Its own condition, not left to an error string, so an answer never posted can't read as complete (I-R2).
    unposted = approval.get("answer") is not None and not approval.get("answered")
    if misses:
        reason = f"{misses} {'model call' if misses == 1 else 'model calls'} had no recording in replay"
    elif errors:
        key, text = next(iter(errors.items()))
        reason = f"FinBot's {key} evidence can't be read: {text}"
    elif unposted:
        reason = f"the --answer wasn't posted: {approval_error or 'no call waited on the approver page'}"
    elif approval_error:
        reason = approval_error
    elif record["sessions_unended"]:
        count = len(record["sessions_unended"])
        reason = f"{count} {'session' if count == 1 else 'sessions'} got no session end from the gateway"
    else:
        record["error"] = None
        return report.EXIT_PASS, "ran"
    record["result"], record["error"] = "not_yet", _fold(reason)
    return report.EXIT_NOT_YET, "ran short"


def _evidence() -> ModuleType:
    """evidence.py, the reader every check uses, so the policy hash here is the one a check compares."""
    loaded = sys.modules.get("evidence")
    if loaded is not None:
        return loaded
    path = HERE.parent / "modules" / "checks" / "evidence.py"
    spec = importlib.util.spec_from_file_location("evidence", path)
    if spec is None or spec.loader is None:
        raise DriverError("the run record reader isn't in this bundle")
    module = importlib.util.module_from_spec(spec)
    sys.modules["evidence"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("evidence", None)
        raise
    return module


def _sync_dir(directory: Path) -> None:
    """fsync the directory, so the record's new name survives a power cut too."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_record(directory: Path, record: dict[str, Any], started: datetime) -> Path:
    """The record as <run_id>.json, written once through a temporary file and one link, never over another run."""
    directory.mkdir(parents=True, exist_ok=True)
    base = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{record['scenario']}"
    for n in range(1, 100):
        run_id = base if n == 1 else f"{base}-{n}"
        record["run_id"] = run_id
        # The temporary name doesn't end in .json, so evidence.py never reads a half-written record.
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{run_id}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, sort_keys=True, ensure_ascii=True)
                f.write("\n")
                f.flush()
                # On disk before it gets its name, so a crash leaves the whole record or none of it.
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            target = directory / f"{run_id}.json"
            try:
                # The atomic rename step. link gives the record its name in one step, as rename does, and fails when
                # the name exists, so a second run in the same second takes the next name instead of replacing one.
                os.link(tmp, target)
            except FileExistsError:
                continue
            _sync_dir(directory)
            return target
        finally:
            Path(tmp).unlink(missing_ok=True)
    raise DriverError(f"state/runs holds too many runs named {base}")


def main(argv: list[str], *, settings: Settings | None = None) -> int:
    settings = settings or Settings()
    try:
        args = parse_args(argv)
        scenario = load_scenario(settings.scenarios_dir, args)
        bundle = Path(os.environ.get("LAB_BUNDLE") or HERE.parent)
        # docker compose run stops the container with SIGTERM. Only the main thread may set a handler, and the old one
        # goes back afterwards, so nothing outlives the run.
        previous = None
        if threading.current_thread() is threading.main_thread():
            previous = signal.signal(signal.SIGTERM, _on_sigterm)
        try:
            return Run(args, scenario, settings, bundle).execute()
        finally:
            if previous is not None:
                signal.signal(signal.SIGTERM, previous)
    except DriverError as e:
        report.not_yet(_fold(e))
        return report.EXIT_BROKEN
