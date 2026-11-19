"""Pins the FinBot lab bundle: its git hygiene, compose file and workflows (issue #588, LAB-15).

The bundle lives on the lab branch only. Each test reads a file as text or YAML and checks one property the lab
depends on, so a change that would leak a secret, publish a port off loopback, or let FinBot reach the Guardian shows
red here before anyone runs the stack.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "labs" / "finbot"


def _rules(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return {" ".join(line.split()) for line in lines if line.strip() and not line.lstrip().startswith("#")}


def test_gitattributes_forces_lf():
    # A checkout that turns lab.sh or the entrypoint into CRLF breaks them inside a Linux container.
    rules = _rules(BUNDLE / ".gitattributes")
    for pattern in ("*.sh", "*.py", "Dockerfile*", "*.Dockerfile", "*.yaml", "*.yml"):
        assert f"{pattern} text eol=lf" in rules, pattern


def test_gitignore_covers_secrets():
    rules = _rules(BUNDLE / ".gitignore")
    for pattern in ("state/", ".env", "*.key", "*.token"):
        assert pattern in rules, pattern


def test_no_state_tracked():
    tracked = subprocess.run(["git", "ls-files", "labs/finbot/state", "labs/finbot/.env"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    assert tracked == ""


# ---------------------------------------------------------------------------------------------------------------------
# compose.yaml and compose.openai.yaml (Task 3)
# ---------------------------------------------------------------------------------------------------------------------

import re  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

COMPOSE = BUNDLE / "compose.yaml"
COMPOSE_OPENAI = BUNDLE / "compose.openai.yaml"
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
LAB_IMAGES = {"LAB_RUNTIME_IMAGE": "ghcr.io/genai-security-project/acs-lab-runtime",
              "LAB_FINBOT_IMAGE": "ghcr.io/genai-security-project/acs-lab-finbot"}
# A.2 as amended: four published ports, each on loopback with its own override variable.
PORTS = {"finbot": ("LAB_PORT_FINBOT", 8000), "acs-gateway": ("LAB_PORT_APPROVER", 8090),
         "acs-viewer": ("LAB_PORT_VIEWER", 8095), "jaeger": ("LAB_PORT_JAEGER", 16686)}
# FinBot's own docker-compose.yml at 1450fc4, its app service's environment block, vendored so the test needs no
# network. The lab may differ from it in exactly the four A.3 settings.
FINBOT_OWN_ENV = {"REDIS_URL": "redis://redis:6379", "DATABASE_URL": "${DATABASE_URL:-sqlite://data/finbot.db}",
                  "POSTGRES_HOST": "postgres"}
FINBOT_LAB_SETTINGS = {"OPENAI_BASE_URL": "http://acs-gateway:8080/v1", "OPENAI_API_KEY": "lab-dummy",
                       "LLM_TIMEOUT": "360", "WEB_CONCURRENCY": "1"}
ACS_SERVICES = ("acs-gateway", "acs-guardian", "acs-viewer", "lab")


def _compose(path: Path = COMPOSE) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _services(path: Path = COMPOSE) -> dict:
    return _compose(path)["services"]


def _env(service: dict) -> dict[str, str]:
    env = service.get("environment", {})
    assert isinstance(env, dict), "environment is written as a mapping"
    return {k: str(v) for k, v in env.items()}


def _image_default(image: str) -> tuple[str | None, str]:
    match = re.fullmatch(r"\$\{(\w+):-([^}]+)\}", image)
    return (match.group(1), match.group(2)) if match else (None, image)


def _all_images() -> list[tuple[str, str]]:
    found = []
    for path in (COMPOSE, COMPOSE_OPENAI):
        for name, service in _services(path).items():
            if "image" in service:
                found.append((name, service["image"]))
    return found


def test_third_party_images_pinned_by_digest():
    for name, image in _all_images():
        variable, default = _image_default(image)
        if variable in LAB_IMAGES:
            continue
        assert DIGEST.search(image), f"{name}: {image}"


@pytest.mark.xfail(strict=True, reason="The two lab images get digests only after labs-images.yml first publishes. "
                   "The follow-up commit pins them and removes this mark (issue #588).")
def test_every_image_pinned_by_digest():
    for name, image in _all_images():
        _, default = _image_default(image)
        assert DIGEST.search(default), f"{name}: {image}"


def test_lab_images_name_ghcr_and_keep_a_build():
    # Rock 2026-11-17: pull from ghcr first, build locally when the pull fails. lab.sh swaps the name through the
    # variable, since docker can't tag a local build with a digest reference.
    seen = set()
    for name, service in _services().items():
        variable, default = _image_default(service.get("image", ""))
        if variable is None:
            continue
        assert variable in LAB_IMAGES, f"{name}: {service['image']}"
        assert default.startswith(LAB_IMAGES[variable]), f"{name}: {default}"
        assert "build" in service, f"{name} needs a build section for the local fallback"
        seen.add(variable)
    assert seen == set(LAB_IMAGES)


def test_finbot_builds_pinned_commit_with_pinned_bases():
    build = _services()["finbot"]["build"]
    assert build["context"] == ("https://github.com/GenAI-Security-Project/finbot-ctf.git"
                                "#1450fc4d15cbe80dbaf52dde1df767dbc967e32e")
    assert build["target"] == "app"
    contexts = build["additional_contexts"]
    assert set(contexts) == {"python:3.13-slim-bookworm", "ghcr.io/astral-sh/uv:0.6"}
    for key, value in contexts.items():
        assert value.startswith(f"docker-image://{key}@sha256:") and DIGEST.search(value), value


def test_ports_bind_loopback_with_override():
    services = _services()
    for name, (variable, port) in PORTS.items():
        assert services[name]["ports"] == [f"127.0.0.1:${{{variable}:-{port}}}:{port}"], name


def test_only_four_ports_published():
    published = {name for path in (COMPOSE, COMPOSE_OPENAI) for name, s in _services(path).items() if s.get("ports")}
    assert published == set(PORTS)
    for path in (COMPOSE, COMPOSE_OPENAI):
        for name, service in _services(path).items():
            assert "expose" not in service and service.get("network_mode") is None, name


def test_no_replay_service():
    # Ledger 2026-11-17: replay runs inside the gateway, so there is no replay or collector container (P22).
    services = _services()
    assert "replay" not in services and "otel-collector" not in services
    assert "8070" not in COMPOSE.read_text(encoding="utf-8")


def test_no_proxy_value():
    assert _env(_services()["acs-gateway"])["NO_PROXY"] == "acs-guardian,jaeger"


def test_acs_net_internal_and_ui_net_not():
    networks = _compose()["networks"]
    assert networks["acs-net"]["internal"] is True
    assert not networks["ui-net"].get("internal", False)
    assert not networks["finbot-net"].get("internal", False)


def test_published_services_have_a_non_internal_network():
    # Docker publishes no port for a container whose only network is internal.
    networks = _compose()["networks"]
    for name in PORTS:
        attached = _services()[name]["networks"]
        assert any(not networks[n].get("internal", False) for n in attached), name


def test_service_networks_match_a2():
    expected = {"finbot": {"finbot-net"}, "redis": {"finbot-net"}, "acs-gateway": {"finbot-net", "acs-net"},
                "acs-guardian": {"acs-net"}, "opa": {"acs-net"}, "acs-viewer": {"ui-net"},
                "jaeger": {"acs-net", "ui-net"}, "lab": {"acs-net"}}
    services = _services()
    assert set(services) == set(expected)
    for name, nets in expected.items():
        assert set(services[name]["networks"]) == nets, name


def test_guardian_unreachable_from_finbot_net():
    services = _services()
    for name in ("acs-guardian", "opa"):
        assert list(services[name]["networks"]) == ["acs-net"], name


def test_admin_port_binds_only_the_fixed_acs_net_address():
    # Review focus 1: FinBot's network_request tool runs on finbot-net, where the gateway also sits.
    compose = _compose()
    subnet = compose["networks"]["acs-net"]["ipam"]["config"][0]["subnet"]
    gateway = compose["services"]["acs-gateway"]
    address = gateway["networks"]["acs-net"]["ipv4_address"]
    env = _env(gateway)
    assert env["ACS_GATEWAY_ADMIN_HOST"] == address
    assert env["ACS_GATEWAY_ADMIN_PORT"] == "8091"
    assert subnet == "${LAB_ACS_SUBNET:-10.88.47.0/24}"
    assert address == "${LAB_GATEWAY_ADMIN_IP:-10.88.47.10}"
    assert _env(compose["services"]["lab"])["ACS_GATEWAY_ADMIN_HOST"] == address


def test_secrets_only_where_a2_says():
    # The lab CLI holds the whole bundle mount, which it needs to write state/, so it gets no compose secret.
    expected = {"acs-gateway": {"acs-hmac", "acs-admin-token", "acs-approver-token"},
                "acs-guardian": {"acs-hmac", "acs-guardian-key"}}
    for name, service in _services().items():
        assert set(service.get("secrets", [])) == expected.get(name, set()), name
    openai = _services(COMPOSE_OPENAI)
    assert set(openai) == {"acs-gateway"}
    assert set(openai["acs-gateway"]["secrets"]) == {"openai-key"}
    assert set(_compose(COMPOSE_OPENAI)["secrets"]) == {"openai-key"}
    files = {name: s["file"] for name, s in _compose()["secrets"].items()}
    assert files == {"acs-hmac": "./state/secrets/hmac.key", "acs-guardian-key": "./state/secrets/guardian.key",
                     "acs-admin-token": "./state/secrets/admin.token",
                     "acs-approver-token": "./state/secrets/approver.token"}


def test_lab_secrets_name_every_mounted_secret():
    # The entrypoint copies exactly what LAB_SECRETS names, so the two lists must agree.
    for path in (COMPOSE, COMPOSE_OPENAI):
        for name, service in _services(path).items():
            env = service.get("environment", {})
            if "LAB_SECRETS" not in env:
                continue
            names = {pair.split(":", 1)[0] for pair in env["LAB_SECRETS"].split()}
            secrets = set(service.get("secrets", []))
            if path == COMPOSE_OPENAI:
                secrets |= set(_services()[name].get("secrets", []))
            assert names == secrets, f"{path.name} {name}"


def test_state_secrets_masked_outside_the_cli():
    # Every ACS service but the CLI mounts state/ for logs and keys. A tmpfs over state/secrets keeps the Guardian's
    # private key out of the gateway and the viewer, which run as the same uid.
    for name in ("acs-gateway", "acs-guardian", "acs-viewer"):
        service = _services()[name]
        assert any(v.split(":")[0] == "./state" for v in service["volumes"]), name
        assert "/lab/state/secrets" in service["tmpfs"], name


def test_finbot_settings_differ_in_exactly_four():
    finbot = _services()["finbot"]
    env = _env(finbot)
    changed = {k: v for k, v in env.items() if FINBOT_OWN_ENV.get(k) != v}
    assert changed == FINBOT_LAB_SETTINGS
    assert set(FINBOT_OWN_ENV) <= set(env)
    assert "SECRET_KEY" not in env and "env_file" not in finbot


def test_jaeger_only_under_traces_profile():
    services = _services()
    assert services["jaeger"]["profiles"] == ["traces"]
    assert services["lab"]["profiles"] == ["cli"]
    for name, service in services.items():
        if name not in ("jaeger", "lab"):
            assert "profiles" not in service, name
    # Spans go to Jaeger only when lab traces on sets the endpoint. Empty leaves tracing off in the gateway.
    assert _env(services["acs-gateway"])["OTEL_EXPORTER_OTLP_ENDPOINT"] == "${LAB_OTLP_ENDPOINT:-}"


def test_opa_ignores_reference_dirs():
    opa = _services()["opa"]
    assert opa["command"] == ["run", "--server", "--addr", "0.0.0.0:8181", "--watch", "--ignore", "starters",
                              "--ignore", "solutions", "--ignore", "tests", "--ignore", "tools", "/policy"]
    assert opa["volumes"] == ["./policy:/policy:ro"]


def test_no_secret_in_environment():
    # A key name may only point at a file under /run/acs, never carry a value, apart from FinBot's dummy key.
    secretish = re.compile(r"(KEY|TOKEN|PASSWORD|SECRET)(_FILE)?$")
    for path in (COMPOSE, COMPOSE_OPENAI):
        for name, service in _services(path).items():
            for key, value in _env(service).items():
                if not secretish.search(key) or key in ("ACS_HMAC_KEY_ID", "ACS_GUARDIAN_KEY_ID"):
                    continue
                if (name, key) == ("finbot", "OPENAI_API_KEY"):
                    assert value == "lab-dummy"
                    continue
                if key == "ACS_UPSTREAM_KEY_SHARED":
                    continue
                assert value.startswith("/run/acs/") or key == "ACS_GATEWAY_ADMIN_TOKEN_FILE", f"{name} {key}"


def test_gateway_environment_names_match_the_gateway():
    # Interface pin: every ACS_ name compose sets on the gateway is one the gateway or acs.client reads.
    source = "\n".join(p.read_text(encoding="utf-8") for p in
                       [*(ROOT / "adapters" / "gateway" / "src" / "acs_gateway").glob("*.py"),
                        *(ROOT / "adapters" / "src" / "acs" / "client").glob("*.py")])
    for key in _env(_services()["acs-gateway"]):
        if key.startswith("ACS_"):
            assert f'"{key}"' in source, key


def test_guardian_environment_names_match_the_guardian():
    source = "\n".join(p.read_text(encoding="utf-8") for p in
                       [*(ROOT / "adapters" / "src" / "acs" / "guardian").glob("*.py"),
                        *(ROOT / "adapters" / "src" / "acs" / "client").glob("*.py")])
    guardian = _services()["acs-guardian"]
    for key in _env(guardian):
        if key.startswith("ACS_"):
            assert f'"{key}"' in source, key
    assert guardian["command"] == ["acs-example-guardian", "--host", "0.0.0.0", "--port", "8787"]
    assert 'acs-example-guardian = "acs.guardian.example_guardian:main"' in (
        ROOT / "adapters" / "pyproject.toml").read_text(encoding="utf-8")


def test_guardian_fails_closed_and_signs_ml_dsa_by_default():
    env = _env(_services()["acs-guardian"])
    assert "ACS_ON_DECISION_FAILURE" not in env
    assert env["ACS_RESPONSE_SIGNING"] == "${ACS_RESPONSE_SIGNING:-ML-DSA-65}"
    assert _env(_services()["acs-gateway"])["ACS_RESPONSE_ALGORITHMS"] == "${ACS_RESPONSE_ALGORITHMS:-ML-DSA-65}"
    assert _env(_services()["acs-gateway"])["ACS_LAB_MODE"] == "${ACS_LAB_MODE:-enforce}"


def test_replay_by_default_and_openai_only_by_override():
    gateway = _env(_services()["acs-gateway"])
    assert gateway["ACS_UPSTREAM"] == "replay"
    assert "ACS_UPSTREAM_KEY_FILE" not in gateway
    openai = _env(_services(COMPOSE_OPENAI)["acs-gateway"])
    assert openai["ACS_UPSTREAM"] == "openai"
    assert openai["ACS_UPSTREAM_KEY_FILE"] == "/run/acs/openai.key"
    # LAB-06 final review: a key file on a non-loopback model port needs the explicit opt-in.
    assert openai["ACS_UPSTREAM_KEY_SHARED"] == "1"
    assert _compose(COMPOSE_OPENAI)["secrets"]["openai-key"]["file"] == "./state/secrets/openai.key"


def test_acs_services_drop_to_the_attendee_uid():
    services = _services()
    for name in ("acs-gateway", "acs-guardian"):
        env = _env(services[name])
        assert env["LAB_UID"] == "${LAB_UID:-10001}" and env["LAB_GID"] == "${LAB_GID:-10001}", name
        assert "user" not in services[name], name
    for name in ("acs-viewer", "lab"):
        assert services[name]["user"] == "${LAB_UID:-10001}:${LAB_GID:-10001}", name
    for name in ACS_SERVICES:
        assert "no-new-privileges:true" in services[name]["security_opt"], name
        assert services[name]["cap_drop"] == ["ALL"], name


def test_viewer_command_matches_lab_13():
    viewer = _services()["acs-viewer"]
    assert viewer["command"] == ["python", "/opt/lab/viewer/server.py", "--host", "0.0.0.0", "--port", "8095"]
    server = BUNDLE / "viewer" / "server.py"
    if not server.exists():
        pytest.skip("LAB-13's viewer has not merged into this tree yet")
    text = server.read_text(encoding="utf-8")
    for needle in ('"--host"', '"--port"', "ACS_TRANSCRIPT_DIR", "ACS_AUDIT_FILE", "ACS_GUARDIAN_KEYS"):
        assert needle in text, needle


# ---------------------------------------------------------------------------------------------------------------------
# .github/workflows/labs-images.yml and labs.yml (Tasks 6 and 7)
# ---------------------------------------------------------------------------------------------------------------------

WORKFLOWS = ROOT / ".github" / "workflows"
IMAGES_WORKFLOW = WORKFLOWS / "labs-images.yml"
LABS_WORKFLOW = WORKFLOWS / "labs.yml"
PINNED_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s*v\d")


def _workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(job: dict) -> list[dict]:
    return job.get("steps", [])


def _check_hygiene(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        if re.match(r"^\s*(?:-\s*)?uses:", line):
            assert PINNED_USES.match(line), f"{path.name}: {line.strip()}"
    workflow = _workflow(path)
    assert workflow["permissions"] == {}
    for name, job in workflow["jobs"].items():
        assert "permissions" in job, f"{path.name} {name} grants its own permissions"
        for step in _steps(job):
            assert "${{" not in step.get("run", ""), f"{path.name} {name}: {step.get('name')}"
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False, f"{path.name} {name}"


def test_images_workflow_pins_and_scopes():
    _check_hygiene(IMAGES_WORKFLOW)
    workflow = _workflow(IMAGES_WORKFLOW)
    # PyYAML reads the key `on` as True.
    trigger = workflow[True]
    assert trigger["push"]["branches"] == ["refimpl/acs-lab-2026-12-09"]
    assert trigger["push"]["tags"] == ["acs-lab-*"]
    assert set(workflow["jobs"]) == {"publish"}
    job = workflow["jobs"]["publish"]
    assert job["permissions"] == {"contents": "read", "packages": "write"}
    builds = [s for s in _steps(job) if s.get("uses", "").startswith("docker/build-push-action@")]
    assert len(builds) == 2
    names = set()
    for step in builds:
        args = step["with"]
        assert args["platforms"] == "linux/amd64,linux/arm64"
        assert "push-by-digest=true" in args["outputs"] and "push=true" in args["outputs"]
        names.add(re.search(r"name=([^,]+)", args["outputs"]).group(1))
    assert names == set(LAB_IMAGES.values())
    runtime, finbot = sorted(builds, key=lambda s: "finbot" in s["with"]["outputs"])
    assert runtime["with"]["file"] == "labs/finbot/images/acs.Dockerfile" and runtime["with"]["context"] == "."
    compose_finbot = _services()["finbot"]["build"]
    assert finbot["with"]["context"] == compose_finbot["context"]
    assert finbot["with"]["target"] == compose_finbot["target"]
    contexts = dict(line.split("=", 1) for line in finbot["with"]["build-contexts"].split())
    assert contexts == compose_finbot["additional_contexts"]


def test_only_the_publish_job_writes_packages():
    for path in (IMAGES_WORKFLOW, LABS_WORKFLOW):
        for name, job in _workflow(path)["jobs"].items():
            if (path, name) != (IMAGES_WORKFLOW, "publish"):
                assert "packages" not in job["permissions"], f"{path.name} {name}"


def test_labs_workflow_shape():
    _check_hygiene(LABS_WORKFLOW)
    workflow = _workflow(LABS_WORKFLOW)
    trigger = workflow[True]
    for event in ("push", "pull_request"):
        assert set(trigger[event]["paths"]) == {"labs/**", "adapters/**", ".github/workflows/labs.yml"}
    jobs = workflow["jobs"]
    assert set(jobs) == {"policy", "compose", "cli", "viewer", "images", "smoke"}
    for name, job in jobs.items():
        assert job["permissions"] == {"contents": "read"}, name
    # Rock 2026-11-17: macOS and Linux only, so no windows leg.
    assert jobs["cli"]["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    assert "windows" not in LABS_WORKFLOW.read_text(encoding="utf-8").lower()
    assert jobs["smoke"]["needs"] == "images"


def _runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in _steps(job))


def test_policy_job_runs_every_lab_12_check_on_the_compose_opa_version():
    job = _workflow(LABS_WORKFLOW)["jobs"]["policy"]
    runs = _runs(job)
    assert "python3 labs/finbot/policy/tools/check_pack.py --opa" in runs
    assert "uv run --project adapters --locked python labs/finbot/policy/tools/check_pack.py --opa" in runs
    assert "--verdicts" in runs
    # LAB-12's interface pins need the gateway environment, or they never run in CI.
    assert ("uv run --project adapters/gateway --locked --group test python -m pytest "
            "labs/finbot/policy/tools/test_pins.py -v") in runs
    env = {k: str(v) for step in _steps(job) for k, v in step.get("env", {}).items()}
    opa_tag = _services()["opa"]["image"].split("@")[0].split(":")[1]
    assert env["OPA_VERSION"] == opa_tag
    assert re.fullmatch(r"[0-9a-f]{64}", env["OPA_SHA256"])
    assert "sha256sum -c" in runs


def test_compose_job_checks_every_combination():
    runs = _runs(_workflow(LABS_WORKFLOW)["jobs"]["compose"])
    assert "docker compose -f compose.yaml config --quiet" in runs
    assert "docker compose -f compose.yaml --profile traces --profile cli config --quiet" in runs
    assert "docker compose -f compose.yaml -f compose.openai.yaml config --quiet" in runs


def test_cli_viewer_and_images_jobs_run_their_suites():
    jobs = _workflow(LABS_WORKFLOW)["jobs"]
    assert "python -m pytest labs/finbot/cli/tests -v" in _runs(jobs["cli"])
    assert ("uv run --project adapters --locked --extra pqc --group test python -m pytest labs/finbot/viewer/tests -v"
            in _runs(jobs["viewer"]))
    images = jobs["images"]
    assert "python -m pytest labs/finbot/images/tests -v" in _runs(images)
    assert any(step.get("env", {}).get("LAB_REQUIRE_DOCKER") == "1" for step in _steps(images))


def test_viewer_job_installs_the_repositorys_pinned_bun_first():
    # LAB-13's page test runs the page's app.js under bun and skips without a runtime, so the viewer job installs bun
    # before its suite. Same action SHA and bun version as the reference implementation's workflow, so one bump moves
    # every job together.
    steps = _steps(_workflow(LABS_WORKFLOW)["jobs"]["viewer"])
    setup = [i for i, s in enumerate(steps) if s.get("uses", "").startswith("oven-sh/setup-bun@")]
    suite = [i for i, s in enumerate(steps) if "labs/finbot/viewer/tests" in s.get("run", "")]
    assert len(setup) == 1 and suite and setup[0] < suite[0]
    reference = [s for s in _steps(_workflow(WORKFLOWS / "reference-implementation.yml")["jobs"]["agt"])
                 if s.get("uses", "").startswith("oven-sh/setup-bun@")]
    assert reference, "reference-implementation.yml no longer installs bun"
    step = steps[setup[0]]
    assert step["uses"] == reference[0]["uses"]
    assert step["with"] == {"bun-version": reference[0]["with"]["bun-version"]}
    assert re.fullmatch(r"\d+\.\d+\.\d+", step["with"]["bun-version"])


def test_smoke_job_runs_the_bundle_with_no_model_key():
    job = _workflow(LABS_WORKFLOW)["jobs"]["smoke"]
    runs = _runs(job)
    for command in ("./lab.sh init", "./lab.sh up", "./images/smoke.sh"):
        assert command in runs, command
    text = yaml.safe_dump(job)
    assert "OPENAI" not in text.upper().replace("COMPOSE.OPENAI", "")
    teardown = [s for s in _steps(job) if "./lab.sh down" in s.get("run", "")]
    assert teardown and teardown[0].get("if") == "always()"


def test_every_long_running_acs_service_has_a_healthcheck():
    # `up --wait` passes a service with no healthcheck while it restarts in a loop.
    for name in ("finbot", "redis", "acs-gateway", "acs-guardian", "acs-viewer"):
        assert "healthcheck" in _services()[name], name


# ---------------------------------------------------------------------------------------------------------------------
# Fix round 1: the review's minors
# ---------------------------------------------------------------------------------------------------------------------

def _uses_run_acs(service: dict) -> bool:
    env = _env(service) if "environment" in service else {}
    return "LAB_SECRETS" in env or any(v.startswith("/run/acs/") for v in env.values())


def test_run_acs_is_a_tmpfs_wherever_it_is_used():
    # The entrypoint copies each secret into /run/acs. On a tmpfs the copies live in memory and go with the container,
    # never in its writable layer, where `docker commit` or `docker export` would carry them out.
    users = [name for name, service in _services().items() if _uses_run_acs(service)]
    assert set(users) == {"acs-gateway", "acs-guardian"}
    for name in users:
        assert "/run/acs" in _services()[name]["tmpfs"], name


def test_base_compose_never_shares_the_model_key():
    # LAB-06 ruling R4b: the opt-in belongs in compose.openai.yaml alone. In the base file it would stay set after an
    # attendee pointed the gateway at a key some other way.
    for name, service in _services().items():
        assert "ACS_UPSTREAM_KEY_SHARED" not in service.get("environment", {}), name


CLAIMS_REQUIREMENTS = BUNDLE / "images" / "claims-requirements.txt"
# LAB-14 round 8 (#587) moved the claims check to markdown-it-py, a CommonMark parser, whose one dependency is mdurl.
CLAIMS_PINS = {"markdown-it-py": "4.2.0", "mdurl": "0.1.2"}
LAB_CLAIMS = BUNDLE / "cli" / "lab_claims.py"


def _claims_pins() -> dict[str, tuple[str, set[str]]]:
    pins: dict[str, tuple[str, set[str]]] = {}
    # A trailing backslash continues a requirement onto the next line, as pip and uv read it.
    text = CLAIMS_REQUIREMENTS.read_text(encoding="utf-8").replace("\\\n", " ")
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        spec, *options = line.split()
        name, version = spec.split("==")
        hashes = {o.split("=", 1)[1] for o in options if o.startswith("--hash=")}
        assert hashes, f"{name} has no hash"
        pins[name.lower()] = (version, hashes)
    return pins


def _root_lock_packages() -> dict[str, dict]:
    import tomllib

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {p["name"]: p for p in lock["package"]}


def test_claims_check_packages_pinned():
    # The claims check exits 2 without its parser, so the CLI image carries it at exact versions, one sha256 each.
    pins = _claims_pins()
    assert {name: version for name, (version, _) in pins.items()} == CLAIMS_PINS
    for name, (_, hashes) in pins.items():
        assert len(hashes) == 1 and all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes), name


def test_claims_check_packages_pinned_to_the_root_lock():
    # The pins are the root uv.lock's version and wheel hash, so the CLI parses exactly what the repository's tests
    # parse. The root lock gains markdown-it-py with LAB-14's claims check, so this waits only while neither is here.
    packages = _root_lock_packages()
    if "markdown-it-py" not in packages and not LAB_CLAIMS.exists():
        pytest.skip("the root uv.lock gets markdown-it-py with LAB-14's claims check (#587), not on this branch yet")
    pins = _claims_pins()
    for name, (version, hashes) in pins.items():
        package = packages[name]
        assert version == package["version"], name
        assert hashes <= {w["hash"] for w in package.get("wheels", [])}, name
        # The image installs with --no-deps, which holds only while the pinned set carries every locked dependency.
        assert {d["name"] for d in package.get("dependencies", [])} <= set(pins), name


def test_image_installs_the_claims_packages_by_hash():
    text = (BUNDLE / "images" / "acs.Dockerfile").read_text(encoding="utf-8")
    assert "COPY labs/finbot/images/claims-requirements.txt" in text
    install = re.search(r"uv pip install[^\n]*(?:\\\n[^\n]*)*", text)
    assert install, "no uv pip install step"
    for flag in ("--require-hashes", "--no-deps", "--only-binary :all:", "--python /opt/acs/adapters/.venv/bin/python"):
        assert flag in install.group(0), flag


# ---------------------------------------------------------------------------------------------------------------------
# Final review
# ---------------------------------------------------------------------------------------------------------------------

def test_services_that_write_only_mounts_run_read_only():
    # They write only to tmpfs mounts and ./state, so a compromised service can't change its own image files.
    for name in ("acs-gateway", "acs-guardian", "acs-viewer", "opa"):
        assert _services()[name].get("read_only") is True, name


def test_redis_keeps_only_the_capabilities_its_user_drop_needs():
    redis = _services()["redis"]
    assert redis["cap_drop"] == ["ALL"]
    assert sorted(redis.get("cap_add", [])) == ["SETGID", "SETUID"]
    assert redis["security_opt"] == ["no-new-privileges:true"]


DOCKERFILE = BUNDLE / "images" / "acs.Dockerfile"
# The bundle paths the image runs from. policy/, replay/ and state/ reach the containers by bind mount, never the image.
IMAGE_SOURCES = {"labs/finbot/cli", "labs/finbot/vie[w]er", "labs/finbot/images/entrypoint.sh",
                 "labs/finbot/images/claims-requirements.txt"}


def _stages() -> list[str]:
    return re.split(r"(?m)^FROM ", DOCKERFILE.read_text(encoding="utf-8"))[1:]


def test_image_copies_only_the_bundle_paths_it_runs():
    # A whole-bundle COPY puts state/ and every key into a layer whenever the builder skips the dockerignore.
    sources = set()
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        words = line.split()
        if words[:1] == ["COPY"] and not any(w.startswith("--from") for w in words):
            sources.update(w for w in words[1:-1] if w.startswith("labs/"))
    assert sources == IMAGE_SOURCES


def test_build_stage_fails_on_state_or_a_key_and_nothing_scrubs():
    build, final = _stages()
    assert "/opt/lab" in build.split("COPY labs/finbot/cli", 1)[1]
    # A continued RUN: every line that ends in a backslash, then the last line.
    check = re.search(r"RUN (?:[^\n]*\\\n)*[^\n]*", build.split("COPY labs/finbot/vie[w]er", 1)[1])
    assert check, "no RUN after the lab COPY in the build stage"
    for needle in ("/opt/lab/state", "*.key", "exit 1"):
        assert needle in check.group(0), needle
    assert "COPY --from=build /opt/lab /opt/lab" in final
    assert "rm -rf" not in DOCKERFILE.read_text(encoding="utf-8")


def test_dockerignore_keeps_tests_out_of_the_copied_paths():
    rules = _rules(BUNDLE / "images" / "acs.Dockerfile.dockerignore")
    for pattern in ("labs/finbot/cli/tests", "labs/finbot/viewer/tests"):
        assert pattern in rules, pattern
