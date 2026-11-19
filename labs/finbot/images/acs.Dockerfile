# syntax=docker/dockerfile:1
# acs-lab-runtime: every ACS service in the FinBot lab and the lab CLI, in one image (issue #588, LAB-15).
#
# Version 1.0.0. Owner: Rock Lambros. Build context: the repository root.
#   docker build -f labs/finbot/images/acs.Dockerfile -t acs-lab-runtime:local .
#
# One image, so the Guardian, the gateway, the viewer and the CLI share one digest to publish, pull and verify. Each
# service still mounts only its own secrets at run time (A.2).
#
# Base images by digest, read 2026-11-18 with `docker buildx imagetools inspect`:
#   python:3.12-slim-bookworm  sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df (built 2026-11-05)
#   ghcr.io/astral-sh/uv:0.9.9 sha256:f6e3549ed287fee0ddde2460a2a74a2d74366f84b04aaa34c1f19fec40da8652 (uv 0.9.9, as CI)

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build

COPY --from=ghcr.io/astral-sh/uv:0.9.9@sha256:f6e3549ed287fee0ddde2460a2a74a2d74366f84b04aaa34c1f19fec40da8652 /uv /usr/local/bin/uv

# The base image's interpreter, never a downloaded one, so the venvs work in the final stage unchanged.
ENV UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1

# The adapters' build hook bundles specification/v0.1.0 as acs/core/schemas, so the schemas come along.
COPY specification/v0.1.0 /src/specification/v0.1.0
COPY adapters /src/adapters

# Both lockfiles hold, with no dev or test groups. The pqc extra brings ML-DSA-65 signing to the Guardian and
# ML-DSA-65 verification to the gateway. --no-editable installs the adapters as a wheel, so /src isn't needed after.
RUN cd /src/adapters \
 && UV_PROJECT_ENVIRONMENT=/opt/acs/adapters/.venv uv sync --locked --no-default-groups --no-editable --extra pqc \
 && cd /src/adapters/gateway \
 && UV_PROJECT_ENVIRONMENT=/opt/acs/gateway/.venv uv sync --locked --no-default-groups --no-editable --extra pqc

# The claims check's Markdown parser goes into the venv the lab CLI runs from, by wheel hash at the root uv.lock's
# versions. claims-requirements.txt says why each flag is there.
COPY labs/finbot/images/claims-requirements.txt /src/claims-requirements.txt
RUN uv pip install --python /opt/acs/adapters/.venv/bin/python --require-hashes --no-deps --only-binary :all: \
        -r /src/claims-requirements.txt

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

LABEL org.opencontainers.image.title="acs-lab-runtime" \
      org.opencontainers.image.description="ACS Guardian, gateway, decision viewer and lab CLI for the FinBot lab" \
      org.opencontainers.image.source="https://github.com/GenAI-Security-Project/agent-control-standard" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /opt/acs /opt/acs
# The lab's own files. The dockerignore beside this file keeps state/, .env, keys and tokens out.
COPY labs/finbot /opt/lab
COPY docs/topics/signature-benchmark.md /opt/lab/docs/signature-benchmark.md
COPY labs/finbot/images/entrypoint.sh /usr/local/bin/lab-entrypoint

# A CRLF entrypoint fails here, at build time, rather than at the first container start.
RUN if grep -q "$(printf '\r')" /usr/local/bin/lab-entrypoint; then \
        echo "lab-entrypoint has CRLF line endings" >&2; exit 1; \
    fi \
 && chmod 0755 /usr/local/bin/lab-entrypoint \
 && rm -rf /opt/lab/state /opt/lab/images/tests /opt/lab/cli/tests

ENV PATH="/opt/acs/adapters/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
