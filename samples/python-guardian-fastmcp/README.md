# SPDX-License-Identifier: Apache-2.0
# Python Guardian sample + FastMCP client instrumentation for ACS v0.1.
#
# What this is: the smallest possible Guardian Agent (stdlib HTTP,
# pluggable policy, per-session hash chain) plus a FastMCP client
# wrapper that enforces Guardian verdicts BEFORE tools run. It exists
# so framework authors can see the Observed→Guardian round trip
# without installing anything beyond Python 3.11+.
#
# What this is NOT: production code (no auth on POST /acs — bind
# loopback or front it; no persistence beyond JSONL), and not a claim
# of conformance (see "Limits" below).
#
# Run the Guardian:
#   python guardian.py [--port 8787] [--host 127.0.0.1]
# Run the tests (stdlib only, no extra deps):
#   python -m pytest . -q
# Live demo (needs `pip install fastmcp` + a running Guardian):
#   python -c "import asyncio; from fastmcp_instrumentation import demo; asyncio.run(demo())"
#
# Limits, stated plainly:
# - modify | ask | defer verdicts are treated as deny (no
#   modification/approval loop in a sample).
# - Request signatures are accepted but not verified (v0.1 sample;
#   production Guardians MUST verify per the ACS-Crypto profile).
# - No OTel/OCSF trace emission yet (roadmap v1 mappers).
