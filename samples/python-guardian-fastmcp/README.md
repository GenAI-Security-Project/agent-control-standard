<!-- SPDX-License-Identifier: Apache-2.0 -->

# Python Guardian sample and FastMCP client instrumentation

A minimal ACS v0.1 Guardian Agent (stdlib HTTP, pluggable policy, per-session
hash chain) plus a FastMCP client wrapper that enforces Guardian verdicts
before a tool runs. It exists so framework authors can watch the
Observed-to-Guardian round trip without installing anything beyond Python 3.11.

This is not production code. `POST /acs` has no authentication, so bind
loopback or put something in front of it, and nothing persists past a JSONL
log. It is also not a conformance claim: the gaps are listed under
[Limits](#limits).

## Run it

```bash
python guardian.py [--port 8787] [--host 127.0.0.1]
```

The sample code imports nothing outside the standard library. The tests need
pytest, and the conformance suite needs jsonschema:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest . -q
```

A live demo against a real MCP server needs `pip install fastmcp` and a running
Guardian:

```bash
python -c "import asyncio; from fastmcp_instrumentation import demo; asyncio.run(demo())"
```

## How the tests are split

`test_sample.py` covers behaviour: fail-closed posture, the hash chain, verdict
handling. `test_conformance.py` covers shape, by loading
`specification/v0.1.0/` off disk and validating every envelope this sample
emits against it. Agreeing with yourself about a wire format proves nothing,
so drift between the sample and the standard fails there rather than in
somebody else's integration.

Neither suite is collected by the docs deploy gate, because `testpaths` in
`pyproject.toml` scopes that run to `tests/`. They run from
`.github/workflows/samples.yml` instead.

## Arguments carry the ACS wrapper

`hooks/tool-call-request.json` requires each argument to be an object with a
`value` key, so a provenance record can attach per argument:

```json
"arguments": {"path": {"value": "/tmp/x"}}
```

`build_tool_call_envelope` takes an ordinary Python mapping and applies that
wrapper on the way out. The Guardian rejects anything else with `-32600` and
hands the policy layer plain unwrapped values, so a policy author never has to
think about the envelope form.

## Limits

- `modify`, `ask` and `defer` are treated as deny. A sample has no
  modification or approval loop, and downgrading them to allow would be the
  wrong direction to fail in.
- Request signatures are accepted but not verified. ACS-Core requires an
  HMAC-SHA256 over the JCS-canonicalized envelope with an HKDF-derived
  per-session key, and this sample does not implement it, which is the same
  gap [#70](https://github.com/GenAI-Security-Project/agent-control-standard/issues/70)
  tracks against the reference Guardian. Until the wire is authenticated,
  reachability is the access control.
- No OpenTelemetry or OCSF trace emission.
