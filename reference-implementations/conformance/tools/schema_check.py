"""One-off: validate every recorded T4-pilot message against the official ACS v0.1.0 JSON
schemas with a real JSON Schema validator. Usage: schema_check.py <spec v0.1.0 dir> <transcript>"""
import glob
import json
import os
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

spec_dir, tpath = sys.argv[1], sys.argv[2]
resources, by_path = [], {}
for p in glob.glob(os.path.join(spec_dir, "**", "*.json"), recursive=True):
    s = json.load(open(p))
    if "$id" in s:
        resources.append((s["$id"], Resource.from_contents(s)))
        by_path[os.path.relpath(p, spec_dir)] = s
registry = Registry().with_resources(resources)


def v(name):
    return Draft202012Validator(by_path[name], registry=registry, format_checker=FormatChecker())


req_env, resp_env = v("request-envelope.json"), v("response-envelope.json")
hook = {"steps/toolCallRequest": v("hooks/tool-call-request.json"),
        "steps/toolCallResult": v("hooks/tool-call-result.json")}

checked, failures = 0, []
for line in open(tpath):
    t = json.loads(line)
    if t["ev"] not in ("decide", "result") or "request" not in t:
        continue
    req = t["request"]
    for label, validator, inst in (("request envelope", req_env, req),
                                   ("payload", hook[req["method"]], req["params"]["payload"])):
        errs = list(validator.iter_errors(inst))
        checked += 1
        if errs:
            failures.append(f"{t['case']} {req['method']} {label}: {errs[0].message}")
    resp = t.get("response") or {}
    if "result" in resp and t["case"] not in ("P9", "P10"):   # P9/P10 are deliberately malformed stubs
        errs = list(resp_env.iter_errors(resp))
        checked += 1
        if errs:
            failures.append(f"{t['case']} {req['method']} response: {errs[0].message}")

print(f"official v0.1.0 schema validation: {checked - len(failures)}/{checked} instances valid")
for f in failures:
    print("  FAIL", f)
sys.exit(1 if failures else 0)
