# Module 6 tests: a step whose tool.version isn't one of the tool's pinned digests denies, on calls and results.
#
# The starter fails every test but test_any_pinned_digest_allows.
package finbot_test.m6

import data.finbot

tools := {
	"finmail__send_email": {"digests": ["sha256:aa"]},
	"get_vendor_details": {"digests": ["sha256:d1", "sha256:d2"]},
}

tool(name, version) := {"name": name, "version": version}

call(t) := {
	"method": "steps/toolCallRequest",
	"payload": {"tool": t, "arguments": {"to": {"value": ["admin@ns_user_abc.finbot"]}}},
	"metadata": {},
}

result(t) := {
	"method": "steps/toolCallResult",
	"payload": {"tool": t, "exit_status": "success", "outputs": [{"value": "sent"}]},
	"metadata": {},
}

verdict_for(inp) := v if {
	v := finbot.verdict with input as inp with data.finbot_lab.tools as tools
}

mismatch(inp) if {
	v := verdict_for(inp)
	v.decision == "deny"
	v.reason_codes == ["tool_content_hash_mismatch"]
}

test_changed_digest_denies_call if {
	mismatch(call(tool("finmail__send_email", "sha256:ee")))
}

test_changed_digest_denies_result if {
	mismatch(result(tool("finmail__send_email", "sha256:ee")))
}

test_missing_version_denies_call if {
	mismatch(call({"name": "finmail__send_email"}))
}

test_missing_version_denies_result if {
	mismatch(result({"name": "finmail__send_email"}))
}

test_non_string_version_denies if {
	mismatch(call(tool("finmail__send_email", ["sha256:aa"])))
}

test_any_pinned_digest_allows if {
	verdict_for(call(tool("get_vendor_details", "sha256:d2"))) == {"decision": "allow"}
}
