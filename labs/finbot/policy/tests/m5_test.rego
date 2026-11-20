# Module 5 tests: every bank_account_number in a tool's output is redacted before the model reads it.
#
# The starter fails the four redaction tests.
package finbot_test.m5

import data.finbot

tools := {"get_vendor_details": {"digests": ["sha256:dd"]}}

result(value) := {
	"method": "steps/toolCallResult",
	"payload": {
		"tool": {"name": "get_vendor_details", "version": "sha256:dd"},
		"exit_status": "success",
		"outputs": [{"value": value}],
	},
	"metadata": {},
}

verdict_for(inp) := v if {
	v := finbot.verdict with input as inp with data.finbot_lab.tools as tools
}

paths(v) := [r.path | some r in v.modifications.redactions]

test_flat_vendor_record_redacted if {
	v := verdict_for(result({"name": "Acme", "bank_account_number": "111"}))
	v.decision == "modify"
	v.reason_codes == ["sensitive_field_redacted"]
	v.modifications == {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}
}

test_nested_and_listed_numbers_all_redacted if {
	v := verdict_for(result({"vendors": [{"bank_account_number": "1"}, {"bank_account_number": "2"}]}))
	paths(v) == ["/outputs/0/value/vendors/0/bank_account_number", "/outputs/0/value/vendors/1/bank_account_number"]
}

test_key_with_slash_escaped if {
	v := verdict_for(result({"a/b": {"bank_account_number": "1"}, "c~d": {"bank_account_number": "2"}}))
	paths(v) == ["/outputs/0/value/a~1b/bank_account_number", "/outputs/0/value/c~0d/bank_account_number"]
}

# A redaction inside another would overlap, which the Guardian rejects, so only the outer field is redacted.
test_field_inside_the_field_redacted_once if {
	v := verdict_for(result({"bank_account_number": {"bank_account_number": "1"}}))
	paths(v) == ["/outputs/0/value/bank_account_number"]
}

test_string_output_allows if {
	verdict_for(result("bank_account_number: 111")) == {"decision": "allow"}
}

test_call_never_redacted if {
	inp := {
		"method": "steps/toolCallRequest",
		"payload": {
			"tool": {"name": "get_vendor_details", "version": "sha256:dd"},
			"arguments": {"bank_account_number": {"value": "111"}},
		},
		"metadata": {},
	}
	verdict_for(inp) == {"decision": "allow"}
}
