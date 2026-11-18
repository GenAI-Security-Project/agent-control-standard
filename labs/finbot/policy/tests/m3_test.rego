# Module 3 tests: outbound email reaches the company and its known vendors only.
#
# The starter fails test_vendor_notice_allowed, the WP6 trap. The solution passes with solutions/m3/data.patch.json
# applied to data.json.
package finbot_test.m3

import data.finbot

tools := {"finmail__send_email": {"digests": ["sha256:aa"]}}

send(args) := {
	"method": "steps/toolCallRequest",
	"payload": {
		"tool": {"name": "finmail__send_email", "version": "sha256:aa"},
		"arguments": {k: {"value": v} | some k, v in object.union({"subject": "Status", "body": "Hello"}, args)},
	},
	"metadata": {},
}

verdict_for(args) := v if {
	v := finbot.verdict with input as send(args) with data.finbot_lab.tools as tools
}

test_exfil_denied if {
	v := verdict_for({"to": ["collector@exfil.example"]})
	v.decision == "deny"
	v.reason_codes == ["external_recipient"]
}

test_internal_allowed if {
	verdict_for({"to": ["admin@ns_user_abc.finbot"]}) == {"decision": "allow"}
}

test_vendor_notice_allowed if {
	verdict_for({"to": ["billing@northwind-supplies.example"]}) == {"decision": "allow"}
}

test_bcc_external_denies if {
	v := verdict_for({"to": ["admin@ns_user_abc.finbot"], "bcc": ["collector@exfil.example"]})
	v.reason_codes == ["external_recipient"]
}

test_cc_external_denies if {
	v := verdict_for({"to": ["admin@ns_user_abc.finbot"], "cc": ["Collector@Exfil.Example"]})
	v.reason_codes == ["external_recipient"]
}

test_uppercase_internal_allowed if {
	verdict_for({"to": ["ADMIN@NS_USER_ABC.FINBOT"]}) == {"decision": "allow"}
}

test_malformed_recipients_deny if {
	not_list := verdict_for({"to": "admin@ns_user_abc.finbot"})
	not_list.reason_codes == ["external_recipient"]
	not_string := verdict_for({"to": ["admin@ns_user_abc.finbot", 7]})
	not_string.reason_codes == ["external_recipient"]
}

# send_email types cc and bcc as a list or None, so a model that sends null names nobody there.
test_null_copy_list_allowed if {
	verdict_for({"to": ["admin@ns_user_abc.finbot"], "cc": null, "bcc": null}) == {"decision": "allow"}
}
