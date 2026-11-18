# Module 4 tests: a transfer above data.finbot_lab.payment_ask_threshold waits for a person.
#
# tools/modules.json lists the tests the starter fails.
package finbot_test.m4

import data.finbot

tools := {"finstripe__create_transfer": {"digests": ["sha256:cc"]}}

transfer_payload(amount) := {
	"tool": {"name": "finstripe__create_transfer", "version": "sha256:cc"},
	"arguments": {k: {"value": v} | some k, v in {
		"vendor_account": "000111",
		"amount": amount,
		"invoice_reference": "INV-1",
		"vendor_id": 3,
		"invoice_id": 9,
	}},
}

transfer(amount) := {"method": "steps/toolCallRequest", "payload": transfer_payload(amount), "metadata": {}}

# The approval resend the gateway sends: the asked payload plus x_acs_lab_ask_answer (issue #175).
resend(amount, approver) := {
	"method": "steps/toolCallRequest",
	"payload": object.union(transfer_payload(amount), {"x_acs_lab_ask_answer": {
		"ask_request_id": "6f1d2c3b-0000-4000-8000-000000000001",
		"answer": "approve",
		"approver": approver,
		"assurance": "declared",
	}}),
	"metadata": {},
}

verdict_for(inp) := v if {
	v := finbot.verdict with input as inp with data.finbot_lab.tools as tools
}

test_above_threshold_asks if {
	v := verdict_for(transfer(7500))
	v.decision == "ask"
	v.reason_codes == ["payment_over_threshold"]
	v.ask_details.approver == {"type": "human", "id": "lab-approver"}
	v.ask_details.timeout_seconds == 240
	v.ask_details.question == "Approve a transfer of 7500?"
	not "timeout_disposition" in object.keys(v.ask_details)
}

test_below_threshold_allows if {
	verdict_for(transfer(4999)) == {"decision": "allow"}
}

test_at_threshold_allows if {
	verdict_for(transfer(5000)) == {"decision": "allow"}
}

test_non_number_amount_asks if {
	verdict_for(transfer("9000")).decision == "ask"
}

test_missing_amount_asks if {
	inp := json.remove(transfer(7500), ["payload/arguments/amount"])
	verdict_for(inp).decision == "ask"
}

test_missing_threshold_asks if {
	v := finbot.verdict with input as transfer(100)
		with data.finbot_lab as {"tools": tools, "vendor_domains": [], "egress_allow": []}
	v.decision == "ask"
}

test_string_threshold_asks if {
	v := finbot.verdict with input as transfer(100) with data.finbot_lab.tools as tools
		with data.finbot_lab.payment_ask_threshold as "5000"
	v.decision == "ask"
}

test_deny_beats_ask if {
	v := finbot.verdict with input as transfer(7500) with data.finbot_lab.tools as {}
	v.reason_codes == ["tool_unregistered"]
}

test_approved_resend_allows if {
	verdict_for(resend(7500, {"type": "human", "id": "lab-approver"})) == {"decision": "allow"}
}

test_forged_answer_still_asks if {
	verdict_for(resend(7500, {"type": "agent", "id": "lab-approver"})).decision == "ask"
}

# The result the gateway builds for a transfer: no arguments, only the tool's output (apply.py result_payload).
transfer_result(output) := {
	"method": "steps/toolCallResult",
	"payload": {
		"tool": {"name": "finstripe__create_transfer", "version": "sha256:cc"},
		"exit_status": "success",
		"outputs": [{"value": output}],
	},
	"metadata": {},
}

# The amount rules read the call's arguments, so they judge the call only. Asking on the result of a transfer the
# pack allowed would withhold the result of a payment that already moved money.
test_allowed_transfer_result_allows if {
	verdict_for(transfer(100)) == {"decision": "allow"}
	verdict_for(transfer_result({"transfer_id": "tr_1", "status": "completed", "amount": 100})) == {"decision": "allow"}
}

test_approved_transfer_result_allows if {
	verdict_for(resend(7500, {"type": "human", "id": "lab-approver"})) == {"decision": "allow"}
	verdict_for(transfer_result({"transfer_id": "tr_2", "status": "completed", "amount": 7500})) == {"decision": "allow"}
}

test_unregistered_transfer_result_denies if {
	v := finbot.verdict with input as transfer_result({"transfer_id": "tr_1", "amount": 100})
		with data.finbot_lab.tools as {}
	v.reason_codes == ["tool_unregistered"]
}

# The pack keeps no state between steps, so a result never knows whether its call was asked or allowed. A
# registered tool's result follows the result default, allow, whatever amount its output names.
test_result_without_call_context_follows_the_result_default if {
	verdict_for(transfer_result({"transfer_id": "tr_3", "status": "completed", "amount": 9000})) == {"decision": "allow"}
	verdict_for(transfer_result("completed")) == {"decision": "allow"}
}
