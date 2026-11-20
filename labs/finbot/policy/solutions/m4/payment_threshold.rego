# Module 4: a transfer above the threshold waits for a person.
#
# finstripe__create_transfer moves money, so an amount above data.finbot_lab.payment_ask_threshold becomes an ask
# request. base.rego turns the request into an ASK for the lab approver, and allows
# the call when the gateway resends it with the approver's answer (payload.x_acs_lab_ask_answer, a lab convention
# until issue #175). The input and verdict shape are a lab convention until issue #531.
#
# Arguments arrive wrapped, so the amount is input.payload.arguments.amount.value, which arg("amount") reads:
#   {"tool": {"name": "finstripe__create_transfer", "version": "sha256:..."},
#    "arguments": {"amount": {"value": 7500}, "vendor_id": {"value": 3}, ...}}
#
# Both rules judge the call only (tool_call). The transfer's result carries no arguments, so without the guard every
# result would read as an unreadable amount and ask, and the gateway would withhold the result of a payment that
# already went through. The result of an allowed or approved transfer therefore allows.
#
# Each check negates a named rule, never an expression over a value that may be missing. OPA binds the value before
# the not, so `not is_number(arg("amount"))` with no amount would fail the body and the transfer would go through.
package finbot

# A readable amount that isn't within the threshold.
ask_requests contains {"amount": amount, "question": sprintf("Approve a transfer of %v?", [amount])} if {
	tool_call
	tool_name == "finstripe__create_transfer"
	amount := arg("amount")
	amount_readable
	not amount_within_threshold
}

# An amount that is missing or not a number goes to a person rather than through. The question names no amount,
# since the value is model text.
ask_requests contains {"amount": null, "question": "Approve a transfer whose amount the policy could not read?"} if {
	tool_call
	tool_name == "finstripe__create_transfer"
	not amount_readable
}

amount_readable if is_number(arg("amount"))

# Within only against a numeric threshold, so a missing or misspelled threshold sends every transfer to a person.
amount_within_threshold if {
	threshold := data.finbot_lab.payment_ask_threshold
	is_number(threshold)
	arg("amount") <= threshold
}
