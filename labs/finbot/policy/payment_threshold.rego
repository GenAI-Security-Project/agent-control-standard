# Module 4: a transfer above the threshold waits for a person.
#
# finstripe__create_transfer moves money. Add an ask request when its amount is above
# data.finbot_lab.payment_ask_threshold. base.rego turns the request into an ASK for the lab approver, and allows
# the call when the gateway resends it with the approver's answer (payload.x_acs_lab_ask_answer, a lab convention
# until issue #175). The input and verdict shape are a lab convention until issue #531.
#
# Arguments arrive wrapped, so the amount is input.payload.arguments.amount.value, which arg("amount") reads:
#   {"tool": {"name": "finstripe__create_transfer", "version": "sha256:..."},
#    "arguments": {"amount": {"value": 7500}, "vendor_id": {"value": 3}, ...}}
#
# Each rule below has a body that never matches, so every transfer goes through. Replace each false with the
# conditions its comment names, using the two helper rules. Negate a named rule, never an expression over a value
# that may be missing: OPA binds the value before the not, so `not is_number(arg("amount"))` with no amount fails
# the body and the transfer goes through.
package finbot

# A readable amount that isn't within the threshold. Replace false with amount_readable and
# not amount_within_threshold.
ask_requests contains {"amount": amount, "question": sprintf("Approve a transfer of %v?", [amount])} if {
	tool_name == "finstripe__create_transfer"
	amount := arg("amount")
	false
}

# An amount that is missing or not a number goes to a person rather than through. The question names no amount,
# since the value is model text. Replace false with not amount_readable.
ask_requests contains {"amount": null, "question": "Approve a transfer whose amount the policy could not read?"} if {
	tool_name == "finstripe__create_transfer"
	false
}

amount_readable if is_number(arg("amount"))

# Within only against a numeric threshold, so a missing or misspelled threshold sends every transfer to a person.
amount_within_threshold if {
	threshold := data.finbot_lab.payment_ask_threshold
	is_number(threshold)
	arg("amount") <= threshold
}
