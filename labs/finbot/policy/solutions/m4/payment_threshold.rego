# Module 4: a transfer above the threshold waits for a person.
#
# finstripe__create_transfer moves money, so an amount above data.finbot_lab.payment_ask_threshold becomes an ask
# request. base.rego turns it into an ASK for the lab approver, and allows the call when the gateway resends it with
# the approver's answer (payload.x_acs_lab_ask_answer, a lab convention until issue #175). The input and verdict
# shape are a lab convention until issue #531.
package finbot

ask_requests contains {"amount": amount, "question": sprintf("Approve a transfer of %v?", [amount])} if {
	tool_name == "finstripe__create_transfer"
	amount := arg("amount")
	is_number(amount)
	amount > data.finbot_lab.payment_ask_threshold
}

# An amount the policy can't read as a number goes to a person rather than through. The question names no amount,
# since the value is model text.
ask_requests contains {"amount": null, "question": "Approve a transfer whose amount the policy could not read?"} if {
	tool_name == "finstripe__create_transfer"
	not is_number(arg("amount"))
}
