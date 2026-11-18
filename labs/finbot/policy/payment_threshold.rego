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
package finbot

# The starter's body never matches, so every transfer goes through. Replace false with the rule.
ask_requests contains {"amount": amount, "question": "Approve this transfer?"} if {
	tool_name == "finstripe__create_transfer"
	amount := arg("amount")
	false
}
