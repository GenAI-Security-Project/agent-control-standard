# Module 6: pin each tool's declaration, so a changed description or schema denies.
#
# The gateway hashes the declaration the model read for each function (name, description, parameters, strict) and
# sends it as payload.tool.version, a lab convention until issue #38 settles how a call binds to its declaration.
# data.finbot_lab.tools.<name>.digests lists the digests tools/pins.py recorded from a trusted run, any of which
# matches. base.rego denies a tool the registry doesn't hold. The input and verdict shape are a lab convention until
# issue #531.
package finbot

# A version that is present and pinned for none of this tool's declarations. A registry entry with no digests list
# pins nothing, so it matches no version. The check negates a named rule, since `not version in <digests>` over a
# missing list would never fire.
deny_codes contains "tool_content_hash_mismatch" if {
	registered
	version_readable
	not version_pinned
}

version_pinned if {
	digests := data.finbot_lab.tools[tool_name].digests
	is_array(digests)
	input.payload.tool.version in digests
}

# No version, or one that isn't a string. A result of a call the gateway never gated after an epoch bump carries
# none, and a step the policy can't compare can't pass the pin. The check negates a named rule, since OPA binds a
# missing version before a not and `not is_string(input.payload.tool.version)` would then never fire.
deny_codes contains "tool_content_hash_mismatch" if {
	registered
	not version_readable
}

version_readable if is_string(input.payload.tool.version)
