"""Register the ACS component with Relay's configuration-owned plugin host."""

from acs.integrations.relay.adapter import ACSRelay


class GuardianPlugin:
    def validate(self, config):
        unknown = set(config) - {
            "guardian_url",
            "timeout_s",
            "default_deny",
            "agent_id",
        }
        try:
            if unknown:
                raise ValueError(f"unknown ACS options: {sorted(unknown)}")
            ACSRelay(**config)
        except (TypeError, ValueError) as exc:
            return [
                {"level": "error", "code": "acs_config_invalid", "message": str(exc)}
            ]
        return []

    def register(self, config, context):
        adapter = ACSRelay(**config)
        context.register_tool_execution_intercept("guardian", 1000, adapter.intercept)


def register():
    """Call once before Relay initializes components from plugins.toml."""
    import nemo_relay

    nemo_relay.plugin.register("acs_guardian", GuardianPlugin())
