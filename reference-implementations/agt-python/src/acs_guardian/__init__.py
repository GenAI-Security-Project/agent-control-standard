"""Python reference Guardian implementation for OWASP ACS v0.1.0.

An independent implementation of the ACS wire contract
(docs/spec/conformance.md): JSON-RPC 2.0 envelopes, the capability
negotiation handshake, the hook taxonomy, the five dispositions, the
SessionContext audit chain, replay protection, and the HMAC-SHA256 baseline
signature. Wrapped MCP is not implemented yet; see README.md for the exact
status of the ACS-Core claim.
"""

__version__ = "0.1.0"
