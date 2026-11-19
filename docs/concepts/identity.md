# Identity

Identity answers who a party is: the Observed Agent, the Guardian, the Approver, and the principal on whose behalf the agent acts. It is an upstream dependency of authorization: a [capability](./capability.md) decision is only as meaningful as the identity it is bound to.

> **Workstream ownership.** The identity descriptor schema is owned by the Identity workstream. This page defines the cross-cutting concept and its boundary with the pillars; the descriptor shapes and any future identity profile live with that workstream.

## Principals and descriptors

A principal is the authenticated party initiating or acting within a session. ACS does not invent an identity format. Conceptual identity descriptors align with [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) (*Subject Identifiers for Security Event Tokens*), which defines typed subject identifiers under an IANA registry (`iss_sub` carrying both `iss` and `sub` for OAuth/OIDC principals, `uri` for SPIFFE and WIMSE workload IDs, `did`, `email`, and `opaque`), alongside OS-local and certificate schemes (`posix_uid`, `windows_sid`, `cert_subject`, `spiffe`). For workload identity, see the WIMSE and SPIFFE discussion in [Standards](../identity/standards.md).

*Example.* A POSIX deployment carries `{ "type": "posix_uid", "uid": 1000 }`; an OAuth or OIDC deployment carries an issuer-qualified RFC 9493 `iss_sub` descriptor `{ "format": "iss_sub", "iss": "https://idp.example.com", "sub": "user-123" }` (never a bare `sub` without `iss`, which is not globally unique across issuers); a workload-identity deployment carries a SPIFFE SVID URI `{ "format": "uri", "uri": "spiffe://example.com/agent/finbot" }` (or `{ "type": "spiffe", "uri": "spiffe://example.com/agent/finbot" }`). In v0.1, the wire schemas (`user_identity` in [`session-start.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/session-start.json) and `user_context` in [`request-envelope.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/request-envelope.json)) carry `{user_id, roles, authentication_method}` (often summarized in profile prose as `{id, role, attributes}` or `{user_id, tenant_id, roles, session_attributes}`) without a separate `type` or `format` discriminator field on the wire.

Three identities are distinct and MUST NOT be conflated:

- **Observed Agent identity**: which agent is under governance (`metadata.agent_id` in `request-envelope.json`).
- **Guardian identity**: which Guardian service or instance is deciding, named as its own principal—distinct from the policy document (`policy_references`) and its author ([Conformance](../spec/conformance.md)). In v0.1, neither `ServerHello` (`handshake.json`) nor `response-envelope.json` carries a Guardian principal identifier field; a signed response identifies the Guardian's configured signing key through `signature.key_id` ([Specification §10](../spec/instrument/specification.md#10-cryptographic-signatures)).
- **Policy-author identity**: who authored the policy that produced a decision ([Conformance](../spec/conformance.md)).

## Authentication is deployment-defined

> **No mandated mechanism (normative).** ACS mandates no authentication mechanism. In v0.1, `handshake.json` defines no authentication-mechanism field (`signature_algorithms_supported` negotiates envelope signing only); authentication is established by the deployment's transport and host boundary. Trust schemes (for example SPIFFE, OIDC, DID, organizational PKI, or quorum signing) are deployment-defined and stay off the core wire contract.

This keeps the adoption floor low: a deployment binds ACS to whatever identity infrastructure it already runs. The future Policy Attestation profile will bind policy-author identity to verifiable signatures using the ACS-Crypto registry, without pulling the trust scheme onto the wire.

## Identity and trust basis

An identity descriptor is itself a fact with a [trust basis](./trust.md). An asserted identity is weaker than one bound by a verified credential or signature, and policy that gates high-impact actions should require an identity at an appropriate rung of that spectrum. In v0.1, ACS defines no on-wire field in the JSON-RPC envelope for proof of possession, DPoP, mTLS client-certificate binding, or SVID presentation; whether an identity descriptor was verified by the transport/host or merely asserted by the caller is established out of band by the deployment's transport and authentication boundary.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): `user_identity` at session start; Approver identity verification (§9); envelope signing key identification via `signature.key_id` (§10); identity descriptors (§11).
- **Trace**, [extend OCSF](../spec/trace/extend_ocsf.md): agent vs human actors distinguished in emitted events.
- **Inspect**, [AgBOM](../spec/inspect/README.md): peer identity on `a2a_peer` components.
- See also [Agents](./agents.md), [Capability](./capability.md), and [Trust basis](./trust.md).
