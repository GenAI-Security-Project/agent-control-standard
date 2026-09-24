# Custom engine example

This standalone module embeds the Guardian without AGT. It demonstrates the
four interfaces with its own implementations:

- `PolicyEngine`: denies commands containing `rm -rf` or `mkfs`;
- `Signer`: looks up HMAC keying material by `key_id`;
- `SessionContextStore`: wraps the bounded in-memory store;
- `AuditLog`: receives Guardian audit events.

From this directory, provide at least 32 bytes of shared keying material and
run the example:

```bash
ACS_HMAC_SECRET=0123456789abcdef0123456789abcdef go run .
```

The default endpoint is `http://127.0.0.1:8788/acs`. Use `--listen` to select
another address.

This module uses a local `replace` directive so it tests the current checkout.
For what each implementation must do, read
[extend the Guardian](../../docs/extending.md).
