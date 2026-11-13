# Run with the reference adapters

The reference adapters in [`adapters/`](../../../adapters/README.md) connect Claude Code, Cursor and NVIDIA NeMo Agent Toolkit (NAT) to an ACS Guardian. This page connects them to this Guardian. Follow each adapter's install steps, with the changes below.

## Give both sides the same secret

The adapters sign their requests and the Guardian signs its responses with one shared secret. Each side derives its signing key from the secret with HKDF, the key derivation function of [§10](../../../docs/spec/instrument/specification.md#10-cryptographic-signatures). The two sides read the secret file differently:

| Reader | Expected file content | Bytes passed to HKDF |
| --- | --- | --- |
| This Guardian | standard base64, as [`reference-implementations/README.md`](../../README.md#signing-and-verification) requires | the decoded bytes |
| The adapters | any content of at least 32 bytes; their step 1 writes `openssl rand -hex 32` to `~/.acs/hmac.key` | the raw bytes of the file, without trailing whitespace |

Hex text is also valid base64. So the Guardian accepts the adapters' file without an error, decodes it to 48 other bytes, and every signed message fails with `SIGNATURE_INVALID`.

Do the adapter's step 1. Then, from `reference-implementations/agt-go`, write the same secret in base64 to the Guardian's file:

```bash
mkdir -p .acs
(umask 077; tr -d '\n' < ~/.acs/hmac.key | openssl base64 -A > .acs/hmac-secret)
```

`tr` removes the newline that `openssl rand` writes, because the adapters remove it too. The Guardian then decodes exactly the bytes the adapters use.

This replaces the secret that `make dev-secret` wrote. The Codex and OpenCode examples in this directory read the same file, so they keep working with the new secret.

Discussion [#552](https://github.com/GenAI-Security-Project/agent-control-standard/discussions/552) asks the leads for one format for both readers.

## Start this Guardian

Skip the adapter's step 2, which starts its example Guardian. Start this Guardian with `make run` instead, and restart it if it is running: it reads the secret only at start. It listens at `http://127.0.0.1:8787/acs`, the URL the adapters' READMEs use.

## Use this Guardian's key ID

The adapters' READMEs use the key ID `2026-11`. This Guardian's key ID is `2026-10`, set in `security.hmac_key_id` in [`guardian.yaml`](../guardian.yaml). Give the adapters that key ID:

- Claude Code and Cursor: in step 3, pass `--key-id=2026-10` to `acs-claude-code-wire` or `acs-cursor-wire`. The wire tool writes the key ID and the secret file into each hook command, so a variable exported in your shell does not reach the hooks.
- NAT: set `ACS_HMAC_SECRET_FILE=~/.acs/hmac.key` and `ACS_HMAC_KEY_ID=2026-10` in the environment of the NAT process. The NAT adapter runs inside that process and reads both variables there.

## Which tools the policy governs

The reference policy in [`../agt`](../../agt) registers only shell and web-fetch tools: `Bash`, `bash`, `run_shell`, `WebFetch` and `webfetch`. The Guardian denies a call to any other tool. Claude Code and Cursor send every tool call, so with the reference policy the agent can run shell commands but cannot read, edit or search a file.

To govern another tool, copy `../agt/policy` and `../agt/mapping.yaml` to a directory of your own, and point `policy.deployment_dir` at it. Then, for each tool:

1. Register the tool's name under `tools:` in `policy/manifest.yaml`.
2. Name the argument the policy checks under `policy_target_argument.by_tool` in `mapping.yaml`. For Claude Code's `Read`, the argument is `file_path`.

The policy matches tool names exactly. A host whose shell tool has another name needs an alias in `policy.tool_aliases` instead. [`guardian.yaml`](../guardian.yaml) maps Cursor's `Shell` and the name `shell` to `bash`. The NAT adapter sends the name of the workflow function, so a NAT function called `shell` reaches the shell rules through that alias.
