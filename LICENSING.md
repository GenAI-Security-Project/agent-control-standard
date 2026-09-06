# Licensing

ACS ships under two licenses. Code and machine-readable schemas use the **Apache License 2.0**. Prose documentation uses **Creative Commons Attribution-ShareAlike 4.0 International**. This matches how the OWASP GenAI Security Project licenses its guidance and its code.

Copyright 2025-2026 The OWASP GenAI Security Project and the ACS contributors.

## What each license covers

| Path | License | SPDX identifier |
| --- | --- | --- |
| `specification/**` | Apache License 2.0 | `Apache-2.0` |
| `.github/**` | Apache License 2.0 | `Apache-2.0` |
| `pyproject.toml`, `uv.lock`, `mkdocs.yml`, `.vscode/**` | Apache License 2.0 | `Apache-2.0` |
| Code samples embedded in any Markdown file | Apache License 2.0 | `Apache-2.0` |
| `docs/**` | CC BY-SA 4.0 | `CC-BY-SA-4.0` |
| `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTORS.md`, `STYLE.md`, `SPEC_REVIEW_PRINCIPLES.md`, `LICENSING.md` | CC BY-SA 4.0 | `CC-BY-SA-4.0` |
| `landing/**`, `tools/**`, `tests/**` | Apache License 2.0 | `Apache-2.0` |
| `overrides/**` | CC BY-SA 4.0 | `CC-BY-SA-4.0` |
| `design/**` | CC BY-SA 4.0 | `CC-BY-SA-4.0` |
| `landing/assets/fonts/**` | SIL Open Font License 1.1 | `OFL-1.1` |
| Everything else, including any new top-level directory | Apache License 2.0 | `Apache-2.0` |

A more specific row wins over the catch-all. The catch-all exists so a directory added later is governed the day it lands rather than on the day someone notices it was never listed. Apache 2.0 is the default because a new directory is usually code, and an over-permissive grant on prose costs less than a ShareAlike obligation attaching by accident to reference code that adopters copy into their own systems. When a new directory holds prose, add an explicit `CC-BY-SA-4.0` row for it in the same pull request that creates it.

Full texts live in [`LICENSE`](./LICENSE) for Apache 2.0, [`LICENSE-DOCS`](./LICENSE-DOCS) for CC BY-SA 4.0, and [`landing/assets/fonts/OFL.txt`](./landing/assets/fonts/OFL.txt) for the SIL Open Font License 1.1. Attribution details live in [`NOTICE`](./NOTICE).

Code samples inside the documentation carry the Apache 2.0 grant, not the ShareAlike obligation. Copy a JSON payload or a hook definition out of `docs/` into a proprietary agent and nothing forces you to open-source the result.

## Provenance of the landing page design

The design tokens in `landing/assets/acs.css`, the diagram geometry in
`landing/assets/starburst.svg`, and the mark in `landing/assets/icon.svg`, which is
duplicated at `docs/assets/icon.svg` because MkDocs requires a theme logo inside its own
documentation directory, derive from agentcontrolstandard.org, which the OWASP GenAI
Security Project operates and which is built from a separate repository. They are used
here as the project's own work. Both copies of the mark are covered by the
`landing/**` row above.

The OWASP GenAI Security Project holds the rights to this design, confirmed by the
project lead. No outside party has a claim on the tokens, the diagram geometry, or the
mark, so they are covered by the rows above with no further condition.

The vendored font is Inter, redistributed under the SIL Open Font License 1.1. Its
recorded checksum is in `landing/assets/fonts/CHECKSUMS.txt`.

The documentation header inlines the GitHub mark from the Simple Icons set bundled with
Material for MkDocs, dedicated to the public domain under CC0 1.0 Universal. It is
included at build time rather than vendored, so no copy lives in this repository.

## Why the split

Documentation under CC BY-SA 4.0 stays free to copy, translate, and adapt. Adaptations carry the same license forward, so derived guidance stays open.

Code and schemas under Apache 2.0 give implementers an express patent grant. Building an ACS-conformant agent does not expose you to patent claims from the people who wrote the schema. MIT is silent on patents, which is the reason ACS moved off it.

## Apply the license to your own work

For a source file:

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 <your name or organization>
```

For a document derived from ACS prose:

```markdown
Adapted from the Agent Control Standard, licensed under CC BY-SA 4.0.
Source: https://github.com/GenAI-Security-Project/agent-control-standard
```

## Contributing

Contributions land under the license that governs the file you touch. Sign your commits with `git commit -s` to certify the Developer Certificate of Origin. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Trademarks

These licenses cover copyright. They grant no rights to the OWASP name, the OWASP GenAI Security Project name, the Agent Control Standard name, or any associated logo. Describe your implementation as ACS-conformant. Do not imply endorsement.

## License history

Releases up to and including v0.1.0 were published under the MIT License. That grant stands. Anyone who obtained ACS under the MIT License keeps their rights under it. Contributions merged after the relicense are governed by the terms on this page.
